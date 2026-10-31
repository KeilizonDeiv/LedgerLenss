import uuid
from datetime import UTC, datetime
from typing import Annotated
from urllib.parse import quote

from fastapi import APIRouter, BackgroundTasks, Depends, Query, Response, UploadFile
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from app.api.deps import AdminUser, CurrentUser, PipelineDep, ReviewerUser, SessionDep, SettingsDep, StorageDep
from app.core.errors import Conflict, Forbidden, NotFound
from app.core.ratelimit import rate_limit
from app.models import DocStatus, Document, User
from app.schemas import DecisionRequest, DocumentDetail, DocumentOut, DocumentPage
from app.services import audit
from app.services.files import read_limited, validate_upload

router = APIRouter(prefix="/documents", tags=["documents"])


async def _get_owned(session, doc_id: uuid.UUID, user: User) -> Document:
    # Tenant isolation: always filter by org_id. Return 404 (not 403) for other tenants'
    # documents so attackers can't even confirm an ID exists (prevents IDOR probing).
    doc = await session.scalar(select(Document).where(Document.id == doc_id, Document.org_id == user.org_id))
    if doc is None:
        raise NotFound("Document not found")
    return doc


@router.post("", response_model=DocumentOut, status_code=202,
             dependencies=[Depends(rate_limit("upload", "upload_rate_per_minute"))])
async def upload_document(file: UploadFile, background: BackgroundTasks, user: CurrentUser, session: SessionDep,
                          settings: SettingsDep, storage: StorageDep, pipeline: PipelineDep) -> Document:
    """Accept an invoice (PDF or text). Returns 202: processing continues asynchronously."""
    data = await read_limited(file, settings.max_upload_bytes)
    vf = validate_upload(data, file.filename)

    if await session.scalar(select(Document.id).where(Document.org_id == user.org_id, Document.sha256 == vf.sha256)):
        raise Conflict("This exact file was already uploaded")

    doc_id = uuid.uuid4()
    key = f"{user.org_id}/{doc_id}.{vf.extension}"  # server-generated key; user filename never touches the FS
    await storage.save(key, vf.data)
    doc = Document(id=doc_id, org_id=user.org_id, uploaded_by=user.id, original_filename=vf.safe_name,
                   storage_key=key, content_type=vf.content_type, size_bytes=len(vf.data), sha256=vf.sha256)
    session.add(doc)
    await audit.record(session, org_id=user.org_id, actor_id=user.id, action="document.uploaded",
                       target_type="document", target_id=doc_id, details={"sha256": vf.sha256, "size": len(vf.data)})
    try:
        await session.commit()
    except IntegrityError:  # lost a race with an identical concurrent upload
        await session.rollback()
        await storage.delete(key)
        raise Conflict("This exact file was already uploaded") from None

    background.add_task(pipeline.run, doc_id)
    return doc


@router.get("", response_model=DocumentPage)
async def list_documents(user: CurrentUser, session: SessionDep,
                         status: DocStatus | None = None,
                         limit: Annotated[int, Query(ge=1, le=100)] = 20,
                         offset: Annotated[int, Query(ge=0)] = 0) -> DocumentPage:
    base = select(Document).where(Document.org_id == user.org_id)
    if status:
        base = base.where(Document.status == status)
    total = await session.scalar(select(func.count()).select_from(base.subquery()))
    rows = await session.scalars(base.order_by(Document.created_at.desc()).limit(limit).offset(offset))
    return DocumentPage(items=[DocumentOut.model_validate(d) for d in rows], total=total or 0, limit=limit, offset=offset)


@router.get("/{doc_id}", response_model=DocumentDetail)
async def get_document(doc_id: uuid.UUID, user: CurrentUser, session: SessionDep) -> Document:
    return await _get_owned(session, doc_id, user)


@router.get("/{doc_id}/file")
async def download_document(doc_id: uuid.UUID, user: CurrentUser, session: SessionDep, storage: StorageDep) -> Response:
    doc = await _get_owned(session, doc_id, user)
    data = await storage.read(doc.storage_key)
    await audit.record(session, org_id=user.org_id, actor_id=user.id, action="document.downloaded",
                       target_type="document", target_id=doc.id)
    await session.commit()
    # attachment + nosniff: the browser downloads instead of rendering (no stored XSS via uploads).
    return Response(content=data, media_type=doc.content_type, headers={
        "Content-Disposition": f"attachment; filename*=UTF-8''{quote(doc.original_filename)}",
        "X-Content-Type-Options": "nosniff",
    })


@router.post("/{doc_id}/decision", response_model=DocumentDetail)
async def decide_document(doc_id: uuid.UUID, body: DecisionRequest, user: ReviewerUser, session: SessionDep) -> Document:
    doc = await _get_owned(session, doc_id, user)
    if doc.status != DocStatus.NEEDS_REVIEW:
        raise Conflict(f"Only documents in '{DocStatus.NEEDS_REVIEW}' can be decided (current: '{doc.status}')")
    # Segregation of duties — a core financial control (SOX-style): the person who
    # submits a payment request must not be the one who approves it.
    if doc.uploaded_by == user.id:
        raise Forbidden("Segregation of duties: you cannot decide on a document you submitted")
    doc.status = DocStatus.APPROVED if body.decision == "approve" else DocStatus.REJECTED
    doc.decided_by, doc.decided_at, doc.decision_note = user.id, datetime.now(UTC), body.note or None
    await audit.record(session, org_id=user.org_id, actor_id=user.id, action=f"document.{doc.status}",
                       target_type="document", target_id=doc.id, details={"note": body.note})
    await session.commit()
    return doc


@router.post("/{doc_id}/reprocess", response_model=DocumentOut, status_code=202)
async def reprocess_document(doc_id: uuid.UUID, admin: AdminUser, session: SessionDep,
                             background: BackgroundTasks, pipeline: PipelineDep) -> Document:
    doc = await _get_owned(session, doc_id, admin)
    if doc.status != DocStatus.FAILED:
        raise Conflict("Only failed documents can be reprocessed")
    doc.status, doc.error = DocStatus.QUEUED, None
    await audit.record(session, org_id=admin.org_id, actor_id=admin.id, action="document.requeued",
                       target_type="document", target_id=doc.id)
    await session.commit()
    background.add_task(pipeline.run, doc.id)
    return doc
