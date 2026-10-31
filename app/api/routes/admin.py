"""Organization administration: users, expense policy, audit trail."""
from typing import Annotated

from fastapi import APIRouter, Query
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.api.deps import AdminUser, CurrentUser, SessionDep
from app.core.errors import Conflict
from app.core.security import hash_password
from app.models import AuditEvent, Organization, User
from app.schemas import AuditEventOut, AuditVerifyOut, CreateUserRequest, PolicyIn, PolicyOut, UserOut
from app.services import audit

router = APIRouter(tags=["admin"])


@router.post("/users", response_model=UserOut, status_code=201)
async def create_user(body: CreateUserRequest, admin: AdminUser, session: SessionDep) -> User:
    user = User(org_id=admin.org_id, email=body.email.lower(), password_hash=hash_password(body.password), role=body.role)
    session.add(user)
    try:
        await session.flush()
    except IntegrityError:
        raise Conflict("An account with this email already exists") from None
    await audit.record(session, org_id=admin.org_id, actor_id=admin.id, action="user.created", target_type="user",
                       target_id=user.id, details={"role": body.role})
    await session.commit()
    return user


@router.get("/users", response_model=list[UserOut])
async def list_users(admin: AdminUser, session: SessionDep) -> list[User]:
    return list(await session.scalars(select(User).where(User.org_id == admin.org_id).order_by(User.created_at)))


@router.get("/org/policy", response_model=PolicyOut)
async def get_policy(user: CurrentUser, session: SessionDep) -> PolicyOut:
    org = await session.get(Organization, user.org_id)
    return PolicyOut(text=org.expense_policy)


@router.put("/org/policy", response_model=PolicyOut)
async def set_policy(body: PolicyIn, admin: AdminUser, session: SessionDep) -> PolicyOut:
    org = await session.get(Organization, admin.org_id)
    org.expense_policy = body.text
    await audit.record(session, org_id=org.id, actor_id=admin.id, action="policy.updated",
                       target_type="organization", target_id=org.id, details={"length": len(body.text)})
    await session.commit()
    return PolicyOut(text=org.expense_policy)


@router.get("/audit", response_model=list[AuditEventOut])
async def list_audit(admin: AdminUser, session: SessionDep,
                     limit: Annotated[int, Query(ge=1, le=500)] = 100) -> list[AuditEvent]:
    stmt = select(AuditEvent).where(AuditEvent.org_id == admin.org_id).order_by(AuditEvent.id.desc()).limit(limit)
    return list(await session.scalars(stmt))


@router.get("/audit/verify", response_model=AuditVerifyOut)
async def verify_audit(admin: AdminUser, session: SessionDep) -> AuditVerifyOut:
    result = await audit.verify_chain(session, admin.org_id)
    return AuditVerifyOut(valid=result.valid, events_checked=result.events_checked,
                          first_invalid_event_id=result.first_invalid_event_id)
