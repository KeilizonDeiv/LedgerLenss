"""Document processing pipeline (the orchestrator).

  load -> extract text -> sanitize -> LLM extract -> rules -> duplicate check
       -> LLM policy review -> risk score -> decision -> persist + audit

Architecture notes:
  * Short DB sessions: we never hold a DB connection while waiting on an LLM
    (calls can take 30s+; holding connections would exhaust the pool under load).
  * Idempotent: only QUEUED documents are picked up, so a retried job is harmless.
  * Runs in FastAPI BackgroundTasks today. Because state lives in the DB (status
    column), moving to a durable queue (Celery/ARQ/Azure Service Bus) means changing
    only *who calls run()*, not the pipeline.
"""
import asyncio
import logging
import uuid
from datetime import UTC, date, datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.ai.sanitize import prepare_untrusted_text
from app.ai.schemas import InvoiceExtraction, PolicyReview
from app.ai.service import AIService, AIServiceError
from app.core.config import Settings
from app.core.errors import PipelineError
from app.models import DocStatus, Document, Organization
from app.services import audit, rules
from app.services.files import extract_text
from app.services.rules import Finding
from app.services.storage import FileStorage

logger = logging.getLogger(__name__)
FLAG_FINDINGS = {
    "injection_pattern": Finding("PROMPT_INJECTION_PATTERN", "high", "Text matches known prompt-injection phrasing"),
    "truncated": Finding("TRUNCATED", "low", "Document was truncated before AI analysis"),
}


class DocumentPipeline:
    def __init__(self, *, session_factory: async_sessionmaker[AsyncSession], storage: FileStorage,
                 ai: AIService, settings: Settings) -> None:
        self._sessions = session_factory
        self._storage = storage
        self._ai = ai
        self._settings = settings

    async def run(self, document_id: uuid.UUID) -> None:
        if not await self._claim(document_id):
            return
        try:
            await self._process(document_id)
        except Exception as exc:  # noqa: BLE001 - last line of defence, must record failure
            await self._mark_failed(document_id, exc)

    async def _claim(self, document_id: uuid.UUID) -> bool:
        async with self._sessions() as s:
            doc = await s.get(Document, document_id)
            if doc is None or doc.status != DocStatus.QUEUED:
                return False
            doc.status = DocStatus.PROCESSING
            await audit.record(s, org_id=doc.org_id, action="document.processing_started",
                               target_type="document", target_id=doc.id)
            await s.commit()
            return True

    async def _process(self, document_id: uuid.UUID) -> None:
        # 1) Load inputs in a short session.
        async with self._sessions() as s:
            doc = await s.get(Document, document_id)
            org = await s.get(Organization, doc.org_id)
            storage_key, content_type, policy = doc.storage_key, doc.content_type, org.expense_policy

        # 2) Slow work with no DB connection held.
        data = await self._storage.read(storage_key)
        raw = await asyncio.to_thread(extract_text, data, content_type, self._settings.max_pdf_pages)
        if not raw.strip():
            raise PipelineError("NO_TEXT", "No extractable text (scanned image?). OCR is not enabled.")
        text, flags = prepare_untrusted_text(raw, self._settings.max_llm_chars)
        extraction = await self._ai.extract_invoice(text)

        findings = rules.evaluate(extraction, today=date.today(), auto_approve_limit=self._settings.auto_approve_limit)
        findings += [FLAG_FINDINGS[f] for f in flags]

        review: PolicyReview | None = None
        if not policy:
            findings.append(Finding("NO_POLICY_CONFIGURED", "low", "No expense policy configured; policy check skipped"))
        elif extraction.is_invoice:
            review = await self._ai.review_policy(policy, extraction)

        # 3) Persist results in one transaction (with the duplicate check, so it sees fresh data).
        async with self._sessions() as s:
            doc = await s.get(Document, document_id)
            if await self._is_duplicate_invoice(s, doc, extraction):
                findings.append(Finding("DUPLICATE_INVOICE", "high",
                                        "Another document has the same vendor and invoice number (possible double payment)"))
            score = rules.risk_score(findings, review)
            status = rules.decide(score, findings, review)

            doc.extraction = extraction.model_dump(mode="json")
            doc.findings = [f.to_dict() for f in findings]
            doc.policy_review = review.model_dump(mode="json") if review else None
            doc.risk_score = score
            doc.status = status
            doc.vendor_name = (extraction.vendor_name or "")[:200] or None
            doc.invoice_number = (extraction.invoice_number or "")[:100] or None
            doc.total_amount = rules.money(extraction.total)
            doc.currency = (extraction.currency or "")[:3].upper() or None
            if status == DocStatus.AUTO_APPROVED:
                doc.decided_at = datetime.now(UTC)
            await audit.record(s, org_id=doc.org_id, action=f"document.{status.value}", target_type="document",
                               target_id=doc.id, details={"risk_score": score, "findings": [f.code for f in findings]})
            await s.commit()

    @staticmethod
    async def _is_duplicate_invoice(s: AsyncSession, doc: Document, inv: InvoiceExtraction) -> bool:
        if not (inv.vendor_name and inv.invoice_number):
            return False
        stmt = select(func.count()).select_from(Document).where(
            Document.org_id == doc.org_id,
            Document.id != doc.id,
            Document.invoice_number == inv.invoice_number[:100],
            func.lower(Document.vendor_name) == inv.vendor_name[:200].lower(),
            Document.status.not_in([DocStatus.FAILED, DocStatus.REJECTED]),
        )
        return (await s.scalar(stmt) or 0) > 0

    async def _mark_failed(self, document_id: uuid.UUID, exc: Exception) -> None:
        if isinstance(exc, PipelineError):
            code, message = exc.code, exc.public_message
            logger.warning("pipeline rejected document %s: %s", document_id, code)
        elif isinstance(exc, AIServiceError):
            code, message = "AI_ERROR", "AI provider failed; an admin can retry processing"
            logger.exception("AI failure for document %s", document_id)
        else:
            # Never leak internals (stack traces, SQL, paths) to API consumers.
            code, message = "INTERNAL_ERROR", "Unexpected processing error"
            logger.exception("Unexpected pipeline failure for document %s", document_id)
        async with self._sessions() as s:
            doc = await s.get(Document, document_id)
            if doc is None:
                return
            doc.status = DocStatus.FAILED
            doc.error = message
            await audit.record(s, org_id=doc.org_id, action="document.failed", target_type="document",
                               target_id=doc.id, details={"code": code})
            await s.commit()
