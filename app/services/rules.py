"""Deterministic accounting checks + risk scoring.

Design principle: the LLM *reads*, code *decides*. Arithmetic, dates and thresholds
are checked with Decimal math, never by asking the model. Pure functions -> trivially testable.
"""
from dataclasses import asdict, dataclass
from datetime import date
from decimal import ROUND_HALF_UP, Decimal
from typing import Literal

from app.ai.schemas import InvoiceExtraction, PolicyReview
from app.models import DocStatus

Severity = Literal["low", "medium", "high"]
SEVERITY_WEIGHT: dict[str, int] = {"low": 5, "medium": 15, "high": 40}
TOLERANCE = Decimal("0.05")  # rounding slack between printed amounts
AUTO_APPROVE_MAX_SCORE = 20
MIN_CONFIDENCE = 0.7


@dataclass(frozen=True)
class Finding:
    code: str
    severity: Severity
    message: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


def money(value: float | None) -> Decimal | None:
    if value is None:
        return None
    return Decimal(str(value)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


def evaluate(inv: InvoiceExtraction, *, today: date, auto_approve_limit: Decimal) -> list[Finding]:
    f: list[Finding] = []
    if not inv.is_invoice:
        f.append(Finding("NOT_AN_INVOICE", "high", "Document does not look like an invoice or receipt"))
    for field in ("vendor_name", "invoice_number", "total"):
        if getattr(inv, field) in (None, ""):
            f.append(Finding("MISSING_FIELD", "medium", f"Required field '{field}' was not found"))

    subtotal, tax, total = money(inv.subtotal), money(inv.tax), money(inv.total)
    if total is not None and total <= 0:
        f.append(Finding("NON_POSITIVE_TOTAL", "high", "Total must be greater than zero"))

    amounts = [money(li.amount) for li in inv.line_items]
    if amounts and all(a is not None for a in amounts) and subtotal is not None:
        lines_sum = sum(amounts, Decimal("0"))
        if abs(lines_sum - subtotal) > TOLERANCE:
            f.append(Finding("LINE_ITEMS_MISMATCH", "medium", f"Line items sum to {lines_sum}, subtotal is {subtotal}"))
    if subtotal is not None and total is not None:
        expected = subtotal + (tax or Decimal("0"))
        if abs(expected - total) > TOLERANCE:
            f.append(Finding("TOTAL_MISMATCH", "high", f"Subtotal + tax = {expected}, but total is {total}"))

    if inv.invoice_date and inv.invoice_date > today:
        f.append(Finding("FUTURE_DATED", "high", f"Invoice date {inv.invoice_date} is in the future"))
    if inv.invoice_date and inv.due_date and inv.due_date < inv.invoice_date:
        f.append(Finding("DUE_BEFORE_ISSUE", "medium", "Due date is before the invoice date"))
    if inv.confidence < MIN_CONFIDENCE:
        f.append(Finding("LOW_CONFIDENCE", "medium", f"Extraction confidence {inv.confidence:.2f} is below {MIN_CONFIDENCE}"))
    if inv.suspicious_instructions:
        f.append(Finding("PROMPT_INJECTION_SUSPECTED", "high", "Document contains instructions aimed at the AI/reviewer"))
    if total is not None and total > auto_approve_limit:
        f.append(Finding("ABOVE_AUTO_APPROVE_LIMIT", "low", f"Total {total} exceeds auto-approve limit {auto_approve_limit}"))
    return f


def risk_score(findings: list[Finding], review: PolicyReview | None) -> int:
    score = sum(SEVERITY_WEIGHT[x.severity] for x in findings)
    if review:
        score += sum(SEVERITY_WEIGHT[v.severity] for v in review.violations)
    return min(score, 100)


def decide(score: int, findings: list[Finding], review: PolicyReview | None) -> DocStatus:
    """Auto-approve only the boring, clean, small invoices. Everything else -> a human."""
    blocking = any(x.severity != "low" or x.code == "ABOVE_AUTO_APPROVE_LIMIT" for x in findings)
    if review is not None and not review.compliant:
        blocking = True
    return DocStatus.AUTO_APPROVED if score < AUTO_APPROVE_MAX_SCORE and not blocking else DocStatus.NEEDS_REVIEW
