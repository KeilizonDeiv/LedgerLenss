"""API contracts (request/response DTOs) — deliberately separate from ORM models so
the database schema can evolve without breaking clients, and secrets like
password_hash can never be serialised by accident."""
import uuid
from datetime import datetime
from decimal import Decimal
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from app.models import Role

Password = Field(min_length=12, max_length=128, description="At least 12 characters")


class RegisterRequest(BaseModel):
    org_name: str = Field(min_length=2, max_length=200)
    email: EmailStr
    password: str = Password


class CreateUserRequest(BaseModel):
    email: EmailStr
    password: str = Password
    role: Role


class TokenResponse(BaseModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"  # noqa: S105 (OAuth2 token type, not a secret)
    expires_in: int


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    org_id: uuid.UUID
    email: str
    role: Role
    is_active: bool


class PolicyIn(BaseModel):
    text: str = Field(min_length=1, max_length=20_000)


class PolicyOut(BaseModel):
    text: str | None


class DocumentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    original_filename: str
    content_type: str
    size_bytes: int
    status: str
    risk_score: int | None
    vendor_name: str | None
    invoice_number: str | None
    total_amount: Decimal | None
    currency: str | None
    error: str | None
    created_at: datetime
    updated_at: datetime


class DocumentDetail(DocumentOut):
    uploaded_by: uuid.UUID
    extraction: dict[str, Any] | None
    findings: list[dict[str, Any]] | None
    policy_review: dict[str, Any] | None
    decided_by: uuid.UUID | None
    decided_at: datetime | None
    decision_note: str | None


class DocumentPage(BaseModel):
    items: list[DocumentOut]
    total: int
    limit: int
    offset: int


class DecisionRequest(BaseModel):
    decision: Literal["approve", "reject"]
    note: str = Field(default="", max_length=1000)


class AuditEventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    actor_id: uuid.UUID | None
    action: str
    target_type: str
    target_id: str
    details: dict[str, Any]
    created_at: datetime
    hash: str


class AuditVerifyOut(BaseModel):
    valid: bool
    events_checked: int
    first_invalid_event_id: int | None
