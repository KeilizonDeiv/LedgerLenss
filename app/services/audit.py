"""Tamper-evident audit trail (hash chain per organization).

hash_n = SHA256(hash_{n-1} || canonical_json(event_n))

Defence in depth:
  1. Application never issues UPDATE/DELETE on audit_events.
  2. Postgres trigger (see migration) rejects UPDATE/DELETE/TRUNCATE.
  3. Even a DBA bypassing the trigger can't hide edits: /audit/verify recomputes the chain.
"""
import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import AuditEvent

GENESIS_HASH = "0" * 64


def _canonical_ts(dt: datetime) -> str:
    # Normalise to naive-UTC so the hash is identical whether the DB returns tz-aware or naive values.
    if dt.tzinfo is not None:
        dt = dt.astimezone(UTC).replace(tzinfo=None)
    return dt.isoformat(timespec="microseconds")


def compute_hash(*, prev_hash: str, org_id: uuid.UUID, actor_id: uuid.UUID | None, action: str,
                 target_type: str, target_id: str, details: dict[str, Any], created_at: datetime) -> str:
    payload = json.dumps(
        {
            "org_id": str(org_id),
            "actor_id": str(actor_id) if actor_id else None,
            "action": action,
            "target_type": target_type,
            "target_id": target_id,
            "details": details,
            "created_at": _canonical_ts(created_at),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256((prev_hash + payload).encode()).hexdigest()


async def record(session: AsyncSession, *, org_id: uuid.UUID, action: str, actor_id: uuid.UUID | None = None,
                 target_type: str = "", target_id: str | uuid.UUID = "", details: dict[str, Any] | None = None) -> AuditEvent:
    """Append an event inside the caller's transaction (commit is the caller's job,
    so the audit row and the business change succeed or fail together)."""
    if session.bind is not None and session.bind.dialect.name == "postgresql":
        # Serialise appends per org; otherwise two concurrent writers could read the
        # same prev_hash and fork the chain. Lock is released at commit/rollback.
        await session.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(:k, 0))"), {"k": f"audit:{org_id}"})

    prev = await session.scalar(
        select(AuditEvent.hash).where(AuditEvent.org_id == org_id).order_by(AuditEvent.id.desc()).limit(1)
    )
    clean_details = json.loads(json.dumps(details or {}, default=str))  # JSON-native types only
    created_at = datetime.now(UTC)
    fields = dict(org_id=org_id, actor_id=actor_id, action=action, target_type=target_type,
                  target_id=str(target_id), details=clean_details, created_at=created_at)
    event = AuditEvent(**fields, prev_hash=prev or GENESIS_HASH,
                       hash=compute_hash(prev_hash=prev or GENESIS_HASH, **fields))
    session.add(event)
    await session.flush()
    return event


@dataclass
class ChainVerification:
    valid: bool
    events_checked: int
    first_invalid_event_id: int | None = None


async def verify_chain(session: AsyncSession, org_id: uuid.UUID) -> ChainVerification:
    expected_prev = GENESIS_HASH
    checked = 0
    result = await session.stream_scalars(
        select(AuditEvent).where(AuditEvent.org_id == org_id).order_by(AuditEvent.id)
    )
    async for ev in result:
        checked += 1
        recomputed = compute_hash(prev_hash=ev.prev_hash, org_id=ev.org_id, actor_id=ev.actor_id, action=ev.action,
                                  target_type=ev.target_type, target_id=ev.target_id, details=ev.details,
                                  created_at=ev.created_at)
        if ev.prev_hash != expected_prev or ev.hash != recomputed:
            return ChainVerification(False, checked, ev.id)
        expected_prev = ev.hash
    return ChainVerification(True, checked)
