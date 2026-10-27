from sqlalchemy import update

from app.models import AuditEvent
from tests.conftest import register, upload


async def test_audit_chain_verifies_and_detects_tampering(client):
    admin = await register(client, "admin@acme-corp.com")
    await upload(client, admin, b"Invoice INV-1 total 100")

    r = (await client.get("/audit/verify", headers=admin)).json()
    assert r["valid"] is True and r["events_checked"] >= 4

    events = (await client.get("/audit", headers=admin)).json()
    victim_id = events[-1]["id"]  # oldest event
    async with client.app.state.session_factory() as s:  # simulate a malicious DB edit
        await s.execute(update(AuditEvent).where(AuditEvent.id == victim_id).values(action="nothing.to.see"))
        await s.commit()

    r = (await client.get("/audit/verify", headers=admin)).json()
    assert r["valid"] is False
    assert r["first_invalid_event_id"] == victim_id
