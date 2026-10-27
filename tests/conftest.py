"""Test harness: real app + real SQL (SQLite) + fake AI. No network, no API keys."""
from collections.abc import AsyncIterator, Callable
from datetime import date

import httpx
import pytest

from app.ai.schemas import InvoiceExtraction, LineItem, PolicyReview
from app.ai.service import AIServiceError
from app.core.config import Settings
from app.db.base import Base
from app.main import create_app

STRONG_PASSWORD = "correct-horse-battery-staple"


def good_invoice(**overrides) -> InvoiceExtraction:
    data = dict(
        is_invoice=True, vendor_name="Acme Office Supplies", vendor_tax_id="123-456-789-000",
        invoice_number="INV-1001", invoice_date=date(2026, 1, 15), due_date=date(2026, 2, 14),
        currency="PHP", subtotal=1000.00, tax=120.00, total=1120.00,
        line_items=[LineItem(description="Printer paper", quantity=10, unit_price=100, amount=1000.00)],
        confidence=0.95,
    )
    data.update(overrides)
    return InvoiceExtraction(**data)


class FakeAIService:
    """Deterministic stand-in for the LLM. Tests set .extraction / .review / .fail."""

    def __init__(self) -> None:
        self.extraction: InvoiceExtraction = good_invoice()
        self.review = PolicyReview(compliant=True, summary="Within policy")
        self.fail = False
        self.seen_texts: list[str] = []

    async def extract_invoice(self, document_text: str) -> InvoiceExtraction:
        self.seen_texts.append(document_text)
        if self.fail:
            raise AIServiceError("provider down")
        return self.extraction

    async def review_policy(self, policy: str, invoice: InvoiceExtraction) -> PolicyReview:
        return self.review


def make_pdf(text: str) -> bytes:
    """Minimal valid single-page PDF with a text layer (no external deps)."""
    stream = f"BT /F1 12 Tf 72 720 Td ({text}) Tj ET".encode()
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R "
        b"/Resources << /Font << /F1 5 0 R >> >> >>",
        b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out, offsets = bytearray(b"%PDF-1.4\n"), []
    for i, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % i + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1)
    out += b"".join(b"%010d 00000 n \n" % o for o in offsets)
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objects) + 1, xref)
    return bytes(out)


@pytest.fixture
def fake_ai() -> FakeAIService:
    return FakeAIService()


@pytest.fixture
def make_settings(tmp_path) -> Callable[..., Settings]:
    def _make(**overrides) -> Settings:
        values = dict(env="test", jwt_secret="t" * 48, database_url=f"sqlite+aiosqlite:///{tmp_path}/test.db",
                      storage_dir=str(tmp_path / "uploads"), llm_provider="ollama", log_level="WARNING")
        values.update(overrides)
        return Settings(_env_file=None, **values)

    return _make


@pytest.fixture
async def make_client(make_settings, fake_ai):
    managers = []

    async def _make(**overrides) -> httpx.AsyncClient:
        app = create_app(make_settings(**overrides), ai_service=fake_ai)
        lifespan = app.router.lifespan_context(app)
        await lifespan.__aenter__()
        async with app.state.engine.begin() as conn:  # tests use create_all; prod uses Alembic
            await conn.run_sync(Base.metadata.create_all)
        client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")
        client.app = app  # type: ignore[attr-defined]
        managers.append((client, lifespan))
        return client

    yield _make
    for client, lifespan in managers:
        await client.aclose()
        await lifespan.__aexit__(None, None, None)


@pytest.fixture
async def client(make_client) -> AsyncIterator[httpx.AsyncClient]:
    return await make_client()


async def register(client: httpx.AsyncClient, email: str, org: str = "Acme Corp") -> dict[str, str]:
    r = await client.post("/auth/register", json={"org_name": org, "email": email, "password": STRONG_PASSWORD})
    assert r.status_code == 201, r.text
    return await login(client, email)


async def login(client: httpx.AsyncClient, email: str, password: str = STRONG_PASSWORD) -> dict[str, str]:
    r = await client.post("/auth/token", data={"username": email, "password": password})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


async def add_user(client: httpx.AsyncClient, admin: dict[str, str], email: str, role: str) -> dict[str, str]:
    r = await client.post("/users", headers=admin, json={"email": email, "password": STRONG_PASSWORD, "role": role})
    assert r.status_code == 201, r.text
    return await login(client, email)


async def upload(client: httpx.AsyncClient, headers: dict[str, str], content: bytes, name: str = "invoice.txt"):
    return await client.post("/documents", headers=headers, files={"file": (name, content, "text/plain")})
