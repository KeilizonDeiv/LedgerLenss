from tests.conftest import STRONG_PASSWORD, add_user, login, register


async def test_register_login_and_me(client):
    headers = await register(client, "admin@acme-corp.com")
    r = await client.get("/auth/me", headers=headers)
    assert r.status_code == 200
    assert r.json()["role"] == "admin"


async def test_wrong_password_and_unknown_user_look_identical(client):
    await register(client, "admin@acme-corp.com")
    wrong = await client.post("/auth/token", data={"username": "admin@acme-corp.com", "password": "x" * 12})
    unknown = await client.post("/auth/token", data={"username": "ghost@acme-corp.com", "password": "x" * 12})
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json() == unknown.json()  # no user enumeration


async def test_weak_password_rejected_and_not_echoed(client):
    r = await client.post("/auth/register", json={"org_name": "Acme", "email": "a@acme-corp.com", "password": "short"})
    assert r.status_code == 422
    assert "short" not in r.text


async def test_duplicate_email_conflict(client):
    await register(client, "admin@acme-corp.com")
    r = await client.post("/auth/register",
                          json={"org_name": "Other", "email": "admin@acme-corp.com", "password": STRONG_PASSWORD})
    assert r.status_code == 409


async def test_tampered_token_rejected(client):
    headers = await register(client, "admin@acme-corp.com")
    bad = {"Authorization": headers["Authorization"][:-3] + "abc"}
    r = await client.get("/auth/me", headers=bad)
    assert r.status_code == 401
    assert r.headers["www-authenticate"] == "Bearer"


async def test_rbac_submitter_cannot_manage_users(client):
    admin = await register(client, "admin@acme-corp.com")
    submitter = await add_user(client, admin, "sub@acme-corp.com", "submitter")
    r = await client.post("/users", headers=submitter,
                          json={"email": "x@acme-corp.com", "password": STRONG_PASSWORD, "role": "admin"})
    assert r.status_code == 403


async def test_login_rate_limited(make_client):
    client = await make_client(login_rate_per_minute=3)
    await register(client, "admin@acme-corp.com")  # uses 2 of the 3 allowed calls
    await login(client, "admin@acme-corp.com")
    r = await client.post("/auth/token", data={"username": "admin@acme-corp.com", "password": STRONG_PASSWORD})
    assert r.status_code == 429
    assert r.headers["retry-after"] == "60"


async def test_security_headers_present(client):
    r = await client.get("/health/live", headers={"X-Request-ID": "abc-123"})
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["x-request-id"] == "abc-123"
    assert "default-src 'none'" in r.headers["content-security-policy"]
