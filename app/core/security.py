"""Password hashing (Argon2id) and JWT access tokens."""
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

from app.core.config import Settings

# Argon2id = memory-hard, winner of the Password Hashing Competition, OWASP's #1 pick.
_hasher = PasswordHasher()
# Used to burn the same CPU time when the email doesn't exist -> prevents
# user enumeration via response-time differences.
_DUMMY_HASH = _hasher.hash("timing-equalizer-not-a-real-password")


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except (VerificationError, InvalidHashError):
        return False


def burn_verify_time(password: str) -> None:
    verify_password(password, _DUMMY_HASH)


def create_access_token(*, user_id: uuid.UUID, org_id: uuid.UUID, role: str, settings: Settings) -> tuple[str, int]:
    now = datetime.now(UTC)
    ttl = settings.access_token_minutes * 60
    claims = {
        "sub": str(user_id),
        "org": str(org_id),
        "role": role,  # informational only; authorization re-reads the role from the DB
        "iat": now,
        "exp": now + timedelta(seconds=ttl),
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "jti": uuid.uuid4().hex,  # unique id -> enables a revocation list later
    }
    token = jwt.encode(claims, settings.jwt_secret.get_secret_value(), algorithm=settings.jwt_algorithm)
    return token, ttl


def decode_access_token(token: str, settings: Settings) -> dict[str, Any]:
    """Raises jwt.PyJWTError on any problem. `algorithms` is pinned to stop alg-confusion attacks."""
    return jwt.decode(
        token,
        settings.jwt_secret.get_secret_value(),
        algorithms=[settings.jwt_algorithm],
        audience=settings.jwt_audience,
        issuer=settings.jwt_issuer,
        options={"require": ["exp", "iat", "sub", "org", "iss", "aud"]},
    )
