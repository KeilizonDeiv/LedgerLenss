import logging
from typing import Annotated

from fastapi import APIRouter, Depends
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.api.deps import CurrentUser, SessionDep, SettingsDep
from app.core.errors import Conflict, Unauthorized
from app.core.ratelimit import rate_limit
from app.core.security import burn_verify_time, create_access_token, hash_password, verify_password
from app.models import Organization, Role, User
from app.schemas import RegisterRequest, TokenResponse, UserOut
from app.services import audit

router = APIRouter(prefix="/auth", tags=["auth"])
logger = logging.getLogger(__name__)
login_limit = Depends(rate_limit("login", "login_rate_per_minute"))


@router.post("/register", response_model=UserOut, status_code=201, dependencies=[login_limit])
async def register(body: RegisterRequest, session: SessionDep) -> User:
    """Create a new organization and its first admin (tenant onboarding)."""
    org = Organization(name=body.org_name.strip())
    session.add(org)
    await session.flush()
    user = User(org_id=org.id, email=body.email.lower(), password_hash=hash_password(body.password), role=Role.ADMIN)
    session.add(user)
    try:
        await session.flush()
    except IntegrityError:
        raise Conflict("An account with this email already exists") from None
    await audit.record(session, org_id=org.id, actor_id=user.id, action="org.created", target_type="organization",
                       target_id=org.id, details={"name": org.name})
    await session.commit()
    return user


@router.post("/token", response_model=TokenResponse, dependencies=[login_limit])
async def login(form: Annotated[OAuth2PasswordRequestForm, Depends()], session: SessionDep,
                settings: SettingsDep) -> TokenResponse:
    user = await session.scalar(select(User).where(User.email == form.username.lower()))
    if user is None:
        burn_verify_time(form.password)  # same timing whether or not the email exists
        raise Unauthorized("Incorrect email or password")
    if not verify_password(form.password, user.password_hash) or not user.is_active:
        await audit.record(session, org_id=user.org_id, actor_id=user.id, action="auth.login_failed",
                           target_type="user", target_id=user.id)
        await session.commit()
        raise Unauthorized("Incorrect email or password")  # identical message: no enumeration
    token, ttl = create_access_token(user_id=user.id, org_id=user.org_id, role=user.role, settings=settings)
    await audit.record(session, org_id=user.org_id, actor_id=user.id, action="auth.login", target_type="user",
                       target_id=user.id)
    await session.commit()
    return TokenResponse(access_token=token, expires_in=ttl)


@router.get("/me", response_model=UserOut)
async def me(user: CurrentUser) -> User:
    return user
