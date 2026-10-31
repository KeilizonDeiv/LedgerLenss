"""Dependency-injection wiring: sessions, current user, RBAC, pipeline."""
import uuid
from collections.abc import AsyncIterator
from typing import Annotated

import jwt
from fastapi import Depends, Request
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.errors import Forbidden, Unauthorized
from app.core.security import decode_access_token
from app.models import Role, User
from app.services.pipeline import DocumentPipeline
from app.services.storage import FileStorage

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")


def get_settings_dep(request: Request) -> Settings:
    return request.app.state.settings


async def get_session(request: Request) -> AsyncIterator[AsyncSession]:
    async with request.app.state.session_factory() as session:
        yield session


def get_storage(request: Request) -> FileStorage:
    return request.app.state.storage


def get_pipeline(request: Request) -> DocumentPipeline:
    st = request.app.state
    return DocumentPipeline(session_factory=st.session_factory, storage=st.storage, ai=st.ai_service, settings=st.settings)


SettingsDep = Annotated[Settings, Depends(get_settings_dep)]
SessionDep = Annotated[AsyncSession, Depends(get_session)]
StorageDep = Annotated[FileStorage, Depends(get_storage)]
PipelineDep = Annotated[DocumentPipeline, Depends(get_pipeline)]


async def get_current_user(session: SessionDep, settings: SettingsDep,
                           token: Annotated[str, Depends(oauth2_scheme)]) -> User:
    try:
        claims = decode_access_token(token, settings)
        user_id = uuid.UUID(claims["sub"])
    except (jwt.PyJWTError, ValueError, KeyError):
        raise Unauthorized() from None
    user = await session.get(User, user_id)
    # Re-check against the DB on every request: deactivated users and role changes take
    # effect immediately instead of waiting for token expiry.
    if user is None or not user.is_active or str(user.org_id) != claims.get("org"):
        raise Unauthorized()
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


def require_roles(*roles: Role):
    async def _check(user: CurrentUser) -> User:
        if user.role not in roles:
            raise Forbidden("Your role does not permit this action")
        return user

    return _check


AdminUser = Annotated[User, Depends(require_roles(Role.ADMIN))]
ReviewerUser = Annotated[User, Depends(require_roles(Role.ADMIN, Role.APPROVER))]
