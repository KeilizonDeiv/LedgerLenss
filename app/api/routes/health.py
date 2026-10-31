from fastapi import APIRouter
from sqlalchemy import text

from app.api.deps import SessionDep

router = APIRouter(prefix="/health", tags=["health"])


@router.get("/live")
async def live() -> dict[str, str]:
    """Liveness: the process is up (used by Docker/K8s to restart a hung container)."""
    return {"status": "ok"}


@router.get("/ready")
async def ready(session: SessionDep) -> dict[str, str]:
    """Readiness: dependencies reachable (used by load balancers to route traffic)."""
    await session.execute(text("SELECT 1"))
    return {"status": "ready"}
