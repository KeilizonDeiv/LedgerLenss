"""Application factory (composition root).

All concrete implementations (DB engine, storage, AI provider) are created and wired
here, and nowhere else. Tests call create_app() with their own settings and a fake
AIService. Run with: uvicorn app.main:create_app --factory
"""
import logging
import re
import time
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.ai.providers import build_chat_model
from app.ai.service import AIService, LangChainAIService
from app.api.routes import admin, auth, documents, health
from app.core.config import Settings, get_settings
from app.core.errors import DomainError
from app.core.logging import configure_logging, request_id_ctx
from app.db.session import create_engine_and_sessionmaker
from app.services.storage import LocalFileStorage

logger = logging.getLogger("ledgerlens")
_SAFE_REQUEST_ID = re.compile(r"^[A-Za-z0-9\-]{1,64}$")


def _error(status: int, code: str, message: str, headers: dict[str, str] | None = None, **extra) -> JSONResponse:
    return JSONResponse(status_code=status, content={"error": {"code": code, "message": message, **extra}},
                        headers=headers)


def create_app(settings: Settings | None = None, *, ai_service: AIService | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_level)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        engine, session_factory = create_engine_and_sessionmaker(settings.database_url)
        app.state.engine = engine
        app.state.session_factory = session_factory
        app.state.storage = LocalFileStorage(settings.storage_dir)
        app.state.ai_service = ai_service or LangChainAIService(build_chat_model(settings))
        app.state.rate_limiters = {}
        logger.info("started env=%s llm_provider=%s model=%s", settings.env, settings.llm_provider, settings.llm_model)
        yield
        await engine.dispose()

    docs = settings.enable_docs and settings.env != "prod"
    app = FastAPI(title=settings.app_name, version="1.0.0", lifespan=lifespan,
                  description="AI-powered accounts-payable invoice processing API",
                  docs_url="/docs" if docs else None, redoc_url=None, openapi_url="/openapi.json" if docs else None)
    app.state.settings = settings

    if settings.cors_origins:  # explicit allow-list only; never "*" with credentials
        app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origins, allow_credentials=True,
                           allow_methods=["GET", "POST", "PUT"], allow_headers=["Authorization", "Content-Type"])

    @app.middleware("http")
    async def request_context(request: Request, call_next):
        incoming = request.headers.get("x-request-id", "")
        request_id = incoming if _SAFE_REQUEST_ID.match(incoming) else uuid.uuid4().hex  # no log injection
        token = request_id_ctx.set(request_id)
        started = time.perf_counter()
        try:
            try:
                response = await call_next(request)
            except Exception:  # unhandled -> generic 500; details stay in logs
                logger.exception("unhandled error on %s %s", request.method, request.url.path)
                response = _error(500, "internal_error", "Internal server error", request_id=request_id)
            response.headers["X-Request-ID"] = request_id
            response.headers.setdefault("X-Content-Type-Options", "nosniff")
            response.headers.setdefault("X-Frame-Options", "DENY")
            response.headers.setdefault("Referrer-Policy", "no-referrer")
            response.headers.setdefault("Cache-Control", "no-store")  # invoices must not sit in shared caches
            if not request.url.path.startswith(("/docs", "/openapi")):
                response.headers.setdefault("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
            if settings.env == "prod":
                response.headers.setdefault("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
            logger.info("%s %s -> %s (%.1f ms)", request.method, request.url.path, response.status_code,
                        (time.perf_counter() - started) * 1000)
            return response
        finally:
            request_id_ctx.reset(token)

    @app.exception_handler(DomainError)
    async def domain_error_handler(_: Request, exc: DomainError) -> JSONResponse:
        return _error(exc.status_code, exc.code, exc.message, headers=exc.headers)

    @app.exception_handler(RequestValidationError)
    async def validation_handler(_: Request, exc: RequestValidationError) -> JSONResponse:
        # Strip 'input' so submitted passwords are never echoed back in error bodies.
        fields = [{"loc": list(e["loc"]), "msg": e["msg"]} for e in exc.errors()]
        return _error(422, "validation_failed", "Request validation failed", fields=fields)

    for module in (health, auth, admin, documents):
        app.include_router(module.router)
    return app
