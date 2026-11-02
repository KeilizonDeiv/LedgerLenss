# ---- build stage: compile wheels (build tools never reach the runtime image) ----
FROM python:3.12-slim AS build
WORKDIR /build
COPY requirements.txt .
RUN pip wheel --no-cache-dir --wheel-dir /wheels -r requirements.txt

# ---- runtime stage ----
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app

# Non-root user: a container escape or RCE doesn't start with root.
RUN groupadd --system app && useradd --system --gid app --home /app app
COPY --from=build /wheels /wheels
RUN pip install --no-index /wheels/* && rm -rf /wheels

COPY --chown=app:app app ./app
COPY --chown=app:app migrations ./migrations
COPY --chown=app:app alembic.ini ./
RUN mkdir -p /data/uploads && chown -R app:app /data

USER app
ENV LL_STORAGE_DIR=/data/uploads
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health/live')" || exit 1

# Migrate, then exec (PID 1 = uvicorn, so SIGTERM triggers graceful shutdown).
CMD ["sh", "-c", "alembic upgrade head && exec uvicorn app.main:create_app --factory --host 0.0.0.0 --port 8000 --proxy-headers"]
