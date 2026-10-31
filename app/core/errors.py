"""Domain exceptions -> consistent JSON error envelope.

Routes and services raise these instead of HTTPException so the service layer
stays framework-agnostic (it could be reused from a CLI or a queue worker).
"""


class DomainError(Exception):
    status_code = 400
    code = "bad_request"

    def __init__(self, message: str, *, headers: dict[str, str] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.headers = headers or {}


class Unauthorized(DomainError):
    status_code, code = 401, "unauthorized"

    def __init__(self, message: str = "Invalid or expired credentials") -> None:
        super().__init__(message, headers={"WWW-Authenticate": "Bearer"})


class Forbidden(DomainError):
    status_code, code = 403, "forbidden"


class NotFound(DomainError):
    status_code, code = 404, "not_found"


class Conflict(DomainError):
    status_code, code = 409, "conflict"


class PayloadTooLarge(DomainError):
    status_code, code = 413, "payload_too_large"


class UnsupportedFile(DomainError):
    status_code, code = 415, "unsupported_file"


class ValidationFailed(DomainError):
    status_code, code = 422, "validation_failed"


class RateLimited(DomainError):
    status_code, code = 429, "rate_limited"

    def __init__(self, retry_after: int = 60) -> None:
        super().__init__("Too many requests", headers={"Retry-After": str(retry_after)})


class PipelineError(Exception):
    """Expected processing failure with a message that is safe to show users."""

    def __init__(self, code: str, public_message: str) -> None:
        super().__init__(public_message)
        self.code = code
        self.public_message = public_message
