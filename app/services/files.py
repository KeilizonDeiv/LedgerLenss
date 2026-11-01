"""Upload validation and text extraction.

Rules: never trust the client's filename, extension or Content-Type. Identify files
by magic bytes, cap size while streaming, cap PDF pages, reject encrypted PDFs.
"""
import hashlib
import io
import re
from dataclasses import dataclass
from pathlib import PurePosixPath

from fastapi import UploadFile
from pypdf import PdfReader
from pypdf.errors import PdfReadError

from app.core.errors import PayloadTooLarge, PipelineError, UnsupportedFile, ValidationFailed

PDF = "application/pdf"
TEXT = "text/plain"
_IMAGE_SIGNATURES = (b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff", b"GIF8", b"II*\x00", b"MM\x00*")
_UNSAFE_NAME_CHARS = re.compile(r"[\x00-\x1f\x7f<>:\"|?*]")


@dataclass(frozen=True)
class ValidatedFile:
    data: bytes
    sha256: str
    content_type: str
    extension: str
    safe_name: str


async def read_limited(upload: UploadFile, max_bytes: int) -> bytes:
    """Stream the upload in chunks and abort as soon as the cap is exceeded.
    (Also cap body size at the reverse proxy — e.g. nginx client_max_body_size —
    because the multipart parser spools the body before this runs.)"""
    chunks, total = [], 0
    while chunk := await upload.read(64 * 1024):
        total += len(chunk)
        if total > max_bytes:
            raise PayloadTooLarge(f"File exceeds {max_bytes // (1024 * 1024)} MB limit")
        chunks.append(chunk)
    return b"".join(chunks)


def sanitize_filename(name: str | None) -> str:
    base = PurePosixPath((name or "").replace("\\", "/")).name  # drops ../ and directories
    base = _UNSAFE_NAME_CHARS.sub("", base).strip().strip(".")
    return base[:255] or "upload"


def sniff_content_type(data: bytes) -> str:
    if data.startswith(b"%PDF-"):
        return PDF
    if data.startswith(_IMAGE_SIGNATURES):
        raise UnsupportedFile("Image invoices need OCR, which is not enabled. Upload a PDF with a text layer or a .txt file.")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise UnsupportedFile("Only PDF and UTF-8 text files are accepted") from None
    if "\x00" in text:
        raise UnsupportedFile("Binary content is not accepted")
    return TEXT


def validate_upload(data: bytes, filename: str | None) -> ValidatedFile:
    if not data:
        raise ValidationFailed("File is empty")
    content_type = sniff_content_type(data)
    return ValidatedFile(
        data=data,
        sha256=hashlib.sha256(data).hexdigest(),
        content_type=content_type,
        extension="pdf" if content_type == PDF else "txt",
        safe_name=sanitize_filename(filename),
    )


def extract_text(data: bytes, content_type: str, max_pages: int) -> str:
    """CPU-bound: call via asyncio.to_thread so the event loop stays responsive."""
    if content_type == TEXT:
        return data.decode("utf-8")
    try:
        reader = PdfReader(io.BytesIO(data))
        if reader.is_encrypted:
            raise PipelineError("ENCRYPTED_PDF", "Encrypted PDFs are not supported")
        if len(reader.pages) > max_pages:
            raise PipelineError("TOO_MANY_PAGES", f"PDF exceeds {max_pages} pages")
        return "\n".join(page.extract_text() or "" for page in reader.pages)
    except PdfReadError as exc:
        raise PipelineError("CORRUPT_PDF", "The PDF could not be parsed") from exc
