"""Pre-processing of untrusted document text before it reaches the LLM.

Prompt injection can't be fully 'solved' with filters, so this is one layer of several:
  * normalise + strip invisible characters used to hide instructions
  * neutralise our own delimiter tags so the document can't 'close' its sandbox
  * heuristic detection -> raises a risk flag (never silently trusted)
  * the LLM has NO tools and NO authority: it only returns validated JSON, and
    approval is decided by deterministic code + a human.
"""
import re
import unicodedata

_DELIMITER = re.compile(r"<\s*/?\s*document\s*>", re.IGNORECASE)
_INJECTION_HINTS = re.compile(
    r"(?i)(ignore\s+(all\s+|any\s+)?(previous|prior|above)\s+(instructions|prompts|rules)"
    r"|disregard\s+(all|the|previous)\s+\w*\s*(instructions|rules)"
    r"|you\s+are\s+now|system\s+prompt|developer\s+mode"
    r"|(auto[-\s]?)?approve\s+this\s+(invoice|document|payment)"
    r"|mark\s+(this|it)\s+as\s+(approved|paid|compliant))"
)


def prepare_untrusted_text(text: str, max_chars: int) -> tuple[str, list[str]]:
    flags: list[str] = []
    text = unicodedata.normalize("NFKC", text)
    # Drop control (Cc) and format (Cf: zero-width, bidi overrides) chars, keep newlines/tabs.
    text = "".join(ch for ch in text if ch in "\n\t" or unicodedata.category(ch) not in ("Cc", "Cf"))
    text = _DELIMITER.sub("[tag removed]", text)
    if len(text) > max_chars:
        text = text[:max_chars]
        flags.append("truncated")
    if _INJECTION_HINTS.search(text):
        flags.append("injection_pattern")
    return text, flags
