"""Secret and PII redaction applied before evidence is persisted.

Key-based redaction is authoritative: a value is secret because of the field it
sits in, not because of how it happens to look. Value-based redaction is limited
to credential shapes that are secrets by construction, because a generic "long
string" heuristic also matches every uuid, idempotency key and provider
reference the product depends on for evidence.
"""

import re
from collections.abc import Mapping
from typing import Any

_SECRET_KEYS = re.compile(
    r"(api[_-]?key|authorization|password|passwd|secret|token|access[_-]?token|refresh[_-]?token)",
    re.IGNORECASE,
)
_PII_KEYS = re.compile(
    r"(email|phone|telephone|mobile|ssn|social[_-]?security|address|dob|date[_-]?of[_-]?birth)",
    re.IGNORECASE,
)
_EMAIL = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
_BEARER = re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]+\b", re.IGNORECASE)
# Credential shapes only. A bare "32+ alphanumeric characters" heuristic also
# matches every uuid, idempotency key and provider reference the product relies
# on for evidence, so those are deliberately not redacted.
_VENDOR_TOKEN = re.compile(
    r"\b(?:"
    r"sk-[A-Za-z0-9]{16,}"              # OpenAI-style
    r"|gh[pousr]_[A-Za-z0-9]{16,}"      # GitHub tokens
    r"|AKIA[0-9A-Z]{16}"                # AWS access key ids
    r"|AIza[A-Za-z0-9_-]{35}"           # Google API keys
    r"|xox[abprs]-[A-Za-z0-9-]{10,}"    # Slack
    r")\b"
)


def redact(value: Any, *, _key: str | None = None) -> Any:
    """Recursively redact common secrets and direct PII before persistence."""
    if _key and _SECRET_KEYS.search(_key):
        return "[REDACTED_SECRET]"
    if _key and _PII_KEYS.search(_key):
        return "[REDACTED_PII]"

    if isinstance(value, Mapping):
        return {str(k): redact(v, _key=str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact(item) for item in value)
    if isinstance(value, str):
        text = _EMAIL.sub("[REDACTED_EMAIL]", value)
        text = _BEARER.sub("Bearer [REDACTED_SECRET]", text)
        # Do NOT apply a generic "long string" heuristic here. Durable evidence
        # depends on identifiers: run_ids, intent keys, provider references and
        # replay links are all 32+ characters, and redacting them destroys the
        # ability to join a trace back to its own row. Value-based redaction is
        # limited to shapes that are credentials by construction.
        return _VENDOR_TOKEN.sub("[REDACTED_SECRET]", text)
    return value
