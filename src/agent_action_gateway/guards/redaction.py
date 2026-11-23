"""Secret and PII redaction applied before evidence is persisted.

Key-based redaction is authoritative: a value is secret because of the field it
sits in, not because of how it happens to look. Value-based redaction is limited
to credential and payment shapes that are sensitive by construction.

The counter-test matters as much as the rule. A generic "32+ alphanumeric
characters" heuristic also matches every uuid, idempotency key and provider
reference the product depends on for evidence. Destroying those would make the
trace useless for the one job it has: proving what happened. So identifiers are
deliberately preserved, and payment data is caught by a Luhn check rather than
by digit count.
"""

from __future__ import annotations

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
# Payment and identity fields. Key-based, so a card stored under an unexpected
# name is still caught by the value patterns below.
_PAYMENT_KEYS = re.compile(
    r"(^|_|\b)(card|card_?number|cc_?number|ccid|cvv|cvv2|cvc|cvn|"
    r"iban|pan|pan_?number|routing_?number|account_?number|acct_?number|"
    r"sort_?code|swift|bic|taxpayer_?id|national_?id|passport)"
    r"($|_|\b)",
    re.IGNORECASE,
)
# Names are only caught by key. Detecting them by shape would redact ordinary
# words and break the evidence the traces exist to hold.
_NAME_KEYS = re.compile(r"^(full_?name|first_?name|last_?name|surname|given_?name)$", re.IGNORECASE)

_EMAIL = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
_BEARER = re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]+\b", re.IGNORECASE)
# Credential shapes only.
_VENDOR_TOKEN = re.compile(
    r"\b(?:"
    r"sk-[A-Za-z0-9]{16,}"              # OpenAI-style
    r"|gh[pousr]_[A-Za-z0-9]{16,}"      # GitHub tokens
    r"|AKIA[0-9A-Z]{16}"                # AWS access key ids
    r"|AIza[A-Za-z0-9_-]{35}"           # Google API keys
    r"|xox[abprs]-[A-Za-z0-9-]{10,}"    # Slack
    r")\b"
)
# Digit runs that could be a payment card. Validated by Luhn before redacting so
# ordinary long identifiers are left alone.
# A candidate must not touch a letter, a digit or a dash. Letters matter because
# identifiers such as UUIDs hold runs of digits next to hex letters, and about one
# in 650 random UUIDs held a run that looked like a card and was redacted, which
# destroyed the identifier the trace exists to keep.
_CARD_CANDIDATE = re.compile(r"(?<![A-Za-z0-9-])(\d[\d -]{11,25}\d)(?![A-Za-z0-9-])")
_IBAN = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b")
_SSN = re.compile(r"(?<![\d-])\d{3}-\d{2}-\d{4}(?![\d-])")

REDACTED_SECRET = "[REDACTED_SECRET]"
REDACTED_PII = "[REDACTED_PII]"
REDACTED_PAN = "[REDACTED_PAN]"


def luhn_valid(digits: str) -> bool:
    """Standard mod-10 check. Used to tell a card number from an identifier."""
    cleaned = re.sub(r"[ -]", "", digits)
    if not cleaned.isdigit() or not (13 <= len(cleaned) <= 19):
        return False
    total = 0
    for index, character in enumerate(reversed(cleaned)):
        value = int(character)
        if index % 2 == 1:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def _redact_card_numbers(text: str) -> str:
    def replace(match: re.Match[str]) -> str:
        return REDACTED_PAN if luhn_valid(match.group(1)) else match.group(0)

    return _CARD_CANDIDATE.sub(replace, text)


def redact(value: Any, *, _key: str | None = None) -> Any:
    """Recursively redact secrets, PII and payment data before persistence."""
    if _key:
        if _SECRET_KEYS.search(_key):
            return REDACTED_SECRET
        if _NAME_KEYS.match(_key):
            return REDACTED_PII
        if _PAYMENT_KEYS.search(_key):
            return REDACTED_PAN if _is_cardish(value) else REDACTED_SECRET
        if _PII_KEYS.search(_key):
            return REDACTED_PII

    if isinstance(value, Mapping):
        return {str(k): redact(v, _key=str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact(item) for item in value)
    if isinstance(value, str):
        text = _EMAIL.sub("[REDACTED_EMAIL]", value)
        text = _BEARER.sub(f"Bearer {REDACTED_SECRET}", text)
        text = _redact_card_numbers(text)
        text = _IBAN.sub(REDACTED_SECRET, text)
        text = _SSN.sub(REDACTED_PII, text)
        return _VENDOR_TOKEN.sub(REDACTED_SECRET, text)
    return value


def _is_cardish(value: Any) -> bool:
    """A payment field holds a card number rather than an account or token."""
    if isinstance(value, str):
        return luhn_valid(value)
    return False
