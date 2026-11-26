"""A stable identity for an effect, independent of run and attempt.

A key built from the run and step (`{run_id}:{step_id}`) is unique per run, so it
cannot deduplicate: a retry after a crash or a second worker gets a new run and
a different key.

This module produces a key from what the action *is* rather than when it was
attempted. Two claims of the same effect produce the same key, on any host, in
any run, across any number of workers. A unique constraint on that key is then
sufficient to guarantee the effect happens once.

The assumption this rests on is that identical normalised arguments mean an
identical effect. That holds for most tools and fails for a few -- "send the
reminder now" is the same call a minute apart but not the same intent.
`identity_fields` is the escape hatch: name the arguments that actually define
the effect and the rest is excluded from the hash.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from typing import Any

#: Truncated sha256. 32 hex chars is 128 bits, which makes an accidental
#: collision between two distinct effects negligible for the volumes one agent
#: run can produce, while keeping the key short enough to read in a log line
#: and to compare by eye.
_KEY_LENGTH = 32

#: Floats are rounded before hashing because the same logical value does not
#: always round-trip identically: a JSON body that has been through a decimal
#: parse and re-serialise can differ in the last place, and two workers
#: computing "the same" value can disagree. Twelve significant digits is far
#: beyond any precision a real action depends on, so it removes the drift
#: without merging two genuinely different values.
_FLOAT_PRECISION = 12


def _normalise(value: Any) -> Any:
    """Reduce a value to a canonical JSON-representable form.

    Dictionaries are rebuilt with sorted keys so that argument order, which is
    an accident of how a caller wrote the call, cannot change the key. Floats
    are rounded. Containers become lists. Anything the JSON encoder cannot
    represent becomes its `repr`, which is lossy but stable within a process --
    and a caller passing an exotic object into a destructive tool is already in
    territory where a stable, reviewable key matters more than an exact one.
    """
    if isinstance(value, bool) or value is None or isinstance(value, (int, str)):
        return value
    if isinstance(value, float):
        # Significant digits, not decimal places: `round(x, 12)` leaves a value
        # like 19.990000000001 untouched because it has only twelve places
        # already, and the drift survives. `%.12g` keeps twelve significant
        # digits regardless of magnitude, which is what the comment above
        # describes. The `+ 0.0` normalises -0.0 to 0.0.
        return float(f"{value:.{_FLOAT_PRECISION}g}") + 0.0
    if isinstance(value, Mapping):
        return {str(k): _normalise(value[k]) for k in sorted(value, key=str)}
    if isinstance(value, (list, tuple)):
        return [_normalise(item) for item in value]
    if isinstance(value, (set, frozenset)):
        # A set has no order of its own, so it is sorted before hashing.
        return sorted((_normalise(item) for item in value), key=repr)
    return repr(value)


def fingerprint(
    action: str,
    arguments: Mapping[str, Any] | None = None,
    *,
    scope: str = "",
    identity_fields: Iterable[str] = (),
) -> str:
    """Return the stable identity of one effect.

    `action` is included because two different actions with identical arguments
    are still two different effects -- "delete" and "archive" on the same path.

    `scope` separates otherwise-identical effects across tenants, principals or
    workflows. It defaults to empty, which means every caller shares one
    namespace: correct for a single-tenant deployment and wrong for a shared
    one, because two tenants issuing the same action would collide and the
    second would be silently suppressed. Any deployment serving more than one
    tenant must pass one.

    `identity_fields` names the arguments that define the effect. When empty,
    all of them are used.
    """
    payload = dict(arguments or {})
    fields = tuple(identity_fields)
    if fields:
        unknown = [name for name in fields if name not in payload]
        if unknown:
            raise ValueError(
                f"identity_fields names arguments that were not supplied: "
                f"{', '.join(sorted(unknown))}"
            )
        payload = {name: payload[name] for name in fields}

    canonical = json.dumps(
        {"action": action, "scope": scope, "arguments": _normalise(payload)},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:_KEY_LENGTH]
