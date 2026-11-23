"""Credential custody: the agent holds a placeholder, never the real secret.

This is the model production agent platforms use. The secret is held here, the
agent receives an opaque placeholder in an environment variable, and a request
is allowed to carry the real value only when its destination is in the
credential's allow-list.

The design has two properties that are easy to lose:

- **The agent cannot read the secret.** It only ever sees the placeholder. Even
  a prompt-injected agent that prints its environment leaks a worthless token.
- **The proxy cannot be tricked into releasing a secret to another host.** The
  allow-list is checked on the destination, not on what the agent claims.

No vendor-specific knowledge lives here. The agent already writes the request
in the shape the vendor expects, including where the credential goes. This
module only replaces the placeholder value in place.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field, replace
from typing import Protocol

PLACEHOLDER_PREFIX = "safety-placeholder-"


class CredentialError(RuntimeError):
    """A credential could not be resolved or applied."""


class CredentialNotAllowed(CredentialError):
    """A placeholder was presented for a host it is not allowed for.

    This is an attack-shaped condition, not a configuration typo: the agent
    tried to spend a credential somewhere it was not scoped to. It must fail
    closed and leave a trace, never fall through as an ordinary header.
    """


class SecretResolver(Protocol):
    """Where a real secret comes from. The agent never has one of these."""

    def resolve(self, name: str) -> str: ...


class EnvSecretResolver:
    """Resolve from an environment variable, or a `file:` path with strict mode.

    This is the local/dev backend and the one the existing gateway already
    trusts. `--secret file:/path` refuses a group/world-readable file or one
    not owned by the current user, because a leaked secret file is the same
    failure regardless of which layer reads it.
    """

    def resolve(self, name: str) -> str:
        if name.startswith("file:"):
            path = name[5:]
            try:
                stat = os.stat(path)
            except FileNotFoundError:
                raise CredentialError(f"secret file not found: {path}") from None
            if stat.st_mode & 0o077:
                raise CredentialError(
                    f"secret file {path} must be 0600 (mode {oct(stat.st_mode & 0o777)})"
                )
            if stat.st_uid != os.geteuid():
                raise CredentialError(
                    f"secret file {path} must be owned by this user (uid {os.geteuid()})"
                )
            with open(path, encoding="utf-8") as handle:
                value = handle.read().strip()
        else:
            value = os.environ.get(name, "")
        if not value:
            raise CredentialError(f"upstream credential missing: {name}")
        return value


@dataclass(frozen=True)
class HttpSecretResolver:
    """Resolve through a secret manager's HTTP API (Vault-style).

    The library stays stdlib-only: this uses `urllib` and takes a transport so
    it can be tested without a live vault. The returned JSON is walked through
    `data.data` when present (the KV-v2 shape) and the requested field is read.

    The token is read from the environment on every call, so rotation does not
    require rebuilding the resolver.
    """

    base_url: str
    token_env: str
    field: str = "value"
    timeout: float = 5.0
    transport: Callable[[urllib.request.Request, float], bytes] | None = None

    def resolve(self, name: str) -> str:
        token = os.environ.get(self.token_env, "")
        if not token:
            raise CredentialError(f"secret manager token missing: {self.token_env}")
        request = urllib.request.Request(
            f"{self.base_url.rstrip('/')}/{name}",
            headers={"X-Vault-Token": token, "Accept": "application/json"},
            method="GET",
        )
        send = self.transport or _default_transport
        try:
            raw = send(request, self.timeout)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise CredentialError(f"secret manager unreachable for {name!r}: {exc}") from exc
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CredentialError("secret manager returned non-JSON") from exc
        if not isinstance(payload, dict):
            raise CredentialError("secret manager response was not an object")
        data = payload.get("data")
        if isinstance(data, dict) and isinstance(data.get("data"), dict):
            data = data["data"]
        value = data.get(self.field) if isinstance(data, dict) else None
        if not isinstance(value, str) or not value:
            raise CredentialError(f"secret {name!r} had no {self.field!r} field")
        return value


def _default_transport(request: urllib.request.Request, timeout: float) -> bytes:
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


@dataclass(frozen=True)
class CredentialRule:
    """One credential and the hosts it may be released to.

    ``secret_name`` is what the agent sees in its environment. ``secret`` is the
    real value, held only here. ``allowed_hosts`` is exact host names (optionally
    with a port), matching OpenAI's model: no wildcards, no schemes, no paths.
    """

    secret_name: str
    secret: str
    allowed_hosts: frozenset[str] = field(default_factory=frozenset)
    #: When set, the proxy injects this header rather than expecting the agent
    #: to place the placeholder itself. Useful for the reverse-proxy mode.
    header: str | None = None
    #: Expiry, for short-lived credentials minted by a secret manager.
    expires_at: float | None = None

    def allows(self, host: str) -> bool:
        return _normalise_host(host) in {_normalise_host(h) for h in self.allowed_hosts}

    def expired(self, *, now: float | None = None) -> bool:
        return self.expires_at is not None and (now or time.time()) > self.expires_at


def _normalise_host(host: str) -> str:
    """Lower-case, strip a trailing dot and a `:port` for exact matching."""
    value = host.strip().lower().rstrip(".")
    if value.startswith("["):  # IPv6 literal
        return value
    return value.rsplit(":", 1)[0] if value.count(":") == 1 else value


@dataclass
class PlaceholderVault:
    """Maps opaque placeholders to real credentials, scoped by host.

    The placeholder value is stable across rotation: the agent keeps using the
    same environment variable while the real secret changes behind it.
    """

    _rules: dict[str, CredentialRule] = field(default_factory=dict)
    _placeholder_for: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_rules(cls, rules: Iterable[CredentialRule]) -> PlaceholderVault:
        import secrets

        vault = cls()
        for rule in rules:
            placeholder = f"{PLACEHOLDER_PREFIX}{secrets.token_urlsafe(24)}"
            vault._rules[placeholder] = rule
            vault._placeholder_for[rule.secret_name] = placeholder
        return vault

    def agent_environment(self) -> dict[str, str]:
        """The values to hand the agent. Each is a worthless placeholder."""
        return dict(self._placeholder_for)

    def placeholders(self) -> tuple[str, ...]:
        return tuple(self._rules)

    def rotate(self, secret_name: str, secret: str, *, expires_at: float | None = None) -> None:
        """Replace the real value without changing the agent's placeholder."""
        placeholder = self._placeholder_for.get(secret_name)
        if placeholder is None:
            raise CredentialError(f"unknown credential: {secret_name}")
        old = self._rules[placeholder]
        self._rules[placeholder] = replace(old, secret=secret, expires_at=expires_at)

    def swap(
        self,
        headers: Mapping[str, str],
        host: str,
        *,
        now: float | None = None,
    ) -> dict[str, str]:
        """Replace any known placeholder in ``headers`` for an allowed host.

        A placeholder sent to a host it is not scoped to raises
        :class:`CredentialNotAllowed` — the agent is trying to spend a
        credential outside its grant. Unknown tokens are left alone; they may
        be ordinary header values, and treating them as attacks would make the
        proxy unusable.
        """
        result = dict(headers)
        for name, value in list(result.items()):
            if not isinstance(value, str):
                continue
            for placeholder, rule in self._rules.items():
                if placeholder not in value:
                    continue
                if not rule.allows(host):
                    raise CredentialNotAllowed(
                        f"credential {rule.secret_name!r} is not allowed for host {host!r}"
                    )
                if rule.expired(now=now):
                    raise CredentialError(f"credential {rule.secret_name!r} has expired")
                result[name] = value.replace(placeholder, rule.secret)
        return result

    def injected(
        self,
        headers: Mapping[str, str],
        host: str,
        *,
        now: float | None = None,
    ) -> dict[str, str]:
        """Swap placeholders and add any ``header``-mode credentials.

        Used by the reverse-proxy path, where the agent does not need to know
        where the credential goes: the rule names the header and the proxy
        fills it with the real value.
        """
        result = self.swap(headers, host, now=now)
        for rule in self._rules.values():
            if rule.header is None:
                continue
            if not rule.allows(host):
                continue
            if rule.expired(now=now):
                raise CredentialError(f"credential {rule.secret_name!r} has expired")
            result[rule.header] = f"Bearer {rule.secret}"
        return result


__all__ = [
    "CredentialError",
    "CredentialNotAllowed",
    "CredentialRule",
    "EnvSecretResolver",
    "HttpSecretResolver",
    "PlaceholderVault",
    "SecretResolver",
]
