"""Egress policy: the decision made on an outbound request before it leaves.

This module is transport-agnostic. It does not care whether the request arrived
through a reverse proxy, a forward proxy or an MCP tool call — it answers one
question: may this request go out, and with which credential substituted?

Keeping the decision separate from the socket handling is what makes it
testable without a live proxy, and what lets the same rules be enforced by
every door in the system.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from agent_action_gateway.credential.credentials import (
    CredentialError,
    CredentialNotAllowed,
    PlaceholderVault,
)

# Destinations that must never be reached, even if an allow-list would permit
# the hostname. Cloud metadata, loopback and private ranges are the classic
# SSRF/DNS-rebinding payoff, and a hostname in an allow-list can still resolve
# to one of them.
_FORBIDDEN_NETWORKS = tuple(
    ipaddress.ip_network(cidr)
    for cidr in (
        "127.0.0.0/8",
        "::1/128",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",  # cloud metadata (incl. 169.254.169.254)
        "100.64.0.0/10",  # CGNAT
        "0.0.0.0/8",
        "fc00::/7",
        "fe80::/10",
    )
)
_FORBIDDEN_HOSTNAMES = frozenset({"localhost", "metadata", "metadata.google.internal"})


class EgressDenied(RuntimeError):
    """The request is not allowed to leave."""


def forbidden_ip(address: str) -> bool:
    """Whether a literal IP is one no agent request should ever reach."""
    candidate = address.strip()
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]  # bracketed IPv6 literal, e.g. "[::1]"
    try:
        ip = ipaddress.ip_address(candidate)
    except ValueError:
        return False
    return any(ip in network for network in _FORBIDDEN_NETWORKS)


def safe_host(host: str, *, dns: Callable[[str], list[str]] | None = None) -> bool:
    """Reject loopback/private/metadata destinations, literal or via DNS.

    ``dns`` is injectable so this is testable without real DNS. When it is
    omitted, only literal IPs are checked — resolution happens at connect time
    in the proxy, which applies this same check to the address it dials.
    """
    lowered = host.strip().lower().rstrip(".")
    if lowered in _FORBIDDEN_HOSTNAMES:
        return False
    if forbidden_ip(lowered):
        return False
    if dns is not None:
        try:
            for address in dns(host):
                if forbidden_ip(address):
                    return False
        except (OSError, socket.gaierror):
            return False
    return True


@dataclass(frozen=True)
class EgressDecision:
    allowed: bool
    host: str
    reason: str
    headers: dict[str, str] | None = None


class EgressPolicy:
    """Host allow-list + credential substitution + audit, in one decision.

    ``allowed_hosts`` is the set of destinations the workload may reach at all
    (the network boundary's policy expressed in software). ``vault`` decides
    which credentials may be released to each host. Both must agree for a
    request to pass — a host on the network allow-list with no matching
    credential is still allowed to go out, just without a secret attached.
    """

    def __init__(
        self,
        vault: PlaceholderVault,
        allowed_hosts: frozenset[str] | None = None,
        *,
        audit: Callable[[Mapping[str, Any]], None] | None = None,
        dns: Callable[[str], list[str]] | None = None,
        inject_headers: bool = True,
    ) -> None:
        self.vault = vault
        self.allowed_hosts = allowed_hosts or frozenset()
        self.audit = audit
        self.dns = dns
        self.inject_headers = inject_headers

    @classmethod
    def from_hosts(cls, hosts: Iterable[str], vault: PlaceholderVault, **kwargs: Any) -> EgressPolicy:
        return cls(vault, frozenset(hosts), **kwargs)

    def _host_allowed(self, host: str) -> bool:
        if not self.allowed_hosts:
            return False
        from agent_action_gateway.credential.credentials import _normalise_host

        target = _normalise_host(host)
        return target in {_normalise_host(h) for h in self.allowed_hosts}

    def decide(
        self,
        host: str,
        headers: Mapping[str, str] | None = None,
        *,
        now: float | None = None,
    ) -> EgressDecision:
        """Return the decision without raising. Always audited, never logs a secret."""
        headers = dict(headers or {})
        outcome: EgressDecision
        if not safe_host(host, dns=self.dns):
            outcome = EgressDecision(False, host, "forbidden destination")
        elif not self._host_allowed(host):
            outcome = EgressDecision(False, host, "host not in allow-list")
        else:
            try:
                swapped = (
                    self.vault.injected(headers, host, now=now)
                    if self.inject_headers
                    else self.vault.swap(headers, host, now=now)
                )
            except CredentialNotAllowed as exc:
                outcome = EgressDecision(False, host, str(exc))
            except CredentialError as exc:
                outcome = EgressDecision(False, host, str(exc))
            else:
                outcome = EgressDecision(True, host, "allowed", headers=swapped)

        if self.audit is not None:
            # Headers are deliberately NOT audited: they carry the real secret
            # after the swap. Only the decision and its reason are evidence.
            self.audit({"host": outcome.host, "allowed": outcome.allowed, "reason": outcome.reason})
        return outcome

    def enforce(self, host: str, headers: Mapping[str, str] | None = None) -> dict[str, str]:
        """Like :meth:`decide` but raise on refusal. Returns the outbound headers."""
        decision = self.decide(host, headers)
        if not decision.allowed:
            raise EgressDenied(decision.reason)
        return decision.headers or {}


__all__ = ["EgressDecision", "EgressDenied", "EgressPolicy", "forbidden_ip", "safe_host"]
