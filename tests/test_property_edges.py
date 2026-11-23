"""Parameterized edge cases for pure logic.

One table covers many inputs instead of one test function per value. This is the
cheap form of property-style testing: exhaustive over a chosen edge set.
"""
from __future__ import annotations

import pytest

from safety_layer.credential.egress import forbidden_ip, safe_host
from safety_layer.guards.redaction import redact
from safety_layer.policy.fingerprint import _normalise, fingerprint


@pytest.mark.unit
@pytest.mark.parametrize(
    "address,forbidden",
    [
        ("127.0.0.1", True), ("10.0.0.5", True), ("172.16.0.1", True),
        ("192.168.1.1", True), ("169.254.169.254", True), ("::1", True),
        ("100.64.0.1", True), ("140.82.112.3", False), ("8.8.8.8", False),
        ("not-an-ip", False),
    ],
)
def test_forbidden_ip_table(address: str, forbidden: bool) -> None:
    assert forbidden_ip(address) is forbidden


@pytest.mark.unit
@pytest.mark.parametrize(
    "host", ["localhost", "metadata", "metadata.google.internal", "127.0.0.1", "[::1]"]
)
def test_unsafe_hostnames_are_refused(host: str) -> None:
    assert safe_host(host) is False


@pytest.mark.unit
@pytest.mark.parametrize(
    "value,secret",
    [
        ("tok_abcdefghijklmnop", "token"),
        ("sk-abcdefghijklmnopqrst", "api_key"),
        ("ghp_abcdefghijklmnopqrst", "authorization"),
        ("user@example.com", "email"),
    ],
)
def test_key_based_redaction(value: str, secret: str) -> None:
    result = redact({secret: value})
    assert value not in str(result)


@pytest.mark.unit
@pytest.mark.parametrize(
    "a,b,equal",
    [
        ({"x": 1, "y": 2}, {"y": 2, "x": 1}, True),   # key order irrelevant
        ({"x": 1.0}, {"x": 1.0000000000001}, True),    # float precision
        ({"x": 1}, {"x": 2}, False),
    ],
)
def test_fingerprint_normalisation(a: dict, b: dict, equal: bool) -> None:
    assert (fingerprint("act", a) == fingerprint("act", b)) is equal
    assert _normalise(a) is not None


@pytest.mark.unit
@pytest.mark.parametrize("scope", ["", "tenant-a", "tenant-b"])
def test_scope_changes_the_key(scope: str) -> None:
    keys = {fingerprint("act", {"x": 1}, scope=s) for s in ("", "tenant-a", "tenant-b")}
    assert len(keys) == 3
