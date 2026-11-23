"""The effect key must not depend on when or where the claim was made."""

from __future__ import annotations

import pytest

from safety_layer.policy.fingerprint import fingerprint


def test_the_same_effect_produces_the_same_key() -> None:
    assert fingerprint("patch", {"app": "shop-api", "memory": "768Mi"}) == fingerprint(
        "patch", {"app": "shop-api", "memory": "768Mi"}
    )


def test_argument_order_does_not_change_the_key() -> None:
    """`{"a":1,"b":2}` and `{"b":2,"a":1}` are the same claim.

    Argument order is an accident of how a caller wrote the call. If it changed
    the key, two workers building the same call differently would each execute.
    """
    assert fingerprint("patch", {"a": 1, "b": 2}) == fingerprint("patch", {"b": 2, "a": 1})


def test_float_drift_does_not_change_the_key() -> None:
    """A value that has been through a decimal round-trip is still the same."""
    assert fingerprint("charge", {"amount": 19.99}) == fingerprint("charge", {"amount": 19.990000000001})


def test_genuinely_different_floats_do_not_share_a_key() -> None:
    """Rounding must remove drift, not merge two real amounts."""
    assert fingerprint("charge", {"amount": 19.99}) != fingerprint("charge", {"amount": 19.98})


def test_negative_zero_and_zero_agree() -> None:
    assert fingerprint("set", {"delta": -0.0}) == fingerprint("set", {"delta": 0.0})


def test_a_different_action_is_a_different_effect() -> None:
    """"delete" and "archive" on one path are two effects, not one."""
    assert fingerprint("delete", {"path": "/tmp/x"}) != fingerprint("archive", {"path": "/tmp/x"})


def test_scope_separates_otherwise_identical_effects() -> None:
    """Two tenants issuing the same action must not collide.

    Without this, the second tenant's action is silently suppressed as a
    duplicate of the first, which is a wrong answer rather than a slow one.
    """
    assert fingerprint("patch", {"app": "x"}, scope="tenant-a") != fingerprint(
        "patch", {"app": "x"}, scope="tenant-b"
    )


def test_identity_fields_excludes_arguments_that_are_not_the_effect() -> None:
    """A changing body does not make a new effect if the effect is the title."""
    first = fingerprint(
        "create_issue", {"owner": "acme", "title": "Bug", "body": "draft one"},
        identity_fields=["owner", "title"],
    )
    second = fingerprint(
        "create_issue", {"owner": "acme", "title": "Bug", "body": "draft two"},
        identity_fields=["owner", "title"],
    )
    assert first == second


def test_identity_fields_ignores_arguments_it_was_not_given() -> None:
    """The escape hatch cannot silently widen the key."""
    with pytest.raises(ValueError, match="identity_fields"):
        fingerprint("patch", {"app": "x"}, identity_fields=["app", "missing"])


def test_nested_structures_are_canonicalised() -> None:
    left = fingerprint("patch", {"spec": {"limits": {"cpu": 1, "memory": 2}, "replicas": 3}})
    right = fingerprint("patch", {"spec": {"replicas": 3, "limits": {"memory": 2, "cpu": 1}}})
    assert left == right


def test_a_set_argument_is_ordered_before_hashing() -> None:
    """A set has no order of its own; two claims built from one must agree."""
    assert fingerprint("tag", {"labels": {"b", "a"}}) == fingerprint("tag", {"labels": {"a", "b"}})


def test_no_arguments_is_a_valid_effect() -> None:
    assert fingerprint("flush") == fingerprint("flush", {})


def test_an_unrepresentable_value_still_yields_a_stable_key() -> None:
    """A caller passing an exotic object still gets a reviewable key."""
    class Opaque:
        def __repr__(self) -> str:
            return "<opaque>"

    assert fingerprint("patch", {"thing": Opaque()}) == fingerprint("patch", {"thing": Opaque()})


def test_the_key_is_short_enough_to_read_in_a_log_line() -> None:
    assert len(fingerprint("patch", {"app": "x"})) == 32


def test_unicode_survives_encoding_identically() -> None:
    assert fingerprint("tag", {"name": "café"}) == fingerprint("tag", {"name": "café"})
