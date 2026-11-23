"""Both backends must behave identically, asserted rather than assumed.

The claim this file exists to make is "swap `--db` to a `postgres://` URL and
nothing changes". A claim like that is worthless unless something checks it, so
every assertion below runs twice -- once against SQLite, once against PostgreSQL
-- and compares the observable results.

PostgreSQL is only exercised when `SAFETY_TEST_POSTGRES` is set, because CI
should not require a database service. When it is unset the PostgreSQL half
skips loudly rather than quietly passing, which would make this file decorative.

Run it with:
    docker run -d --name pgt -e POSTGRES_PASSWORD=pw -e POSTGRES_DB=safety \\
        -p 55432:5432 postgres:16-alpine
    SAFETY_TEST_POSTGRES=postgresql://postgres:pw@127.0.0.1:55432/safety \\
        python -m pytest tests/test_backend_agreement.py -v
"""

from __future__ import annotations

import os
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from safety_layer.policy.fingerprint import fingerprint
from safety_layer.policy.locks import ApprovalStore
from safety_layer.runtime.records import GateVerdict, TraceEvent
from safety_layer.storage.traces import TraceStore

POSTGRES_DSN = os.environ.get("SAFETY_TEST_POSTGRES", "")


def backends() -> list[tuple[str, str]]:
    """(name, target) for each backend under test.

    SQLite uses a fresh file per backend entry; PostgreSQL uses a fresh schema
    per entry, since both cannot share one database and see each other's rows.
    """
    found = [("sqlite", ":memory:")]
    if POSTGRES_DSN:
        found.append(("postgres", POSTGRES_DSN))
    return found


def fresh_target(name: str, index: int) -> str:
    if name == "sqlite":
        directory = tempfile.mkdtemp(prefix="agreement-")
        return str(Path(directory) / f"runtime-{index}.db")
    # A separate schema keeps stores from colliding on table names. Built by
    # parsing the URL rather than slicing on "//", which loses the scheme.
    import urllib.parse

    import psycopg

    schema = f"agreement_{index}"
    parsed = urllib.parse.urlparse(POSTGRES_DSN)
    scoped = urllib.parse.urlunparse(parsed._replace(path=f"/{parsed.path.lstrip('/')}"))
    # Created on the *same* database the store will connect to. Creating it on a
    # maintenance database would leave the store pointing at a schema that does
    # not exist there, which fails as "no schema has been selected".
    with psycopg.connect(scoped, autocommit=True) as connection:
        connection.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        connection.execute(f'CREATE SCHEMA "{schema}"')
    return f"{scoped}?options=-csearch_path%3D{schema}"


class BackendAgreementTest(unittest.TestCase):
    """Every method runs on both engines and both answers are compared."""

    maxDiff = None

    def _run_on_both(self, body) -> None:
        results = []
        for index, (name, _target) in enumerate(backends()):
            target = fresh_target(name, index)
            try:
                results.append((name, body(target)))
            except Exception as exc:  # surfaced rather than swallowed
                results.append((name, f"RAISED {type(exc).__name__}: {exc}"))
        if len(results) < 2:
            self.skipTest("set SAFETY_TEST_POSTGRES to compare backends")
        first, second = results
        self.assertEqual(
            first[1],
            second[1],
            f"sqlite and postgres disagree\n  sqlite: {first[1]!r}\n  postgres: {second[1]!r}",
        )

    # -- schema -----------------------------------------------------------

    def test_the_same_migrations_apply(self) -> None:
        def body(target: str) -> Any:
            return TraceStore(target).applied_migrations()

        self._run_on_both(body)

    def test_reopening_does_not_re_apply_migrations(self) -> None:
        def body(target: str) -> Any:
            store = TraceStore(target)
            before = store.applied_migrations()
            return before == TraceStore(target).applied_migrations()

        self._run_on_both(body)

    # -- traces -----------------------------------------------------------

    def test_a_trace_round_trips_with_every_column(self) -> None:
        def body(target: str) -> Any:
            store = TraceStore(target)
            store.append_trace(
                TraceEvent(
                    "run-1", 3, "agent", {"order_id": "ORD-1"}, {"status": "ok"},
                    "completed", flags=("a",), provider_metadata={"model": "m"},
                    provider_evidence={"e": 1}, prompt="p", completion="c",
                    tokens_in=10, tokens_out=4, cost_usd=0.25, latency_ms=12.5,
                ),
                enforcement="enforced",
            )
            row = store.snapshot()["traces"][0]
            return (
                row["run_id"], row["step"], row["event"], row["input"], row["output"],
                row["status"], tuple(row["flags"]), row["provider_metadata"],
                row["provider_evidence"], row["prompt"], row["completion"],
                row["tokens_in"], row["tokens_out"], row["cost_usd"], row["latency_ms"],
                row["enforcement"],
            )

        self._run_on_both(body)

    def test_input_and_output_round_trip_as_structures(self) -> None:
        def body(target: str) -> Any:
            store = TraceStore(target)
            store.append_trace(TraceEvent("r", 1, "e", {"a": [1, {"b": 2}]}, [3, 4], "ok"))
            row = store.snapshot()["traces"][0]
            return (row["input"], row["output"])

        self._run_on_both(body)

    def test_redaction_happens_before_storage(self) -> None:
        def body(target: str) -> Any:
            store = TraceStore(target)
            store.append_trace(
                TraceEvent("r", 1, "e", "card 4111111111111111", "a@b.com", "ok")
            )
            row = store.snapshot()["traces"][0]
            return (row["input"], row["output"])

        self._run_on_both(body)

    def test_the_last_insert_rowid_returns_the_real_id(self) -> None:
        """The SQLite original calls `last_insert_rowid()`; PostgreSQL needs
        `lastval()`. Getting this wrong silently returns the wrong row."""

        def body(target: str) -> Any:
            store = TraceStore(target)
            first = store.append_trace(TraceEvent("r", 1, "e", None, None, "ok"))
            second = store.append_trace(TraceEvent("r", 2, "e", None, None, "ok"))
            return (first, second, sorted(t["id"] for t in store.snapshot()["traces"]))

        self._run_on_both(body)

    # -- receipts ---------------------------------------------------------

    def test_receipts_and_queries_agree(self) -> None:

        def body(target: str) -> Any:
            store = TraceStore(target)
            for state in ("unknown", "done", "failed"):
                with store.connection() as connection:
                    connection.execute(
                        "INSERT INTO receipts(run_id, step_id, intent_key, action,"
                        " arguments_json, state) VALUES (?, ?, ?, ?, ?, ?)",
                        ("r1", "1", f"k-{state}", "charge", '{"a":1}', state),
                    )
            rows = store.snapshot()["receipts"]
            return [(r["intent_key"], r["state"], r["action"]) for r in rows]

        self._run_on_both(body)

    def test_claiming_an_effect_agrees(self) -> None:
        """The dedup guarantee must be identical on both backends.

        It rests on a partial unique index and an `ON CONFLICT` upsert, neither
        of which is guaranteed to behave the same through a SQL translation
        layer. If only one backend deduplicates, the guarantee is a property of
        the deployment rather than of the library.
        """

        def body(target: str) -> Any:
            store = TraceStore(target)
            effect_key = fingerprint("patch", {"app": "shop-api"})
            args = {"app": "shop-api"}
            first, first_owned = store.claim_receipt(effect_key, "run-A", "s1", "patch", args)
            second, second_owned = store.claim_receipt(effect_key, "run-B", "s1", "patch", args)
            store.mark_done(first.intent_key, "patch-1")
            third, third_owned = store.claim_receipt(effect_key, "run-C", "s1", "patch", args)
            rows = store.snapshot()["receipts"]
            return (
                first_owned, second_owned, third_owned,
                third.state, third.provider_ref,
                len(rows),
                store.applied_migrations(),
            )

        self._run_on_both(body)

    def test_two_effects_stay_distinct_on_both_backends(self) -> None:
        def body(target: str) -> Any:
            store = TraceStore(target)
            one = fingerprint("patch", {"app": "shop-api", "memory": "768Mi"})
            two = fingerprint("patch", {"app": "shop-api", "memory": "1Gi"})
            store.claim_receipt(one, "run-A", "s1", "patch", {"memory": "768Mi"})
            store.claim_receipt(two, "run-A", "s2", "patch", {"memory": "1Gi"})
            return len(store.snapshot()["receipts"])

        self._run_on_both(body)

    # -- approvals --------------------------------------------------------

    def test_approval_lifecycle_agrees(self) -> None:
        def body(target: str) -> Any:
            store = TraceStore(target)
            approvals = ApprovalStore(store)
            requested = approvals.request(
                "charge", {"amount": 100},
                datetime.now(UTC) + timedelta(minutes=5),
            )
            pending_before = [a.approval_id for a in approvals.pending()]
            approvals.approve(requested.approval_id, "operator")
            pending_after = [a.approval_id for a in approvals.pending()]
            approvals.consume(requested.approval_id)
            pending_consumed = [a.approval_id for a in approvals.pending()]
            return (len(pending_before), len(pending_after), len(pending_consumed))

        self._run_on_both(body)

    def test_consuming_an_approval_twice_agrees(self) -> None:
        def body(target: str) -> Any:
            store = TraceStore(target)
            approvals = ApprovalStore(store)
            requested = approvals.request(
                "charge", {"amount": 100},
                datetime.now(UTC) + timedelta(minutes=5),
            )
            approvals.approve(requested.approval_id, "operator")
            approvals.consume(requested.approval_id)
            try:
                approvals.consume(requested.approval_id)
                return "consumed twice"
            except Exception as exc:
                return type(exc).__name__

        self._run_on_both(body)

    # -- other tables -----------------------------------------------------

    def test_gate_verdicts_and_budgets_agree(self) -> None:
        from safety_layer.policy.fuses import FuseSnapshot

        def body(target: str) -> Any:
            store = TraceStore(target)
            store.append_gate(GateVerdict("r1", "PASS", 0.9, 0.8))
            store.record_fuse_snapshot(
                "r1",
                FuseSnapshot(steps_used=3, dollars_used=1.25, elapsed_seconds=2.5,
                             tripped=False, degraded=False, reason=None),
            )
            gates = [(g["run_id"], g["verdict"], g["score"]) for g in store.snapshot()["gate_verdicts"]]
            budgets = store.dashboard_snapshot()["budgets"]
            return (gates, [(b["steps_used"], b["dollars_used"], b["tripped"]) for b in budgets])

        self._run_on_both(body)

    def test_virtual_keys_agree(self) -> None:
        def body(target: str) -> Any:
            store = TraceStore(target)
            store.save_virtual_key("k1", "agent", ["/charge"], expires_at=12345.0)
            store.save_virtual_key("k2", "other", ["/refund"], expires_at=None)
            before = store.load_virtual_keys()
            revoked = store.revoke_virtual_key("k1")
            after = store.load_virtual_keys()
            return (
                [(k["key"], k["name"], tuple(k["routes"]), k["expires_at"], k["revoked"])
                 for k in before],
                revoked,
                [(k["key"], k["revoked"]) for k in after],
            )

        self._run_on_both(body)

    # -- introspection ----------------------------------------------------

    def test_column_introspection_agrees(self) -> None:
        def body(target: str) -> Any:
            store = TraceStore(target)
            return (
                "enforcement" in store._columns("trace_events"),
                "prompt_json" in store._columns("trace_events"),
                "nope" not in store._columns("trace_events"),
                store._table_exists("trace_events"),
                store._table_exists("definitely_not_here"),
            )

        self._run_on_both(body)


class TargetParsingTest(unittest.TestCase):
    """A typo must not silently create an empty SQLite file."""

    def test_a_path_selects_sqlite(self) -> None:
        from safety_layer.storage.base import _resolve

        self.assertEqual(_resolve("data/runtime.db"), ("sqlite", "data/runtime.db"))
        self.assertEqual(_resolve(":memory:"), ("sqlite", ":memory:"))

    def test_a_postgres_url_selects_postgres(self) -> None:
        from safety_layer.storage.base import _resolve

        for scheme in ("postgres://", "postgresql://"):
            self.assertEqual(_resolve(f"{scheme}h/db")[0], "postgres")

    def test_an_unknown_scheme_is_refused(self) -> None:
        from safety_layer.storage.base import _resolve

        with self.assertRaises(ValueError) as raised:
            _resolve("mysql://localhost/db")
        self.assertIn("unsupported database scheme", str(raised.exception))

    def test_the_backend_is_recorded_on_the_store(self) -> None:
        self.assertEqual(TraceStore(":memory:").backend, "sqlite")


if __name__ == "__main__":
    unittest.main()
