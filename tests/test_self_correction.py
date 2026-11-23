"""Phase 5: self-correction that cannot become a way around the guard.

Retrying is the highest-leverage thing an agent can do, and the easiest way to
turn a safety limit into a suggestion. A loop that retries will eventually get
past a cap by trying often enough. So the rule is asymmetric: allowed calls
retry, blocked calls never do.

The tests below are mostly negative on purpose. "It did not retry" cannot be
proven by watching it succeed.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from agent_action_gateway.runtime.session import session
from agent_action_gateway.storage.traces import TraceStore


class RetryHarness(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.store = TraceStore(Path(self._tmp.name) / "runtime.db")

    def _session(self):
        return session(store=self.store)


class BlockedIsNeverRetriedTest(RetryHarness):
    """The rule this whole phase exists to enforce."""

    def test_the_tool_is_never_reached(self) -> None:
        """Stronger than "not retried": policy blocks *before* dispatch, so the
        tool function is never invoked at all."""
        calls: list[int] = []

        with self._session() as ctx:
            raw = ctx.tool(
                lambda **k: (calls.append(1), {"status": "refunded"})[1],
                action="refund",
                risk="destructive",
            )
            ctx.retrying(raw, attempts=5)(amount=100)

        self.assertEqual(len(calls), 0, "a held action must never reach the tool")

    def test_the_refusal_is_returned_to_the_caller(self) -> None:
        with self._session() as ctx:
            raw = ctx.tool(
                lambda **k: {"status": "ok"}, action="refund", risk="destructive"
            )
            result = ctx.retrying(raw, attempts=4)(amount=100)
        self.assertTrue(result.get("blocked") or result.get("needs_approval"), result)

    def test_the_refusal_to_retry_is_recorded(self) -> None:
        """An operator must be able to see that an agent tried again."""
        with self._session() as ctx:
            raw = ctx.tool(
                lambda **k: {"status": "ok"}, action="refund", risk="destructive"
            )
            ctx.retrying(raw, attempts=3)(amount=100)

        events = [t["event"] for t in self.store.snapshot()["traces"]]
        self.assertIn("self_correction.refused", events)

    def test_the_budget_is_not_consumed_by_the_extra_attempts(self) -> None:
        """Six blocked attempts must cost one step, not six."""
        with self._session() as ctx:
            raw = ctx.tool(
                lambda **k: {"status": "ok"}, action="refund", risk="destructive"
            )
            ctx.retrying(raw, attempts=6)(amount=100)
            # Counted by prefix, not by a specific event name: a held action is
            # recorded as enforcement.approval rather than
            # enforcement.decision, and the point is that exactly one policy
            # decision happened however many attempts were configured.
            decisions = [
                t for t in self.store.snapshot()["traces"]
                if t["event"].startswith("enforcement.")
            ]
        self.assertEqual(len(decisions), 1, "one policy decision per actual attempt")


class RetryGuardOnItsOwnTest(RetryHarness):
    """The retry rule, independent of the pipeline.

    When `ctx.tool` holds an action it blocks *before* dispatch, so the tool is
    never reached and the retry loop has nothing to retry. That is the primary
    defence, and it makes the retry guard look unnecessary. It is not: a tool can
    also report a refusal from its own provider after being called, and a retry
    loop must respect that too. These tests use a plain callable so the retry
    rule is what is under test.
    """

    # Each case also claims to be transient. Without that, they would pass even
    # with the refusal check removed, because the retryable check would stop the
    # loop anyway -- a test that passes for the wrong reason is not a test.
    _TRANSIENT = {"transient": True, "status_code": 503}

    def test_a_refused_result_is_never_retried(self) -> None:
        calls: list[int] = []

        with self._session() as ctx:
            fn = ctx.retrying(
                lambda **k: (calls.append(1), {"status": "blocked", **self._TRANSIENT})[1],
                attempts=6,
            )
            fn()

        self.assertEqual(len(calls), 1, "a refused result must not be retried")

    def test_a_needs_approval_result_is_never_retried(self) -> None:
        calls: list[int] = []

        with self._session() as ctx:
            fn = ctx.retrying(
                lambda **k: (calls.append(1), {"needs_approval": True, **self._TRANSIENT})[1],
                attempts=6,
            )
            fn()

        self.assertEqual(len(calls), 1)

    def test_a_guard_envelope_reporting_a_block_is_never_retried(self) -> None:
        calls: list[int] = []

        with self._session() as ctx:
            fn = ctx.retrying(
                lambda **k: (calls.append(1), {
                    "status": "blocked", "decision": "FUSE", "result": None,
                    "error": "budget", "transient": True,
                })[1],
                attempts=6,
            )
            fn()

        self.assertEqual(len(calls), 1)

    def test_a_result_may_still_be_retried_when_the_refusal_check_is_intact(self) -> None:
        """The control: a transient result with no refusal IS retried.

        Without this, the tests above would also pass if the retry loop had been
        deleted outright.
        """
        calls: list[int] = []

        with self._session() as ctx:
            fn = ctx.retrying(lambda **k: (calls.append(1), self._TRANSIENT)[1], attempts=4)
            fn()

        self.assertEqual(len(calls), 4)

    def test_a_refused_result_looks_transient_and_is_still_not_retried(self) -> None:
        """The dangerous case: a refusal that *claims* to be transient.

        If the retry check ran before the refusal check, this would retry six
        times and the guard would be advisory.
        """
        calls: list[int] = []

        with self._session() as ctx:
            fn = ctx.retrying(
                lambda **k: (calls.append(1), {
                    "status": "blocked", "transient": True, "status_code": 503,
                })[1],
                attempts=6,
            )
            fn()

        self.assertEqual(len(calls), 1, "a refusal outranks any transient signal")


class RetryLogicTest(RetryHarness):
    """The retry rule on its own, wrapping a plain callable.

    Guarded tools are covered separately below. Mixing the two would hide which
    guard stopped a loop: `ctx.retrying` bounds its own attempts, and the
    no-progress fuse bounds repeated calls to a guarded action.
    """

    def test_a_5xx_result_is_retried_up_to_the_bound(self) -> None:
        calls: list[int] = []

        with self._session() as ctx:
            fn = ctx.retrying(lambda **k: (calls.append(1), {"status_code": 503})[1], attempts=3)
            fn()

        self.assertEqual(len(calls), 3)

    def test_repeating_one_call_is_stopped_by_the_fuse(self) -> None:
        """Belt and braces: a retry loop over a guarded action cannot grind
        past the no-progress guard by asking repeatedly."""
        calls: list[int] = []

        with self._session() as ctx:
            raw = ctx.tool(
                lambda **k: (calls.append(1), {"status_code": 503})[1],
                action="lookup",
                risk="read",
            )
            ctx.retrying(raw, attempts=10)()

        self.assertLess(len(calls), 10, "the fuse must stop an identical retry loop")

    def test_guarded_and_retrying_together_still_stop(self) -> None:
        calls: list[int] = []

        with self._session() as ctx:
            raw = ctx.tool(
                lambda **k: (calls.append(1), {"status_code": 503})[1],
                action="lookup",
                risk="read",
            )
            ctx.retrying(raw, attempts=8)()

        self.assertLessEqual(len(calls), 3)

    def test_a_successful_retry_returns_the_good_result(self) -> None:
        outcomes = [{"status_code": 503}, {"status_code": 503}, {"status": "ok"}]

        with self._session() as ctx:
            fn = ctx.retrying(lambda **k: outcomes.pop(0), attempts=3)
            result = fn()

        self.assertEqual(result, {"status": "ok"})

    def test_a_retry_over_a_guarded_tool_returns_the_payload(self) -> None:
        """A caller must not have to unwrap the guard envelope because it asked
        for a retry -- the two composable surfaces should look like one."""
        with self._session() as ctx:
            raw = ctx.tool(lambda **k: {"status": "ok"}, action="lookup", risk="read")
            result = ctx.retrying(raw, attempts=1)()

        self.assertEqual(result, {"status": "ok"})

    def test_an_explicitly_transient_marker_is_retried(self) -> None:
        calls: list[int] = []

        with self._session() as ctx:
            ctx.retrying(lambda **k: (calls.append(1), {"transient": True})[1], attempts=2)()

        self.assertEqual(len(calls), 2)

    def test_the_bound_is_respected(self) -> None:
        calls: list[int] = []

        with self._session() as ctx:
            ctx.retrying(lambda **k: (calls.append(1), {"status_code": 500})[1], attempts=2)()

        self.assertEqual(len(calls), 2, "attempts is a ceiling, not a hint")

    def test_on_retry_is_called_before_each_retry(self) -> None:
        seen: list[int] = []

        with self._session() as ctx:
            ctx.retrying(
                lambda **k: {"status_code": 503}, attempts=3,
                on_retry=lambda n, r: seen.append(n),
            )()

        self.assertEqual(seen, [1, 2], "called once per retry, not once per attempt")


class UnknownFailureIsNotRetriedTest(RetryHarness):
    def test_an_unrecognised_failure_is_returned_immediately(self) -> None:
        """Retrying an unknown failure is how a budget disappears."""
        calls: list[int] = []

        with self._session() as ctx:
            result = ctx.retrying(
                lambda **k: (calls.append(1), {"error": "weird"})[1], attempts=4
            )()

        self.assertEqual(len(calls), 1)
        self.assertEqual(result, {"error": "weird"})

    def test_a_4xx_is_not_retried(self) -> None:
        calls: list[int] = []

        with self._session() as ctx:
            ctx.retrying(lambda **k: (calls.append(1), {"status_code": 404})[1], attempts=3)()

        self.assertEqual(len(calls), 1)


class ArgumentTest(RetryHarness):
    def test_attempts_below_one_is_rejected(self) -> None:
        with self._session() as ctx:
            with self.assertRaises(ValueError):
                ctx.retrying(lambda: {}, attempts=0)

    def test_a_non_dict_result_is_returned_untouched(self) -> None:
        with self._session() as ctx:
            result = ctx.retrying(lambda: "plain string", attempts=3)()
        self.assertEqual(result, "plain string")

    def test_attempts_of_one_never_retry(self) -> None:
        calls: list[int] = []

        with self._session() as ctx:
            raw = ctx.tool(
                lambda **k: (calls.append(1), {"status_code": 503})[1],
                action="lookup",
                risk="read",
            )
            ctx.retrying(raw, attempts=1)()

        self.assertEqual(len(calls), 1)


if __name__ == "__main__":
    unittest.main()
