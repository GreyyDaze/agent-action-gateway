import unittest

from agent_action_gateway.audit.failure_wall import build_failure_wall
from agent_action_gateway.guards.capture import suspicious_flags


class FailureWallProofTests(unittest.TestCase):
    """Deterministic acceptance proof for silent-wrong and clustering."""

    def test_all_planted_silent_wrong_cases_are_flagged(self) -> None:
        cases = (
            {"empty_result": True},
            {"invariant_failed": True},
            {"cross_check_failed": True},
            {
                "empty_result": True,
                "invariant_failed": True,
                "cross_check_failed": True,
            },
        )

        missed = []
        for case in cases:
            flags = suspicious_flags(**case)
            if not flags:
                missed.append(case)

        self.assertEqual(missed, [])
        self.assertEqual(len(missed), 0)

    def test_equivalent_failures_share_one_group_and_normalize_config_order(self) -> None:
        traces = [
            self._trace(
                1,
                error="provider-timeout",
                step="create_invoice",
                config={"timeout": 8, "retries": 2},
            ),
            self._trace(
                2,
                error="provider-timeout",
                step="create_invoice",
                config={"retries": 2, "timeout": 8},
            ),
            self._trace(
                3,
                error="provider-timeout",
                step="create_invoice",
                config={"timeout": 8, "retries": 2},
            ),
        ]

        groups = build_failure_wall(traces)

        self.assertEqual(len(groups), 1)
        self.assertEqual(
            {record.trace_id for record in groups[0].records},
            {1, 2, 3},
        )

    def test_each_signature_dimension_creates_a_different_group(self) -> None:
        base = self._trace(
            10,
            error="provider-timeout",
            step="create_invoice",
            config={"timeout": 8, "retries": 2},
        )
        different_error = self._trace(
            11,
            error="validation-error",
            step="create_invoice",
            config={"timeout": 8, "retries": 2},
        )
        different_step = self._trace(
            12,
            error="provider-timeout",
            step="send_invoice",
            config={"timeout": 8, "retries": 2},
        )
        different_config = self._trace(
            13,
            error="provider-timeout",
            step="create_invoice",
            config={"timeout": 30, "retries": 2},
        )

        groups = build_failure_wall(
            [base, different_error, different_step, different_config]
        )

        self.assertEqual(len(groups), 4)
        self.assertEqual(
            {record.trace_id for group in groups for record in group.records},
            {10, 11, 12, 13},
        )

    def test_failure_wall_is_an_exact_trace_partition(self) -> None:
        traces = [
            self._trace(
                20,
                error="provider-timeout",
                step="create_invoice",
                config={"timeout": 8},
            ),
            self._trace(
                21,
                error="provider-timeout",
                step="create_invoice",
                config={"timeout": 8},
            ),
            self._trace(
                22,
                error="validation-error",
                step="create_invoice",
                config={"timeout": 8},
            ),
            self._trace(
                23,
                error="provider-timeout",
                step="send_invoice",
                config={"timeout": 8},
            ),
            self._trace(
                24,
                error="provider-timeout",
                step="create_invoice",
                config={"timeout": 30},
            ),
            {
                "id": 99,
                "run_id": "control-run",
                "step": 1,
                "event": "tool.read",
                "status": "completed",
                "output": {"ok": True},
            },
        ]

        groups = build_failure_wall(traces)
        grouped_ids = [
            record.trace_id
            for group in groups
            for record in group.records
        ]

        self.assertEqual(sorted(grouped_ids), [20, 21, 22, 23, 24])
        self.assertNotIn(99, grouped_ids)
        self.assertEqual(len(grouped_ids), len(set(grouped_ids)))

        signatures = {
            (
                record.trace_id,
                record.error_type,
                record.failing_step,
                record.config_fingerprint,
            )
            for group in groups
            for record in group.records
        }
        self.assertEqual(len(signatures), 5)

    @staticmethod
    def _trace(
        trace_id: int,
        *,
        error: str,
        step: str,
        config: dict,
    ) -> dict:
        return {
            "id": trace_id,
            "run_id": f"run-{trace_id}",
            "step": 4,
            "event": step,
            "status": "failed",
            "output": {"error": {"type": error}},
            "provider_metadata": {"config": config},
        }


if __name__ == "__main__":
    unittest.main()
