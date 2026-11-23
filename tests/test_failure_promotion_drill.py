import tempfile
import unittest
from pathlib import Path

from agent_action_gateway.audit.failure_wall import build_failure_wall
from agent_action_gateway.audit.promotions import (
    GoldenCasePromotionStore,
    promote_failure_group,
)
from agent_action_gateway.audit.wall import FailureWallStore
from agent_action_gateway.eval.evaluator import evaluate_cases
from agent_action_gateway.eval.golden import load_golden_cases, load_golden_set
from agent_action_gateway.eval.models import GoldenCase


class FailurePromotionDrillTests(unittest.TestCase):
    def test_human_confirmation_to_evaluation_end_to_end(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wall = FailureWallStore(root / "failure-wall.db")
            promotions = GoldenCasePromotionStore(root / "golden-promotions.db")

            group = build_failure_wall(
                [
                    {
                        "id": 601,
                        "run_id": "run-601",
                        "step": 4,
                        "event": "provider.call",
                        "status": "failed",
                        "output": {"error": {"type": "TimeoutError"}},
                        "provider_metadata": {
                            "config": {"model": "m1", "timeout": 10}
                        },
                    },
                    {
                        "id": 602,
                        "run_id": "run-602",
                        "step": 4,
                        "event": "provider.call",
                        "status": "failed",
                        "output": {"error": {"type": "TimeoutError"}},
                        "provider_metadata": {
                            "config": {"timeout": 10, "model": "m1"}
                        },
                    },
                ]
            )[0]

            # Human confirmation is persisted before promotion.
            wall.save_group(group)
            confirmed = wall.confirm(group.group_id)
            self.assertEqual(confirmed.state, "confirmed")
            self.assertEqual(
                wall.decisions(group.group_id)[0]["decision"],
                "confirm",
            )

            promote_failure_group(
                wall,
                promotions,
                group.group_id,
                case_id="failure-drill-001",
                task="Refund order ORD-601",
                expected={"order_id": "ORD-601", "status": "refunded"},
                check_type="field-equality",
            )

            # Reopen both stores to prove the drill is durable.
            reopened_wall = FailureWallStore(root / "failure-wall.db")
            reopened_promotions = GoldenCasePromotionStore(
                root / "golden-promotions.db"
            )
            persisted_group = reopened_wall.get_group(group.group_id)
            persisted_promotion = reopened_promotions.get("failure-drill-001")

            self.assertIsNotNone(persisted_group)
            self.assertIsNotNone(persisted_promotion)
            assert persisted_group is not None
            assert persisted_promotion is not None

            self.assertEqual(persisted_group.state, "confirmed")
            self.assertEqual(
                persisted_promotion.failure_group_id,
                group.group_id,
            )
            self.assertEqual(
                persisted_promotion.source_trace_ids,
                (601, 602),
            )

            combined = load_golden_cases(
                promotion_store=reopened_promotions
            )
            promoted = next(
                case for case in combined if case.case_id == "failure-drill-001"
            )

            self.assertEqual(len(load_golden_set()), 30)
            self.assertEqual(len(combined), 31)
            self.assertEqual(
                promoted.source,
                f"failure-wall:{group.group_id}",
            )

            def correct_output(case: GoldenCase) -> object:
                return case.expected

            summary = evaluate_cases(
                (promoted,),
                correct_output,
                runs=1,
            )

            self.assertEqual(summary.cases_evaluated, 1)
            self.assertEqual(summary.samples[0].label, "pass")
            self.assertEqual(summary.samples[0].case_id, "failure-drill-001")


if __name__ == "__main__":
    unittest.main()
