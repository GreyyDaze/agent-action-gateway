import tempfile
import unittest
from pathlib import Path

from safety_layer.failure_wall_store import FailureWallStore
from safety_layer.golden import load_golden_cases, load_golden_set
from safety_layer.golden_promotion import (
    GoldenCasePromotionStore,
    promote_failure_group,
)
from safety_layer.trace import build_failure_wall


class FailurePromotionTests(unittest.TestCase):
    def _confirmed_group(self, path: Path):
        wall = FailureWallStore(path)
        group = build_failure_wall(
            [
                {
                    "id": 501,
                    "run_id": "run-501",
                    "step": 4,
                    "event": "provider.call",
                    "status": "failed",
                    "output": {"error": {"type": "TimeoutError"}},
                    "provider_metadata": {"config": {"model": "m1"}},
                },
                {
                    "id": 502,
                    "run_id": "run-502",
                    "step": 4,
                    "event": "provider.call",
                    "status": "failed",
                    "output": {"error": {"type": "TimeoutError"}},
                    "provider_metadata": {"config": {"model": "m1"}},
                },
            ]
        )[0]
        wall.save_group(group)
        wall.confirm(group.group_id)
        return wall, group

    def test_unconfirmed_group_cannot_be_promoted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            wall_path = Path(directory) / "failure-wall.db"
            promotions = GoldenCasePromotionStore(
                Path(directory) / "golden-promotions.db"
            )
            group = build_failure_wall(
                [
                    {
                        "id": 503,
                        "run_id": "run-503",
                        "step": 4,
                        "event": "provider.call",
                        "status": "failed",
                        "output": {"error": {"type": "TimeoutError"}},
                    }
                ]
            )[0]
            FailureWallStore(wall_path).save_group(group)

            with self.assertRaisesRegex(ValueError, "must be confirmed"):
                promote_failure_group(
                    FailureWallStore(wall_path),
                    promotions,
                    group.group_id,
                    case_id="failure-001",
                    task={"request": "refund order 123"},
                    expected={"status": "refunded"},
                    check_type="field-equality",
                )

    def test_confirmed_group_becomes_golden_case_with_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            wall, group = self._confirmed_group(
                Path(directory) / "failure-wall.db"
            )
            promotions = GoldenCasePromotionStore(
                Path(directory) / "golden-promotions.db"
            )

            promotion = promote_failure_group(
                wall,
                promotions,
                group.group_id,
                case_id="failure-001",
                task={"request": "refund order 123"},
                expected={"status": "refunded"},
                check_type="field-equality",
            )

            self.assertEqual(promotion.case.case_id, "failure-001")
            self.assertEqual(promotion.case.task, {"request": "refund order 123"})
            self.assertEqual(promotion.case.expected, {"status": "refunded"})
            self.assertEqual(promotion.case.check_type, "field-equality")
            self.assertEqual(
                promotion.case.source,
                f"failure-wall:{group.group_id}",
            )
            self.assertEqual(promotion.failure_group_id, group.group_id)
            self.assertEqual(promotion.source_trace_ids, (501, 502))

    def test_promotion_survives_store_reopen(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            wall, group = self._confirmed_group(
                Path(directory) / "failure-wall.db"
            )
            promotion_path = Path(directory) / "golden-promotions.db"
            promotions = GoldenCasePromotionStore(promotion_path)

            promote_failure_group(
                wall,
                promotions,
                group.group_id,
                case_id="failure-002",
                task="refund order 456",
                expected={"status": "refunded"},
                check_type="exact",
            )

            reopened = GoldenCasePromotionStore(promotion_path).get("failure-002")

            self.assertIsNotNone(reopened)
            assert reopened is not None
            self.assertEqual(reopened.failure_group_id, group.group_id)
            self.assertEqual(reopened.source_trace_ids, (501, 502))
            self.assertEqual(reopened.case.expected, {"status": "refunded"})

    def test_same_group_cannot_be_promoted_twice(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            wall, group = self._confirmed_group(
                Path(directory) / "failure-wall.db"
            )
            promotions = GoldenCasePromotionStore(
                Path(directory) / "golden-promotions.db"
            )
            kwargs = {
                "case_id": "failure-003",
                "task": "refund order 789",
                "expected": {"status": "refunded"},
                "check_type": "exact",
            }

            promote_failure_group(wall, promotions, group.group_id, **kwargs)

            with self.assertRaisesRegex(ValueError, "already promoted"):
                promote_failure_group(
                    wall,
                    promotions,
                    group.group_id,
                    case_id="failure-004",
                    task="refund order 789",
                    expected={"status": "refunded"},
                    check_type="exact",
                )

    def test_promoted_case_is_an_explicit_evaluation_golden_overlay(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            wall, group = self._confirmed_group(
                Path(directory) / "failure-wall.db"
            )
            promotion_store = GoldenCasePromotionStore(
                Path(directory) / "golden-promotions.db"
            )

            promote_failure_group(
                wall,
                promotion_store,
                group.group_id,
                case_id="failure-005",
                task={"request": "refund order 999"},
                expected={"status": "refunded"},
                check_type="field-equality",
            )

            canonical = load_golden_set()
            combined = load_golden_cases(promotion_store=promotion_store)

            self.assertEqual(len(canonical), 30)
            self.assertEqual(len(combined), 31)
            self.assertEqual(combined[-1].case_id, "failure-005")
            self.assertEqual(combined[-1].source, f"failure-wall:{group.group_id}")


if __name__ == "__main__":
    unittest.main()
