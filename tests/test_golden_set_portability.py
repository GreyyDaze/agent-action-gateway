"""The golden set loader must accept an adopter's own data, not just ours.

The loader previously required exactly the number of cases in the shipped
example file. That number described the example, not a requirement of the
evaluation method, so it made an adopter's own set unloadable.

These tests pin the behaviour that matters: any sufficiently large set loads,
and the floor exists to protect the baseline comparison rather than to
enforce a particular example.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from agent_action_gateway.eval.golden import (
    MIN_GOLDEN_CASES,
    load_golden_set,
)
from agent_action_gateway.eval.models import GOLDEN_SET_VERSION


def build_case(index: int, *, catastrophic: bool) -> dict[str, object]:
    """A case in an unrelated domain, so no rollback vocabulary is involved."""
    return {
        "case_id": f"appt-{index:03d}",
        "task": f"Book patient P-{index} for cardiology on 2026-11-{index:02d}",
        "expected": {
            "patient_id": f"P-{index}",
            "specialty": "cardiology",
            "date": f"2026-11-{index:02d}",
        },
        "check_type": "field-equality",
        "source": "adopter",
        "catastrophic": catastrophic,
        "rubric": [],
    }


def write_set(cases: list[dict[str, object]]) -> Path:
    directory = Path(tempfile.mkdtemp())
    path = directory / "golden-v1.json"
    path.write_text(
        json.dumps({"version": GOLDEN_SET_VERSION, "cases": cases}),
        encoding="utf-8",
    )
    return path


class GoldenSetPortabilityTest(unittest.TestCase):
    """An adopter's set loads without touching the evaluation code."""

    def test_loads_a_set_of_arbitrary_size_above_the_floor(self) -> None:
        for count in (MIN_GOLDEN_CASES, 17, 50, 120):
            with self.subTest(count=count):
                cases = [
                    build_case(i, catastrophic=(i == 1)) for i in range(1, count + 1)
                ]
                loaded = load_golden_set(write_set(cases))
                self.assertEqual(len(loaded), count)

    def test_loads_a_set_from_an_unrelated_domain(self) -> None:
        cases = [build_case(i, catastrophic=(i == 1)) for i in range(1, 13)]
        loaded = load_golden_set(write_set(cases))

        self.assertEqual(len(loaded), 12)
        self.assertTrue(all("rollback" not in c.task.lower() for c in loaded))
        self.assertEqual(
            {c.check_type for c in loaded}, {"field-equality"}
        )

    def test_rejects_a_set_below_the_floor(self) -> None:
        """Too few cases cannot support a baseline comparison."""
        cases = [build_case(i, catastrophic=(i == 1)) for i in range(1, MIN_GOLDEN_CASES)]
        with self.assertRaises(ValueError) as caught:
            load_golden_set(write_set(cases))
        self.assertIn("too few cases", str(caught.exception))

    def test_rejects_a_set_without_a_catastrophic_case(self) -> None:
        cases = [build_case(i, catastrophic=False) for i in range(1, 13)]
        with self.assertRaises(ValueError) as caught:
            load_golden_set(write_set(cases))
        self.assertIn("catastrophic", str(caught.exception))

    def test_shipped_example_still_loads(self) -> None:
        """The bundled dataset is unchanged by any of this."""
        cases = load_golden_set()
        self.assertGreaterEqual(len(cases), MIN_GOLDEN_CASES)
        self.assertTrue(any(c.catastrophic for c in cases))


class EvaluationPortabilityTest(unittest.TestCase):
    """A non-rollback dataset scores and gates like any other."""

    def _cases(self):
        raw = [build_case(i, catastrophic=(i == 1)) for i in range(1, 13)]
        return load_golden_set(write_set(raw))

    def test_scores_a_foreign_dataset(self) -> None:
        from agent_action_gateway.eval.evaluator import evaluate_cases

        cases = self._cases()
        correct = {c.case_id: c.expected for c in cases}
        summary = evaluate_cases(cases, lambda c: correct[c.case_id], runs=1)

        self.assertEqual(summary.observed_score, 1.0)
        self.assertFalse(summary.catastrophic_failure)

    def test_a_single_catastrophic_failure_is_flagged(self) -> None:
        """The averaging case that must never pass quietly."""
        from agent_action_gateway.eval.evaluator import evaluate_cases

        cases = self._cases()
        answers = {c.case_id: c.expected for c in cases}
        broken = dict(answers)
        target = next(c for c in cases if c.catastrophic)
        broken[target.case_id] = {"patient_id": "WRONG", "specialty": "none", "date": "n/a"}

        summary = evaluate_cases(cases, lambda c: broken[c.case_id], runs=1)

        self.assertGreater(summary.observed_score, 0.5, "most cases still passed")
        self.assertTrue(
            summary.catastrophic_failure,
            "one catastrophic failure must be reported as such",
        )


if __name__ == "__main__":
    unittest.main()
