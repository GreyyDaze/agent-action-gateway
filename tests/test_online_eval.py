"""Phase 4: online eval is report-only unless someone explicitly promotes it.

The failure this guards against is specific and common: an online judge starts
failing CI on noise, the team switches it off, and the signal is gone. So the
default has to be incapable of blocking, and the guarantee is tested rather than
asserted in a docstring.

Determinism matters too. A report you cannot reproduce is an argument, not
evidence.
"""

from __future__ import annotations

import unittest

from agent_action_gateway.eval.online import assess, gate_status, group_runs, render, select


def trace(run_id: str, event="enforcement.decision", status="completed", step_no=1, **kwargs):
    return {
        "id": kwargs.get("id", step_no),
        "run_id": run_id,
        "event": event,
        "status": status,
        "step": step_no,
        "input": kwargs.get("input", {}),
        "output": kwargs.get("output", {}),
    }


def clean_run(run_id: str) -> list[dict]:
    return [
        trace(run_id, output={"action": f"act-{i}", "risk": "read"}, step_no=i, id=i)
        for i in range(1, 4)
    ]


def degraded_run(run_id: str) -> list[dict]:
    return [
        trace(run_id, output={"action": "refund", "risk": "destructive"}, status="blocked",
              id=1),
    ]


def fuse_run(run_id: str) -> list[dict]:
    return [trace(run_id, event="enforcement.fuse", status="blocked", output="limit", id=1)]


class GroupingTest(unittest.TestCase):
    def test_traces_split_into_ordered_runs(self) -> None:
        rows = clean_run("a") + clean_run("b") + degraded_run("c")
        runs = group_runs(rows)
        self.assertEqual(set(runs), {"a", "b", "c"})
        self.assertEqual([t["step"] for t in runs["a"]], [1, 2, 3])

    def test_interleaved_rows_still_group_correctly(self) -> None:
        rows = [clean_run("a")[0], clean_run("b")[0], clean_run("a")[1], clean_run("b")[1]]
        runs = group_runs(rows)
        self.assertEqual(len(runs["a"]), 2)
        self.assertEqual([t["step"] for t in runs["a"]], [1, 2])


class SamplingTest(unittest.TestCase):
    def _many(self, n: int) -> dict[str, list[dict]]:
        return {f"run-{i:02d}": clean_run(f"run-{i:02d}") for i in range(n)}

    def test_the_same_seed_selects_the_same_runs(self) -> None:
        runs = self._many(50)
        self.assertEqual(select(runs, 0.2, seed=7), select(runs, 0.2, seed=7))

    def test_a_different_seed_can_select_differently(self) -> None:
        runs = self._many(50)
        self.assertNotEqual(select(runs, 0.2, seed=1), select(runs, 0.2, seed=2))

    def test_a_sample_of_one_selects_everything(self) -> None:
        runs = self._many(10)
        self.assertEqual(len(select(runs, 1.0, seed=0)), 10)

    def test_a_tiny_sample_still_selects_at_least_one_run(self) -> None:
        runs = self._many(20)
        self.assertEqual(len(select(runs, 0.001, seed=0)), 1)

    def test_a_zero_sample_selects_nothing(self) -> None:
        self.assertEqual(select(self._many(10), 0.0, seed=0), [])

    def test_no_runs_selects_nothing(self) -> None:
        self.assertEqual(select({}, 1.0, seed=0), [])


class ReportOnlyTest(unittest.TestCase):
    """The central guarantee."""

    def _report_with_a_degraded_run(self):
        return assess({"bad": degraded_run("bad")}, sample=1.0, seed=0)

    def test_a_degraded_run_does_not_fail_by_default(self) -> None:
        report = self._report_with_a_degraded_run()
        self.assertEqual(len(report.degraded), 1)
        self.assertFalse(gate_status(report, promote=False))

    def test_a_degraded_run_does_fail_once_promoted(self) -> None:
        report = self._report_with_a_degraded_run()
        self.assertTrue(gate_status(report, promote=True))

    def test_promotion_is_stated_in_the_output(self) -> None:
        report = self._report_with_a_degraded_run()
        self.assertIn("report only", render(report, promote=False))
        self.assertIn("PROMOTED", render(report, promote=True))

    def test_a_clean_population_never_fails(self) -> None:
        runs = {f"r{i}": clean_run(f"r{i}") for i in range(5)}
        report = assess(runs, sample=1.0, seed=0)
        self.assertFalse(gate_status(report, promote=True))


class HumanDisagreementTest(unittest.TestCase):
    """A judge that quietly disagrees with a human is a broken judge."""

    def test_a_held_run_is_not_counted_as_degraded(self) -> None:
        report = assess({"r": degraded_run("r")}, sample=1.0, blocked_run_ids=["r"])
        self.assertEqual(len(report.degraded), 0)

    def test_a_held_run_the_scorer_likes_is_reported_as_a_disagreement(self) -> None:
        """Human held it, scorer found nothing: the scorer is under suspicion."""
        report = assess({"r": clean_run("r")}, sample=1.0, blocked_run_ids=["r"])
        self.assertEqual(report.disagreements, ["r"])

    def test_the_disagreement_is_visible_in_the_output(self) -> None:
        report = assess({"r": clean_run("r")}, sample=1.0, blocked_run_ids=["r"])
        self.assertIn("disagreement", render(report, promote=False).lower())


class HonestyTest(unittest.TestCase):
    def test_too_small_a_sample_says_so_and_does_not_fail(self) -> None:
        runs = {f"r{i:02d}": clean_run(f"r{i:02d}") for i in range(12)}
        report = assess(runs, sample=0.05, seed=0)
        self.assertTrue(report.below_baseline)
        # Too little data must never be reported as a pass *or* a failure.
        self.assertFalse(gate_status(report, promote=True))
        self.assertIn("too few", render(report, promote=True).lower())

    def test_an_empty_database_reports_nothing_and_does_not_fail(self) -> None:
        report = assess({}, sample=1.0, seed=0)
        self.assertEqual(report.sampled, 0)
        self.assertFalse(gate_status(report, promote=True))

    def test_a_fuse_tripped_is_reported(self) -> None:
        report = assess({"f": fuse_run("f")}, sample=1.0, seed=0)
        self.assertIn("fuse_tripped", report.assessments[0].kinds)


class OutputShapeTest(unittest.TestCase):
    def test_as_dict_is_serialisable(self) -> None:
        import json

        report = assess({"r": degraded_run("r")}, sample=1.0, seed=0)
        json.dumps(report.as_dict())

    def test_the_report_states_its_population_and_sample(self) -> None:
        runs = {f"r{i}": clean_run(f"r{i}") for i in range(10)}
        report = assess(runs, sample=0.5, seed=0)
        self.assertEqual(report.population, 10)
        self.assertEqual(report.sampled, 5)
        self.assertIn("sampled 5 of 10", render(report, promote=False))


if __name__ == "__main__":
    unittest.main()
