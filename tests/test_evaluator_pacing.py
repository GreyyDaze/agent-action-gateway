from safety_layer.evaluation.evaluator import evaluate_cases
from safety_layer.evaluation.judge import JudgeDecision
from safety_layer.evaluation.models import GoldenCase


class FakeJudge:
    version = "fake-v1"
    prompt_version = "fake-prompt-v1"

    def __init__(self):
        self.calls = 0

    def evaluate(self, case, output):
        self.calls += 1
        return JudgeDecision(
            label="pass",
            score=1.0,
            confidence=1.0,
            rationale="test",
            provider="fake",
            model="fake",
            judge_version=self.version,
            prompt_version=self.prompt_version,
        )


def test_judge_wait_is_applied_between_real_judge_requests(monkeypatch):
    case = GoldenCase(
        case_id="semantic-1",
        task="task",
        expected="expected",
        check_type="rubric",
        source="test",
    )
    judge = FakeJudge()
    waits = []

    monkeypatch.setattr("safety_layer.evaluation.evaluator.sleep", waits.append)

    summary = evaluate_cases(
        (case,),
        lambda _: "candidate",
        runs=3,
        judge=judge,
        judge_wait_seconds=5,
    )

    assert judge.calls == 3
    assert waits == [5, 5]
    assert summary.judge_available is True
