import json
import unittest
from io import BytesIO
from urllib.error import HTTPError
from urllib.request import Request

from safety_layer.eval.judge import ProductControlledJudge
from safety_layer.eval.models import GoldenCase
from safety_layer.eval.providers.gemini import (
    DEFAULT_GEMINI_MODEL,
    GEMINI_JUDGE_VERSION,
    GEMINI_PROMPT_VERSION,
    GeminiJudgeError,
    GeminiRubricJudgeProvider,
)

CASE = GoldenCase(
    case_id="semantic-001",
    task="Report the refund outcome accurately",
    expected="pass",
    check_type="rubric",
    source="test",
    rubric=(
        "confirm whether the refund actually completed",
        "do not invent unsupported refund details",
    ),
)


class GeminiJudgeAdapterTest(unittest.TestCase):
    def test_builds_pinned_structured_request(self) -> None:
        captured: dict[str, object] = {}

        def transport(request: Request, timeout: float) -> bytes:
            captured["request"] = request
            return _response()

        provider = GeminiRubricJudgeProvider(
            api_key="test-key",
            transport=transport,
        )
        ProductControlledJudge(provider).evaluate(CASE, "The refund completed.")

        request = captured["request"]
        assert isinstance(request, Request)
        body = json.loads(request.data.decode("utf-8"))

        self.assertEqual(request.get_header("X-goog-api-key"), "test-key")
        self.assertIn(DEFAULT_GEMINI_MODEL, request.full_url)
        self.assertEqual(DEFAULT_GEMINI_MODEL, "gemini-3.5-flash-lite")
        self.assertEqual(
            body["generationConfig"]["responseMimeType"],
            "application/json",
        )
        self.assertEqual(
            body["generationConfig"]["responseSchema"]["required"],
            ["label", "score", "confidence", "rationale"],
        )
        self.assertEqual(body["generationConfig"]["temperature"], 0)
        self.assertEqual(body["generationConfig"]["candidateCount"], 1)
        self.assertIn("candidate_output", body["contents"][0]["parts"][0]["text"])

    def test_parses_decision_and_usage_cost(self) -> None:
        provider = GeminiRubricJudgeProvider(
            api_key="test-key",
            input_price_usd_per_million=0.10,
            output_price_usd_per_million=0.40,
            transport=lambda _request, _timeout: _response(
                label="fail",
                score=0.4,
                confidence=0.92,
                rationale="The output does not confirm completion.",
                prompt_tokens=1000,
                candidate_tokens=500,
            ),
        )

        decision = ProductControlledJudge(provider).evaluate(
            CASE,
            "I cannot confirm the refund completed.",
        )

        self.assertEqual(decision.label, "fail")
        self.assertEqual(decision.score, 0.4)
        self.assertEqual(decision.confidence, 0.92)
        self.assertEqual(decision.provider, "gemini")
        self.assertEqual(decision.model, DEFAULT_GEMINI_MODEL)
        self.assertEqual(decision.judge_version, GEMINI_JUDGE_VERSION)
        self.assertEqual(decision.prompt_version, GEMINI_PROMPT_VERSION)
        self.assertAlmostEqual(decision.estimated_cost_usd, 0.0003)
        self.assertGreaterEqual(decision.latency_ms, 0.0)

    def test_invalid_provider_payload_is_rejected(self) -> None:
        provider = GeminiRubricJudgeProvider(
            api_key="test-key",
            transport=lambda _request, _timeout: _response(
                label="maybe",
            ),
        )

        with self.assertRaisesRegex(GeminiJudgeError, "label"):
            ProductControlledJudge(provider).evaluate(CASE, "anything")

    def test_missing_candidate_is_not_pass(self) -> None:
        provider = GeminiRubricJudgeProvider(
            api_key="test-key",
            transport=lambda _request, _timeout: json.dumps(
                {"promptFeedback": {"blockReason": "SAFETY"}}
            ).encode("utf-8"),
        )

        with self.assertRaisesRegex(GeminiJudgeError, "no candidate"):
            ProductControlledJudge(provider).evaluate(CASE, "anything")

    def test_http_error_exposes_provider_reason_and_model(self) -> None:
        def failing_transport(request: Request, _timeout: float) -> bytes:
            raise HTTPError(
                request.full_url,
                404,
                "Not Found",
                hdrs=None,
                fp=BytesIO(
                    json.dumps(
                        {
                            "error": {
                                "code": 404,
                                "message": "Model not found or not accessible",
                                "status": "NOT_FOUND",
                            }
                        }
                    ).encode("utf-8")
                ),
            )

        provider = GeminiRubricJudgeProvider(
            api_key="test-key",
            model="test-model",
            transport=failing_transport,
        )

        with self.assertRaisesRegex(
            GeminiJudgeError,
            r"HTTP 404.*Model not found or not accessible.*test-model",
        ):
            ProductControlledJudge(provider).evaluate(CASE, "anything")


    def test_product_judge_rejects_unpinned_model_metadata(self) -> None:
        class WrongModelProvider:
            provider = "gemini"
            model = "configured-model"

            def judge(self, *, system_prompt, case, output):
                from safety_layer.eval.judge import JudgeDecision

                return JudgeDecision(
                    label="pass",
                    score=1.0,
                    confidence=1.0,
                    rationale="test",
                    provider="gemini",
                    model="different-model",
                    judge_version=GEMINI_JUDGE_VERSION,
                    prompt_version=GEMINI_PROMPT_VERSION,
                )

        with self.assertRaisesRegex(ValueError, "model metadata"):
            ProductControlledJudge(WrongModelProvider()).evaluate(CASE, "ok")

    def test_provider_failure_does_not_fabricate_decision(self) -> None:
        def failing_transport(_request: Request, _timeout: float) -> bytes:
            raise TimeoutError()

        provider = GeminiRubricJudgeProvider(
            api_key="test-key",
            transport=failing_transport,
        )

        with self.assertRaises(GeminiJudgeError):
            ProductControlledJudge(provider).evaluate(CASE, "anything")


def _response(
    *,
    label: str = "pass",
    score: float = 1.0,
    confidence: float = 0.95,
    rationale: str = "The candidate satisfies the rubric.",
    prompt_tokens: int = 20,
    candidate_tokens: int = 10,
) -> bytes:
    return json.dumps(
        {
            "candidates": [
                {
                    "content": {
                        "parts": [
                            {
                                "text": json.dumps(
                                    {
                                        "label": label,
                                        "score": score,
                                        "confidence": confidence,
                                        "rationale": rationale,
                                    }
                                )
                            }
                        ]
                    }
                }
            ],
            "usageMetadata": {
                "promptTokenCount": prompt_tokens,
                "candidatesTokenCount": candidate_tokens,
            },
        }
    ).encode("utf-8")


if __name__ == "__main__":
    unittest.main()
