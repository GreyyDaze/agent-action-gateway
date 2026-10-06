from .models import GateVerdict
from .store import TraceStore


def evaluate(run_id: str, store: TraceStore, score: float = 1.0, threshold: float = 0.8) -> GateVerdict:
    """Phase 0 gate: one run, one score, one deterministic threshold."""
    verdict = "PASS" if score >= threshold else "FAIL"
    result = GateVerdict(run_id=run_id, verdict=verdict, score=score, threshold=threshold)
    store.append_gate(result)
    return result
