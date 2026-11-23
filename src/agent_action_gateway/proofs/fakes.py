"""In-memory test doubles for the verification suites and tests. Not a product API."""
from dataclasses import dataclass


@dataclass(frozen=True)
class Deployment:
    deployment_id: str
    owner: str
    rollback_due: bool


class MockProvider:
    """Reference provider for baseline; no safety guards are applied yet."""

    def __init__(self) -> None:
        self.deployments = {
            "DEP-100": Deployment("DEP-100", "Ava", True),
            "DEP-200": Deployment("DEP-200", "Noah", False),
        }
        self.rollbacks: list[dict[str, str]] = []

    def lookup_deployment(self, owner: str) -> Deployment | None:
        return next((d for d in self.deployments.values() if d.owner.lower() == owner.lower()), None)

    def rollback(self, deployment_id: str) -> dict[str, str]:
        self.rollbacks.append({"deployment_id": deployment_id, "status": "rolled_back"})
        return self.rollbacks[-1]


class MockEffectProvider:
    """Failure-injection test double. It is not the production external-action path."""

    def __init__(self, *, dedupe: bool) -> None:
        self.dedupe = dedupe
        self.rollbacks: list[dict[str, str]] = []

    def execute(self, target: str, intent_key: str) -> str:
        if self.dedupe:
            existing = next((item for item in self.rollbacks if item["intent_key"] == intent_key), None)
            if existing is not None:
                return existing["provider_ref"]
        provider_ref = f"mock-{len(self.rollbacks) + 1}"
        self.rollbacks.append({"intent_key": intent_key, "target": target, "provider_ref": provider_ref})
        return provider_ref

    def find(self, intent_key: str, target: str | None = None) -> str | None:
        item = next((item for item in self.rollbacks if item["intent_key"] == intent_key), None)
        return None if item is None else item["provider_ref"]
