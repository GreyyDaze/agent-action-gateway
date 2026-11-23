"""In-memory test doubles for the verification suites and tests. Not a product API."""


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
