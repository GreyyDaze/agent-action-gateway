from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_documentation_scope_documents_exist() -> None:
    assert (ROOT / "docs" / "sdk.md").is_file()
    assert (ROOT / "ROADMAP.md").is_file()
    assert (ROOT / "docs" / "history" / "release-proof.md").is_file()
    assert (ROOT / "docs" / "history" / "release-handoff.md").is_file()


def test_documentation_roadmap_has_eight_deferred_and_eight_non_goals() -> None:
    text = (ROOT / "ROADMAP.md").read_text(encoding="utf-8")
    deferred = ["E1.4", "E2.7", "E3.11", "E4.6", "E4.8", "E5.4", "E5.5", "E5.6"]
    non_goals = ["E1.7", "E2.4", "E2.9", "E4.5", "E4.7", "E4.9", "E5.7", "E5.9"]

    assert all(item in text for item in deferred)
    assert all(item in text for item in non_goals)


def test_documentation_sdk_documents_gate_exit_contract() -> None:
    text = (ROOT / "docs" / "sdk.md").read_text(encoding="utf-8")
    assert "PASS" in text and "0" in text
    assert "FAIL" in text and "1" in text
    assert "UNCERTAIN" in text and "2" in text
    assert "not" in text.lower() and "false regression" in text.lower()
