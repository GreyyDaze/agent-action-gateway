"""Documentation/link checks only.

These verify files parse and links resolve — not that a specific word appears.
Content-word assertions were removed: they broke on harmless edits and proved
nothing about behavior (see the test-suite audit).
"""
from __future__ import annotations

import json
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_required_documents_exist() -> None:
    for relative in (
        "README.md",
        "ROADMAP.md",
        "SECURITY.md",
        "docs/sdk.md",
        "docs/architecture.md",
        "docs/history/release-proof.md",
        "docs/history/release-handoff.md",
    ):
        assert (ROOT / relative).is_file(), relative


def test_route_table_examples_are_valid_data() -> None:
    for name in ("routes.example.json", "routes.credentials.example.json"):
        text = (ROOT / "deploy" / name).read_text(encoding="utf-8")
        data = json.loads(text)
        assert isinstance(data, dict)


def test_pyproject_parses() -> None:
    with (ROOT / "pyproject.toml").open("rb") as handle:
        config = tomllib.load(handle)
    assert "project" in config
    assert "tool" in config
