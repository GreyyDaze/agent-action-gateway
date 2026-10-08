"""Documentation and packaging clarity.

Two failure modes are checked here, both of which have already happened once:

1. Internal identifiers leaking into files a reader outside the project sees.
   The proof output was labelled `P1`-`P6`, which meant nothing until you read
   the build plan. Rule IDs such as `R-11` had the same problem in source.
2. Packaging metadata that misleads an installed user: a package name that
   collides with someone else's, or metadata with no homepage.
"""

from __future__ import annotations

import ast
import re
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src" / "safety_layer"

# Internal shorthand. None of it means anything to a reader who has not read
# the project's own planning documents.
INTERNAL_IDS = re.compile(r"\b(?:R-\d{2}|FR-\d{1,2}|E[1-5]\.\d{1,2}|P[1-6])\b")


class NoInternalJargonTest(unittest.TestCase):
    """Public-facing files must read without the project's planning docs."""

    PUBLIC_FILES = (
        "README.md",
        "docs/sdk.md",
        "SECURITY.md",
        "docs/examples/quickstart.py",
    )

    def test_public_docs_contain_no_internal_identifiers(self) -> None:
        for relative in self.PUBLIC_FILES:
            path = ROOT / relative
            with self.subTest(file=relative):
                self.assertTrue(path.is_file(), f"{relative} is missing")
                found = INTERNAL_IDS.findall(path.read_text(encoding="utf-8"))
                self.assertEqual(
                    found, [], f"{relative} leaks internal identifiers: {found}"
                )

    def test_shipped_source_docstrings_contain_no_internal_identifiers(self) -> None:
        """Rule IDs live in docs/, not in the code someone has to maintain."""
        offenders: list[str] = []
        for module in sorted(SOURCE.rglob("*.py")):
            if "__pycache__" in str(module):
                continue
            relative = module.relative_to(SOURCE)
            tree = ast.parse(module.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if not isinstance(
                    node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
                ):
                    continue
                docstring = ast.get_docstring(node)
                if not docstring:
                    continue
                if INTERNAL_IDS.search(docstring):
                    name = getattr(node, "name", "<module>")
                    offenders.append(f"{relative}:{name}")
        self.assertEqual(offenders, [], f"internal identifiers in docstrings: {offenders}")

    def test_shipped_source_comments_contain_no_internal_identifiers(self) -> None:
        offenders: list[str] = []
        for module in sorted(SOURCE.rglob("*.py")):
            if "__pycache__" in str(module):
                continue
            relative = module.relative_to(SOURCE)
            for number, line in enumerate(
                module.read_text(encoding="utf-8").splitlines(), start=1
            ):
                if "#" not in line:
                    continue
                # Drop string literals so colour codes and messages are exempt.
                prose = re.sub(r'"[^"]*"|\'[^\']*\'', "", line)
                if INTERNAL_IDS.search(prose):
                    offenders.append(f"{relative}:{number}")
        self.assertEqual(offenders, [], f"internal identifiers in comments: {offenders}")

    def test_proof_output_is_labelled_by_property(self) -> None:
        """Regression guard for the P1-P6 relabel."""
        from safety_layer.proofs.proof import PROOFS

        for guarantee, _paths, _statement in PROOFS:
            with self.subTest(guarantee=guarantee):
                self.assertIsNone(
                    INTERNAL_IDS.fullmatch(guarantee),
                    f"proof label {guarantee!r} is still a phase number",
                )
                self.assertGreater(len(guarantee.split()), 1)


class PackagingMetadataTest(unittest.TestCase):
    """Metadata an installed user can act on."""

    @classmethod
    def setUpClass(cls) -> None:
        with (ROOT / "pyproject.toml").open("rb") as handle:
            cls.config = tomllib.load(handle)

    def test_project_links_are_declared(self) -> None:
        urls = self.config["project"].get("urls", {})
        for key in ("Homepage", "Repository", "Issues"):
            with self.subTest(url=key):
                self.assertIn(key, urls, f"[project.urls] is missing {key}")
                self.assertTrue(str(urls[key]).startswith("https://"))

    def test_package_name_matches_the_repository(self) -> None:
        """A mismatched name publishes to the wrong PyPI project."""
        name = self.config["project"]["name"]
        self.assertEqual(
            name,
            "agent-safety-eval-layer",
            "package name must match the repository to avoid a PyPI collision",
        )

    def test_version_is_a_release_version(self) -> None:
        version = self.config["project"]["version"]
        self.assertRegex(version, r"^\d+\.\d+\.\d+$")

    def test_license_file_exists(self) -> None:
        declared = str(self.config["project"].get("license", {}).get("text", "")).upper()
        if declared:
            self.assertTrue(
                (ROOT / "LICENSE").is_file(),
                "a license is declared in metadata but no LICENSE file exists",
            )


class ErrorMessageClarityTest(unittest.TestCase):
    """An error message is the first documentation an adopter ever reads.

    Messages that describe the file through the project's own vocabulary tell
    someone bringing their own data nothing they can act on. Each message has
    to name the field to change, or the count that is wrong, or the reason the
    rule exists.
    """

    # Vocabulary from the project's planning documents and internal model.
    # A message may still mention the case file's own field names, or a
    # command-line flag the reader typed themselves.
    #
    # Deliberately absent: "wall", because "wall-clock" is ordinary English,
    # and "candidate", because a hosted model provider uses the word for its
    # own output. Those are not the project's private vocabulary.
    OFFENDING_TERMS = (
        "golden",
        "catastrophic",
        "fuse",
        "lane",
    )

    def _messages(self) -> dict[str, str]:
        import re

        found: dict[str, str] = {}
        pattern = re.compile(r'raise\s+\w+(?:Error|Exception)\(\s*f?["\']([^"\']+)["\']')
        for module in sorted(SOURCE.rglob("*.py")):
            if "__pycache__" in str(module):
                continue
            for number, line in enumerate(
                module.read_text(encoding="utf-8").splitlines(), start=1
            ):
                match = pattern.search(line)
                if match:
                    found[f"{module.relative_to(SOURCE)}:{number}"] = match.group(1)
        return found

    def test_raised_messages_do_not_use_internal_vocabulary(self) -> None:
        offenders = {
            where: message
            for where, message in self._messages().items()
            if any(
                re.search(rf"\b{term}\b", message, re.IGNORECASE)
                for term in self.OFFENDING_TERMS
            )
        }
        self.assertEqual(offenders, {}, f"jargon in error messages: {offenders}")

    def test_golden_loader_messages_name_the_field_to_fix(self) -> None:
        """Each loader failure must point at a concrete field or count."""
        import json
        import tempfile

        from safety_layer.evaluation.golden import load_golden_set
        from safety_layer.evaluation.models import GOLDEN_SET_VERSION

        def case(index: int = 1, *, catastrophic: bool = False) -> dict[str, object]:
            return {
                "case_id": f"c{index}",
                "task": "do the thing",
                "expected": {"ok": True},
                "check_type": "exact",
                "source": "test",
                "catastrophic": catastrophic,
                "rubric": [],
            }

        def message_for(payload: object) -> str:
            directory = Path(tempfile.mkdtemp())
            path = directory / "golden-v1.json"
            path.write_text(
                payload if isinstance(payload, str) else json.dumps(payload),
                encoding="utf-8",
            )
            with self.assertRaises(ValueError) as caught:
                load_golden_set(path)
            return str(caught.exception)

        scenarios = {
            "version": (
                {"version": "v9", "cases": [case(i, catastrophic=i == 1) for i in range(1, 13)]},
                '"version"',
            ),
            "cases key": (
                {"version": GOLDEN_SET_VERSION},
                '"cases"',
            ),
            "too few": (
                {"version": GOLDEN_SET_VERSION,
                 "cases": [case(i, catastrophic=i == 1) for i in range(1, 4)]},
                "at least 10",
            ),
            "no catastrophic": (
                {"version": GOLDEN_SET_VERSION, "cases": [case(i) for i in range(1, 13)]},
                '"catastrophic": true',
            ),
            "bad check type": (
                {"version": GOLDEN_SET_VERSION,
                 "cases": [{**case(i, catastrophic=i == 1), "check_type": "vibes"}
                           for i in range(1, 13)]},
                '"check_type"',
            ),
            "duplicate id": (
                {"version": GOLDEN_SET_VERSION,
                 "cases": [case(1, catastrophic=True)] + [case(1) for _ in range(11)]},
                "unique",
            ),
            "missing field": (
                {"version": GOLDEN_SET_VERSION,
                 "cases": [{k: v for k, v in case(i, catastrophic=i == 1).items()
                            if k != "task"} for i in range(1, 13)]},
                "task",
            ),
            "malformed json": ("{ not json", "JSON"),
        }

        for label, (payload, expected) in scenarios.items():
            with self.subTest(scenario=label):
                self.assertIn(expected, message_for(payload))


class PublicSurfaceTest(unittest.TestCase):
    """__all__ should name what a consumer needs, not every internal type."""

    def test_public_surface_is_minimal(self) -> None:
        """Advertising internals invites callers to depend on them."""
        import safety_layer

        self.assertEqual(
            sorted(safety_layer.__all__),
            ["FuseLimits", "SafetySession", "run", "session"],
        )

    def test_documented_entry_points_are_importable(self) -> None:
        import safety_layer

        for name in safety_layer.__all__:
            with self.subTest(name=name):
                self.assertTrue(hasattr(safety_layer, name))

    def test_session_exposes_the_documented_methods(self) -> None:
        from safety_layer.runtime.session import SafetySession

        for method in ("tool", "run", "request_approval", "approve", "deny"):
            with self.subTest(method=method):
                self.assertTrue(callable(getattr(SafetySession, method, None)))


if __name__ == "__main__":
    unittest.main()
