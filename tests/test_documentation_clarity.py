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
