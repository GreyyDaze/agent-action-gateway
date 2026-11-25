"""Verify that an adopter's agent actually routes actions through the layer.

The library's own suites prove the enforcement path works. They say nothing
about whether a given application uses it, which is the failure this module
exists to catch: an agent that imports a provider directly, or calls the
unenforced runner on a path that changes production, is unprotected while every
published check still reports green.

Two inputs, because neither alone is sufficient:

`--app`
    A static scan of the caller's code. This is the only mode that can see a
    bypass, because a bypass records nothing.

`--db`
    An audit of a trace database. This can only report on actions that were
    recorded, so an empty or unpopulated database is reported as inconclusive.
    Absence of evidence is never reported as safety.
"""

from __future__ import annotations

import ast
import sqlite3
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

PASS = "PASS"
FAIL = "FAIL"
INCONCLUSIVE = "INCONCLUSIVE"


class Status(StrEnum):
    """The three outcomes a check may report.

    `INCONCLUSIVE` exists so that "nothing to look at" can never be rendered
    as a passing result.
    """

    PASS = PASS
    FAIL = FAIL
    INCONCLUSIVE = INCONCLUSIVE


@dataclass(frozen=True)
class Finding:
    """One check result, with the file and line that caused it."""

    name: str
    status: Status
    detail: str
    locations: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status.value,
            "detail": self.detail,
            "locations": list(self.locations),
        }


@dataclass
class Report:
    """The collected result of one `agent-gateway check` invocation."""

    subject: str
    mode: str
    findings: list[Finding] = field(default_factory=list)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    @property
    def status(self) -> Status:
        if any(f.status is Status.FAIL for f in self.findings):
            return Status.FAIL
        if not self.findings or any(
            f.status is Status.INCONCLUSIVE for f in self.findings
        ):
            return Status.INCONCLUSIVE
        return Status.PASS

    def as_dict(self) -> dict[str, Any]:
        return {
            "subject": self.subject,
            "mode": self.mode,
            "status": self.status.value,
            "findings": [f.as_dict() for f in self.findings],
        }

    def render(self) -> str:
        width = max((len(f.name) for f in self.findings), default=0)
        lines = [
            f"SCOPE: your integration — this reports on {self.subject}.",
            "It does not re-verify the library itself.",
            "",
        ]
        for finding in self.findings:
            marks = "." * max(3, width - len(finding.name) + 3)
            lines.append(
                f"{finding.name:<{width}} {marks} {finding.status.value}"
            )
            lines.append(f"    {finding.detail}")
            for location in finding.locations:
                lines.append(f"      at {location}")
        passed = sum(1 for f in self.findings if f.status is Status.PASS)
        total = len(self.findings)
        lines.append("")
        lines.append(f"WIRING: {passed}/{total} — overall {self.status.value}")
        return "\n".join(lines)


# --------------------------------------------------------------------------
# Static scan of the caller's code
# --------------------------------------------------------------------------

# Provider clients that reach the outside world on their own. Reaching one of
# these without the layer means the action is unguarded.
_BYPASS_MODULES = frozenset(
    {
        "anthropic",
        "openai",
        "google.generativeai",
        "boto3",
        "kubernetes",
        "stripe",
    }
)

# Calls that reach the network directly, bypassing the layer. These are the
# shapes that change systems or data without a receipt, whichever SDK is used.
_NETWORK_CALLS = (
    "requests.post(",
    "requests.put(",
    "requests.patch(",
    "requests.delete(",
    "httpx.post(",
    "httpx.put(",
    "httpx.patch(",
    "httpx.delete(",
    "urllib.request.urlopen(",
    "urlopen(",
)

# Calls that name a provider method directly rather than going through a
# guarded tool. The sanctioned interface methods (`execute`, `find`) are
# deliberately absent: calling them from inside a `ctx.tool` wrapper is the
# documented pattern, and calling them from anywhere else is caught by the
# import check.
_PROVIDER_CALLS = frozenset(
    {".rollback(", ".delete(", ".deploy(", ".drop_table(", ".refund(", ".charge(", ".create_payment("}
)


def _inside_a_tool_call(node: ast.AST, wrapped: set[int]) -> bool:
    """True when `node` sits inside a `ctx.tool(...)` argument.

    A wrapper is allowed to call the provider; that call is the guard working,
    not a bypass.
    """
    return id(node) in wrapped


def _collect_wrapped_ids(tree: ast.AST) -> set[int]:
    """Ids of every node lexically inside a `ctx.tool(...)` call."""
    wrapped: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        rendered = _render_call(node.func)
        if rendered is None or ".tool(" not in rendered:
            continue
        for argument in node.args:
            for inner in ast.walk(argument):
                wrapped.add(id(inner))
    return wrapped


def _iter_python_files(root: Path) -> list[Path]:
    if root.is_file():
        return [root] if root.suffix == ".py" else []
    return sorted(
        path
        for path in root.rglob("*.py")
        if "__pycache__" not in path.parts and ".venv" not in path.parts
    )


def scan_code(root: Path) -> Report:
    """Inspect the caller's source for actions that bypass the layer."""
    subject = f"{root}"
    report = Report(subject=subject, mode="--app")

    files = _iter_python_files(root)
    if not files:
        report.add(
            Finding(
                "source files",
                Status.INCONCLUSIVE,
                f"no Python files found under {root}",
            )
        )
        return report

    report.add(
        Finding(
            "source files",
            Status.PASS,
            f"scanned {len(files)} Python file(s) under {root}",
        )
    )

    direct_imports: list[str] = []
    guarded_tools: list[str] = []
    bare_provider_calls: list[str] = []

    for path in files:
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except SyntaxError as exc:
            report.add(
                Finding(
                    "readable source",
                    Status.INCONCLUSIVE,
                    f"{exc}",
                    (f"{path}:{exc.lineno}",),
                )
            )
            continue

        relative = str(path)
        wrapped = _collect_wrapped_ids(tree)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root_name = alias.name.split(".")[0]
                    if root_name in _BYPASS_MODULES:
                        direct_imports.append(f"{relative}:{node.lineno} {alias.name}")
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                root_name = module.split(".")[0]
                if root_name in _BYPASS_MODULES:
                    direct_imports.append(f"{relative}:{node.lineno} {module}")

            if isinstance(node, ast.Call):
                rendered = _render_call(node.func)
                if rendered is None:
                    continue
                if ".tool(" in rendered:
                    guarded_tools.append(f"{relative}:{node.lineno}")
                if _inside_a_tool_call(node, wrapped):
                    continue
                for marker in _PROVIDER_CALLS:
                    if marker in rendered:
                        bare_provider_calls.append(f"{relative}:{node.lineno} {rendered}")
                source = ast.unparse(node.func) if hasattr(ast, "unparse") else rendered
                for marker in _NETWORK_CALLS:
                    if marker.rstrip("(") in source and marker not in source:
                        # e.g. requests.post(...) written as a bare name
                        bare_provider_calls.append(
                            f"{relative}:{node.lineno} {source}"
                        )

    report.add(
        Finding(
            "tools wrapped with ctx.tool",
            Status.PASS if guarded_tools else Status.INCONCLUSIVE,
            (
                f"{len(guarded_tools)} call(s) wrap a tool"
                if guarded_tools
                else "no ctx.tool(...) calls found; cannot confirm any action is guarded"
            ),
            tuple(guarded_tools[:5]),
        )
    )

    report.add(
        Finding(
            "direct provider imports",
            Status.FAIL if direct_imports else Status.PASS,
            (
                f"{len(direct_imports)} import(s) reach an outside service directly"
                if direct_imports
                else "no direct provider or model-client imports"
            ),
            tuple(direct_imports[:5]),
        )
    )

    report.add(
        Finding(
            "provider calls outside a wrapper",
            Status.FAIL if bare_provider_calls else Status.PASS,
            (
                f"{len(bare_provider_calls)} call(s) invoke a provider method directly"
                if bare_provider_calls
                else "every provider call goes through a wrapper"
            ),
            tuple(bare_provider_calls[:5]),
        )
    )

    return report


def _render_call(node: ast.expr) -> str | None:
    """Render `a.b.c(...)` so a call site can be matched by shape."""
    parts: list[str] = []
    current: ast.expr = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
        return "." + ".".join(reversed(parts)) + "("
    return None


# --------------------------------------------------------------------------
# Audit of the caller's trace database
# --------------------------------------------------------------------------

# Actions that move something irreversible and therefore must be recorded.
_DESTRUCTIVE_MARKERS = ("rollback", "delete", "drop", "deploy", "write", "refund", "charge", "payment")


def audit_database(path: Path) -> Report:
    """Audit recorded actions. Absence of records is never treated as safety."""
    subject = f"{path}"
    report = Report(subject=subject, mode="--db")

    if not path.exists():
        report.add(
            Finding(
                "database",
                Status.INCONCLUSIVE,
                f"no database at {path}",
            )
        )
        return report

    try:
        connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        connection.row_factory = sqlite3.Row
        tables = {
            row["name"]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
    except sqlite3.Error as exc:
        report.add(Finding("database", Status.INCONCLUSIVE, f"cannot read: {exc}"))
        return report

    try:
        if "trace_events" not in tables:
            report.add(
                Finding(
                    "database",
                    Status.INCONCLUSIVE,
                    f"{path} has no trace_events table; it was not written by this layer",
                )
            )
            return report

        rows = connection.execute("SELECT * FROM trace_events").fetchall()
        if not rows:
            report.add(
                Finding(
                    "recorded actions",
                    Status.INCONCLUSIVE,
                    "no traces recorded. An action that bypassed the layer would "
                    "leave nothing behind, so an empty database is not evidence "
                    "that nothing is unguarded",
                )
            )
            return report

        destructive = [
            row
            for row in rows
            if any(marker in str(dict(row)).lower() for marker in _DESTRUCTIVE_MARKERS)
        ]

        report.add(
            Finding(
                "recorded actions",
                Status.PASS,
                f"{len(rows)} action(s) recorded, {len(destructive)} of them "
                f"looking irreversible",
            )
        )

        # Now that the path is persisted, an audit can finally answer whether
        # these runs were protected or merely recorded.
        modes = [row["enforcement"] for row in rows]
        observed = sum(1 for mode in modes if mode == "observe")
        enforced = sum(1 for mode in modes if mode == "enforced")
        unknown = sum(1 for mode in modes if mode is None)
        if observed and enforced or observed:
            run_path_status = Status.FAIL
        elif enforced:
            run_path_status = Status.PASS
        else:
            run_path_status = Status.INCONCLUSIVE
        report.add(
            Finding(
                "run path",
                run_path_status,
                (
                    f"{enforced} enforced, {observed} observe-only, {unknown} "
                    f"unrecorded"
                ),
                (
                    (
                        f"{observed} action(s) were recorded in observe mode, which "
                        f"does not enforce anything; use session() for protection"
                    ),
                )
                if observed
                else (),
            )
        )

        if "receipts" in tables:
            total = connection.execute("SELECT COUNT(*) FROM receipts").fetchone()[0]
            # A receipt left in a non-terminal state means an action was
            # interrupted after it may already have taken effect.
            terminal = ("done", "failed", "resolved")
            placeholders = ",".join("?" for _ in terminal)
            unresolved = connection.execute(
                f"SELECT intent_key, state FROM receipts "  # noqa: S608 - fixed shape
                f"WHERE state NOT IN ({placeholders})",
                terminal,
            ).fetchall()
            report.add(
                Finding(
                    "receipts",
                    Status.PASS if not unresolved else Status.FAIL,
                    (
                        f"{total} receipt(s), all in a terminal state"
                        if not unresolved
                        else f"{len(unresolved)} of {total} receipt(s) left "
                        f"unresolved ({', '.join(sorted({str(r['state']) for r in unresolved}))}); "
                        f"an interrupted action may have taken effect"
                    ),
                    tuple(f"{r['intent_key']} is {r['state']}" for r in unresolved[:5]),
                )
            )
        else:
            report.add(
                Finding(
                    "receipts",
                    Status.INCONCLUSIVE,
                    "no receipts table; an interrupted action cannot be ruled out",
                )
            )
    finally:
        connection.close()

    return report


def run_check(*, app: str | None, db: str | None) -> Report:
    """Produce the report for whichever inputs were supplied."""
    if app:
        return scan_code(Path(app))
    if db:
        return audit_database(Path(db))
    return Report(
        subject="nothing (no input given)",
        mode="none",
        findings=[
            Finding(
                "input",
                Status.INCONCLUSIVE,
                "supply --app <module:callable or path> or --db <database>",
            )
        ],
    )
