"""The README's code examples must do what their comments say.

The quick start is the first code a reader runs. Each call in it carries a
comment saying whether it is blocked or allowed; this test runs the example
as written and checks every one of those outcomes, so the README cannot drift
from the code.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from agent_action_gateway.runtime.session import SafetySession

ROOT = Path(__file__).resolve().parents[1]


def _python_blocks() -> list[str]:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    return re.findall(r"~~~python\n(.*?)~~~", readme, re.S)


def test_quick_start_outcomes_match_its_comments(tmp_path, monkeypatch) -> None:
    blocks = _python_blocks()
    assert len(blocks) == 2, "expected the quick start and the run example"
    quick_start, run_example = blocks

    # Each commented call states its expected outcome; read them from the text.
    expected = re.findall(r"^\s*drop\(.*\)\s*# (blocked|allowed)", quick_start, re.M)
    assert expected, "the quick start should annotate its calls"

    outcomes: list[str] = []
    original = SafetySession.tool

    def recording_tool(self, fn, **kwargs):
        guarded = original(self, fn, **kwargs)

        def call(*args, **kw):
            result = guarded(*args, **kw)
            outcomes.append(result["status"])
            return result

        return call

    monkeypatch.setattr(SafetySession, "tool", recording_tool)
    monkeypatch.chdir(tmp_path)  # the default store writes data/runtime.db

    # Run the second example inside the first one's session, with a small agent
    # that tries an action nobody approved.
    indented_run = "".join(f"    {line}\n" for line in run_example.splitlines())
    code = (
        quick_start
        + "    def agent(task, tools):\n"
        + "        return tools['drop_table'](table='deployments')\n"
        + "    task = 'clean up old tables'\n"
        + indented_run
    )
    namespace: dict = {}
    exec(compile(code, "README.md", "exec"), namespace)  # noqa: S102

    assert outcomes[: len(expected)] == expected
    assert outcomes[len(expected):] == ["blocked"], "the unapproved agent action must be refused"
    assert namespace["result"]["status"] == "blocked"
    assert os.path.exists(tmp_path / "data" / "runtime.db")
