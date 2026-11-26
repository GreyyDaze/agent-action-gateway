"""Deployment boundary: the refusals and the shipped examples.

These cover the two halves of a deployment claim. The gateway half is code we
own and can therefore assert on. The topology half is the adopter's OS, which
we cannot assert -- that is what `make verify-boundary` is for, and it runs in
the adopter's environment, not here.

The example configs are tested because a shipped example that cannot be parsed
is worse than none: it is a first-run failure discovered by a stranger.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

from agent_action_gateway.cli import load_route_policy
from agent_action_gateway.integrations.gateway import (
    GatewayError,
    GatewayPolicy,
    Route,
    SafetyGateway,
    build_gateway_server,
)
from agent_action_gateway.storage.traces import TraceStore

ROOT = Path(__file__).resolve().parents[1]
DEPLOY = ROOT / "deploy"
PROBE = ROOT / "src" / "agent_action_gateway" / "verify_boundary.py"


class ShippedExamplesTest(unittest.TestCase):
    """The reference deployment must work on a default install."""

    def test_json_example_parses_without_a_third_party_parser(self) -> None:
        """The library is stdlib-only, so the default example must be JSON.

        A YAML example needs PyYAML, which is an optional extra. Shipping YAML
        as the default meant the documented first run failed on a clean install.
        """
        policy = load_route_policy(str(DEPLOY / "routes.example.json"))
        self.assertIn("/deploy", policy.routes)
        self.assertEqual(policy.master_key_env, "AGENT_GATEWAY_MASTER_KEY")

    def test_every_route_uses_a_post_body(self) -> None:
        """The HTTP shell exposes POST only; a GET route is dead config."""
        policy = load_route_policy(str(DEPLOY / "routes.example.json"))
        for route in policy.routes.values():
            self.assertEqual(route.method, "POST", f"{route.path} is unreachable")

    def test_no_route_references_a_bare_environment_variable_for_its_secret(self) -> None:
        """A file can have an owner and a mode. An env var cannot.

        The example is the thing people copy, so it has to model the practice it
        asks for rather than the one it merely permits.
        """
        policy = load_route_policy(str(DEPLOY / "routes.example.json"))
        for route in policy.routes.values():
            if route.secret_env:
                self.assertTrue(
                    route.secret_env.startswith("file:"),
                    f"{route.path} uses a bare variable; copy the file: form",
                )

    def test_compose_does_not_ship_an_agent_service(self) -> None:
        """The adopter's agent is their code; faking one would imply we ship it.

        It would also be circular: we strip its key, block its egress, then
        announce it cannot reach a provider.
        """
        compose = (DEPLOY / "docker-compose.yml").read_text(encoding="utf-8")
        self.assertNotIn("\n  agent:", compose)
        self.assertIn("agent_net", compose)

    def test_probe_is_named_for_what_it_is(self) -> None:
        """It is a probe, not an agent."""
        self.assertTrue(PROBE.exists())
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        self.assertIn("verify-boundary", makefile)
        self.assertNotIn("verify-agent", makefile)

    def test_default_network_fails_closed(self) -> None:
        """The default must be the safe one.

        An adopter who follows the reference file with no changes should get the
        barrier, not a silently weaker setup.
        """
        compose = (DEPLOY / "docker-compose.yml").read_text(encoding="utf-8")
        self.assertIn("internal: true", compose)

    def test_the_egress_override_states_what_it_gives_up(self) -> None:
        """An override that only relaxes a control is a trap if it is quiet.

        Most real agents do need egress -- a deployment agent also calls a model
        API. So the override has to exist, and it has to say that turning egress
        on means a leaked key becomes usable.
        """
        override = (DEPLOY / "docker-compose.egress.yml").read_text(encoding="utf-8")
        self.assertIn("internal: false", override)
        self.assertIn("WHAT THIS GIVES UP", override)
        self.assertIn("leaked", override.lower())


class SecretFileRefusalTest(unittest.TestCase):
    """A credential the agent can read is not a credential the gateway holds."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.path = Path(self._tmp.name) / "github_token"
        self.path.write_text("ghp_example")

    def _route(self) -> Route:
        return Route(
            path="/deploy",
            upstream="https://example.invalid",
            action="deploy",
            secret_env=f"file:{self.path}",
        )

    def test_a_readable_file_is_accepted(self) -> None:
        self.path.chmod(0o600)
        self.assertEqual(self._route().credential(), "ghp_example")

    def test_a_group_readable_file_is_refused(self) -> None:
        self.path.chmod(0o640)
        with self.assertRaises(GatewayError) as raised:
            self._route().credential()
        self.assertIn("0600", str(raised.exception))

    def test_a_world_readable_file_is_refused(self) -> None:
        self.path.chmod(0o604)
        with self.assertRaises(GatewayError):
            self._route().credential()

    def test_a_missing_file_is_a_clear_error(self) -> None:
        self.path.unlink()
        with self.assertRaises(GatewayError) as raised:
            self._route().credential()
        self.assertIn("not found", str(raised.exception))

    def test_refusal_names_the_mode_rather_than_just_failing(self) -> None:
        """An operator has to be able to fix this without reading our source."""
        self.path.chmod(0o644)
        with self.assertRaises(GatewayError) as raised:
            self._route().credential()
        message = str(raised.exception)
        self.assertIn(str(self.path), message)
        self.assertIn("0o644", message)

    def test_a_secret_owned_by_another_user_is_refused(self) -> None:
        """Ownership, not just mode, is half of what makes a file a secret.

        Mode alone is satisfied by any file the operator's own uid created, so
        a test that only chmods would never reach this branch -- everything on a
        developer machine is owned by the same user.
        """
        self.path.chmod(0o600)
        real_stat = os.stat

        def stat_owned_by_someone_else(target, *args, **kwargs):
            info = real_stat(target, *args, **kwargs)
            return os.stat_result(
                (
                    info.st_mode,
                    info.st_ino,
                    info.st_dev,
                    info.st_nlink,
                    info.st_uid + 4242,  # not us
                    info.st_gid,
                    info.st_size,
                    info.st_atime,
                    info.st_mtime,
                    info.st_ctime,
                )
            )

        with unittest.mock.patch("os.stat", side_effect=stat_owned_by_someone_else):
            with self.assertRaises(GatewayError) as raised:
                self._route().credential()
        self.assertIn("owned by gateway user", str(raised.exception))


class EmbeddedLaunchRefusalTest(unittest.TestCase):
    """A gateway inside the agent's process has no custody at all.

    The agent can read the same environment the key came from, so the property
    the gateway claims does not merely weaken -- it is absent.
    """

    def test_building_a_server_from_a_script_is_refused(self) -> None:
        """The common case: a module in the agent's own codebase.

        This is a signal, not a boundary. It keys on the launcher having a
        __main__ file, so it cannot see an embed through `python -c`, exec() or
        a REPL. The refusals that hold regardless are the secret-file owner and
        mode checks; this one exists to make the ordinary mistake loud.
        """
        previous = os.environ.pop("AGENT_GATEWAY", None)
        self.addCleanup(
            lambda: os.environ.__setitem__("AGENT_GATEWAY", previous)
            if previous is not None
            else None
        )
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "embed_gateway.py"
            script.write_text(
                "from agent_action_gateway.integrations.gateway import build_gateway_server, "
                "GatewayPolicy\n"
                "from agent_action_gateway.storage.traces import TraceStore\n"
                f"build_gateway_server(TraceStore({str(Path(directory) / 'r.db')!r}), "
                "GatewayPolicy())\n"
            )
            result = subprocess.run(
                [sys.executable, str(script)],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
        self.assertNotEqual(result.returncode, 0, "embedded launch was allowed")
        self.assertIn("embedded", (result.stderr + result.stdout).lower())

    def test_the_cli_launch_path_is_allowed(self) -> None:
        os.environ["AGENT_GATEWAY"] = "1"
        self.addCleanup(os.environ.pop, "AGENT_GATEWAY", None)
        server, handler = build_gateway_server(
            TraceStore(Path(self.enterContext(tempfile.TemporaryDirectory())) / "r.db"),
            load_route_policy(str(DEPLOY / "routes.example.json")),
            port=0,
        )
        self.addCleanup(server.server_close)
        self.assertTrue(hasattr(handler, "access_token"))


class ProbeShippedWithThePackageTest(unittest.TestCase):
    """The probe is a command of the installed package, and stays standalone."""

    def test_the_command_runs_the_probe(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "agent_action_gateway.cli", "verify-boundary",
             "--gateway", "http://127.0.0.1:9", "--key", "unused"],
            cwd=ROOT, capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("INCONCLUSIVE", result.stdout)

    def test_the_file_imports_nothing_from_the_package(self) -> None:
        """If it imported our code, a bug in our code could make it pass."""
        import ast

        tree = ast.parse(PROBE.read_text(encoding="utf-8"))
        imported = [
            alias.name for node in ast.walk(tree) if isinstance(node, ast.Import)
            for alias in node.names
        ] + [
            node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
        ]
        self.assertFalse([name for name in imported if "agent_action_gateway" in name])


class ProbeInconclusiveTest(unittest.TestCase):
    """A check that cannot run must never report success."""

    def _probe(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(PROBE), *args],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )

    def test_an_unreachable_gateway_is_inconclusive_not_a_pass(self) -> None:
        result = self._probe("--gateway", "http://127.0.0.1:9", "--key", "unused")
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertIn("INCONCLUSIVE", result.stdout)
        self.assertNotIn("BOUNDARY HELD", result.stdout)

    def test_it_states_what_it_does_not_prove(self) -> None:
        """The output says what the probe does not prove."""
        result = self._probe("--gateway", "http://127.0.0.1:9")
        self.assertIn("Does NOT prove", result.stdout)


class DoctorScopeTest(unittest.TestCase):
    """The doctor reports this host, and says so.

    It cannot observe the agent's network -- a different machine, namespace or
    container.
    """

    def _run(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-m", "agent_action_gateway.cli", "gateway", "doctor", *args],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )

    def test_it_declares_the_scope_it_can_actually_check(self) -> None:
        result = self._run("--config", str(DEPLOY / "routes.example.json"))
        self.assertIn("agent-gateway verify-boundary", result.stdout)

    def test_a_missing_secret_file_is_reported_as_a_problem(self) -> None:
        result = self._run("--config", str(DEPLOY / "routes.example.json"))
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("/run/secrets/github_token", result.stdout)

    def test_an_unreadable_config_is_reported_not_crashed(self) -> None:
        result = self._run("--config", "/nonexistent/routes.json")
        self.assertEqual(result.returncode, 1)
        self.assertIn("could not read", (result.stderr + result.stdout))

    def test_it_says_it_does_not_cover_the_proxy(self) -> None:
        result = self._run("--config", str(DEPLOY / "routes.example.json"))
        self.assertIn("not the MCP proxy", result.stdout)
        self.assertIn("agent-gateway verify-boundary", result.stdout)


class DoctorCredentialsBlockTest(unittest.TestCase):
    """A secret in the `credentials` block is checked like a route's secret.

    Before, doctor crashed with a traceback when that secret was missing or had
    the wrong mode, and never reported on it when it was fine.
    """

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.secret = self.dir / "token"
        example = (DEPLOY / "routes.credentials.example.json").read_text(encoding="utf-8")
        self.config = self.dir / "routes.json"
        self.config.write_text(
            example.replace("/run/secrets/github_token", str(self.secret)), encoding="utf-8"
        )

    def _run(self, *before: str) -> subprocess.CompletedProcess[str]:
        env = {**os.environ, "AGENT_GATEWAY_MASTER_KEY": "test-master-key"}
        return subprocess.run(
            [sys.executable, "-m", "agent_action_gateway.cli", "gateway", *before,
             "doctor", "--config", str(self.config)],
            cwd=ROOT, capture_output=True, text=True, env=env,
        )

    def test_a_missing_secret_is_a_failure_not_a_traceback(self) -> None:
        result = self._run()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("[FAIL] credential GITHUB_TOKEN secret", result.stdout)
        self.assertNotIn("Traceback", result.stderr)

    def test_a_readable_by_others_secret_is_a_failure(self) -> None:
        self.secret.write_text("t", encoding="utf-8")
        self.secret.chmod(0o644)
        result = self._run()
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("mode 0644", result.stdout)

    def test_a_good_secret_is_reported_as_checked(self) -> None:
        self.secret.write_text("t", encoding="utf-8")
        self.secret.chmod(0o600)
        result = self._run()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("[OK] credential GITHUB_TOKEN secret", result.stdout)

    def test_the_user_name_comes_from_the_user_list(self) -> None:
        import pwd

        self.secret.write_text("t", encoding="utf-8")
        self.secret.chmod(0o600)
        result = self._run()
        self.assertIn(f"running as {pwd.getpwuid(os.geteuid()).pw_name}", result.stdout)

    def test_a_bind_beyond_this_machine_is_a_warning(self) -> None:
        self.secret.write_text("t", encoding="utf-8")
        self.secret.chmod(0o600)
        result = self._run("--host", "0.0.0.0")
        self.assertIn("[WARN] bind address", result.stdout)


class MethodGuardTest(unittest.TestCase):
    """A route the gateway can never serve must fail loudly at load time."""

    def test_a_get_route_is_refused_with_an_explanation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "routes.json"
            path.write_text(
                json.dumps(
                    {
                        "routes": [
                            {
                                "path": "/deploy",
                                "upstream": "https://example.invalid",
                                "action": "deploy",
                                "method": "GET",
                            }
                        ]
                    }
                )
            )
            with self.assertRaises(ValueError) as raised:
                load_route_policy(str(path))
            self.assertIn("POST only", str(raised.exception))


if __name__ == "__main__":
    unittest.main()


class CredentialUnavailableTest(unittest.TestCase):
    """A secret the gateway cannot read must be a refusal, not a dead socket.

    Found by running the gateway as a different user than the owner of its own
    secret file: `GatewayError` escaped `handle`, the handler thread died, and
    the caller received nothing at all.
    """

    def _gateway(self, store: TraceStore) -> SafetyGateway:
        policy = GatewayPolicy(session_environment="prod")
        policy.register(
            Route(
                path="/deploy",
                upstream="https://example.invalid",
                action="deploy",
                risk="read",
                secret_env="file:/definitely/not/here",
                environment="prod",
            )
        )
        return SafetyGateway(store, policy, transport=lambda *a: (200, {"ok": True}))

    def test_an_unreadable_secret_returns_a_refusal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = TraceStore(Path(directory) / "r.db")
            result = self._gateway(store).handle("POST", "/deploy", {})
        self.assertEqual(result.status, 503)
        self.assertIn("credential unavailable", result.body["error"])

    def test_the_refusal_does_not_disclose_the_path_or_owner(self) -> None:
        """The detail names a file path and a uid. That is for the trace, not
        for whoever made the request."""
        with tempfile.TemporaryDirectory() as directory:
            store = TraceStore(Path(directory) / "r.db")
            result = self._gateway(store).handle("POST", "/deploy", {})
        rendered = json.dumps(result.body)
        self.assertNotIn("/definitely/not/here", rendered)
        self.assertNotIn("uid", rendered)

    def test_the_reason_is_traced_even_though_it_is_not_returned(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = TraceStore(Path(directory) / "r.db")
            self._gateway(store).handle("POST", "/deploy", {})
            events = [t["event"] for t in store.snapshot()["traces"]]
        self.assertIn("gateway.credential_unavailable", events)


class PeerCredRefusalShapeTest(unittest.TestCase):
    """The same-UID refusal must answer, and must not stop the accept loop.

    The original closed the socket and raised. The caller saw a reset rather
    than a reason, and the exception escaped `get_request` into the serve loop,
    so one rejected caller took the gateway down for everyone.
    """

    def test_the_server_exposes_a_refusal_writer(self) -> None:
        from agent_action_gateway.integrations.gateway import _UnixSocketServer

        self.assertTrue(callable(getattr(_UnixSocketServer, "_refuse", None)))

    def test_get_request_does_not_raise_for_a_same_uid_caller(self) -> None:
        """It returns a connection and writes the refusal, rather than raising.

        Asserted against the source because constructing a real peercred socket
        needs two Linux users; `deploy/` and the Linux job exercise the real
        path. The guard here is that the raise is gone.
        """
        import inspect

        from agent_action_gateway.integrations.gateway import _UnixSocketServer

        source = inspect.getsource(_UnixSocketServer.get_request)
        self.assertNotIn("raise GatewayError", source)
        self.assertIn("_refuse", source)
