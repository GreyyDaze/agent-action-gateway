"""The proxy's reference deployment: the shape that keeps the agent out.

The real check runs with Docker (`make verify-proxy-boundary`). These tests pin
the file so an edit cannot quietly put the agent next to the gateway, publish
the dashboard to the network, or drop the probe.
"""

from __future__ import annotations

import os
import subprocess
import sys
import unittest
import unittest.mock
from pathlib import Path

from agent_action_gateway.integrations.mcp_proxy import load_proxy_config

ROOT = Path(__file__).resolve().parents[1]
DEPLOY = ROOT / "deploy"
PROBE = ROOT / "src" / "agent_action_gateway" / "verify_boundary.py"
COMPOSE = DEPLOY / "docker-compose.proxy.yml"

try:
    import yaml
except ImportError:  # PyYAML is an optional extra
    yaml = None


@unittest.skipIf(yaml is None, "PyYAML is needed to read the Compose file")
class ProxyComposeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.compose = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
        self.services = self.compose["services"]

    def networks_of(self, service: str) -> set[str]:
        return set(self.services[service].get("networks", []))

    def test_no_agent_service_is_shipped(self) -> None:
        self.assertNotIn("agent", self.services)

    def test_the_agent_network_holds_only_the_proxy_and_the_probe(self) -> None:
        on_agent_net = {name for name in self.services if "agent_net" in self.networks_of(name)}
        self.assertEqual(on_agent_net, {"proxy", "probe"})

    def test_the_gateway_is_not_reachable_from_the_agent_network(self) -> None:
        self.assertNotIn("agent_net", self.networks_of("gateway"))
        self.assertIn("tools_net", self.networks_of("gateway"))

    def test_the_agent_and_tool_networks_are_internal(self) -> None:
        networks = self.compose["networks"]
        self.assertTrue(networks["agent_net"]["internal"])
        self.assertTrue(networks["tools_net"]["internal"])

    def test_only_the_dashboard_is_published_and_only_on_this_machine(self) -> None:
        published = {name: s["ports"] for name, s in self.services.items() if s.get("ports")}
        self.assertEqual(list(published), ["dashboard"])
        for port in published["dashboard"]:
            self.assertTrue(str(port).startswith("127.0.0.1:"), port)

    def test_the_dashboard_names_the_address_a_person_opens(self) -> None:
        command = self.services["dashboard"]["command"]
        self.assertIn("--allow-origin", command)
        self.assertIn("http://127.0.0.1:8765", command)

    def test_tokens_are_required_not_defaulted(self) -> None:
        proxy_env = self.services["proxy"]["environment"]
        self.assertIn(":?", proxy_env["AGENT_GATEWAY_PROXY_TOKEN"])
        dashboard_env = self.services["dashboard"]["environment"]
        self.assertIn(":?", dashboard_env["AGENT_GATEWAY_DASHBOARD_TOKEN"])

    def test_the_gateway_does_not_ask_for_a_second_approval(self) -> None:
        mounts = " ".join(self.services["gateway"]["volumes"])
        self.assertIn("routes.credentials.example.json", mounts)

    def test_the_probe_targets_the_proxy(self) -> None:
        command = self.services["probe"]["command"]
        self.assertEqual(command[command.index("--target") + 1], "proxy")
        self.assertEqual(self.services["probe"]["profiles"], ["probe"])


class ProxyExampleConfigTest(unittest.TestCase):
    def test_the_example_config_loads(self) -> None:
        with unittest.mock.patch.dict(os.environ, {"GATEWAY_VIRTUAL_KEY": "k"}):
            config = load_proxy_config(str(DEPLOY / "servers.proxy.example.json"))
        (server,) = config.servers
        self.assertEqual(server.url, "http://gateway:8080/mcp")

    def test_make_has_the_proxy_probe(self) -> None:
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        self.assertIn("verify-proxy-boundary:", makefile)
        self.assertIn("docker-compose.proxy.yml", makefile)


class ProxyProbeInconclusiveTest(unittest.TestCase):
    def test_an_unreachable_proxy_is_inconclusive_not_a_pass(self) -> None:
        result = subprocess.run(
            [
                sys.executable, str(PROBE),
                "--target", "proxy",
                "--proxy", "http://127.0.0.1:9/mcp",
                "--gateway", "http://127.0.0.1:9",
                "--token", "unused",
            ],
            cwd=ROOT, capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertIn("INCONCLUSIVE", result.stdout)
        self.assertNotIn("BOUNDARY HELD", result.stdout)
        self.assertIn("Does NOT prove", result.stdout)


if __name__ == "__main__":
    unittest.main()
