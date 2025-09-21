"""End-to-end tests for the management service HTTP API."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from app.agents import AgentRegistry
from app.database import Database
from app.service import create_app


class ManagementServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tempdir = tempfile.TemporaryDirectory()
        db_path = Path(self._tempdir.name) / "management.sqlite3"
        self.database = Database(db_path)
        self.database.initialize()
        self.user_email = "alice@example.com"
        self.user_password = "SuperSecret123!"
        self.user = self.database.create_user("Alice", self.user_email, self.user_password)

    def tearDown(self) -> None:
        self._tempdir.cleanup()

    def _auth(self) -> tuple[str, str]:
        email = self.user.email or self.user_email
        return email, self.user_password

    def test_agent_connection_and_tunnel_lifecycle(self) -> None:
        registry = AgentRegistry()
        app = create_app(database=self.database, registry=registry)

        with TestClient(app) as client:
            connect = client.post(
                "/v1/agents/connect",
                auth=self._auth(),
                json={
                    "agent_id": "agent-01",
                    "hostname": "hypervisor01",
                    "capabilities": ["ssh", "metrics"],
                },
            )
            self.assertEqual(connect.status_code, 200, connect.text)
            payload = connect.json()
            self.assertIn("session_id", payload)
            self.assertIn("agent_token", payload)
            self.assertEqual(payload["tunnel_endpoint"], {"host": "api.playrservers.com", "port": 443})

            session_id = payload["session_id"]
            agent_token = payload["agent_token"]

            heartbeat = client.post(
                "/v1/agents/agent-01/heartbeat",
                auth=self._auth(),
                json={
                    "session_id": session_id,
                    "agent_token": agent_token,
                },
            )
            self.assertEqual(heartbeat.status_code, 200, heartbeat.text)
            heartbeat_payload = heartbeat.json()
            self.assertEqual(heartbeat_payload["agent_id"], "agent-01")

            created = client.post(
                "/v1/agents/agent-01/tunnels",
                auth=self._auth(),
                json={
                    "session_id": session_id,
                    "agent_token": agent_token,
                    "purpose": "ssh",
                    "remote_port": 22,
                },
            )
            self.assertEqual(created.status_code, 201, created.text)
            tunnel_info = created.json()
            self.assertEqual(tunnel_info["endpoint"], {"host": "api.playrservers.com", "port": 443})
            tunnel_id = tunnel_info["tunnel_id"]

            status = client.get("/v1/agents/agent-01", auth=self._auth())
            self.assertEqual(status.status_code, 200, status.text)
            status_payload = status.json()
            self.assertEqual(len(status_payload["tunnels"]), 1)
            self.assertEqual(status_payload["tunnels"][0]["tunnel_id"], tunnel_id)

            listing = client.get("/v1/agents/agent-01/tunnels", auth=self._auth())
            self.assertEqual(listing.status_code, 200, listing.text)
            listing_payload = listing.json()
            self.assertEqual(len(listing_payload["tunnels"]), 1)

            closed = client.post(
                f"/v1/agents/agent-01/tunnels/{tunnel_id}/close",
                auth=self._auth(),
                json={
                    "session_id": session_id,
                    "agent_token": agent_token,
                },
            )
            self.assertEqual(closed.status_code, 200, closed.text)
            closed_payload = closed.json()
            self.assertEqual(closed_payload["state"], "closed")

    def test_agent_cannot_be_claimed_by_other_user(self) -> None:
        other = self.database.create_user("Bob", "bob@example.com", "Password456?")

        registry = AgentRegistry()
        app = create_app(database=self.database, registry=registry)

        with TestClient(app) as client:
            first = client.post(
                "/v1/agents/connect",
                auth=self._auth(),
                json={"agent_id": "duplicate", "hostname": "node-a"},
            )
            self.assertEqual(first.status_code, 200, first.text)

            second = client.post(
                "/v1/agents/connect",
                auth=(other.email or "", "Password456?"),
                json={"agent_id": "duplicate", "hostname": "node-b"},
            )
            self.assertEqual(second.status_code, 403, second.text)

    def test_heartbeat_rejects_invalid_session(self) -> None:
        registry = AgentRegistry()
        app = create_app(database=self.database, registry=registry)

        with TestClient(app) as client:
            connect = client.post(
                "/v1/agents/connect",
                auth=self._auth(),
                json={"agent_id": "agent-02", "hostname": "hypervisor02"},
            )
            self.assertEqual(connect.status_code, 200, connect.text)
            payload = connect.json()

            bad_heartbeat = client.post(
                "/v1/agents/agent-02/heartbeat",
                auth=self._auth(),
                json={
                    "session_id": payload["session_id"],
                    "agent_token": "not-the-right-token",
                },
            )
            self.assertEqual(bad_heartbeat.status_code, 401, bad_heartbeat.text)

    def test_custom_tunnel_endpoint_can_be_overridden(self) -> None:
        registry = AgentRegistry(tunnel_host="staging.playrservers.com", tunnel_port=8443)
        app = create_app(database=self.database, registry=registry)

        with TestClient(app) as client:
            connect = client.post(
                "/v1/agents/connect",
                auth=self._auth(),
                json={"agent_id": "agent-03", "hostname": "hypervisor03"},
            )
            self.assertEqual(connect.status_code, 200, connect.text)
            payload = connect.json()
            self.assertEqual(payload["tunnel_endpoint"], {"host": "staging.playrservers.com", "port": 8443})

    def test_agent_listing_endpoint_returns_active_sessions(self) -> None:
        registry = AgentRegistry()
        app = create_app(database=self.database, registry=registry)

        with TestClient(app) as client:
            empty = client.get("/v1/agents", auth=self._auth())
            self.assertEqual(empty.status_code, 200, empty.text)
            empty_payload = empty.json()
            self.assertEqual(empty_payload, {"agents": []})

            connect = client.post(
                "/v1/agents/connect",
                auth=self._auth(),
                json={"agent_id": "agent-list", "hostname": "hypervisor-list"},
            )
            self.assertEqual(connect.status_code, 200, connect.text)
            session_id = connect.json()["session_id"]
            agent_token = connect.json()["agent_token"]

            client.post(
                "/v1/agents/agent-list/heartbeat",
                auth=self._auth(),
                json={"session_id": session_id, "agent_token": agent_token},
            )

            listing = client.get("/v1/agents", auth=self._auth())
            self.assertEqual(listing.status_code, 200, listing.text)
            payload = listing.json()
            self.assertEqual(len(payload["agents"]), 1)
            agent_info = payload["agents"][0]
            self.assertEqual(agent_info["agent_id"], "agent-list")
            self.assertEqual(agent_info["hostname"], "hypervisor-list")

    def test_hypervisor_detail_management_endpoints(self) -> None:
        registry = AgentRegistry()
        app = create_app(database=self.database, registry=registry)

        cpu_payload = [
            {"id": 0, "label": "Core 0", "usage": 42.5},
            {"id": 1, "label": "Core 1", "usage": 87.0},
        ]
        vm_payload = [
            {
                "id": "web-01",
                "name": "web-01",
                "status": "running",
                "power_state": "running",
                "cpu": "2 vCPU",
                "memory": "4 GiB",
            },
            {
                "id": "db-01",
                "name": "db-01",
                "status": "stopped",
                "power_state": "shut off",
                "cpu": "4 vCPU",
                "memory": "8 GiB",
            },
        ]

        with TestClient(app, base_url="https://testserver") as client:
            connect = client.post(
                "/v1/agents/connect",
                auth=self._auth(),
                json={
                    "agent_id": "agent-detail",
                    "hostname": "hypervisor-detail",
                    "metadata": {
                        "cpu_cores": json.dumps(cpu_payload),
                        "vms": json.dumps(vm_payload),
                        "ssh_login": "admin",
                        "ssh_user": "tunnels",
                        "memory_total": "64 GiB",
                    },
                },
            )
            self.assertEqual(connect.status_code, 200, connect.text)

            login = client.post(
                "/login",
                data={"email": self.user_email, "password": self.user_password},
                follow_redirects=True,
            )
            self.assertEqual(login.status_code, 200, login.text)

            detail = client.get("/hypervisors/agent-detail")
            self.assertEqual(detail.status_code, 200, detail.text)
            body = detail.text
            self.assertIn("Core 0", body)
            self.assertIn("web-01", body)
            self.assertIn("Launch terminal", body)
            self.assertIn("admin@hypervisor-detail", body)

            terminal = client.post("/hypervisors/agent-detail/terminal")
            self.assertEqual(terminal.status_code, 200, terminal.text)
            terminal_payload = terminal.json()
            self.assertIn("ssh_command", terminal_payload)
            self.assertIn("sshpass", terminal_payload["ssh_command"])
            self.assertEqual(terminal_payload["remote_port"], 2200)
            self.assertEqual(terminal_payload["local_port"], 22)

            vm_action = client.post("/hypervisors/agent-detail/vms/web-01/start")
            self.assertEqual(vm_action.status_code, 202, vm_action.text)
            action_payload = vm_action.json()
            self.assertEqual(action_payload["action"], "start")
            self.assertEqual(action_payload["vm"], "web-01")

    def test_dashboard_displays_connected_hypervisors(self) -> None:
        registry = AgentRegistry()
        app = create_app(database=self.database, registry=registry)

        with TestClient(app, base_url="https://testserver") as client:
            login = client.post(
                "/login",
                data={"email": self.user_email, "password": self.user_password},
                follow_redirects=True,
            )
            self.assertEqual(login.status_code, 200, login.text)

            connect = client.post(
                "/v1/agents/connect",
                auth=self._auth(),
                json={"agent_id": "agent-ui", "hostname": "hypervisor-ui"},
            )
            self.assertEqual(connect.status_code, 200, connect.text)

            dashboard = client.get("/dashboard")
            self.assertEqual(dashboard.status_code, 200, dashboard.text)
            body = dashboard.text
            self.assertIn("Hypervisors", body)
            self.assertIn("agent-ui", body)
            self.assertIn("hypervisor-ui", body)

    def test_agent_endpoints_accept_api_keys(self) -> None:
        api_key = self.database.create_api_key(self.user.id, "Test agent key")
        registry = AgentRegistry()
        app = create_app(database=self.database, registry=registry)

        headers = {"Authorization": f"Bearer {api_key}"}

        with TestClient(app) as client:
            connect = client.post(
                "/v1/agents/connect",
                headers=headers,
                json={"agent_id": "key-agent", "hostname": "hypervisor-key"},
            )
            self.assertEqual(connect.status_code, 200, connect.text)
            payload = connect.json()
            session_id = payload["session_id"]
            token = payload["agent_token"]

            heartbeat = client.post(
                "/v1/agents/key-agent/heartbeat",
                headers=headers,
                json={"session_id": session_id, "agent_token": token},
            )
            self.assertEqual(heartbeat.status_code, 200, heartbeat.text)

    def test_web_login_and_dashboard_flow(self) -> None:
        registry = AgentRegistry()
        app = create_app(database=self.database, registry=registry)

        with TestClient(app, base_url="https://testserver") as client:
            landing = client.get("/")
            self.assertEqual(landing.status_code, 200)
            self.assertIn("Welcome back", landing.text)

            bad_login = client.post(
                "/login",
                data={"email": self.user_email, "password": "incorrect"},
            )
            self.assertEqual(bad_login.status_code, 400)
            self.assertIn("Invalid email or password", bad_login.text)

            response = client.post(
                "/login",
                data={"email": self.user_email, "password": self.user_password},
                follow_redirects=False,
            )
            self.assertEqual(response.status_code, 303)
            self.assertTrue(response.headers["location"].endswith("/dashboard"))

            dashboard = client.get("/dashboard")
            self.assertEqual(dashboard.status_code, 200)
            self.assertIn("Account overview", dashboard.text)

            logout = client.get("/logout", follow_redirects=False)
            self.assertEqual(logout.status_code, 303)
            self.assertTrue(logout.headers["location"].endswith("/login"))

            redirected = client.get("/dashboard", follow_redirects=False)
            self.assertEqual(redirected.status_code, 303)
            self.assertTrue(redirected.headers["location"].endswith("/login"))

    def test_root_package_create_app_includes_api_and_web(self) -> None:
        from app import create_app as root_create_app

        registry = AgentRegistry()
        app = root_create_app(database=self.database, registry=registry)

        with TestClient(app, base_url="https://testserver") as client:
            health = client.get("/healthz")
            self.assertEqual(health.status_code, 200, health.text)

            landing = client.get("/")
            self.assertEqual(landing.status_code, 200, landing.text)
            self.assertIn("Welcome back", landing.text)

    def test_create_app_can_disable_specific_interfaces(self) -> None:
        registry = AgentRegistry()
        api_app = create_app(
            database=self.database,
            registry=registry,
            include_api=True,
            include_web=False,
        )

        with TestClient(api_app) as client:
            self.assertEqual(client.get("/healthz").status_code, 200)
            self.assertEqual(client.get("/").status_code, 404)

        web_app = create_app(
            database=self.database,
            registry=registry,
            include_api=False,
            include_web=True,
        )

        with TestClient(web_app, base_url="https://testserver") as client:
            self.assertEqual(client.get("/").status_code, 200)
            self.assertEqual(client.get("/healthz").status_code, 404)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
