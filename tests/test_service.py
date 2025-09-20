"""End-to-end tests for the management service HTTP API."""

from __future__ import annotations

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
            self.assertEqual(payload["tunnel_endpoint"], {"host": "manage.playrservers.com", "port": 443})

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
            self.assertEqual(tunnel_info["endpoint"], {"host": "manage.playrservers.com", "port": 443})
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


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
