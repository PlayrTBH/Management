import os
import sys
from pathlib import Path

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

os.environ.setdefault("MANAGEMENT_SESSION_SECRET", "tests-secret-key")

from app.agent_registration import AgentProvisioningSettings
from app.api import create_app
from app.database import Database
from app.security import APIKeyAuth


PRIVATE_KEY = """-----BEGIN OPENSSH PRIVATE KEY-----\ntest-private-key\n-----END OPENSSH PRIVATE KEY-----""".strip()
PUBLIC_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey playrservers@example.com"


def _build_app(tmp_path: Path, *, settings: AgentProvisioningSettings | None = None):
    database = Database(tmp_path / "db.sqlite3")
    database.initialize()
    user, api_key = database.create_user("Test User", "user@example.com", "long-password-123")

    if settings is None:
        private_key_path = tmp_path / "id_ed25519"
        private_key_path.write_text(PRIVATE_KEY + "\n", encoding="utf-8")
        public_key_path = tmp_path / "id_ed25519.pub"
        public_key_path.write_text(PUBLIC_KEY + "\n", encoding="utf-8")
        settings = AgentProvisioningSettings(
            private_key_path=private_key_path,
            public_key_path=public_key_path,
            username="hvdeploy",
            port=22,
            allow_unknown_hosts=False,
            known_hosts_path=None,
            close_other_sessions=True,
        )

    app = create_app(
        database=database,
        auth=APIKeyAuth(database),
        agent_settings=settings,
    )

    return app, database, user, api_key, settings


def _auth_header(api_key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {api_key}"}


def _registration_payload(settings: AgentProvisioningSettings) -> dict[str, object]:
    return {
        "hostname": "hv-01",
        "ip_address": "192.0.2.10",
        "platform": "Linux",
        "username": settings.username,
        "authorized_keys": [PUBLIC_KEY],
    }


def test_account_profile_returns_authorized_keys(tmp_path: Path):
    app, _, _, api_key, settings = _build_app(tmp_path)

    with TestClient(app) as client:
        response = client.get("/v1/account/profile", headers=_auth_header(api_key))

    assert response.status_code == 200
    payload = response.json()
    assert payload["username"] == settings.username
    assert payload["authorized_keys"] == [PUBLIC_KEY]


def test_agent_registration_creates_new_agent(tmp_path: Path):
    app, database, user, api_key, settings = _build_app(tmp_path)

    payload = _registration_payload(settings)

    with TestClient(app) as client:
        response = client.post("/v1/servers/connect", json=payload, headers=_auth_header(api_key))

    assert response.status_code == 200
    data = response.json()
    assert data["authorized_keys"] == [PUBLIC_KEY]
    assert data["username"] == settings.username
    assert data["close_other_sessions"] is True
    assert data["hostname"] == "192.0.2.10"

    agents = database.list_agents_for_user(user.id)
    assert len(agents) == 1
    agent = agents[0]
    assert agent.name == "hv-01"
    assert agent.hostname == "192.0.2.10"
    assert agent.port == settings.port
    assert agent.username == settings.username
    assert agent.private_key == PRIVATE_KEY
    assert agent.allow_unknown_hosts is False
    assert agent.known_hosts_path is None


def test_agent_registration_updates_existing_agent(tmp_path: Path):
    private_key_path = tmp_path / "management_key"
    private_key_path.write_text(PRIVATE_KEY + "\n", encoding="utf-8")
    public_key_path = tmp_path / "management_key.pub"
    public_key_path.write_text(PUBLIC_KEY + "\n", encoding="utf-8")
    known_hosts_path = tmp_path / "known_hosts"
    known_hosts_path.write_text("example host key\n", encoding="utf-8")

    settings = AgentProvisioningSettings(
        private_key_path=private_key_path,
        public_key_path=public_key_path,
        username="hvdeploy",
        port=26,
        allow_unknown_hosts=True,
        known_hosts_path=known_hosts_path,
        close_other_sessions=False,
    )

    app, database, user, api_key, _ = _build_app(tmp_path, settings=settings)

    database.create_agent(
        user.id,
        name="stale",
        hostname="192.0.2.10",
        port=2022,
        username="legacy",
        private_key="old-key",
        private_key_passphrase="passphrase",
        allow_unknown_hosts=False,
        known_hosts_path="/tmp/old_known_hosts",
    )

    payload = _registration_payload(settings)

    with TestClient(app) as client:
        response = client.post("/v1/servers/connect", json=payload, headers=_auth_header(api_key))

    assert response.status_code == 200
    data = response.json()
    assert data["authorized_keys"] == [PUBLIC_KEY]
    assert data["username"] == settings.username
    assert data["close_other_sessions"] is False
    assert data["hostname"] == "192.0.2.10"

    agents = database.list_agents_for_user(user.id)
    assert len(agents) == 1
    agent = agents[0]
    assert agent.name == "hv-01"
    assert agent.hostname == "192.0.2.10"
    assert agent.port == settings.port
    assert agent.username == settings.username
    assert agent.private_key == PRIVATE_KEY
    assert agent.private_key_passphrase is None
    assert agent.allow_unknown_hosts is True
    assert agent.known_hosts_path == str(known_hosts_path)


def test_agent_registration_updates_when_ip_changes(tmp_path: Path):
    app, database, user, api_key, settings = _build_app(tmp_path)

    with TestClient(app) as client:
        first = client.post(
            "/v1/servers/connect",
            json=_registration_payload(settings),
            headers=_auth_header(api_key),
        )
        assert first.status_code == 200

        second = client.post(
            "/v1/servers/connect",
            json={
                **_registration_payload(settings),
                "ip_address": "192.0.2.20",
            },
            headers=_auth_header(api_key),
        )
        assert second.status_code == 200
        data = second.json()
        assert data["hostname"] == "192.0.2.20"

    agents = database.list_agents_for_user(user.id)
    assert len(agents) == 1
    agent = agents[0]
    assert agent.hostname == "192.0.2.20"
    assert agent.name == "hv-01"

