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


def _build_app(tmp_path: Path, *, settings: AgentProvisioningSettings | None = None):
    database = Database(tmp_path / "db.sqlite3")
    database.initialize()
    user, api_key = database.create_user("Test User", "user@example.com", "long-password-123")

    if settings is None:
        settings = AgentProvisioningSettings(
            username="hvdeploy",
            port=22,
            allow_unknown_hosts=False,
            known_hosts_path=None,
            close_other_sessions=True,
        )

    keys = database.ensure_user_provisioning_keys(user.id)

    app = create_app(
        database=database,
        auth=APIKeyAuth(database),
        agent_settings=settings,
    )

    return app, database, user, api_key, settings, keys


def _auth_header(api_key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {api_key}"}


def _registration_payload(settings: AgentProvisioningSettings, public_key: str) -> dict[str, object]:
    return {
        "hostname": "hv-01",
        "ip_address": "192.0.2.10",
        "platform": "Linux",
        "username": settings.username,
        "authorized_keys": [public_key],
    }


def test_account_profile_returns_authorized_keys(tmp_path: Path):
    app, _, _, api_key, settings, keys = _build_app(tmp_path)

    with TestClient(app) as client:
        response = client.get("/v1/account/profile", headers=_auth_header(api_key))

    assert response.status_code == 200
    payload = response.json()
    assert payload["username"] == settings.username
    assert payload["authorized_keys"] == [keys.public_key]


def test_agent_registration_creates_new_agent(tmp_path: Path):
    app, database, user, api_key, settings, keys = _build_app(tmp_path)

    payload = _registration_payload(settings, keys.public_key)

    with TestClient(app) as client:
        response = client.post("/v1/servers/connect", json=payload, headers=_auth_header(api_key))

    assert response.status_code == 200
    data = response.json()
    assert data["authorized_keys"] == [keys.public_key]
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
    assert agent.private_key == keys.private_key
    assert agent.allow_unknown_hosts is False
    assert agent.known_hosts_path is None


def test_agent_registration_updates_existing_agent(tmp_path: Path):
    known_hosts_path = tmp_path / "known_hosts"
    known_hosts_path.write_text("example host key\n", encoding="utf-8")

    settings = AgentProvisioningSettings(
        username="hvdeploy",
        port=26,
        allow_unknown_hosts=True,
        known_hosts_path=known_hosts_path,
        close_other_sessions=False,
    )

    app, database, user, api_key, _, keys = _build_app(tmp_path, settings=settings)

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

    payload = _registration_payload(settings, keys.public_key)

    with TestClient(app) as client:
        response = client.post("/v1/servers/connect", json=payload, headers=_auth_header(api_key))

    assert response.status_code == 200
    data = response.json()
    assert data["authorized_keys"] == [keys.public_key]
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
    assert agent.private_key == keys.private_key
    assert agent.private_key_passphrase is None
    assert agent.allow_unknown_hosts is True
    assert agent.known_hosts_path == str(known_hosts_path)


def test_agent_registration_updates_when_ip_changes(tmp_path: Path):
    app, database, user, api_key, settings, keys = _build_app(tmp_path)

    with TestClient(app) as client:
        first = client.post(
            "/v1/servers/connect",
            json=_registration_payload(settings, keys.public_key),
            headers=_auth_header(api_key),
        )
        assert first.status_code == 200

        second = client.post(
            "/v1/servers/connect",
            json={
                **_registration_payload(settings, keys.public_key),
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


def test_private_key_cannot_be_retrieved_via_api(tmp_path: Path):
    app, database, user, api_key, _, _ = _build_app(tmp_path)

    key_pair = database.ensure_user_provisioning_keys(user.id)

    agent = database.create_agent(
        user.id,
        name="hv-sensitive",
        hostname="198.51.100.10",
        port=2222,
        username="hvdeploy",
        private_key=key_pair.private_key,
        private_key_passphrase="secret-passphrase",
        allow_unknown_hosts=False,
        known_hosts_path=None,
    )

    with TestClient(app) as client:
        listing = client.get("/agents", headers=_auth_header(api_key))
        assert listing.status_code == 200
        listing_payload = listing.json()
        assert listing_payload
        first_agent = next(
            (item for item in listing_payload if item["id"] == agent.id),
            None,
        )
        assert first_agent is not None
        assert "private_key" not in first_agent
        assert "private_key_passphrase" not in first_agent

        detail = client.get(f"/agents/{agent.id}", headers=_auth_header(api_key))
        assert detail.status_code == 200
        detail_payload = detail.json()
        assert detail_payload["id"] == agent.id
        assert "private_key" not in detail_payload
        assert "private_key_passphrase" not in detail_payload

        credentials = client.get(
            f"/agents/{agent.id}/credentials", headers=_auth_header(api_key)
        )
        assert credentials.status_code == 404


def test_provisioning_keys_are_unique_per_user(tmp_path: Path):
    database = Database(tmp_path / "db.sqlite3")
    database.initialize()

    first_user, _ = database.create_user("First", "first@example.com", "password-12345")
    second_user, _ = database.create_user("Second", "second@example.com", "password-12345")

    first_keys = database.ensure_user_provisioning_keys(first_user.id)
    second_keys = database.ensure_user_provisioning_keys(second_user.id)

    assert first_keys.private_key != second_keys.private_key
    assert first_keys.public_key != second_keys.public_key
