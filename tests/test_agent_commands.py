import os
import sys
from pathlib import Path

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

os.environ.setdefault("MANAGEMENT_SESSION_SECRET", "tests-secret-key")

from app.agent_registration import AgentProvisioningSettings  # noqa: E402
from app.api import create_app  # noqa: E402
from app.database import Database  # noqa: E402
from app.security import APIKeyAuth  # noqa: E402


def _build_app(tmp_path: Path):
    database = Database(tmp_path / "db.sqlite3")
    database.initialize()
    user, api_key = database.create_user("Test User", "user@example.com", "long-password-123")

    settings = AgentProvisioningSettings(
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

    return app, database, user, api_key


def _auth_header(api_key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {api_key}"}


def test_commands_endpoint_returns_empty_list(tmp_path: Path) -> None:
    app, _, _, api_key = _build_app(tmp_path)

    with TestClient(app) as client:
        response = client.get("/v1/servers/commands", headers=_auth_header(api_key))

    assert response.status_code == 200
    assert response.json() == {"commands": []}


def test_commands_endpoint_returns_pending_commands(tmp_path: Path) -> None:
    app, database, user, api_key = _build_app(tmp_path)

    first = database.enqueue_agent_command(user.id, "uptime")
    second = database.enqueue_agent_command(user.id, "echo hello")

    with TestClient(app) as client:
        response = client.get("/v1/servers/commands", headers=_auth_header(api_key))

    assert response.status_code == 200
    payload = response.json()
    assert payload == {
        "commands": [
            {"id": first.id, "command": "uptime"},
            {"id": second.id, "command": "echo hello"},
        ]
    }

    # Commands should be marked as dispatched after being served.
    assert database.list_pending_agent_commands(user.id) == []
    refreshed = database.get_agent_command(user.id, first.id)
    assert refreshed is not None and refreshed.dispatched_at is not None
    refreshed_second = database.get_agent_command(user.id, second.id)
    assert refreshed_second is not None and refreshed_second.dispatched_at is not None


def test_commands_endpoint_scopes_results_to_user(tmp_path: Path) -> None:
    app, database, user, first_api_key = _build_app(tmp_path)
    other_user, other_api_key = database.create_user("Second", "second@example.com", "password-12345")

    first_command = database.enqueue_agent_command(user.id, "whoami")
    other_command = database.enqueue_agent_command(other_user.id, "hostname")

    with TestClient(app) as client:
        first_response = client.get("/v1/servers/commands", headers=_auth_header(first_api_key))
        other_response = client.get("/v1/servers/commands", headers=_auth_header(other_api_key))

    assert first_response.status_code == 200
    assert first_response.json() == {
        "commands": [{"id": first_command.id, "command": "whoami"}]
    }

    assert other_response.status_code == 200
    assert other_response.json() == {
        "commands": [{"id": other_command.id, "command": "hostname"}]
    }
