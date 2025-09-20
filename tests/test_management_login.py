import json
import os
import re
from pathlib import Path
import sys
import tempfile

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

os.environ.setdefault("MANAGEMENT_SESSION_SECRET", "tests-secret-key")
os.environ.setdefault(
    "MANAGEMENT_DB_PATH",
    str(Path(tempfile.gettempdir()) / "management-tests.sqlite3"),
)

from app.database import Database
from app.management import create_app


EMAIL = "user@example.com"
PASSWORD = "super-secret-password"


def test_login_redirects_to_dashboard_when_credentials_valid(tmp_path):
    database = Database(tmp_path / "test.sqlite3")
    database.initialize()
    database.create_user("Test User", EMAIL, PASSWORD)

    app = create_app(
        database=database,
        session_secret="not-so-secret",
        api_base_url="https://example.com",
    )

    with TestClient(app) as client:
        response = client.post(
            "/login",
            data={"email": EMAIL, "password": PASSWORD},
            follow_redirects=False,
        )

        assert response.status_code == 303
        assert response.headers["location"].endswith("/dashboard")

        follow = client.get("/dashboard", follow_redirects=False)
        assert follow.status_code == 200


def test_management_page_renders_with_registered_agent(tmp_path):
    database = Database(tmp_path / "management.sqlite3")
    database.initialize()
    user, _ = database.create_user("Agent Owner", EMAIL, PASSWORD)
    agent = database.create_agent(
        user.id,
        name="hypervisor-01",
        hostname="203.0.113.10",
        port=2222,
        username="hvdeploy",
        private_key="-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----",
        private_key_passphrase=None,
        allow_unknown_hosts=False,
        known_hosts_path=None,
    )

    app = create_app(
        database=database,
        session_secret="not-so-secret",
        api_base_url="https://example.com",
    )

    with TestClient(app) as client:
        login = client.post(
            "/login",
            data={"email": EMAIL, "password": PASSWORD},
            follow_redirects=False,
        )
        assert login.status_code == 303

        response = client.get("/management")
        assert response.status_code == 200

        match = re.search(
            r"<script id=\"agent-data\" type=\"application/json\">(.*?)</script>",
            response.text,
            re.DOTALL,
        )
        assert match is not None

        agents_payload = json.loads(match.group(1))
        assert agents_payload
        assert agents_payload[0]["id"] == agent.id
        assert (
            agents_payload[0]["remove_url"]
            == f"http://testserver/management/agents/{agent.id}/delete"
        )


def test_account_api_key_reveal_requires_password(tmp_path):
    database = Database(tmp_path / "management.sqlite3")
    database.initialize()
    _, api_key = database.create_user("Reveal User", EMAIL, PASSWORD)

    app = create_app(
        database=database,
        session_secret="not-so-secret",
        api_base_url="https://example.com",
    )

    with TestClient(app) as client:
        login = client.post(
            "/login",
            data={"email": EMAIL, "password": PASSWORD},
            follow_redirects=False,
        )
        assert login.status_code == 303

        # Incorrect password should not reveal the key
        denied = client.post(
            "/account/api-key/reveal",
            data={"password": "wrong-password"},
            follow_redirects=False,
        )
        assert denied.status_code == 303
        follow = client.get("/account")
        assert follow.status_code == 200
        assert "Password is incorrect." in follow.text
        assert api_key not in follow.text

        # Correct password exposes the key on the account page
        allowed = client.post(
            "/account/api-key/reveal",
            data={"password": PASSWORD},
            follow_redirects=False,
        )
        assert allowed.status_code == 303
        revealed = client.get("/account")
        assert revealed.status_code == 200
        assert api_key in revealed.text
        assert "Full API key" in revealed.text
