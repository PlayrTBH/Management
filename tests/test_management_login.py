import os
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
