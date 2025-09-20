import os
import sys
from pathlib import Path

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

os.environ.setdefault("MANAGEMENT_SESSION_SECRET", "tests-secret-key")

from app.database import Database
from app.management import create_app
from app.ssh import CommandResult
import app.management as management_module


EMAIL = "internal@example.com"
PASSWORD = "super-secret"


def test_management_uses_internal_api_configuration(monkeypatch, tmp_path):
    database = Database(tmp_path / "management.sqlite3")
    database.initialize()

    user, _ = database.create_user("Operator", EMAIL, PASSWORD)
    agent = database.create_agent(
        user.id,
        name="hypervisor-01",
        hostname="hv.internal",
        port=22,
        username="qemu",
        private_key="dummy",
        private_key_passphrase=None,
        allow_unknown_hosts=True,
        known_hosts_path=None,
    )

    captured = {}

    def fake_runner(base_url, api_key, *, agent_id, hostname, port, verify=None):  # noqa: D401
        captured.update(
            {
                "base_url": base_url,
                "verify": verify,
                "agent_id": agent_id,
                "hostname": hostname,
                "port": port,
            }
        )

        class Runner:
            def run(self, args, timeout: int = 60) -> CommandResult:
                stdout = (
                    " Id   Name               State\n"
                    "---------------------------------\n"
                    " 1    vm01               running\n"
                )
                return CommandResult(command=args, exit_status=0, stdout=stdout, stderr="")

        return Runner()

    monkeypatch.setattr(management_module, "APICommandRunner", fake_runner)

    app = create_app(
        database=database,
        session_secret="tests-secret",
        api_base_url="https://public.example.com",
        internal_api_base_url="https://internal.example.com/api",
        internal_api_verify="/tmp/internal-ca.pem",
    )

    with TestClient(app) as client:
        login = client.post(
            "/login",
            data={"email": EMAIL, "password": PASSWORD},
            follow_redirects=False,
        )
        assert login.status_code == 303

        response = client.get(f"/management/agents/{agent.id}/vms")
        assert response.status_code == 200

    assert captured["base_url"] == "https://internal.example.com/api"
    assert captured["verify"] == "/tmp/internal-ca.pem"
    assert captured["agent_id"] == agent.id
    assert captured["hostname"] == agent.hostname
    assert captured["port"] == agent.port
