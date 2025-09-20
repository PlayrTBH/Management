import os
import sys
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

os.environ.setdefault("MANAGEMENT_SESSION_SECRET", "tests-secret-key")

from app.api import create_app
from app.api_runner import APICommandRunner
from app.database import Database
from app.ssh import CommandResult, HostKeyVerificationError, SSHError


EMAIL = "api-command@example.com"
PASSWORD = "super-secret"


class DummySSHRunner:
    def __init__(self, *_args, **_kwargs) -> None:
        pass

    def run(self, _command, timeout: int = 60) -> CommandResult:
        return CommandResult(
            command=["echo", "hello"],
            exit_status=0,
            stdout="hello\n",
            stderr="",
        )


@pytest.fixture
def api_app(tmp_path):
    database = Database(tmp_path / "management.sqlite3")
    database.initialize()
    user, api_key = database.create_user("Operator", EMAIL, PASSWORD)
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

    app = create_app(database=database)
    yield app, database, user, api_key, agent


def test_api_ssh_command_endpoint_returns_result(api_app, monkeypatch):
    app, database, user, api_key, agent = api_app

    class Runner(DummySSHRunner):
        pass

    monkeypatch.setattr("app.api.SSHCommandRunner", Runner)

    with TestClient(app) as client:
        response = client.post(
            f"/agents/{agent.id}/ssh/command",
            headers={"Authorization": f"Bearer {api_key}"},
            json={"command": ["echo", "hello"], "timeout": 5},
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload == {
        "command": ["echo", "hello"],
        "exit_status": 0,
        "stdout": "hello\n",
        "stderr": "",
    }


def test_api_ssh_command_endpoint_handles_host_key_error(api_app, monkeypatch):
    app, database, user, api_key, agent = api_app

    class Runner:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def run(self, _command, timeout: int = 60):
            raise HostKeyVerificationError(agent.hostname, port=agent.port, suggestion="check host")

    monkeypatch.setattr("app.api.SSHCommandRunner", Runner)

    with TestClient(app) as client:
        response = client.post(
            f"/agents/{agent.id}/ssh/command",
            headers={"Authorization": f"Bearer {api_key}"},
            json={"command": ["uptime"]},
        )

    assert response.status_code == 502
    payload = response.json()
    assert payload["detail"]["code"] == "host_key_verification_failed"
    assert payload["detail"]["hostname"] == agent.hostname
    assert payload["detail"]["port"] == agent.port


def test_api_command_runner_success(monkeypatch):
    result_payload = {
        "command": ["virsh", "list"],
        "exit_status": 0,
        "stdout": "ok",
        "stderr": "",
    }

    def fake_post(url, json=None, headers=None, timeout=None, verify=None):  # noqa: A002
        assert verify is None
        return httpx.Response(200, json=result_payload)

    monkeypatch.setattr(httpx, "post", fake_post)

    runner = APICommandRunner(
        "https://api.example.com",
        "api-key",
        agent_id=1,
        hostname="hv.internal",
        port=22,
    )

    result = runner.run(["virsh", "list"])
    assert result.command == tuple(result_payload["command"])
    assert result.exit_status == 0
    assert result.stdout == "ok"


def test_api_command_runner_host_key_error(monkeypatch):
    detail = {
        "detail": {
            "code": "host_key_verification_failed",
            "message": "verification failed",
            "hostname": "hv.internal",
            "port": 22,
        }
    }

    def fake_post(url, json=None, headers=None, timeout=None, verify=None):  # noqa: A002
        assert verify is None
        return httpx.Response(502, json=detail)

    monkeypatch.setattr(httpx, "post", fake_post)

    runner = APICommandRunner(
        "https://api.example.com",
        "api-key",
        agent_id=1,
        hostname="hv.internal",
        port=22,
    )

    with pytest.raises(HostKeyVerificationError):
        runner.run(["virsh", "list"])


def test_api_command_runner_http_error(monkeypatch):
    def fake_post(url, json=None, headers=None, timeout=None, verify=None):  # noqa: A002
        assert verify is None
        return httpx.Response(401, json={"detail": "unauthorized"})


def test_api_command_runner_verify_option(monkeypatch):
    captured = {}

    def fake_post(url, json=None, headers=None, timeout=None, verify=None):  # noqa: A002
        captured.update({
            "url": url,
            "verify": verify,
        })
        return httpx.Response(200, json={
            "command": ["uptime"],
            "exit_status": 0,
            "stdout": "ok",
            "stderr": "",
        })

    monkeypatch.setattr(httpx, "post", fake_post)

    runner = APICommandRunner(
        "https://api.example.com",
        "api-key",
        agent_id=7,
        hostname="hv.internal",
        port=22,
        verify="/tmp/ca.pem",
    )

    runner.run(["uptime"])
    assert captured["url"].endswith("/agents/7/ssh/command")
    assert captured["verify"] == "/tmp/ca.pem"

    monkeypatch.setattr(httpx, "post", fake_post)

    runner = APICommandRunner(
        "https://api.example.com",
        "api-key",
        agent_id=1,
        hostname="hv.internal",
        port=22,
    )

    runner.run(["virsh", "list"])
    assert captured["url"].endswith("/agents/1/ssh/command")
    assert captured["verify"] is None
