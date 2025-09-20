import os
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

os.environ.setdefault("MANAGEMENT_SESSION_SECRET", "tests-secret-key")

from app.database import Database
from app.management import create_app
from app.qemu import QEMUError
from app.ssh import CommandResult, HostKeyVerificationError


EMAIL = "deploy@example.com"
PASSWORD = "super-secret"


class StubManager:
    def __init__(self, result=None, error=None):
        self.calls = []
        self._result = result or CommandResult(command=["bash", "-lc", ""], exit_status=0, stdout="", stderr="")
        self._error = error

    def deploy_vm(self, profile_id, vm_name, **kwargs):
        self.calls.append((profile_id, vm_name, kwargs))
        if self._error:
            raise self._error
        return self._result


@pytest.fixture
def app(tmp_path):
    database = Database(tmp_path / "management.sqlite3")
    database.initialize()
    user, _ = database.create_user("Operator", EMAIL, PASSWORD)
    database.create_agent(
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

    application = create_app(
        database=database,
        session_secret="tests-secret",
        api_base_url="https://example.com",
    )
    return application


def authenticate(client: TestClient):
    response = client.post(
        "/login",
        data={"email": EMAIL, "password": PASSWORD},
        follow_redirects=False,
    )
    assert response.status_code == 303


def test_deploy_endpoint_requires_authentication(app):
    manager = StubManager()
    app.state.qemu_manager_factory = lambda agent: manager

    with TestClient(app) as client:
        response = client.post(
            "/management/agents/1/deployments",
            json={"profile_id": "ubuntu-24-04", "vm_name": "vm"},
        )
        assert response.status_code == 401
        assert not manager.calls


def test_deploy_endpoint_invokes_manager(app):
    result = CommandResult(command=["bash", "-lc", "echo"], exit_status=0, stdout="ok", stderr="")
    manager = StubManager(result=result)
    app.state.qemu_manager_factory = lambda agent: manager

    with TestClient(app) as client:
        authenticate(client)
        response = client.post(
            "/management/agents/1/deployments",
            json={
                "profile_id": "ubuntu-24-04",
                "vm_name": "vm-alpha",
                "memory_mb": 4096,
                "vcpus": 2,
                "disk_gb": 40,
            },
        )

        assert response.status_code == 200
        payload = response.json()
        assert payload["status"] == "ok"
        assert "credentials" in payload
        assert payload["credentials"]["username"] == "playradmin"
        assert payload["credentials"]["password"] == "PlayrServers!23"
        assert manager.calls
        profile_id, vm_name, kwargs = manager.calls[0]
        assert profile_id == "ubuntu-24-04"
        assert vm_name == "vm-alpha"
        assert kwargs["memory_mb"] == 4096
        assert kwargs["username"] == "playradmin"
        assert kwargs["password"] == "PlayrServers!23"


def test_deploy_endpoint_accepts_custom_credentials(app):
    manager = StubManager()
    app.state.qemu_manager_factory = lambda agent: manager

    with TestClient(app) as client:
        authenticate(client)
        response = client.post(
            "/management/agents/1/deployments",
            json={
                "profile_id": "ubuntu-24-04",
                "vm_name": "vm-delta",
                "username": " customadmin ",
                "password": "SuperSecurePass1!",
            },
        )

        assert response.status_code == 200
        payload = response.json()
        assert payload["status"] == "ok"
        assert payload["credentials"]["username"] == "customadmin"
        assert payload["credentials"]["password"] == "SuperSecurePass1!"
        assert manager.calls
        profile_id, vm_name, kwargs = manager.calls[0]
        assert profile_id == "ubuntu-24-04"
        assert vm_name == "vm-delta"
        assert kwargs["username"] == "customadmin"
        assert kwargs["password"] == "SuperSecurePass1!"


def test_deploy_endpoint_rejects_invalid_password(app):
    manager = StubManager()
    app.state.qemu_manager_factory = lambda agent: manager

    with TestClient(app) as client:
        authenticate(client)
        response = client.post(
            "/management/agents/1/deployments",
            json={
                "profile_id": "ubuntu-24-04",
                "vm_name": "vm-epsilon",
                "password": "short",
            },
        )

        assert response.status_code == 400
        payload = response.json()
        assert payload["status"] == "error"
        assert "Password must be" in payload["message"]
        assert not manager.calls


def test_deploy_endpoint_reports_host_key_error(app):
    manager = StubManager(error=HostKeyVerificationError("hv.internal", port=22))
    app.state.qemu_manager_factory = lambda agent: manager

    with TestClient(app) as client:
        authenticate(client)
        response = client.post(
            "/management/agents/1/deployments",
            json={"profile_id": "ubuntu-24-04", "vm_name": "vm-beta"},
        )
        assert response.status_code == 502
        payload = response.json()
        assert payload["code"] == "host_key_verification_failed"


def test_deploy_endpoint_reports_qemu_error(app):
    error_result = CommandResult(command=["bash", "-lc", "echo"], exit_status=1, stdout="", stderr="failure")
    manager = StubManager(error=QEMUError("boom", error_result))
    app.state.qemu_manager_factory = lambda agent: manager

    with TestClient(app) as client:
        authenticate(client)
        response = client.post(
            "/management/agents/1/deployments",
            json={"profile_id": "ubuntu-24-04", "vm_name": "vm-gamma"},
        )
        assert response.status_code == 502
        payload = response.json()
        assert payload["status"] == "error"
        assert "result" in payload
