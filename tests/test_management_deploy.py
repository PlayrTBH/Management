import logging
import os
import sys
import threading
import time
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
        self._event = threading.Event()

    def deploy_vm(self, profile_id, vm_name, **kwargs):
        self.calls.append((profile_id, vm_name, kwargs))
        self._event.set()
        if self._error:
            raise self._error
        return self._result

    def wait_for_call(self, timeout=1.0):
        return self._event.wait(timeout)


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


def get_deployment_detail(client: TestClient, deployment_id: str):
    response = client.get(f"/management/deployments/{deployment_id}")
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ok"
    return payload["deployment"]


def wait_for_deployment_status(
    client: TestClient,
    deployment_id: str,
    expected_status: str,
    timeout: float = 2.0,
):
    deadline = time.time() + timeout
    expected = expected_status.lower()
    last_detail = None
    while time.time() < deadline:
        detail = get_deployment_detail(client, deployment_id)
        last_detail = detail
        if (detail.get("status") or "").lower() == expected:
            return detail
        time.sleep(0.05)
    last_status = last_detail.get("status") if last_detail else "unknown"
    raise AssertionError(
        f"Deployment {deployment_id} did not reach status {expected_status!r}; last status was {last_status!r}."
    )


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

        assert response.status_code == 202
        payload = response.json()
        assert payload["status"] == "ok"
        assert "credentials" in payload
        assert payload["credentials"]["username"] == "playradmin"
        assert payload["credentials"]["password"] == "PlayrServers!23"
        assert manager.wait_for_call(timeout=1.0)
        assert manager.calls
        profile_id, vm_name, kwargs = manager.calls[0]
        assert profile_id == "ubuntu-24-04"
        assert vm_name == "vm-alpha"
        assert kwargs["memory_mb"] == 4096
        assert kwargs["username"] == "playradmin"
        assert kwargs["password"] == "PlayrServers!23"

        deployment_id = payload.get("deployment_id")
        assert deployment_id
        detail = wait_for_deployment_status(client, deployment_id, "succeeded")
        assert detail["exit_status"] == 0
        assert detail["command"] == result.command


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

        assert response.status_code == 202
        payload = response.json()
        assert payload["status"] == "ok"
        assert payload["credentials"]["username"] == "customadmin"
        assert payload["credentials"]["password"] == "SuperSecurePass1!"
        assert manager.wait_for_call(timeout=1.0)
        assert manager.calls
        profile_id, vm_name, kwargs = manager.calls[0]
        assert profile_id == "ubuntu-24-04"
        assert vm_name == "vm-delta"
        assert kwargs["username"] == "customadmin"
        assert kwargs["password"] == "SuperSecurePass1!"

        deployment_id = payload.get("deployment_id")
        assert deployment_id
        detail = wait_for_deployment_status(client, deployment_id, "succeeded")
        assert detail["status"].lower() == 'succeeded'


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
        assert response.status_code == 202
        payload = response.json()
        assert payload["status"] == "ok"
        assert manager.wait_for_call(timeout=1.0)

        deployment_id = payload.get("deployment_id")
        assert deployment_id
        detail = wait_for_deployment_status(client, deployment_id, "failed")
        assert 'host key verification failed' in (detail.get("error") or '').lower()
        messages = detail.get("messages") or []
        assert any(
            (entry.get("stream") == "error" and 'host key verification failed' in (entry.get("message") or '').lower())
            for entry in messages
        )


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
        assert response.status_code == 202
        payload = response.json()
        assert payload["status"] == "ok"
        assert manager.wait_for_call(timeout=1.0)

        deployment_id = payload.get("deployment_id")
        assert deployment_id
        detail = wait_for_deployment_status(client, deployment_id, "failed")
        assert detail.get("error") == "boom"
        assert detail.get("exit_status") == error_result.exit_status
        assert detail.get("command") == error_result.command
        messages = detail.get("messages") or []
        assert any((entry.get("stream") == "error") for entry in messages)


def test_deploy_endpoint_logs_qemu_error_details(app, caplog):
    error_result = CommandResult(
        command=["bash", "-lc", "deploy"],
        exit_status=2,
        stdout="deployment output",
        stderr="deployment failure",
    )
    manager = StubManager(error=QEMUError("boom", error_result))
    app.state.qemu_manager_factory = lambda agent: manager

    with TestClient(app) as client:
        authenticate(client)
        caplog.set_level(logging.ERROR, logger="playrservers.management.deployments")
        response = client.post(
            "/management/agents/1/deployments",
            json={"profile_id": "ubuntu-24-04", "vm_name": "vm-theta"},
        )

        assert response.status_code == 202
        payload = response.json()
        assert manager.wait_for_call(timeout=1.0)

        deployment_id = payload.get("deployment_id")
        assert deployment_id
        wait_for_deployment_status(client, deployment_id, "failed")

        for _ in range(50):
            if any(
                "VM deployment failed for 'vm-theta'" in record.message
                and "profile 'ubuntu-24-04'" in record.message
                and "exit_status=2" in record.message
                and "stderr='deployment failure'" in record.message
                for record in caplog.records
            ):
                break
            time.sleep(0.05)
        else:
            raise AssertionError("Expected deployment failure log message was not emitted")
