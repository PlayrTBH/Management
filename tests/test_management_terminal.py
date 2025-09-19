import json
import os
import queue
import sys
import threading
from contextlib import contextmanager
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

os.environ.setdefault("MANAGEMENT_SESSION_SECRET", "tests-secret-key")

from app.database import Database
from app.management import create_app


EMAIL = "terminal@example.com"
PASSWORD = "super-secret"


class DummyChannel:
    def __init__(self) -> None:
        self.sent = []
        self.resizes = []
        self.closed = False
        self.send_event = threading.Event()
        self.resize_event = threading.Event()
        self._queue = queue.Queue()

    def queue_data(self, data: bytes) -> None:
        self._queue.put(data)

    def recv(self, _size: int) -> bytes:
        return self._queue.get()

    def send(self, data: bytes) -> int:
        payload = bytes(data)
        self.sent.append(payload)
        self.send_event.set()
        return len(payload)

    def resize_pty(self, width: int, height: int) -> None:
        self.resizes.append((width, height))
        self.resize_event.set()

    def close(self) -> None:
        if not self.closed:
            self.closed = True
            self._queue.put(b"")


def test_terminal_websocket_requires_authentication(tmp_path):
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
        allow_unknown_hosts=False,
        known_hosts_path=None,
    )

    app = create_app(
        database=database,
        session_secret="tests-secret",
        api_base_url="https://example.com",
    )

    with TestClient(app) as client:
        with pytest.raises(WebSocketDisconnect) as excinfo:
            with client.websocket_connect(f"/management/agents/{agent.id}/terminal"):
                pass
        assert excinfo.value.code == 4401


def test_terminal_websocket_streams_data(tmp_path):
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

    app = create_app(
        database=database,
        session_secret="tests-secret",
        api_base_url="https://example.com",
    )

    channels: list[DummyChannel] = []

    def terminal_factory(requested_agent):
        assert requested_agent.id == agent.id
        channel = DummyChannel()
        channels.append(channel)

        @contextmanager
        def manager():
            try:
                yield channel
            finally:
                channel.close()

        return manager()

    app.state.ssh_terminal_factory = terminal_factory

    with TestClient(app) as client:
        login = client.post(
            "/login",
            data={"email": EMAIL, "password": PASSWORD},
            follow_redirects=False,
        )
        assert login.status_code == 303

        with client.websocket_connect(f"/management/agents/{agent.id}/terminal") as websocket:
            message = websocket.receive_json()
            assert message["type"] == "status"
            assert message["status"] == "connected"

            channel = channels[0]
            channel.queue_data(b"welcome\n")
            assert websocket.receive_bytes() == b"welcome\n"

            websocket.send_bytes(b"ls\n")
            assert channel.send_event.wait(timeout=1)
            assert channel.sent[-1] == b"ls\n"

            websocket.send_text(json.dumps({"type": "resize", "cols": 120, "rows": 40}))
            assert channel.resize_event.wait(timeout=1)
            assert channel.resizes[-1] == (120, 40)
            websocket.send_text(json.dumps({"type": "close"}))

        assert channel.closed is True

