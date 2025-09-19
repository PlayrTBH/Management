import os
import sys
from pathlib import Path

import paramiko
import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

os.environ.setdefault("MANAGEMENT_SESSION_SECRET", "tests-secret-key")

from app import ssh as ssh_module
from app.ssh import SSHClientFactory, SSHTarget, SSHError


class DummyChannel:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


def _make_target() -> SSHTarget:
    return SSHTarget(
        hostname="example.com",
        port=22,
        username="root",
        private_key="dummy",
    )


def test_connect_unknown_host_error(monkeypatch):
    factory = SSHClientFactory(_make_target())

    class DummyClient:
        def __init__(self) -> None:
            self.closed = False

        def load_host_keys(self, *_args, **_kwargs) -> None:
            pass

        def load_system_host_keys(self) -> None:
            pass

        def set_missing_host_key_policy(self, _policy) -> None:
            pass

        def connect(self, **_kwargs) -> None:
            raise paramiko.SSHException("Server 'example.com' not found in known_hosts")

        def close(self) -> None:
            self.closed = True

    monkeypatch.setattr(paramiko, "SSHClient", DummyClient)
    monkeypatch.setattr(ssh_module, "_load_private_key", lambda _key, _passphrase: object())

    with pytest.raises(SSHError) as excinfo:
        with factory.connect():
            pass

    assert "Add the host to the configured known hosts file" in str(excinfo.value)


def test_open_shell_propagates_error(monkeypatch):
    factory = SSHClientFactory(_make_target())

    class DummyClient:
        def __init__(self) -> None:
            self.closed = False

        def load_host_keys(self, *_args, **_kwargs) -> None:
            pass

        def load_system_host_keys(self) -> None:
            pass

        def set_missing_host_key_policy(self, _policy) -> None:
            pass

        def connect(self, **_kwargs) -> None:
            pass

        def invoke_shell(self, **_kwargs):
            raise paramiko.SSHException("no shell")

        def close(self) -> None:
            self.closed = True

    monkeypatch.setattr(paramiko, "SSHClient", DummyClient)
    monkeypatch.setattr(ssh_module, "_load_private_key", lambda _key, _passphrase: object())

    with pytest.raises(SSHError) as excinfo:
        with factory.open_shell():
            pass

    assert "Failed to open an interactive shell" in str(excinfo.value)


def test_open_shell_closes_channel(monkeypatch):
    factory = SSHClientFactory(_make_target())

    channel = DummyChannel()

    class DummyClient:
        def __init__(self) -> None:
            self.closed = False

        def load_host_keys(self, *_args, **_kwargs) -> None:
            pass

        def load_system_host_keys(self) -> None:
            pass

        def set_missing_host_key_policy(self, _policy) -> None:
            pass

        def connect(self, **_kwargs) -> None:
            pass

        def invoke_shell(self, **_kwargs):
            return channel

        def close(self) -> None:
            self.closed = True

    monkeypatch.setattr(paramiko, "SSHClient", DummyClient)
    monkeypatch.setattr(ssh_module, "_load_private_key", lambda _key, _passphrase: object())

    with factory.open_shell() as opened:
        assert opened is channel

    assert channel.closed is True

