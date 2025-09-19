import os
from pathlib import Path
import sys

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

os.environ.setdefault("MANAGEMENT_SESSION_SECRET", "tests-secret-key")

from app.database import Database
from app.management import create_app
from app.ssh import CommandResult


EMAIL = "host@example.com"
PASSWORD = "super-secret"


class FakeRunner:
    def __init__(self) -> None:
        self.commands = []

    def run(self, args, timeout: int = 60) -> CommandResult:
        self.commands.append(list(args))
        joined = " ".join(args)
        if joined == "virsh nodeinfo":
            stdout = """CPU model: x86_64\nCPU(s): 4\nCPU frequency: 2400 MHz\nMemory size: 16777216 KiB\n"""
            return CommandResult(command=args, exit_status=0, stdout=stdout, stderr="")
        if joined == "uname -sr":
            return CommandResult(command=args, exit_status=0, stdout="Linux 6.1.0\n", stderr="")
        if joined == "cat /proc/loadavg":
            return CommandResult(command=args, exit_status=0, stdout="0.25 0.50 0.75 1/234 5678\n", stderr="")
        if joined == "free -b":
            stdout = (
                "              total        used        free      shared  buff/cache   available\n"
                "Mem:     16777216000  4294967296  2147483648   536870912  10200547328  1234567890\n"
                "Swap:     2147483648          0  2147483648\n"
            )
            return CommandResult(command=args, exit_status=0, stdout=stdout, stderr="")
        raise AssertionError(f"Unexpected command: {args}")


def test_host_info_endpoint_returns_metrics(tmp_path):
    database = Database(tmp_path / "management.sqlite3")
    database.initialize()
    user, _ = database.create_user("Observer", EMAIL, PASSWORD)
    agent = database.create_agent(
        user.id,
        name="hypervisor-01",
        hostname="hv.internal",
        port=22,
        username="qemu",
        private_key="dummy-key",
        private_key_passphrase=None,
        allow_unknown_hosts=False,
        known_hosts_path=None,
    )

    app = create_app(
        database=database,
        session_secret="tests-secret", 
        api_base_url="https://example.com",
    )

    runner = FakeRunner()

    def runner_factory(requested_agent):
        assert requested_agent.id == agent.id
        return runner

    app.state.ssh_runner_factory = runner_factory

    with TestClient(app) as client:
        login = client.post(
            "/login",
            data={"email": EMAIL, "password": PASSWORD},
            follow_redirects=False,
        )
        assert login.status_code == 303

        response = client.get(f"/management/agents/{agent.id}/host-info")
        assert response.status_code == 200

    payload = response.json()
    assert payload["status"] == "ok"
    assert payload["system"]["hostname"] == agent.hostname
    assert payload["system"]["username"] == agent.username
    assert payload["nodeinfo"]["CPU(s)"] == "4"
    assert payload["nodeinfo"]["CPU model"] == "x86_64"

    load = payload["performance"]["load_average"]
    assert load == {"one": 0.25, "five": 0.5, "fifteen": 0.75}

    memory = payload["performance"]["memory"]
    assert memory["total_bytes"] == 16777216000
    assert memory["used_bytes"] == 4294967296
    assert memory["available_bytes"] == 1234567890
    assert memory["usage_percent"] == 25.6

    assert payload["collected_at"].endswith("Z")
    assert runner.commands == [
        ["virsh", "nodeinfo"],
        ["uname", "-sr"],
        ["cat", "/proc/loadavg"],
        ["free", "-b"],
    ]
