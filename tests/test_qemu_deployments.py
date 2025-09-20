import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.qemu import QEMUManager
from app.ssh import CommandResult


class DummyRunner:
    def __init__(self) -> None:
        self.calls = []

    def run(self, args, timeout: int = 60) -> CommandResult:
        self.calls.append((args, timeout))
        return CommandResult(command=args, exit_status=0, stdout="ok", stderr="")


def extract_script(runner: DummyRunner) -> tuple[str, int]:
    assert runner.calls, "No commands executed"
    command, timeout = runner.calls[0]
    assert command[0] == "bash"
    assert command[1] == "-lc"
    return command[2], timeout


def test_deploy_vm_ubuntu_generates_cloud_init_script():
    runner = DummyRunner()
    manager = QEMUManager(runner)

    result = manager.deploy_vm(
        "ubuntu-24-04",
        "vm-test",
        memory_mb=2048,
        vcpus=2,
        disk_gb=32,
    )

    script, timeout = extract_script(runner)
    assert "cloud-images.ubuntu.com" in script
    assert "virt-install" in script
    assert "cloud-config" in script
    assert "playradmin:PlayrServers!23" in script
    assert "ubuntu24.04" in script
    assert timeout == 900
    assert result.exit_status == 0


def test_deploy_vm_windows_generates_unattend_script():
    runner = DummyRunner()
    manager = QEMUManager(runner)

    result = manager.deploy_vm(
        "windows-server-2022",
        "win-host",
        memory_mb=4096,
        vcpus=4,
        disk_gb=60,
    )

    script, timeout = extract_script(runner)
    assert "software-download.microsoft.com" in script
    assert "Autounattend.xml" in script
    assert "PlayrServers!23" in script
    assert "virt-install" in script
    assert "win2k22" in script
    assert timeout == 1800
    assert result.exit_status == 0


def test_deploy_vm_rejects_unknown_profile():
    runner = DummyRunner()
    manager = QEMUManager(runner)

    with pytest.raises(ValueError):
        manager.deploy_vm("unknown-profile", "bad-vm")


def test_deploy_vm_rejects_invalid_name():
    runner = DummyRunner()
    manager = QEMUManager(runner)

    with pytest.raises(ValueError):
        manager.deploy_vm("ubuntu-24-04", "invalid name")

