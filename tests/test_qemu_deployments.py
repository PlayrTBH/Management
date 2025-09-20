import shlex
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
    assert "instance-id: vm-test" in script
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


def test_deploy_vm_ubuntu_supports_custom_credentials():
    runner = DummyRunner()
    manager = QEMUManager(runner)

    manager.deploy_vm(
        "ubuntu-24-04",
        "vm-credentials",
        memory_mb=2048,
        vcpus=2,
        disk_gb=32,
        username="customadmin",
        password="SuperSecurePass1!",
    )

    script, _ = extract_script(runner)
    assert "name: customadmin" in script
    assert "customadmin:SuperSecurePass1!" in script


def test_deploy_vm_windows_supports_custom_credentials():
    runner = DummyRunner()
    manager = QEMUManager(runner)

    manager.deploy_vm(
        "windows-server-2022",
        "win-credentials",
        memory_mb=4096,
        vcpus=4,
        disk_gb=80,
        username="customadmin",
        password="SuperSecurePass1!",
    )

    script, _ = extract_script(runner)
    assert "<Name>customadmin</Name>" in script
    assert script.count("SuperSecurePass1!") >= 2


def test_deploy_vm_rejects_invalid_password_length():
    runner = DummyRunner()
    manager = QEMUManager(runner)

    with pytest.raises(ValueError):
        manager.deploy_vm(
            "ubuntu-24-04",
            "vm-invalid-password",
            password="short",
        )


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


def test_deploy_vm_uses_custom_image_root(monkeypatch, tmp_path):
    runner = DummyRunner()
    manager = QEMUManager(runner)

    custom_root = tmp_path / "custom-images"
    monkeypatch.setenv("MANAGEMENT_QEMU_IMAGE_ROOT", str(custom_root))

    manager.deploy_vm(
        "ubuntu-24-04",
        "vm-custom-root",
        memory_mb=2048,
        vcpus=2,
        disk_gb=32,
    )

    script, _ = extract_script(runner)
    expected_assignment = f"DEFAULT_IMAGE_ROOT={shlex.quote(str(custom_root))}"
    assert expected_assignment in script
    assert 'IMAGES_DIR="$DEFAULT_IMAGE_ROOT"' in script
    assert 'SEED_DIR="$IMAGES_DIR/seed/${VM_NAME}"' in script


def test_deploy_vm_script_mentions_remote_override():
    runner = DummyRunner()
    manager = QEMUManager(runner)

    manager.deploy_vm(
        "ubuntu-24-04",
        "vm-remote-override",
        memory_mb=2048,
        vcpus=2,
        disk_gb=32,
    )

    script, _ = extract_script(runner)
    assert "MANAGEMENT_QEMU_IMAGE_ROOT" in script
    assert 'CANDIDATE="$(printf' in script

