"""Abstractions for controlling QEMU/KVM instances using virsh."""
from __future__ import annotations

from dataclasses import dataclass
from typing import List

from .ssh import CommandResult, SSHCommandRunner, SSHError


class QEMUError(RuntimeError):
    """Raised when QEMU/virsh commands fail."""

    def __init__(self, message: str, result: CommandResult | None = None) -> None:
        super().__init__(message)
        self.result = result


@dataclass
class VMInfo:
    name: str
    state: str
    id: str | None


class QEMUManager:
    """High level interface for VM lifecycle operations."""

    def __init__(self, runner: SSHCommandRunner) -> None:
        self._runner = runner

    def list_vms(self) -> List[VMInfo]:
        result = self._runner.run(["virsh", "list", "--all"])
        if result.exit_status != 0:
            raise QEMUError("Failed to list virtual machines", result)

        lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        # Skip header lines (first two lines in standard virsh output)
        entries = lines[2:]
        vms: List[VMInfo] = []
        for entry in entries:
            parts = entry.split()
            if len(parts) < 3:
                # Unexpected format, skip but continue processing others
                continue
            vm_id = parts[0]
            name = parts[1]
            state = " ".join(parts[2:])
            vms.append(VMInfo(name=name, state=state, id=None if vm_id == "-" else vm_id))
        return vms

    def start_vm(self, name: str) -> CommandResult:
        return self._execute(["virsh", "start", name], f"start virtual machine '{name}'")

    def shutdown_vm(self, name: str) -> CommandResult:
        return self._execute(["virsh", "shutdown", name], f"shutdown virtual machine '{name}'")

    def force_stop_vm(self, name: str) -> CommandResult:
        return self._execute(["virsh", "destroy", name], f"force stop virtual machine '{name}'")

    def reboot_vm(self, name: str) -> CommandResult:
        return self._execute(["virsh", "reboot", name], f"reboot virtual machine '{name}'")

    def get_vm_info(self, name: str) -> CommandResult:
        return self._execute(["virsh", "dominfo", name], f"retrieve information for virtual machine '{name}'")

    def _execute(self, command: List[str], action: str) -> CommandResult:
        try:
            result = self._runner.run(command)
        except SSHError as exc:
            raise QEMUError(f"Failed to {action}: {exc}") from exc

        if result.exit_status != 0:
            raise QEMUError(f"Failed to {action}", result)
        return result


__all__ = ["QEMUManager", "QEMUError", "VMInfo"]
