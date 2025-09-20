"""Abstractions for controlling QEMU/KVM instances using virsh."""
from __future__ import annotations

from __future__ import annotations

import html
import re
import shlex
import textwrap
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Sequence, Tuple

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


ScriptBuilder = Callable[[str, int, int, int, str, str], str]


@dataclass(frozen=True)
class VMDeploymentProfile:
    """Describes a turn-key VM deployment recipe."""

    id: str
    name: str
    description: str
    default_username: str
    default_password: str
    default_memory_mb: int
    default_vcpus: int
    default_disk_gb: int
    download_url: str
    source_url: str
    os_variant: str
    _builder: ScriptBuilder = field(repr=False)
    notes: str | None = None
    timeout_seconds: int = 900

    def build_script(
        self,
        vm_name: str,
        memory_mb: int,
        vcpus: int,
        disk_gb: int,
        username: str,
        password: str,
    ) -> str:
        return self._builder(vm_name, memory_mb, vcpus, disk_gb, username, password)

    def resolve_credentials(
        self,
        username: str | None,
        password: str | None,
    ) -> Tuple[str, str]:
        candidate_username = _clean_optional(username) or self.default_username
        candidate_password = _clean_optional(password) or self.default_password
        resolved_username = _sanitize_username(candidate_username)
        resolved_password = _sanitize_password(candidate_password)
        return resolved_username, resolved_password

    def to_public_dict(self) -> Dict[str, object]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "default_username": self.default_username,
            "default_password": self.default_password,
            "default_memory_mb": self.default_memory_mb,
            "default_vcpus": self.default_vcpus,
            "default_disk_gb": self.default_disk_gb,
            "download_url": self.download_url,
            "source_url": self.source_url,
            "os_variant": self.os_variant,
            "notes": self.notes,
        }


IMAGE_ROOT = "/var/lib/libvirt/images/playrservers"


_USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,32}$")


def _clean_optional(value: str | None) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        return None
    cleaned = value.strip()
    if not cleaned:
        return None
    return cleaned


def _sanitize_vm_name(name: str) -> str:
    cleaned = name.strip()
    if not cleaned:
        raise ValueError("Virtual machine name must not be empty.")
    if not re.match(r"^[A-Za-z0-9._-]+$", cleaned):
        raise ValueError("Virtual machine name may only include letters, numbers, dots, dashes, and underscores.")
    return cleaned


def _sanitize_username(username: str) -> str:
    cleaned = username.strip()
    if not cleaned:
        raise ValueError("Username must not be empty.")
    if not _USERNAME_PATTERN.fullmatch(cleaned):
        raise ValueError(
            "Username may only include letters, numbers, dots, dashes, and underscores, and must be at most 32 characters."
        )
    return cleaned


def _sanitize_password(password: str) -> str:
    if not isinstance(password, str):
        raise ValueError("Password must be a string.")
    if any(ch in password for ch in "\r\n"):
        raise ValueError("Password must not contain newline characters.")
    if any(ch.isspace() for ch in password):
        raise ValueError("Password must not contain whitespace characters.")
    if ":" in password:
        raise ValueError("Password must not contain colon characters.")
    if len(password) < 12:
        raise ValueError("Password must be at least 12 characters long.")
    if len(password) > 128:
        raise ValueError("Password must not exceed 128 characters.")
    return password


def _render_ubuntu_deployment_script(
    vm_name: str,
    memory_mb: int,
    vcpus: int,
    disk_gb: int,
    username: str,
    password: str,
) -> str:
    image_path = f"{IMAGE_ROOT}/cloud/noble-server-cloudimg-amd64.img"
    disk_path = f"{IMAGE_ROOT}/{vm_name}.qcow2"
    seed_dir = f"{IMAGE_ROOT}/seed/{vm_name}"
    user_data = f"{seed_dir}/user-data"
    meta_data = f"{seed_dir}/meta-data"
    script = f"""
set -euo pipefail

VM_NAME={shlex.quote(vm_name)}
IMAGES_DIR={shlex.quote(IMAGE_ROOT)}
BASE_IMAGE={shlex.quote(image_path)}
DISK_IMAGE={shlex.quote(disk_path)}
SEED_DIR={shlex.quote(seed_dir)}
USER_DATA={shlex.quote(user_data)}
META_DATA={shlex.quote(meta_data)}
DOWNLOAD_URL={shlex.quote('https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img')}

mkdir -p "$IMAGES_DIR" "$IMAGES_DIR/cloud" "$IMAGES_DIR/seed"

if virsh dominfo "$VM_NAME" >/dev/null 2>&1; then
    echo "Virtual machine '$VM_NAME' already exists." >&2
    exit 50
fi

if [ -e "$DISK_IMAGE" ]; then
    echo "Disk image $DISK_IMAGE already exists." >&2
    exit 51
fi

if [ ! -f "$BASE_IMAGE" ]; then
    tmpfile=$(mktemp "${{BASE_IMAGE}}.XXXX")
    curl -L --fail --silent --show-error -o "$tmpfile" "$DOWNLOAD_URL"
    mv "$tmpfile" "$BASE_IMAGE"
fi

qemu-img create -f qcow2 -F qcow2 -b "$BASE_IMAGE" "$DISK_IMAGE" {disk_gb}G

mkdir -p "$SEED_DIR"
cat <<'EOF' > "$USER_DATA"
#cloud-config
users:
  - name: {username}
    sudo: ALL=(ALL) NOPASSWD:ALL
    groups: sudo
    shell: /bin/bash
    lock_passwd: false
chpasswd:
  expire: false
  list: |
    {username}:{password}
ssh_pwauth: true
EOF

cat <<'EOF' > "$META_DATA"
instance-id: {vm_name}
local-hostname: {vm_name}
EOF

virt-install \
  --name "$VM_NAME" \
  --memory {memory_mb} \
  --vcpus {vcpus} \
  --disk path="$DISK_IMAGE",format=qcow2 \
  --import \
  --os-variant ubuntu24.04 \
  --graphics spice \
  --network network=default \
  --cloud-init user-data="$USER_DATA",meta-data="$META_DATA" \
  --noautoconsole \
  --wait 0
"""
    return textwrap.dedent(script).strip()


def _render_windows_deployment_script(
    vm_name: str,
    memory_mb: int,
    vcpus: int,
    disk_gb: int,
    username: str,
    password: str,
) -> str:
    iso_path = f"{IMAGE_ROOT}/iso/windows-server-2022.iso"
    disk_path = f"{IMAGE_ROOT}/{vm_name}.qcow2"
    unattend_dir = f"{IMAGE_ROOT}/unattend/{vm_name}"
    unattend_xml = f"{unattend_dir}/Autounattend.xml"
    unattend_iso = f"{unattend_dir}/autounattend.iso"
    download_url = "https://software-download.microsoft.com/download/pr/20348.169.210806-2348.fe_release_svc_refresh_SERVER_EVAL_x64FRE_en-us.iso"
    script = f"""
set -euo pipefail

VM_NAME={shlex.quote(vm_name)}
IMAGES_DIR={shlex.quote(IMAGE_ROOT)}
ISO_STORE={shlex.quote(IMAGE_ROOT + '/iso')}
ISO_PATH={shlex.quote(iso_path)}
DISK_IMAGE={shlex.quote(disk_path)}
UNATTEND_DIR={shlex.quote(unattend_dir)}
UNATTEND_XML={shlex.quote(unattend_xml)}
UNATTEND_ISO={shlex.quote(unattend_iso)}
DOWNLOAD_URL={shlex.quote(download_url)}

mkdir -p "$IMAGES_DIR" "$ISO_STORE" "$UNATTEND_DIR"

if virsh dominfo "$VM_NAME" >/dev/null 2>&1; then
    echo "Virtual machine '$VM_NAME' already exists." >&2
    exit 50
fi

if [ -e "$DISK_IMAGE" ]; then
    echo "Disk image $DISK_IMAGE already exists." >&2
    exit 51
fi

if [ ! -f "$ISO_PATH" ]; then
    tmpfile=$(mktemp "${{ISO_PATH}}.XXXX")
    curl -L --fail --silent --show-error -o "$tmpfile" "$DOWNLOAD_URL"
    mv "$tmpfile" "$ISO_PATH"
fi

qemu-img create -f qcow2 "$DISK_IMAGE" {disk_gb}G

cat > "$UNATTEND_XML" <<'EOF'
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <settings pass="windowsPE">
    <component name="Microsoft-Windows-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
      <DiskConfiguration>
        <Disk wcm:action="add">
          <DiskID>0</DiskID>
          <WillWipeDisk>true</WillWipeDisk>
          <CreatePartitions>
            <CreatePartition wcm:action="add">
              <Order>1</Order>
              <Type>Primary</Type>
              <Size>500</Size>
            </CreatePartition>
            <CreatePartition wcm:action="add">
              <Order>2</Order>
              <Type>Primary</Type>
              <Extend>true</Extend>
            </CreatePartition>
          </CreatePartitions>
          <ModifyPartitions>
            <ModifyPartition wcm:action="add">
              <Order>1</Order>
              <PartitionID>1</PartitionID>
              <Format>NTFS</Format>
              <Label>System</Label>
              <Letter>C</Letter>
              <Active>true</Active>
            </ModifyPartition>
            <ModifyPartition wcm:action="add">
              <Order>2</Order>
              <PartitionID>2</PartitionID>
              <Format>NTFS</Format>
              <Label>Windows</Label>
              <Letter>C</Letter>
            </ModifyPartition>
          </ModifyPartitions>
        </Disk>
        <WillShowUI>OnError</WillShowUI>
      </DiskConfiguration>
      <ImageInstall>
        <OSImage>
          <InstallTo>
            <DiskID>0</DiskID>
            <PartitionID>2</PartitionID>
          </InstallTo>
          <InstallToAvailablePartition>true</InstallToAvailablePartition>
        </OSImage>
      </ImageInstall>
      <UserData>
        <AcceptEula>true</AcceptEula>
        <FullName>PlayrServers</FullName>
        <Organization>PlayrServers</Organization>
      </UserData>
    </component>
  </settings>
  <settings pass="specialize">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <ComputerName>*</ComputerName>
    </component>
  </settings>
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-International-Core" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <InputLocale>en-US</InputLocale>
      <SystemLocale>en-US</SystemLocale>
      <UILanguage>en-US</UILanguage>
      <UserLocale>en-US</UserLocale>
    </component>
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <OOBE>
        <HideEULAPage>true</HideEULAPage>
        <HideLocalAccountScreen>true</HideLocalAccountScreen>
        <HideOnlineAccountScreens>true</HideOnlineAccountScreens>
        <NetworkLocation>Work</NetworkLocation>
        <ProtectYourPC>1</ProtectYourPC>
      </OOBE>
      <UserAccounts>
        <AdministratorPassword>
          <Value>{html.escape(password, quote=True)}</Value>
          <PlainText>true</PlainText>
        </AdministratorPassword>
        <LocalAccounts>
          <LocalAccount wcm:action="add">
            <Name>{html.escape(username, quote=True)}</Name>
            <DisplayName>Playr Admin</DisplayName>
            <Group>Administrators</Group>
            <Password>
              <Value>{html.escape(password, quote=True)}</Value>
              <PlainText>true</PlainText>
            </Password>
          </LocalAccount>
        </LocalAccounts>
      </UserAccounts>
      <RegisteredOrganization>PlayrServers</RegisteredOrganization>
      <RegisteredOwner>PlayrServers</RegisteredOwner>
      <TimeZone>UTC</TimeZone>
    </component>
  </settings>
</unattend>
EOF

ISO_TOOL=""
for candidate in genisoimage mkisofs xorrisofs; do
  if command -v "$candidate" >/dev/null 2>&1; then
    ISO_TOOL="$candidate"
    break
  fi
done

if [ -z "$ISO_TOOL" ]; then
    echo "Unable to locate a utility to build ISO images (genisoimage, mkisofs, or xorrisofs)." >&2
    exit 52
fi

"$ISO_TOOL" -quiet -o "$UNATTEND_ISO" -V AUTOUNATTEND -graft-points Autounattend.xml="$UNATTEND_XML"

virt-install \
  --name "$VM_NAME" \
  --memory {memory_mb} \
  --vcpus {vcpus} \
  --disk path="$DISK_IMAGE",format=qcow2,bus=sata \
  --disk path="$UNATTEND_ISO",device=cdrom \
  --cdrom "$ISO_PATH" \
  --os-variant win2k22 \
  --network network=default,model=e1000 \
  --graphics spice \
  --boot uefi \
  --noautoconsole \
  --wait 0
"""
    return textwrap.dedent(script).strip()


_DEPLOYMENT_PROFILES: Dict[str, VMDeploymentProfile] = {
    "ubuntu-24-04": VMDeploymentProfile(
        id="ubuntu-24-04",
        name="Ubuntu Server 24.04 LTS",
        description="Deploys the official Ubuntu 24.04 LTS cloud image with a ready-to-use automation account.",
        default_username="playradmin",
        default_password="PlayrServers!23",
        default_memory_mb=4096,
        default_vcpus=2,
        default_disk_gb=40,
        download_url="https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img",
        source_url="https://ubuntu.com/download/server",
        os_variant="ubuntu24.04",
        notes="Uses cloud-init to provision the default administrator account and password.",
        timeout_seconds=900,
        _builder=_render_ubuntu_deployment_script,
    ),
    "windows-server-2022": VMDeploymentProfile(
        id="windows-server-2022",
        name="Windows Server 2022 Datacenter (Evaluation)",
        description="Downloads the Microsoft evaluation ISO and performs an unattended installation with administrator credentials configured.",
        default_username="playradmin",
        default_password="PlayrServers!23",
        default_memory_mb=8192,
        default_vcpus=4,
        default_disk_gb=80,
        download_url="https://software-download.microsoft.com/download/pr/20348.169.210806-2348.fe_release_svc_refresh_SERVER_EVAL_x64FRE_en-us.iso",
        source_url="https://www.microsoft.com/en-us/evalcenter/download-windows-server-2022",
        os_variant="win2k22",
        notes="Creates an Autounattend ISO on the hypervisor to automate the installation and set the administrator password.",
        timeout_seconds=1800,
        _builder=_render_windows_deployment_script,
    ),
}


def get_vm_deployment_profiles() -> Sequence[VMDeploymentProfile]:
    return list(_DEPLOYMENT_PROFILES.values())


def get_vm_deployment_profile(profile_id: str) -> VMDeploymentProfile | None:
    return _DEPLOYMENT_PROFILES.get(profile_id)


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

    def deploy_vm(
        self,
        profile_id: str,
        vm_name: str,
        *,
        memory_mb: int | None = None,
        vcpus: int | None = None,
        disk_gb: int | None = None,
        username: str | None = None,
        password: str | None = None,
    ) -> CommandResult:
        profile = get_vm_deployment_profile(profile_id)
        if profile is None:
            raise ValueError("Unknown deployment profile requested.")

        cleaned_name = _sanitize_vm_name(vm_name)

        resolved_username, resolved_password = profile.resolve_credentials(username, password)

        def _coerce(value: int | None, default: int, label: str) -> int:
            try:
                coerced = int(value) if value is not None else int(default)
            except (TypeError, ValueError) as exc:  # pragma: no cover - defensive
                raise ValueError(f"{label} must be a whole number.") from exc
            if coerced <= 0:
                raise ValueError(f"{label} must be greater than zero.")
            return coerced

        resolved_memory = _coerce(memory_mb, profile.default_memory_mb, "Memory (MiB)")
        resolved_vcpus = _coerce(vcpus, profile.default_vcpus, "vCPU count")
        resolved_disk = _coerce(disk_gb, profile.default_disk_gb, "Disk size (GiB)")

        script = profile.build_script(
            cleaned_name,
            resolved_memory,
            resolved_vcpus,
            resolved_disk,
            resolved_username,
            resolved_password,
        )

        try:
            result = self._runner.run(["bash", "-lc", script], timeout=profile.timeout_seconds)
        except SSHError as exc:
            raise QEMUError(f"Failed to deploy virtual machine '{cleaned_name}': {exc}") from exc
        if result.exit_status != 0:
            raise QEMUError(
                f"Failed to deploy virtual machine '{cleaned_name}'",
                result,
            )
        return result

    def _execute(self, command: List[str], action: str) -> CommandResult:
        try:
            result = self._runner.run(command)
        except SSHError as exc:
            raise QEMUError(f"Failed to {action}: {exc}") from exc

        if result.exit_status != 0:
            raise QEMUError(f"Failed to {action}", result)
        return result


__all__ = [
    "QEMUManager",
    "QEMUError",
    "VMInfo",
    "VMDeploymentProfile",
    "get_vm_deployment_profiles",
    "get_vm_deployment_profile",
]
