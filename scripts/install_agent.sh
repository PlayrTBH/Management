#!/usr/bin/env bash
# PlayrServers hypervisor agent installer
#
# This script provisions the dependencies required to run QEMU-based virtual
# machines, installs the PlayrServers agent runtime, and configures a systemd
# service that maintains an authenticated control tunnel back to the management
# plane.

set -euo pipefail

SCRIPT_NAME="playr-agent-installer"
DEFAULT_AGENT_HOME="/opt/playr-agent"
DEFAULT_CONFIG_DIR="/etc/playr-agent"
DEFAULT_CONFIG_FILE="${DEFAULT_CONFIG_DIR}/config.json"
DEFAULT_LOG_DIR="/var/log/playr-agent"
DEFAULT_MANAGEMENT_URL="https://api.playrservers.com"
DEFAULT_TUNNEL_HOST="api.playrservers.com"
DEFAULT_TUNNEL_PORT="443"
DEFAULT_SSH_USER="tunnels"
DEFAULT_SSH_PORT="22"
DEFAULT_HEARTBEAT="30"

APT_PACKAGES=(
  qemu-kvm
  qemu-utils
  libvirt-daemon-system
  libvirt-clients
  bridge-utils
  virtinst
  cloud-image-utils
  python3
  python3-venv
  python3-pip
  openssh-client
  sshpass
  socat
)

print_header() {
  echo "==> ${1}"
}

error() {
  echo "${SCRIPT_NAME}: ${1}" >&2
}

require_root() {
  if [[ ${EUID} -ne 0 ]]; then
    error "This installer must be run as root. Try again with sudo."
    exit 1
  fi
}

command_exists() {
  command -v "$1" >/dev/null 2>&1
}

usage() {
  cat <<USAGE
Usage: curl <host>/agent | sudo bash [-s -- [options]]

Options:
  --api-key <key>          API key used to authenticate with the management plane.
  --agent-id <id>          Identifier reported to the control plane (default: hostname).
  --management-url <url>   Base URL of the management plane (default: ${DEFAULT_MANAGEMENT_URL}).
  --tunnel-host <host>     Hostname used for reverse tunnels (default: ${DEFAULT_TUNNEL_HOST}).
  --tunnel-port <port>     TCP port for tunnel rendezvous (default: ${DEFAULT_TUNNEL_PORT}).
  --ssh-user <user>        SSH account used when establishing reverse tunnels (default: ${DEFAULT_SSH_USER}).
  --ssh-port <port>        SSH port used for reverse tunnels (default: ${DEFAULT_SSH_PORT}).
  --agent-home <path>      Installation directory for the agent runtime (default: ${DEFAULT_AGENT_HOME}).
  --config-file <path>     Location of the agent configuration file (default: ${DEFAULT_CONFIG_FILE}).
  --heartbeat <seconds>    Override the heartbeat interval in seconds (default: ${DEFAULT_HEARTBEAT}).
  --non-interactive        Fail if required values are missing instead of prompting.
  -h, --help               Show this help message.
USAGE
}

prompt_value() {
  local prompt="$1"
  local var
  read -r -p "${prompt}: " var
  echo "${var}"
}

ensure_directories() {
  local agent_home="$1"
  local config_file="$2"
  local log_dir="$3"
  install -d -m 0755 "${agent_home}"
  install -d -m 0750 "$(dirname "${config_file}")"
  install -d -m 0750 "${log_dir}"
}

ensure_user() {
  local user="playr-agent"
  if id "${user}" >/dev/null 2>&1; then
    return
  fi
  useradd --system --home "${DEFAULT_AGENT_HOME}" --shell /usr/sbin/nologin "${user}"
}

install_packages() {
  if ! command_exists apt-get; then
    error "Only Debian/Ubuntu based systems are supported by this installer."
    exit 1
  fi

  print_header "Updating package index"
  DEBIAN_FRONTEND=noninteractive apt-get update -y

  print_header "Installing agent dependencies"
  DEBIAN_FRONTEND=noninteractive apt-get install -y "${APT_PACKAGES[@]}"
}

create_virtualenv() {
  local agent_home="$1"
  if [[ ! -d "${agent_home}/venv" ]]; then
    print_header "Creating Python virtual environment"
    python3 -m venv "${agent_home}/venv"
  fi
  print_header "Installing Python dependencies"
  "${agent_home}/venv/bin/pip" install --upgrade pip >/dev/null
  "${agent_home}/venv/bin/pip" install httpx >/dev/null
}

write_agent_runtime() {
  local agent_home="$1"
  cat <<'PYCODE' > "${agent_home}/agent.py"
#!/usr/bin/env python3
"""PlayrServers hypervisor agent runtime."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import platform
import signal
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, Optional

import httpx

DEFAULT_HEARTBEAT = 30
_LOGGER = logging.getLogger("playr.agent")


def _default_agent_id() -> str:
    return os.getenv("PLAYR_AGENT_ID", platform.node() or "hypervisor")


@dataclass
class SSHSettings:
    user: str
    port: int
    private_key: Optional[str] = None
    extra_args: tuple[str, ...] = ()


@dataclass
class AgentConfig:
    management_url: str
    api_key: str
    agent_id: str
    hostname: str
    tunnel_host: str
    tunnel_port: int
    heartbeat_interval: int = DEFAULT_HEARTBEAT
    capabilities: tuple[str, ...] = ("qemu", "hypervisor")
    metadata: Dict[str, str] = field(default_factory=dict)
    ssh: SSHSettings = field(default_factory=lambda: SSHSettings(user="tunnels", port=22))

    @classmethod
    def from_file(cls, path: Path) -> "AgentConfig":
        data = json.loads(path.read_text())
        ssh_data = data.get("ssh", {})
        ssh = SSHSettings(
            user=ssh_data.get("user", "tunnels"),
            port=int(ssh_data.get("port", 22)),
            private_key=ssh_data.get("private_key"),
            extra_args=tuple(ssh_data.get("extra_args", [])),
        )
        metadata = {str(k): str(v) for k, v in data.get("metadata", {}).items()}
        capabilities = tuple(str(item) for item in data.get("capabilities", ["qemu", "hypervisor"]))
        return cls(
            management_url=data["management_url"].rstrip("/"),
            api_key=data["api_key"],
            agent_id=data.get("agent_id") or _default_agent_id(),
            hostname=data.get("hostname") or platform.node(),
            tunnel_host=data.get("tunnel_host", data["management_url"].split("://", 1)[-1]),
            tunnel_port=int(data.get("tunnel_port", 443)),
            heartbeat_interval=int(data.get("heartbeat_interval", DEFAULT_HEARTBEAT)),
            capabilities=capabilities,
            metadata=metadata,
            ssh=ssh,
        )


@dataclass
class TunnelProcess:
    identifier: str
    remote_port: int
    client_token: str
    ssh_settings: SSHSettings
    tunnel_host: str
    local_port: Optional[int] = None
    process: Optional[asyncio.subprocess.Process] = None

    async def start(self) -> None:
        if self.process and self.process.returncode is None:
            return
        local_port = self.local_port or self.remote_port
        command = [
            "ssh",
            "-NT",
            "-o",
            "ExitOnForwardFailure=yes",
            "-o",
            "ServerAliveInterval=30",
            "-o",
            "ServerAliveCountMax=3",
            "-p",
            str(self.ssh_settings.port),
            "-R",
            f"{self.remote_port}:127.0.0.1:{local_port}",
        ]
        if self.ssh_settings.private_key:
            command.extend(["-i", self.ssh_settings.private_key])
        for extra in self.ssh_settings.extra_args:
            command.append(extra)
        command.append(f"{self.ssh_settings.user}@{self.tunnel_host}")
        if self.client_token:
            command = ["sshpass", "-p", self.client_token, *command]
        _LOGGER.info(
            "Starting tunnel %s forwarding management port %s to local port %s",
            self.identifier,
            self.remote_port,
            local_port,
        )
        self.process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        asyncio.create_task(self._log_stream(self.process.stdout, logging.DEBUG))
        asyncio.create_task(self._log_stream(self.process.stderr, logging.WARNING))

    async def stop(self) -> None:
        if not self.process:
            return
        if self.process.returncode is None:
            _LOGGER.info("Stopping tunnel %s", self.identifier)
            self.process.terminate()
            try:
                await asyncio.wait_for(self.process.wait(), timeout=10)
            except asyncio.TimeoutError:
                self.process.kill()
        self.process = None

    async def _log_stream(self, stream: Optional[asyncio.StreamReader], level: int) -> None:
        if stream is None:
            return
        while True:
            line = await stream.readline()
            if not line:
                break
            _LOGGER.log(level, "[tunnel %s] %s", self.identifier, line.decode(errors="ignore").rstrip())

    def is_active(self) -> bool:
        return self.process is not None and self.process.returncode is None


class AgentRuntime:
    def __init__(self, config: AgentConfig) -> None:
        self.config = config
        self.session_id: Optional[str] = None
        self.agent_token: Optional[str] = None
        self._client = httpx.AsyncClient(
            base_url=self.config.management_url,
            timeout=httpx.Timeout(30.0, connect=30.0),
            headers={"User-Agent": "PlayrServers-Agent/1.0"},
        )
        self._shutdown = asyncio.Event()
        self._tunnels: Dict[str, TunnelProcess] = {}

    async def run(self) -> None:
        while not self._shutdown.is_set():
            try:
                await self._connect()
                await self._heartbeat_loop()
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # pragma: no cover - resilience logic
                _LOGGER.exception("Agent loop crashed: %s", exc)
                await asyncio.sleep(5)

    async def stop(self) -> None:
        self._shutdown.set()
        await self._client.aclose()
        await asyncio.gather(*(tunnel.stop() for tunnel in list(self._tunnels.values())), return_exceptions=True)

    async def _connect(self) -> None:
        payload = {
            "agent_id": self.config.agent_id,
            "hostname": self.config.hostname,
            "capabilities": list(self.config.capabilities),
            "metadata": {
                **self.config.metadata,
                "os": platform.platform(),
                "python": sys.version.split()[0],
            },
        }
        _LOGGER.info("Connecting agent %s to %s", self.config.agent_id, self.config.management_url)
        response = await self._client.post(
            "/v1/agents/connect",
            json=payload,
            headers=self._auth_header(),
        )
        response.raise_for_status()
        data = response.json()
        self.session_id = data["session_id"]
        self.agent_token = data["agent_token"]
        _LOGGER.info("Agent %s connected; session %s", self.config.agent_id, self.session_id)

    async def _heartbeat_loop(self) -> None:
        interval = max(self.config.heartbeat_interval, 5)
        while not self._shutdown.is_set():
            await self._sync_state()
            try:
                await asyncio.wait_for(self._shutdown.wait(), timeout=interval)
            except asyncio.TimeoutError:
                continue

    async def _sync_state(self) -> None:
        active = [identifier for identifier, tunnel in self._tunnels.items() if tunnel.is_active()]
        response = await self._client.post(
            f"/v1/agents/{self.config.agent_id}/heartbeat",
            json={
                "session_id": self.session_id,
                "agent_token": self.agent_token,
                "active_tunnels": active,
            },
            headers=self._auth_header(),
        )
        if response.status_code == 401:
            _LOGGER.warning("Authentication rejected; reconnecting")
            raise RuntimeError("Authentication failed")
        response.raise_for_status()
        payload = response.json()
        tunnel_state = {entry["tunnel_id"]: entry for entry in payload.get("tunnels", [])}
        if tunnel_state:
            await self._reconcile_tunnels(tunnel_state)

    async def _reconcile_tunnels(self, state: Dict[str, Dict[str, object]]) -> None:
        details = await self._fetch_tunnel_details()
        for identifier, info in state.items():
            desired_state = str(info.get("state", "pending"))
            if desired_state == "closed":
                await self._stop_tunnel(identifier)
                continue
            remote_port = int(info.get("remote_port", 0))
            detail = details.get(identifier)
            if not detail:
                _LOGGER.warning("Missing tunnel metadata for %s", identifier)
                continue
            client_token = detail.get("client_token") or ""
            metadata = detail.get("metadata") if isinstance(detail, dict) else None
            await self._ensure_tunnel(identifier, remote_port, client_token, metadata)

        active_identifiers = set(state.keys())
        for identifier in list(self._tunnels.keys()):
            if identifier not in active_identifiers:
                await self._stop_tunnel(identifier)

    async def _ensure_tunnel(
        self,
        identifier: str,
        remote_port: int,
        client_token: str,
        metadata: Dict[str, object] | None = None,
    ) -> None:
        tunnel = self._tunnels.get(identifier)
        if tunnel and tunnel.is_active():
            return
        local_port = remote_port
        if metadata:
            local_override = metadata.get("local_port") or metadata.get("target_port")
            if local_override is not None:
                try:
                    local_port = int(str(local_override))
                except ValueError:
                    _LOGGER.warning(
                        "Ignoring invalid local_port override for tunnel %s: %r",
                        identifier,
                        local_override,
                    )
        tunnel = TunnelProcess(
            identifier=identifier,
            remote_port=remote_port,
            client_token=client_token,
            ssh_settings=self.config.ssh,
            tunnel_host=self.config.tunnel_host,
            local_port=local_port,
        )
        self._tunnels[identifier] = tunnel
        try:
            await tunnel.start()
        except FileNotFoundError as exc:
            _LOGGER.error("SSH binary missing while starting tunnel %s: %s", identifier, exc)
        except Exception as exc:  # pragma: no cover - defensive logging
            _LOGGER.exception("Unable to start tunnel %s: %s", identifier, exc)

    async def _stop_tunnel(self, identifier: str) -> None:
        tunnel = self._tunnels.pop(identifier, None)
        if tunnel:
            await tunnel.stop()

    async def _fetch_tunnel_details(self) -> Dict[str, Dict[str, object]]:
        response = await self._client.get(
            f"/v1/agents/{self.config.agent_id}",
            headers=self._auth_header(),
        )
        response.raise_for_status()
        payload = response.json()
        details = {}
        for entry in payload.get("tunnels", []):
            details[str(entry.get("tunnel_id"))] = entry
        return details

    def _auth_header(self) -> Dict[str, str]:
        return {"Authorization": f"Bearer {self.config.api_key}"}


async def _run(config_path: Path) -> None:
    config = AgentConfig.from_file(config_path)
    runtime = AgentRuntime(config)

    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()

    for signame in {signal.SIGINT, signal.SIGTERM}:
        loop.add_signal_handler(signame, stop_event.set)

    async def _shutdown() -> None:
        await stop_event.wait()
        await runtime.stop()

    await asyncio.gather(runtime.run(), _shutdown())


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="PlayrServers hypervisor agent")
    parser.add_argument("--config", default="/etc/playr-agent/config.json", help="Path to agent configuration file")
    parser.add_argument("--log-level", default="INFO", help="Logging level (default: INFO)")
    args = parser.parse_args(argv)

    logging.basicConfig(level=getattr(logging, args.log_level.upper(), logging.INFO), format="%(asctime)s %(levelname)s %(name)s %(message)s")
    config_path = Path(args.config)
    if not config_path.exists():
        raise SystemExit(f"Configuration file {config_path} does not exist")

    asyncio.run(_run(config_path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
PYCODE
  chmod +x "${agent_home}/agent.py"
}

write_configuration() {
  local config_file="$1"
  local management_url="$2"
  local api_key="$3"
  local agent_id="$4"
  local tunnel_host="$5"
  local tunnel_port="$6"
  local ssh_user="$7"
  local ssh_port="$8"
  local heartbeat="$9"
  cat <<JSONCONFIG > "${config_file}"
{
  "management_url": "${management_url}",
  "api_key": "${api_key}",
  "agent_id": "${agent_id}",
  "hostname": "${agent_id}",
  "tunnel_host": "${tunnel_host}",
  "tunnel_port": ${tunnel_port},
  "heartbeat_interval": ${heartbeat},
  "ssh": {
    "user": "${ssh_user}",
    "port": ${ssh_port},
    "extra_args": ["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null"]
  },
  "capabilities": ["qemu", "libvirt", "hypervisor"],
  "metadata": {
    "provisioned_by": "${SCRIPT_NAME}"
  }
}
JSONCONFIG
  chmod 0640 "${config_file}"
  chown playr-agent:playr-agent "${config_file}"
}

write_service_unit() {
  local agent_home="$1"
  local config_file="$2"
  local unit_path="/etc/systemd/system/playr-agent.service"
  cat <<UNIT > "${unit_path}"
[Unit]
Description=PlayrServers Hypervisor Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=playr-agent
Group=playr-agent
Environment="PATH=${agent_home}/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin"
ExecStart="${agent_home}/venv/bin/python" "${agent_home}/agent.py" --config "${config_file}"
Restart=on-failure
RestartSec=5
StandardOutput=append:${DEFAULT_LOG_DIR}/agent.log
StandardError=append:${DEFAULT_LOG_DIR}/agent.log

[Install]
WantedBy=multi-user.target
UNIT
  if command_exists systemctl; then
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl enable playr-agent.service >/dev/null 2>&1 || true
    systemctl restart playr-agent.service >/dev/null 2>&1 || true
  else
    print_header "Systemd not detected; skip enabling playr-agent.service"
  fi
}

main() {
  local api_key=""
  local agent_id=""
  local management_url="${DEFAULT_MANAGEMENT_URL}"
  local tunnel_host="${DEFAULT_TUNNEL_HOST}"
  local tunnel_port="${DEFAULT_TUNNEL_PORT}"
  local ssh_user="${DEFAULT_SSH_USER}"
  local ssh_port="${DEFAULT_SSH_PORT}"
  local agent_home="${DEFAULT_AGENT_HOME}"
  local config_file="${DEFAULT_CONFIG_FILE}"
  local heartbeat="${DEFAULT_HEARTBEAT}"
  local non_interactive="0"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --api-key)
        api_key="$2"; shift 2 ;;
      --agent-id)
        agent_id="$2"; shift 2 ;;
      --management-url)
        management_url="$2"; shift 2 ;;
      --tunnel-host)
        tunnel_host="$2"; shift 2 ;;
      --tunnel-port)
        tunnel_port="$2"; shift 2 ;;
      --ssh-user)
        ssh_user="$2"; shift 2 ;;
      --ssh-port)
        ssh_port="$2"; shift 2 ;;
      --agent-home)
        agent_home="$2"; shift 2 ;;
      --config-file)
        config_file="$2"; shift 2 ;;
      --heartbeat)
        heartbeat="$2"; shift 2 ;;
      --non-interactive)
        non_interactive="1"; shift ;;
      -h|--help)
        usage; exit 0 ;;
      *)
        error "Unknown option: $1"; usage; exit 1 ;;
    esac
  done

  require_root

  if [[ -z "${agent_id}" ]]; then
    agent_id="$(hostname -s 2>/dev/null || hostname)"
  fi

  if [[ -z "${api_key}" ]]; then
    if [[ "${non_interactive}" == "1" ]]; then
      error "--api-key is required in non-interactive mode"
      exit 1
    fi
    api_key="$(prompt_value "Enter the management API key")"
  fi

  if [[ -z "${api_key}" ]]; then
    error "An API key is required to authenticate with the management plane"
    exit 1
  fi

  install_packages
  ensure_user

  ensure_directories "${agent_home}" "${config_file}" "${DEFAULT_LOG_DIR}"
  chown -R playr-agent:playr-agent "${agent_home}" "$(dirname "${config_file}")" "${DEFAULT_LOG_DIR}"

  create_virtualenv "${agent_home}"
  write_agent_runtime "${agent_home}"
  write_configuration "${config_file}" "${management_url}" "${api_key}" "${agent_id}" "${tunnel_host}" "${tunnel_port}" "${ssh_user}" "${ssh_port}" "${heartbeat}"
  write_service_unit "${agent_home}" "${config_file}"

  print_header "Installation complete"
  echo "Agent ID: ${agent_id}"
  echo "Configuration: ${config_file}"
  echo "Logs: ${DEFAULT_LOG_DIR}/agent.log"
}

main "$@"
