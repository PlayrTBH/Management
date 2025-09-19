"""Helpers for automatically onboarding hypervisors via the agent API."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional


class AgentProvisioningError(RuntimeError):
    """Raised when the management host is misconfigured for agent onboarding."""


def _env_bool(value: Optional[str], default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() not in {"0", "false", "no", "off"}


def _env_int(value: Optional[str], default: int) -> int:
    if value is None or value.strip() == "":
        return default
    try:
        return int(value)
    except ValueError as exc:  # pragma: no cover - guards against misconfiguration
        raise AgentProvisioningError(
            f"Invalid integer value {value!r} for agent provisioning setting"
        ) from exc


def _env_path(value: Optional[str], default: Path) -> Path:
    if value is None or value.strip() == "":
        return default
    return Path(value).expanduser().resolve(strict=False)


def _resolve_default_public_key_path(private_key_path: Path) -> Path:
    """Return the default public key path for a given private key."""

    return Path(str(private_key_path) + ".pub").expanduser().resolve(strict=False)


@dataclass(frozen=True)
class AgentProvisioningSettings:
    """Configuration required to bootstrap new hypervisors via the agent."""

    private_key_path: Path
    public_key_path: Path
    username: str
    port: int = 22
    allow_unknown_hosts: bool = False
    known_hosts_path: Optional[Path] = None
    close_other_sessions: bool = True

    def known_hosts_as_string(self) -> Optional[str]:
        if self.known_hosts_path is None:
            return None
        return str(self.known_hosts_path)


def load_agent_provisioning_settings() -> AgentProvisioningSettings:
    """Load provisioning settings from environment variables."""

    default_private = Path("/etc/playrservers/ssh/id_ed25519").resolve(strict=False)
    private_key_path = _env_path(os.getenv("MANAGEMENT_AGENT_PRIVATE_KEY_PATH"), default_private)

    public_env = os.getenv("MANAGEMENT_AGENT_PUBLIC_KEY_PATH")
    if public_env:
        public_key_path = Path(public_env).expanduser().resolve(strict=False)
    else:
        public_key_path = _resolve_default_public_key_path(private_key_path)

    username = os.getenv("MANAGEMENT_AGENT_USERNAME", "hvdeploy").strip() or "hvdeploy"
    port = _env_int(os.getenv("MANAGEMENT_AGENT_SSH_PORT"), 22)
    allow_unknown_hosts = _env_bool(os.getenv("MANAGEMENT_AGENT_ALLOW_UNKNOWN_HOSTS"), False)
    known_hosts_env = os.getenv("MANAGEMENT_AGENT_KNOWN_HOSTS_PATH")
    known_hosts_path = (
        Path(known_hosts_env).expanduser().resolve(strict=False) if known_hosts_env else None
    )
    close_other_sessions = _env_bool(
        os.getenv("MANAGEMENT_AGENT_CLOSE_OTHER_SESSIONS"), True
    )

    return AgentProvisioningSettings(
        private_key_path=private_key_path,
        public_key_path=public_key_path,
        username=username,
        port=port,
        allow_unknown_hosts=allow_unknown_hosts,
        known_hosts_path=known_hosts_path,
        close_other_sessions=close_other_sessions,
    )


def _read_file(path: Path) -> str:
    try:
        data = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise AgentProvisioningError(f"File not found: {path}") from exc
    except OSError as exc:  # pragma: no cover - filesystem error
        raise AgentProvisioningError(f"Failed to read {path}: {exc}") from exc
    return data


def load_private_key(settings: AgentProvisioningSettings) -> str:
    """Return the management SSH private key used for new agents."""

    contents = _read_file(settings.private_key_path).strip()
    if not contents:
        raise AgentProvisioningError(
            f"Management SSH private key at {settings.private_key_path} is empty"
        )
    return contents


def load_authorized_keys(settings: AgentProvisioningSettings) -> List[str]:
    """Return the list of authorized public keys for the management account."""

    contents = _read_file(settings.public_key_path)
    keys: List[str] = [line.strip() for line in contents.splitlines() if line.strip()]
    if not keys:
        raise AgentProvisioningError(
            f"Management SSH public key at {settings.public_key_path} is empty"
        )
    return keys


def iter_authorized_keys(settings: AgentProvisioningSettings) -> Iterable[str]:
    """Yield the authorized keys for callers that prefer a generator."""

    for key in load_authorized_keys(settings):
        yield key


__all__ = [
    "AgentProvisioningError",
    "AgentProvisioningSettings",
    "iter_authorized_keys",
    "load_agent_provisioning_settings",
    "load_authorized_keys",
    "load_private_key",
]
