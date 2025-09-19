"""Helpers for automatically onboarding hypervisors via the agent API."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


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


@dataclass(frozen=True)
class AgentProvisioningSettings:
    """Configuration required to bootstrap new hypervisors via the agent."""

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
        username=username,
        port=port,
        allow_unknown_hosts=allow_unknown_hosts,
        known_hosts_path=known_hosts_path,
        close_other_sessions=close_other_sessions,
    )


def generate_provisioning_key_pair() -> tuple[str, str]:
    """Generate a new Ed25519 SSH key pair for provisioning agents."""

    try:
        private_key = ed25519.Ed25519PrivateKey.generate()
    except Exception as exc:  # pragma: no cover - cryptography failure is exceptional
        raise AgentProvisioningError("Failed to generate provisioning key material") from exc

    private_text = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8").strip()

    public_text = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    ).decode("utf-8").strip()

    return private_text, public_text


__all__ = [
    "AgentProvisioningError",
    "AgentProvisioningSettings",
    "load_agent_provisioning_settings",
    "generate_provisioning_key_pair",
]
