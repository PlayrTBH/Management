"""Configuration management for the QEMU management service."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, Optional

import yaml


@dataclass(frozen=True)
class HostConfig:
    """Configuration for a remote virtualization host."""

    name: str
    hostname: str
    username: str
    private_key_path: Path
    port: int = 22
    passphrase: Optional[str] = None
    allow_unknown_hosts: bool = False
    known_hosts_file: Optional[Path] = None

    @staticmethod
    def from_dict(data: Dict[str, object], base_path: Path | None = None) -> "HostConfig":
        """Create a :class:`HostConfig` from raw dictionary data."""
        required_fields = {"name", "hostname", "username", "private_key_path"}
        missing = required_fields - data.keys()
        if missing:
            raise ValueError(f"Missing required host configuration fields: {', '.join(sorted(missing))}")

        raw_key_path = Path(str(data["private_key_path"]))
        if raw_key_path.is_absolute():
            private_key_path = raw_key_path.expanduser().resolve(strict=False)
        else:
            expanded = raw_key_path.expanduser()
            if base_path is not None:
                private_key_path = (base_path / expanded).resolve(strict=False)
            else:
                private_key_path = expanded.resolve(strict=False)
        known_hosts = data.get("known_hosts_file")
        if known_hosts:
            raw_known_hosts = Path(str(known_hosts))
            if raw_known_hosts.is_absolute():
                known_hosts_path = raw_known_hosts.expanduser().resolve(strict=False)
            else:
                expanded_known_hosts = raw_known_hosts.expanduser()
                if base_path is not None:
                    known_hosts_path = (base_path / expanded_known_hosts).resolve(strict=False)
                else:
                    known_hosts_path = expanded_known_hosts.resolve(strict=False)
        else:
            known_hosts_path = None

        return HostConfig(
            name=str(data["name"]),
            hostname=str(data["hostname"]),
            username=str(data["username"]),
            port=int(data.get("port", 22)),
            private_key_path=private_key_path,
            passphrase=str(data["passphrase"]) if data.get("passphrase") is not None else None,
            allow_unknown_hosts=bool(data.get("allow_unknown_hosts", False)),
            known_hosts_file=known_hosts_path,
        )


class HostRegistry:
    """Read-only registry of configured hosts."""

    def __init__(self, hosts: Iterable[HostConfig]) -> None:
        self._hosts: Dict[str, HostConfig] = {host.name: host for host in hosts}
        if len(self._hosts) == 0:
            raise ValueError("Host registry must contain at least one host configuration")

    def get(self, name: str) -> HostConfig:
        try:
            return self._hosts[name]
        except KeyError as exc:  # pragma: no cover - FastAPI handles response conversion
            raise KeyError(f"Unknown host '{name}'") from exc

    def list(self) -> Iterable[HostConfig]:
        return self._hosts.values()


def load_host_registry(config_path: Path) -> HostRegistry:
    """Load host configurations from a YAML file."""
    with config_path.open("r", encoding="utf-8") as handle:
        raw = yaml.safe_load(handle) or {}

    hosts_raw = raw.get("hosts")
    if not hosts_raw:
        raise ValueError("Configuration file must define at least one host under the 'hosts' key")

    config_dir = config_path.parent
    hosts = [HostConfig.from_dict(item, base_path=config_dir) for item in hosts_raw]
    return HostRegistry(hosts)


def resolve_config_path(env_value: Optional[str]) -> Path:
    """Resolve the path to the configuration file."""
    if env_value:
        candidate = Path(env_value).expanduser().resolve(strict=False)
    else:
        candidate = (Path(__file__).resolve().parent.parent / "config" / "hosts.yaml").resolve(strict=False)
    return candidate


__all__ = ["HostConfig", "HostRegistry", "load_host_registry", "resolve_config_path"]
