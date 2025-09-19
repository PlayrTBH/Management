"""SSH utilities for interacting with remote hosts."""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Generator, Sequence

import shlex

import paramiko

from .config import HostConfig


class SSHError(RuntimeError):
    """Raised when an SSH operation fails."""


@dataclass
class CommandResult:
    """Result of an executed SSH command."""

    command: Sequence[str]
    exit_status: int
    stdout: str
    stderr: str


def _load_private_key(path: Path, passphrase: str | None) -> paramiko.PKey:
    exceptions: list[Exception] = []
    for key_cls in (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey, paramiko.DSSKey):
        try:
            return key_cls.from_private_key_file(str(path), password=passphrase)
        except FileNotFoundError as exc:
            raise SSHError(f"Private key file not found: {path}") from exc
        except paramiko.PasswordRequiredException as exc:
            raise SSHError("The private key is encrypted and requires a passphrase") from exc
        except paramiko.SSHException as exc:
            exceptions.append(exc)
    raise SSHError("Unable to load private key - unsupported format or invalid passphrase")


class SSHClientFactory:
    """Factory that builds SSH clients using host configuration."""

    def __init__(self, host_config: HostConfig) -> None:
        self._config = host_config

    @contextmanager
    def connect(self) -> Generator[paramiko.SSHClient, None, None]:
        client = paramiko.SSHClient()
        if self._config.known_hosts_file:
            client.load_host_keys(str(self._config.known_hosts_file))
        else:
            client.load_system_host_keys()

        if self._config.allow_unknown_hosts:
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        else:
            client.set_missing_host_key_policy(paramiko.RejectPolicy())

        pkey = _load_private_key(self._config.private_key_path, self._config.passphrase)
        try:
            client.connect(
                hostname=self._config.hostname,
                port=self._config.port,
                username=self._config.username,
                pkey=pkey,
                timeout=20,
                look_for_keys=False,
                allow_agent=False,
            )
            yield client
        except paramiko.AuthenticationException as exc:
            raise SSHError("Authentication with the remote host failed") from exc
        except paramiko.SSHException as exc:
            raise SSHError(f"SSH connection failed: {exc}") from exc
        finally:
            client.close()


class SSHCommandRunner:
    """Executes commands on a remote host over SSH."""

    def __init__(self, factory: SSHClientFactory) -> None:
        self._factory = factory

    def run(self, args: Sequence[str], timeout: int = 60) -> CommandResult:
        command = " ".join(shlex.quote(arg) for arg in args)
        with self._factory.connect() as client:
            try:
                stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
            except paramiko.SSHException as exc:
                raise SSHError(f"Failed to execute remote command '{command}': {exc}") from exc

            stdout_text = stdout.read().decode("utf-8", errors="replace")
            stderr_text = stderr.read().decode("utf-8", errors="replace")
            exit_status = stdout.channel.recv_exit_status()

        return CommandResult(command=args, exit_status=exit_status, stdout=stdout_text, stderr=stderr_text)


__all__ = ["SSHError", "CommandResult", "SSHClientFactory", "SSHCommandRunner"]
