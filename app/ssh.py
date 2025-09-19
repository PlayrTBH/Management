"""SSH utilities for interacting with remote hosts."""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from io import StringIO
from pathlib import Path
from typing import Generator, Optional, Sequence

import shlex

import paramiko


class SSHError(RuntimeError):
    """Raised when an SSH operation fails."""


@dataclass
class CommandResult:
    """Result of an executed SSH command."""

    command: Sequence[str]
    exit_status: int
    stdout: str
    stderr: str


@dataclass
class SSHTarget:
    """Connection parameters for a remote host."""

    hostname: str
    port: int
    username: str
    private_key: str
    passphrase: Optional[str] = None
    allow_unknown_hosts: bool = False
    known_hosts_path: Optional[Path] = None


def _load_private_key(private_key: str, passphrase: str | None) -> paramiko.PKey:
    key_classes = (
        paramiko.Ed25519Key,
        paramiko.ECDSAKey,
        paramiko.RSAKey,
        paramiko.DSSKey,
    )
    cleaned = private_key.strip()

    if "-----BEGIN" in cleaned:
        last_error: Exception | None = None
        for key_cls in key_classes:
            stream = StringIO(cleaned)
            try:
                return key_cls.from_private_key(stream, password=passphrase)
            except paramiko.PasswordRequiredException as exc:
                raise SSHError("The private key is encrypted and requires a passphrase") from exc
            except paramiko.SSHException as exc:
                last_error = exc
        if last_error is None:
            raise SSHError("Unable to load private key - unsupported format or invalid passphrase")
        raise SSHError("Unable to load private key - unsupported format or invalid passphrase") from last_error

    path = Path(cleaned)
    exceptions: list[Exception] = []
    for key_cls in key_classes:
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

    def __init__(self, target: SSHTarget) -> None:
        self._target = target

    @contextmanager
    def connect(self) -> Generator[paramiko.SSHClient, None, None]:
        client = paramiko.SSHClient()
        if self._target.known_hosts_path:
            client.load_host_keys(str(self._target.known_hosts_path))
        else:
            client.load_system_host_keys()

        if self._target.allow_unknown_hosts:
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        else:
            client.set_missing_host_key_policy(paramiko.RejectPolicy())

        pkey = _load_private_key(self._target.private_key, self._target.passphrase)
        try:
            client.connect(
                hostname=self._target.hostname,
                port=self._target.port,
                username=self._target.username,
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


__all__ = ["SSHError", "CommandResult", "SSHTarget", "SSHClientFactory", "SSHCommandRunner"]
