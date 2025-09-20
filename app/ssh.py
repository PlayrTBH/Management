"""SSH utilities for interacting with remote hosts."""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from io import StringIO
from pathlib import Path
from typing import Callable, Generator, Optional, Sequence

import shlex
import time

import paramiko


class SSHError(RuntimeError):
    """Raised when an SSH operation fails."""


class HostKeyVerificationError(SSHError):
    """Raised when host key verification fails for a remote host."""

    def __init__(self, hostname: str, *, port: int | None = None, suggestion: str | None = None) -> None:
        base = f"Host key verification failed for {hostname}"
        if port is not None:
            base += f":{port}"
        base += "."
        if suggestion:
            base = f"{base} {suggestion}".strip()
        super().__init__(base)
        self.hostname = hostname
        self.port = port
        self.suggestion = suggestion


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
        except paramiko.BadHostKeyException as exc:
            suggestion = (
                "The host key differs from the entry stored in the known hosts file. "
                "Update the stored key or enable \"Allow unknown host keys\" for this hypervisor."
            )
            raise HostKeyVerificationError(
                exc.hostname,
                port=self._target.port,
                suggestion=suggestion,
            ) from exc
        except paramiko.SSHException as exc:
            message = str(exc)
            if "not found in known_hosts" in message:
                host = self._target.hostname
                suggestion = (
                    "Host key verification failed for {host}. "
                    "Add the host to the configured known hosts file or enable "
                    '"Allow unknown host keys" for this hypervisor.'
                )
                raise HostKeyVerificationError(
                    host,
                    port=self._target.port,
                    suggestion=suggestion.format(host=host),
                ) from exc
            raise SSHError(f"SSH connection failed: {message}") from exc
        finally:
            client.close()

    @contextmanager
    def open_shell(
        self,
        *,
        term: str = "xterm-256color",
        width: int = 80,
        height: int = 24,
    ) -> Generator[paramiko.Channel, None, None]:
        """Open an interactive shell channel on the remote host."""

        with self.connect() as client:
            try:
                channel = client.invoke_shell(term=term, width=width, height=height)
            except paramiko.SSHException as exc:
                raise SSHError(f"Failed to open an interactive shell: {exc}") from exc
            try:
                yield channel
            finally:
                try:
                    channel.close()
                except Exception:  # pragma: no cover - best effort shutdown
                    pass


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

    def run_streaming(
        self,
        args: Sequence[str],
        *,
        timeout: int = 60,
        on_stdout: Callable[[str], None] | None = None,
        on_stderr: Callable[[str], None] | None = None,
    ) -> CommandResult:
        """Execute a command while streaming output through callbacks."""

        command = " ".join(shlex.quote(arg) for arg in args)
        with self._factory.connect() as client:
            transport = client.get_transport()
            if transport is None:
                raise SSHError("SSH transport is unavailable for streaming command execution")

            try:
                channel = transport.open_session()
            except paramiko.SSHException as exc:
                raise SSHError(f"Failed to execute remote command '{command}': {exc}") from exc

            channel.settimeout(timeout)

            try:
                channel.exec_command(command)
            except paramiko.SSHException as exc:
                channel.close()
                raise SSHError(f"Failed to execute remote command '{command}': {exc}") from exc

            stdout_chunks: list[str] = []
            stderr_chunks: list[str] = []
            start = time.monotonic()

            try:
                while True:
                    if timeout and time.monotonic() - start > timeout:
                        raise SSHError(
                            f"Remote command '{command}' timed out after {timeout} seconds"
                        )

                    has_data = False

                    if channel.recv_ready():
                        try:
                            data = channel.recv(4096)
                        except paramiko.SSHException as exc:
                            raise SSHError(
                                f"Failed to read stdout from remote command '{command}': {exc}"
                            ) from exc
                        if data:
                            text = data.decode("utf-8", errors="replace")
                            stdout_chunks.append(text)
                            if on_stdout is not None:
                                try:
                                    on_stdout(text)
                                except Exception:
                                    pass
                            has_data = True

                    if channel.recv_stderr_ready():
                        try:
                            data = channel.recv_stderr(4096)
                        except paramiko.SSHException as exc:
                            raise SSHError(
                                f"Failed to read stderr from remote command '{command}': {exc}"
                            ) from exc
                        if data:
                            text = data.decode("utf-8", errors="replace")
                            stderr_chunks.append(text)
                            if on_stderr is not None:
                                try:
                                    on_stderr(text)
                                except Exception:
                                    pass
                            has_data = True

                    if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                        break

                    if not has_data:
                        time.sleep(0.1)

                exit_status = channel.recv_exit_status()
            finally:
                channel.close()

        stdout_text = "".join(stdout_chunks)
        stderr_text = "".join(stderr_chunks)
        return CommandResult(command=args, exit_status=exit_status, stdout=stdout_text, stderr=stderr_text)


__all__ = [
    "SSHError",
    "HostKeyVerificationError",
    "CommandResult",
    "SSHTarget",
    "SSHClientFactory",
    "SSHCommandRunner",
]
