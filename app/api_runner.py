"""HTTP-backed SSH command runner for interacting with the management API."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

import httpx

from .ssh import CommandResult, HostKeyVerificationError, SSHError


@dataclass
class _RunnerConfig:
    base_url: str
    api_key: str
    agent_id: int
    hostname: str
    port: int
    timeout: float


def _normalize_base_url(base_url: str) -> str:
    cleaned = (base_url or "").strip()
    if not cleaned:
        raise ValueError("API base URL must not be empty")
    return cleaned.rstrip("/")


def _build_endpoint(base_url: str, path: str) -> str:
    if not path.startswith("/"):
        path = "/" + path
    return f"{base_url}{path}"


def _extract_error_message(payload: object, default: str) -> str:
    if isinstance(payload, dict):
        for key in ("message", "detail", "error"):
            value = payload.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    if isinstance(payload, str) and payload.strip():
        return payload.strip()
    return default


class APICommandRunner:
    """Execute SSH commands by delegating to the management API."""

    def __init__(
        self,
        base_url: str,
        api_key: str,
        *,
        agent_id: int,
        hostname: str,
        port: int,
        timeout: float = 30.0,
    ) -> None:
        self._config = _RunnerConfig(
            base_url=_normalize_base_url(base_url),
            api_key=api_key.strip(),
            agent_id=agent_id,
            hostname=hostname,
            port=port,
            timeout=timeout,
        )
        if not self._config.api_key:
            raise ValueError("API key must not be empty when using APICommandRunner")

    def run(self, args: Sequence[str], timeout: int = 60) -> CommandResult:
        command = [str(part) for part in args]
        if not command:
            raise SSHError("SSH command must not be empty")

        url = _build_endpoint(
            self._config.base_url,
            f"/agents/{self._config.agent_id}/ssh/command",
        )

        headers = {"Authorization": f"Bearer {self._config.api_key}"}
        payload = {"command": command, "timeout": timeout}

        try:
            response = httpx.post(
                url,
                json=payload,
                headers=headers,
                timeout=self._config.timeout,
            )
        except httpx.RequestError as exc:  # pragma: no cover - network failure
            raise SSHError(f"Failed to contact SSH relay API: {exc}") from exc

        if response.status_code >= 400:
            message = f"SSH relay API request failed with status {response.status_code}"
            detail_payload: object | None = None
            try:
                parsed = response.json()
            except ValueError:
                parsed = None

            if isinstance(parsed, dict):
                detail = parsed.get("detail")
                if isinstance(detail, dict):
                    code = detail.get("code")
                    if code == "host_key_verification_failed":
                        hostname = detail.get("hostname") or self._config.hostname
                        port = detail.get("port") or self._config.port
                        suggestion = detail.get("suggestion")
                        raise HostKeyVerificationError(
                            hostname,
                            port=port,
                            suggestion=suggestion,
                        )
                    detail_payload = detail
                    message = _extract_error_message(detail, message)
                else:
                    detail_payload = parsed
                    message = _extract_error_message(parsed, message)
            elif parsed is not None:
                detail_payload = parsed
                message = _extract_error_message(parsed, message)

            if response.status_code == 401:
                raise SSHError("Authentication with the SSH relay API failed")
            if response.status_code == 403:
                raise SSHError("The SSH relay API denied access to this hypervisor")
            if response.status_code == 404:
                raise SSHError("Hypervisor not found in the SSH relay API")

            raise SSHError(message)

        try:
            data = response.json()
        except ValueError as exc:
            raise SSHError("SSH relay API returned an invalid response") from exc

        if not isinstance(data, dict):
            raise SSHError("SSH relay API returned an unexpected response payload")

        try:
            command_result = data["command"]
            exit_status = int(data["exit_status"])
            stdout = str(data.get("stdout", ""))
            stderr = str(data.get("stderr", ""))
        except (KeyError, TypeError, ValueError) as exc:
            raise SSHError("SSH relay API response was missing required fields") from exc

        if not isinstance(command_result, (list, tuple)):
            raise SSHError("SSH relay API returned an invalid command description")

        normalized_command = [str(part) for part in command_result]

        return CommandResult(
            command=tuple(normalized_command),
            exit_status=exit_status,
            stdout=stdout,
            stderr=stderr,
        )


__all__ = ["APICommandRunner"]

