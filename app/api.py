"""FastAPI application that exposes virtualization management endpoints."""
from __future__ import annotations

import os
from contextlib import suppress
import shlex
from contextlib import suppress
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set

import anyio
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request, Response, WebSocket, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator, model_validator
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware
from starlette.websockets import WebSocketState

from .agent_registration import (
    AgentProvisioningError,
    AgentProvisioningSettings,
    load_agent_provisioning_settings,
)
from .database import Database, resolve_database_path
from .models import Agent, User
from .qemu import QEMUError, QEMUManager
from .security import APIKeyAuth
from .ssh import (
    CommandResult,
    HostKeyVerificationError,
    SSHClientFactory,
    SSHCommandRunner,
    SSHTarget,
    SSHError,
)
from .terminals import send_websocket_json, stream_ssh_channel


class UserResponse(BaseModel):
    id: int
    name: str
    email: Optional[str]
    api_key_prefix: str
    created_at: datetime


class RotateAPIKeyResponse(BaseModel):
    api_key: str
    api_key_prefix: str


class UpdateAgentRequest(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=100)
    hostname: Optional[str] = Field(default=None, min_length=1, max_length=255)
    port: Optional[int] = Field(default=None, ge=1, le=65535)
    username: Optional[str] = Field(default=None, min_length=1, max_length=64)
    private_key: Optional[str] = Field(default=None, min_length=40)
    private_key_passphrase: Optional[str] = Field(default=None, max_length=255)
    allow_unknown_hosts: Optional[bool] = None
    known_hosts_path: Optional[str] = Field(default=None, max_length=1024)


class AgentResponse(BaseModel):
    id: int
    name: str
    hostname: str
    port: int
    username: str
    allow_unknown_hosts: bool
    known_hosts_path: Optional[str]
    created_at: datetime


class AccountProfileResponse(BaseModel):
    username: Optional[str] = Field(default=None, max_length=64)
    authorized_keys: List[str] = Field(..., min_length=1)


class AgentConnectRequest(BaseModel):
    hostname: Optional[str] = Field(default=None, max_length=255)
    ip_address: Optional[str] = Field(default=None, max_length=255)
    username: str = Field(..., min_length=1, max_length=64)
    authorized_keys: List[str] = Field(..., min_length=1)
    metadata: Dict[str, object] = Field(default_factory=dict)

    class Config:
        extra = "allow"

    @field_validator("username")
    @classmethod
    def _normalize_username(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("username must not be empty")
        return stripped

    @field_validator("authorized_keys", mode="before")
    @classmethod
    def _normalise_authorized_keys(cls, value: object) -> List[str]:
        if value is None:
            raise ValueError("authorized_keys must not be empty")
        if isinstance(value, str):
            value = [value]
        if not isinstance(value, list):
            raise ValueError("authorized_keys must be provided as a list of strings")
        normalised: List[str] = []
        seen: Set[str] = set()
        for item in value:
            if not isinstance(item, str):
                raise ValueError("authorized_keys must contain only strings")
            stripped = item.strip()
            if not stripped or stripped in seen:
                continue
            normalised.append(stripped)
            seen.add(stripped)
        if not normalised:
            raise ValueError("authorized_keys must not be empty")
        return normalised

    @staticmethod
    def _normalize(value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        stripped = value.strip()
        return stripped or None

    def resolved_hostname(self) -> Optional[str]:
        for candidate in (self.ip_address, self.hostname):
            normalized = self._normalize(candidate)
            if normalized:
                return normalized
        return None

    def resolved_name(self) -> Optional[str]:
        return self._normalize(self.hostname) or self.resolved_hostname()


class AgentConnectResponse(BaseModel):
    agent_id: int
    name: str
    hostname: str
    port: int
    username: str
    authorized_keys: List[str]
    close_other_sessions: bool


class AgentCommandPayload(BaseModel):
    id: int
    command: str = Field(..., min_length=1)


class AgentCommandListResponse(BaseModel):
    commands: List[AgentCommandPayload]


class AgentCommandReplyRequest(BaseModel):
    data: Dict[str, object] = Field(default_factory=dict)
    metadata: Dict[str, object] = Field(default_factory=dict)
    stdout: Optional[str] = None
    stderr: Optional[str] = None
    exit_status: Optional[int] = None

    @model_validator(mode="after")
    def _ensure_non_empty(self):  # type: ignore[override]
        if (
            not self.data
            and not self.metadata
            and self.stdout is None
            and self.stderr is None
            and self.exit_status is None
        ):
            raise ValueError("Reply payload must include at least one field")
        return self


class AgentCommandReplyPayload(BaseModel):
    id: int
    command_id: int
    created_at: datetime
    data: Dict[str, object] = Field(default_factory=dict)


class AgentCommandReplyListResponse(BaseModel):
    replies: List[AgentCommandReplyPayload]


class RunSSHCommandRequest(BaseModel):
    command: List[str] = Field(..., min_length=1)
    timeout: Optional[int] = Field(default=60, ge=1, le=3600)

    @field_validator("command")
    @classmethod
    def _normalize_command(cls, value: List[str]) -> List[str]:
        normalized: List[str] = []
        for part in value:
            if not isinstance(part, str):
                raise ValueError("command must be a list of strings")
            stripped = part.strip()
            normalized.append(stripped)
        return normalized

def command_result_to_dict(result: CommandResult) -> Dict[str, object]:
    return {
        "command": list(result.command),
        "exit_status": result.exit_status,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def parse_dominfo(stdout: str) -> Dict[str, str]:
    data: Dict[str, str] = {}
    for line in stdout.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        data[key.strip()] = value.strip()
    return data


def user_to_response(user: User) -> UserResponse:
    return UserResponse(
        id=user.id,
        name=user.name,
        email=user.email,
        api_key_prefix=user.api_key_prefix,
        created_at=user.created_at,
    )


def agent_to_response(agent: Agent) -> AgentResponse:
    return AgentResponse(
        id=agent.id,
        name=agent.name,
        hostname=agent.hostname,
        port=agent.port,
        username=agent.username,
        allow_unknown_hosts=agent.allow_unknown_hosts,
        known_hosts_path=agent.known_hosts_path,
        created_at=agent.created_at,
    )


def agent_to_target(agent: Agent) -> SSHTarget:
    known_hosts_path: Optional[Path] = None
    if agent.known_hosts_path:
        known_hosts_path = Path(agent.known_hosts_path).expanduser().resolve(strict=False)
    return SSHTarget(
        hostname=agent.hostname,
        port=agent.port,
        username=agent.username,
        private_key=agent.private_key,
        passphrase=agent.private_key_passphrase,
        allow_unknown_hosts=agent.allow_unknown_hosts,
        known_hosts_path=known_hosts_path,
    )


def _trusted_proxy_hosts() -> list[str] | str:
    raw = os.getenv("MANAGEMENT_TRUSTED_PROXIES")
    if not raw:
        return "*"
    hosts = [item.strip() for item in raw.split(",") if item.strip()]
    return hosts or "*"


def create_app(
    *,
    database: Database | None = None,
    auth: APIKeyAuth | None = None,
    initialize_database: bool = False,
    agent_settings: AgentProvisioningSettings | None = None,
) -> FastAPI:
    if database is None:
        db_path = resolve_database_path(os.getenv("MANAGEMENT_DB_PATH"))
        database = Database(db_path)
        database.initialize()
    elif initialize_database:
        database.initialize()

    if auth is None:
        auth = APIKeyAuth(database)

    if agent_settings is None:
        agent_settings = load_agent_provisioning_settings()

    app = FastAPI(
        title="PlayrServers QEMU Manager",
        description="Secure API for managing remote QEMU hypervisors over SSH",
        version="2.0.0",
    )
    app.add_middleware(ProxyHeadersMiddleware, trusted_hosts=_trusted_proxy_hosts())
    app.state.database = database

    def _authenticate_websocket(websocket: WebSocket) -> tuple[User | None, int | None]:
        header = websocket.headers.get("authorization")
        if not header:
            return None, 4401
        parts = header.strip().split(" ", 1)
        if len(parts) != 2 or parts[0].lower() != "bearer":
            return None, 4401
        token = parts[1].strip()
        if not token:
            return None, 4401
        user = database.get_user_by_api_key(token)
        if user is None:
            return None, 4403
        return user, None

    def _build_ssh_terminal(agent: Agent):
        override = getattr(app.state, "ssh_terminal_factory", None)
        if callable(override):
            terminal = override(agent)
            if terminal is None:
                raise RuntimeError("SSH terminal override must return a context manager")
            return terminal
        factory = SSHClientFactory(agent_to_target(agent))
        return factory.open_shell()

    def get_db() -> Database:
        return database

    async def get_current_user(request: Request) -> User:
        return await auth(request)

    def get_agent(agent_id: int, current_user: User = Depends(get_current_user), db: Database = Depends(get_db)) -> Agent:
        agent = db.get_agent_for_user(current_user.id, agent_id)
        if agent is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")
        return agent

    def get_qemu_manager(agent: Agent = Depends(get_agent)) -> QEMUManager:
        target = agent_to_target(agent)
        factory = SSHClientFactory(target)
        runner = SSHCommandRunner(factory)
        return QEMUManager(runner)

    @app.get("/health")
    async def healthcheck() -> Dict[str, str]:
        return {"status": "ok"}

    @app.get("/users/me", response_model=UserResponse)
    async def read_current_user(current_user: User = Depends(get_current_user)) -> UserResponse:
        return user_to_response(current_user)

    @app.get("/v1/account/profile", response_model=AccountProfileResponse)
    async def read_account_profile(
        current_user: User = Depends(get_current_user),
        db: Database = Depends(get_db),
    ) -> AccountProfileResponse:
        try:
            key_pair = db.ensure_user_provisioning_keys(current_user.id)
        except AgentProvisioningError as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=str(exc),
            ) from exc

        return AccountProfileResponse(
            username=agent_settings.username,
            authorized_keys=[key_pair.public_key],
        )

    @app.post(
        "/users/me/api-key/rotate",
        response_model=RotateAPIKeyResponse,
        name="api_rotate_api_key",
    )
    async def rotate_api_key(current_user: User = Depends(get_current_user), db: Database = Depends(get_db)) -> RotateAPIKeyResponse:
        refreshed, api_key = db.rotate_api_key(current_user.id)
        return RotateAPIKeyResponse(api_key=api_key, api_key_prefix=refreshed.api_key_prefix)

    protected_router = APIRouter()

    @protected_router.get("/agents", response_model=List[AgentResponse])
    async def list_agents(current_user: User = Depends(get_current_user), db: Database = Depends(get_db)) -> List[AgentResponse]:
        agents = db.list_agents_for_user(current_user.id)
        return [agent_to_response(agent) for agent in agents]

    @protected_router.get("/agents/{agent_id}", response_model=AgentResponse)
    async def read_agent(agent: Agent = Depends(get_agent)) -> AgentResponse:
        return agent_to_response(agent)

    @protected_router.post("/agents/{agent_id}/ssh/command")
    async def run_ssh_command(
        payload: RunSSHCommandRequest,
        agent: Agent = Depends(get_agent),
    ) -> Dict[str, object]:
        target = agent_to_target(agent)
        runner = SSHCommandRunner(SSHClientFactory(target))
        timeout = payload.timeout or 60
        try:
            result = runner.run(payload.command, timeout=timeout)
        except HostKeyVerificationError as exc:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail={
                    "message": str(exc),
                    "code": "host_key_verification_failed",
                    "hostname": exc.hostname,
                    "port": exc.port or agent.port,
                    "suggestion": exc.suggestion,
                },
            ) from exc
        except SSHError as exc:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=str(exc),
            ) from exc

        return command_result_to_dict(result)

    @protected_router.post("/v1/servers/connect", response_model=AgentConnectResponse)
    async def register_server(
        payload: AgentConnectRequest,
        current_user: User = Depends(get_current_user),
        db: Database = Depends(get_db),
    ) -> AgentConnectResponse:
        hostname = payload.resolved_hostname()
        if not hostname:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Request must include a hostname or ip_address",
            )

        name = payload.resolved_name()
        if name is None:
            name = hostname

        configured_username = agent_settings.username.strip() if agent_settings.username else ""
        resolved_username = configured_username or payload.username

        try:
            key_pair = db.ensure_user_provisioning_keys(current_user.id)
        except AgentProvisioningError as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=str(exc),
            ) from exc

        private_key = key_pair.private_key
        authorized_keys = [key_pair.public_key]

        existing = db.find_agent_by_hostname(current_user.id, hostname)
        if existing is None and name:
            existing = db.find_agent_by_name(current_user.id, name)
        desired_known_hosts = agent_settings.known_hosts_as_string()

        if existing is None:
            agent = db.create_agent(
                current_user.id,
                name=name,
                hostname=hostname,
                port=agent_settings.port,
                username=resolved_username,
                private_key=private_key,
                private_key_passphrase=None,
                allow_unknown_hosts=agent_settings.allow_unknown_hosts,
                known_hosts_path=desired_known_hosts,
            )
        else:
            updates: Dict[str, object] = {}
            if existing.name != name:
                updates["name"] = name
            if existing.hostname != hostname:
                updates["hostname"] = hostname
            if existing.port != agent_settings.port:
                updates["port"] = agent_settings.port
            if existing.username != resolved_username:
                updates["username"] = resolved_username
            if existing.private_key != private_key:
                updates["private_key"] = private_key
            if existing.private_key_passphrase is not None:
                updates["private_key_passphrase"] = None
            if existing.allow_unknown_hosts != agent_settings.allow_unknown_hosts:
                updates["allow_unknown_hosts"] = agent_settings.allow_unknown_hosts
            if existing.known_hosts_path != desired_known_hosts:
                updates["known_hosts_path"] = desired_known_hosts

            if updates:
                agent = db.update_agent(current_user.id, existing.id, **updates)
                if agent is None:  # pragma: no cover - defensive guard
                    raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        detail="Failed to update agent during registration",
                    )
            else:
                agent = existing

        return AgentConnectResponse(
            agent_id=agent.id,
            name=agent.name,
            hostname=agent.hostname,
            port=agent.port,
            username=agent.username,
            authorized_keys=authorized_keys,
            close_other_sessions=agent_settings.close_other_sessions,
        )

    @protected_router.get(
        "/v1/servers/commands",
        response_model=AgentCommandListResponse,
    )
    async def fetch_pending_commands(
        current_user: User = Depends(get_current_user),
        db: Database = Depends(get_db),
    ) -> AgentCommandListResponse:
        commands = db.list_pending_agent_commands(current_user.id)
        command_ids = [command.id for command in commands]
        if command_ids:
            db.mark_agent_commands_dispatched(current_user.id, command_ids)
        return AgentCommandListResponse(
            commands=[
                AgentCommandPayload(id=command.id, command=command.command)
                for command in commands
            ]
        )

    @protected_router.get(
        "/v1/servers/commands/replies",
        response_model=AgentCommandReplyListResponse,
    )
    async def fetch_command_replies(
        current_user: User = Depends(get_current_user),
        db: Database = Depends(get_db),
    ) -> AgentCommandReplyListResponse:
        replies = db.list_pending_agent_command_replies(current_user.id)
        reply_ids = [reply.id for reply in replies]
        if reply_ids:
            db.mark_agent_command_replies_acknowledged(current_user.id, reply_ids)
        return AgentCommandReplyListResponse(
            replies=[
                AgentCommandReplyPayload(
                    id=reply.id,
                    command_id=reply.command_id,
                    created_at=reply.created_at,
                    data=reply.data,
                )
                for reply in replies
            ]
        )

    @protected_router.post(
        "/v1/servers/commands/{command_id}/reply",
        response_model=AgentCommandReplyPayload,
        status_code=status.HTTP_201_CREATED,
    )
    async def submit_command_reply(
        command_id: int,
        payload: AgentCommandReplyRequest,
        current_user: User = Depends(get_current_user),
        db: Database = Depends(get_db),
    ) -> AgentCommandReplyPayload:
        cleaned: Dict[str, object] = {}
        for key, value in payload.model_dump().items():
            if value is None:
                continue
            if isinstance(value, dict) and not value:
                continue
            cleaned[key] = value

        try:
            reply = db.record_agent_command_reply(current_user.id, command_id, cleaned)
        except ValueError as exc:
            message = str(exc)
            if message == "Command not found":
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=message,
                ) from exc
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=message,
            ) from exc

        return AgentCommandReplyPayload(
            id=reply.id,
            command_id=reply.command_id,
            created_at=reply.created_at,
            data=reply.data,
        )

    @protected_router.patch("/agents/{agent_id}", response_model=AgentResponse)
    async def update_agent(
        agent_id: int,
        payload: UpdateAgentRequest,
        current_user: User = Depends(get_current_user),
        db: Database = Depends(get_db),
    ) -> AgentResponse:
        updates = payload.dict(exclude_unset=True)
        sanitized: Dict[str, object] = {}
        for key, value in updates.items():
            if isinstance(value, str):
                value = value.strip()
            if key in {"private_key_passphrase", "known_hosts_path"} and value == "":
                value = None
            if value is None and key not in {"private_key_passphrase", "known_hosts_path"}:
                continue
            sanitized[key] = value
        updated = db.update_agent(current_user.id, agent_id, **sanitized)
        if updated is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")
        return agent_to_response(updated)

    @protected_router.delete("/agents/{agent_id}", status_code=status.HTTP_204_NO_CONTENT)
    async def delete_agent(
        agent_id: int,
        current_user: User = Depends(get_current_user),
        db: Database = Depends(get_db),
    ) -> Response:
        deleted = db.delete_agent(current_user.id, agent_id)
        if not deleted:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    @protected_router.get("/agents/{agent_id}/vms")
    async def list_host_vms(manager: QEMUManager = Depends(get_qemu_manager)) -> List[Dict[str, object]]:
        return [{"name": vm.name, "state": vm.state, "id": vm.id} for vm in manager.list_vms()]

    @protected_router.get("/agents/{agent_id}/vms/{vm_name}")
    async def get_vm_info(vm_name: str, manager: QEMUManager = Depends(get_qemu_manager)) -> Dict[str, object]:
        result = manager.get_vm_info(vm_name)
        return {"dominfo": parse_dominfo(result.stdout), "raw": command_result_to_dict(result)}

    @protected_router.post("/agents/{agent_id}/vms/{vm_name}/start")
    async def start_vm(vm_name: str, manager: QEMUManager = Depends(get_qemu_manager)) -> Dict[str, object]:
        result = manager.start_vm(vm_name)
        return command_result_to_dict(result)

    @protected_router.post("/agents/{agent_id}/vms/{vm_name}/shutdown")
    async def shutdown_vm(vm_name: str, manager: QEMUManager = Depends(get_qemu_manager)) -> Dict[str, object]:
        result = manager.shutdown_vm(vm_name)
        return command_result_to_dict(result)

    @protected_router.post("/agents/{agent_id}/vms/{vm_name}/force-stop")
    async def force_stop_vm(vm_name: str, manager: QEMUManager = Depends(get_qemu_manager)) -> Dict[str, object]:
        result = manager.force_stop_vm(vm_name)
        return command_result_to_dict(result)

    @protected_router.post("/agents/{agent_id}/vms/{vm_name}/reboot")
    async def reboot_vm(vm_name: str, manager: QEMUManager = Depends(get_qemu_manager)) -> Dict[str, object]:
        result = manager.reboot_vm(vm_name)
        return command_result_to_dict(result)

    @app.websocket("/agents/{agent_id}/terminal")
    async def agent_terminal(websocket: WebSocket, agent_id: int):
        user, error_code = _authenticate_websocket(websocket)
        if user is None:
            await websocket.close(code=error_code or 4401)
            return

        agent = database.get_agent_for_user(user.id, agent_id)
        if agent is None:
            await websocket.close(code=4404)
            return

        await websocket.accept()

        try:
            with _build_ssh_terminal(agent) as channel:
                await send_websocket_json(
                    websocket,
                    {"type": "status", "status": "connected"},
                )
                await stream_ssh_channel(websocket, channel)
        except HostKeyVerificationError as exc:
            await send_websocket_json(
                websocket,
                {
                    "type": "error",
                    "message": str(exc),
                    "code": "host_key_verification_failed",
                },
            )
        except (SSHError, RuntimeError) as exc:
            await send_websocket_json(
                websocket, {"type": "error", "message": str(exc)}
            )
        except Exception:
            await send_websocket_json(
                websocket,
                {
                    "type": "error",
                    "message": "SSH session terminated unexpectedly.",
                },
            )
        finally:
            if websocket.client_state != WebSocketState.DISCONNECTED:
                with suppress(Exception):
                    await websocket.close()

    @app.websocket("/agents/{agent_id}/vms/{vm_name}/console")
    async def agent_vm_console(websocket: WebSocket, agent_id: int, vm_name: str):
        user, error_code = _authenticate_websocket(websocket)
        if user is None:
            await websocket.close(code=error_code or 4401)
            return

        agent = database.get_agent_for_user(user.id, agent_id)
        if agent is None:
            await websocket.close(code=4404)
            return

        cleaned_vm_name = vm_name.strip()
        if not cleaned_vm_name:
            await websocket.close(code=4404)
            return

        await websocket.accept()

        try:
            with _build_ssh_terminal(agent) as channel:
                command = f"virsh console --force {shlex.quote(cleaned_vm_name)}\n"
                await anyio.to_thread.run_sync(channel.send, command.encode("utf-8"))

                async def detach_console():
                    with suppress(Exception):
                        await anyio.to_thread.run_sync(channel.send, b"\x1d\n")
                        await anyio.to_thread.run_sync(channel.send, b"exit\n")

                await send_websocket_json(
                    websocket,
                    {"type": "status", "status": "connected", "vm": cleaned_vm_name},
                )
                await stream_ssh_channel(websocket, channel, on_close=detach_console)
        except HostKeyVerificationError as exc:
            await send_websocket_json(
                websocket,
                {
                    "type": "error",
                    "message": str(exc),
                    "code": "host_key_verification_failed",
                },
            )
        except (SSHError, RuntimeError) as exc:
            await send_websocket_json(
                websocket,
                {"type": "error", "message": str(exc)},
            )
        except Exception:
            await send_websocket_json(
                websocket,
                {
                    "type": "error",
                    "message": "Console session terminated unexpectedly.",
                },
            )
        finally:
            if websocket.client_state != WebSocketState.DISCONNECTED:
                with suppress(Exception):
                    await websocket.close()

    app.include_router(protected_router)

    @app.exception_handler(QEMUError)
    async def handle_qemu_error(_: object, exc: QEMUError):
        payload: Dict[str, object] = {"detail": str(exc)}
        if exc.result is not None:
            payload["command"] = command_result_to_dict(exc.result)
        return JSONResponse(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content=payload)

    @app.exception_handler(SSHError)
    async def handle_ssh_error(_: object, exc: SSHError):
        return JSONResponse(status_code=status.HTTP_502_BAD_GATEWAY, content={"detail": str(exc)})

    return app


app = create_app()


__all__ = ["app", "create_app"]
