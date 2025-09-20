"""Browser-based management interface for the PlayrServers control plane."""
from __future__ import annotations

import asyncio
import inspect
import json
import logging
import os
import shlex
from contextlib import suppress
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

import anyio
import websockets
from fastapi import FastAPI, Form, Request, WebSocket, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from httpx import URL
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.websockets import WebSocketDisconnect, WebSocketState
from urllib.parse import quote

from .database import Database, resolve_database_path
from .deployments import DeploymentLogManager
from .models import Agent, User
from .qemu import (
    QEMUError,
    QEMUManager,
    build_virsh_command,
    get_vm_deployment_profile,
    get_vm_deployment_profiles,
)
from .ssh import (
    HostKeyVerificationError,
    SSHClientFactory,
    SSHCommandRunner,
    SSHTarget,
    SSHError,
)
from .terminals import send_websocket_json, stream_ssh_channel
from .api_runner import APICommandRunner


TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"

PASSWORD_MIN_LENGTH = 12


logger = logging.getLogger("playrservers.management.deployments")


def _trusted_proxy_hosts() -> list[str] | str:
    raw = os.getenv("MANAGEMENT_TRUSTED_PROXIES")
    if not raw:
        return "*"
    hosts = [item.strip() for item in raw.split(",") if item.strip()]
    return hosts or "*"


def create_app(
    *,
    database: Optional[Database] = None,
    api_base_url: Optional[str] = None,
    session_secret: Optional[str] = None,
    initialize_database: bool = False,
    internal_api_base_url: Optional[str] = None,
    internal_api_verify: str | bool | None = None,
) -> FastAPI:
    """Create the management web application."""

    if database is None:
        db_path = resolve_database_path(os.getenv("MANAGEMENT_DB_PATH"))
        database = Database(db_path)
        database.initialize()
    elif initialize_database:
        database.initialize()

    if session_secret is None:
        session_secret = os.getenv("MANAGEMENT_SESSION_SECRET")
    if not session_secret:
        raise RuntimeError(
            "MANAGEMENT_SESSION_SECRET must be configured to use the management interface"
        )

    if api_base_url is None:
        api_base_url = os.getenv("MANAGEMENT_PUBLIC_API_URL", "https://api.playrservers.com")

    app = FastAPI(
        title="PlayrServers Management Interface",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.add_middleware(ProxyHeadersMiddleware, trusted_hosts=_trusted_proxy_hosts())
    app.state.database = database
    app.state.public_api_url = api_base_url
    app.state.internal_api_base_url = internal_api_base_url
    app.state.internal_api_verify = internal_api_verify
    if not hasattr(app.state, "deployment_logs"):
        app.state.deployment_logs = DeploymentLogManager()

    secure_cookie_setting = os.getenv("MANAGEMENT_SESSION_SECURE")
    if secure_cookie_setting is None:
        secure_cookie = False
    else:
        secure_cookie = secure_cookie_setting.strip().lower() not in {
            "0",
            "false",
            "no",
        }

    app.add_middleware(
        SessionMiddleware,
        secret_key=session_secret,
        session_cookie="playrservers_session",
        https_only=secure_cookie,
        same_site="lax",
        max_age=60 * 60 * 24 * 7,
    )

    templates = Jinja2Templates(directory=str(TEMPLATE_DIR))
    templates.env.globals["api_base_url"] = api_base_url
    templates.env.globals["now"] = datetime.utcnow

    def _flash(request: Request, message: str, *, category: str = "info") -> None:
        messages = request.session.get("flash_messages")
        if not isinstance(messages, list):
            messages = []
        messages.append({"message": message, "category": category})
        request.session["flash_messages"] = messages

    def _consume_flash(request: Request) -> List[Dict[str, str]]:
        messages = request.session.pop("flash_messages", [])
        if isinstance(messages, list):
            return messages
        return []

    def _agent_to_view(agent: Agent) -> Dict[str, object]:
        return {
            "id": agent.id,
            "name": agent.name,
            "hostname": agent.hostname,
            "port": agent.port,
            "username": agent.username,
            "allow_unknown_hosts": agent.allow_unknown_hosts,
            "known_hosts_path": agent.known_hosts_path,
            "created_at": agent.created_at.isoformat(),
        }

    def _fetch_user(user_id: object) -> Optional[User]:
        try:
            numeric_id = int(user_id)
        except (TypeError, ValueError):
            return None
        return database.get_user(numeric_id)

    def _get_current_user(request: Request) -> Optional[User]:
        user_id = request.session.get("user_id")
        if not user_id:
            return None
        user = _fetch_user(user_id)
        if user is None:
            request.session.pop("user_id", None)
        return user

    def _get_current_user_from_session(session) -> Optional[User]:
        if not isinstance(session, dict):
            return None
        user_id = session.get("user_id")
        if not user_id:
            return None
        return _fetch_user(user_id)

    def _resolve_api_base_url() -> str:
        base = getattr(app.state, "public_api_url", "")
        if not isinstance(base, str) or not base.strip():
            raise RuntimeError("Public API URL is not configured")
        return base.strip().rstrip("/")

    def _build_api_http_url(path: str) -> str:
        base = _resolve_api_base_url()
        if not path.startswith("/"):
            path = "/" + path
        return f"{base}{path}"

    def _build_api_websocket_url(path: str) -> str:
        url = URL(_build_api_http_url(path))
        scheme = "wss" if url.scheme == "https" else "ws" if url.scheme == "http" else url.scheme
        return str(url.copy_with(scheme=scheme))

    async def _proxy_api_websocket(
        websocket: WebSocket,
        *,
        path: str,
        user: User,
    ) -> None:
        try:
            api_key = _get_user_api_key(user)
            relay_url = _build_api_websocket_url(path)
        except RuntimeError as exc:
            await websocket.accept()
            await send_websocket_json(
                websocket,
                {"type": "error", "message": str(exc)},
            )
            with suppress(Exception):
                await websocket.close()
            return

        await websocket.accept()

        try:
            async with websockets.connect(
                relay_url,
                extra_headers={"Authorization": f"Bearer {api_key}"},
            ) as remote:
                cancel_exc = anyio.get_cancelled_exc_class()

                async with anyio.create_task_group() as task_group:
                    async def pump_client() -> None:
                        try:
                            while True:
                                message = await websocket.receive()
                                if message["type"] == "websocket.disconnect":
                                    await remote.close()
                                    break
                                data = message.get("bytes")
                                if data is not None:
                                    if data:
                                        await remote.send(data)
                                    continue
                                text = message.get("text")
                                if text is not None:
                                    await remote.send(text)
                        except (WebSocketDisconnect, cancel_exc):
                            pass
                        except Exception:
                            pass
                        finally:
                            task_group.cancel_scope.cancel()

                    async def pump_remote() -> None:
                        try:
                            while True:
                                data = await remote.recv()
                                if isinstance(data, bytes):
                                    if data:
                                        await websocket.send_bytes(data)
                                    else:
                                        await websocket.send_bytes(data)
                                    continue
                                if data is None:
                                    break
                                await websocket.send_text(data)
                        except cancel_exc:
                            pass
                        except websockets.ConnectionClosed:
                            pass
                        except Exception:
                            pass
                        finally:
                            task_group.cancel_scope.cancel()

                    task_group.start_soon(pump_client)
                    task_group.start_soon(pump_remote)
        except websockets.InvalidStatusCode as exc:
            await send_websocket_json(
                websocket,
                {
                    "type": "error",
                    "message": f"SSH relay rejected the connection (status {exc.status_code}).",
                },
            )
        except Exception as exc:
            await send_websocket_json(
                websocket,
                {"type": "error", "message": f"Failed to establish SSH relay: {exc}"},
            )
        finally:
            if websocket.client_state != WebSocketState.DISCONNECTED:
                with suppress(Exception):
                    await websocket.close()

    def _build_target(agent: Agent) -> SSHTarget:
        return SSHTarget(
            hostname=agent.hostname,
            port=agent.port,
            username=agent.username,
            private_key=agent.private_key,
            passphrase=agent.private_key_passphrase,
            allow_unknown_hosts=agent.allow_unknown_hosts,
            known_hosts_path=Path(agent.known_hosts_path).expanduser() if agent.known_hosts_path else None,
        )

    def _get_user_api_key(user: User) -> str:
        api_key = database.get_user_api_key(user.id)
        if not api_key:
            raise RuntimeError(
                "API key not available for this account. Rotate the key from the account page."
            )
        return api_key

    def _api_runner_for(agent: Agent, user: User | None) -> APICommandRunner:
        if user is None:
            raise RuntimeError("User context required for API-backed SSH runner")

        api_key = _get_user_api_key(user)

        internal_base = getattr(app.state, "internal_api_base_url", None)
        verify = getattr(app.state, "internal_api_verify", None)
        base_url = internal_base or _resolve_api_base_url()

        return APICommandRunner(
            base_url,
            api_key,
            agent_id=agent.id,
            hostname=agent.hostname,
            port=agent.port,
            verify=verify if internal_base else None,
        )

    def _build_ssh_runner(agent: Agent, *, user: User | None = None) -> SSHCommandRunner:
        override = getattr(app.state, "ssh_runner_factory", None)
        if callable(override):
            try:
                runner = override(agent, user=user)
            except TypeError:
                runner = override(agent)
            if runner is None:
                raise RuntimeError("SSH runner override must return a runner instance")
            return runner

        if user is not None:
            return _api_runner_for(agent, user)

        target = _build_target(agent)
        factory = SSHClientFactory(target)
        return SSHCommandRunner(factory)

    def _build_ssh_terminal(agent: Agent):
        override = getattr(app.state, "ssh_terminal_factory", None)
        if callable(override):
            terminal = override(agent)
            if terminal is None:
                raise RuntimeError("SSH terminal override must return a context manager")
            return terminal

        target = _build_target(agent)
        factory = SSHClientFactory(target)
        return factory.open_shell()

    def _build_qemu_manager(agent: Agent, *, user: User | None = None) -> QEMUManager:
        override = getattr(app.state, "qemu_manager_factory", None)
        if callable(override):
            try:
                manager = override(agent, user=user)
            except TypeError:
                manager = override(agent)
            if manager is None:
                raise RuntimeError("QEMU manager override must return a manager instance")
            return manager

        runner = _build_ssh_runner(agent, user=user)
        return QEMUManager(runner)

    def _get_deployment_logs() -> DeploymentLogManager:
        manager = getattr(app.state, "deployment_logs", None)
        if manager is None:
            manager = DeploymentLogManager()
            app.state.deployment_logs = manager
        return manager

    def _schedule_background_task(coro) -> None:
        runner = getattr(app.state, "deployment_task_runner", None)
        if callable(runner):
            try:
                result = runner(coro)
            except Exception:
                logger.exception("Deployment task runner failed to schedule coroutine")
                return
            if inspect.isawaitable(result):
                asyncio.create_task(result)
            return

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            asyncio.run(coro)
        else:
            loop.create_task(coro)

    def _command_result_payload(result) -> Dict[str, object]:
        return {
            "command": list(result.command),
            "exit_status": result.exit_status,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }

    def _parse_dominfo(stdout: str) -> Dict[str, str]:
        data: Dict[str, str] = {}
        for line in stdout.splitlines():
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            data[key.strip()] = value.strip()
        return data

    def _parse_loadavg(stdout: str) -> Optional[Dict[str, float]]:
        parts = stdout.strip().split()
        if len(parts) < 3:
            return None
        try:
            return {
                "one": float(parts[0]),
                "five": float(parts[1]),
                "fifteen": float(parts[2]),
            }
        except ValueError:
            return None

    def _parse_free(stdout: str) -> Optional[Dict[str, object]]:
        lines = [line.strip() for line in stdout.splitlines() if line.strip()]
        if len(lines) < 2:
            return None

        header_parts = lines[0].split()
        mem_line: Optional[List[str]] = None
        for line in lines[1:]:
            if line.lower().startswith("mem:"):
                mem_line = line.split()
                break

        if mem_line is None:
            return None

        values = mem_line[1:]
        keys = header_parts
        if len(keys) > len(values):
            keys = keys[-len(values):]
        elif len(values) > len(keys):
            values = values[: len(keys)]
        stats: Dict[str, int] = {}
        for key, value in zip(keys, values):
            cleaned_key = (
                key.strip()
                .lower()
                .replace("/", "_")
                .replace("-", "_")
                .replace("(", "")
                .replace(")", "")
            )
            try:
                stats[cleaned_key] = int(value)
            except ValueError:
                continue

        total = stats.get("total")
        used = stats.get("used")
        free_value = stats.get("free")
        available = stats.get("available")

        usage_percent: Optional[float] = None
        if total and used is not None and total > 0:
            usage_percent = round((used / total) * 100, 2)

        return {
            "raw": stats,
            "total_bytes": total,
            "used_bytes": used,
            "free_bytes": free_value,
            "available_bytes": available,
            "usage_percent": usage_percent,
        }

    def _handle_api_key_rotation(request: Request, user: User) -> RedirectResponse:
        refreshed, api_key = database.rotate_api_key(user.id)
        request.session["flash_api_key"] = api_key
        request.session["user_id"] = refreshed.id
        _flash(request, "Issued a new API key.", category="success")
        return RedirectResponse(
            request.url_for("account"),
            status_code=status.HTTP_303_SEE_OTHER,
        )

    def _redirect_to_login(request: Request) -> RedirectResponse:
        return RedirectResponse(
            request.url_for("show_login"),
            status_code=status.HTTP_303_SEE_OTHER,
        )

    @app.get("/", response_class=HTMLResponse)
    async def root(request: Request):
        user = _get_current_user(request)
        if user is None:
            return RedirectResponse(
                request.url_for("show_login"),
                status_code=status.HTTP_303_SEE_OTHER,
            )
        return RedirectResponse(
            request.url_for("dashboard"),
            status_code=status.HTTP_303_SEE_OTHER,
        )

    @app.get("/login", response_class=HTMLResponse, name="show_login")
    async def login_form(request: Request):
        user = _get_current_user(request)
        if user is not None:
            return RedirectResponse(
                request.url_for("dashboard"),
                status_code=status.HTTP_303_SEE_OTHER,
            )
        error = request.session.pop("login_error", None)
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": error},
        )

    @app.post("/login", name="process_login")
    async def process_login(request: Request, email: str = Form(...), password: str = Form(...)):
        user = database.authenticate_user(email, password)
        if user is None:
            request.session["login_error"] = "Invalid email or password."
            return RedirectResponse(
                request.url_for("show_login"),
                status_code=status.HTTP_303_SEE_OTHER,
            )

        request.session.clear()
        request.session["user_id"] = user.id
        return RedirectResponse(
            request.url_for("dashboard"),
            status_code=status.HTTP_303_SEE_OTHER,
        )

    @app.get("/logout", name="logout")
    async def logout(request: Request):
        request.session.clear()
        return RedirectResponse(
            request.url_for("show_login"),
            status_code=status.HTTP_303_SEE_OTHER,
        )

    @app.get("/dashboard", response_class=HTMLResponse, name="dashboard")
    async def dashboard(request: Request):
        user = _get_current_user(request)
        if user is None:
            return _redirect_to_login(request)
        return templates.TemplateResponse(
            "dashboard.html",
            {
                "request": request,
                "user": user,
            },
        )

    @app.get("/account", response_class=HTMLResponse, name="account")
    async def account(request: Request):
        user = _get_current_user(request)
        if user is None:
            return _redirect_to_login(request)
        messages = _consume_flash(request)
        generated = request.session.pop("flash_api_key", None)
        revealed = request.session.pop("revealed_api_key", None)
        return templates.TemplateResponse(
            "account.html",
            {
                "request": request,
                "user": user,
                "messages": messages,
                "generated_api_key": generated,
                "revealed_api_key": revealed,
                "password_min_length": PASSWORD_MIN_LENGTH,
            },
        )

    @app.post("/account/profile", name="update_profile")
    async def update_profile(request: Request, name: str = Form(...), email: str = Form("")):
        user = _get_current_user(request)
        if user is None:
            return _redirect_to_login(request)

        cleaned_name = name.strip()
        cleaned_email = email.strip()

        try:
            updated = database.update_user_profile(
                user.id,
                name=cleaned_name,
                email=cleaned_email or None,
            )
        except ValueError as exc:
            _flash(request, str(exc), category="error")
            return RedirectResponse(
                request.url_for("account"),
                status_code=status.HTTP_303_SEE_OTHER,
            )

        _flash(request, "Account details updated.", category="success")
        request.session["user_id"] = updated.id
        return RedirectResponse(
            request.url_for("account"),
            status_code=status.HTTP_303_SEE_OTHER,
        )

    @app.post("/account/password", name="change_password")
    async def change_password(
        request: Request,
        current_password: str = Form(...),
        new_password: str = Form(...),
        confirm_password: str = Form(...),
    ):
        user = _get_current_user(request)
        if user is None:
            return _redirect_to_login(request)

        errors: List[str] = []
        if len(new_password) < PASSWORD_MIN_LENGTH:
            errors.append(
                f"New password must be at least {PASSWORD_MIN_LENGTH} characters long."
            )
        if new_password != confirm_password:
            errors.append("New password and confirmation do not match.")
        if not database.verify_user_password(user.id, current_password):
            errors.append("Current password is incorrect.")

        if errors:
            for message in errors:
                _flash(request, message, category="error")
            return RedirectResponse(
                request.url_for("account"),
                status_code=status.HTTP_303_SEE_OTHER,
            )

        database.set_user_password(user.id, new_password)
        _flash(request, "Password updated successfully.", category="success")
        return RedirectResponse(
            request.url_for("account"),
            status_code=status.HTTP_303_SEE_OTHER,
        )

    @app.post("/account/api-key/rotate", name="rotate_api_key")
    async def rotate_api_key(request: Request):
        user = _get_current_user(request)
        if user is None:
            return _redirect_to_login(request)
        return _handle_api_key_rotation(request, user)

    @app.post("/account/api-key/reveal", name="reveal_api_key")
    async def reveal_api_key(request: Request, password: str = Form(...)):
        user = _get_current_user(request)
        if user is None:
            return _redirect_to_login(request)

        if not database.verify_user_password(user.id, password):
            _flash(request, "Password is incorrect.", category="error")
            return RedirectResponse(
                request.url_for("account"),
                status_code=status.HTTP_303_SEE_OTHER,
            )

        try:
            api_key = database.get_user_api_key(user.id)
        except (RuntimeError, ValueError) as exc:
            _flash(request, str(exc), category="error")
            return RedirectResponse(
                request.url_for("account"),
                status_code=status.HTTP_303_SEE_OTHER,
            )

        if not api_key:
            _flash(
                request,
                "No API key is available to reveal. Rotate the credential to generate a new secret.",
                category="error",
            )
            return RedirectResponse(
                request.url_for("account"),
                status_code=status.HTTP_303_SEE_OTHER,
            )

        request.session["revealed_api_key"] = api_key
        _flash(
            request,
            "API key revealed below. Keep this secret safe and rotate it if exposure is suspected.",
            category="warning",
        )
        return RedirectResponse(
            request.url_for("account"),
            status_code=status.HTTP_303_SEE_OTHER,
        )

    @app.post("/api-key/rotate")
    async def legacy_rotate_api_key(request: Request):
        user = _get_current_user(request)
        if user is None:
            return _redirect_to_login(request)
        return _handle_api_key_rotation(request, user)

    @app.get("/api-key", response_class=HTMLResponse, name="api_key")
    async def api_key(request: Request):
        user = _get_current_user(request)
        if user is None:
            return _redirect_to_login(request)
        return RedirectResponse(
            request.url_for("account"),
            status_code=status.HTTP_303_SEE_OTHER,
        )

    @app.get("/management", response_class=HTMLResponse, name="management")
    async def management(request: Request):
        user = _get_current_user(request)
        if user is None:
            return _redirect_to_login(request)

        agents = database.list_agents_for_user(user.id)
        agent_views = [_agent_to_view(agent) for agent in agents]
        for entry in agent_views:
            entry["remove_url"] = request.app.url_path_for(
                "remove_agent", agent_id=entry["id"]
            )
        selected_agent: Optional[Dict[str, object]] = None

        selected_param = request.query_params.get("agent")
        selected_id: Optional[int] = None
        if selected_param:
            try:
                selected_id = int(selected_param)
            except ValueError:
                selected_id = None

        if selected_id is not None:
            for entry in agent_views:
                if entry["id"] == selected_id:
                    selected_agent = entry
                    break

        if selected_agent is None and agent_views:
            selected_agent = agent_views[0]

        messages = _consume_flash(request)

        endpoints = {
            "list_vms": request.app.url_path_for(
                "management_list_vms", agent_id=0
            ),
            "vm_info": request.app.url_path_for(
                "management_vm_info", agent_id=0, vm_name="__VM__"
            ),
            "vm_action": request.app.url_path_for(
                "management_vm_action",
                agent_id=0,
                vm_name="__VM__",
                action="__ACTION__",
            ),
            "host_info": request.app.url_path_for(
                "management_host_info", agent_id=0
            ),
            "ssh_terminal": request.app.url_path_for(
                "management_agent_terminal", agent_id=0
            ),
            "allow_unknown_hosts": request.app.url_path_for(
                "management_allow_unknown_hosts", agent_id=0
            ),
            "deploy_vm": request.app.url_path_for(
                "management_deploy_vm", agent_id=0
            ),
            "vm_console": request.app.url_path_for(
                "management_vm_console", agent_id=0, vm_name="__VM__"
            ),
            "deployment_logs": request.app.url_path_for(
                "management_list_deployments"
            ),
            "deployment_detail": request.app.url_path_for(
                "management_get_deployment", deployment_id="__DEPLOYMENT__"
            ),
        }

        deployment_profiles = [
            profile.to_public_dict() for profile in get_vm_deployment_profiles()
        ]

        return templates.TemplateResponse(
            "management.html",
            {
                "request": request,
                "user": user,
                "agents": agent_views,
                "selected_agent": selected_agent,
                "messages": messages,
                "endpoints": endpoints,
                "deployment_profiles": deployment_profiles,
            },
        )

    @app.post("/management/agents/{agent_id}/delete", name="remove_agent")
    async def remove_agent(request: Request, agent_id: int):
        user = _get_current_user(request)
        if user is None:
            return _redirect_to_login(request)

        agent = database.get_agent_for_user(user.id, agent_id)
        if agent is None:
            _flash(request, "Hypervisor not found.", category="error")
            return RedirectResponse(
                request.url_for("management"),
                status_code=status.HTTP_303_SEE_OTHER,
            )

        database.delete_agent(user.id, agent_id)
        _flash(request, f"Removed hypervisor '{agent.name}'.", category="success")
        return RedirectResponse(
            request.url_for("management"),
            status_code=status.HTTP_303_SEE_OTHER,
        )

    def _json_auth_error() -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"status": "error", "message": "Authentication required."},
        )

    def _json_agent_missing() -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"status": "error", "message": "Hypervisor not found."},
        )

    @app.get("/management/agents/{agent_id}/vms")
    async def management_list_vms(request: Request, agent_id: int):
        user = _get_current_user(request)
        if user is None:
            return _json_auth_error()

        agent = database.get_agent_for_user(user.id, agent_id)
        if agent is None:
            return _json_agent_missing()

        try:
            manager = _build_qemu_manager(agent, user=user)
        except RuntimeError as exc:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"status": "error", "message": str(exc)},
            )
        try:
            vms = manager.list_vms()
        except HostKeyVerificationError as exc:
            return JSONResponse(
                status_code=status.HTTP_502_BAD_GATEWAY,
                content={
                    "status": "error",
                    "message": str(exc),
                    "code": "host_key_verification_failed",
                    "hostname": exc.hostname,
                    "port": exc.port or agent.port,
                },
            )
        except (QEMUError, SSHError) as exc:
            return JSONResponse(
                status_code=status.HTTP_502_BAD_GATEWAY,
                content={"status": "error", "message": str(exc)},
            )

        return JSONResponse(
            content={
                "status": "ok",
                "vms": [
                    {"name": vm.name, "state": vm.state, "id": vm.id}
                    for vm in vms
                ],
            }
        )

    @app.get("/management/agents/{agent_id}/vms/{vm_name}")
    async def management_vm_info(request: Request, agent_id: int, vm_name: str):
        user = _get_current_user(request)
        if user is None:
            return _json_auth_error()

        agent = database.get_agent_for_user(user.id, agent_id)
        if agent is None:
            return _json_agent_missing()

        try:
            manager = _build_qemu_manager(agent, user=user)
        except RuntimeError as exc:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"status": "error", "message": str(exc)},
            )
        try:
            result = manager.get_vm_info(vm_name)
        except HostKeyVerificationError as exc:
            return JSONResponse(
                status_code=status.HTTP_502_BAD_GATEWAY,
                content={
                    "status": "error",
                    "message": str(exc),
                    "code": "host_key_verification_failed",
                    "hostname": exc.hostname,
                    "port": exc.port or agent.port,
                },
            )
        except (QEMUError, SSHError) as exc:
            return JSONResponse(
                status_code=status.HTTP_502_BAD_GATEWAY,
                content={"status": "error", "message": str(exc)},
            )

        return JSONResponse(
            content={
                "status": "ok",
                "dominfo": _parse_dominfo(result.stdout),
                "raw": _command_result_payload(result),
            }
        )

    @app.post("/management/agents/{agent_id}/vms/{vm_name}/{action}")
    async def management_vm_action(request: Request, agent_id: int, vm_name: str, action: str):
        user = _get_current_user(request)
        if user is None:
            return _json_auth_error()

        agent = database.get_agent_for_user(user.id, agent_id)
        if agent is None:
            return _json_agent_missing()

        try:
            manager = _build_qemu_manager(agent, user=user)
        except RuntimeError as exc:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"status": "error", "message": str(exc)},
            )
        operations = {
            "start": manager.start_vm,
            "shutdown": manager.shutdown_vm,
            "force-stop": manager.force_stop_vm,
            "reboot": manager.reboot_vm,
            "destroy": manager.destroy_vm,
        }
        operation = operations.get(action)
        if operation is None:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"status": "error", "message": "Unsupported action."},
            )

        try:
            result = operation(vm_name)
        except HostKeyVerificationError as exc:
            return JSONResponse(
                status_code=status.HTTP_502_BAD_GATEWAY,
                content={
                    "status": "error",
                    "message": str(exc),
                    "code": "host_key_verification_failed",
                    "hostname": exc.hostname,
                    "port": exc.port or agent.port,
                },
            )
        except (QEMUError, SSHError) as exc:
            return JSONResponse(
                status_code=status.HTTP_502_BAD_GATEWAY,
                content={"status": "error", "message": str(exc)},
            )

        return JSONResponse(
            content={
                "status": "ok",
                "message": f"Dispatched {action} for '{vm_name}'.",
                "result": _command_result_payload(result),
            }
        )

    @app.post("/management/agents/{agent_id}/deployments", name="management_deploy_vm")
    async def management_deploy_vm(request: Request, agent_id: int):
        user = _get_current_user(request)
        if user is None:
            return _json_auth_error()

        agent = database.get_agent_for_user(user.id, agent_id)
        if agent is None:
            return _json_agent_missing()

        try:
            payload = await request.json()
        except Exception:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"status": "error", "message": "Invalid JSON payload."},
            )

        if not isinstance(payload, dict):
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"status": "error", "message": "Invalid request payload."},
            )

        profile_id = str(payload.get("profile_id") or "").strip()
        vm_name = str(payload.get("vm_name") or "").strip()
        memory_mb = payload.get("memory_mb")
        vcpus = payload.get("vcpus")
        disk_gb = payload.get("disk_gb")
        username = payload.get("username")
        password = payload.get("password")

        profile = get_vm_deployment_profile(profile_id)
        if profile is None:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"status": "error", "message": "Unknown deployment profile."},
            )

        try:
            resolved_username, resolved_password = profile.resolve_credentials(username, password)
        except ValueError as exc:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"status": "error", "message": str(exc)},
            )

        def _resolve(value, default):
            if value is None:
                return default
            if isinstance(value, str):
                stripped = value.strip()
                if not stripped:
                    return default
                value = stripped
            return int(value)

        try:
            resolved_memory = _resolve(memory_mb, profile.default_memory_mb)
            resolved_vcpus = _resolve(vcpus, profile.default_vcpus)
            resolved_disk = _resolve(disk_gb, profile.default_disk_gb)
        except (TypeError, ValueError):
            resolved_memory = profile.default_memory_mb
            resolved_vcpus = profile.default_vcpus
            resolved_disk = profile.default_disk_gb

        deployment_logs = _get_deployment_logs()
        record = deployment_logs.create(
            user_id=user.id,
            agent_id=agent.id,
            agent_name=agent.name,
            vm_name=vm_name,
            profile_id=profile.id,
            profile_name=profile.name,
            parameters={
                "memory_mb": resolved_memory,
                "vcpus": resolved_vcpus,
                "disk_gb": resolved_disk,
            },
        )
        deployment_logs.append_message(
            record.id,
            "info",
            f"Deployment queued on {agent.name} ({agent.hostname}).",
        )

        try:
            manager = _build_qemu_manager(agent, user=user)
        except RuntimeError as exc:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"status": "error", "message": str(exc)},
            )

        async def run_deployment_task():
            deployment_logs.mark_running(record.id)
            deployment_logs.append_message(
                record.id,
                "info",
                f"Starting deployment for '{vm_name}' using profile '{profile.name}'.",
            )

            def handle_stdout(chunk: str) -> None:
                deployment_logs.append_stream(record.id, "stdout", chunk)

            def handle_stderr(chunk: str) -> None:
                deployment_logs.append_stream(record.id, "stderr", chunk)

            def _deploy_vm_sync():
                return manager.deploy_vm(
                    profile.id,
                    vm_name,
                    memory_mb=resolved_memory,
                    vcpus=resolved_vcpus,
                    disk_gb=resolved_disk,
                    username=resolved_username,
                    password=resolved_password,
                    stream_stdout=handle_stdout,
                    stream_stderr=handle_stderr,
                )

            try:
                result = await anyio.to_thread.run_sync(
                    _deploy_vm_sync,
                    abandon_on_cancel=True,
                )
            except ValueError as exc:
                deployment_logs.mark_failed(record.id, str(exc))
            except HostKeyVerificationError as exc:
                deployment_logs.mark_failed(record.id, str(exc))
            except QEMUError as exc:
                command_result = getattr(exc, "result", None)
                log_message = str(exc)
                if command_result is not None:
                    payload = _command_result_payload(command_result)
                    log_message = (
                        f"{log_message} "
                        f"(exit_status={payload['exit_status']}, "
                        f"stdout={payload['stdout']!r}, "
                        f"stderr={payload['stderr']!r})"
                    )

                logger.error(
                    "VM deployment failed for '%s' on agent '%s' (id=%d, %s@%s:%s) using profile '%s': %s",
                    vm_name,
                    agent.name,
                    agent.id,
                    agent.username,
                    agent.hostname,
                    agent.port,
                    profile.id,
                    log_message,
                )
                deployment_logs.mark_failed(record.id, str(exc), command_result)
            except SSHError as exc:
                deployment_logs.mark_failed(record.id, str(exc))
            except Exception:
                logger.exception(
                    "Unhandled exception during deployment for '%s' on agent '%s' (id=%d)",
                    vm_name,
                    agent.name,
                    agent.id,
                )
                deployment_logs.mark_failed(
                    record.id,
                    "Deployment failed due to an unexpected error.",
                )
            else:
                deployment_logs.mark_success(record.id, result)

        _schedule_background_task(run_deployment_task())

        response_payload = {
            "status": "ok",
            "message": f"Deployment for '{vm_name}' queued on {agent.name}.",
            "deployment_id": record.id,
            "profile": profile.to_public_dict(),
            "parameters": {
                "memory_mb": resolved_memory,
                "vcpus": resolved_vcpus,
                "disk_gb": resolved_disk,
            },
            "credentials": {
                "username": resolved_username,
                "password": resolved_password,
            },
        }

        return JSONResponse(
            status_code=status.HTTP_202_ACCEPTED,
            content=response_payload,
        )

    @app.get("/management/deployments", name="management_list_deployments")
    async def management_list_deployments(request: Request):
        user = _get_current_user(request)
        if user is None:
            return _json_auth_error()

        deployments = _get_deployment_logs().list_for_user(user.id)
        return JSONResponse(
            content={"status": "ok", "deployments": deployments}
        )

    @app.get(
        "/management/deployments/{deployment_id}",
        name="management_get_deployment",
    )
    async def management_get_deployment(
        request: Request, deployment_id: str
    ):
        user = _get_current_user(request)
        if user is None:
            return _json_auth_error()

        after_param = request.query_params.get("after")
        after_sequence: Optional[int] = None
        if after_param is not None:
            try:
                after_sequence = int(after_param)
            except (TypeError, ValueError):
                return JSONResponse(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    content={
                        "status": "error",
                        "message": "Invalid 'after' parameter.",
                    },
                )
            if after_sequence < 0:
                after_sequence = None

        deployment = _get_deployment_logs().get_for_user(
            user.id, deployment_id, after=after_sequence
        )
        if deployment is None:
            return JSONResponse(
                status_code=status.HTTP_404_NOT_FOUND,
                content={"status": "error", "message": "Deployment not found."},
            )

        return JSONResponse(
            content={"status": "ok", "deployment": deployment}
        )

    @app.websocket("/management/agents/{agent_id}/terminal", name="management_agent_terminal")
    async def management_agent_terminal(websocket: WebSocket, agent_id: int):
        user = _get_current_user_from_session(websocket.session)
        if user is None:
            await websocket.close(code=4401)
            return

        agent = database.get_agent_for_user(user.id, agent_id)
        if agent is None:
            await websocket.close(code=4404)
            return

        override = getattr(app.state, "ssh_terminal_factory", None)
        if callable(override):
            try:
                terminal = override(agent, user=user)
            except TypeError:
                terminal = override(agent)
            if terminal is None:
                await websocket.accept()
                await send_websocket_json(
                    websocket,
                    {
                        "type": "error",
                        "message": "SSH terminal override must return a context manager.",
                    },
                )
                with suppress(Exception):
                    await websocket.close()
                return

            await websocket.accept()

            try:
                with terminal as channel:
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
            return

        await _proxy_api_websocket(
            websocket,
            path=f"/agents/{agent.id}/terminal",
            user=user,
        )

    @app.websocket(
        "/management/agents/{agent_id}/vms/{vm_name}/console",
        name="management_vm_console",
    )
    async def management_vm_console(websocket: WebSocket, agent_id: int, vm_name: str):
        user = _get_current_user_from_session(websocket.session)
        if user is None:
            await websocket.close(code=4401)
            return

        agent = database.get_agent_for_user(user.id, agent_id)
        if agent is None:
            await websocket.close(code=4404)
            return

        cleaned_vm_name = vm_name.strip()
        if not cleaned_vm_name:
            await websocket.close(code=4404)
            return

        override = getattr(app.state, "ssh_terminal_factory", None)
        if callable(override):
            try:
                terminal = override(agent, user=user)
            except TypeError:
                terminal = override(agent)
            if terminal is None:
                await websocket.accept()
                await send_websocket_json(
                    websocket,
                    {
                        "type": "error",
                        "message": "SSH terminal override must return a context manager.",
                    },
                )
                with suppress(Exception):
                    await websocket.close()
                return

            await websocket.accept()

            try:
                with terminal as channel:
                    command = f"virsh console --force {shlex.quote(cleaned_vm_name)}\n"
                    await anyio.to_thread.run_sync(
                        channel.send, command.encode("utf-8")
                    )

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
                    websocket, {"type": "error", "message": str(exc)}
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
            return

        ws_path = f"/agents/{agent.id}/vms/{quote(cleaned_vm_name, safe='')}/console"
        await _proxy_api_websocket(websocket, path=ws_path, user=user)

    @app.post(
        "/management/agents/{agent_id}/allow-unknown-hosts",
        name="management_allow_unknown_hosts",
    )
    async def management_allow_unknown_hosts(request: Request, agent_id: int):
        user = _get_current_user(request)
        if user is None:
            return _json_auth_error()

        agent = database.get_agent_for_user(user.id, agent_id)
        if agent is None:
            return _json_agent_missing()

        if agent.allow_unknown_hosts:
            return JSONResponse(
                content={
                    "status": "ok",
                    "message": "Unknown host keys are already allowed for this hypervisor.",
                    "agent": _agent_to_view(agent),
                }
            )

        updated = database.update_agent(
            user.id,
            agent_id,
            allow_unknown_hosts=True,
        )
        if updated is None:
            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={
                    "status": "error",
                    "message": "Failed to update hypervisor settings.",
                },
            )

        return JSONResponse(
            content={
                "status": "ok",
                "message": "Unknown host keys will now be accepted for this hypervisor.",
                "agent": _agent_to_view(updated),
            }
        )

    @app.get("/management/agents/{agent_id}/host-info")
    async def management_host_info(request: Request, agent_id: int):
        user = _get_current_user(request)
        if user is None:
            return _json_auth_error()

        agent = database.get_agent_for_user(user.id, agent_id)
        if agent is None:
            return _json_agent_missing()

        try:
            runner = _build_ssh_runner(agent, user=user)
        except RuntimeError as exc:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"status": "error", "message": str(exc)},
            )

        try:
            nodeinfo_result = runner.run(build_virsh_command("nodeinfo"))
        except HostKeyVerificationError as exc:
            return JSONResponse(
                status_code=status.HTTP_502_BAD_GATEWAY,
                content={
                    "status": "error",
                    "message": str(exc),
                    "code": "host_key_verification_failed",
                    "hostname": exc.hostname,
                    "port": exc.port or agent.port,
                },
            )
        except SSHError as exc:
            return JSONResponse(
                status_code=status.HTTP_502_BAD_GATEWAY,
                content={"status": "error", "message": str(exc)},
            )

        if nodeinfo_result.exit_status != 0:
            return JSONResponse(
                status_code=status.HTTP_502_BAD_GATEWAY,
                content={
                    "status": "error",
                    "message": "Failed to collect host diagnostics via virsh.",
                    "result": _command_result_payload(nodeinfo_result),
                },
            )

        nodeinfo = _parse_dominfo(nodeinfo_result.stdout)

        warnings: List[str] = []
        raw_outputs: Dict[str, Dict[str, object]] = {
            "nodeinfo": _command_result_payload(nodeinfo_result),
        }

        kernel = None
        try:
            kernel_result = runner.run(["uname", "-sr"])
        except SSHError:
            kernel_result = None

        if kernel_result is not None:
            raw_outputs["kernel"] = _command_result_payload(kernel_result)
            if kernel_result.exit_status == 0:
                kernel = kernel_result.stdout.strip() or None
            else:
                warnings.append("Unable to determine kernel version from remote host.")
        else:
            warnings.append("Unable to determine kernel version from remote host.")

        load_average = None
        try:
            load_result = runner.run(["cat", "/proc/loadavg"])
        except SSHError:
            load_result = None

        if load_result is not None:
            raw_outputs["loadavg"] = _command_result_payload(load_result)
            if load_result.exit_status == 0:
                load_average = _parse_loadavg(load_result.stdout)
                if load_average is None:
                    warnings.append("Received unexpected load average data from remote host.")
            else:
                warnings.append("Unable to read load averages from remote host.")
        else:
            warnings.append("Unable to read load averages from remote host.")

        memory_stats = None
        try:
            memory_result = runner.run(["free", "-b"])
        except SSHError:
            memory_result = None

        if memory_result is not None:
            raw_outputs["memory"] = _command_result_payload(memory_result)
            if memory_result.exit_status == 0:
                memory_stats = _parse_free(memory_result.stdout)
                if memory_stats is None:
                    warnings.append(
                        "Received unexpected memory statistics from remote host."
                    )
            else:
                warnings.append("Unable to read memory statistics from remote host.")
        else:
            warnings.append("Unable to read memory statistics from remote host.")

        timestamp = datetime.utcnow().isoformat() + "Z"

        payload: Dict[str, object] = {
            "status": "ok",
            "collected_at": timestamp,
            "system": {
                "hostname": agent.hostname,
                "username": agent.username,
                "kernel": kernel,
            },
            "nodeinfo": nodeinfo,
            "performance": {
                "load_average": load_average,
                "memory": memory_stats,
            },
        }

        cleaned_warnings = [message for message in warnings if message]
        if cleaned_warnings:
            payload["warnings"] = cleaned_warnings

        payload["raw"] = raw_outputs

        return JSONResponse(content=payload)

    return app


__all__ = ["create_app"]
