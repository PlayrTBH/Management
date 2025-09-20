"""Browser-based management interface for the PlayrServers control plane."""
from __future__ import annotations

import inspect
import json
import os
import shlex
from contextlib import suppress
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

import anyio
from fastapi import FastAPI, Form, Request, WebSocket, WebSocketDisconnect, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from starlette.websockets import WebSocketState

from .database import Database, resolve_database_path
from .models import Agent, User
from .qemu import (
    QEMUError,
    QEMUManager,
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


TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"

PASSWORD_MIN_LENGTH = 12


def create_app(
    *,
    database: Optional[Database] = None,
    api_base_url: Optional[str] = None,
    session_secret: Optional[str] = None,
    initialize_database: bool = False,
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
    app.state.database = database
    app.state.public_api_url = api_base_url

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

    def _build_ssh_runner(agent: Agent) -> SSHCommandRunner:
        override = getattr(app.state, "ssh_runner_factory", None)
        if callable(override):
            runner = override(agent)
            if runner is None:
                raise RuntimeError("SSH runner override must return a runner instance")
            return runner

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

    def _build_qemu_manager(agent: Agent) -> QEMUManager:
        override = getattr(app.state, "qemu_manager_factory", None)
        if callable(override):
            manager = override(agent)
            if manager is None:
                raise RuntimeError("QEMU manager override must return a manager instance")
            return manager

        runner = _build_ssh_runner(agent)
        return QEMUManager(runner)

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
        return templates.TemplateResponse(
            "account.html",
            {
                "request": request,
                "user": user,
                "messages": messages,
                "generated_api_key": generated,
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
            entry["remove_url"] = str(
                request.url_for("remove_agent", agent_id=entry["id"])
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
            "list_vms": str(
                request.url_for("management_list_vms", agent_id=0)
            ),
            "vm_info": str(
                request.url_for(
                    "management_vm_info", agent_id=0, vm_name="__VM__"
                )
            ),
            "vm_action": str(
                request.url_for(
                    "management_vm_action",
                    agent_id=0,
                    vm_name="__VM__",
                    action="__ACTION__",
                )
            ),
            "host_info": str(
                request.url_for("management_host_info", agent_id=0)
            ),
            "ssh_terminal": str(
                request.url_for("management_agent_terminal", agent_id=0)
            ),
            "allow_unknown_hosts": str(
                request.url_for("management_allow_unknown_hosts", agent_id=0)
            ),
            "deploy_vm": str(
                request.url_for("management_deploy_vm", agent_id=0)
            ),
            "vm_console": str(
                request.url_for(
                    "management_vm_console", agent_id=0, vm_name="__VM__"
                )
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

    @app.post("/management/agents", name="register_agent")
    async def register_agent(
        request: Request,
        name: str = Form(...),
        hostname: str = Form(...),
        port: str = Form("22"),
        username: str = Form(...),
        private_key: str = Form(...),
        private_key_passphrase: str = Form(""),
        allow_unknown_hosts: Optional[str] = Form(None),
        known_hosts_path: str = Form(""),
    ):
        user = _get_current_user(request)
        if user is None:
            return _redirect_to_login(request)

        errors: List[str] = []
        cleaned_name = name.strip()
        cleaned_hostname = hostname.strip()
        cleaned_username = username.strip()
        cleaned_key = private_key.strip()
        cleaned_passphrase = private_key_passphrase.strip()
        cleaned_known_hosts = known_hosts_path.strip()
        port_value = 22

        if not cleaned_name:
            errors.append("Hypervisor name is required.")
        if not cleaned_hostname:
            errors.append("Hostname or IP address is required.")
        try:
            port_value = int(port)
            if not (1 <= port_value <= 65535):
                errors.append("Port must be between 1 and 65535.")
        except ValueError:
            errors.append("Port must be a valid integer.")
        if not cleaned_username:
            errors.append("SSH username is required.")
        if not cleaned_key:
            errors.append("An SSH private key is required.")

        if errors:
            for message in errors:
                _flash(request, message, category="error")
            return RedirectResponse(
                request.url_for("management"),
                status_code=status.HTTP_303_SEE_OTHER,
            )

        try:
            agent = database.create_agent(
                user.id,
                name=cleaned_name,
                hostname=cleaned_hostname,
                port=port_value,
                username=cleaned_username,
                private_key=cleaned_key,
                private_key_passphrase=cleaned_passphrase or None,
                allow_unknown_hosts=bool(allow_unknown_hosts),
                known_hosts_path=cleaned_known_hosts or None,
            )
        except ValueError as exc:
            _flash(request, str(exc), category="error")
            return RedirectResponse(
                request.url_for("management"),
                status_code=status.HTTP_303_SEE_OTHER,
            )

        _flash(request, f"Added hypervisor '{agent.name}'.", category="success")
        return RedirectResponse(
            f"{request.url_for('management')}?agent={agent.id}",
            status_code=status.HTTP_303_SEE_OTHER,
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

    async def _send_websocket_json(websocket: WebSocket, payload: Dict[str, object]) -> None:
        if websocket.client_state == WebSocketState.DISCONNECTED:
            return
        with suppress(Exception):
            await websocket.send_json(payload)

    async def _stream_ssh_channel(websocket: WebSocket, channel, *, on_close=None) -> None:
        cancel_exc = anyio.get_cancelled_exc_class()
        closed = False

        async def cleanup() -> None:
            nonlocal closed
            if closed:
                return
            closed = True
            if on_close is not None:
                try:
                    result = on_close()
                    if inspect.isawaitable(result):
                        await result
                except Exception:
                    pass
            with suppress(Exception):
                await anyio.to_thread.run_sync(channel.close)
            with suppress(Exception):
                if websocket.application_state != WebSocketState.DISCONNECTED:
                    await websocket.close()

        async def pump_ssh_to_websocket(task_group) -> None:
            try:
                while True:
                    data = await anyio.to_thread.run_sync(
                        channel.recv,
                        4096,
                        abandon_on_cancel=True,
                    )
                    if not data:
                        break
                    try:
                        await websocket.send_bytes(data)
                    except Exception:
                        break
            except cancel_exc:
                pass
            except Exception:
                pass
            finally:
                task_group.cancel_scope.cancel()
                await cleanup()

        async def pump_websocket_to_ssh(task_group) -> None:
            try:
                while True:
                    message = await websocket.receive()
                    if message["type"] == "websocket.disconnect":
                        break
                    data = message.get("bytes")
                    if data is not None:
                        if data:
                            with suppress(Exception):
                                await anyio.to_thread.run_sync(channel.send, data)
                        continue
                    text = message.get("text")
                    if text is None:
                        continue
                    try:
                        payload = json.loads(text)
                    except json.JSONDecodeError:
                        encoded = text.encode("utf-8", errors="ignore")
                        if encoded:
                            with suppress(Exception):
                                await anyio.to_thread.run_sync(channel.send, encoded)
                        continue
                    message_type = payload.get("type")
                    if message_type == "resize":
                        cols = payload.get("cols")
                        rows = payload.get("rows")
                        try:
                            width = int(cols) if cols else 0
                        except (TypeError, ValueError):
                            width = 0
                        try:
                            height = int(rows) if rows else 0
                        except (TypeError, ValueError):
                            height = 0
                        width = width if width > 0 else 80
                        height = height if height > 0 else 24
                        with suppress(Exception):
                            await anyio.to_thread.run_sync(channel.resize_pty, width, height)
                        continue
                    if message_type == "close":
                        break
            except (WebSocketDisconnect, cancel_exc):
                pass
            except Exception:
                pass
            finally:
                task_group.cancel_scope.cancel()
                await cleanup()

        async with anyio.create_task_group() as task_group:
            task_group.start_soon(pump_ssh_to_websocket, task_group)
            task_group.start_soon(pump_websocket_to_ssh, task_group)

    @app.get("/management/agents/{agent_id}/vms")
    async def management_list_vms(request: Request, agent_id: int):
        user = _get_current_user(request)
        if user is None:
            return _json_auth_error()

        agent = database.get_agent_for_user(user.id, agent_id)
        if agent is None:
            return _json_agent_missing()

        manager = _build_qemu_manager(agent)
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

        manager = _build_qemu_manager(agent)
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

        manager = _build_qemu_manager(agent)
        operations = {
            "start": manager.start_vm,
            "shutdown": manager.shutdown_vm,
            "force-stop": manager.force_stop_vm,
            "reboot": manager.reboot_vm,
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

        manager = _build_qemu_manager(agent)

        try:
            result = manager.deploy_vm(
                profile.id,
                vm_name,
                memory_mb=memory_mb,
                vcpus=vcpus,
                disk_gb=disk_gb,
                username=resolved_username,
                password=resolved_password,
            )
        except ValueError as exc:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"status": "error", "message": str(exc)},
            )
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
        except QEMUError as exc:
            error_payload: Dict[str, object] = {"status": "error", "message": str(exc)}
            if getattr(exc, "result", None) is not None:
                error_payload["result"] = _command_result_payload(exc.result)
            return JSONResponse(
                status_code=status.HTTP_502_BAD_GATEWAY,
                content=error_payload,
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

        response_payload = {
            "status": "ok",
            "message": f"Deployment for '{vm_name}' started on {agent.name}.",
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
            "result": _command_result_payload(result),
        }

        return JSONResponse(content=response_payload)

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

        await websocket.accept()

        try:
            with _build_ssh_terminal(agent) as channel:
                await _send_websocket_json(
                    websocket,
                    {"type": "status", "status": "connected"},
                )
                await _stream_ssh_channel(websocket, channel)
        except HostKeyVerificationError as exc:
            await _send_websocket_json(
                websocket,
                {
                    "type": "error",
                    "message": str(exc),
                    "code": "host_key_verification_failed",
                },
            )
        except (SSHError, RuntimeError) as exc:
            await _send_websocket_json(websocket, {"type": "error", "message": str(exc)})
        except Exception:
            await _send_websocket_json(
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

        await websocket.accept()

        try:
            with _build_ssh_terminal(agent) as channel:
                command = f"virsh console --force {shlex.quote(cleaned_vm_name)}\n"
                await anyio.to_thread.run_sync(channel.send, command.encode("utf-8"))

                async def detach_console():
                    with suppress(Exception):
                        await anyio.to_thread.run_sync(channel.send, b"\x1d\n")
                        await anyio.to_thread.run_sync(channel.send, b"exit\n")

                await _send_websocket_json(
                    websocket,
                    {"type": "status", "status": "connected", "vm": cleaned_vm_name},
                )
                await _stream_ssh_channel(websocket, channel, on_close=detach_console)
        except HostKeyVerificationError as exc:
            await _send_websocket_json(
                websocket,
                {
                    "type": "error",
                    "message": str(exc),
                    "code": "host_key_verification_failed",
                },
            )
        except (SSHError, RuntimeError) as exc:
            await _send_websocket_json(
                websocket, {"type": "error", "message": str(exc)}
            )
        except Exception:
            await _send_websocket_json(
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

        runner = _build_ssh_runner(agent)

        try:
            nodeinfo_result = runner.run(["virsh", "nodeinfo"])
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
