"""Browser-based management interface for the PlayrServers control plane."""
from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from fastapi import FastAPI, Form, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from .database import Database, resolve_database_path
from .models import Agent, User
from .qemu import QEMUError, QEMUManager
from .ssh import SSHClientFactory, SSHCommandRunner, SSHTarget, SSHError


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

    def _build_qemu_manager(agent: Agent) -> QEMUManager:
        target = SSHTarget(
            hostname=agent.hostname,
            port=agent.port,
            username=agent.username,
            private_key=agent.private_key,
            passphrase=agent.private_key_passphrase,
            allow_unknown_hosts=agent.allow_unknown_hosts,
            known_hosts_path=Path(agent.known_hosts_path).expanduser() if agent.known_hosts_path else None,
        )
        factory = SSHClientFactory(target)
        runner = SSHCommandRunner(factory)
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

    def _handle_api_key_rotation(request: Request, user: User) -> RedirectResponse:
        refreshed, api_key = database.rotate_api_key(user.id)
        request.session["flash_api_key"] = api_key
        request.session["user_id"] = refreshed.id
        _flash(request, "Issued a new API key.", category="success")
        return RedirectResponse(
            request.url_for("account"),
            status_code=status.HTTP_303_SEE_OTHER,
        )

    def _get_current_user(request: Request) -> Optional[User]:
        user_id = request.session.get("user_id")
        if not user_id:
            return None
        user = database.get_user(int(user_id))
        if user is None:
            request.session.pop("user_id", None)
        return user

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
            entry["remove_url"] = request.url_for("remove_agent", agent_id=entry["id"])
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
            "list_vms": request.url_for("management_list_vms", agent_id=0),
            "vm_info": request.url_for(
                "management_vm_info", agent_id=0, vm_name="__VM__"
            ),
            "vm_action": request.url_for(
                "management_vm_action",
                agent_id=0,
                vm_name="__VM__",
                action="__ACTION__",
            ),
        }

        return templates.TemplateResponse(
            "management.html",
            {
                "request": request,
                "user": user,
                "agents": agent_views,
                "selected_agent": selected_agent,
                "messages": messages,
                "endpoints": endpoints,
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

    return app


__all__ = ["create_app"]
