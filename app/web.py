"""Web interface for the PlayrServers management control plane."""

from __future__ import annotations

import html
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, Optional, Tuple

from fastapi import APIRouter, FastAPI, HTTPException, Request, status
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .agents import AgentRegistry, AgentSession, Tunnel, TunnelState
from .database import Database
from .models import User
from .sessions import SessionManager
from urllib.parse import parse_qs

logger = logging.getLogger("playrservers.web")

SESSION_COOKIE_NAME = "psm_session"


@dataclass(frozen=True)
class HypervisorSummary:
    """Presentation details for a paired hypervisor."""

    agent_id: str
    hostname: str
    capabilities: tuple[str, ...]
    metadata: Dict[str, str]
    connected_at: datetime
    last_seen: datetime
    endpoint_host: str
    endpoint_port: int
    is_online: bool
    active_tunnels: int
    pending_tunnels: int
    closed_tunnels: int


def _template_environment() -> Jinja2Templates:
    base_dir = Path(__file__).resolve().parent
    templates = Jinja2Templates(directory=str(base_dir / "templates"))
    return templates


def _format_datetime(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%d %b %Y • %H:%M %Z")


def _tunnel_counters(tunnels: Iterable[Tunnel]) -> tuple[int, int, int]:
    active = pending = closed = 0
    for tunnel in tunnels:
        if tunnel.state is TunnelState.ACTIVE:
            active += 1
        elif tunnel.state is TunnelState.CLOSED:
            closed += 1
        else:
            pending += 1
    return active, pending, closed


def _session_to_summary(session: AgentSession, registry: AgentRegistry) -> HypervisorSummary:
    expires_at = session.expires_at(registry.session_timeout)
    now = datetime.now(timezone.utc)
    is_online = expires_at > now
    active, pending, closed = _tunnel_counters(session.tunnels.values())

    return HypervisorSummary(
        agent_id=session.agent_id,
        hostname=session.hostname,
        capabilities=session.capabilities,
        metadata=dict(session.metadata),
        connected_at=session.created_at,
        last_seen=session.last_seen,
        endpoint_host=registry.tunnel_host,
        endpoint_port=registry.tunnel_port,
        is_online=is_online,
        active_tunnels=active,
        pending_tunnels=pending,
        closed_tunnels=closed,
    )


def register_ui_routes(
    app: FastAPI,
    database: Database,
    registry: AgentRegistry,
    *,
    session_manager: SessionManager,
    secure_cookies: bool,
) -> None:
    """Expose the HTML management interface on the provided FastAPI app."""

    try:
        templates = _template_environment()
    except AssertionError:
        logger.warning(
            "jinja2 is not installed; falling back to a minimal HTML renderer for the"
            " management dashboard."
        )
        templates = None
    static_dir = Path(__file__).resolve().parent / "static"
    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    router = APIRouter(include_in_schema=False)
    agent_script_path = Path(__file__).resolve().parent.parent / "scripts" / "install_agent.sh"

    def _base_context(request: Request, user: Optional[User], **extra):
        context = {
            "request": request,
            "user": user,
            "format_datetime": _format_datetime,
            "now": datetime.now,
        }
        context.update(extra)
        return context

    def _build_base_markup(
        request: Request,
        *,
        user: Optional[User],
        title: str,
        stylesheet: str,
        content: str,
    ) -> str:
        dashboard_url = request.url_for("ui_dashboard")
        agent_url = request.url_for("ui_agent_installer")
        logout_url = request.url_for("ui_logout")
        brand = "PlayrServers Management"
        if user:
            user_name = html.escape(user.name)
            current_path = request.url.path
            dashboard_path = request.app.url_path_for("ui_dashboard")
            agent_path = request.app.url_path_for("ui_agent_installer")
            dashboard_class = "nav-link"
            if current_path == dashboard_path:
                dashboard_class += " nav-link--active"
            agent_class = "nav-link"
            if current_path == agent_path:
                agent_class += " nav-link--active"
            nav_actions = (
                f'<nav class="navbar__actions" aria-label="Primary">'
                f'<a href="{dashboard_url}" class="{dashboard_class}">Dashboard</a>'
                f'<a href="{agent_url}" class="{agent_class}">Agent installer</a>'
                f'<a href="{logout_url}" class="nav-link">Sign out</a>'
                f'<span class="navbar__user">{user_name}</span>'
                "</nav>"
            )
        else:
            nav_actions = ""

        year = datetime.now().year
        navbar = (
            f'<header class="navbar">'
            f'<div class="navbar__brand"><span class="navbar__logo" aria-hidden="true">⛅</span><span>{brand}</span></div>'
            f"{nav_actions}"
            "</header>"
        )

        footer = (
            f'<footer class="footer">© {year} PlayrServers. Secure management for your infrastructure.</footer>'
        )

        return (
            "<!DOCTYPE html>\n"
            "<html lang=\"en\">\n"
            "  <head>\n"
            "    <meta charset=\"utf-8\" />\n"
            "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />\n"
            f"    <title>{html.escape(title)}</title>\n"
            f"    <link rel=\"stylesheet\" href=\"{stylesheet}\" />\n"
            "  </head>\n"
            "  <body>\n"
            f"    {navbar}\n"
            "    <main class=\"page\">\n"
            f"{content}\n"
            "    </main>\n"
            f"    {footer}\n"
            "  </body>\n"
            "</html>"
        )

    def _render_login_markup(context: Dict[str, object], request: Request) -> str:
        email = html.escape(str(context.get("email", "")))
        error = context.get("error")
        error_html = (
            f'<div class="alert alert--error">{html.escape(str(error))}</div>'
            if error
            else ""
        )
        stylesheet = request.url_for("static", path="css/app.css")
        body = f"""
<section class="card card--centered">
  <h1 class="card__title">Welcome back</h1>
  <p class="card__subtitle">
    Sign in with your management credentials to access your account overview and paired hypervisors.
  </p>
  {error_html}
  <form method="post" action="{request.url_for('ui_login_submit')}" class="form">
    <label class="form__label" for="email">Email address</label>
    <input class="form__input" type="email" id="email" name="email" value="{email}" autocomplete="username" required />
    <label class="form__label" for="password">Password</label>
    <input class="form__input" type="password" id="password" name="password" autocomplete="current-password" required />
    <button type="submit" class="button button--primary">Sign in</button>
  </form>
</section>
"""
        return _build_base_markup(
            request,
            user=None,
            title="Sign in · PlayrServers Management",
            stylesheet=str(stylesheet),
            content=body,
        )

    def _render_dashboard_markup(context: Dict[str, object], request: Request) -> str:
        user = context.get("user")
        assert isinstance(user, User)
        hypervisors = context.get("hypervisors", [])
        assert isinstance(hypervisors, list)
        hypervisor_count = int(context.get("hypervisor_count", 0))
        online_count = int(context.get("online_count", 0))
        stylesheet = request.url_for("static", path="css/app.css")

        account_details = f"""
<section class="card">
  <h1 class="card__title">Account overview</h1>
  <p class="card__subtitle">Review the details associated with your management account.</p>
  <dl class="detail-grid">
    <div class="detail-grid__item"><dt>Name</dt><dd>{html.escape(user.name)}</dd></div>
    <div class="detail-grid__item"><dt>Email</dt><dd>{html.escape(user.email) if user.email else 'Not set'}</dd></div>
    <div class="detail-grid__item"><dt>Created</dt><dd>{html.escape(_format_datetime(user.created_at))}</dd></div>
    <div class="detail-grid__item"><dt>Paired hypervisors</dt><dd>{hypervisor_count}</dd></div>
    <div class="detail-grid__item"><dt>Online now</dt><dd>{online_count}</dd></div>
  </dl>
</section>
"""

        rows = []
        for summary in hypervisors:
            if not isinstance(summary, HypervisorSummary):
                continue
            capabilities = ", ".join(html.escape(cap) for cap in summary.capabilities)
            if capabilities:
                capabilities_html = capabilities
            else:
                capabilities_html = '<span class="text-muted">None reported</span>'
            status_class = "status-pill status-pill--success" if summary.is_online else "status-pill status-pill--muted"
            status_label = "Online" if summary.is_online else "Offline"
            tunnel_parts = [f"<strong>{summary.active_tunnels}</strong> active"]
            if summary.pending_tunnels:
                tunnel_parts.append(f"{summary.pending_tunnels} pending")
            if summary.closed_tunnels:
                tunnel_parts.append(f"{summary.closed_tunnels} closed")
            tunnels_text = " · ".join(tunnel_parts)
            rows.append(
                """
    <div class="table__row">
      <span class="table__cell table__cell--emphasis">{agent}</span>
      <span class="table__cell">{hostname}</span>
      <span class="table__cell"><span class="{status_class}">{status_label}</span></span>
      <span class="table__cell">{capabilities}</span>
      <span class="table__cell">{last_seen}</span>
      <span class="table__cell">{tunnels}</span>
    </div>
""".format(
                    agent=html.escape(summary.agent_id),
                    hostname=html.escape(summary.hostname),
                    status_class=status_class,
                    status_label=status_label,
                    capabilities=capabilities_html,
                    last_seen=html.escape(_format_datetime(summary.last_seen)),
                    tunnels=tunnels_text,
                )
            )

        if rows:
            table_body = "\n".join(rows)
            hypervisor_section = f"""
<section class="card">
  <div class="card__title">Paired hypervisors</div>
  <p class="card__subtitle">Hypervisors authenticate back to this control plane and surface secure tunnels.</p>
  <div class="table">
    <div class="table__header">
      <span>Agent</span>
      <span>Hostname</span>
      <span>Status</span>
      <span>Capabilities</span>
      <span>Last seen</span>
      <span>Tunnels</span>
    </div>
{table_body}
  </div>
</section>
"""
        else:
            hypervisor_section = """
<section class="card">
  <div class="card__title">Paired hypervisors</div>
  <p class="card__subtitle">Hypervisors authenticate back to this control plane and surface secure tunnels.</p>
  <div class="empty-state">
    <h2>No hypervisors connected yet</h2>
    <p>Install and pair a PlayrServers agent to begin managing your infrastructure from this dashboard.</p>
  </div>
</section>
"""

        body = account_details + hypervisor_section
        return _build_base_markup(
            request,
            user=user,
            title="Dashboard · PlayrServers Management",
            stylesheet=str(stylesheet),
            content=body,
        )

    def _render_login_response(
        request: Request, context: Dict[str, object], *, status_code: int
    ) -> HTMLResponse:
        if templates is not None:
            return templates.TemplateResponse("login.html", context, status_code=status_code)
        markup = _render_login_markup(context, request)
        return HTMLResponse(markup, status_code=status_code)

    def _render_dashboard_response(request: Request, context: Dict[str, object]) -> HTMLResponse:
        if templates is not None:
            return templates.TemplateResponse("dashboard.html", context)
        markup = _render_dashboard_markup(context, request)
        return HTMLResponse(markup)

    def _render_agent_installer_markup(context: Dict[str, object], request: Request) -> str:
        user = context.get("user")
        assert isinstance(user, User)
        script_url = html.escape(str(context.get("script_url", "")))
        curl_command = html.escape(str(context.get("curl_command", "")))
        api_help = html.escape(str(context.get("api_help", "")))
        api_key_error = context.get("api_key_error")
        api_key_error_html = (
            f'<div class="alert alert--error">{html.escape(str(api_key_error))}</div>'
            if api_key_error
            else ""
        )
        generated_api_key = context.get("generated_api_key")
        generated_api_key_html = (
            """
  <div class=\"callout callout--success\">
    <p><strong>Your new API key</strong></p>
    <code>{key}</code>
    <p class=\"text-muted\">Copy this key now. It will not be shown again.</p>
  </div>
""".format(key=html.escape(str(generated_api_key)))
            if generated_api_key
            else ""
        )
        api_key_form_name = html.escape(str(context.get("api_key_form_name", "Hypervisor agent")))
        generate_api_key_url = html.escape(
            str(context.get("generate_api_key_url", request.url_for("ui_generate_api_key")))
        )
        stylesheet = request.url_for("static", path="css/app.css")
        body = f"""
<section class=\"card\">
  <h1 class=\"card__title\">Install the hypervisor agent</h1>
  <p class=\"card__subtitle\">Deploy the PlayrServers agent on a supported Ubuntu host to pair it with this control plane.</p>
  <div class=\"callout\">
    <code>{curl_command}</code>
  </div>
  <p>The command above downloads the signed installer from <code>{script_url}</code> and provisions QEMU, libvirt, and the reverse tunnel runtime.</p>
  <p>{api_help}</p>
  <h2>Generate an API key</h2>
  <p>Create a dedicated credential for hypervisors connecting back to this management plane.</p>
{api_key_error_html}
{generated_api_key_html}
  <form method=\"post\" action=\"{generate_api_key_url}\" class=\"form\">
    <label class=\"form__label\" for=\"api-key-name\">Key name</label>
    <input class=\"form__input\" type=\"text\" id=\"api-key-name\" name=\"name\" value=\"{api_key_form_name}\" required />
    <button type=\"submit\" class=\"button button--primary\">Generate API key</button>
  </form>
  <h2>Non-interactive installs</h2>
  <p>Provide flags to the installer to skip prompts:</p>
  <pre><code>{curl_command} -- --api-key &lt;your-api-key&gt; --agent-id $(hostname)</code></pre>
</section>
"""
        return _build_base_markup(
            request,
            user=user,
            title="Agent installer · PlayrServers Management",
            stylesheet=str(stylesheet),
            content=body,
        )

    def _render_agent_installer_response(request: Request, context: Dict[str, object]) -> HTMLResponse:
        if templates is not None:
            return templates.TemplateResponse("agent_installer.html", context)
        markup = _render_agent_installer_markup(context, request)
        return HTMLResponse(markup)

    def _agent_installer_context(
        request: Request,
        user: User,
        *,
        generated_api_key: str | None = None,
        api_key_error: str | None = None,
        api_key_form_name: str | None = None,
    ) -> Dict[str, object]:
        script_url = request.url_for("agent_installer_script")
        curl_command = f"curl -fsSL {script_url} | sudo bash"
        api_help = (
            "Use this dashboard to generate a management API key and supply it to the installer "
            "using the --api-key flag to authorise the agent."
        )
        form_name = api_key_form_name if api_key_form_name is not None else "Hypervisor agent"
        return _base_context(
            request,
            user,
            script_url=script_url,
            curl_command=curl_command,
            api_help=api_help,
            generated_api_key=generated_api_key,
            api_key_error=api_key_error,
            api_key_form_name=form_name,
            generate_api_key_url=request.url_for("ui_generate_api_key"),
        )

    async def _parse_login_form(request: Request) -> Tuple[str, str]:
        body_bytes = await request.body()
        content_type = request.headers.get("content-type", "")
        charset = "utf-8"
        if "charset=" in content_type:
            charset = content_type.split("charset=", 1)[1].split(";", 1)[0].strip() or "utf-8"
        try:
            decoded = body_bytes.decode(charset)
        except (LookupError, UnicodeDecodeError):
            decoded = body_bytes.decode("utf-8", errors="ignore")
        data = parse_qs(decoded, keep_blank_values=True)
        email = data.get("email", [""])[0]
        password = data.get("password", [""])[0]
        return email, password

    async def _parse_api_key_form(request: Request) -> str:
        body_bytes = await request.body()
        content_type = request.headers.get("content-type", "")
        charset = "utf-8"
        if "charset=" in content_type:
            charset = content_type.split("charset=", 1)[1].split(";", 1)[0].strip() or "utf-8"
        try:
            decoded = body_bytes.decode(charset)
        except (LookupError, UnicodeDecodeError):
            decoded = body_bytes.decode("utf-8", errors="ignore")
        data = parse_qs(decoded, keep_blank_values=True)
        return data.get("name", [""])[0]

    def _load_user(request: Request) -> Tuple[Optional[User], Optional[str]]:
        token = request.cookies.get(SESSION_COOKIE_NAME)
        if not token:
            return None, None
        user_id = session_manager.resolve(token)
        if user_id is None:
            return None, token
        user = database.get_user(user_id)
        if user is None:
            session_manager.destroy(token)
            return None, token
        return user, token

    def _clear_session_cookie(response, token: Optional[str]) -> None:
        if token:
            session_manager.destroy(token)
        response.delete_cookie(SESSION_COOKIE_NAME, path="/")

    def _issue_session_cookie(response, token: str) -> None:
        response.set_cookie(
            SESSION_COOKIE_NAME,
            token,
            max_age=session_manager.cookie_max_age,
            secure=secure_cookies,
            httponly=True,
            samesite="lax",
            path="/",
        )

    def _render_login(
        request: Request,
        *,
        email: str = "",
        error: str | None = None,
        status_code: int = status.HTTP_200_OK,
    ):
        user, token = _load_user(request)
        if user is not None and token:
            response = RedirectResponse(
                request.url_for("ui_dashboard"), status_code=status.HTTP_303_SEE_OTHER
            )
            _issue_session_cookie(response, token)
            return response

        context = _base_context(request, None, email=email, error=error)
        response = _render_login_response(request, context, status_code=status_code)
        if token:
            _clear_session_cookie(response, token)
        return response

    @router.get("/", response_class=HTMLResponse, name="ui_home")
    async def homepage(request: Request):
        return _render_login(request)

    @router.get("/login", response_class=HTMLResponse, name="ui_login")
    async def login_form(request: Request):
        return _render_login(request)

    @router.post("/login", name="ui_login_submit")
    async def login_submit(request: Request):
        email, password = await _parse_login_form(request)
        if not email or not password:
            return _render_login(
                request,
                email=email,
                error="Please provide both email and password.",
                status_code=status.HTTP_400_BAD_REQUEST,
            )

        user = database.authenticate_user(email, password)
        if user is None:
            logger.warning("Failed web login attempt for %s", email)
            return _render_login(
                request,
                email=email,
                error="Invalid email or password. Please try again.",
                status_code=status.HTTP_400_BAD_REQUEST,
            )

        existing_token = request.cookies.get(SESSION_COOKIE_NAME)
        if existing_token:
            session_manager.destroy(existing_token)

        token = session_manager.create(user.id)
        logger.info("User %s signed in to the web dashboard", user.id)
        response = RedirectResponse(
            request.url_for("ui_dashboard"), status_code=status.HTTP_303_SEE_OTHER
        )
        _issue_session_cookie(response, token)
        return response

    @router.get("/logout", name="ui_logout")
    async def logout(request: Request):
        token = request.cookies.get(SESSION_COOKIE_NAME)
        response = RedirectResponse(
            request.url_for("ui_login"), status_code=status.HTTP_303_SEE_OTHER
        )
        _clear_session_cookie(response, token)
        return response

    @router.get("/dashboard", response_class=HTMLResponse, name="ui_dashboard")
    async def dashboard(request: Request):
        user, token = _load_user(request)
        if user is None:
            response = RedirectResponse(
                request.url_for("ui_login"), status_code=status.HTTP_303_SEE_OTHER
            )
            if token:
                _clear_session_cookie(response, token)
            return response

        sessions = await registry.list_sessions(user_id=user.id)
        summaries = [_session_to_summary(session, registry) for session in sessions]
        online = sum(1 for summary in summaries if summary.is_online)

        context = _base_context(
            request,
            user,
            hypervisors=summaries,
            hypervisor_count=len(summaries),
            online_count=online,
        )
        response = _render_dashboard_response(request, context)
        if token:
            _issue_session_cookie(response, token)
        return response

    @router.get("/installers/agent", response_class=HTMLResponse, name="ui_agent_installer")
    async def agent_installer(request: Request):
        user, token = _load_user(request)
        if user is None:
            response = RedirectResponse(
                request.url_for("ui_login"), status_code=status.HTTP_303_SEE_OTHER
            )
            if token:
                _clear_session_cookie(response, token)
            return response
        context = _agent_installer_context(request, user)
        response = _render_agent_installer_response(request, context)
        if token:
            _issue_session_cookie(response, token)
        return response

    @router.post(
        "/installers/agent/api-keys",
        response_class=HTMLResponse,
        name="ui_generate_api_key",
    )
    async def generate_api_key(request: Request):
        user, token = _load_user(request)
        if user is None:
            response = RedirectResponse(
                request.url_for("ui_login"), status_code=status.HTTP_303_SEE_OTHER
            )
            if token:
                _clear_session_cookie(response, token)
            return response

        raw_name = await _parse_api_key_form(request)
        trimmed_name = raw_name.strip()
        generated_key: str | None = None
        error_message: str | None = None

        if not trimmed_name:
            error_message = "Please provide a name for the API key."
        else:
            try:
                generated_key = database.create_api_key(user.id, trimmed_name)
            except ValueError as exc:
                error_message = str(exc)

        form_name = raw_name if error_message else trimmed_name
        context = _agent_installer_context(
            request,
            user,
            generated_api_key=generated_key,
            api_key_error=error_message,
            api_key_form_name=form_name,
        )
        response = _render_agent_installer_response(request, context)
        if token:
            _issue_session_cookie(response, token)
        return response

    @router.get("/agent", response_class=PlainTextResponse, name="agent_installer_script")
    async def agent_installer_script():
        try:
            content = agent_script_path.read_text(encoding="utf-8")
        except FileNotFoundError as exc:  # pragma: no cover - missing asset
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent installer not available") from exc
        headers = {"Content-Disposition": "attachment; filename=install_agent.sh"}
        return PlainTextResponse(content, headers=headers)

    app.include_router(router)


__all__ = ["register_ui_routes", "HypervisorSummary"]
