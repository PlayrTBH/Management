"""Web interface for the PlayrServers management control plane."""

from __future__ import annotations

import asyncio
import contextlib
import html
import json
import logging
import os
import pty
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from fastapi import APIRouter, FastAPI, HTTPException, Query, Request, WebSocket, WebSocketDisconnect, status
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
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


@dataclass(frozen=True)
class CPUCoreMetric:
    """Describes utilisation for a single CPU core."""

    id: str
    label: str
    usage: float


@dataclass(frozen=True)
class VirtualMachineEntry:
    """Represents a guest exposed by a hypervisor."""

    id: str
    name: str
    status: Optional[str]
    power_state: Optional[str]
    cpu: Optional[str]
    memory: Optional[str]
    metadata: Dict[str, str]


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


def _normalise_percentage(value: Any) -> Optional[float]:
    """Convert assorted metric formats into a percentage."""

    if value is None:
        return None
    if isinstance(value, str):
        cleaned = value.strip()
        if not cleaned:
            return None
        if cleaned.endswith("%"):
            cleaned = cleaned[:-1]
        try:
            number = float(cleaned)
        except ValueError:
            return None
    else:
        try:
            number = float(value)
        except (TypeError, ValueError):
            return None

    if number < 0:
        number = 0.0
    if number > 100:
        number = min(number, 100.0)
    return number


def _parse_cpu_metrics(metadata: Mapping[str, str]) -> List[CPUCoreMetric]:
    """Extract per-core utilisation readings from agent metadata."""

    cores: Dict[str, Dict[str, Any]] = {}

    def _ensure_core(identifier: str) -> Dict[str, Any]:
        entry = cores.setdefault(identifier, {"label": f"Core {identifier}", "usage": None})
        return entry

    def _ingest_mapping(index: int, entry: Mapping[str, Any]) -> None:
        core_id = str(entry.get("id") or entry.get("core") or entry.get("index") or index)
        info = _ensure_core(core_id)
        label = entry.get("label") or entry.get("name") or entry.get("title")
        if label:
            info["label"] = str(label)
        usage = (
            _normalise_percentage(
                entry.get("usage")
                or entry.get("value")
                or entry.get("percent")
                or entry.get("utilisation")
                or entry.get("load")
                or entry.get("usage_percent")
            )
        )
        if usage is not None:
            info["usage"] = usage

    json_candidates = (
        metadata.get("cpu_cores"),
        metadata.get("cpu.cores"),
        metadata.get("cpu.core_stats"),
    )
    for candidate in json_candidates:
        if not candidate:
            continue
        try:
            payload = json.loads(candidate)
        except (TypeError, ValueError):
            continue
        if isinstance(payload, dict):
            if isinstance(payload.get("cores"), list):
                payload = payload["cores"]
            else:
                payload = list(payload.values())
        if not isinstance(payload, list):
            continue
        for index, entry in enumerate(payload):
            if isinstance(entry, Mapping):
                _ingest_mapping(index, entry)
                continue
            usage = _normalise_percentage(entry)
            if usage is None:
                continue
            core_id = str(index)
            info = _ensure_core(core_id)
            info["usage"] = usage

    core_key = re.compile(r"^cpu[._-]?core[._-]?(?P<id>\d+)(?:[._-]?(?P<field>[A-Za-z0-9_]+))?$", re.IGNORECASE)
    for key, value in metadata.items():
        match = core_key.match(key)
        if not match:
            continue
        core_id = match.group("id")
        field = match.group("field")
        info = _ensure_core(core_id)
        if field is None:
            usage = _normalise_percentage(value)
            if usage is not None:
                info["usage"] = usage
            continue
        field_lower = field.lower()
        if field_lower in {"usage", "util", "percent", "load"}:
            usage = _normalise_percentage(value)
            if usage is not None:
                info["usage"] = usage
        elif field_lower in {"label", "name", "title"}:
            info["label"] = str(value)

    metrics: List[CPUCoreMetric] = []
    for identifier, info in cores.items():
        usage = info.get("usage")
        if usage is None:
            continue
        label = str(info.get("label") or f"Core {identifier}")
        metrics.append(CPUCoreMetric(id=identifier, label=label, usage=float(usage)))

    metrics.sort(key=lambda item: int(item.id) if item.id.isdigit() else item.id)
    return metrics


_VM_METADATA_PATTERN = re.compile(r"^(?:vm|virtual_machine)[._-](?P<id>[A-Za-z0-9_.:-]+)[._-](?P<field>[A-Za-z0-9_.:-]+)$")


def _parse_virtual_machines(metadata: Mapping[str, str]) -> List[VirtualMachineEntry]:
    """Normalise metadata into structured VM entries."""

    entries: Dict[str, Dict[str, Any]] = {}

    def _ensure_vm(vm_id: str) -> Dict[str, Any]:
        record = entries.setdefault(vm_id, {"id": vm_id, "name": vm_id, "metadata": {}})
        return record

    json_candidates = (
        metadata.get("vms"),
        metadata.get("virtual_machines"),
        metadata.get("vm_list"),
        metadata.get("vm.inventory"),
    )

    for candidate in json_candidates:
        if not candidate:
            continue
        try:
            payload = json.loads(candidate)
        except (TypeError, ValueError):
            continue
        if isinstance(payload, dict):
            if isinstance(payload.get("vms"), list):
                payload = payload["vms"]
            elif isinstance(payload.get("items"), list):
                payload = payload["items"]
            else:
                payload = list(payload.values())
        if not isinstance(payload, list):
            continue
        for index, entry in enumerate(payload):
            if isinstance(entry, Mapping):
                vm_id = str(entry.get("id") or entry.get("uuid") or entry.get("name") or f"vm-{index}")
                record = _ensure_vm(vm_id)
                if entry.get("name"):
                    record["name"] = str(entry.get("name"))
                status_value = entry.get("status") or entry.get("state")
                if status_value:
                    record["status"] = str(status_value)
                power_value = entry.get("power_state") or entry.get("power")
                if power_value:
                    record["power_state"] = str(power_value)
                cpu_value = entry.get("cpu") or entry.get("vcpus")
                if cpu_value is not None:
                    record["cpu"] = str(cpu_value)
                memory_value = entry.get("memory") or entry.get("ram")
                if memory_value is not None:
                    record["memory"] = str(memory_value)
                extras = {
                    str(k): str(v)
                    for k, v in entry.items()
                    if k
                    not in {
                        "id",
                        "uuid",
                        "name",
                        "status",
                        "state",
                        "power_state",
                        "power",
                        "cpu",
                        "vcpus",
                        "memory",
                        "ram",
                    }
                }
                if extras:
                    _ensure_vm(vm_id)["metadata"].update(extras)
            elif isinstance(entry, str):
                vm_name = entry.strip()
                if not vm_name:
                    continue
                record = _ensure_vm(vm_name)
                record["name"] = vm_name

    for key, value in metadata.items():
        match = _VM_METADATA_PATTERN.match(key)
        if not match:
            continue
        vm_id = match.group("id")
        field = match.group("field").lower()
        record = _ensure_vm(vm_id)
        if field in {"name", "label", "title"}:
            record["name"] = str(value)
        elif field in {"status", "state"}:
            record["status"] = str(value)
        elif field in {"power", "power_state"}:
            record["power_state"] = str(value)
        elif field in {"cpu", "vcpus"}:
            record["cpu"] = str(value)
        elif field in {"memory", "ram"}:
            record["memory"] = str(value)
        else:
            record.setdefault("metadata", {})[field] = str(value)

    virtual_machines: List[VirtualMachineEntry] = []
    for vm_id, record in entries.items():
        metadata_payload = {str(k): str(v) for k, v in record.get("metadata", {}).items()}
        virtual_machines.append(
            VirtualMachineEntry(
                id=vm_id,
                name=str(record.get("name") or vm_id),
                status=record.get("status"),
                power_state=record.get("power_state"),
                cpu=record.get("cpu"),
                memory=record.get("memory"),
                metadata=metadata_payload,
            )
        )

    virtual_machines.sort(key=lambda entry: entry.name.lower())
    return virtual_machines


def _collect_host_overview(summary: HypervisorSummary) -> List[Tuple[str, str]]:
    """Produce key/value pairs describing the host."""

    overview: List[Tuple[str, str]] = [
        ("Hostname", summary.hostname),
        ("Status", "Online" if summary.is_online else "Offline"),
        ("Endpoint", f"{summary.endpoint_host}:{summary.endpoint_port}"),
        ("Connected", _format_datetime(summary.connected_at)),
        ("Last seen", _format_datetime(summary.last_seen)),
        (
            "Tunnels",
            f"{summary.active_tunnels} active"
            + (f" · {summary.pending_tunnels} pending" if summary.pending_tunnels else "")
            + (f" · {summary.closed_tunnels} closed" if summary.closed_tunnels else ""),
        ),
    ]

    metadata = summary.metadata

    def _pick(keys: Iterable[str]) -> Optional[str]:
        for key in keys:
            value = metadata.get(key)
            if value:
                return value
        return None

    additional = [
        ("Operating system", ("os_name", "os")),
        ("Kernel", ("kernel", "os_kernel")),
        ("Architecture", ("architecture", "arch")),
        ("CPU model", ("cpu_model", "cpu.model", "cpu")),
        ("Physical cores", ("cpu_physical_cores", "cpu.physical_cores")),
        ("Logical cores", ("cpu_logical_cores", "cpu.logical_cores")),
        ("Total memory", ("memory_total", "memory.total", "memory")),
        ("Uptime", ("uptime", "host_uptime", "system_uptime")),
        ("Agent", ("provisioned_by", "agent_version")),
    ]
    for label, keys in additional:
        value = _pick(keys)
        if value:
            overview.append((label, value))

    return overview


def _resolve_ssh_defaults(metadata: Mapping[str, str]) -> tuple[str, str, int]:
    """Return sensible defaults for SSH connectivity."""

    def _pick(keys: Iterable[str], default: str) -> str:
        for key in keys:
            value = metadata.get(key)
            if value:
                return str(value)
        return default

    bastion_user = _pick(("ssh_user", "ssh.user", "bastion_user"), "tunnels")
    login_user = _pick(("ssh_login", "ssh.login", "default_login", "hypervisor_user"), "root")
    port_raw = _pick(("ssh_port", "ssh.port", "local_ssh_port"), "22")
    try:
        local_port = int(str(port_raw))
    except ValueError:
        local_port = 22
    return bastion_user, login_user, local_port


def _next_remote_port(session: AgentSession, *, start: int = 2200) -> int:
    """Choose a remote port for a new tunnel, avoiding collisions."""

    used_ports = {tunnel.remote_port for tunnel in session.tunnels.values()}
    port = start
    while port in used_ports and port < 64000:
        port += 1
    if port in used_ports:
        # All high ports exhausted; fall back to a lower, but safe range.
        port = 1025
        while port in used_ports and port < 2000:
            port += 1
    return port


async def _wait_for_port(host: str, port: int, timeout: float = 20.0) -> bool:
    """Poll ``host``/``port`` until reachable or the timeout elapses."""

    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while True:
        try:
            reader, writer = await asyncio.open_connection(host, port)
        except OSError:
            if loop.time() >= deadline:
                return False
            await asyncio.sleep(0.5)
            continue
        except asyncio.CancelledError:
            raise
        except Exception:  # pragma: no cover - defensive
            if loop.time() >= deadline:
                return False
            await asyncio.sleep(0.5)
            continue
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
        return True


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
        agent_installer_url = html.escape(str(request.url_for("ui_agent_installer")))

        page_header = f"""
<header class="page-head">
  <div class="page-head__content">
    <h1 class="page-head__title">Hypervisors</h1>
    <p class="page-head__subtitle">Monitor the systems paired with your management plane and review their tunnel activity.</p>
    <div class="page-head__metrics">
      <div class="page-head__metric">
        <span class="page-head__metric-value">{hypervisor_count}</span>
        <span class="page-head__metric-label">Paired</span>
      </div>
      <div class="page-head__metric">
        <span class="page-head__metric-value">{online_count}</span>
        <span class="page-head__metric-label">Online now</span>
      </div>
    </div>
  </div>
  <div class="page-head__actions">
    <a class="button button--primary" href="{agent_installer_url}">Add hypervisor</a>
  </div>
</header>
"""

        account_details = f"""
<section class="card">
  <h2 class="card__title">Account overview</h2>
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
            detail_url = html.escape(
                str(request.url_for("ui_hypervisor", agent_id=summary.agent_id))
            )
            rows.append(
                """
    <div class="table__row">
      <span class="table__cell table__cell--emphasis"><a class="table__link" href="{detail_url}">{agent}</a></span>
      <span class="table__cell">{hostname}</span>
      <span class="table__cell"><span class="{status_class}">{status_label}</span></span>
      <span class="table__cell">{capabilities}</span>
      <span class="table__cell">{last_seen}</span>
      <span class="table__cell">{tunnels}</span>
    </div>
""".format(
                    detail_url=detail_url,
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
<section class="card" id="hypervisors">
  <h2 class="card__title">Paired hypervisors</h2>
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
<section class="card" id="hypervisors">
  <h2 class="card__title">Paired hypervisors</h2>
  <p class="card__subtitle">Hypervisors authenticate back to this control plane and surface secure tunnels.</p>
  <div class="empty-state">
    <h2>No hypervisors connected yet</h2>
    <p>Install and pair a PlayrServers agent to begin managing your infrastructure from this dashboard.</p>
  </div>
</section>
"""

        body = page_header + account_details + hypervisor_section
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

    def _render_hypervisor_markup(context: Dict[str, object], request: Request) -> str:
        hypervisor = context.get("hypervisor")
        if not isinstance(hypervisor, HypervisorSummary):
            raise AssertionError("Missing hypervisor context")
        host_overview = context.get("host_overview", [])
        cpu_metrics = context.get("cpu_metrics", [])
        virtual_machines = context.get("virtual_machines", [])
        ssh_command = context.get("ssh_command_example")
        stylesheet = request.url_for("static", path="css/app.css")

        overview_rows = [
            """
    <div class=\"detail-grid__item\"><dt>{label}</dt><dd>{value}</dd></div>
""".format(label=html.escape(str(label)), value=html.escape(str(value)))
            for label, value in host_overview
        ]
        overview_html = "\n".join(overview_rows)

        if cpu_metrics:
            metric_rows = [
                """
      <li class=\"metric-list__item\">
        <span class=\"metric-list__label\">{label}</span>
        <div class=\"metric-bar\"><div class=\"metric-bar__fill\" style=\"width: {usage:.2f}%\"></div></div>
        <span class=\"metric-list__value\">{usage:.1f}%</span>
      </li>
""".format(label=html.escape(metric.label), usage=metric.usage)
                for metric in cpu_metrics
            ]
            metrics_html = "<ul class=\"metric-list\">\n" + "\n".join(metric_rows) + "\n    </ul>"
        else:
            metrics_html = "<p class=\"text-muted\">No performance metrics reported yet.</p>"

        if virtual_machines:
            vm_rows = [
                """
      <li><strong>{name}</strong> – {status}</li>
""".format(
                    name=html.escape(vm.name),
                    status=html.escape(vm.status or "Unknown"),
                )
                for vm in virtual_machines
            ]
            vm_html = "<ul>\n" + "\n".join(vm_rows) + "\n    </ul>"
        else:
            vm_html = "<p class=\"text-muted\">No virtual machines reported.</p>"

        ssh_html = ""
        if ssh_command:
            ssh_html = """
    <div class=\"callout\"><code>{command}</code></div>
""".format(command=html.escape(str(ssh_command)))

        body = f"""
<header class=\"page-head\">
  <div class=\"page-head__content\">
    <h1 class=\"page-head__title\">{html.escape(hypervisor.agent_id)}</h1>
    <p class=\"page-head__subtitle\">Management view for {html.escape(hypervisor.hostname)}.</p>
  </div>
  <div class=\"page-head__actions\">
    <a class=\"button button--primary\" href=\"{request.url_for('ui_dashboard')}\">Back to dashboard</a>
  </div>
</header>

<section class=\"card\">
  <h2 class=\"card__title\">Host overview</h2>
  <dl class=\"detail-grid\">
{overview_html}
  </dl>
</section>

<section class=\"card\">
  <h2 class=\"card__title\">Performance metrics</h2>
{metrics_html}
</section>

<section class=\"card\">
  <h2 class=\"card__title\">Virtual machines</h2>
{vm_html}
</section>

<section class=\"card\">
  <h2 class=\"card__title\">SSH terminal</h2>
  <p>Request a secure shell via the management plane.</p>
{ssh_html}
</section>
"""

        return _build_base_markup(
            request,
            user=context.get("user"),
            title=f"{hypervisor.agent_id} · Hypervisor · PlayrServers Management",
            stylesheet=str(stylesheet),
            content=body,
        )

    def _render_hypervisor_response(request: Request, context: Dict[str, object]) -> HTMLResponse:
        if templates is not None:
            return templates.TemplateResponse("hypervisor.html", context)
        markup = _render_hypervisor_markup(context, request)
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

    def _load_user_from_cookies(
        cookies: Mapping[str, str] | None,
    ) -> Tuple[Optional[User], Optional[str]]:
        token = cookies.get(SESSION_COOKIE_NAME) if cookies else None
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

    def _load_user(request: Request) -> Tuple[Optional[User], Optional[str]]:
        return _load_user_from_cookies(request.cookies)

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
        summaries = sorted(
            (_session_to_summary(session, registry) for session in sessions),
            key=lambda summary: summary.last_seen,
            reverse=True,
        )
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

    @router.get("/hypervisors/{agent_id}", response_class=HTMLResponse, name="ui_hypervisor")
    async def hypervisor_detail(agent_id: str, request: Request):
        user, token = _load_user(request)
        if user is None:
            response = RedirectResponse(
                request.url_for("ui_login"), status_code=status.HTTP_303_SEE_OTHER
            )
            if token:
                _clear_session_cookie(response, token)
            return response

        try:
            session = await registry.get_session(agent_id=agent_id, user_id=user.id)
        except KeyError as exc:  # pragma: no cover - defensive
            raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Hypervisor not found") from exc

        summary = _session_to_summary(session, registry)
        host_overview = _collect_host_overview(summary)
        bastion_user, login_user, local_port = _resolve_ssh_defaults(session.metadata)
        if login_user:
            host_overview.append(("SSH login", f"{login_user}@{summary.hostname}"))

        cpu_metrics = _parse_cpu_metrics(session.metadata)
        virtual_machines = _parse_virtual_machines(session.metadata)
        ssh_example = (
            f"ssh -o ProxyCommand=\"ssh -W 127.0.0.1:<remote-port> {bastion_user}@{summary.endpoint_host} "
            f"-p {summary.endpoint_port}\" {login_user}@127.0.0.1"
        )

        context = _base_context(
            request,
            user,
            hypervisor=summary,
            host_overview=host_overview,
            cpu_metrics=cpu_metrics,
            virtual_machines=virtual_machines,
            ssh_defaults={
                "bastion_user": bastion_user,
                "login_user": login_user,
                "local_port": local_port,
            },
            ssh_command_example=ssh_example,
        )
        response = _render_hypervisor_response(request, context)
        if token:
            _issue_session_cookie(response, token)
        return response

    @router.post("/hypervisors/{agent_id}/terminal", name="ui_hypervisor_terminal")
    async def hypervisor_terminal(agent_id: str, request: Request):
        user, _ = _load_user(request)
        if user is None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Authentication required")

        try:
            session = await registry.get_session(agent_id=agent_id, user_id=user.id)
        except KeyError as exc:  # pragma: no cover - defensive
            raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Hypervisor not found") from exc

        if session.expires_at(registry.session_timeout) <= datetime.now(timezone.utc):
            raise HTTPException(status.HTTP_409_CONFLICT, detail="Hypervisor is offline")

        summary = _session_to_summary(session, registry)
        bastion_user, login_user, local_port = _resolve_ssh_defaults(session.metadata)
        remote_port = _next_remote_port(session)

        metadata = {
            "local_port": str(local_port),
            "target_user": login_user,
            "kind": "ssh-terminal",
        }

        tunnel, _ = await registry.create_tunnel(
            agent_id=agent_id,
            user_id=user.id,
            session_id=session.session_id,
            token=session.token,
            purpose="ssh-terminal",
            remote_port=remote_port,
            description="Web SSH session",
            metadata=metadata,
        )

        ssh_command = (
            "ssh -o ProxyCommand=\"sshpass -p '{token}' ssh -W 127.0.0.1:{remote_port} "
            "{bastion}@{host} -p {port} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null\" "
            "{login}@127.0.0.1 -p {local_port}"
        ).format(
            token=tunnel.token,
            remote_port=tunnel.remote_port,
            bastion=bastion_user,
            host=summary.endpoint_host,
            port=summary.endpoint_port,
            login=login_user,
            local_port=local_port,
        )

        message = (
            f"Tunnel {tunnel.id} established. Connect as {login_user}@127.0.0.1 using the command below."
        )

        payload = {
            "tunnel_id": tunnel.id,
            "remote_port": tunnel.remote_port,
            "local_port": local_port,
            "client_token": tunnel.token,
            "endpoint": {"host": summary.endpoint_host, "port": summary.endpoint_port},
            "ssh_command": ssh_command,
            "message": message,
            "websocket_path": str(
                request.app.url_path_for("ui_hypervisor_terminal_ws", agent_id=agent_id)
            )
            + f"?tunnel_id={tunnel.id}",
        }
        return JSONResponse(payload)

    @router.websocket("/hypervisors/{agent_id}/terminal/ws", name="ui_hypervisor_terminal_ws")
    async def hypervisor_terminal_ws(
        websocket: WebSocket,
        agent_id: str,
        tunnel_id: str = Query(..., alias="tunnel_id"),
    ):
        user, _ = _load_user_from_cookies(websocket.cookies)
        if user is None:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return

        try:
            session = await registry.get_session(agent_id=agent_id, user_id=user.id)
        except (PermissionError, KeyError):
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return

        tunnel = session.tunnels.get(str(tunnel_id))
        if tunnel is None:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return

        await websocket.accept()

        ready = await _wait_for_port("127.0.0.1", tunnel.remote_port)
        if not ready:
            with contextlib.suppress(Exception):
                await websocket.send_text(
                    "Unable to reach the remote tunnel. The hypervisor may still be initialising."
                )
            await websocket.close(code=status.WS_1011_INTERNAL_ERROR)
            return

        login_user = tunnel.metadata.get("target_user") or _resolve_ssh_defaults(session.metadata)[1]
        remote_port = tunnel.remote_port

        command = [
            "ssh",
            "-tt",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "ServerAliveInterval=30",
            "-o",
            "ServerAliveCountMax=3",
            "-o",
            "ConnectTimeout=10",
            "-p",
            str(remote_port),
            f"{login_user}@127.0.0.1",
        ]

        env = os.environ.copy()
        env.setdefault("TERM", "xterm-256color")

        master_fd, slave_fd = pty.openpty()
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                env=env,
            )
        except FileNotFoundError:
            with contextlib.suppress(Exception):
                await websocket.send_text("SSH binary is not available on the management host.")
            await websocket.close(code=status.WS_1011_INTERNAL_ERROR)
            with contextlib.suppress(OSError):
                os.close(master_fd)
                os.close(slave_fd)
            return
        finally:
            with contextlib.suppress(OSError):
                os.close(slave_fd)

        loop = asyncio.get_running_loop()
        socket_open = True

        async def _forward_output() -> None:
            nonlocal socket_open
            try:
                while True:
                    data = await loop.run_in_executor(None, os.read, master_fd, 4096)
                    if not data:
                        break
                    await websocket.send_bytes(data)
            except WebSocketDisconnect:
                socket_open = False
            except RuntimeError:
                socket_open = False
            except Exception:  # pragma: no cover - defensive
                socket_open = False

        async def _forward_input() -> None:
            nonlocal socket_open
            try:
                while True:
                    message = await websocket.receive()
                    if message.get("type") == "websocket.disconnect":
                        socket_open = False
                        break
                    text = message.get("text")
                    if text is not None:
                        try:
                            os.write(master_fd, text.encode())
                        except OSError:
                            break
                        continue
                    payload = message.get("bytes")
                    if payload is not None:
                        try:
                            os.write(master_fd, payload)
                        except OSError:
                            break
            except WebSocketDisconnect:
                socket_open = False
            except RuntimeError:
                socket_open = False
            except Exception:  # pragma: no cover - defensive
                socket_open = False

        output_task = asyncio.create_task(_forward_output())
        input_task = asyncio.create_task(_forward_input())
        process_task = asyncio.create_task(process.wait())

        done, pending = await asyncio.wait(
            {output_task, input_task, process_task},
            return_when=asyncio.FIRST_COMPLETED,
        )

        for task in pending:
            task.cancel()

        with contextlib.suppress(Exception):
            await asyncio.gather(*pending, return_exceptions=True)

        if process_task in done:
            exit_code = process_task.result()
        else:
            exit_code = None

        if process.returncode is None:
            with contextlib.suppress(ProcessLookupError, asyncio.TimeoutError):
                process.terminate()
                await asyncio.wait_for(process.wait(), timeout=5)

        with contextlib.suppress(OSError):
            os.close(master_fd)

        try:
            await registry.close_tunnel(
                agent_id=agent_id,
                user_id=user.id,
                session_id=session.session_id,
                token=session.token,
                tunnel_id=str(tunnel_id),
            )
        except PermissionError:  # pragma: no cover - defensive
            logger.warning("User %s is no longer authorised to close tunnel %s", user.id, tunnel_id)
        except KeyError:  # pragma: no cover - defensive
            logger.warning("Tunnel %s vanished before it could be closed", tunnel_id)

        if socket_open:
            close_message = "Terminal session ended." if exit_code == 0 else "Terminal session closed."
            with contextlib.suppress(Exception):
                await websocket.send_text(close_message)
            with contextlib.suppress(Exception):
                await websocket.close()

    @router.post(
        "/hypervisors/{agent_id}/vms/{vm_id}/{action}",
        name="ui_hypervisor_vm_action",
    )
    async def hypervisor_vm_action(agent_id: str, vm_id: str, action: str, request: Request):
        user, _ = _load_user(request)
        if user is None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Authentication required")

        try:
            session = await registry.get_session(agent_id=agent_id, user_id=user.id)
        except KeyError as exc:  # pragma: no cover - defensive
            raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Hypervisor not found") from exc

        if session.expires_at(registry.session_timeout) <= datetime.now(timezone.utc):
            raise HTTPException(status.HTTP_409_CONFLICT, detail="Hypervisor is offline")

        action_key = action.lower()
        supported_actions = {"start", "stop", "restart", "force-stop", "console"}
        if action_key not in supported_actions:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Unsupported action")

        virtual_machines = _parse_virtual_machines(session.metadata)
        target_vm: Optional[VirtualMachineEntry] = None
        for vm in virtual_machines:
            if vm.id == vm_id or vm.name == vm_id:
                target_vm = vm
                break

        logger.info(
            "User %s queued action %s for VM %s on hypervisor %s",
            user.id,
            action_key,
            vm_id,
            agent_id,
        )

        if target_vm is None:
            detail_message = (
                f"Queued {action_key} for {vm_id}. Waiting for the agent to reconcile the VM inventory."
            )
        else:
            detail_message = f"Queued {action_key} for {target_vm.name}."

        return JSONResponse(
            {
                "status": "accepted",
                "action": action_key,
                "vm": target_vm.name if target_vm else vm_id,
                "message": detail_message,
            },
            status_code=status.HTTP_202_ACCEPTED,
        )

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
