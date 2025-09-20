"""Application factory that serves both the API and the management UI."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Optional, Tuple

from fastapi import FastAPI

from .api import create_app as create_api_app
from .database import Database, resolve_database_path
from .management import create_app as create_management_app
from .security import APIKeyAuth


def _resolve_public_api_url() -> str:
    return os.getenv("MANAGEMENT_PUBLIC_API_URL", "https://api.playrservers.com")


def _env_flag(value: Optional[str], default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _parse_verify_setting(value: str) -> Optional[str | bool]:
    lowered = value.strip().lower()
    if lowered in {"", "default"}:
        return None
    if lowered in {"0", "false", "no", "off"}:
        return False
    if lowered in {"1", "true", "yes", "on"}:
        return True
    path = Path(value).expanduser()
    return str(path)


def _resolve_internal_api_settings() -> Tuple[Optional[str], Optional[str | bool]]:
    custom_base = os.getenv("MANAGEMENT_INTERNAL_API_URL")
    verify_setting = os.getenv("MANAGEMENT_INTERNAL_API_VERIFY")

    if custom_base:
        cleaned = custom_base.strip().rstrip("/")
        verify = _parse_verify_setting(verify_setting) if verify_setting else None
        return cleaned or None, verify

    port = int(os.getenv("MANAGEMENT_PORT", "443"))
    disable_tls = _env_flag(os.getenv("MANAGEMENT_DISABLE_TLS"), False)
    scheme = "http" if disable_tls else "https"
    host = os.getenv("MANAGEMENT_INTERNAL_API_HOST", "127.0.0.1").strip() or "127.0.0.1"

    base_url = f"{scheme}://{host}:{port}/api"

    if disable_tls:
        return base_url, None

    cert_path = os.getenv("MANAGEMENT_SSL_CERTFILE")
    if cert_path:
        candidate = Path(cert_path).expanduser()
    else:
        project_root = Path(__file__).resolve().parent.parent
        candidate = project_root / "config" / "tls" / "server.crt"

    verify: str | bool
    if candidate.exists():
        verify = str(candidate)
    else:
        verify = False

    return base_url, verify


def create_application(
    *,
    database_path: Optional[str] = None,
) -> FastAPI:
    """Create the combined ASGI application."""

    db_path = resolve_database_path(database_path or os.getenv("MANAGEMENT_DB_PATH"))
    database = Database(db_path)
    database.initialize()

    api_auth = APIKeyAuth(database)
    api_app = create_api_app(database=database, auth=api_auth)

    internal_api_base_url, internal_api_verify = _resolve_internal_api_settings()

    management_app = create_management_app(
        database=database,
        api_base_url=_resolve_public_api_url(),
        session_secret=os.getenv("MANAGEMENT_SESSION_SECRET"),
        internal_api_base_url=internal_api_base_url,
        internal_api_verify=internal_api_verify,
    )

    app = FastAPI(
        title="PlayrServers Control Plane",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.database = database
    app.state.api = api_app
    app.state.management = management_app

    app.mount("/api", api_app)
    app.mount("/", management_app)

    return app


__all__ = ["create_application"]
