"""Application factory that serves both the API and the management UI."""
from __future__ import annotations

import os
from typing import Optional

from fastapi import FastAPI

from .api import create_app as create_api_app
from .database import Database, resolve_database_path
from .management import create_app as create_management_app
from .security import APIKeyAuth


def _resolve_public_api_url() -> str:
    return os.getenv("MANAGEMENT_PUBLIC_API_URL", "https://api.playrservers.com")


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

    management_app = create_management_app(
        database=database,
        api_base_url=_resolve_public_api_url(),
        session_secret=os.getenv("MANAGEMENT_SESSION_SECRET"),
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
