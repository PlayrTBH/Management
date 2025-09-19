"""ASGI application entrypoint for PlayrServers."""
from __future__ import annotations

from .application import create_application

app = create_application()

__all__ = ["app", "create_application"]
