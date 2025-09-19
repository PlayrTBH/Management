"""ASGI application entrypoint for PlayrServers.

The CLI utilities import :mod:`app` in order to reach the database layer, but
those hosts might not have the FastAPI dependency installed. Importing the
package should therefore succeed even when ``fastapi`` is missing; the ASGI app
is only instantiated when the dependency is available.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:  # pragma: no cover - used only for typing
    from fastapi import FastAPI


def create_application(*args, **kwargs):
    """Import the factory lazily so CLI imports do not require FastAPI."""

    from .application import create_application as factory

    return factory(*args, **kwargs)


try:
    app: Optional["FastAPI"] = create_application()
except ModuleNotFoundError as exc:
    if exc.name != "fastapi":
        raise
    # FastAPI is not installed; CLI utilities can still import app.database.
    app = None


__all__ = ["app", "create_application"]
