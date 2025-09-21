"""Core utilities for the PlayrServers management rewrite."""

from __future__ import annotations

from typing import Any

from .database import Database, resolve_database_path


def create_app(*args: Any, **kwargs: Any):
    """Factory function that returns the combined web + API application."""

    from .service import create_app as _create_app

    return _create_app(*args, **kwargs)


def create_api_app(*args: Any, **kwargs: Any):
    """Factory function for the API-only application."""

    from .service import create_api_app as _create_api_app

    return _create_api_app(*args, **kwargs)


def create_web_app(*args: Any, **kwargs: Any):
    """Factory function for the web-only application."""

    from .service import create_web_app as _create_web_app

    return _create_web_app(*args, **kwargs)


__all__ = [
    "Database",
    "resolve_database_path",
    "create_app",
    "create_api_app",
    "create_web_app",
]
