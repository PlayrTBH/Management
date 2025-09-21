"""Core utilities for the PlayrServers management rewrite."""

from __future__ import annotations

from typing import Any

from .database import Database, resolve_database_path


def create_app(*args: Any, **kwargs: Any):
    """Factory function that returns the combined web + API application."""

    from .service import create_app as _create_app

    return _create_app(*args, **kwargs)


__all__ = ["Database", "resolve_database_path", "create_app"]
