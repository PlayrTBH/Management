"""Entry point for running the management API."""
from __future__ import annotations

import os

import uvicorn


def _env_flag(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


if __name__ == "__main__":
    host = os.getenv("MANAGEMENT_HOST", "0.0.0.0")
    port = int(os.getenv("MANAGEMENT_PORT", "8000"))
    workers = int(os.getenv("MANAGEMENT_WORKERS", "1"))
    reload = _env_flag("MANAGEMENT_RELOAD", False)
    uvicorn.run("app.api:app", host=host, port=port, reload=reload, workers=workers)
