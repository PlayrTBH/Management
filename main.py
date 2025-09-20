"""Entry point for running the combined PlayrServers application."""
from __future__ import annotations

import logging
import os
import sys

import uvicorn

from app.database import Database, resolve_database_path

logger = logging.getLogger("playrservers.main")


def _env_flag(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_str(name: str, default: str) -> str:
    value = os.getenv(name)
    if value is None:
        return default
    stripped = value.strip()
    return stripped or default


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw)
    except ValueError as exc:  # pragma: no cover - guards against misconfiguration
        raise SystemExit(f"{name} must be an integer (got {raw!r})") from exc


def _initialize_database() -> None:
    db_path = resolve_database_path(os.getenv("MANAGEMENT_DB_PATH"))
    Database(db_path).initialize()
    logger.info("Database initialised at %s", db_path)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

    host = _env_str("MANAGEMENT_HOST", "0.0.0.0")
    port = _env_int("MANAGEMENT_PORT", 443)
    workers = _env_int("MANAGEMENT_WORKERS", 1)
    reload_enabled = _env_flag("MANAGEMENT_RELOAD", False)

    _initialize_database()

    logger.info("Starting combined management and API server on %s:%d", host, port)
    uvicorn.run(
        "app:create_application",
        host=host,
        port=port,
        reload=reload_enabled,
        workers=workers,
        factory=True,
    )


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception:  # pragma: no cover - ensures unhandled errors exit cleanly
        logger.exception("Fatal error during startup")
        sys.exit(1)
