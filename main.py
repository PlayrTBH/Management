"""Entry point for running the combined PlayrServers application."""
from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from typing import Dict

import uvicorn

from app.database import Database, resolve_database_path

logger = logging.getLogger("playrservers.main")

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_CERT_PATH = BASE_DIR / "config" / "tls" / "server.crt"
DEFAULT_KEY_PATH = BASE_DIR / "config" / "tls" / "server.key"


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


def _env_path(name: str, default: Path | None = None) -> Path | None:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        if default is None:
            return None
        raw = str(default)
    path = Path(raw).expanduser()
    return path


def _initialize_database() -> None:
    db_path = resolve_database_path(os.getenv("MANAGEMENT_DB_PATH"))
    Database(db_path).initialize()
    logger.info("Database initialised at %s", db_path)


def _resolve_tls_settings() -> Dict[str, object]:
    if _env_flag("MANAGEMENT_DISABLE_TLS", False):
        logger.warning("TLS has been explicitly disabled; serving the API over HTTP")
        return {}

    cert_path = _env_path("MANAGEMENT_SSL_CERTFILE", DEFAULT_CERT_PATH)
    key_path = _env_path("MANAGEMENT_SSL_KEYFILE", DEFAULT_KEY_PATH)

    if cert_path is None or key_path is None:
        raise SystemExit(
            "TLS is enabled but MANAGEMENT_SSL_CERTFILE and MANAGEMENT_SSL_KEYFILE must be configured"
        )

    if not cert_path.exists():
        raise SystemExit(f"TLS certificate not found: {cert_path}")
    if not key_path.exists():
        raise SystemExit(f"TLS private key not found: {key_path}")

    logger.info("TLS enabled using certificate %s", cert_path)

    tls_settings: Dict[str, object] = {
        "ssl_certfile": str(cert_path),
        "ssl_keyfile": str(key_path),
    }

    password = os.getenv("MANAGEMENT_SSL_KEYFILE_PASSWORD")
    if password:
        tls_settings["ssl_keyfile_password"] = password

    ca_certs = _env_path("MANAGEMENT_SSL_CA_CERTS")
    if ca_certs is not None:
        if not ca_certs.exists():
            raise SystemExit(f"TLS CA bundle not found: {ca_certs}")
        tls_settings["ssl_ca_certs"] = str(ca_certs)

    return tls_settings


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

    host = _env_str("MANAGEMENT_HOST", "0.0.0.0")
    port = _env_int("MANAGEMENT_PORT", 443)
    workers = _env_int("MANAGEMENT_WORKERS", 1)
    reload_enabled = _env_flag("MANAGEMENT_RELOAD", False)

    _initialize_database()

    logger.info("Starting combined management and API server on %s:%d", host, port)

    tls_settings = _resolve_tls_settings()

    uvicorn.run(
        "app:create_application",
        host=host,
        port=port,
        reload=reload_enabled,
        workers=workers,
        factory=True,
        **tls_settings,
    )


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception:  # pragma: no cover - ensures unhandled errors exit cleanly
        logger.exception("Fatal error during startup")
        sys.exit(1)
