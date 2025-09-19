"""Entry point for running the management API and UI on separate ports."""
from __future__ import annotations

import logging
import multiprocessing
import os
import signal
import sys
import threading

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


def _serve(app_path: str, host: str, port: int, reload_enabled: bool, workers: int) -> None:
    uvicorn.run(
        app_path,
        host=host,
        port=port,
        reload=reload_enabled,
        workers=workers,
        factory=True,
    )


def _terminate_process(name: str, process: multiprocessing.Process) -> None:
    if not process.is_alive():
        return
    logger.info("Stopping %s server", name)
    process.terminate()
    process.join(timeout=5)
    if process.is_alive():
        logger.warning("Force killing %s server", name)
        process.kill()
        process.join()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

    host = _env_str("MANAGEMENT_HOST", "0.0.0.0")
    port = _env_int("MANAGEMENT_PORT", 8000)
    api_host = _env_str("MANAGEMENT_API_HOST", host)
    api_port = _env_int("MANAGEMENT_API_PORT", 8001)
    workers = _env_int("MANAGEMENT_WORKERS", 1)
    reload_enabled = _env_flag("MANAGEMENT_RELOAD", False)

    db_path = resolve_database_path(os.getenv("MANAGEMENT_DB_PATH"))
    Database(db_path).initialize()

    stop_event = threading.Event()

    def _handle_signal(signum: int, frame) -> None:  # type: ignore[override]
        logger.info("Received signal %s; shutting down servers", signum)
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, _handle_signal)

    endpoints = [
        ("management", "app.management:create_app", host, port),
        ("api", "app.api:create_app", api_host, api_port),
    ]

    processes: list[tuple[str, str, int, multiprocessing.Process]] = []
    exit_code = 0

    try:
        for name, app_path, listen_host, listen_port in endpoints:
            process = multiprocessing.Process(
                target=_serve,
                args=(app_path, listen_host, listen_port, reload_enabled, workers),
                name=f"{name}-server",
            )
            processes.append((name, listen_host, listen_port, process))
            logger.info("Starting %s server on %s:%d", name, listen_host, listen_port)
            process.start()

        while not stop_event.is_set():
            all_running = True
            for name, listen_host, listen_port, process in processes:
                process.join(timeout=0.5)
                if process.exitcode is not None:
                    all_running = False
                    if process.exitcode != 0:
                        logger.error("%s server exited with code %s", name, process.exitcode)
                        exit_code = process.exitcode if process.exitcode and process.exitcode > 0 else 1
                    else:
                        logger.info("%s server stopped", name)
                    stop_event.set()
                    break
            if not all_running:
                break
    finally:
        stop_event.set()
        for name, _, _, process in processes:
            _terminate_process(name, process)
    sys.exit(exit_code)
