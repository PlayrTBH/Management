"""Command-line interface for the PlayrServers management service."""

from __future__ import annotations

import argparse
import logging
import os
from typing import Sequence

from app.database import Database, resolve_database_path

logger = logging.getLogger("playrservers.main")


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="PlayrServers management utilities")
    subparsers = parser.add_subparsers(dest="command")

    parser.set_defaults(command="init-db")

    subparsers.add_parser("init-db", help="Initialise the management database")

    serve_parser = subparsers.add_parser("serve", help="Start the HTTP management service")
    serve_parser.add_argument("--host", default="0.0.0.0", help="Bind address for the API")
    serve_parser.add_argument("--port", type=int, default=8000, help="Port for the API")
    serve_parser.add_argument(
        "--tunnel-host",
        default=None,
        help="Override the public hostname advertised to agents",
    )
    serve_parser.add_argument(
        "--tunnel-port",
        type=int,
        default=None,
        help="Override the public port advertised to agents",
    )

    return parser.parse_args(argv)


def _initialise_database() -> Database:
    db_path = resolve_database_path(os.getenv("MANAGEMENT_DB_PATH"))
    database = Database(db_path)
    database.initialize()
    logger.info("Database initialised at %s", db_path)
    return database


def _serve(
    *,
    database: Database,
    host: str,
    port: int,
    tunnel_host: str | None,
    tunnel_port: int | None,
) -> None:
    from app.service import create_app
    import uvicorn

    logger.info("Starting management API on %s:%s", host, port)

    app = create_app(
        database=database,
        tunnel_host=tunnel_host,
        tunnel_port=tunnel_port,
    )
    uvicorn.run(app, host=host, port=port, log_level="info")


def main(argv: Sequence[str] | None = None) -> None:
    """Entry point for CLI usage."""

    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

    args = _parse_args(argv)
    database = _initialise_database()

    if args.command == "serve":
        _serve(
            database=database,
            host=args.host,
            port=args.port,
            tunnel_host=args.tunnel_host,
            tunnel_port=args.tunnel_port,
        )


if __name__ == "__main__":
    main()
