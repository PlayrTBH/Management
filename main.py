"""Utility entry point for preparing the management database."""

from __future__ import annotations

import logging
import os

from app.database import Database, resolve_database_path

logger = logging.getLogger("playrservers.main")


def main() -> None:
    """Initialise the SQLite database and exit."""

    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

    db_path = resolve_database_path(os.getenv("MANAGEMENT_DB_PATH"))
    Database(db_path).initialize()
    logger.info("Database initialised at %s", db_path)

    logger.warning(
        "The HTTP API and management interface have been removed. "
        "This command now only prepares the database for future development."
    )


if __name__ == "__main__":
    main()
