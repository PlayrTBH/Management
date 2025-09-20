"""Generate API keys for authenticating hypervisor agents."""

from __future__ import annotations

import argparse
import sys

from app.database import Database, resolve_database_path


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Create a PlayrServers API key")
    parser.add_argument("email", help="Email address of the user who will own the key")
    parser.add_argument(
        "--name",
        default="Hypervisor agent",
        help="Friendly name for the API key (default: Hypervisor agent)",
    )
    parser.add_argument(
        "--db-path",
        default=None,
        help="Override the database location (defaults to MANAGEMENT_DB_PATH or the repository data directory)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(list(argv) if argv is not None else None)

    db_path = resolve_database_path(args.db_path)
    database = Database(db_path)
    database.initialize()

    user = database.get_user_by_email(args.email)
    if user is None:
        print(f"No user with email {args.email!r} found in {db_path}", file=sys.stderr)
        return 1

    api_key = database.create_api_key(user.id, args.name)
    print("Generated API key:")
    print(api_key)
    print("\nStore this value securely; it will not be shown again.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
