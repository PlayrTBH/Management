import argparse
import getpass
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.database import Database, resolve_database_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Create a PlayrServers management user")
    parser.add_argument("name", help="Display name for the user")
    parser.add_argument("email", help="Unique email address for login")
    parser.add_argument(
        "--db",
        dest="db_path",
        default=None,
        help="Path to the SQLite database (defaults to MANAGEMENT_DB_PATH or data/management.sqlite3)",
    )
    return parser.parse_args()


def prompt_for_password() -> str:
    for _ in range(3):
        password = getpass.getpass("Password: ")
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            print("Passwords do not match. Try again.", file=sys.stderr)
            continue
        if len(password) < 12:
            print("Password must be at least 12 characters long.", file=sys.stderr)
            continue
        return password
    raise SystemExit("Failed to set password after three attempts.")


def main() -> int:
    args = parse_args()
    password = prompt_for_password()

    db_env = args.db_path or os.getenv("MANAGEMENT_DB_PATH")
    db_path = resolve_database_path(db_env)

    database = Database(db_path)
    database.initialize()

    try:
        user = database.create_user(args.name.strip(), args.email.strip().lower(), password)
    except ValueError as exc:  # duplicates, etc.
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print(f"Created user #{user.id}: {user.name} <{user.email}>")
    print("API keys and hypervisor management have been removed; this account stores only login details.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
