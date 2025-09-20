#!/usr/bin/env python3
"""Installer for the PlayrServers management service."""

from __future__ import annotations

import argparse
import getpass
import os
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Sequence

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.database import Database, resolve_database_path


class UserInputError(RuntimeError):
    """Raised when the installer cannot obtain interactive user input."""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Install and bootstrap the management service")
    parser.add_argument(
        "--db",
        dest="db_path",
        default=None,
        help="Path to the SQLite database (defaults to MANAGEMENT_DB_PATH or data/management.sqlite3)",
    )
    parser.add_argument(
        "--skip-deps",
        action="store_true",
        help="Skip installing Python dependencies via pip",
    )
    parser.add_argument(
        "--pip-extra-args",
        default="",
        help=(
            "Additional arguments forwarded to `pip install -r requirements.txt`. "
            "Provide them as a quoted string, e.g. --pip-extra-args='--proxy=http://proxy:3128'"
        ),
    )
    parser.add_argument(
        "--admin-name",
        dest="admin_name",
        default=None,
        help="Display name for the initial administrator account (non-interactive mode)",
    )
    parser.add_argument(
        "--admin-email",
        dest="admin_email",
        default=None,
        help="Email address for the initial administrator account (non-interactive mode)",
    )
    parser.add_argument(
        "--admin-password",
        dest="admin_password",
        default=None,
        help="Password for the initial administrator account (non-interactive mode)",
    )
    return parser.parse_args()


def run_command(command: Sequence[str]) -> None:
    printable = " ".join(shlex.quote(part) for part in command)
    print(f"-> {printable}")
    subprocess.check_call(command)


def install_dependencies(extra_args: Sequence[str]) -> None:
    requirements = ROOT / "requirements.txt"
    if not requirements.exists():
        print("No requirements.txt found; skipping dependency installation.")
        return

    command = [sys.executable, "-m", "pip", "install", "-r", str(requirements)]
    if extra_args:
        command.extend(extra_args)

    print("Installing Python dependencies...")
    run_command(command)


def initialise_database(db_path_arg: str | None) -> tuple[Database, Path]:
    db_env = db_path_arg or os.getenv("MANAGEMENT_DB_PATH")
    resolved_path = resolve_database_path(db_env)
    database = Database(resolved_path)
    database.initialize()
    print(f"Database initialised at {resolved_path}")
    return database, resolved_path


def prompt_for_non_empty(prompt: str) -> str:
    while True:
        try:
            value = input(prompt)
        except EOFError as exc:
            raise UserInputError("Input stream closed while waiting for a response.") from exc

        value = value.strip()
        if value:
            return value
        print("Value must not be empty. Please try again.")


def prompt_for_password() -> str:
    while True:
        try:
            password = getpass.getpass("Password (minimum 12 characters): ")
            confirm = getpass.getpass("Confirm password: ")
        except EOFError as exc:
            raise UserInputError("Input stream closed while reading the password.") from exc
        if password != confirm:
            print("Passwords do not match. Please try again.")
            continue
        if len(password) < 12:
            print("Password must be at least 12 characters long.")
            continue
        return password


def _normalize_cli_user_details(
    name: str | None, email: str | None, password: str | None
) -> tuple[str, str, str] | None:
    """Validate and normalise CLI-supplied user details."""

    if name is None and email is None and password is None:
        return None

    pairs = (("name", name), ("email", email), ("password", password))
    missing = [field for field, value in pairs if value is None]
    if missing:
        missing_fields = ", ".join(f"--admin-{field}" for field in missing)
        raise ValueError(
            "All of --admin-name, --admin-email, and --admin-password must be provided together. "
            f"Missing {missing_fields}."
        )

    normalized_name = name.strip() if name else ""
    normalized_email = email.strip().lower() if email else ""
    if not normalized_name:
        raise ValueError("--admin-name must not be empty")
    if not normalized_email:
        raise ValueError("--admin-email must not be empty")
    if password is None or len(password) < 12:
        raise ValueError("--admin-password must be at least 12 characters long")

    return normalized_name, normalized_email, password


def create_initial_user(
    database: Database,
    *,
    admin_name: str | None = None,
    admin_email: str | None = None,
    admin_password: str | None = None,
) -> None:
    if database.has_users():
        print("Existing users detected; skipping initial user creation.")
        return

    cli_user = _normalize_cli_user_details(admin_name, admin_email, admin_password)
    if cli_user is not None:
        name, email, password = cli_user
        try:
            user = database.create_user(name, email, password)
        except ValueError as exc:
            raise ValueError(f"Failed to create user: {exc}") from exc

        print(f"\nCreated user #{user.id}: {user.name} <{user.email}>")
        return

    print("\nNo users were found in the database. Let's create the first account.")
    if not sys.stdin.isatty():
        raise UserInputError(
            "Unable to prompt for initial user details because standard input is not interactive. "
            "Re-run the installer with --admin-name, --admin-email, and --admin-password.",
        )
    while True:
        name = prompt_for_non_empty("Display name: ")
        email = prompt_for_non_empty("Email address (used for login): ").lower()

        if database.get_user_by_email(email):
            print("A user with that email already exists. Please choose a different email address.")
            continue

        password = prompt_for_password()

        try:
            user = database.create_user(name, email, password)
        except ValueError as exc:
            print(f"Failed to create user: {exc}")
            continue

        print(f"\nCreated user #{user.id}: {user.name} <{user.email}>")
        break


def main() -> int:
    args = parse_args()
    pip_args = shlex.split(args.pip_extra_args) if args.pip_extra_args else []

    try:
        if not args.skip_deps:
            install_dependencies(pip_args)
        database, db_path = initialise_database(args.db_path)
        create_initial_user(
            database,
            admin_name=args.admin_name,
            admin_email=args.admin_email,
            admin_password=args.admin_password,
        )
    except subprocess.CalledProcessError as exc:
        cmd = exc.cmd
        if isinstance(cmd, (list, tuple)):
            cmd_display = " ".join(shlex.quote(str(part)) for part in cmd)
        else:
            cmd_display = str(cmd)
        print(f"Command failed with exit code {exc.returncode}: {cmd_display}", file=sys.stderr)
        return exc.returncode or 1
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except UserInputError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nInstallation aborted by user.")
        return 1

    print("\nInstallation complete!\n")
    print("Next steps:")
    service_entry = ROOT / "main.py"
    start_command = f"python {service_entry} serve --host 0.0.0.0 --port 8000"
    print(f"  • Start the API with: {start_command}")
    print(f"  • Database stored at: {db_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
