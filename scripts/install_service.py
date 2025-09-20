#!/usr/bin/env python3
"""Installer for the PlayrServers management service."""

from __future__ import annotations

import argparse
import contextlib
import getpass
import os
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Sequence, TextIO

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


@contextlib.contextmanager
def _temporary_stdio(stdin: TextIO | None, stdout: TextIO | None):
    """Temporarily replace ``sys.stdin`` and ``sys.stdout``."""

    original_stdin, original_stdout = sys.stdin, sys.stdout
    try:
        if stdin is not None:
            sys.stdin = stdin
        if stdout is not None:
            sys.stdout = stdout
        yield
    finally:
        sys.stdin = original_stdin
        sys.stdout = original_stdout


def _prompt_input(
    prompt: str,
    *,
    stdin: TextIO | None = None,
    stdout: TextIO | None = None,
    password: bool = False,
) -> str:
    """Invoke ``input``/``getpass`` using optional replacement streams."""

    func = getpass.getpass if password else input
    if stdin is None and stdout is None:
        return func(prompt)

    with _temporary_stdio(stdin, stdout):
        return func(prompt)


def _print_prompt_message(message: str, stdout: TextIO | None) -> None:
    """Print a message to the prompt stream (and log to stdout when different)."""

    if stdout is None or stdout is sys.stdout:
        print(message, flush=True)
        return

    print(message, file=stdout, flush=True)
    print(message, flush=True)


@contextlib.contextmanager
def _interactive_prompt_io() -> tuple[TextIO | None, TextIO | None]:
    """Provide streams suitable for prompting the user.

    When the current standard input/output are already interactive, ``None`` is
    yielded for both streams so that the default ``input``/``print`` behaviour is
    preserved. Otherwise a handle to the controlling terminal is opened to allow
    interactive prompting even though ``sys.stdin`` is not a TTY.
    """

    if sys.stdin.isatty() and sys.stdout.isatty():
        yield None, None
        return

    tty_path = "CONIN$" if os.name == "nt" else "/dev/tty"
    try:
        if os.name == "nt":
            tty_in = open(tty_path, "r", encoding="utf-8", buffering=1)
            tty_out = open("CONOUT$", "w", encoding="utf-8", buffering=1)
        else:
            # ``/dev/tty`` is not seekable which makes opening it in read/write mode
            # with ``open(..., "r+")`` unsuitable – the ``io`` module requires a
            # seekable file object for ``r+`` and raises ``OSError`` otherwise.
            # Use separate read/write handles instead so that interactive prompts
            # continue to function even when ``sys.stdin``/``stdout`` are redirected
            # (for example when running the installer via a shell pipeline).
            tty_in = open(tty_path, "r", encoding="utf-8", buffering=1)
            tty_out = open(tty_path, "w", encoding="utf-8", buffering=1)
    except OSError as exc:
        # Fall back to the existing standard streams when a controlling terminal
        # is unavailable (e.g. when the installer runs inside a pipeline or
        # container without a dedicated TTY). ``input``/``getpass`` can still
        # consume from ``sys.stdin`` in these environments, so allow the prompts
        # to proceed rather than aborting the installation.
        if getattr(sys.stdin, "closed", False) or getattr(sys.stdout, "closed", False):
            raise UserInputError(
                "Unable to prompt for initial user details because a controlling terminal "
                "could not be accessed. Re-run the installer with --admin-name, "
                "--admin-email, and --admin-password."
            ) from exc

        yield sys.stdin, sys.stdout
        return

    try:
        yield tty_in, tty_out
    finally:
        tty_in.close()
        if tty_out is not tty_in:
            tty_out.close()


def prompt_for_non_empty(
    prompt: str, *, stdin: TextIO | None = None, stdout: TextIO | None = None
) -> str:
    while True:
        try:
            value = _prompt_input(prompt, stdin=stdin, stdout=stdout)
        except EOFError as exc:
            raise UserInputError("Input stream closed while waiting for a response.") from exc

        value = value.strip()
        if value:
            return value
        _print_prompt_message("Value must not be empty. Please try again.", stdout)


def prompt_for_password(
    *, stdin: TextIO | None = None, stdout: TextIO | None = None
) -> str:
    while True:
        try:
            password = _prompt_input(
                "Password (minimum 12 characters): ",
                stdin=stdin,
                stdout=stdout,
                password=True,
            )
            confirm = _prompt_input(
                "Confirm password: ",
                stdin=stdin,
                stdout=stdout,
                password=True,
            )
        except EOFError as exc:
            raise UserInputError("Input stream closed while reading the password.") from exc
        if password != confirm:
            _print_prompt_message("Passwords do not match. Please try again.", stdout)
            continue
        if len(password) < 12:
            _print_prompt_message("Password must be at least 12 characters long.", stdout)
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

    with _interactive_prompt_io() as (prompt_stdin, prompt_stdout):
        _print_prompt_message(
            "\nNo users were found in the database. Let's create the first account.",
            prompt_stdout,
        )
        while True:
            name = prompt_for_non_empty(
                "Display name: ", stdin=prompt_stdin, stdout=prompt_stdout
            )
            email = (
                prompt_for_non_empty(
                    "Email address (used for login): ",
                    stdin=prompt_stdin,
                    stdout=prompt_stdout,
                ).lower()
            )

            if database.get_user_by_email(email):
                _print_prompt_message(
                    "A user with that email already exists. Please choose a different "
                    "email address.",
                    prompt_stdout,
                )
                continue

            password = prompt_for_password(
                stdin=prompt_stdin, stdout=prompt_stdout
            )

            try:
                user = database.create_user(name, email, password)
            except ValueError as exc:
                _print_prompt_message(f"Failed to create user: {exc}", prompt_stdout)
                continue

            _print_prompt_message(
                f"\nCreated user #{user.id}: {user.name} <{user.email}>", prompt_stdout
            )
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
