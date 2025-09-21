"""Command-line interface for the PlayrServers management service."""

from __future__ import annotations
import argparse
import logging
import os
import shutil
import subprocess
import sys
from getpass import getpass
from pathlib import Path
from typing import Sequence


def _running_in_virtualenv() -> bool:
    """Return ``True`` when the current interpreter is executing inside a venv."""

    base_prefix = getattr(sys, "base_prefix", sys.prefix)
    return sys.prefix != base_prefix


def _bootstrap_virtualenv() -> None:
    """Re-exec the script using the bundled virtualenv interpreter when available."""

    if _running_in_virtualenv():
        return

    root = Path(__file__).resolve().parent
    venv_dir = root / ".venv"
    if not venv_dir.is_dir():
        return

    candidates = (
        venv_dir / "bin" / "python",
        venv_dir / "bin" / "python3",
        venv_dir / "Scripts" / "python.exe",
        venv_dir / "Scripts" / "python",
    )

    script = str(Path(__file__).resolve())
    for candidate in candidates:
        if candidate.exists():
            os.execv(str(candidate), [str(candidate), script, *sys.argv[1:]])


_bootstrap_virtualenv()

try:
    import httpx
except ImportError as exc:  # pragma: no cover - exercised in environments missing deps
    raise SystemExit(
        "The 'httpx' package is required. Re-run scripts/install_service.py or "
        "execute `pip install -r requirements.txt` to install dependencies."
    ) from exc

from app.database import Database, resolve_database_path

logger = logging.getLogger("playrservers.main")

_DEFAULT_SERVICE_URL = "https://localhost"
SYSTEMD_SERVICE_NAME = "playr-management"


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="PlayrServers management utilities")
    subparsers = parser.add_subparsers(dest="command")

    parser.set_defaults(command="serve")

    subparsers.add_parser("init-db", help="Initialise the management database")

    serve_parser = subparsers.add_parser("serve", help="Start the HTTP management service")
    serve_parser.add_argument("--host", default="0.0.0.0", help="Bind address for the API")
    serve_parser.add_argument(
        "--port",
        type=int,
        default=443,
        help="Port for the HTTPS API (default: 443)",
    )
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
    serve_parser.add_argument(
        "--ssl-certfile",
        default=None,
        help="Path to the TLS certificate chain in PEM format",
    )
    serve_parser.add_argument(
        "--ssl-keyfile",
        default=None,
        help="Path to the TLS private key in PEM format",
    )
    serve_parser.add_argument(
        "--ssl-keyfile-password",
        default=None,
        help="Password for the TLS private key, if encrypted",
    )

    admin_parser = subparsers.add_parser(
        "admin", help="Launch the interactive administration console"
    )
    admin_parser.add_argument(
        "--service-url",
        default=None,
        help="Base URL of a running management service (default: https://localhost)",
    )
    admin_parser.add_argument(
        "--hypervisor-email",
        default=None,
        help=(
            "Account email whose paired hypervisors should be listed by the admin console. "
            "Defaults to the MANAGEMENT_CLI_EMAIL environment variable when unset."
        ),
    )

    args_list = list(argv) if argv is not None else sys.argv[1:]
    known_commands = {"serve", "admin", "init-db"}

    if not args_list:
        args_list = ["serve"]
    else:
        first = args_list[0]
        if first in ("-h", "--help"):
            return parser.parse_args(args_list)
        if first not in known_commands:
            if any(flag in args_list for flag in ("-h", "--help")):
                return parser.parse_args(args_list)
            args_list = ["serve", *args_list]

    return parser.parse_args(args_list)


def _project_root() -> Path:
    return Path(__file__).resolve().parent


def _systemctl_path() -> str | None:
    return shutil.which("systemctl")


def _run_systemctl(*args: str) -> None:
    systemctl = _systemctl_path()
    if not systemctl:
        print("systemctl not available; skipping:", "systemctl", *args)
        return

    result = subprocess.run([systemctl, *args], check=False)
    if result.returncode != 0:
        print(
            f"systemctl {' '.join(args)} exited with status {result.returncode}.",
        )


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
    ssl_certfile: str | None,
    ssl_keyfile: str | None,
    ssl_keyfile_password: str | None,
) -> None:
    from app.service import create_app
    import uvicorn

    if bool(ssl_certfile) ^ bool(ssl_keyfile):
        raise SystemExit("Both --ssl-certfile and --ssl-keyfile must be provided together.")

    protocol = "https" if ssl_certfile and ssl_keyfile else "http"
    logger.info("Starting management API on %s://%s:%s", protocol, host, port)

    app = create_app(
        database=database,
        tunnel_host=tunnel_host,
        tunnel_port=tunnel_port,
    )
    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level="info",
        ssl_certfile=ssl_certfile,
        ssl_keyfile=ssl_keyfile,
        ssl_keyfile_password=ssl_keyfile_password,
    )


def _run_admin_cli(
    database: Database,
    *,
    default_service_url: str | None = None,
    hypervisor_email: str | None = None,
) -> None:
    """Provide an interactive management console for administrators."""

    service_url = default_service_url or _DEFAULT_SERVICE_URL

    print("PlayrServers Management Administration Console")
    print("Press Ctrl+C at any time to exit.\n")

    try:
        while True:
            print("Select an option:")
            print("  1) List all users")
            print("  2) Add a new user")
            print("  3) Show paired hypervisors")
            print("  4) Run automated tests")
            print("  5) View recent service logs")
            print("  6) Update service from upstream repository")
            print("  7) Exit")

            choice = input("Enter choice [1-7]: ").strip()

            if choice == "1":
                _list_users(database)
            elif choice == "2":
                _add_user(database)
            elif choice == "3":
                service_url = _show_hypervisors(
                    service_url, default_email=hypervisor_email
                )
            elif choice == "4":
                _run_tests()
            elif choice == "5":
                _view_logs()
            elif choice == "6":
                _update_service()
            elif choice == "7":
                print("Goodbye!")
                return
            else:
                print("Invalid selection. Please choose a number from the menu.\n")

            print()
    except KeyboardInterrupt:
        print("\nExiting administration console.")


def _list_users(database: Database) -> None:
    users = database.list_users()
    if not users:
        print("No users are currently registered.")
        return

    print(f"{len(users)} user(s) found:")
    print(f"{'ID':>4}  {'Name':<24}  {'Email':<32}  Created")
    print("-" * 80)
    for user in users:
        created = user.created_at.strftime("%Y-%m-%d %H:%M:%S %Z")
        email = user.email or "<no email>"
        print(f"{user.id:>4}  {user.name:<24}  {email:<32}  {created}")


def _add_user(database: Database) -> None:
    print("\nCreate a new user (leave the name blank to cancel).")
    name = input("Name: ").strip()
    if not name:
        print("User creation cancelled.")
        return

    email = input("Email address: ").strip() or None

    password = _prompt_for_password()
    if password is None:
        print("Aborted creating user.")
        return

    try:
        user = database.create_user(name, email, password)
    except ValueError as exc:
        print(f"Failed to create user: {exc}")
        return

    print(f"Created user #{user.id}: {user.name} <{user.email or 'no email set'}>")


def _prompt_for_password() -> str | None:
    for _ in range(3):
        password = getpass("Password (min 12 characters): ")
        if len(password) < 12:
            print("Password is too short. Please try again.")
            continue
        confirmation = getpass("Confirm password: ")
        if password != confirmation:
            print("Passwords do not match. Please try again.")
            continue
        return password
    return None


def _show_hypervisors(default_url: str, *, default_email: str | None = None) -> str:
    base_url = default_url or _DEFAULT_SERVICE_URL

    email = default_email or os.getenv("MANAGEMENT_CLI_EMAIL")
    if not email:
        print(
            "No management account email configured. Provide --hypervisor-email when launching "
            "the admin console or set the MANAGEMENT_CLI_EMAIL environment variable."
        )
        return base_url

    password = os.getenv("MANAGEMENT_CLI_PASSWORD")
    if not password:
        print(
            "No management account password available. Set the MANAGEMENT_CLI_PASSWORD "
            "environment variable before running this command."
        )
        return base_url

    endpoint = base_url.rstrip("/") + "/v1/agents"

    try:
        response = httpx.get(endpoint, auth=(email, password), timeout=10.0)
    except httpx.HTTPError as exc:
        print(f"Failed to contact management service: {exc}")
        return base_url

    if response.status_code == 401:
        print(
            "Authentication failed when querying the management service. Verify the "
            "configured credentials."
        )
        return base_url
    if response.status_code != 200:
        print(f"Service responded with {response.status_code}: {response.text.strip()}")
        return base_url

    try:
        payload = response.json()
    except ValueError:
        print("Service returned an unexpected response format.")
        return base_url
    agents = payload.get("agents", [])

    if not agents:
        print(f"No hypervisors are currently paired with {email}.")
        return base_url

    print(f"Found {len(agents)} paired hypervisor(s) for {email}:")
    for agent in agents:
        agent_id = agent.get("agent_id", "unknown-agent")
        hostname = agent.get("hostname", "unknown-host")
        last_seen = agent.get("last_seen", "unknown time")
        endpoint_info = agent.get("tunnel_endpoint", {})
        host = endpoint_info.get("host", "?")
        port = endpoint_info.get("port", "?")
        print(f"- {agent_id} ({hostname}) -> {host}:{port} (last seen {last_seen})")

    return base_url


def _run_tests() -> None:
    print("Running test suite using pytest...\n")
    result = subprocess.run(["pytest"], cwd=_project_root(), check=False)
    if result.returncode == 0:
        print("All tests completed successfully.")
    else:
        print(f"Tests exited with status code {result.returncode}.")


def _view_logs() -> None:
    journalctl_path = shutil.which("journalctl")
    if not journalctl_path:
        print("journalctl is not available on this system. Unable to display service logs.")
        return

    command = [
        journalctl_path,
        "-u",
        SYSTEMD_SERVICE_NAME,
        "-n",
        "20",
        "--no-pager",
    ]

    print(f"Collecting the last 20 log entries for {SYSTEMD_SERVICE_NAME}...")
    result = subprocess.run(command, capture_output=True, text=True, check=False)

    if result.returncode != 0:
        stderr = result.stderr.strip() or "journalctl exited with an error."
        print(stderr)
        return

    output = result.stdout.strip()
    if not output:
        print("No log entries were returned by journalctl.")
        return

    print(output)


def _update_service() -> None:
    print("Fetching latest changes from upstream repository...\n")
    result = subprocess.run(["git", "pull", "--ff-only"], cwd=_project_root(), check=False)
    if result.returncode != 0:
        print("git pull failed. Please resolve the issues above and try again.")
        return

    print("Repository is up to date.\n")

    installer = _project_root() / "scripts" / "install_service.py"
    if installer.exists():
        print("Re-applying installer to refresh dependencies and service configuration...\n")
        install_result = subprocess.run(
            [sys.executable, str(installer)],
            cwd=_project_root(),
            check=False,
        )
        if install_result.returncode != 0:
            print(
                "Installer exited with a non-zero status. Review the output above and try again.",
            )
            return
    else:
        print("Installer script not found; restarting service directly.")
        _run_systemctl("daemon-reload")
        _run_systemctl("restart", SYSTEMD_SERVICE_NAME)
        return

    _run_systemctl("restart", SYSTEMD_SERVICE_NAME)
    print("Service update complete.")


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
            ssl_certfile=args.ssl_certfile,
            ssl_keyfile=args.ssl_keyfile,
            ssl_keyfile_password=args.ssl_keyfile_password,
        )
    elif args.command == "admin":
        _run_admin_cli(
            database,
            default_service_url=args.service_url,
            hypervisor_email=getattr(args, "hypervisor_email", None),
        )
    elif args.command == "init-db":
        print("Database initialisation complete.")


if __name__ == "__main__":
    main()
