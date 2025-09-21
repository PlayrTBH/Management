from main import _parse_args


def test_default_command_invokes_serve() -> None:
    args = _parse_args([])
    assert args.command == "serve"


def test_default_command_accepts_options_without_subcommand() -> None:
    args = _parse_args(["--host", "127.0.0.1", "--port", "8080"])
    assert args.command == "serve"
    assert args.host == "127.0.0.1"
    assert args.port == 8080


def test_admin_subcommand_still_available() -> None:
    args = _parse_args(["admin"])
    assert args.command == "admin"
