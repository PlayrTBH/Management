"""Tests for the non-interactive installer helpers."""

from __future__ import annotations

import contextlib
import io

import pytest

from app.database import Database
from scripts.install_service import (
    UserInputError,
    create_initial_user,
    ensure_required_packages_installed,
    prompt_for_non_empty,
    _interactive_prompt_io,
)


def _initialised_database(tmp_path):
    db_path = tmp_path / "installer.sqlite3"
    database = Database(db_path)
    database.initialize()
    return database


def test_create_initial_user_cli_arguments(tmp_path):
    database = _initialised_database(tmp_path)

    create_initial_user(
        database,
        admin_name="Service Admin",
        admin_email="ADMIN@example.com",
        admin_password="supersecurepw",
    )

    stored = database.get_user_by_email("admin@example.com")
    assert stored is not None
    assert stored.name == "Service Admin"


def test_create_initial_user_cli_missing_field(tmp_path):
    database = _initialised_database(tmp_path)

    with pytest.raises(ValueError):
        create_initial_user(
            database,
            admin_name="Service Admin",
            admin_password="anothersecurepw",
        )


def test_create_initial_user_cli_short_password(tmp_path):
    database = _initialised_database(tmp_path)

    with pytest.raises(ValueError):
        create_initial_user(
            database,
            admin_name="Service Admin",
            admin_email="admin@example.com",
            admin_password="short",
        )


def test_create_initial_user_prompts_when_stdin_not_interactive(tmp_path, monkeypatch):
    database = _initialised_database(tmp_path)

    monkeypatch.setattr("scripts.install_service.sys.stdin.isatty", lambda: False)

    prompts = iter([
        "Service Admin",
        "admin@example.com",
    ])
    passwords = iter(["supersecurepw"])

    captured_calls = []

    def fake_prompt_for_non_empty(prompt, *, stdin=None, stdout=None):  # pragma: no cover - exercised in test
        captured_calls.append((stdin, stdout))
        return next(prompts)

    def fake_prompt_for_password(*, stdin=None, stdout=None):  # pragma: no cover - exercised in test
        captured_calls.append((stdin, stdout))
        return next(passwords)

    monkeypatch.setattr("scripts.install_service.prompt_for_non_empty", fake_prompt_for_non_empty)
    monkeypatch.setattr("scripts.install_service.prompt_for_password", fake_prompt_for_password)

    fake_stdin = object()
    fake_stdout = io.StringIO()

    @contextlib.contextmanager
    def fake_prompt_io():
        yield fake_stdin, fake_stdout

    monkeypatch.setattr("scripts.install_service._interactive_prompt_io", fake_prompt_io)

    create_initial_user(database)

    stored = database.get_user_by_email("admin@example.com")
    assert stored is not None
    assert stored.name == "Service Admin"
    assert all(call == (fake_stdin, fake_stdout) for call in captured_calls)


def test_prompt_for_non_empty_eof(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda _: (_ for _ in ()).throw(EOFError()))

    with pytest.raises(UserInputError):
        prompt_for_non_empty("Display name: ")


def test_interactive_prompt_io_falls_back_to_standard_streams(monkeypatch):

    class FakeStream(io.StringIO):
        def isatty(self):
            return False

    fake_stdin = FakeStream()
    fake_stdout = FakeStream()

    def fake_open(*_args, **_kwargs):  # pragma: no cover - simple fallback path
        raise OSError("no controlling terminal")

    monkeypatch.setattr("scripts.install_service.sys.stdin", fake_stdin)
    monkeypatch.setattr("scripts.install_service.sys.stdout", fake_stdout)
    monkeypatch.setattr("scripts.install_service.open", fake_open, raising=False)

    with _interactive_prompt_io() as (stdin, stdout):
        assert stdin is fake_stdin
        assert stdout is fake_stdout


def test_ensure_required_packages_installed_success(monkeypatch):

    imported = []

    def fake_import(name):
        imported.append(name)
        return object()

    monkeypatch.setattr("scripts.install_service.importlib.import_module", fake_import)

    ensure_required_packages_installed(["fastapi", "uvicorn"])
    assert imported == ["fastapi", "uvicorn"]


def test_ensure_required_packages_installed_missing(monkeypatch):

    def fake_import(name):
        if name == "uvicorn":
            raise ImportError("No module named 'uvicorn'")
        return object()

    monkeypatch.setattr("scripts.install_service.importlib.import_module", fake_import)

    with pytest.raises(RuntimeError) as excinfo:
        ensure_required_packages_installed(["fastapi", "uvicorn", "httpx"])

    message = str(excinfo.value)
    assert "uvicorn" in message
    # Ensure the error lists every missing dependency only once
    assert message.count("uvicorn") == 1
