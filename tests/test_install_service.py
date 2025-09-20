"""Tests for the non-interactive installer helpers."""

from __future__ import annotations

import pytest

from app.database import Database
from scripts.install_service import (
    UserInputError,
    create_initial_user,
    prompt_for_non_empty,
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


def test_create_initial_user_requires_interactive_stdin(tmp_path, monkeypatch):
    database = _initialised_database(tmp_path)

    monkeypatch.setattr("scripts.install_service.sys.stdin.isatty", lambda: False)

    with pytest.raises(UserInputError):
        create_initial_user(database)


def test_prompt_for_non_empty_eof(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda _: (_ for _ in ()).throw(EOFError()))

    with pytest.raises(UserInputError):
        prompt_for_non_empty("Display name: ")
