from __future__ import annotations

from pathlib import Path

import pytest

from app.database import Database


@pytest.fixture()
def database(tmp_path: Path) -> Database:
    db_path = tmp_path / "management.sqlite3"
    db = Database(db_path)
    db.initialize()
    return db


def test_create_and_authenticate_api_key(database: Database) -> None:
    user = database.create_user("Agent Owner", "owner@example.com", "Sup3rSecurePwd!")
    api_key = database.create_api_key(user.id, "Primary agent key")

    assert api_key.startswith("psm_")
    retrieved = database.authenticate_api_key(api_key)
    assert retrieved is not None
    assert retrieved.id == user.id

    assert database.authenticate_api_key("psm_invalid_key") is None


def test_api_key_requires_non_empty_name(database: Database) -> None:
    user = database.create_user("Tester", "tester@example.com", "AnotherSecret123!")
    with pytest.raises(ValueError):
        database.create_api_key(user.id, "  ")
