"""SQLite-backed persistence for the rebooted management service."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import secrets
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

try:  # pragma: no cover - exercised indirectly via tests
    from passlib.context import CryptContext
except ModuleNotFoundError:  # pragma: no cover - explicitly tested below
    CryptContext = None  # type: ignore[assignment]

from .models import User


def _ensure_directory(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def resolve_database_path(env_value: Optional[str]) -> Path:
    """Resolve the on-disk path for the application database."""

    if env_value:
        return Path(env_value).expanduser().resolve(strict=False)
    base_dir = Path(__file__).resolve().parent.parent / "data"
    return (base_dir / "management.sqlite3").resolve(strict=False)


def _current_timestamp() -> datetime:
    return datetime.now(timezone.utc)


def _serialize_datetime(value: datetime) -> str:
    return value.isoformat()


def _parse_datetime(value: str) -> datetime:
    return datetime.fromisoformat(value)


_pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto") if CryptContext else None

_PBKDF2_SCHEME = "pbkdf2_sha256"
_PBKDF2_ROUNDS = 600_000
_PBKDF2_SALT_BYTES = 16


def _hash_password_pbkdf2(password: str) -> str:
    salt = secrets.token_bytes(_PBKDF2_SALT_BYTES)
    hash_bytes = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, _PBKDF2_ROUNDS)
    encoded_salt = base64.b64encode(salt).decode("ascii")
    encoded_hash = base64.b64encode(hash_bytes).decode("ascii")
    return f"{_PBKDF2_SCHEME}${_PBKDF2_ROUNDS}${encoded_salt}${encoded_hash}"


def _verify_password_pbkdf2(password: str, hashed: str) -> bool:
    try:
        _, rounds_text, salt_b64, hash_b64 = hashed.split("$", 3)
        rounds = int(rounds_text)
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(hash_b64)
    except (ValueError, TypeError, binascii.Error):
        return False

    calculated = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, rounds)
    return hmac.compare_digest(expected, calculated)


def _hash_password(password: str) -> str:
    if _pwd_context is not None:
        return _pwd_context.hash(password)
    return _hash_password_pbkdf2(password)


def _verify_password(password: str, hashed: str) -> bool:
    if hashed.startswith(f"{_PBKDF2_SCHEME}$"):
        return _verify_password_pbkdf2(password, hashed)

    if _pwd_context is None:
        return False

    try:
        return _pwd_context.verify(password, hashed)
    except ValueError:
        return False


class Database:
    """Thin wrapper around SQLite for persisting user accounts."""

    def __init__(self, path: Path) -> None:
        _ensure_directory(path)
        self._path = path

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def initialize(self) -> None:
        """Create the required tables if they do not already exist."""

        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    email TEXT UNIQUE,
                    password_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                """
            )

    def create_user(self, name: str, email: Optional[str], password: str) -> User:
        """Create a new user with a hashed password."""

        normalized_name = name.strip()
        if not normalized_name:
            raise ValueError("Name must not be empty")

        if not password:
            raise ValueError("Password must not be empty")

        normalized_email = email.strip().lower() if email else None
        created_at = _current_timestamp()
        password_hash = _hash_password(password)

        with self._connect() as conn:
            try:
                cursor = conn.execute(
                    """
                    INSERT INTO users (name, email, password_hash, created_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        normalized_name,
                        normalized_email,
                        password_hash,
                        _serialize_datetime(created_at),
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ValueError("A user with that email already exists") from exc

            user_id = cursor.lastrowid

        user = User(id=int(user_id), name=normalized_name, email=normalized_email, created_at=created_at)
        return user

    def get_user(self, user_id: int) -> Optional[User]:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if row is None:
            return None
        return self._row_to_user(row)

    def get_user_by_email(self, email: str) -> Optional[User]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM users WHERE email = ?",
                (email.strip().lower(),),
            ).fetchone()
        if row is None:
            return None
        return self._row_to_user(row)

    def authenticate_user(self, email: str, password: str) -> Optional[User]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM users WHERE email = ?",
                (email.strip().lower(),),
            ).fetchone()
        if row is None:
            return None
        stored_hash = row["password_hash"]
        if not stored_hash or not _verify_password(password, stored_hash):
            return None
        return self._row_to_user(row)

    def verify_user_password(self, user_id: int, password: str) -> bool:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT password_hash FROM users WHERE id = ?",
                (user_id,),
            ).fetchone()

        if row is None:
            return False

        stored_hash = row["password_hash"]
        if not stored_hash:
            return False

        return _verify_password(password, stored_hash)

    def set_user_password(self, user_id: int, password: str) -> None:
        if not password:
            raise ValueError("Password must not be empty")
        password_hash = _hash_password(password)
        with self._connect() as conn:
            conn.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (password_hash, user_id),
            )

    def update_user_profile(self, user_id: int, *, name: str, email: Optional[str]) -> User:
        normalized_name = name.strip()
        if not normalized_name:
            raise ValueError("Name must not be empty")

        normalized_email = email.strip().lower() if email else None

        with self._connect() as conn:
            try:
                conn.execute(
                    "UPDATE users SET name = ?, email = ? WHERE id = ?",
                    (normalized_name, normalized_email, user_id),
                )
            except sqlite3.IntegrityError as exc:
                raise ValueError("A user with that email already exists") from exc

        refreshed = self.get_user(user_id)
        if refreshed is None:
            raise ValueError("User not found")
        return refreshed

    def _row_to_user(self, row: sqlite3.Row) -> User:
        return User(
            id=int(row["id"]),
            name=str(row["name"]),
            email=row["email"],
            created_at=_parse_datetime(str(row["created_at"])),
        )


__all__ = ["Database", "resolve_database_path"]
