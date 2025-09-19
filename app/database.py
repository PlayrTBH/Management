"""SQLite-backed persistence for users and agents."""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Tuple

from .models import Agent, User


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


def _generate_api_key() -> str:
    return secrets.token_urlsafe(32)


def _hash_api_key(api_key: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", api_key.encode("utf-8"), salt, 600_000)


class Database:
    """Simple wrapper around SQLite for persisting users and agents."""

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
                    api_key_prefix TEXT NOT NULL,
                    api_key_hash TEXT NOT NULL,
                    api_key_salt TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS agents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    name TEXT NOT NULL,
                    hostname TEXT NOT NULL,
                    port INTEGER NOT NULL DEFAULT 22,
                    username TEXT NOT NULL,
                    private_key TEXT NOT NULL,
                    private_key_passphrase TEXT,
                    allow_unknown_hosts INTEGER NOT NULL DEFAULT 0,
                    known_hosts_path TEXT,
                    created_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_agents_user_id ON agents(user_id);
                CREATE INDEX IF NOT EXISTS idx_users_api_key_prefix ON users(api_key_prefix);
                """
            )

    # ------------------------------------------------------------------
    # User management
    # ------------------------------------------------------------------
    def create_user(self, name: str, email: Optional[str] = None) -> Tuple[User, str]:
        """Create a new user and return it along with the generated API key."""

        created_at = _current_timestamp()
        api_key = _generate_api_key()
        salt = secrets.token_bytes(16)
        hash_bytes = _hash_api_key(api_key, salt)
        prefix = api_key[:8]

        with self._connect() as conn:
            try:
                cursor = conn.execute(
                    """
                    INSERT INTO users (name, email, api_key_prefix, api_key_hash, api_key_salt, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        name,
                        email,
                        prefix,
                        base64.b64encode(hash_bytes).decode("ascii"),
                        base64.b64encode(salt).decode("ascii"),
                        _serialize_datetime(created_at),
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ValueError("A user with that email already exists") from exc

            user_id = cursor.lastrowid

        user = User(id=user_id, name=name, email=email, api_key_prefix=prefix, created_at=created_at)
        return user, api_key

    def get_user(self, user_id: int) -> Optional[User]:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if row is None:
            return None
        return self._row_to_user(row)

    def get_user_by_api_key(self, api_key: str) -> Optional[User]:
        prefix = api_key[:8]
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM users WHERE api_key_prefix = ?",
                (prefix,),
            ).fetchall()

        for row in rows:
            salt = base64.b64decode(row["api_key_salt"])
            expected_hash = base64.b64decode(row["api_key_hash"])
            calculated = _hash_api_key(api_key, salt)
            if hmac.compare_digest(expected_hash, calculated):
                return self._row_to_user(row)
        return None

    def rotate_api_key(self, user_id: int) -> Tuple[User, str]:
        user = self.get_user(user_id)
        if user is None:
            raise ValueError("User not found")

        api_key = _generate_api_key()
        salt = secrets.token_bytes(16)
        hash_bytes = _hash_api_key(api_key, salt)
        prefix = api_key[:8]

        with self._connect() as conn:
            conn.execute(
                """
                UPDATE users
                   SET api_key_prefix = ?, api_key_hash = ?, api_key_salt = ?
                 WHERE id = ?
                """,
                (
                    prefix,
                    base64.b64encode(hash_bytes).decode("ascii"),
                    base64.b64encode(salt).decode("ascii"),
                    user_id,
                ),
            )

        refreshed = self.get_user(user_id)
        if refreshed is None:
            raise ValueError("User not found")
        return refreshed, api_key

    # ------------------------------------------------------------------
    # Agent management
    # ------------------------------------------------------------------
    def create_agent(
        self,
        user_id: int,
        *,
        name: str,
        hostname: str,
        port: int,
        username: str,
        private_key: str,
        private_key_passphrase: Optional[str],
        allow_unknown_hosts: bool,
        known_hosts_path: Optional[str],
    ) -> Agent:
        created_at = _current_timestamp()
        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO agents (
                    user_id, name, hostname, port, username, private_key, private_key_passphrase,
                    allow_unknown_hosts, known_hosts_path, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    user_id,
                    name,
                    hostname,
                    port,
                    username,
                    private_key.strip(),
                    private_key_passphrase,
                    int(bool(allow_unknown_hosts)),
                    known_hosts_path,
                    _serialize_datetime(created_at),
                ),
            )
            agent_id = cursor.lastrowid

        agent = self.get_agent_for_user(user_id, agent_id)
        if agent is None:
            raise RuntimeError("Failed to load agent after creation")
        return agent

    def list_agents_for_user(self, user_id: int) -> List[Agent]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM agents WHERE user_id = ? ORDER BY name",
                (user_id,),
            ).fetchall()
        return [self._row_to_agent(row) for row in rows]

    def get_agent_for_user(self, user_id: int, agent_id: int) -> Optional[Agent]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM agents WHERE user_id = ? AND id = ?",
                (user_id, agent_id),
            ).fetchone()
        if row is None:
            return None
        return self._row_to_agent(row)

    def delete_agent(self, user_id: int, agent_id: int) -> bool:
        with self._connect() as conn:
            cursor = conn.execute(
                "DELETE FROM agents WHERE user_id = ? AND id = ?",
                (user_id, agent_id),
            )
            return cursor.rowcount > 0

    def update_agent(
        self,
        user_id: int,
        agent_id: int,
        **fields: object,
    ) -> Optional[Agent]:
        if not fields:
            return self.get_agent_for_user(user_id, agent_id)

        allowed = {
            "name": "name",
            "hostname": "hostname",
            "port": "port",
            "username": "username",
            "private_key": "private_key",
            "private_key_passphrase": "private_key_passphrase",
            "allow_unknown_hosts": "allow_unknown_hosts",
            "known_hosts_path": "known_hosts_path",
        }

        updates: List[str] = []
        values: List[object] = []
        nullable_columns = {"private_key_passphrase", "known_hosts_path"}
        for key, column in allowed.items():
            if key not in fields:
                continue
            value = fields[key]
            if value is None and column not in nullable_columns:
                continue
            if column == "private_key":
                value = str(value).strip()
            if column == "allow_unknown_hosts":
                value = int(bool(value))
            updates.append(f"{column} = ?")
            values.append(value)

        if not updates:
            return self.get_agent_for_user(user_id, agent_id)

        values.extend([user_id, agent_id])
        query = f"UPDATE agents SET {', '.join(updates)} WHERE user_id = ? AND id = ?"

        with self._connect() as conn:
            cursor = conn.execute(query, values)
            if cursor.rowcount == 0:
                return None

        return self.get_agent_for_user(user_id, agent_id)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _row_to_user(self, row: sqlite3.Row) -> User:
        return User(
            id=int(row["id"]),
            name=str(row["name"]),
            email=row["email"],
            api_key_prefix=str(row["api_key_prefix"]),
            created_at=_parse_datetime(str(row["created_at"])),
        )

    def _row_to_agent(self, row: sqlite3.Row) -> Agent:
        return Agent(
            id=int(row["id"]),
            user_id=int(row["user_id"]),
            name=str(row["name"]),
            hostname=str(row["hostname"]),
            port=int(row["port"]),
            username=str(row["username"]),
            private_key=str(row["private_key"]),
            private_key_passphrase=row["private_key_passphrase"],
            allow_unknown_hosts=bool(row["allow_unknown_hosts"]),
            known_hosts_path=row["known_hosts_path"],
            created_at=_parse_datetime(str(row["created_at"])),
        )


__all__ = ["Database", "resolve_database_path"]
