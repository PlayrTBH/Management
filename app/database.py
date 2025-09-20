"""SQLite-backed persistence for users and agents."""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os
import secrets
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Tuple

try:  # pragma: no cover - exercised indirectly via tests
    from passlib.context import CryptContext
except ModuleNotFoundError:  # pragma: no cover - explicitly tested below
    CryptContext = None  # type: ignore[assignment]

from cryptography.fernet import Fernet, InvalidToken

from .agent_registration import AgentProvisioningError, generate_provisioning_key_pair
from .models import Agent, ProvisioningKeyPair, User


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
    """Simple wrapper around SQLite for persisting users and agents."""

    def __init__(self, path: Path, *, api_key_secret: Optional[str] = None) -> None:
        _ensure_directory(path)
        self._path = path
        if api_key_secret is None:
            api_key_secret = os.getenv("MANAGEMENT_SESSION_SECRET")
        self._api_key_cipher = self._build_api_key_cipher(api_key_secret)

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
                    api_key_encrypted TEXT,
                    password_hash TEXT,
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

                CREATE TABLE IF NOT EXISTS user_provisioning_keys (
                    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
                    private_key TEXT NOT NULL,
                    public_key TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_agents_user_id ON agents(user_id);
                CREATE INDEX IF NOT EXISTS idx_users_api_key_prefix ON users(api_key_prefix);
                """
            )

            columns = {
                row["name"]
                for row in conn.execute("PRAGMA table_info(users)").fetchall()
            }
            if "password_hash" not in columns:
                conn.execute("ALTER TABLE users ADD COLUMN password_hash TEXT")
            if "api_key_encrypted" not in columns:
                conn.execute("ALTER TABLE users ADD COLUMN api_key_encrypted TEXT")

    # ------------------------------------------------------------------
    # User management
    # ------------------------------------------------------------------
    def create_user(
        self,
        name: str,
        email: Optional[str],
        password: str,
    ) -> Tuple[User, str]:
        """Create a new user and return it along with the generated API key."""

        if not password:
            raise ValueError("Password must not be empty")

        created_at = _current_timestamp()
        api_key = _generate_api_key()
        salt = secrets.token_bytes(16)
        hash_bytes = _hash_api_key(api_key, salt)
        prefix = api_key[:8]
        password_hash = _hash_password(password)
        normalized_email = email.strip().lower() if email else None
        encrypted_api_key = self._encrypt_api_key(api_key)

        with self._connect() as conn:
            try:
                cursor = conn.execute(
                    """
                    INSERT INTO users (
                        name,
                        email,
                        api_key_prefix,
                        api_key_hash,
                        api_key_salt,
                        api_key_encrypted,
                        password_hash,
                        created_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        name,
                        normalized_email,
                        prefix,
                        base64.b64encode(hash_bytes).decode("ascii"),
                        base64.b64encode(salt).decode("ascii"),
                        encrypted_api_key,
                        password_hash,
                        _serialize_datetime(created_at),
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ValueError("A user with that email already exists") from exc

            user_id = cursor.lastrowid

        # Provisioning keys are generated lazily when the user is created so that
        # automation clients can enrol agents immediately.
        self.ensure_user_provisioning_keys(user_id)

        user = User(id=user_id, name=name, email=normalized_email, api_key_prefix=prefix, created_at=created_at)
        return user, api_key

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
        """Return ``True`` if the supplied password matches the stored hash."""

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

    def update_user_profile(
        self,
        user_id: int,
        *,
        name: str,
        email: Optional[str],
    ) -> User:
        """Update the display name/email address for an existing user."""

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

    def set_user_password(self, user_id: int, password: str) -> None:
        if not password:
            raise ValueError("Password must not be empty")
        password_hash = _hash_password(password)
        with self._connect() as conn:
            conn.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (password_hash, user_id),
            )

    def rotate_api_key(self, user_id: int) -> Tuple[User, str]:
        user = self.get_user(user_id)
        if user is None:
            raise ValueError("User not found")

        api_key = _generate_api_key()
        salt = secrets.token_bytes(16)
        hash_bytes = _hash_api_key(api_key, salt)
        prefix = api_key[:8]
        encrypted_api_key = self._encrypt_api_key(api_key)

        with self._connect() as conn:
            conn.execute(
                """
                UPDATE users
                   SET api_key_prefix = ?, api_key_hash = ?, api_key_salt = ?, api_key_encrypted = ?
                 WHERE id = ?
                """,
                (
                    prefix,
                    base64.b64encode(hash_bytes).decode("ascii"),
                    base64.b64encode(salt).decode("ascii"),
                    encrypted_api_key,
                    user_id,
                ),
            )

        refreshed = self.get_user(user_id)
        if refreshed is None:
            raise ValueError("User not found")
        return refreshed, api_key

    def get_user_api_key(self, user_id: int) -> Optional[str]:
        """Return the decrypted API key for the given user, if available."""

        with self._connect() as conn:
            row = conn.execute(
                "SELECT api_key_encrypted FROM users WHERE id = ?",
                (user_id,),
            ).fetchone()

        if row is None:
            return None

        encrypted = row["api_key_encrypted"]
        if not encrypted:
            return None

        return self._decrypt_api_key(str(encrypted))

    # ------------------------------------------------------------------
    # Provisioning key management
    # ------------------------------------------------------------------
    def get_user_provisioning_keys(self, user_id: int) -> Optional[ProvisioningKeyPair]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM user_provisioning_keys WHERE user_id = ?",
                (user_id,),
            ).fetchone()

        if row is None:
            return None

        return self._row_to_provisioning_keys(row)

    def ensure_user_provisioning_keys(self, user_id: int) -> ProvisioningKeyPair:
        existing = self.get_user_provisioning_keys(user_id)
        if existing is not None:
            return existing

        private_key, public_key = generate_provisioning_key_pair()
        created_at = _current_timestamp()
        serialized_created = _serialize_datetime(created_at)

        try:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO user_provisioning_keys (user_id, private_key, public_key, created_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (user_id, private_key, public_key, serialized_created),
                )
        except sqlite3.IntegrityError:
            existing = self.get_user_provisioning_keys(user_id)
            if existing is not None:
                return existing
            raise AgentProvisioningError(
                f"Provisioning keys already exist for user {user_id} but could not be loaded"
            )
        except sqlite3.DatabaseError as exc:  # pragma: no cover - unexpected database failure
            raise AgentProvisioningError(
                f"Failed to persist provisioning key material for user {user_id}"
            ) from exc

        return ProvisioningKeyPair(
            user_id=user_id,
            private_key=private_key,
            public_key=public_key,
            created_at=created_at,
        )

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

    def find_agent_by_hostname(self, user_id: int, hostname: str) -> Optional[Agent]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM agents WHERE user_id = ? AND hostname = ?",
                (user_id, hostname),
            ).fetchone()
        if row is None:
            return None
        return self._row_to_agent(row)

    def find_agent_by_name(self, user_id: int, name: str) -> Optional[Agent]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM agents WHERE user_id = ? AND name = ?",
                (user_id, name),
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

    def _row_to_provisioning_keys(self, row: sqlite3.Row) -> ProvisioningKeyPair:
        return ProvisioningKeyPair(
            user_id=int(row["user_id"]),
            private_key=str(row["private_key"]),
            public_key=str(row["public_key"]),
            created_at=_parse_datetime(str(row["created_at"])),
        )

    def _build_api_key_cipher(self, secret: Optional[str]) -> Optional[Fernet]:
        if not secret:
            return None
        digest = hashlib.sha256(secret.encode("utf-8")).digest()
        key = base64.urlsafe_b64encode(digest)
        return Fernet(key)

    def _require_api_key_cipher(self) -> Fernet:
        if self._api_key_cipher is None:
            raise RuntimeError(
                "API key encryption secret is not configured. Set MANAGEMENT_SESSION_SECRET to enable API key retrieval."
            )
        return self._api_key_cipher

    def _encrypt_api_key(self, api_key: str) -> str:
        cipher = self._require_api_key_cipher()
        token = cipher.encrypt(api_key.encode("utf-8"))
        return token.decode("utf-8")

    def _decrypt_api_key(self, encrypted: str) -> str:
        cipher = self._require_api_key_cipher()
        try:
            plaintext = cipher.decrypt(encrypted.encode("utf-8"))
        except InvalidToken as exc:
            raise ValueError("Stored API key could not be decrypted. Rotate the key to repair it.") from exc
        return plaintext.decode("utf-8")


__all__ = ["Database", "resolve_database_path"]
