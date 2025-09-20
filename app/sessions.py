"""In-memory session handling for the management web interface."""

from __future__ import annotations

import secrets
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional


@dataclass
class _SessionRecord:
    user_id: int
    expires_at: datetime


class SessionManager:
    """Generate, validate, and revoke web dashboard sessions."""

    def __init__(self, *, ttl: timedelta = timedelta(hours=8)) -> None:
        self._ttl = ttl
        self._sessions: Dict[str, _SessionRecord] = {}
        self._lock = threading.Lock()

    @property
    def ttl(self) -> timedelta:
        return self._ttl

    @property
    def cookie_max_age(self) -> int:
        return int(self._ttl.total_seconds())

    def create(self, user_id: int) -> str:
        token = secrets.token_urlsafe(32)
        record = _SessionRecord(user_id=user_id, expires_at=self._now() + self._ttl)
        with self._lock:
            self._sessions[token] = record
        return token

    def resolve(self, token: str) -> Optional[int]:
        now = self._now()
        with self._lock:
            record = self._sessions.get(token)
            if record is None:
                return None
            if record.expires_at <= now:
                self._sessions.pop(token, None)
                return None
            record.expires_at = now + self._ttl
            return record.user_id

    def destroy(self, token: str) -> None:
        with self._lock:
            self._sessions.pop(token, None)

    def _now(self) -> datetime:
        return datetime.now(timezone.utc)


__all__ = ["SessionManager"]
