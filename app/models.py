"""Domain models retained for the pared-down management service."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass(frozen=True)
class User:
    """Represents a user account stored in the management database."""

    id: int
    name: str
    email: Optional[str]
    created_at: datetime


__all__ = ["User"]
