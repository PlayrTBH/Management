"""Domain models for the management service."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass(frozen=True)
class User:
    """Represents an authenticated user of the management service."""

    id: int
    name: str
    email: Optional[str]
    api_key_prefix: str
    created_at: datetime


@dataclass(frozen=True)
class Agent:
    """Represents a remote virtualization agent owned by a user."""

    id: int
    user_id: int
    name: str
    hostname: str
    port: int
    username: str
    private_key: str
    private_key_passphrase: Optional[str]
    allow_unknown_hosts: bool
    known_hosts_path: Optional[str]
    created_at: datetime


@dataclass(frozen=True)
class ProvisioningKeyPair:
    """Stores SSH key material generated for a user profile."""

    user_id: int
    private_key: str
    public_key: str
    created_at: datetime


__all__ = ["Agent", "ProvisioningKeyPair", "User"]
