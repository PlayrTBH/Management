"""In-memory coordination primitives for the management control plane."""

from __future__ import annotations

import asyncio
import re
import secrets
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Dict, Iterable, List, Mapping

DEFAULT_TUNNEL_HOST = "manage.playrservers.com"
DEFAULT_TUNNEL_PORT = 443
DEFAULT_SESSION_TIMEOUT = timedelta(minutes=5)

_MAX_AGENT_ID_LENGTH = 128
_MAX_HOSTNAME_LENGTH = 255
_MAX_CAPABILITIES = 32
_MAX_CAPABILITY_LENGTH = 64
_MAX_METADATA_ITEMS = 16
_MAX_METADATA_KEY_LENGTH = 64
_MAX_METADATA_VALUE_LENGTH = 512
_ALLOWED_PURPOSE = re.compile(r"^[A-Za-z0-9_.-]{1,32}$")
_MAX_DESCRIPTION_LENGTH = 512


class TunnelState(str, Enum):
    """Represents the lifecycle state of a tunnel requested by a user."""

    PENDING = "pending"
    ACTIVE = "active"
    CLOSED = "closed"


@dataclass
class Tunnel:
    """Metadata for an established or pending tunnel."""

    id: str
    user_id: int
    purpose: str
    remote_port: int
    token: str
    created_at: datetime
    updated_at: datetime
    state: TunnelState = TunnelState.PENDING
    description: str | None = None
    metadata: Dict[str, str] = field(default_factory=dict)


@dataclass
class AgentSession:
    """Represents a connected agent associated with a single user."""

    agent_id: str
    user_id: int
    hostname: str
    capabilities: tuple[str, ...]
    metadata: Dict[str, str]
    session_id: str
    token: str
    created_at: datetime
    last_seen: datetime
    tunnels: Dict[str, Tunnel] = field(default_factory=dict)

    def expires_at(self, timeout: timedelta) -> datetime:
        """Return the timestamp after which the session is considered stale."""

        return self.last_seen + timeout


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _normalise_agent_id(agent_id: str) -> str:
    value = agent_id.strip()
    if not value:
        raise ValueError("Agent identifier must not be empty")
    if len(value) > _MAX_AGENT_ID_LENGTH:
        raise ValueError("Agent identifier is too long")
    return value


def _normalise_hostname(hostname: str) -> str:
    value = hostname.strip()
    if not value:
        raise ValueError("Hostname must not be empty")
    if len(value) > _MAX_HOSTNAME_LENGTH:
        raise ValueError("Hostname is too long")
    return value


def _normalise_capabilities(capabilities: Iterable[str]) -> tuple[str, ...]:
    deduplicated: list[str] = []
    for capability in capabilities:
        cleaned = capability.strip()
        if not cleaned:
            continue
        if len(cleaned) > _MAX_CAPABILITY_LENGTH:
            raise ValueError("Capability entries must be 64 characters or fewer")
        if cleaned in deduplicated:
            continue
        deduplicated.append(cleaned)
        if len(deduplicated) > _MAX_CAPABILITIES:
            raise ValueError("Too many capabilities provided")
    return tuple(deduplicated)


def _normalise_metadata(metadata: Mapping[str, str] | None) -> Dict[str, str]:
    if metadata is None:
        return {}
    if len(metadata) > _MAX_METADATA_ITEMS:
        raise ValueError("Too many metadata entries provided")
    cleaned: Dict[str, str] = {}
    for key, value in metadata.items():
        key_text = str(key).strip()
        value_text = str(value).strip()
        if not key_text:
            raise ValueError("Metadata keys must not be empty")
        if len(key_text) > _MAX_METADATA_KEY_LENGTH:
            raise ValueError("Metadata keys must be 64 characters or fewer")
        if len(value_text) > _MAX_METADATA_VALUE_LENGTH:
            raise ValueError("Metadata values must be 512 characters or fewer")
        cleaned[key_text] = value_text
    return cleaned


def _normalise_purpose(purpose: str) -> str:
    value = purpose.strip()
    if not value:
        raise ValueError("Purpose must not be empty")
    if not _ALLOWED_PURPOSE.fullmatch(value):
        raise ValueError(
            "Purpose may only contain letters, numbers, underscores, hyphens, or periods",
        )
    return value


def _normalise_description(description: str | None) -> str | None:
    if description is None:
        return None
    value = description.strip()
    if not value:
        return None
    if len(value) > _MAX_DESCRIPTION_LENGTH:
        raise ValueError("Description is too long")
    return value


class AgentRegistry:
    """Tracks connected agents and the tunnels provisioned for them."""

    def __init__(
        self,
        *,
        tunnel_host: str = DEFAULT_TUNNEL_HOST,
        tunnel_port: int = DEFAULT_TUNNEL_PORT,
        session_timeout: timedelta = DEFAULT_SESSION_TIMEOUT,
    ) -> None:
        self._tunnel_host = tunnel_host
        self._tunnel_port = tunnel_port
        self._session_timeout = session_timeout
        self._lock = asyncio.Lock()
        self._sessions: Dict[str, AgentSession] = {}

    @property
    def tunnel_host(self) -> str:
        return self._tunnel_host

    @property
    def tunnel_port(self) -> int:
        return self._tunnel_port

    @property
    def session_timeout(self) -> timedelta:
        return self._session_timeout

    async def connect_agent(
        self,
        *,
        agent_id: str,
        user_id: int,
        hostname: str,
        capabilities: Iterable[str],
        metadata: Mapping[str, str] | None = None,
    ) -> AgentSession:
        """Register or refresh an agent connection for a user."""

        normalised_id = _normalise_agent_id(agent_id)
        normalised_hostname = _normalise_hostname(hostname)
        normalised_capabilities = _normalise_capabilities(capabilities)
        normalised_metadata = _normalise_metadata(metadata)

        async with self._lock:
            self._prune_expired_locked()
            existing = self._sessions.get(normalised_id)
            if existing and existing.user_id != user_id:
                raise PermissionError("Agent is owned by a different user")

            now = _utcnow()
            session = AgentSession(
                agent_id=normalised_id,
                user_id=user_id,
                hostname=normalised_hostname,
                capabilities=normalised_capabilities,
                metadata=normalised_metadata,
                session_id=secrets.token_hex(16),
                token=secrets.token_urlsafe(32),
                created_at=now,
                last_seen=now,
            )
            self._sessions[normalised_id] = session
            return session

    async def heartbeat(
        self,
        *,
        agent_id: str,
        user_id: int,
        session_id: str,
        token: str,
        active_tunnels: Iterable[str] | None = None,
    ) -> AgentSession:
        """Update the activity timestamp for an agent and refresh tunnel state."""

        normalised_id = _normalise_agent_id(agent_id)

        async with self._lock:
            self._prune_expired_locked()
            session = self._sessions.get(normalised_id)
            if session is None:
                raise KeyError("Unknown agent")
            self._ensure_session_is_valid(session, user_id, session_id, token)

            now = _utcnow()
            session.last_seen = now
            if active_tunnels is not None:
                self._update_tunnel_activity(session, active_tunnels, now)
            return session

    async def create_tunnel(
        self,
        *,
        agent_id: str,
        user_id: int,
        session_id: str,
        token: str,
        purpose: str,
        remote_port: int,
        description: str | None = None,
        metadata: Mapping[str, str] | None = None,
    ) -> tuple[Tunnel, AgentSession]:
        """Provision a new tunnel for the specified agent."""

        if remote_port < 1 or remote_port > 65535:
            raise ValueError("remote_port must be between 1 and 65535")

        normalised_id = _normalise_agent_id(agent_id)
        normalised_purpose = _normalise_purpose(purpose)
        normalised_description = _normalise_description(description)
        normalised_metadata = _normalise_metadata(metadata)

        async with self._lock:
            self._prune_expired_locked()
            session = self._sessions.get(normalised_id)
            if session is None:
                raise KeyError("Unknown agent")
            self._ensure_session_is_valid(session, user_id, session_id, token)

            now = _utcnow()
            tunnel_id = secrets.token_hex(8)
            tunnel = Tunnel(
                id=tunnel_id,
                user_id=user_id,
                purpose=normalised_purpose,
                remote_port=int(remote_port),
                token=secrets.token_urlsafe(32),
                created_at=now,
                updated_at=now,
                state=TunnelState.PENDING,
                description=normalised_description,
                metadata=normalised_metadata,
            )
            session.tunnels[tunnel_id] = tunnel
            session.last_seen = now
            return tunnel, session

    async def close_tunnel(
        self,
        *,
        agent_id: str,
        user_id: int,
        session_id: str,
        token: str,
        tunnel_id: str,
    ) -> tuple[Tunnel, AgentSession]:
        """Mark a tunnel as closed and update the session heartbeat."""

        normalised_id = _normalise_agent_id(agent_id)
        normalised_tunnel_id = tunnel_id.strip()
        if not normalised_tunnel_id:
            raise ValueError("tunnel_id must not be empty")

        async with self._lock:
            self._prune_expired_locked()
            session = self._sessions.get(normalised_id)
            if session is None:
                raise KeyError("Unknown agent")
            self._ensure_session_is_valid(session, user_id, session_id, token)

            tunnel = session.tunnels.get(normalised_tunnel_id)
            if tunnel is None:
                raise KeyError("Unknown tunnel")

            now = _utcnow()
            if tunnel.state != TunnelState.CLOSED:
                tunnel.state = TunnelState.CLOSED
                tunnel.updated_at = now
            session.last_seen = now
            return tunnel, session

    async def get_session(self, *, agent_id: str, user_id: int) -> AgentSession:
        """Retrieve session details for the agent if owned by the user."""

        normalised_id = _normalise_agent_id(agent_id)

        async with self._lock:
            self._prune_expired_locked()
            session = self._sessions.get(normalised_id)
            if session is None:
                raise KeyError("Unknown agent")
            if session.user_id != user_id:
                raise PermissionError("Agent is owned by a different user")
            return session

    async def list_sessions(self, *, user_id: int) -> List[AgentSession]:
        """Return snapshots of all sessions owned by ``user_id``."""

        async with self._lock:
            self._prune_expired_locked()
            sessions = [
                self._clone_session(session)
                for session in self._sessions.values()
                if session.user_id == user_id
            ]
        return sessions

    def _ensure_session_is_valid(
        self,
        session: AgentSession,
        user_id: int,
        session_id: str,
        token: str,
    ) -> None:
        if session.user_id != user_id:
            raise PermissionError("Agent is owned by a different user")
        if session.session_id != session_id or session.token != token:
            raise ValueError("Invalid session credentials")
        if session.expires_at(self._session_timeout) <= _utcnow():
            raise KeyError("Agent session has expired")

    def _update_tunnel_activity(
        self,
        session: AgentSession,
        active_tunnels: Iterable[str],
        timestamp: datetime,
    ) -> None:
        active = {identifier.strip() for identifier in active_tunnels if identifier.strip()}
        for tunnel_id, tunnel in session.tunnels.items():
            if tunnel.state == TunnelState.CLOSED:
                continue
            if tunnel_id in active:
                if tunnel.state != TunnelState.ACTIVE:
                    tunnel.state = TunnelState.ACTIVE
                tunnel.updated_at = timestamp
            else:
                if tunnel.state != TunnelState.PENDING:
                    tunnel.state = TunnelState.PENDING
                    tunnel.updated_at = timestamp

    def _prune_expired_locked(self) -> None:
        now = _utcnow()
        expired = [
            agent_id
            for agent_id, session in self._sessions.items()
            if session.expires_at(self._session_timeout) <= now
        ]
        for agent_id in expired:
            self._sessions.pop(agent_id, None)

    def _clone_session(self, session: AgentSession) -> AgentSession:
        return AgentSession(
            agent_id=session.agent_id,
            user_id=session.user_id,
            hostname=session.hostname,
            capabilities=session.capabilities,
            metadata=dict(session.metadata),
            session_id=session.session_id,
            token=session.token,
            created_at=session.created_at,
            last_seen=session.last_seen,
            tunnels={
                tunnel_id: replace(tunnel, metadata=dict(tunnel.metadata))
                for tunnel_id, tunnel in session.tunnels.items()
            },
        )


__all__ = [
    "AgentRegistry",
    "AgentSession",
    "DEFAULT_SESSION_TIMEOUT",
    "DEFAULT_TUNNEL_HOST",
    "DEFAULT_TUNNEL_PORT",
    "Tunnel",
    "TunnelState",
]
