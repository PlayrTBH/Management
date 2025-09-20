"""HTTP API for coordinating agents and hypervisor management tunnels."""

from __future__ import annotations

import logging
import os
from datetime import datetime
from typing import Dict, List, Optional

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel, Field

from .agents import (
    AgentRegistry,
    AgentSession,
    DEFAULT_TUNNEL_HOST,
    DEFAULT_TUNNEL_PORT,
    Tunnel,
)
from .database import Database, resolve_database_path
from .models import User

logger = logging.getLogger("playrservers.service")


class TunnelEndpoint(BaseModel):
    host: str = Field(..., description="Hostname clients should connect to")
    port: int = Field(..., description="Port exposed for tunnel traffic")


class AgentConnectRequest(BaseModel):
    agent_id: str = Field(..., min_length=1, max_length=128)
    hostname: str = Field(..., min_length=1, max_length=255)
    capabilities: List[str] = Field(default_factory=list)
    metadata: Dict[str, str] = Field(default_factory=dict)


class AgentConnectResponse(BaseModel):
    agent_id: str
    session_id: str
    agent_token: str
    hostname: str
    capabilities: List[str]
    metadata: Dict[str, str]
    tunnel_endpoint: TunnelEndpoint
    connected_at: datetime
    expires_at: datetime


class AgentHeartbeatRequest(BaseModel):
    session_id: str
    agent_token: str
    active_tunnels: Optional[List[str]] = None


class TunnelHeartbeatEntry(BaseModel):
    tunnel_id: str
    state: str
    purpose: str
    remote_port: int


class AgentHeartbeatResponse(BaseModel):
    agent_id: str
    session_id: str
    last_seen: datetime
    expires_at: datetime
    tunnels: List[TunnelHeartbeatEntry]


class TunnelCreateRequest(BaseModel):
    session_id: str
    agent_token: str
    purpose: str = Field(..., min_length=1, max_length=32)
    remote_port: int = Field(..., ge=1, le=65535)
    description: Optional[str] = Field(default=None, max_length=512)
    metadata: Dict[str, str] = Field(default_factory=dict)


class TunnelCloseRequest(BaseModel):
    session_id: str
    agent_token: str


class TunnelView(BaseModel):
    tunnel_id: str
    state: str
    purpose: str
    remote_port: int
    client_token: str
    endpoint: TunnelEndpoint
    created_at: datetime
    updated_at: datetime
    description: Optional[str] = None
    metadata: Dict[str, str] = Field(default_factory=dict)


class TunnelCreateResponse(TunnelView):
    agent_id: str
    session_id: str


class TunnelCloseResponse(TunnelView):
    agent_id: str
    session_id: str


class TunnelListResponse(BaseModel):
    agent_id: str
    tunnels: List[TunnelView]


class AgentStatusResponse(BaseModel):
    agent_id: str
    session_id: str
    hostname: str
    capabilities: List[str]
    metadata: Dict[str, str]
    connected_at: datetime
    last_seen: datetime
    expires_at: datetime
    tunnel_endpoint: TunnelEndpoint
    tunnels: List[TunnelView]


class AgentListResponse(BaseModel):
    agents: List[AgentStatusResponse]


def _tunnel_to_view(tunnel: Tunnel, registry: AgentRegistry) -> TunnelView:
    return TunnelView(
        tunnel_id=tunnel.id,
        state=tunnel.state.value,
        purpose=tunnel.purpose,
        remote_port=tunnel.remote_port,
        client_token=tunnel.token,
        endpoint=TunnelEndpoint(host=registry.tunnel_host, port=registry.tunnel_port),
        created_at=tunnel.created_at,
        updated_at=tunnel.updated_at,
        description=tunnel.description,
        metadata=dict(tunnel.metadata),
    )


def _session_to_status(session: AgentSession, registry: AgentRegistry) -> AgentStatusResponse:
    return AgentStatusResponse(
        agent_id=session.agent_id,
        session_id=session.session_id,
        hostname=session.hostname,
        capabilities=list(session.capabilities),
        metadata=dict(session.metadata),
        connected_at=session.created_at,
        last_seen=session.last_seen,
        expires_at=session.expires_at(registry.session_timeout),
        tunnel_endpoint=TunnelEndpoint(host=registry.tunnel_host, port=registry.tunnel_port),
        tunnels=[_tunnel_to_view(tunnel, registry) for tunnel in session.tunnels.values()],
    )


def _heartbeat_to_response(session: AgentSession, registry: AgentRegistry) -> AgentHeartbeatResponse:
    return AgentHeartbeatResponse(
        agent_id=session.agent_id,
        session_id=session.session_id,
        last_seen=session.last_seen,
        expires_at=session.expires_at(registry.session_timeout),
        tunnels=[
            TunnelHeartbeatEntry(
                tunnel_id=tunnel.id,
                state=tunnel.state.value,
                purpose=tunnel.purpose,
                remote_port=tunnel.remote_port,
            )
            for tunnel in session.tunnels.values()
        ],
    )


def _initialise_database(database: Database) -> Database:
    database.initialize()
    return database


def _build_auth_dependency(database: Database):
    security = HTTPBasic()

    def dependency(credentials: HTTPBasicCredentials = Depends(security)) -> User:
        user = database.authenticate_user(credentials.username, credentials.password)
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Basic"},
            )
        return user

    return dependency


def create_app(
    *,
    database: Database | None = None,
    registry: AgentRegistry | None = None,
    tunnel_host: str | None = None,
    tunnel_port: int | None = None,
) -> FastAPI:
    """Instantiate the FastAPI application for the management plane."""

    db = database or Database(resolve_database_path(os.getenv("MANAGEMENT_DB_PATH")))
    _initialise_database(db)

    app_registry = registry or AgentRegistry(
        tunnel_host=tunnel_host or DEFAULT_TUNNEL_HOST,
        tunnel_port=tunnel_port or DEFAULT_TUNNEL_PORT,
    )

    app = FastAPI(
        title="PlayrServers Management API",
        version="0.1.0",
        description="Control plane for authenticated hypervisor management tunnels.",
    )

    current_user = _build_auth_dependency(db)

    @app.get("/healthz")
    async def healthcheck() -> Dict[str, str]:
        return {"status": "ok"}

    @app.post("/v1/agents/connect", response_model=AgentConnectResponse)
    async def connect_agent(
        request: AgentConnectRequest,
        user: User = Depends(current_user),
    ) -> AgentConnectResponse:
        try:
            session = await app_registry.connect_agent(
                agent_id=request.agent_id,
                user_id=user.id,
                hostname=request.hostname,
                capabilities=request.capabilities,
                metadata=request.metadata,
            )
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        except PermissionError as exc:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc

        logger.info("Agent %s connected for user %s", session.agent_id, user.id)

        return AgentConnectResponse(
            agent_id=session.agent_id,
            session_id=session.session_id,
            agent_token=session.token,
            hostname=session.hostname,
            capabilities=list(session.capabilities),
            metadata=dict(session.metadata),
            tunnel_endpoint=TunnelEndpoint(
                host=app_registry.tunnel_host,
                port=app_registry.tunnel_port,
            ),
            connected_at=session.created_at,
            expires_at=session.expires_at(app_registry.session_timeout),
        )

    @app.post("/v1/agents/{agent_id}/heartbeat", response_model=AgentHeartbeatResponse)
    async def heartbeat(
        agent_id: str,
        request: AgentHeartbeatRequest,
        user: User = Depends(current_user),
    ) -> AgentHeartbeatResponse:
        try:
            session = await app_registry.heartbeat(
                agent_id=agent_id,
                user_id=user.id,
                session_id=request.session_id,
                token=request.agent_token,
                active_tunnels=request.active_tunnels,
            )
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc
        except PermissionError as exc:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
        except KeyError:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")

        return _heartbeat_to_response(session, app_registry)

    @app.post(
        "/v1/agents/{agent_id}/tunnels",
        status_code=status.HTTP_201_CREATED,
        response_model=TunnelCreateResponse,
    )
    async def create_tunnel(
        agent_id: str,
        request: TunnelCreateRequest,
        user: User = Depends(current_user),
    ) -> TunnelCreateResponse:
        try:
            tunnel, session = await app_registry.create_tunnel(
                agent_id=agent_id,
                user_id=user.id,
                session_id=request.session_id,
                token=request.agent_token,
                purpose=request.purpose,
                remote_port=request.remote_port,
                description=request.description,
                metadata=request.metadata,
            )
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        except PermissionError as exc:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
        except KeyError as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc

        return TunnelCreateResponse(
            agent_id=session.agent_id,
            session_id=session.session_id,
            tunnel_id=tunnel.id,
            state=tunnel.state.value,
            purpose=tunnel.purpose,
            remote_port=tunnel.remote_port,
            client_token=tunnel.token,
            endpoint=TunnelEndpoint(
                host=app_registry.tunnel_host,
                port=app_registry.tunnel_port,
            ),
            created_at=tunnel.created_at,
            updated_at=tunnel.updated_at,
            description=tunnel.description,
            metadata=dict(tunnel.metadata),
        )

    @app.post(
        "/v1/agents/{agent_id}/tunnels/{tunnel_id}/close",
        response_model=TunnelCloseResponse,
    )
    async def close_tunnel(
        agent_id: str,
        tunnel_id: str,
        request: TunnelCloseRequest,
        user: User = Depends(current_user),
    ) -> TunnelCloseResponse:
        try:
            tunnel, session = await app_registry.close_tunnel(
                agent_id=agent_id,
                user_id=user.id,
                session_id=request.session_id,
                token=request.agent_token,
                tunnel_id=tunnel_id,
            )
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        except PermissionError as exc:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
        except KeyError as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc

        return TunnelCloseResponse(
            agent_id=session.agent_id,
            session_id=session.session_id,
            tunnel_id=tunnel.id,
            state=tunnel.state.value,
            purpose=tunnel.purpose,
            remote_port=tunnel.remote_port,
            client_token=tunnel.token,
            endpoint=TunnelEndpoint(
                host=app_registry.tunnel_host,
                port=app_registry.tunnel_port,
            ),
            created_at=tunnel.created_at,
            updated_at=tunnel.updated_at,
            description=tunnel.description,
            metadata=dict(tunnel.metadata),
        )

    @app.get("/v1/agents/{agent_id}", response_model=AgentStatusResponse)
    async def get_agent(agent_id: str, user: User = Depends(current_user)) -> AgentStatusResponse:
        try:
            session = await app_registry.get_session(agent_id=agent_id, user_id=user.id)
        except PermissionError as exc:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
        except KeyError:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")
        return _session_to_status(session, app_registry)

    @app.get("/v1/agents", response_model=AgentListResponse)
    async def list_agents(user: User = Depends(current_user)) -> AgentListResponse:
        sessions = await app_registry.list_sessions(user_id=user.id)
        return AgentListResponse(
            agents=[_session_to_status(session, app_registry) for session in sessions]
        )

    @app.get("/v1/agents/{agent_id}/tunnels", response_model=TunnelListResponse)
    async def list_tunnels(agent_id: str, user: User = Depends(current_user)) -> TunnelListResponse:
        try:
            session = await app_registry.get_session(agent_id=agent_id, user_id=user.id)
        except PermissionError as exc:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
        except KeyError:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")

        return TunnelListResponse(
            agent_id=session.agent_id,
            tunnels=[_tunnel_to_view(tunnel, app_registry) for tunnel in session.tunnels.values()],
        )

    return app


__all__ = ["create_app"]
