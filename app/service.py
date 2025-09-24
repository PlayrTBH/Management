"""HTTP API for coordinating agents and hypervisor management tunnels."""

from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta
from typing import Callable, Dict, List, Optional

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import (
    HTTPAuthorizationCredentials,
    HTTPBasic,
    HTTPBasicCredentials,
    HTTPBearer,
)
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
from .sessions import SessionManager
from .web import register_ui_routes

logger = logging.getLogger("playrservers.service")


def _use_secure_cookies() -> bool:
    raw = os.getenv("MANAGEMENT_SESSION_SECURE")
    if raw is None:
        return True
    return raw.strip().lower() not in {"0", "false", "no", "off"}


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
    metadata: Dict[str, str] = Field(default_factory=dict)


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
    basic_security = HTTPBasic(auto_error=False)
    bearer_security = HTTPBearer(auto_error=False)

    def dependency(
        credentials: HTTPBasicCredentials | None = Depends(basic_security),
        bearer: HTTPAuthorizationCredentials | None = Depends(bearer_security),
    ) -> User:
        if bearer is not None:
            user = database.authenticate_api_key(bearer.credentials)
            if user is not None:
                return user

        if credentials is not None:
            user = database.authenticate_user(credentials.username, credentials.password)
            if user is not None:
                return user

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Basic"},
        )

    return dependency


def register_api_routes(
    app: FastAPI,
    registry: AgentRegistry,
    *,
    current_user: Callable[..., User],
) -> None:
    """Expose the JSON API endpoints on the provided FastAPI application."""

    @app.get("/healthz")
    async def healthcheck() -> Dict[str, str]:
        return {"status": "ok"}

    @app.post("/v1/agents/connect", response_model=AgentConnectResponse)
    async def connect_agent(
        request: AgentConnectRequest,
        user: User = Depends(current_user),
    ) -> AgentConnectResponse:
        try:
            session = await registry.connect_agent(
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
                host=registry.tunnel_host,
                port=registry.tunnel_port,
            ),
            connected_at=session.created_at,
            expires_at=session.expires_at(registry.session_timeout),
        )

    @app.post("/v1/agents/{agent_id}/heartbeat", response_model=AgentHeartbeatResponse)
    async def heartbeat(
        agent_id: str,
        request: AgentHeartbeatRequest,
        user: User = Depends(current_user),
    ) -> AgentHeartbeatResponse:
        try:
            session, activated_tunnels = await registry.heartbeat(
                agent_id=agent_id,
                user_id=user.id,
                session_id=request.session_id,
                token=request.agent_token,
                active_tunnels=request.active_tunnels,
                metadata=request.metadata,
            )
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc
        except PermissionError as exc:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
        except KeyError:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")

        for tunnel in activated_tunnels:
            logger.info(
                "Reverse tunnel %s for agent %s is now active (purpose=%s, remote_port=%s)",
                tunnel.id,
                session.agent_id,
                tunnel.purpose,
                tunnel.remote_port,
            )

        return _heartbeat_to_response(session, registry)

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
            tunnel, session = await registry.create_tunnel(
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

        logger.info(
            "User %s opened reverse tunnel %s on agent %s (purpose=%s, remote_port=%s)",
            user.id,
            tunnel.id,
            session.agent_id,
            tunnel.purpose,
            tunnel.remote_port,
        )

        tunnel_kind = tunnel.metadata.get("kind") if tunnel.metadata else None
        if tunnel.purpose == "ssh-terminal" or tunnel_kind == "ssh-terminal":
            target_user = tunnel.metadata.get("target_user") if tunnel.metadata else None
            local_port = tunnel.metadata.get("local_port") if tunnel.metadata else None
            logger.info(
                "User %s initiated SSH session on agent %s via tunnel %s (target_user=%s, local_port=%s, remote_port=%s)",
                user.id,
                session.agent_id,
                tunnel.id,
                target_user or "root",
                local_port,
                tunnel.remote_port,
            )

        return TunnelCreateResponse(
            agent_id=session.agent_id,
            session_id=session.session_id,
            tunnel_id=tunnel.id,
            state=tunnel.state.value,
            purpose=tunnel.purpose,
            remote_port=tunnel.remote_port,
            client_token=tunnel.token,
            endpoint=TunnelEndpoint(
                host=registry.tunnel_host,
                port=registry.tunnel_port,
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
            tunnel, session = await registry.close_tunnel(
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
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")

        logger.info(
            "User %s closed tunnel %s on agent %s (purpose=%s, remote_port=%s)",
            user.id,
            tunnel.id,
            session.agent_id,
            tunnel.purpose,
            tunnel.remote_port,
        )

        return TunnelCloseResponse(
            agent_id=session.agent_id,
            session_id=session.session_id,
            tunnel_id=tunnel.id,
            state=tunnel.state.value,
            purpose=tunnel.purpose,
            remote_port=tunnel.remote_port,
            client_token=tunnel.token,
            endpoint=TunnelEndpoint(
                host=registry.tunnel_host,
                port=registry.tunnel_port,
            ),
            created_at=tunnel.created_at,
            updated_at=tunnel.updated_at,
            description=tunnel.description,
            metadata=dict(tunnel.metadata),
        )

    @app.get("/v1/agents/{agent_id}", response_model=AgentStatusResponse)
    async def get_agent(agent_id: str, user: User = Depends(current_user)) -> AgentStatusResponse:
        try:
            session = await registry.get_session(agent_id=agent_id, user_id=user.id)
        except PermissionError as exc:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
        except KeyError:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")
        return _session_to_status(session, registry)

    @app.get("/v1/agents", response_model=AgentListResponse)
    async def list_agents(user: User = Depends(current_user)) -> AgentListResponse:
        sessions = await registry.list_sessions(user_id=user.id)
        return AgentListResponse(
            agents=[_session_to_status(session, registry) for session in sessions]
        )

    @app.get("/v1/agents/{agent_id}/tunnels", response_model=TunnelListResponse)
    async def list_tunnels(agent_id: str, user: User = Depends(current_user)) -> TunnelListResponse:
        try:
            session = await registry.get_session(agent_id=agent_id, user_id=user.id)
        except PermissionError as exc:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
        except KeyError:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")

        return TunnelListResponse(
            agent_id=session.agent_id,
            tunnels=[_tunnel_to_view(tunnel, registry) for tunnel in session.tunnels.values()],
        )


def create_app(
    *,
    database: Database | None = None,
    registry: AgentRegistry | None = None,
    tunnel_host: str | None = None,
    tunnel_port: int | None = None,
    include_api: bool = True,
    include_web: bool = True,
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

    session_manager: SessionManager | None = None
    secure_cookies = True
    if include_web:
        secure_cookies = _use_secure_cookies()
        if not secure_cookies:
            logger.warning(
                "Session cookies are not marked as secure. Only disable secure cookies for"
                " local development."
            )
        session_manager = SessionManager(ttl=timedelta(hours=8))

    app.state.database = db
    app.state.registry = app_registry
    app.state.session_manager = session_manager

    if include_api:
        current_user = _build_auth_dependency(db)
        register_api_routes(app, app_registry, current_user=current_user)

    if include_web and session_manager is not None:
        register_ui_routes(
            app,
            db,
            app_registry,
            session_manager=session_manager,
            secure_cookies=secure_cookies,
        )

    return app


def create_api_app(
    *,
    database: Database | None = None,
    registry: AgentRegistry | None = None,
    tunnel_host: str | None = None,
    tunnel_port: int | None = None,
) -> FastAPI:
    """Return an application exposing only the agent JSON API."""

    return create_app(
        database=database,
        registry=registry,
        tunnel_host=tunnel_host,
        tunnel_port=tunnel_port,
        include_api=True,
        include_web=False,
    )


def create_web_app(
    *,
    database: Database | None = None,
    registry: AgentRegistry | None = None,
    tunnel_host: str | None = None,
    tunnel_port: int | None = None,
) -> FastAPI:
    """Return an application exposing only the web dashboard."""

    return create_app(
        database=database,
        registry=registry,
        tunnel_host=tunnel_host,
        tunnel_port=tunnel_port,
        include_api=False,
        include_web=True,
    )


__all__ = ["create_app", "create_api_app", "create_web_app"]
