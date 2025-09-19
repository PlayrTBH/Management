"""Security helpers for API key authentication."""
from __future__ import annotations

from fastapi import HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .database import Database
from .models import User


class APIKeyAuth:
    """Bearer token authentication backed by the database."""

    def __init__(self, db: Database) -> None:
        self._db = db
        self._bearer = HTTPBearer(auto_error=False)

    async def __call__(self, request: Request) -> User:
        credentials: HTTPAuthorizationCredentials | None = await self._bearer(request)  # type: ignore[assignment]
        if credentials is None or credentials.scheme.lower() != "bearer":
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing API key")

        api_key = credentials.credentials.strip()
        if not api_key:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing API key")

        user = self._db.get_user_by_api_key(api_key)
        if user is None:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid API key")
        return user


__all__ = ["APIKeyAuth"]
