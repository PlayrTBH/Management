"""Security helpers for the management API."""
from __future__ import annotations

import os
import secrets
from typing import Iterable, List

from fastapi import HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer


class TokenAuth:
    """Bearer token authentication using constant-time comparisons."""

    def __init__(self, tokens: Iterable[str]):
        token_list: List[str] = [token.strip() for token in tokens if token.strip()]
        if not token_list:
            raise ValueError("At least one API token must be provided")
        self._tokens = token_list
        self._bearer = HTTPBearer(auto_error=False)

    async def __call__(self, request: Request) -> None:
        credentials: HTTPAuthorizationCredentials | None = await self._bearer(request)  # type: ignore[assignment]
        if credentials is None or credentials.scheme.lower() != "bearer":
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token")

        provided = credentials.credentials
        for token in self._tokens:
            if secrets.compare_digest(provided, token):
                return None

        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid API token")


def load_tokens_from_env() -> List[str]:
    raw = os.getenv("MANAGEMENT_API_TOKENS", "")
    return [token.strip() for token in raw.split(",") if token.strip()]


__all__ = ["TokenAuth", "load_tokens_from_env"]
