"""Bearer-token auth middleware."""
from __future__ import annotations

import secrets

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.config import settings


bearer = HTTPBearer(auto_error=False)


async def require_token(
    request: Request, creds: HTTPAuthorizationCredentials | None = Depends(bearer)
) -> None:
    if settings.auth_disabled:
        return
    token = creds.credentials if creds is not None and creds.scheme.lower() == "bearer" else None
    if token is None or not secrets.compare_digest(token, settings.auth_token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )
