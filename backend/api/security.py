"""API authentication and role-based access control.

Roles are hierarchical: ``viewer`` < ``analyst`` < ``admin``. Read endpoints
require ``viewer``, analyst feedback requires ``analyst``, and destructive
remediation (approve / reject / execute / rollback) requires ``admin``.

Tokens are read from ``config/auth``; each user's token can be overridden
through the ``GUARDIAN_TOKEN_<NAME>`` environment variable (e.g.
``GUARDIAN_TOKEN_ADMIN``). When ``auth.enabled`` is false every request is
granted a pseudo-user with all roles (local demo mode).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status

from backend.core.config import AuthConfig

ROLE_LEVEL = {"viewer": 0, "analyst": 1, "admin": 2}
ALL_ROLES = frozenset(ROLE_LEVEL)


@dataclass(frozen=True, slots=True)
class User:
    """An authenticated principal with a set of roles."""

    name: str
    roles: frozenset[str]

    def has_role(self, required: str) -> bool:
        level = ROLE_LEVEL[required]
        return max((ROLE_LEVEL.get(r, -1) for r in self.roles), default=-1) >= level


class Authenticator:
    """Maps bearer tokens to users with roles."""

    def __init__(self, config: AuthConfig) -> None:
        self.enabled = config.enabled
        self.header = config.token_header
        self.default_role = config.default_role
        self._tokens: dict[str, User] = {}
        for user_cfg in config.users:
            name = str(user_cfg.get("name") or "anonymous")
            token = os.environ.get(
                f"GUARDIAN_TOKEN_{name.upper()}",
                user_cfg.get("token") or "",
            )
            roles = frozenset(user_cfg.get("roles") or [self.default_role])
            if token:
                self._tokens[token] = User(name=name, roles=roles)
        admin_token = os.environ.get("GUARDIAN_ADMIN_TOKEN")
        if admin_token:
            self._tokens[admin_token] = User(name="admin", roles=frozenset({"admin"}))

    def authenticate(self, token: str | None) -> User | None:
        if not token:
            return None
        return self._tokens.get(token)

    def open_access(self) -> User:
        """Pseudo-user with every role, used when auth is disabled."""
        return User(name="anonymous", roles=ALL_ROLES)


def get_state(request: Request) -> object:
    """Dependency: the shared :class:`RuntimeState` held on the app."""
    return request.app.state.guardian


def get_user(request: Request, state: Annotated[object, Depends(get_state)]) -> User:
    """Dependency: resolve the request's principal from its token header."""
    authenticator = state.authenticator
    if not authenticator.enabled:
        return authenticator.open_access()
    token = request.headers.get(authenticator.header)
    user = authenticator.authenticate(token)
    if user is None:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing token",
        )
    return user


def require_role(required: str):
    """Dependency factory: reject requests below ``required`` role."""

    def dependency(user: Annotated[User, Depends(get_user)]) -> User:
        if not user.has_role(required):
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                detail=f"Role '{required}' required",
            )
        return user

    return dependency


GuardianState = Annotated[object, Depends(get_state)]
AdminUser = Annotated[User, Depends(require_role("admin"))]
AnalystUser = Annotated[User, Depends(require_role("analyst"))]
ViewerUser = Annotated[User, Depends(require_role("viewer"))]
