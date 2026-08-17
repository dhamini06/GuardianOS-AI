"""Tests for API authentication and security utilities."""

from __future__ import annotations

import logging

from backend.api.security import Authenticator
from backend.core.config import AuthConfig


def _auth_config(*, enabled: bool = True, tokens: list[tuple[str, str, list[str]]] | None = None) -> AuthConfig:
    users = [{"name": name, "token": tok, "roles": roles} for name, tok, roles in (tokens or [])]
    return AuthConfig(enabled=enabled, users=users)


# -- Fix 3: default token warning --------------------------------------------

def test_authenticator_warns_on_default_tokens(caplog):
    config = _auth_config(
        tokens=[
            ("admin", "change-me-admin", ["admin"]),
            ("analyst", "change-me-analyst", ["analyst"]),
        ],
    )
    with caplog.at_level(logging.WARNING, logger="guardianos.api.security"):
        Authenticator(config)
    assert "change-me-admin" in caplog.text


def test_authenticator_no_warning_on_custom_tokens(caplog):
    config = _auth_config(
        tokens=[
            ("admin", "super-secret-token-xyz", ["admin"]),
        ],
    )
    with caplog.at_level(logging.WARNING, logger="guardianos.api.security"):
        Authenticator(config)
    assert "default values" not in caplog.text


def test_authenticator_no_warning_when_disabled(caplog):
    config = _auth_config(
        enabled=False,
        tokens=[
            ("admin", "change-me-admin", ["admin"]),
        ],
    )
    with caplog.at_level(logging.WARNING, logger="guardianos.api.security"):
        Authenticator(config)
    assert "default values" not in caplog.text
