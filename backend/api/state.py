"""Shared runtime state handed to API routes and WebSocket clients."""

from __future__ import annotations

from dataclasses import dataclass

from backend.api.changes import ChangeLog
from backend.api.driver import PipelineDriver
from backend.api.security import Authenticator
from backend.pipeline import GuardianPipeline


@dataclass(slots=True)
class RuntimeState:
    """Bundle of live objects the API layer operates on."""

    pipeline: GuardianPipeline
    changes: ChangeLog
    authenticator: Authenticator
    driver: PipelineDriver | None = None
