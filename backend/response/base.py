"""Action executor contract (Layer 5 interface)."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from backend.core.analysis import ResponseAction


class ActionExecutorError(RuntimeError):
    """Raised when an action cannot be executed."""


@runtime_checkable
class ActionExecutor(Protocol):
    """Performs a :class:`ResponseAction` against the live system.

    Executors are responsible for honouring dry-run mode and for marking the
    action's lifecycle status (``EXECUTED`` or ``FAILED``).
    """

    def execute(self, action: ResponseAction) -> ResponseAction:
        """Execute the action, returning it with an updated status."""
        ...
