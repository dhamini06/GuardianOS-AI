"""Response engine (Layer 5).

Recommends and safely performs remediation. Destructive actions always gate
behind approval; the MVP defaults to ``dry_run`` so nothing destructive ever
executes without explicit opt-in.
"""

from backend.response.actions import ResponseActionBuilder
from backend.response.approval import ApprovalGate
from backend.response.base import ActionExecutor, ActionExecutorError
from backend.response.decision import DecisionEngine

__all__ = [
    "ActionExecutor",
    "ActionExecutorError",
    "ResponseActionBuilder",
    "DecisionEngine",
    "ApprovalGate",
]
