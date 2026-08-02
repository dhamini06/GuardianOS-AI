"""Shared core domain models and interfaces.

This package defines the *contracts* every other layer depends on. It is
deliberately dependency-free (standard library only) so that all modules
remain decoupled and independently testable.
"""

from backend.core.analysis import (
    ActionStatus,
    ChainStep,
    DetectionResult,
    Explanation,
    MitreReference,
    ResponseAction,
    Severity,
    ThreatReport,
)
from backend.core.events import (
    EventKind,
    KernelEvent,
    event_chain_key,
)

__all__ = [
    "EventKind",
    "KernelEvent",
    "event_chain_key",
    "ActionStatus",
    "ChainStep",
    "DetectionResult",
    "Explanation",
    "MitreReference",
    "ResponseAction",
    "Severity",
    "ThreatReport",
]
