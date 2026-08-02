"""Explainer contract (Layer 4 interface)."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from backend.core.analysis import DetectionResult, Explanation
from backend.features.extractor import ProcessFeatures


class ExplainerError(RuntimeError):
    """Raised when an explanation cannot be produced."""


@runtime_checkable
class Explainer(Protocol):
    """Turns a detection plus its source events into a human explanation."""

    def explain(self, vector: ProcessFeatures, result: DetectionResult) -> Explanation:
        """Produce an analyst-friendly explanation for a detection."""
        ...
