"""Anomaly detector contracts (Layer 3 interface)."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from backend.core.analysis import DetectionResult
from backend.features.extractor import ProcessFeatures


class DetectorError(RuntimeError):
    """Raised when a detector is used in an invalid state."""


@runtime_checkable
class AnomalyDetector(Protocol):
    """A behavioural anomaly detector.

    Lifecycle: one or more :meth:`fit` calls build the baseline, then
    :meth:`predict` scores new feature vectors. Predicting before fitting
    raises :class:`DetectorError`.
    """

    @property
    def is_trained(self) -> bool: ...

    def fit(self, vectors: list[ProcessFeatures]) -> AnomalyDetector:
        """Learn the normal behavioural baseline from the given window."""
        ...

    def predict(self, vector: ProcessFeatures) -> DetectionResult:
        """Score a single feature vector."""
        ...

    def feature_contributions(self, vector: ProcessFeatures) -> dict[str, float]:
        """Per-feature anomaly attribution (how much each feature deviated)."""
        ...

    def save(self, path: str) -> None: ...

    @classmethod
    def load(cls, path: str) -> AnomalyDetector: ...
