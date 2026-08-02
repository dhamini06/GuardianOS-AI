"""AI detection layer (Layer 3).

Learns what is normal for the machine and flags behavioural deviations.
Detectors implement :class:`AnomalyDetector`; the MVP ships an Isolation
Forest implementation, with Autoencoders and graph anomaly detectors planned
as follow-ups.
"""

from backend.detection.base import AnomalyDetector, DetectorError
from backend.detection.isolation_forest import IsolationForestDetector
from backend.detection.scoring import compute_detection_result

__all__ = [
    "AnomalyDetector",
    "DetectorError",
    "IsolationForestDetector",
    "compute_detection_result",
]
