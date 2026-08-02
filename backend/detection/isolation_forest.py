"""Isolation Forest behavioural detector (MVP model).

Isolation Forest isolates anomalies by randomly splitting feature space;
samples that need few splits to isolate are anomalous. It is the ideal MVP
model because it is unsupervised (learns "normal" without attack labels),
cheap to retrain per-machine, and naturally supports online baselines.

Per-feature attribution uses leave-one-out scoring: we re-score the sample
after replacing each feature with its baseline median and measure how much
the raw score drops. The features whose removal normalises the sample are the
ones that made it anomalous - this is the raw material for the
explainability layer.
"""

from __future__ import annotations

from pathlib import Path

import numpy as np
from joblib import dump, load
from sklearn.ensemble import IsolationForest

from backend.core.analysis import DetectionResult
from backend.core.logging import get_logger
from backend.detection.base import DetectorError
from backend.detection.scoring import compute_detection_result
from backend.features.extractor import ProcessFeatures
from backend.features.names import FEATURE_NAMES, FEATURE_SCHEMA_VERSION

logger = get_logger("detection.isolation_forest")


class IsolationForestDetector:
    """Unsupervised anomaly detector built on scikit-learn's Isolation Forest."""

    def __init__(
        self,
        *,
        contamination: float = 0.01,
        n_estimators: int = 200,
        max_samples: int = 256,
        flagged_threshold: float = 0.60,
        random_state: int = 42,
    ) -> None:
        self._contamination = contamination
        self._flagged_threshold = flagged_threshold
        self._model = IsolationForest(
            n_estimators=n_estimators,
            max_samples=max_samples,
            contamination=contamination,
            random_state=random_state,
        )
        self._trained = False
        self._raw_min = 0.0
        self._raw_max = 0.0
        self._baseline_median: np.ndarray | None = None

    # -- lifecycle --------------------------------------------------------
    @property
    def is_trained(self) -> bool:
        return self._trained

    def fit(self, vectors: list[ProcessFeatures]) -> IsolationForestDetector:
        if not vectors:
            raise DetectorError("fit() requires at least one feature vector")
        X = np.asarray([v.to_vector() for v in vectors], dtype=float)

        # IsolationForest warns if max_samples exceeds n_samples; clamp it.
        n_samples = X.shape[0]
        max_samples = min(self._model.max_samples, n_samples) if self._model.max_samples else None
        self._model.set_params(max_samples=max_samples)
        self._model.fit(X)

        # Calibration: normal samples have negative raw scores (positive
        # decision_function); the model's offset_ is the learned boundary
        # between normal and anomalous at the configured contamination. We
        # normalise so score 1.0 == the boundary and 0.0 == the most normal
        # baseline point.
        raw_scores = -self._model.decision_function(X)
        self._raw_min = float(np.percentile(raw_scores, 5))
        self._raw_max = float(-self._model.offset_) if self._model.offset_ is not None else 0.0
        self._baseline_median = np.median(X, axis=0)
        self._trained = True
        logger.info(
            "Detector trained on %d samples (raw score range [%.3f, %.3f])",
            len(vectors),
            self._raw_min,
            self._raw_max,
        )
        return self

    def predict(self, vector: ProcessFeatures) -> DetectionResult:
        self._require_trained()
        raw = float(-self._model.decision_function(np.asarray([vector.to_vector()]))[0])
        return compute_detection_result(
            vector,
            raw_score=raw,
            score_min=self._raw_min,
            score_max=self._raw_max,
            flagged_threshold=self._flagged_threshold,
            contributions=self.feature_contributions(vector),
        )

    def feature_contributions(self, vector: ProcessFeatures) -> dict[str, float]:
        """Leave-one-out attribution against the baseline median.

        Batched into a single ``decision_function`` call so attribution stays
        cheap enough to run per-window on every chain.
        """
        self._require_trained()
        base = float(-self._model.decision_function(np.asarray([vector.to_vector()]))[0])

        probes = np.repeat(np.asarray([vector.to_vector()], dtype=float), len(FEATURE_NAMES), axis=0)
        for i in range(len(FEATURE_NAMES)):
            probes[i, i] = self._baseline_median[i]
        probe_scores = -self._model.decision_function(probes)

        return {
            name: round(max(0.0, base - float(probe)), 4)
            for name, probe in zip(FEATURE_NAMES, probe_scores, strict=True)
        }

    # -- persistence ------------------------------------------------------
    def save(self, path: str) -> None:
        self._require_trained()
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "schema_version": FEATURE_SCHEMA_VERSION,
            "model": self._model,
            "raw_min": self._raw_min,
            "raw_max": self._raw_max,
            "baseline_median": self._baseline_median,
            "flagged_threshold": self._flagged_threshold,
        }
        dump(payload, target)
        logger.info("Detector saved to %s", target)

    @classmethod
    def load(cls, path: str) -> IsolationForestDetector:
        payload = load(path)
        stored = payload.get("schema_version")
        if stored != FEATURE_SCHEMA_VERSION:
            raise DetectorError(
                f"Persisted detector uses feature schema v{stored} but this build "
                f"expects v{FEATURE_SCHEMA_VERSION}. Retrain the baseline."
            )
        detector = cls(flagged_threshold=payload["flagged_threshold"])
        detector._model = payload["model"]
        detector._raw_min = payload["raw_min"]
        detector._raw_max = payload["raw_max"]
        detector._baseline_median = payload["baseline_median"]
        detector._trained = True
        return detector

    # -- internals --------------------------------------------------------
    def _require_trained(self) -> None:
        if not self._trained:
            raise DetectorError(
                "Detector is not trained. Fit it on a baseline of normal behaviour first."
            )

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return f"<IsolationForestDetector trained={self._trained}>"
