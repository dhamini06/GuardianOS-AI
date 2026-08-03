"""Isolation Forest behavioural detector (MVP model).

Isolation Forest isolates anomalies by randomly splitting feature space;
samples that need few splits to isolate are anomalous. It is the ideal MVP
model because it is unsupervised (learns "normal" without attack labels),
cheap to retrain per-machine, and naturally supports online baselines.

Per-feature attribution is SHAP-style: instead of probing against a single
median baseline, we sample background rows from the learned baseline
distribution and average the raw-score drop when each feature is replaced
with a background value. This mirrors how SHAP perturbs an instance against
a reference set and yields attribution that is stable and faithful to the
whole baseline, not a single central point. Models trained before M4 fall
back to a single median probe automatically.
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
        background_samples: int = 64,
        random_state: int = 42,
    ) -> None:
        self._contamination = contamination
        self._flagged_threshold = flagged_threshold
        self._background_samples = background_samples
        self._random_state = random_state
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
        self._baseline_rows: np.ndarray | None = None

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
        # Keep a bounded reservoir of baseline rows so SHAP-style attribution
        # can sample the distribution instead of probing a single median.
        rng = np.random.default_rng(self._random_state)
        if X.shape[0] <= 256:
            self._baseline_rows = X.copy()
        else:
            self._baseline_rows = X[rng.choice(X.shape[0], size=256, replace=False)]
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
        result = compute_detection_result(
            vector,
            raw_score=raw,
            score_min=self._raw_min,
            score_max=self._raw_max,
            flagged_threshold=self._flagged_threshold,
            contributions={},
        )
        # Attribution is explainability for alerts: it is only meaningful for
        # flagged chains and is expensive (sampling estimator), so compute it
        # lazily instead of paying it on every (mostly normal) vector.
        if result.flagged:
            result.contributing_features = self.feature_contributions(vector)
        return result

    def feature_contributions(self, vector: ProcessFeatures) -> dict[str, float]:
        """SHAP-style per-feature attribution against the baseline.

        Uses the Strumbej-Kononenko sampling estimator: for a sample of
        baseline rows, each feature's attribution is the average marginal
        contribution of swapping that feature between the observed sample and
        the baseline row, measured in both directions. Averaging over the
        baseline distribution (rather than a single median) yields attribution
        that is stable and captures correlations between features. Models
        without a stored baseline (pre M4) fall back to a single median probe.
        """
        self._require_trained()
        x = np.asarray([vector.to_vector()], dtype=float)[0]
        base = float(-self._model.decision_function(x[None, :])[0])

        if self._baseline_rows is None or len(self._baseline_rows) == 0:
            median = self._baseline_median
            if median is None:
                median = np.zeros(len(FEATURE_NAMES))
            probes = np.repeat(x[None, :], len(FEATURE_NAMES), axis=0)
            for i in range(len(FEATURE_NAMES)):
                probes[i, i] = median[i]
            probe_scores = -self._model.decision_function(probes)
            return {
                name: round(max(0.0, base - float(probe)), 4)
                for name, probe in zip(FEATURE_NAMES, probe_scores, strict=True)
            }

        rng = np.random.default_rng(self._random_state)
        n = min(max(1, self._background_samples), len(self._baseline_rows))
        background = self._baseline_rows[
            rng.integers(0, len(self._baseline_rows), size=n)
        ]
        d = len(FEATURE_NAMES)
        phi = np.zeros(d)
        for b in background:
            x_replace = np.repeat(x[None, :], d, axis=0)
            b_replace = np.repeat(b[None, :], d, axis=0)
            for i in range(d):
                x_replace[i, i] = b[i]
                b_replace[i, i] = x[i]
            scores = -self._model.decision_function(
                np.vstack([x[None, :], b[None, :], x_replace, b_replace])
            )
            f_x, f_b = scores[0], scores[1]
            s_xr = scores[2 : 2 + d]
            s_br = scores[2 + d : 2 + 2 * d]
            phi += (f_x - s_xr) + (s_br - f_b)
        phi /= 2.0 * n
        return {
            name: round(float(value), 4)
            for name, value in zip(FEATURE_NAMES, np.clip(phi, 0.0, None), strict=True)
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
            "baseline_rows": self._baseline_rows.tolist() if self._baseline_rows is not None else None,
            "background_samples": self._background_samples,
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
        stored_rows = payload.get("baseline_rows")
        detector._baseline_rows = (
            np.asarray(stored_rows, dtype=float) if stored_rows is not None else None
        )
        detector._background_samples = payload.get("background_samples", 64)
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
