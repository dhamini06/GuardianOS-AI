"""Normalisation of raw model output into threat semantics.

Isolation Forest (and most unsupervised detectors) emit a raw score with no
meaningful scale. This module maps raw scores to an interpretable
``(anomaly_score, confidence, severity, flagged)`` tuple used everywhere
downstream. Keeping this logic separate lets new detectors reuse the same
semantics without re-implementing thresholds.

Detection is *hybrid*: the unsupervised ML score captures behavioural
deviation from the learned baseline, and a hard-signal score (below) captures
well-known malicious primitives (exec from /tmp, high-port egress, privilege
escalation, interpreter chains). The final score is the stronger of the two,
so classic kill chains are never missed while the baseline still drives
long-tail anomaly detection.
"""

from __future__ import annotations

from backend.core.analysis import DetectionResult, Severity
from backend.features.extractor import ProcessFeatures


def signal_anomaly(vector: ProcessFeatures) -> float:
    """0..1 hard-signal score from a chain's behavioural indicators."""
    v = vector.values
    score = 0.0
    if v.get("tmp_execs", 0.0) > 0:
        score += 0.50  # execution from world-writable staging dir
    if v.get("suspicious_ports", 0.0) > 0:
        score += 0.45  # egress to non-standard high port
    if v.get("privilege_escalations", 0.0) > 0:
        score += 0.40  # privilege boundary crossed
    if v.get("script_interpreters", 0.0) >= 2:
        score += 0.20  # interpreter spawning interpreter
    return min(1.0, score)


def _scale(raw: float, score_min: float, score_max: float) -> float:
    if score_max <= score_min:
        return 0.0
    return min(1.0, max(0.0, (raw - score_min) / (score_max - score_min)))


def _severity(anomaly_score: float, contributions: dict[str, float]) -> Severity:
    if anomaly_score >= 0.93:
        return Severity.CRITICAL
    if anomaly_score >= 0.85:
        return Severity.HIGH
    if anomaly_score >= 0.75:
        return Severity.MEDIUM
    if anomaly_score >= 0.60:
        return Severity.LOW
    return Severity.INFO


def compute_detection_result(
    vector: ProcessFeatures,
    *,
    raw_score: float,
    score_min: float,
    score_max: float,
    flagged_threshold: float,
    contributions: dict[str, float] | None = None,
) -> DetectionResult:
    """Build a :class:`DetectionResult` from a raw score and calibration range."""
    ml_score = _scale(raw_score, score_min, score_max)
    signal_score = signal_anomaly(vector)
    anomaly_score = max(ml_score, signal_score)
    flagged = anomaly_score >= flagged_threshold
    contributions = contributions or {}

    return DetectionResult(
        pid=vector.pid,
        exe=vector.exe,
        raw_score=raw_score,
        anomaly_score=round(anomaly_score, 4),
        confidence=round(anomaly_score, 4),
        severity=_severity(anomaly_score, contributions),
        flagged=flagged,
        contributing_features=contributions,
        context={
            "chain_key": vector.chain_key,
            "window": [vector.window_start, vector.window_end],
            "ml_score": round(ml_score, 4),
            "signal_score": round(signal_score, 4),
        },
    )
