"""Analysis result models shared across detection / explainability / response.

These dataclasses are the output contracts of Layers 3-5 and feed the
dashboard (Layer 6). They are intentionally plain and serialisable so the
pipeline, API layer and dashboard can be developed independently.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Severity(StrEnum):
    """Risk severity of a detection."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value


class ActionStatus(StrEnum):
    """Lifecycle state of a recommended/performed response action."""

    RECOMMENDED = "recommended"
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTED = "executed"
    FAILED = "failed"

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value


@dataclass(slots=True)
class ChainStep:
    """A single, human-readable link in an observed behaviour chain."""

    position: int
    description: str
    kind: str
    exe: str
    pid: int
    suspicious: bool = False
    detail: str | None = None


@dataclass(slots=True)
class MitreReference:
    """A MITRE ATT&CK technique mapping."""

    technique_id: str  # e.g. "T1059"
    name: str
    tactic: str
    url: str

    def __str__(self) -> str:
        return f"{self.technique_id} ({self.name} / {self.tactic})"


@dataclass(slots=True)
class DetectionResult:
    """Output of the AI detection engine (Layer 3)."""

    pid: int
    exe: str
    raw_score: float
    anomaly_score: float  # normalised 0..1
    confidence: float  # 0..1
    severity: Severity
    flagged: bool
    contributing_features: dict[str, float] = field(default_factory=dict)
    context: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "pid": self.pid,
            "exe": self.exe,
            "raw_score": self.raw_score,
            "anomaly_score": self.anomaly_score,
            "confidence": self.confidence,
            "severity": self.severity.value,
            "flagged": self.flagged,
            "contributing_features": self.contributing_features,
            "context": self.context,
        }


@dataclass(slots=True)
class Explanation:
    """Analyst-friendly explanation produced by Layer 4."""

    summary: str
    reasons: list[str] = field(default_factory=list)
    chain: list[ChainStep] = field(default_factory=list)
    mitre: list[MitreReference] = field(default_factory=list)
    confidence: float = 0.0
    severity: Severity = Severity.INFO

    def __str__(self) -> str:
        lines = [self.summary, ""]
        lines += [f"  - {r}" for r in self.reasons]
        if self.chain:
            lines.append("")
            lines += [f"    {s.position}. {s.description}" for s in self.chain]
        if self.mitre:
            lines.append("")
            lines.append("  MITRE ATT&CK:")
            lines += [f"    {m}" for m in self.mitre]
        lines.append(f"\n  Confidence: {self.confidence:.0%} | Severity: {self.severity.value}")
        return "\n".join(lines)


@dataclass(slots=True)
class ResponseAction:
    """A recommended (or performed) remediation action (Layer 5)."""

    action_type: str  # e.g. "kill_process", "block_ip", "quarantine_file"
    description: str
    destructive: bool
    requires_approval: bool
    target: dict[str, Any] = field(default_factory=dict)
    status: ActionStatus = ActionStatus.RECOMMENDED
    rationale: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_type": self.action_type,
            "description": self.description,
            "destructive": self.destructive,
            "requires_approval": self.requires_approval,
            "target": self.target,
            "status": self.status.value,
            "rationale": self.rationale,
        }


@dataclass(slots=True)
class ThreatReport:
    """Complete report for one flagged detection, aggregated by the pipeline."""

    report_id: str
    timestamp: float
    detection: DetectionResult
    explanation: Explanation
    actions: list[ResponseAction] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        from dataclasses import asdict

        return {
            "report_id": self.report_id,
            "timestamp": self.timestamp,
            "detection": self.detection.to_dict(),
            "explanation": {
                "summary": self.explanation.summary,
                "reasons": self.explanation.reasons,
                "chain": [asdict(s) for s in self.explanation.chain],
                "mitre": [asdict(m) for m in self.explanation.mitre],
                "confidence": self.explanation.confidence,
                "severity": self.explanation.severity.value,
            },
            "actions": [a.to_dict() for a in self.actions],
        }
