"""Decision engine: derives remediation actions from a detection.

The decision engine only *recommends*. All execution goes through the
approval gate and executor so destructive operations stay human-in-the-loop.
Rules live in a declarative playbook (``config/playbooks.yaml``) so responses
can be tuned per severity and MITRE technique without touching code.
"""

from __future__ import annotations

from backend.core.analysis import DetectionResult, Explanation, ResponseAction
from backend.features.extractor import ProcessFeatures
from backend.response.playbook import PlaybookEngine


class DecisionEngine:
    """Maps a detection to safe, evidence-backed remediation actions."""

    def __init__(self, playbook: PlaybookEngine | None = None) -> None:
        self._playbook = playbook if playbook is not None else PlaybookEngine.load()

    def decide(
        self,
        vector: ProcessFeatures,
        result: DetectionResult,
        explanation: Explanation,
    ) -> list[ResponseAction]:
        return self._playbook.decide(vector, result, explanation)
