"""Decision engine: derives remediation actions from a detection.

The decision engine only *recommends*. All execution goes through the
approval gate and executor so destructive operations stay human-in-the-loop.
"""

from __future__ import annotations

from backend.core.analysis import DetectionResult, Explanation, ResponseAction, Severity
from backend.core.events import EventKind
from backend.features.extractor import ProcessFeatures
from backend.response.actions import ResponseActionBuilder


class DecisionEngine:
    """Maps a detection to safe, evidence-backed remediation actions."""

    def __init__(self) -> None:
        self._builder = ResponseActionBuilder()

    def decide(
        self,
        vector: ProcessFeatures,
        result: DetectionResult,
        explanation: Explanation,
    ) -> list[ResponseAction]:
        if not result.flagged:
            return []

        actions: list[ResponseAction] = []
        rationale = f"Detected anomaly (score {result.anomaly_score:.2f})"

        if result.severity in (Severity.HIGH, Severity.CRITICAL):
            actions.append(
                self._builder.kill_process(vector.pid, vector.basename, rationale)
            )
        elif result.severity == Severity.MEDIUM:
            actions.append(
                self._builder.freeze_process(vector.pid, vector.basename, rationale)
            )

        suspicious_ips = self._suspicious_ips(vector)
        for ip in suspicious_ips:
            actions.append(self._builder.block_ip(ip, rationale))

        for path in self._tmp_payloads(vector):
            actions.append(self._builder.quarantine_file(path, rationale))

        return actions

    # -- helpers ----------------------------------------------------------
    def _suspicious_ips(self, vector: ProcessFeatures) -> list[str]:
        ips: list[str] = []
        for event in vector.related_events:
            if event.kind != EventKind.NETWORK_CONNECT:
                continue
            ip = event.details.get("remote_ip")
            port = event.details.get("remote_port")
            if not ip or ip.startswith(("10.", "192.168.", "127.", "169.254.")):
                continue
            if port and port not in (80, 443, 22, 53) and port > 1024 and ip not in ips:
                ips.append(ip)
        return ips

    def _tmp_payloads(self, vector: ProcessFeatures) -> list[str]:
        paths: list[str] = []
        for event in vector.related_events:
            if event.kind == EventKind.FILE_WRITE:
                path = event.details.get("path", "")
                if path.startswith(("/tmp", "/dev/shm", "/var/tmp")) and path not in paths:
                    paths.append(path)
        return paths
