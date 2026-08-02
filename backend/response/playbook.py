"""Playbook engine: configurable responses per severity / technique.

The decision layer is driven by declarative YAML rules instead of hard-coded
severity branches. Each rule matches on detection severity and/or the MITRE
techniques present in the explanation, and expands to the listed remediation
actions with concrete targets extracted from the chain. Actions are
de-duplicated across rules (first match wins per action type).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from backend.core.analysis import DetectionResult, Explanation, ResponseAction
from backend.core.events import EventKind
from backend.core.logging import get_logger
from backend.features.extractor import ProcessFeatures
from backend.response.actions import ResponseActionBuilder

logger = get_logger("response.playbook")

DEFAULT_PLAYBOOK_PATH = Path(__file__).resolve().parents[2] / "config" / "playbooks.yaml"

#: Built-in rules used when no playbook file is configured (equivalent to the
#: pre-M5 hard-coded severity logic, so existing behaviour is preserved).
DEFAULT_RULES: list[dict[str, Any]] = [
    {
        "name": "critical_high_containment",
        "when": {"severity": ["critical", "high"]},
        "actions": ["kill_process", "block_ip", "quarantine_file"],
    },
    {
        "name": "medium_investigate",
        "when": {"severity": ["medium"]},
        "actions": ["freeze_process"],
    },
]


class PlaybookEngine:
    """Maps detections to remediation actions via declarative rules."""

    def __init__(self, rules: list[dict[str, Any]] | None = None) -> None:
        self._rules = rules if rules is not None else list(DEFAULT_RULES)
        self._builder = ResponseActionBuilder()

    @classmethod
    def load(cls, path: str | Path | None = None) -> PlaybookEngine:
        """Load rules from YAML; falls back to :data:`DEFAULT_RULES`."""
        target = Path(path) if path else DEFAULT_PLAYBOOK_PATH
        if not target.exists():
            logger.info("Playbook %s not found; using built-in default rules", target)
            return cls()
        with target.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        rules = (data.get("playbook") or []) if isinstance(data, dict) else []
        logger.info("Loaded %d playbook rule(s) from %s", len(rules), target)
        return cls(rules)

    @property
    def rules(self) -> list[dict[str, Any]]:
        return list(self._rules)

    def decide(
        self,
        vector: ProcessFeatures,
        result: DetectionResult,
        explanation: Explanation,
    ) -> list[ResponseAction]:
        """Return the de-duplicated actions for a detection."""
        if not result.flagged:
            return []
        actions: list[ResponseAction] = []
        seen: set[tuple[str, str]] = set()
        for rule in self._rules:
            if not self._matches(rule, result, explanation):
                continue
            for action_type in rule.get("actions", []):
                for action in self._build(action_type, vector, result, rule):
                    key = (action.action_type, self._target_key(action))
                    if key in seen:
                        continue
                    seen.add(key)
                    actions.append(action)
        return actions

    # -- matching ----------------------------------------------------------
    def _matches(
        self,
        rule: dict[str, Any],
        result: DetectionResult,
        explanation: Explanation,
    ) -> bool:
        when = rule.get("when") or {}
        severities = when.get("severity")
        if severities and result.severity.value not in severities:
            return False
        techniques = when.get("techniques")
        if techniques:
            present = {m.technique_id for m in explanation.mitre}
            if not present.intersection(techniques):
                return False
        return True

    # -- action expansion --------------------------------------------------
    def _build(
        self,
        action_type: str,
        vector: ProcessFeatures,
        result: DetectionResult,
        rule: dict[str, Any],
    ) -> list[ResponseAction]:
        rationale = f"Playbook [{rule.get('name', '?')}] detected anomaly (score {result.anomaly_score:.2f})"
        if action_type == "kill_process":
            return [self._builder.kill_process(vector.pid, vector.basename, rationale)]
        if action_type == "freeze_process":
            return [self._builder.freeze_process(vector.pid, vector.basename, rationale)]
        if action_type == "block_ip":
            return [
                self._builder.block_ip(ip, rationale) for ip in self._suspicious_ips(vector)
            ]
        if action_type == "quarantine_file":
            return [
                self._builder.quarantine_file(path, rationale)
                for path in self._tmp_payloads(vector)
            ]
        logger.warning("Unknown playbook action type %r; skipping", action_type)
        return []

    @staticmethod
    def _suspicious_ips(vector: ProcessFeatures) -> list[str]:
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

    @staticmethod
    def _tmp_payloads(vector: ProcessFeatures) -> list[str]:
        paths: list[str] = []
        for event in vector.related_events:
            if event.kind == EventKind.FILE_WRITE:
                path = event.details.get("path", "")
                if path.startswith(("/tmp", "/dev/shm", "/var/tmp")) and path not in paths:
                    paths.append(path)
        return paths

    @staticmethod
    def _target_key(action: ResponseAction) -> str:
        if "pid" in action.target:
            return f"pid:{action.target['pid']}"
        if "ip" in action.target:
            return f"ip:{action.target['ip']}"
        if "path" in action.target:
            return f"path:{action.target['path']}"
        return "default"
