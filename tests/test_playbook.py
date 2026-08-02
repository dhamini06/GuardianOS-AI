"""Tests for the response playbook engine."""

from __future__ import annotations

from backend.core.analysis import DetectionResult, Explanation, MitreReference, Severity
from backend.core.events import EventKind, make_event
from backend.features.extractor import FeatureExtractor, ProcessFeatures
from backend.response.playbook import PlaybookEngine


def _result(severity: Severity = Severity.HIGH, flagged: bool = True) -> DetectionResult:
    return DetectionResult(
        pid=2100,
        exe="/usr/bin/python3",
        raw_score=1.2,
        anomaly_score=0.95,
        confidence=0.9,
        severity=severity,
        flagged=flagged,
    )


def _explanation(techniques: tuple[str, ...] = ()) -> Explanation:
    return Explanation(
        summary="test explanation",
        mitre=[
            MitreReference(
                technique_id=tech,
                name=f"Technique {tech}",
                tactic="execution",
                url=f"https://attack.mitre.org/techniques/{tech}",
                confidence=0.8,
            )
            for tech in techniques
        ],
        confidence=0.9,
        severity=Severity.HIGH,
    )


def _vector_with_ip(ip: str = "203.0.113.9", port: int = 4444) -> ProcessFeatures:
    event = make_event(
        EventKind.NETWORK_CONNECT,
        pid=100,
        ppid=1,
        exe="/usr/bin/python3",
        details={"remote_ip": ip, "remote_port": port},
    )
    return ProcessFeatures(
        pid=100,
        exe="/usr/bin/python3",
        chain_key="100:python3",
        window_start=1.0,
        window_end=2.0,
        related_events=[event],
    )


def test_loads_playbook_yaml():
    engine = PlaybookEngine.load()
    assert len(engine.rules) >= 4


def test_severity_rules_emit_containment(attack_events):
    vector = FeatureExtractor().extract(attack_events)[0]
    actions = PlaybookEngine.load().decide(vector, _result(), _explanation())
    assert {a.action_type for a in actions} == {"kill_process", "block_ip", "quarantine_file"}
    block = next(a for a in actions if a.action_type == "block_ip")
    assert block.target["ip"] == "185.220.101.42"
    quarantine = next(a for a in actions if a.action_type == "quarantine_file")
    assert quarantine.target["path"] == "/tmp/payload.sh"


def test_medium_severity_only_freezes(attack_events):
    vector = FeatureExtractor().extract(attack_events)[0]
    actions = PlaybookEngine.load().decide(vector, _result(severity=Severity.MEDIUM), _explanation())
    assert {a.action_type for a in actions} == {"freeze_process"}


def test_low_severity_no_actions(attack_events):
    vector = FeatureExtractor().extract(attack_events)[0]
    actions = PlaybookEngine.load().decide(vector, _result(severity=Severity.LOW), _explanation())
    assert actions == []


def test_technique_rule_triggers_block_without_severity():
    vector = _vector_with_ip()
    actions = PlaybookEngine.load().decide(
        vector, _result(severity=Severity.LOW), _explanation(techniques=["T1105"])
    )
    assert [a.action_type for a in actions] == ["block_ip"]
    assert actions[0].target["ip"] == "203.0.113.9"


def test_actions_deduplicated_across_rules(attack_events):
    vector = FeatureExtractor().extract(attack_events)[0]
    actions = PlaybookEngine.load().decide(
        vector, _result(severity=Severity.CRITICAL), _explanation(techniques=["T1105"])
    )
    assert len([a for a in actions if a.action_type == "block_ip"]) == 1


def test_private_ips_not_blocked():
    vector = _vector_with_ip(ip="10.0.0.15", port=4444)
    actions = PlaybookEngine.load().decide(
        vector, _result(), _explanation(techniques=["T1105"])
    )
    assert all(a.action_type != "block_ip" for a in actions)


def test_persistence_technique_quarantines_write_targets():
    write = make_event(
        EventKind.FILE_WRITE, pid=100, ppid=1, exe="/usr/bin/cron", details={"path": "/tmp/evil.sh"}
    )
    vector = ProcessFeatures(
        pid=100,
        exe="/usr/bin/cron",
        chain_key="100:cron",
        window_start=1.0,
        window_end=2.0,
        related_events=[write],
    )
    actions = PlaybookEngine.load().decide(
        vector, _result(severity=Severity.LOW), _explanation(techniques=["T1053.003"])
    )
    assert [a.action_type for a in actions] == ["quarantine_file"]
    assert actions[0].target["path"] == "/tmp/evil.sh"


def test_not_flagged_returns_empty(attack_events):
    vector = FeatureExtractor().extract(attack_events)[0]
    actions = PlaybookEngine.load().decide(vector, _result(flagged=False), _explanation())
    assert actions == []
