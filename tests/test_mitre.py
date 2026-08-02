"""Tests for MITRE ATT&CK mapping with per-technique confidence (M4)."""

from __future__ import annotations

from backend.explainability.mitre import map_techniques


def test_technique_confidences_in_range(normal_events, attack_events):
    for events in (attack_events, normal_events):
        for technique in map_techniques(events):
            assert 0.0 <= technique.confidence <= 1.0


def test_attack_kill_chain_has_confidence(normal_events, attack_events):
    techniques = map_techniques(attack_events)
    ids = {t.technique_id for t in techniques}
    assert "T1105" in ids
    assert "T1204.002" in ids
    assert "T1059.004" in ids
    confidence = {t.technique_id: t.confidence for t in techniques}
    assert confidence["T1204.002"] >= 0.85
    assert confidence["T1105"] >= 0.65


def test_confidence_grows_with_evidence(attack_events):
    single = map_techniques(attack_events[:6])
    full = map_techniques(attack_events)
    single_conf = {t.technique_id: t.confidence for t in single}
    full_conf = {t.technique_id: t.confidence for t in full}
    for technique_id, conf in full_conf.items():
        if technique_id in single_conf:
            assert conf >= single_conf[technique_id]


def test_cron_persistence_mapping():
    from backend.core.events import EventKind, make_event

    events = [
        make_event(
            EventKind.FILE_WRITE,
            pid=1,
            ppid=0,
            exe="/bin/bash",
            details={"path": "/etc/cron.d/persist.sh"},
            timestamp=1.0,
        ),
        make_event(
            EventKind.FILE_WRITE,
            pid=1,
            ppid=0,
            exe="/bin/bash",
            details={"path": "/etc/systemd/system/evil.service"},
            timestamp=2.0,
        ),
    ]
    ids = {t.technique_id for t in map_techniques(events)}
    assert "T1053.003" in ids  # Cron
    assert "T1543.002" in ids  # Systemd service


def test_mitre_mapping_empty():
    assert map_techniques([]) == []


def test_mitre_normal_activity_no_false_positives(normal_events):
    techniques = map_techniques(normal_events[:12])
    ids = {t.technique_id for t in techniques}
    assert "T1105" not in ids
    assert "T1204.002" not in ids
