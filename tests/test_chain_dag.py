"""Tests for the behaviour-chain DAG (M4)."""

from __future__ import annotations

from backend.explainability.chain import build_dag


def test_attack_dag_structure(attack_events):
    dag = build_dag(attack_events)
    process_ids = {n.id for n in dag.nodes if not n.id.startswith("e")}
    assert process_ids == {"p2100", "p2101", "p2103", "p2104", "p2105"}
    assert dag.roots == ["p2100"]  # python is the session root


def test_attack_dag_spawn_edges(attack_events):
    dag = build_dag(attack_events)
    spawns = [(e.source, e.target) for e in dag.edges if e.kind == "spawn"]
    assert ("p2100", "p2101") in spawns  # python -> bash/curl
    assert ("p2101", "p2103") in spawns  # bash -> chmod
    assert ("p2101", "p2104") in spawns  # bash -> payload
    assert ("p2104", "p2105") in spawns  # payload -> reverse shell


def test_attack_dag_attaches_leaf_events(attack_events):
    dag = build_dag(attack_events)
    attaches = [(e.source, e.target) for e in dag.edges if e.kind == "attach"]
    kinds = {n.kind for n in dag.nodes if n.id.startswith("e")}
    assert len(attaches) == 4
    assert {"network_connect", "file_write", "privilege_escalation"} <= kinds


def test_attack_dag_suspicious_markers(attack_events):
    dag = build_dag(attack_events)
    suspicious = {n.id for n in dag.nodes if n.suspicious}
    assert "p2104" in suspicious  # payload executed from /tmp


def test_exec_updates_process_node_exe(attack_events):
    dag = build_dag(attack_events)
    bash_node = next(n for n in dag.nodes if n.id == "p2101")
    assert bash_node.exe == "/usr/bin/curl"  # bash pid adopted the exec target


def test_normal_dag_has_no_suspicious_root(normal_events):
    dag = build_dag(normal_events)
    assert dag.nodes
    process_ids = [n.id for n in dag.nodes if n.id.startswith("p")]
    assert process_ids
    for root in dag.roots:
        node = next(n for n in dag.nodes if n.id == root)
        assert node.kind in ("process_created", "exec")


def test_empty_dag():
    dag = build_dag([])
    assert dag.nodes == []
    assert dag.edges == []
    assert dag.roots == []


def test_dag_serialisable(attack_events):
    dag = build_dag(attack_events)
    data = dag.to_dict()
    assert data["roots"] == ["p2100"]
    assert len(data["nodes"]) == 9
    assert data["edges"][0]["kind"] in {"spawn", "attach"}
