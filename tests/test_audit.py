"""Tests for the signed, append-only audit trail."""

from __future__ import annotations

import json

from backend.response.audit import AuditTrail, Signer


def test_signer_roundtrip():
    signer = Signer("secret")
    sig = signer.sign({"seq": 1, "event": "approved", "data": {}})
    assert signer.verify({"seq": 1, "event": "approved", "data": {}}, sig)
    assert not signer.verify({"seq": 2, "event": "approved", "data": {}}, sig)


def test_records_are_signed_and_verifiable(tmp_path):
    trail = AuditTrail(tmp_path / "audit.jsonl")
    signer = Signer("hunter2")
    trail.record("approved", report_id="r1", actor="analyst", data={"action": "kill"}, signer=signer)
    trail.record("execution", report_id="r1", data={"action": "kill"}, signer=signer)
    assert trail.seq == 2
    ok, problems = trail.verify_all(signer=signer)
    assert ok, problems
    assert [e["event"] for e in trail.entries()] == ["approved", "execution"]


def test_unsigned_trail_still_records(tmp_path):
    trail = AuditTrail(tmp_path / "audit.jsonl")
    trail.record("rollback", report_id="r1", data={"entry": {}})
    entry = trail.entries()[0]
    assert entry["sig"] is None
    assert trail.verify_all() == (True, [])


def test_tampering_breaks_the_chain(tmp_path):
    trail = AuditTrail(tmp_path / "audit.jsonl")
    signer = Signer("secret")
    trail.record("approved", report_id="r1", data={"action": "kill"}, signer=signer)
    trail.record("execution", report_id="r1", data={"action": "kill"}, signer=signer)
    trail.record("rollback", report_id="r1", data={"entry": {}}, signer=signer)

    path = trail.path
    lines = path.read_text(encoding="utf-8").splitlines()
    tampered = json.loads(lines[0])
    tampered["data"]["action"] = "exfil"
    lines[0] = json.dumps(tampered, sort_keys=True, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    ok, problems = trail.verify_all(signer=signer)
    assert not ok
    assert any("hash chain" in p for p in problems)


def test_signer_secret_change_detected(tmp_path):
    trail = AuditTrail(tmp_path / "audit.jsonl")
    trail.record("approved", report_id="r1", data={"action": "kill"}, signer=Signer("secret-a"))
    ok, problems = trail.verify_all(signer=Signer("secret-b"))
    assert not ok
    assert any("signature" in p for p in problems)


def test_audit_resumes_sequence(tmp_path):
    path = tmp_path / "audit.jsonl"
    first = AuditTrail(path)
    first.record("approved", data={})
    second = AuditTrail(path)
    second.record("execution", data={})
    assert second.seq == 2
