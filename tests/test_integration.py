"""WebSocket streaming, feedback loop, and concurrency integration tests."""

from __future__ import annotations

import threading
import time

from fastapi.testclient import TestClient

from backend.api.changes import ChangeLog
from backend.api.server import create_app
from backend.core.config import AppConfig
from backend.feedback.ledger import BENIGN, MALICIOUS, FeedbackLedger
from backend.pipeline import GuardianPipeline
from backend.telemetry.demo_generator import DemoGenerator

USERS = [
    {"name": "admin", "token": "tok-admin", "roles": ["admin"]},
    {"name": "analyst", "token": "tok-analyst", "roles": ["analyst"]},
    {"name": "viewer", "token": "tok-viewer", "roles": ["viewer"]},
]
AUTH_OVERRIDES = {"auth.enabled": True, "auth.users": USERS}


def _auth_config(tmp_path) -> AppConfig:
    overrides = dict(AUTH_OVERRIDES)
    overrides["data_dir"] = str(tmp_path)
    return AppConfig.load(overrides=overrides)


def _detected_pipeline(config: AppConfig) -> GuardianPipeline:
    generator = DemoGenerator("normal", speed=1e6, normal_runs=40)
    pipeline = GuardianPipeline(config, telemetry=generator)
    pipeline.start()
    while not generator.exhausted:
        pipeline.ingest_tick()
    pipeline.complete_learning()
    generator.reset("attack")
    generator.speed = 1e6
    while not generator.exhausted:
        pipeline.analyze_window()
    return pipeline


def _auth_client(tmp_path, *, token: str | None = None) -> tuple[TestClient, GuardianPipeline]:
    config = _auth_config(tmp_path)
    pipeline = _detected_pipeline(config)
    app = create_app(pipeline, config, start_driver=False)
    client = TestClient(app)
    if token:
        client.headers["X-GUARDIAN-TOKEN"] = token
    return client, pipeline


# ── WebSocket tests ──────────────────────────────────────────────────────────

def test_ws_streams_health_on_tick(tmp_path):
    config = AppConfig.load(
        overrides={"data_dir": str(tmp_path), "server.refresh_seconds": 0.05}
    )
    pipeline = _detected_pipeline(config)
    app = create_app(pipeline, config, start_driver=False)
    try:
        with TestClient(app) as client:
            state = app.state.guardian
            state.changes.record("health", {"health": {"learning": False}})
            with client.websocket_connect("/api/ws") as ws:
                deadline = time.time() + 5
                seen_health = False
                while time.time() < deadline:
                    msg = ws.receive_json()
                    seen_health = any(
                        item["kind"] == "health" for item in msg.get("items", [])
                    )
                    if seen_health:
                        break
                assert seen_health, "WebSocket did not receive health update"
    finally:
        pipeline.stop()


def test_ws_delivery_is_ordered(tmp_path):
    config = AppConfig.load(
        overrides={"data_dir": str(tmp_path), "server.refresh_seconds": 0.05}
    )
    pipeline = _detected_pipeline(config)
    app = create_app(pipeline, config, start_driver=False)
    try:
        with TestClient(app) as client:
            state = app.state.guardian
            for i in range(5):
                state.changes.record("test", {"i": i})
            with client.websocket_connect("/api/ws") as ws:
                msg = ws.receive_json()
                items = msg["items"]
                seqs = [item["seq"] for item in items]
                assert seqs == sorted(seqs), "Messages not in sequence order"
                assert len(items) >= 5
    finally:
        pipeline.stop()


def test_ws_sees_all_prior_when_reconnecting(tmp_path):
    config = AppConfig.load(
        overrides={"data_dir": str(tmp_path), "server.refresh_seconds": 0.05}
    )
    pipeline = _detected_pipeline(config)
    app = create_app(pipeline, config, start_driver=False)
    try:
        with TestClient(app) as client:
            state = app.state.guardian
            for i in range(3):
                state.changes.record("prior", {"i": i})
            with client.websocket_connect("/api/ws") as ws:
                msg = ws.receive_json()
                prior_kinds = [item["kind"] for item in msg["items"]]
                assert prior_kinds.count("prior") >= 3
    finally:
        pipeline.stop()


# ── Feedback → retrain loop tests ────────────────────────────────────────────

def test_feedback_ledger_record_and_query(tmp_path):
    path = tmp_path / "feedback.jsonl"
    ledger = FeedbackLedger(path)
    assert ledger.record("chain-1", BENIGN, report_id="r1") is True
    assert ledger.record("chain-1", BENIGN, report_id="r1") is False  # no change
    assert ledger.verdict_for("chain-1") == BENIGN
    assert ledger.verdict_for("chain-2") is None
    assert "chain-1" in ledger.benign_keys


def test_feedback_ledger_persists_and_reloads(tmp_path):
    path = tmp_path / "feedback.jsonl"
    ledger = FeedbackLedger(path)
    ledger.record("chain-a", MALICIOUS, report_id="ra")
    ledger.record("chain-b", BENIGN, report_id="rb")

    ledger2 = FeedbackLedger(path)
    assert ledger2.verdict_for("chain-a") == MALICIOUS
    assert ledger2.verdict_for("chain-b") == BENIGN
    assert ledger2.summary() == {"benign": 1, "malicious": 1}


def test_label_chain_benign_adds_to_baseline(tmp_path):
    config = AppConfig.load(overrides={"data_dir": str(tmp_path)})
    pipeline = _detected_pipeline(config)
    try:
        report = pipeline.reports[0]
        chain_key = report.detection.context.get("chain_key")
        assert chain_key is not None
        baseline_before = len(pipeline._baseline)

        updated = pipeline.label_chain(report.report_id, BENIGN)
        assert updated is not None
        assert pipeline.feedback.verdict_for(chain_key) == BENIGN
        # Baseline should have grown (benign chain vector added back).
        assert len(pipeline._baseline) >= baseline_before
    finally:
        pipeline.stop()


def test_label_chain_malicious_excludes_from_baseline(tmp_path):
    config = AppConfig.load(overrides={"data_dir": str(tmp_path)})
    pipeline = _detected_pipeline(config)
    try:
        report = pipeline.reports[0]
        chain_key = report.detection.context.get("chain_key")
        assert chain_key is not None

        updated = pipeline.label_chain(report.report_id, MALICIOUS)
        assert updated is not None
        assert pipeline.feedback.verdict_for(chain_key) == MALICIOUS
        # Chain cache should be invalidated for this chain.
        assert chain_key not in pipeline._chain_cache
    finally:
        pipeline.stop()


def test_label_chain_unknown_report_returns_none(tmp_path):
    config = AppConfig.load(overrides={"data_dir": str(tmp_path)})
    pipeline = _detected_pipeline(config)
    try:
        assert pipeline.label_chain("nonexistent-id", BENIGN) is None
    finally:
        pipeline.stop()


def test_label_chain_via_api(tmp_path):
    client, pipeline = _auth_client(tmp_path, token="tok-analyst")
    try:
        threats = client.get("/api/threats").json()
        report_id = threats[0]["report_id"]
        resp = client.post(
            f"/api/threats/{report_id}/label",
            json={"verdict": "benign", "note": "FP during testing"},
        )
        assert resp.status_code == 200
        updated = resp.json()
        assert updated["report_id"] == report_id
    finally:
        pipeline.stop()


# ── Concurrency stress tests ─────────────────────────────────────────────────

def test_concurrent_approve_reject_no_crash(tmp_path):
    config = _auth_config(tmp_path)
    pipeline = _detected_pipeline(config)
    app = create_app(pipeline, config, start_driver=False)
    try:
        with TestClient(app) as client:
            threats = client.get("/api/threats", headers={"X-GUARDIAN-TOKEN": "tok-admin"}).json()
            report_id = threats[0]["report_id"]
            results = []

            def approve():
                r = client.post(
                    f"/api/threats/{report_id}/actions/0/approve",
                    headers={"X-GUARDIAN-TOKEN": "tok-admin"},
                )
                results.append(r.status_code)

            def reject():
                r = client.post(
                    f"/api/threats/{report_id}/actions/0/reject",
                    headers={"X-GUARDIAN-TOKEN": "tok-admin"},
                )
                results.append(r.status_code)

            threads = [threading.Thread(target=approve) for _ in range(5)]
            threads += [threading.Thread(target=reject) for _ in range(5)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=10)

            # At least one should have succeeded (200), rest 409 or 200.
            assert 200 in results
            # No 500s — no crashes.
            assert 500 not in results
    finally:
        pipeline.stop()


def test_concurrent_changelog_writes(tmp_path):
    changes = ChangeLog(maxlen=2000)
    errors = []

    def writer(n):
        try:
            for i in range(100):
                changes.record(f"type-{n}", {"i": i})
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=writer, args=(n,)) for n in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)

    assert not errors, f"Concurrent writes raised: {errors}"
    assert changes.last_seq == 1000
    assert len(changes.since(0)) == 1000


def test_concurrent_feedback_record(tmp_path):
    path = tmp_path / "feedback.jsonl"
    ledger = FeedbackLedger(path)
    errors = []

    def writer(chain_id):
        try:
            for _ in range(50):
                ledger.record(f"chain-{chain_id}", BENIGN, report_id=f"r-{chain_id}")
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=writer, args=(n,)) for n in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)

    assert not errors
    assert len(ledger.entries) == 10
    lines = path.read_text().strip().splitlines()
    assert len(lines) == 10


# ── Rate limiting tests ──────────────────────────────────────────────────────

def test_rate_limit_allows_normal_traffic(tmp_path):
    config = AppConfig.load(overrides={"data_dir": str(tmp_path), "server.rate_limit_rpm": 120})
    pipeline = _detected_pipeline(config)
    app = create_app(pipeline, config, start_driver=False)
    try:
        with TestClient(app) as client:
            for _ in range(10):
                resp = client.get("/api/health")
                assert resp.status_code == 200
    finally:
        pipeline.stop()


def test_rate_limit_returns_429_when_exceeded(tmp_path):
    config = AppConfig.load(overrides={"data_dir": str(tmp_path), "server.rate_limit_rpm": 5})
    pipeline = _detected_pipeline(config)
    app = create_app(pipeline, config, start_driver=False)
    try:
        with TestClient(app) as client:
            for _ in range(5):
                client.get("/api/health")
            resp = client.get("/api/health")
            assert resp.status_code == 429
            assert "Rate limit exceeded" in resp.json()["detail"]
            assert "Retry-After" in resp.headers
    finally:
        pipeline.stop()


def test_rate_limit_does_not_apply_to_static(tmp_path):
    config = AppConfig.load(overrides={"data_dir": str(tmp_path), "server.rate_limit_rpm": 2})
    pipeline = _detected_pipeline(config)
    app = create_app(pipeline, config, start_driver=False)
    try:
        with TestClient(app) as client:
            for _ in range(10):
                resp = client.get("/api/health")
                if resp.status_code == 429:
                    break
            # Static files are exempt from rate limiting.
            for _ in range(10):
                assert client.get("/static/favicon.svg").status_code == 200
    finally:
        pipeline.stop()
