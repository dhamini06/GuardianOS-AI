"""API layer tests: REST endpoints, RBAC, WebSocket streaming and the driver."""

from __future__ import annotations

import re
import time

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from backend.api.changes import ChangeLog
from backend.api.driver import PipelineDriver
from backend.api.server import create_app
from backend.core.config import AppConfig
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
    """Learn a baseline and detect the attack chain; storage stays open."""
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


def _client(config: AppConfig, *, token: str | None = None) -> TestClient:
    app = create_app(_detected_pipeline(config), config, start_driver=False)
    client = TestClient(app)
    if token:
        client.headers["X-GUARDIAN-TOKEN"] = token
    return client


# -- REST: read endpoints ------------------------------------------------
def test_health_and_threats_and_events(tmp_path):
    config = AppConfig.load(overrides={"data_dir": str(tmp_path)})
    pipeline = _detected_pipeline(config)
    app = create_app(pipeline, config, start_driver=False)
    try:
        with TestClient(app) as client:
            health = client.get("/api/health").json()
            assert health["status"] == "ok"
            assert health["threats"] >= 1

            threats = client.get("/api/threats").json()
            assert len(threats) >= 1
            report = threats[0]
            assert report["detection"]["flagged"]

            detail = client.get(f"/api/threats/{report['report_id']}").json()
            assert detail["explanation"]["summary"]
            assert detail["actions"]
            assert detail["explanation"]["dag"]["nodes"]

            events = client.get("/api/events?limit=10").json()
            assert len(events) >= 1
            assert events[0]["kind"]
    finally:
        pipeline.stop()


def test_threat_404(tmp_path):
    config = AppConfig.load(overrides={"data_dir": str(tmp_path)})
    pipeline = _detected_pipeline(config)
    app = create_app(pipeline, config, start_driver=False)
    try:
        with TestClient(app) as client:
            assert client.get("/api/threats/nope").status_code == 404
    finally:
        pipeline.stop()


def test_index_and_static_served(tmp_path):
    config = AppConfig.load(overrides={"data_dir": str(tmp_path)})
    pipeline = _detected_pipeline(config)
    app = create_app(pipeline, config, start_driver=False)
    try:
        with TestClient(app) as client:
            index = client.get("/")
            assert index.status_code == 200
            assert b"GuardianOS-AI" in index.content

            # Built React assets referenced by index.html resolve under /static.
            asset_refs = re.findall(rb"/static/assets/[A-Za-z0-9_.-]+\.(?:js|css)", index.content)
            assert asset_refs, "index.html should reference built /static/assets bundles"
            for ref in set(asset_refs):
                asset = client.get(ref.decode())
                assert asset.status_code == 200, ref
                assert asset.headers["content-type"].startswith(("text/javascript", "text/css"))
            assert client.get("/static/favicon.svg").status_code == 200

            # SPA deep links serve the app shell, unknown API paths still 404.
            deep = client.get("/threats/abc-123")
            assert deep.status_code == 200
            assert b"GuardianOS-AI" in deep.content
            assert client.get("/api/does-not-exist").status_code == 404
    finally:
        pipeline.stop()


# -- RBAC ----------------------------------------------------------------
def test_auth_requires_token(tmp_path):
    client = _client(_auth_config(tmp_path))
    assert client.get("/api/threats").status_code == 401
    client.headers["X-GUARDIAN-TOKEN"] = "bogus"
    assert client.get("/api/threats").status_code == 401


def test_viewer_reads_but_cannot_write(tmp_path):
    client = _client(_auth_config(tmp_path), token="tok-viewer")
    threats = client.get("/api/threats").json()
    assert threats
    report_id = threats[0]["report_id"]
    assert client.post(f"/api/threats/{report_id}/actions/0/approve").status_code == 403
    assert client.post(f"/api/threats/{report_id}/label", json={"verdict": "benign"}).status_code == 403


def test_analyst_can_label_but_not_approve(tmp_path):
    client = _client(_auth_config(tmp_path), token="tok-analyst")
    threats = client.get("/api/threats").json()
    report_id = threats[0]["report_id"]
    assert client.post(f"/api/threats/{report_id}/label", json={"verdict": "benign"}).status_code == 200
    assert client.post(f"/api/threats/{report_id}/actions/0/approve").status_code == 403


def test_admin_can_approve_execute_and_rollback(tmp_path):
    client = _client(_auth_config(tmp_path), token="tok-admin")
    threats = client.get("/api/threats").json()
    report_id = threats[0]["report_id"]
    # action 0 is kill_process (not reversible); 1 is block_ip (reversible).
    updated = client.post(f"/api/threats/{report_id}/actions/1/approve").json()
    assert updated["actions"][1]["status"] == "executed"

    rolled = client.post(f"/api/threats/{report_id}/rollback").json()
    assert rolled["report_id"] == report_id
    assert rolled["rolled_back"] >= 1


def test_admin_can_reject(tmp_path):
    client = _client(_auth_config(tmp_path), token="tok-admin")
    threats = client.get("/api/threats").json()
    report_id = threats[0]["report_id"]
    updated = client.post(f"/api/threats/{report_id}/actions/0/reject").json()
    assert updated["actions"][0]["status"] == "rejected"


def test_label_validates_verdict(tmp_path):
    client = _client(_auth_config(tmp_path), token="tok-admin")
    threats = client.get("/api/threats").json()
    report_id = threats[0]["report_id"]
    assert client.post(f"/api/threats/{report_id}/label", json={"verdict": "maybe"}).status_code == 422


# -- WebSocket streaming -------------------------------------------------
def test_ws_streams_reports(tmp_path):
    config = AppConfig.load(
        overrides={"data_dir": str(tmp_path), "server.refresh_seconds": 0.05}
    )
    pipeline = _detected_pipeline(config)
    app = create_app(pipeline, config, start_driver=False)
    try:
        with TestClient(app) as client:
            state = app.state.guardian
            state.changes.record("report", {"report": pipeline.reports[0].to_dict()})
            with client.websocket_connect("/api/ws") as ws:
                deadline = time.time() + 5
                seen_report = False
                while time.time() < deadline:
                    message = ws.receive_json()
                    seen_report = any(
                        item["kind"] == "report" for item in message.get("items", [])
                    )
                    if seen_report:
                        break
                assert seen_report
    finally:
        pipeline.stop()


def test_ws_rejects_bad_token(tmp_path):
    config = _auth_config(tmp_path)
    pipeline = _detected_pipeline(config)
    app = create_app(pipeline, config, start_driver=False)
    try:
        with TestClient(app) as client, pytest.raises(WebSocketDisconnect), client.websocket_connect(
            "/api/ws?token=bogus"
        ) as ws:
            ws.receive_json()
    finally:
        pipeline.stop()


# -- driver ---------------------------------------------------------------
class _FakePipeline:
    learning = False
    reports = []
    _baseline = []

    def start(self) -> None:
        pass

    def stop(self) -> None:
        pass

    def learning_step(self) -> None:
        pass

    def analyze_window(self) -> list:
        return []

    def current_window(self) -> list:
        return []

    def is_ready_to_detect(self) -> bool:
        return True

    def telemetry_status(self) -> dict:
        return {"provider": "fake", "running": True}


def test_driver_records_reports_and_health():
    changes = ChangeLog()
    calls = {"n": 0}

    def tick(pipeline):  # noqa: ARG001 - fake pipeline contract
        calls["n"] += 1
        return [{"report_id": f"r{calls['n']}"}]

    driver = PipelineDriver(_FakePipeline(), changes, refresh_seconds=0.01, tick=tick)
    driver.start()
    time.sleep(0.15)
    driver.stop()
    items = changes.since(0)
    assert any(i["kind"] == "report" for i in items)
    assert any(i["kind"] == "health" for i in items)
