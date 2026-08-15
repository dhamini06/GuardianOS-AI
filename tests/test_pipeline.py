"""End-to-end pipeline tests (the MVP vertical slice + M2 lifecycle)."""

from __future__ import annotations

from backend.core.config import AppConfig
from backend.pipeline import GuardianPipeline
from backend.telemetry.demo_generator import DemoGenerator


def _run_demo(normal_runs: int = 40, config: AppConfig | None = None) -> GuardianPipeline:
    config = config or AppConfig.load()
    generator = DemoGenerator("normal", speed=1e6, normal_runs=normal_runs)
    pipeline = GuardianPipeline(config, telemetry=generator)
    pipeline.start()
    while not generator.exhausted:
        pipeline.ingest_tick()
    pipeline.complete_learning()
    generator.reset("attack")
    generator.speed = 1e6
    while not generator.exhausted:
        pipeline.analyze_window()
    pipeline.stop()
    return pipeline


def _attack_report(pipeline: GuardianPipeline):
    """The attack-chain report: the only chain whose hard-signal score is 1.0.

    Normal sessions score 0.0 on the hard signals, so the kill chain is
    uniquely identifiable even when the detector also flags a borderline
    normal chain (an unsupervised MVP can produce false positives by design).
    """
    for report in pipeline.reports:
        if report.detection.context.get("signal_score") == 1.0:
            return report
    raise AssertionError("no attack-chain report produced (signal_score == 1.0)")


def test_learning_then_detection_produces_report():
    pipeline = _run_demo()
    assert len(pipeline.reports) >= 1


def test_report_is_complete():
    pipeline = _run_demo()
    report = _attack_report(pipeline)
    assert report.explanation.summary
    assert report.explanation.reasons
    assert report.explanation.chain
    assert report.explanation.mitre
    assert report.actions
    assert report.detection.flagged


def test_analyze_before_learning_raises(app_config):
    import pytest

    from backend.telemetry.demo_generator import DemoGenerator

    pipeline = GuardianPipeline(app_config, telemetry=DemoGenerator("normal", speed=1e6))
    pipeline.start()
    with pytest.raises(RuntimeError):
        pipeline.analyze_window()
    pipeline.stop()


def test_execute_action_end_to_end(app_config):
    pipeline = _run_demo()
    report = _attack_report(pipeline)
    before = report.actions[0].status
    updated = pipeline.execute_action(report.report_id, 0)
    assert updated is report
    assert before != updated.actions[0].status


def test_complete_learning_persists_model(tmp_path):
    config = AppConfig.load(overrides={"detection.model_path": str(tmp_path / "model.joblib")})
    generator = DemoGenerator("normal", speed=1e6, normal_runs=10)
    pipeline = GuardianPipeline(config, telemetry=generator)
    pipeline.start()
    while not generator.exhausted:
        pipeline.ingest_tick()
    pipeline.complete_learning()
    pipeline.stop()
    from pathlib import Path

    assert Path(config.detection.model_path).exists()


def test_autoload_skips_learning(tmp_path):
    model_path = str(tmp_path / "model.joblib")
    train = AppConfig.load(overrides={"detection.model_path": model_path})
    generator = DemoGenerator("normal", speed=1e6, normal_runs=10)
    pipeline = GuardianPipeline(train, telemetry=generator)
    pipeline.start()
    while not generator.exhausted:
        pipeline.ingest_tick()
    pipeline.complete_learning()
    pipeline.stop()

    boot = AppConfig.load(overrides={"detection.model_path": model_path})
    generator2 = DemoGenerator("normal", speed=1e6)
    restarted = GuardianPipeline(boot, telemetry=generator2)
    restarted.start()
    assert not restarted.learning
    assert restarted.detector.is_trained
    assert restarted.is_ready_to_detect()
    restarted.stop()


def test_sliding_baseline_respects_cap(app_config):
    config = AppConfig.load(overrides={"detection.baseline_max_samples": 8})
    generator = DemoGenerator("normal", speed=1e6, normal_runs=40)
    pipeline = GuardianPipeline(config, telemetry=generator)
    pipeline.start()
    while not generator.exhausted:
        pipeline.ingest_tick()
    pipeline.complete_learning()
    assert len(pipeline._baseline) <= 8
    pipeline.stop()


def test_refit_rebuilds_detector_and_clears_cache(app_config):
    pipeline = _run_demo()
    pipeline._refit_detector()
    assert pipeline.detector.is_trained
    assert pipeline._chain_cache == {}


def test_maybe_refit_respects_interval(app_config):
    config = AppConfig.load(overrides={"detection.refit_interval_windows": 3})
    generator = DemoGenerator("normal", speed=1e6, normal_runs=40)
    pipeline = GuardianPipeline(config, telemetry=generator)
    pipeline.start()
    while not generator.exhausted:
        pipeline.ingest_tick()
    pipeline.complete_learning()
    pipeline._windows_since_refit = 2
    pipeline._maybe_refit()
    assert pipeline._windows_since_refit == 0
    assert pipeline.detector.is_trained
    pipeline.stop()


def test_label_benign_adds_chain_to_baseline(tmp_path):
    config = AppConfig.load(overrides={"data_dir": str(tmp_path)})
    pipeline = _run_demo(config=config)
    report = _attack_report(pipeline)
    before = len(pipeline._baseline)
    updated = pipeline.label_chain(report.report_id, "benign")
    assert updated is report
    assert pipeline.feedback.benign_keys
    assert len(pipeline._baseline) >= before


def test_label_malicious_excludes_chain(tmp_path):
    config = AppConfig.load(overrides={"data_dir": str(tmp_path)})
    pipeline = _run_demo(config=config)
    report = _attack_report(pipeline)
    chain_key = report.detection.context["chain_key"]
    updated = pipeline.label_chain(report.report_id, "malicious")
    assert updated is report
    assert all(v.chain_key != chain_key for v in pipeline._baseline)


def test_label_unknown_report_returns_none(tmp_path):
    config = AppConfig.load(overrides={"data_dir": str(tmp_path)})
    pipeline = _run_demo(config=config)
    assert pipeline.label_chain("nope", "benign") is None


def test_pipeline_persists_events_and_reports_to_sqlite(tmp_path):
    from backend.storage.sqlite import SqliteStorage

    config = AppConfig.load(overrides={"data_dir": str(tmp_path)})
    pipeline = _run_demo(config=config)
    # _run_demo() calls stop(), which closes the connection and clears the
    # attribute; the durable record is the SQLite file itself.
    storage = SqliteStorage(tmp_path / "guardian.db")
    counts = storage.counts()
    assert counts["reports"] >= 1
    assert counts["events"] >= 1
    attack = _attack_report(pipeline)
    assert any(r["report_id"] == attack.report_id for r in storage.recent_reports())
    storage.close()


def test_execute_action_records_containment_and_rollback(tmp_path):
    config = AppConfig.load(overrides={"data_dir": str(tmp_path)})
    pipeline = _run_demo(config=config)
    report = _attack_report(pipeline)
    # action 0 is kill_process (not reversible); 1 is block_ip (reversible).
    pipeline.execute_action(report.report_id, 1)
    assert pipeline.containment.entries
    reversed_count = pipeline.rollback_actions(report.report_id)
    assert reversed_count == 1


def test_response_writes_signed_audit_trail(tmp_path):
    config = AppConfig.load(
        overrides={
            "data_dir": str(tmp_path),
            "response.signing_secret": "test-secret",
        }
    )
    pipeline = _run_demo(config=config)
    report = _attack_report(pipeline)
    pipeline.execute_action(report.report_id, 0)
    assert pipeline.audit is not None
    ok, problems = pipeline.audit.verify_all(signer=pipeline.signer)
    assert ok, problems
    events = {e["event"] for e in pipeline.audit.entries()}
    assert "approved" in events and "execution" in events
