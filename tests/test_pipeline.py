"""End-to-end pipeline tests (the MVP vertical slice)."""

from __future__ import annotations

from backend.core.config import AppConfig
from backend.pipeline import GuardianPipeline
from backend.telemetry.demo_generator import DemoGenerator


def _run_demo(normal_runs: int = 40) -> GuardianPipeline:
    config = AppConfig.load()
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


def test_learning_then_detection_produces_report():
    pipeline = _run_demo()
    assert len(pipeline.reports) >= 1


def test_report_is_complete():
    pipeline = _run_demo()
    report = pipeline.reports[0]
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
    report = pipeline.reports[0]
    before = report.actions[0].status
    updated = pipeline.execute_action(report.report_id, 0)
    assert updated is report
    assert before != updated.actions[0].status
