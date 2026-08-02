"""Tests for the optional local-LLM narrative generator (M4)."""

from __future__ import annotations

import json

from backend.core.analysis import Explanation, Severity, ThreatReport
from backend.detection.isolation_forest import IsolationForestDetector
from backend.explainability.explainer import RuleBasedExplainer
from backend.explainability.llm import LlmNarrativeGenerator
from backend.features.extractor import FeatureExtractor


class _FakeResponse:
    def __init__(self, body: bytes) -> None:
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self) -> bytes:
        return self._body


def _explanation() -> Explanation:
    return Explanation(
        summary="rule-based summary",
        reasons=["executed code from /tmp", "dialed out on a high port"],
        confidence=0.9,
        severity=Severity.CRITICAL,
    )


def test_summarize_returns_generated_text(monkeypatch):
    body = json.dumps({"response": "Analyst narrative from the local model."}).encode()
    captured = {}

    def fake_urlopen(request, timeout=10.0):
        captured["url"] = request.full_url
        captured["payload"] = json.loads(request.data.decode())
        return _FakeResponse(body)

    monkeypatch.setattr("backend.explainability.llm.urllib.request.urlopen", fake_urlopen)
    generator = LlmNarrativeGenerator(endpoint="http://127.0.0.1:11434", model="llama3.2:1b")
    assert generator.summarize(_explanation()) == "Analyst narrative from the local model."
    assert captured["url"] == "http://127.0.0.1:11434/api/generate"
    assert captured["payload"]["model"] == "llama3.2:1b"
    assert captured["payload"]["stream"] is False
    assert "reverse" not in captured["payload"]["prompt"]  # prompt carries only evidence


def test_summarize_empty_response_returns_none(monkeypatch):
    def fake_urlopen(request, timeout=10.0):
        return _FakeResponse(b'{"response": ""}')

    monkeypatch.setattr("backend.explainability.llm.urllib.request.urlopen", fake_urlopen)
    generator = LlmNarrativeGenerator(endpoint="http://127.0.0.1:11434", model="llama3.2:1b")
    assert generator.summarize(_explanation()) is None


def test_summarize_failure_falls_back(monkeypatch):
    def fake_urlopen(request, timeout=10.0):
        raise ConnectionError("no local model running")

    monkeypatch.setattr("backend.explainability.llm.urllib.request.urlopen", fake_urlopen)
    generator = LlmNarrativeGenerator(endpoint="http://127.0.0.1:11434", model="llama3.2:1b")
    assert generator.summarize(_explanation()) is None


def test_explainer_uses_llm_when_injected(normal_events, attack_events, monkeypatch):
    detector = IsolationForestDetector().fit(FeatureExtractor().extract(normal_events))
    vector = FeatureExtractor().extract(attack_events)[0]
    result = detector.predict(vector)

    class FakeLlm:
        def __init__(self) -> None:
            self.calls = 0

        def summarize(self, explanation):
            self.calls += 1
            return "LLM-produced narrative."

    llm = FakeLlm()
    explanation = RuleBasedExplainer(llm=llm).explain(vector, result)
    assert explanation.summary == "LLM-produced narrative."
    assert llm.calls == 1


def test_explainer_without_llm_keeps_rule_summary(normal_events, attack_events):
    detector = IsolationForestDetector().fit(FeatureExtractor().extract(normal_events))
    vector = FeatureExtractor().extract(attack_events)[0]
    result = detector.predict(vector)
    explanation = RuleBasedExplainer().explain(vector, result)
    assert "REVERSE SHELL" in explanation.summary


def test_explainer_llm_failure_falls_back_to_rule_summary(normal_events, attack_events, monkeypatch):
    detector = IsolationForestDetector().fit(FeatureExtractor().extract(normal_events))
    vector = FeatureExtractor().extract(attack_events)[0]
    result = detector.predict(vector)

    class FailingLlm:
        def summarize(self, explanation):
            return None

    explanation = RuleBasedExplainer(llm=FailingLlm()).explain(vector, result)
    assert "REVERSE SHELL" in explanation.summary


def test_pipeline_wires_llm_from_config():
    from backend.core.config import AppConfig
    from backend.pipeline import GuardianPipeline

    rules_config = AppConfig.load(overrides={"explainability.narrative_provider": "rules"})
    llm_config = AppConfig.load(overrides={"explainability.narrative_provider": "llm"})

    rules_pipeline = GuardianPipeline(rules_config)
    llm_pipeline = GuardianPipeline(llm_config)

    assert rules_pipeline.explainer._llm is None
    assert llm_pipeline.explainer._llm is not None
    rules_pipeline.stop()
    llm_pipeline.stop()


def test_explanation_dag_is_populated(normal_events, attack_events):
    detector = IsolationForestDetector().fit(FeatureExtractor().extract(normal_events))
    vector = FeatureExtractor().extract(attack_events)[0]
    result = detector.predict(vector)
    explanation = RuleBasedExplainer().explain(vector, result)
    assert explanation.dag is not None
    assert explanation.dag.roots == ["p2100"]
    report = ThreatReport(
        report_id="x", timestamp=1.0, detection=result, explanation=explanation
    )
    assert report.to_dict()["explanation"]["dag"]["roots"] == ["p2100"]
