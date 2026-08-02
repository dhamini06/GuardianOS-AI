"""GuardianOS-AI pipeline: end-to-end orchestration of the MVP vertical slice.

Kernel Event -> Behaviour Features -> Anomaly Detection -> Explanation
              -> Response Recommendation -> Threat Report (dashboard)

The pipeline is deliberately linear and testable. Each layer is a small,
independently replaceable component wired together here (composition root).
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Callable
from pathlib import Path

from backend.core.analysis import ThreatReport
from backend.core.config import AppConfig
from backend.core.events import KernelEvent
from backend.core.logging import get_logger
from backend.detection.isolation_forest import IsolationForestDetector
from backend.explainability.explainer import RuleBasedExplainer
from backend.explainability.llm import LlmNarrativeGenerator
from backend.features.extractor import FeatureExtractor, ProcessFeatures
from backend.feedback.learning import reweight_baseline
from backend.feedback.ledger import BENIGN, FeedbackLedger
from backend.response.actions import ActionExecutor
from backend.response.approval import ApprovalGate
from backend.response.audit import AuditTrail, Signer
from backend.response.containment import ContainmentManager
from backend.response.decision import DecisionEngine
from backend.response.playbook import PlaybookEngine
from backend.storage.sqlite import SqliteStorage
from backend.telemetry.base import TelemetryProvider
from backend.telemetry.event_bus import EventBuffer
from backend.telemetry.factory import create_provider

logger = get_logger("pipeline")

ReportCallback = Callable[[ThreatReport], None]


class GuardianPipeline:
    """Composition root for telemetry -> detection -> explanation -> response."""

    def __init__(
        self,
        config: AppConfig,
        telemetry: TelemetryProvider | None = None,
    ) -> None:
        self.config = config
        self.telemetry = telemetry or create_provider(config)
        self.buffer = EventBuffer()
        self.extractor = FeatureExtractor()
        self.detector = IsolationForestDetector(
            contamination=config.detection.contamination,
            n_estimators=config.detection.n_estimators,
            max_samples=config.detection.max_samples,
            flagged_threshold=config.detection.flagged_threshold,
            background_samples=config.detection.attribution_background_samples,
        )
        llm: LlmNarrativeGenerator | None = None
        if config.explainability.narrative_provider == "llm":
            llm = LlmNarrativeGenerator(
                endpoint=config.explainability.llm_endpoint,
                model=config.explainability.llm_model,
                timeout=config.explainability.llm_timeout_seconds,
            )
        self.explainer = RuleBasedExplainer(llm=llm)
        self.playbook = PlaybookEngine.load(config.response.playbook_path)
        self.decision = DecisionEngine(playbook=self.playbook)

        signing_secret = config.response.signing_secret or os.environ.get("GUARDIAN_SIGNING_SECRET")
        self.signer = Signer(signing_secret) if signing_secret else None
        audit_path = Path(config.data_dir) / config.response.audit_path if config.data_dir else None
        self.audit = AuditTrail(audit_path) if audit_path else None

        self.containment = ContainmentManager(
            dry_run=config.response.dry_run,
            audit=self.audit,
            signer=self.signer,
        )
        self.gate = ApprovalGate(
            auto_approve_destructive=config.response.auto_approve_destructive,
            audit=self.audit,
            signer=self.signer,
        )
        self.executor = ActionExecutor(
            dry_run=config.response.dry_run,
            containment=self.containment,
            audit=self.audit,
            signer=self.signer,
        )
        self.storage = None
        if config.storage.enabled and config.data_dir:
            self.storage = SqliteStorage(
                Path(config.data_dir) / config.storage.path,
                max_events=config.storage.max_events,
            )

        self.learning = True
        self._baseline: list[ProcessFeatures] = []
        self._min_baseline_samples = config.detection.min_baseline_samples
        self._learning_ticks = 0
        self._windows_since_refit = 0
        self.reports: list[ThreatReport] = []
        # chain_key -> (fingerprint, DetectionResult); avoids re-scoring
        # chains whose events have not changed since the previous window.
        self._chain_cache: dict[str, tuple[tuple, object]] = {}
        # chain_key -> most recent feature vector, kept for analyst labelling.
        self._vector_by_chain: dict[str, ProcessFeatures] = {}
        feedback_path = Path(config.data_dir) / "feedback.jsonl" if config.data_dir else None
        self.feedback = FeedbackLedger(feedback_path)

    # -- lifecycle --------------------------------------------------------
    def start(self) -> None:
        self.telemetry.start()
        model_path = self.config.detection.model_path
        if self.config.detection.autoload and model_path and Path(model_path).exists():
            self.detector = IsolationForestDetector.load(model_path)
            self.learning = False
            logger.info("Loaded persisted detector from %s; learning disabled", model_path)
        logger.info("Pipeline started (learning=%s)", self.learning)

    def stop(self) -> None:
        self.telemetry.stop()
        if self.storage is not None:
            self.storage.close()
            self.storage = None
        logger.info("Pipeline stopped (baseline samples=%d)", len(self._baseline))

    # -- learning phase ---------------------------------------------------
    def ingest_tick(self) -> int:
        """Collect one telemetry tick into the buffer without scoring it."""
        events = self.telemetry.collect()
        self.buffer.extend(events)
        return len(events)

    def accumulate_baseline(self) -> int:
        """Collect one telemetry tick and add its features to the baseline."""
        self._ingest()
        vectors = self.extractor.extract(self.current_window())
        return self._add_to_baseline(vectors)

    def accumulate_baseline_delta(self) -> int:
        """Collect one tick and baseline only the newly arrived events.

        Used by the demo runner so each normal session contributes a single,
        clean set of feature vectors instead of re-extracting the whole
        rolling window on every tick.
        """
        events = self.telemetry.collect()
        self.buffer.extend(events)
        return self._add_to_baseline(self.extractor.extract(events))

    def _add_to_baseline(self, vectors: list[ProcessFeatures]) -> int:
        seen = {v.chain_key for v in self._baseline}
        fresh = [v for v in vectors if v.chain_key not in seen]
        self._baseline.extend(fresh)
        max_samples = self.config.detection.baseline_max_samples
        if max_samples and len(self._baseline) > max_samples:
            # Sliding window: forget the oldest chains once the cap is hit.
            self._baseline = self._baseline[-max_samples:]
        return len(fresh)

    def is_ready_to_detect(self) -> bool:
        return self.detector.is_trained or len(self._baseline) >= self._min_baseline_samples

    def learning_step(self, *, min_windows: int = 5) -> None:
        """One live learning tick; completes automatically.

        For scripted telemetry (which exposes ``normal_phase_ends``) learning
        completes when the normal phase ends. For real providers it completes
        after ``min_windows`` ticks once enough baseline is available.
        """
        if not self.learning:
            return
        self.ingest_tick()
        self._learning_ticks += 1
        normal_end = getattr(self.telemetry, "normal_phase_ends", None)
        if normal_end is not None:
            elapsed = getattr(self.telemetry, "elapsed_seconds", None)
            if elapsed is not None and elapsed >= normal_end:
                self.complete_learning()
            return
        if self._learning_ticks >= min_windows:
            self.complete_learning()

    def complete_learning(self) -> None:
        # If the buffer was only ingested (no incremental extraction), build
        # the baseline from the complete window so chains are not partial.
        if not self._baseline:
            self._add_to_baseline(self.extractor.extract(self.current_window()))
        if not self.is_ready_to_detect():
            logger.warning(
                "Completing learning with %d samples (below suggested %d)",
                len(self._baseline),
                self._min_baseline_samples,
            )
        self.detector.fit(self._baseline)
        self.learning = False
        if self.config.detection.model_path:
            self.detector.save(self.config.detection.model_path)
        logger.info("Learning complete; %d baseline samples.", len(self._baseline))

    # -- detection phase --------------------------------------------------
    def analyze_window(self, on_report: ReportCallback | None = None) -> list[ThreatReport]:
        """Score the current window; return new threat reports."""
        if self.learning:
            raise RuntimeError("analyze_window() called before complete_learning()")
        self._ingest()
        vectors = self.extractor.extract(self.current_window())
        new_reports: list[ThreatReport] = []
        for vector in vectors:
            self._vector_by_chain[vector.chain_key] = vector
            fingerprint = self._fingerprint(vector)
            cached = self._chain_cache.get(vector.chain_key)
            if cached is not None and cached[0] == fingerprint:
                result = cached[1]
            else:
                result = self.detector.predict(vector)
                self._chain_cache[vector.chain_key] = (fingerprint, result)
            if not result.flagged:
                # Unflagged chains are evidence of continuing normality and feed
                # the sliding baseline for the periodic online refit.
                self._add_to_baseline([vector])
                continue
            explanation = self.explainer.explain(vector, result)
            actions = self.decision.decide(vector, result, explanation)
            for action in actions:
                self.gate.process(action)
            report = ThreatReport(
                report_id=uuid.uuid4().hex[:10],
                timestamp=vector.window_end,
                detection=result,
                explanation=explanation,
                actions=actions,
            )
            self.reports.append(report)
            new_reports.append(report)
            if self.storage is not None and self.config.storage.save_reports:
                self.storage.save_report(report)
            logger.warning(
                "THREAT %s severity=%s pid=%d exe=%s score=%.2f mitre=%s",
                report.report_id,
                result.severity.value,
                result.pid,
                result.exe,
                result.anomaly_score,
                ",".join(m.technique_id for m in explanation.mitre),
            )
            if on_report:
                on_report(report)
        self._maybe_refit()
        return new_reports

    # -- shared helpers ---------------------------------------------------
    def _ingest(self) -> None:
        events = self.telemetry.collect()
        if events:
            self.buffer.extend(events)
            if self.storage is not None and self.config.storage.save_events:
                self.storage.save_events(events)

    def current_window(self) -> list[KernelEvent]:
        return self.buffer.window(self.config.telemetry.window_seconds)

    @staticmethod
    def _fingerprint(vector: ProcessFeatures) -> tuple:
        """Cheap fingerprint: feature values + the events backing the chain."""
        return (
            tuple(sorted(vector.values.items())),
            tuple(sorted(e.event_id for e in vector.related_events)),
        )

    # -- response control (dashboard-facing) ------------------------------
    def execute_action(self, report_id: str, action_index: int) -> ThreatReport | None:
        """Approve and execute one action of a report; returns updated report."""
        for report in self.reports:
            if report.report_id != report_id:
                continue
            if not (0 <= action_index < len(report.actions)):
                return None
            action = report.actions[action_index]
            self.gate.approve(action)
            self.executor.execute(action, report_id=report.report_id)
            return report
        return None

    def rollback_actions(self, report_id: str) -> int:
        """Undo every contained (reversible) response for a report.

        Returns the number of operations actually reversed. Kills cannot be
        undone and are left in place.
        """
        return self.containment.rollback_all(report_id=report_id)

    # -- online learning / refit -----------------------------------------
    def _maybe_refit(self) -> None:
        """Periodically refit the detector from the sliding baseline."""
        interval = self.config.detection.refit_interval_windows
        if not interval:
            return
        self._windows_since_refit += 1
        if self._windows_since_refit >= interval:
            self._windows_since_refit = 0
            self._refit_detector()

    def _refit_detector(self) -> None:
        vectors = reweight_baseline(self._baseline, self.feedback)
        if len(vectors) < 2:
            logger.warning("Skipping refit: only %d baseline vectors", len(vectors))
            return
        self.detector.fit(vectors)
        # Scores change under the new model; invalidate the per-chain cache.
        self._chain_cache.clear()
        if self.config.detection.model_path:
            self.detector.save(self.config.detection.model_path)
        logger.info("Detector refit on %d baseline vectors", len(vectors))

    # -- analyst feedback -------------------------------------------------
    def label_chain(
        self,
        report_id: str,
        verdict: str,
        *,
        note: str | None = None,
    ) -> ThreatReport | None:
        """Analyst feedback: mark a threat benign or malicious.

        ``benign`` folds the chain back into the normal baseline (false
        positive); ``malicious`` excludes it and drops it from the cache.
        Either way the detector is refit immediately so the model reflects
        the verdict.
        """
        for report in self.reports:
            if report.report_id != report_id:
                continue
            chain_key = report.detection.context.get("chain_key")
            if not chain_key:
                return report
            if self.feedback.record(chain_key, verdict, report_id=report_id, note=note):
                if verdict == BENIGN:
                    vector = self._vector_by_chain.get(chain_key)
                    if vector is not None:
                        self._add_to_baseline([vector])
                self._apply_feedback()
                self._refit_detector()
                self._chain_cache.pop(chain_key, None)
            return report
        return None

    def _apply_feedback(self) -> None:
        """Reapply confirmed verdicts: drop malicious chains from the baseline."""
        self._baseline = reweight_baseline(self._baseline, self.feedback)
