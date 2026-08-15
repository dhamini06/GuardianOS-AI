"""Background thread that drives the pipeline for the web dashboard.

The driver advances the pipeline one tick at a time (learn while learning,
score windows once trained) and records every new threat report and a health
snapshot to the shared :class:`ChangeLog` for WebSocket streaming. A custom
``tick`` callable can be injected for deterministic demo scenarios.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from typing import Any

from backend.api.changes import ChangeLog
from backend.core.logging import get_logger
from backend.pipeline import GuardianPipeline

logger = get_logger("api.driver")

TickFn = Callable[[GuardianPipeline], list[dict]]


def standard_tick(pipeline: GuardianPipeline) -> list[dict]:
    """Default driver tick: learn while learning, otherwise score the window."""
    if pipeline.learning:
        pipeline.learning_step()
        return []
    return [report.to_dict() for report in pipeline.analyze_window()]


class PipelineDriver:
    """Pushes the pipeline loop (learn -> detect) on a worker thread."""

    def __init__(
        self,
        pipeline: GuardianPipeline,
        changes: ChangeLog,
        refresh_seconds: float = 1.0,
        tick: TickFn | None = None,
    ) -> None:
        self.pipeline = pipeline
        self.changes = changes
        self.refresh_seconds = refresh_seconds
        self.tick_fn: TickFn = tick or standard_tick
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._run,
            name="pipeline-driver",
            daemon=True,
        )

    def start(self) -> None:
        self.pipeline.start()
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=5)
        self.pipeline.stop()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                for report in self.tick_fn(self.pipeline):
                    self.changes.record("report", {"report": report})
            except Exception:  # noqa: BLE001 - keep the dashboard alive on faults
                logger.exception("Pipeline driver tick failed")
            try:
                self.changes.record("health", {"health": self._health()})
            except Exception:  # noqa: BLE001
                logger.exception("Pipeline driver health snapshot failed")
            self._stop.wait(self.refresh_seconds)

    def _health(self) -> dict[str, Any]:
        return {
            "learning": self.pipeline.learning,
            "baseline": len(self.pipeline._baseline),
            "threats": len(self.pipeline.reports),
            "events_in_window": len(self.pipeline.current_window()),
            "ready": self.pipeline.is_ready_to_detect(),
            "telemetry": self.pipeline.telemetry_status(),
        }
