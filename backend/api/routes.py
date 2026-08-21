"""REST + WebSocket endpoints exposing live pipeline state.

Read endpoints require ``viewer``; analyst feedback requires ``analyst``;
approve / reject / rollback (destructive remediation) require ``admin``.
"""

from __future__ import annotations

import asyncio
from contextlib import suppress

from fastapi import APIRouter, Depends, HTTPException, Query, WebSocket, status
from pydantic import BaseModel

from backend.api.security import (
    AdminUser,
    AnalystUser,
    GuardianState,
    StateView,
    require_role,
)
from backend.core.logging import get_logger
from backend.pipeline import GuardianPipeline

logger = get_logger("api.routes")

api_router = APIRouter(prefix="/api")
ws_router = APIRouter(prefix="/api")


class LabelRequest(BaseModel):
    """Analyst verdict for a threat report."""

    verdict: str  # "benign" | "malicious"
    note: str | None = None


def _pipeline(state: StateView) -> GuardianPipeline:
    return state.pipeline


def _find_report(pipeline: GuardianPipeline, report_id: str):
    for report in pipeline.reports:
        if report.report_id == report_id:
            return report
    raise HTTPException(status.HTTP_404_NOT_FOUND, detail=f"No such report: {report_id}")


def _action_or_404(report, action_index: int):
    if not (0 <= action_index < len(report.actions)):
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No such action")
    return report.actions[action_index]


# -- public --------------------------------------------------------------
@api_router.get("/health")
def health(state: GuardianState) -> dict:
    pipeline = _pipeline(state)
    return {
        "status": "ok",
        "learning": pipeline.learning,
        "baseline": len(pipeline._baseline),
        "threats": len(pipeline.reports),
        "events_in_window": len(pipeline.current_window()),
        "ready": pipeline.is_ready_to_detect(),
        "telemetry": pipeline.telemetry_status(),
    }


@api_router.get("/metrics")
def metrics(state: GuardianState) -> dict:
    """Live dashboard metrics: severity breakdown, feedback stats, uptime."""
    import time

    pipeline = _pipeline(state)
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for report in pipeline.reports:
        sev = report.detection.severity.value
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    action_stats = {"executed": 0, "pending_approval": 0, "rejected": 0, "recommended": 0}
    for report in pipeline.reports:
        for action in report.actions:
            key = action.status.value
            action_stats[key] = action_stats.get(key, 0) + 1

    return {
        "uptime_seconds": time.time() - pipeline._start_time if hasattr(pipeline, "_start_time") else 0,
        "total_reports": len(pipeline.reports),
        "severity_counts": severity_counts,
        "action_stats": action_stats,
        "feedback": pipeline.feedback.summary(),
        "baseline_samples": len(pipeline._baseline),
        "chain_cache_size": len(pipeline._chain_cache),
        "learning": pipeline.learning,
        "telemetry": pipeline.telemetry_status(),
    }


# -- read-only (viewer+) --------------------------------------------------
@api_router.get(
    "/events",
    dependencies=[Depends(require_role("viewer"))],
)
def events(
    state: GuardianState,
    limit: int = Query(50, ge=1, le=500),
) -> list[dict]:
    pipeline = _pipeline(state)
    if pipeline.storage is not None:
        return pipeline.storage.recent_events(limit)
    return [event.to_dict() for event in reversed(pipeline.current_window())][:limit]


@api_router.get(
    "/threats",
    dependencies=[Depends(require_role("viewer"))],
)
def threats(
    state: GuardianState,
    limit: int = Query(50, ge=1, le=500),
) -> list[dict]:
    pipeline = _pipeline(state)
    return [report.to_dict() for report in reversed(list(pipeline.reports)[-limit:])]


@api_router.get(
    "/threats/{report_id}",
    dependencies=[Depends(require_role("viewer"))],
)
def threat_detail(report_id: str, state: GuardianState) -> dict:
    return _find_report(_pipeline(state), report_id).to_dict()


# -- analyst feedback (analyst+) ------------------------------------------
@api_router.post("/threats/{report_id}/label")
def label_threat(
    report_id: str,
    body: LabelRequest,
    user: AnalystUser,
    state: GuardianState,
) -> dict:
    pipeline = _pipeline(state)
    if body.verdict not in ("benign", "malicious"):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="verdict must be 'benign' or 'malicious'",
        )
    updated = pipeline.label_chain(report_id, body.verdict, note=body.note)
    if updated is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=f"No such report: {report_id}")
    logger.info("Report %s labelled %s by %s", report_id, body.verdict, user.name)
    return updated.to_dict()


# -- destructive remediation (admin only) ---------------------------------
@api_router.post("/threats/{report_id}/actions/{action_index}/approve")
def approve_action(
    report_id: str,
    action_index: int,
    user: AdminUser,
    state: GuardianState,
) -> dict:
    """Human approval: approve and execute one recommended action."""
    pipeline = _pipeline(state)
    report = _find_report(pipeline, report_id)
    _action_or_404(report, action_index)
    logger.info("Action %d of report %s approved by %s", action_index, report_id, user.name)
    updated = pipeline.execute_action(report_id, action_index, actor=user.name)
    if updated is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Report no longer available")
    return updated.to_dict()


@api_router.post("/threats/{report_id}/actions/{action_index}/reject")
def reject_action(
    report_id: str,
    action_index: int,
    user: AdminUser,
    state: GuardianState,
) -> dict:
    pipeline = _pipeline(state)
    report = _find_report(pipeline, report_id)
    action = _action_or_404(report, action_index)
    pipeline.gate.reject(action, actor=user.name, report_id=report_id)
    logger.info("Action %d of report %s rejected by %s", action_index, report_id, user.name)
    return report.to_dict()


@api_router.post("/threats/{report_id}/rollback")
def rollback(
    report_id: str,
    user: AdminUser,
    state: GuardianState,
) -> dict:
    """Undo every reversible containment effect applied for a report."""
    pipeline = _pipeline(state)
    _find_report(pipeline, report_id)
    count = pipeline.rollback_actions(report_id)
    logger.info("Rolled back %d effects of report %s (by %s)", count, report_id, user.name)
    return {"report_id": report_id, "rolled_back": count}


# -- live stream -----------------------------------------------------------
@ws_router.websocket("/ws")
async def ws_stream(websocket: WebSocket) -> None:
    """Push threat reports and health snapshots as they happen.

    Clients authenticate with ``?token=...`` when auth is enabled and receive
    ``{"seq": N, "items": [{"seq", "kind", "data"}, ...]}`` deltas.
    """
    state = websocket.app.state.guardian
    if state.authenticator.enabled:
        token = websocket.query_params.get("token")
        if state.authenticator.authenticate(token) is None:
            await websocket.close(code=4401)
            return
    await websocket.accept()
    last_seq = 0
    if state.driver is not None:
        refresh = state.driver.refresh_seconds
    else:
        refresh = state.pipeline.config.server.refresh_seconds or 1.0
    try:
        while True:
            try:
                await asyncio.wait_for(websocket.receive_text(), timeout=refresh)
            except TimeoutError:
                pass
            except Exception:  # noqa: BLE001 - client gone; stop streaming
                break
            items = state.changes.since(last_seq)
            if items:
                last_seq = items[-1]["seq"]
                await websocket.send_json({"seq": last_seq, "items": items})
    finally:
        with suppress(RuntimeError):
            await websocket.close()
