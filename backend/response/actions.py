"""Concrete remediation actions.

The builder is a static factory for well-formed :class:`ResponseAction`
instances. The executor is the approval-gated dispatch point: it validates
that an action was approved, delegates the platform effect to the
:class:`~backend.response.containment.ContainmentManager` (which records how
to roll it back), and marks the action ``EXECUTED`` or ``FAILED``. Every
execution is mirrored to the signed audit trail. ``dry_run`` mode turns every
execution into a logged recommendation with zero system effect.
"""

from __future__ import annotations

from backend.core.analysis import ActionStatus, ResponseAction
from backend.core.logging import get_logger
from backend.response.audit import AuditTrail, Signer
from backend.response.containment import ContainmentManager

logger = get_logger("response.actions")

DESTRUCTIVE_ACTION_TYPES = {"kill_process", "freeze_process", "block_ip", "quarantine_file"}


class ResponseActionBuilder:
    """Static factory for well-formed :class:`ResponseAction` instances."""

    @staticmethod
    def kill_process(pid: int, exe: str, rationale: str) -> ResponseAction:
        return ResponseAction(
            action_type="kill_process",
            description=f"Terminate process {exe} (pid {pid})",
            destructive=True,
            requires_approval=True,
            target={"pid": pid, "exe": exe},
            rationale=rationale,
        )

    @staticmethod
    def freeze_process(pid: int, exe: str, rationale: str) -> ResponseAction:
        return ResponseAction(
            action_type="freeze_process",
            description=f"Freeze (SIGSTOP) process {exe} (pid {pid}) pending review",
            destructive=False,
            requires_approval=True,
            target={"pid": pid, "exe": exe},
            rationale=rationale,
        )

    @staticmethod
    def block_ip(ip: str, rationale: str) -> ResponseAction:
        return ResponseAction(
            action_type="block_ip",
            description=f"Block outbound connections to {ip}",
            destructive=True,
            requires_approval=True,
            target={"ip": ip},
            rationale=rationale,
        )

    @staticmethod
    def quarantine_file(path: str, rationale: str) -> ResponseAction:
        return ResponseAction(
            action_type="quarantine_file",
            description=f"Quarantine suspicious file {path}",
            destructive=False,
            requires_approval=True,
            target={"path": path},
            rationale=rationale,
        )


class ActionExecutor:
    """Approval-gated dispatch of actions against the live system."""

    def __init__(
        self,
        dry_run: bool = True,
        containment: ContainmentManager | None = None,
        audit: AuditTrail | None = None,
        signer: Signer | None = None,
    ) -> None:
        self.dry_run = dry_run
        self.containment = containment or ContainmentManager(dry_run=dry_run)
        self.audit = audit
        self.signer = signer

    def execute(
        self,
        action: ResponseAction,
        *,
        report_id: str | None = None,
    ) -> ResponseAction:
        if action.status != ActionStatus.APPROVED:
            return action

        try:
            self.containment.apply(action, report_id=report_id)
        except Exception as exc:  # noqa: BLE001 - failures are marked, not raised
            logger.exception("Action failed: %s", action.action_type)
            action.status = ActionStatus.FAILED
            action.rationale = f"{action.rationale or ''} ERROR: {exc}".strip()
            self._audit("execution_failed", report_id, {"action": action.to_dict(), "error": str(exc)})
            return action

        action.status = ActionStatus.EXECUTED
        self._audit("execution", report_id, {"action": action.to_dict()})
        return action

    def _audit(
        self,
        event: str,
        report_id: str | None,
        data: dict,
    ) -> None:
        if self.audit is None:
            return
        self.audit.record(event, report_id=report_id, data=data, signer=self.signer)
