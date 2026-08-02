"""Approval workflow for destructive actions.

Every recommended action starts as ``RECOMMENDED``. The gate decides whether
it may proceed (``APPROVED``) or must wait for human confirmation
(``PENDING_APPROVAL``). Destructive actions are denied automatically unless
``auto_approve_destructive`` is explicitly enabled. Approvals and rejections
are recorded to the signed audit trail so every response decision is
accountable.
"""

from __future__ import annotations

from backend.core.analysis import ActionStatus, ResponseAction
from backend.core.logging import get_logger
from backend.response.actions import DESTRUCTIVE_ACTION_TYPES
from backend.response.audit import AuditTrail, Signer

logger = get_logger("response.approval")


class ApprovalGate:
    """Routes actions to approved or pending-approval based on risk."""

    def __init__(
        self,
        *,
        auto_approve_destructive: bool = False,
        audit: AuditTrail | None = None,
        signer: Signer | None = None,
    ) -> None:
        self.auto_approve_destructive = auto_approve_destructive
        self.audit = audit
        self.signer = signer

    def process(self, action: ResponseAction) -> ResponseAction:
        if action.status != ActionStatus.RECOMMENDED:
            return action

        destructive = action.action_type in DESTRUCTIVE_ACTION_TYPES
        if destructive and not self.auto_approve_destructive:
            action.status = ActionStatus.PENDING_APPROVAL
            logger.info(
                "Action %s requires approval and is pending human confirmation.",
                action.action_type,
            )
        else:
            action.status = ActionStatus.APPROVED
            logger.info(
                "Action %s auto-approved (auto_approve_destructive=%s).",
                action.action_type,
                self.auto_approve_destructive,
            )
            self._audit("auto_approved", action)
        return action

    def approve(self, action: ResponseAction, *, actor: str = "analyst") -> ResponseAction:
        """Human-approved: promote to APPROVED and execute."""
        action.status = ActionStatus.APPROVED
        self._audit("approved", action, actor=actor)
        return action

    def reject(self, action: ResponseAction, *, actor: str = "analyst") -> ResponseAction:
        action.status = ActionStatus.REJECTED
        self._audit("rejected", action, actor=actor)
        return action

    def _audit(
        self,
        event: str,
        action: ResponseAction,
        *,
        actor: str = "system",
    ) -> None:
        if self.audit is None:
            return
        self.audit.record(event, actor=actor, data={"action": action.to_dict()}, signer=self.signer)
