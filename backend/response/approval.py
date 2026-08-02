"""Approval workflow for destructive actions.

Every recommended action starts as ``RECOMMENDED``. The gate decides whether
it may proceed (``APPROVED``) or must wait for human confirmation
(``PENDING_APPROVAL``). Destructive actions are denied automatically unless
``auto_approve_destructive`` is explicitly enabled.
"""

from __future__ import annotations

from backend.core.analysis import ActionStatus, ResponseAction
from backend.core.logging import get_logger
from backend.response.actions import DESTRUCTIVE_ACTION_TYPES

logger = get_logger("response.approval")


class ApprovalGate:
    """Routes actions to approved or pending-approval based on risk."""

    def __init__(self, *, auto_approve_destructive: bool = False) -> None:
        self.auto_approve_destructive = auto_approve_destructive

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
        return action

    def approve(self, action: ResponseAction) -> ResponseAction:
        """Human-approved: promote to APPROVED and execute."""
        action.status = ActionStatus.APPROVED
        return action

    def reject(self, action: ResponseAction) -> ResponseAction:
        action.status = ActionStatus.REJECTED
        return action
