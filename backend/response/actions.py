"""Concrete remediation actions.

Each action type knows how to describe and (when approved and not in dry-run)
perform itself. Actions are *safe by construction*: destructive operations
never run without explicit approval, and ``dry_run`` mode turns every
execution into a logged recommendation.
"""

from __future__ import annotations

import os
import shutil
import sys
import time
from pathlib import Path

from backend.core.analysis import ActionStatus, ResponseAction
from backend.core.logging import get_logger
from backend.response.base import ActionExecutorError

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
    """Executes actions against the live system, honouring dry-run mode."""

    def __init__(self, dry_run: bool = True) -> None:
        self.dry_run = dry_run

    def execute(self, action: ResponseAction) -> ResponseAction:
        if action.status != ActionStatus.APPROVED:
            return action

        handler = self._handlers().get(action.action_type)
        if handler is None:
            action.status = ActionStatus.FAILED
            action.description = f"{action.description} (unsupported action type)"
            return action

        try:
            handler(action)
        except Exception as exc:  # pragma: no cover - defensive
            logger.exception("Action failed: %s", action.action_type)
            action.status = ActionStatus.FAILED
            action.rationale = f"{action.rationale or ''} ERROR: {exc}".strip()
            return action

        action.status = ActionStatus.EXECUTED
        return action

    def _handlers(self) -> dict[str, callable]:
        return {
            "kill_process": self._kill_process,
            "freeze_process": self._freeze_process,
            "block_ip": self._block_ip,
            "quarantine_file": self._quarantine_file,
        }

    # -- handlers ---------------------------------------------------------
    def _kill_process(self, action: ResponseAction) -> None:
        pid = int(action.target["pid"])
        logger.warning("Killing pid %d (dry_run=%s)", pid, self.dry_run)
        if self.dry_run:
            return
        import psutil

        psutil.Process(pid).terminate()

    def _freeze_process(self, action: ResponseAction) -> None:
        pid = int(action.target["pid"])
        logger.warning("Freezing pid %d (dry_run=%s)", pid, self.dry_run)
        if self.dry_run:
            return
        import psutil

        psutil.Process(pid).suspend()

    def _block_ip(self, action: ResponseAction) -> None:
        ip = action.target["ip"]
        logger.warning("Blocking outbound to %s (dry_run=%s)", ip, self.dry_run)
        if self.dry_run:
            return
        if sys.platform != "linux":
            raise ActionExecutorError("block_ip requires Linux iptables/nftables")
        # Firewall rule out; requires privileges. Keep rule insertion simple.
        ret = os.system(f"iptables -A OUTPUT -d {ip} -j DROP")
        if ret != 0:
            raise ActionExecutorError(f"iptables rule failed (exit {ret})")

    def _quarantine_file(self, action: ResponseAction) -> None:
        path = Path(action.target["path"])
        if not path.exists():
            logger.warning("Quarantine target missing: %s", path)
            return
        quarantine_dir = Path("quarantine")
        quarantine_dir.mkdir(parents=True, exist_ok=True)
        dest = quarantine_dir / f"{path.name}.{int(time.time())}.quarantined"
        logger.warning("Quarantining %s -> %s (dry_run=%s)", path, dest, self.dry_run)
        if not self.dry_run:
            shutil.move(str(path), str(dest))
