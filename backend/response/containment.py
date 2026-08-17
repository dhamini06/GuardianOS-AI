"""Containment actions with rollback.

The containment manager performs the platform effect (freeze, block, move to
quarantine, kill) and records a :class:`ContainmentEntry` describing how to
reverse it. Freezing, blocking and quarantining are reversible; killing is
deliberately not. Entries feed the audit trail and allow an analyst to undo a
response after the fact.

Platform effects go through a small :class:`SystemRunner` so tests can drive
apply/rollback with a fake runner; on non-Linux hosts the nftables driver
raises :class:`ContainmentError` instead of issuing unsafe commands.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
import uuid
from collections.abc import Callable
from pathlib import Path

from backend.core.analysis import ResponseAction
from backend.core.logging import get_logger
from backend.response.audit import AuditTrail, Signer
from backend.response.base import ActionExecutorError

logger = get_logger("response.containment")

NFT_TABLE = "ip filter"
NFT_SET = "guardian_blocked"


class ContainmentError(ActionExecutorError):
    """Raised when a containment action cannot be applied or reversed."""


class ContainmentEntry:
    """A recorded containment operation that can (usually) be undone."""

    __slots__ = (
        "entry_id",
        "action_type",
        "target",
        "description",
        "reversible",
        "undo",
        "timestamp",
        "report_id",
    )

    def __init__(
        self,
        *,
        action_type: str,
        target: dict,
        description: str,
        reversible: bool,
        undo: Callable[[], None] | None,
        report_id: str | None = None,
    ) -> None:
        self.entry_id = uuid.uuid4().hex[:12]
        self.action_type = action_type
        self.target = dict(target)
        self.description = description
        self.reversible = reversible
        self.undo = undo
        self.timestamp = time.time()
        self.report_id = report_id

    def to_dict(self) -> dict:
        return {
            "entry_id": self.entry_id,
            "action_type": self.action_type,
            "target": dict(self.target),
            "description": self.description,
            "reversible": self.reversible,
            "timestamp": self.timestamp,
            "report_id": self.report_id,
        }


class SystemRunner:
    """Real system effects: subprocess, file moves, process signals."""

    def run(self, argv: list[str]) -> int:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=10)
        return result.returncode

    def move(self, src: str, dst: str) -> None:
        import shutil

        shutil.move(src, dst)

    def suspend(self, pid: int) -> None:
        import psutil

        psutil.Process(pid).suspend()

    def resume(self, pid: int) -> None:
        import psutil

        psutil.Process(pid).resume()

    def terminate(self, pid: int) -> None:
        import psutil

        psutil.Process(pid).terminate()

    @property
    def platform(self) -> str:
        return sys.platform


class ContainmentManager:
    """Applies reversible containment and supports rollback."""

    def __init__(
        self,
        *,
        dry_run: bool = True,
        quarantine_dir: str = "quarantine",
        runner: SystemRunner | None = None,
        audit: AuditTrail | None = None,
        signer: Signer | None = None,
        persist_path: str | Path | None = None,
    ) -> None:
        self.dry_run = dry_run
        self.quarantine_dir = quarantine_dir
        self._runner = runner or SystemRunner()
        self._audit = audit
        self._signer = signer
        self._entries: list[ContainmentEntry] = []
        self._persist_path = Path(persist_path) if persist_path else None
        if self._persist_path is not None:
            self._load_entries()

    @property
    def entries(self) -> list[ContainmentEntry]:
        return list(self._entries)

    def apply(self, action: ResponseAction, *, report_id: str | None = None) -> ContainmentEntry | None:
        """Perform a containment action; returns its rollback handle."""
        handler = getattr(self, f"_apply_{action.action_type}", None)
        if handler is None:
            return None
        entry = handler(action, report_id)
        self._entries.append(entry)
        self._persist_entry(entry)
        return entry

    def rollback(self, entry: ContainmentEntry) -> bool:
        """Undo one contained operation; returns False if not possible."""
        if not entry.reversible or entry.undo is None:
            return False
        try:
            entry.undo()
        except Exception as exc:  # pragma: no cover - defensive
            logger.exception("Rollback failed for %s: %s", entry.action_type, exc)
            return False
        self._entries.remove(entry)
        logger.warning("Rolled back %s (%s)", entry.action_type, entry.description)
        if self._audit is not None:
            self._audit.record(
                "rollback",
                report_id=entry.report_id,
                data={"entry": entry.to_dict()},
                signer=self._signer,
            )
        return True

    def rollback_all(self, *, report_id: str | None = None) -> int:
        """Roll back every contained operation, optionally for one report."""
        targets = [
            e for e in self._entries if report_id is None or e.report_id == report_id
        ]
        count = 0
        for entry in list(targets):
            if self.rollback(entry):
                count += 1
        return count

    def contained(self, action_type: str) -> list[ContainmentEntry]:
        return [e for e in self._entries if e.action_type == action_type]

    # -- persistence --------------------------------------------------------

    def _persist_entry(self, entry: ContainmentEntry) -> None:
        if self._persist_path is None:
            return
        self._persist_path.parent.mkdir(parents=True, exist_ok=True)
        with self._persist_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry.to_dict(), sort_keys=True) + "\n")

    def _load_entries(self) -> None:
        if self._persist_path is None or not self._persist_path.exists():
            return
        with self._persist_path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    continue
                entry = ContainmentEntry(
                    action_type=data["action_type"],
                    target=data["target"],
                    description=data.get("description", ""),
                    reversible=data.get("reversible", False),
                    undo=self._reconstruct_undo(data["action_type"], data["target"]),
                    report_id=data.get("report_id"),
                )
                entry.entry_id = data.get("entry_id", entry.entry_id)
                entry.timestamp = data.get("timestamp", entry.timestamp)
                self._entries.append(entry)
        if self._entries:
            logger.info(
                "Loaded %d persisted containment entries from %s",
                len(self._entries),
                self._persist_path,
            )

    def _reconstruct_undo(self, action_type: str, target: dict) -> Callable[[], None] | None:
        if action_type == "freeze_process":
            pid = int(target["pid"])
            def undo_freeze() -> None:
                if not self.dry_run:
                    self._runner.resume(pid)
            return undo_freeze
        if action_type == "block_ip":
            ip = target["ip"]
            def undo_block() -> None:
                if not self.dry_run:
                    self._runner.run(["nft", "delete", "element", NFT_TABLE, NFT_SET, f"{{{ip}}}"])
            return undo_block
        if action_type == "quarantine_file":
            src = Path(target["path"])
            dest = Path(target["quarantined_at"])
            def undo_quarantine() -> None:
                if not self.dry_run and dest.exists() and not src.exists():
                    self._runner.move(str(dest), str(src))
            return undo_quarantine
        return None

    # -- action handlers ---------------------------------------------------
    def _apply_freeze_process(self, action: ResponseAction, report_id: str | None) -> ContainmentEntry:
        pid = int(action.target["pid"])
        if not self.dry_run:
            self._runner.suspend(pid)
        logger.warning("Froze pid %d (dry_run=%s)", pid, self.dry_run)

        def undo() -> None:
            if not self.dry_run:
                self._runner.resume(pid)

        return ContainmentEntry(
            action_type="freeze_process",
            target={"pid": pid},
            description=f"resume pid {pid}",
            reversible=True,
            undo=undo,
            report_id=report_id,
        )

    def _apply_block_ip(self, action: ResponseAction, report_id: str | None) -> ContainmentEntry:
        ip = action.target["ip"]
        if not self.dry_run:
            if self._runner.platform != "linux":
                raise ContainmentError("block_ip requires Linux nftables")
            code = self._runner.run(["nft", "add", "element", NFT_TABLE, NFT_SET, f"{{{ip}}}"])
            if code != 0:
                raise ContainmentError(f"nft add element failed (exit {code})")
        logger.warning("Blocked egress to %s (dry_run=%s)", ip, self.dry_run)

        def undo() -> None:
            if not self.dry_run:
                self._runner.run(["nft", "delete", "element", NFT_TABLE, NFT_SET, f"{{{ip}}}"])

        return ContainmentEntry(
            action_type="block_ip",
            target={"ip": ip},
            description=f"unblock egress to {ip}",
            reversible=True,
            undo=undo,
            report_id=report_id,
        )

    def _apply_quarantine_file(self, action: ResponseAction, report_id: str | None) -> ContainmentEntry:
        src = Path(action.target["path"])
        dest_dir = Path(self.quarantine_dir)
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = dest_dir / f"{src.name}.{int(time.time())}.quarantined"
        if not self.dry_run and src.exists():
            self._runner.move(str(src), str(dest))
        logger.warning("Quarantined %s -> %s (dry_run=%s)", src, dest, self.dry_run)

        def undo() -> None:
            if not self.dry_run and dest.exists() and not src.exists():
                self._runner.move(str(dest), str(src))

        return ContainmentEntry(
            action_type="quarantine_file",
            target={"path": str(src), "quarantined_at": str(dest)},
            description=f"restore {src.name}",
            reversible=True,
            undo=undo,
            report_id=report_id,
        )

    def _apply_kill_process(self, action: ResponseAction, report_id: str | None) -> ContainmentEntry:
        pid = int(action.target["pid"])
        if not self.dry_run:
            self._runner.terminate(pid)
        logger.warning("Killed pid %d (dry_run=%s)", pid, self.dry_run)
        # Killing cannot be undone; the entry exists only for the audit trail.
        return ContainmentEntry(
            action_type="kill_process",
            target={"pid": pid},
            description="kill is not reversible",
            reversible=False,
            undo=None,
            report_id=report_id,
        )
