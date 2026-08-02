"""Tests for containment with rollback."""

from __future__ import annotations

import shutil

from backend.core.analysis import ResponseAction
from backend.response.containment import ContainmentManager, SystemRunner


class FakeRunner(SystemRunner):
    def __init__(self) -> None:
        self.calls: list[list[str]] = []
        self.suspended: list[int] = []
        self.moves: list[tuple[str, str]] = []
        self.terminated: list[int] = []
        self._platform = "linux"

    @property
    def platform(self) -> str:
        return self._platform

    def run(self, argv: list[str]) -> int:
        self.calls.append(argv)
        return 0

    def suspend(self, pid: int) -> None:
        self.suspended.append(pid)

    def resume(self, pid: int) -> None:
        self.suspended.remove(pid)

    def move(self, src: str, dst: str) -> None:
        shutil.move(src, dst)
        self.moves.append((src, dst))

    def terminate(self, pid: int) -> None:
        self.terminated.append(pid)


def _freeze_action(pid: int = 42) -> ResponseAction:
    return ResponseAction(
        action_type="freeze_process",
        description="freeze",
        destructive=False,
        requires_approval=True,
        target={"pid": pid, "exe": "bash"},
    )


def _block_action(ip: str = "203.0.113.9") -> ResponseAction:
    return ResponseAction(
        action_type="block_ip",
        description="block",
        destructive=True,
        requires_approval=True,
        target={"ip": ip},
    )


def _kill_action(pid: int = 42) -> ResponseAction:
    return ResponseAction(
        action_type="kill_process",
        description="kill",
        destructive=True,
        requires_approval=True,
        target={"pid": pid, "exe": "bash"},
    )


def test_freeze_records_and_rolls_back():
    runner = FakeRunner()
    manager = ContainmentManager(dry_run=False, runner=runner)
    entry = manager.apply(_freeze_action())
    assert runner.suspended == [42]
    assert manager.contained("freeze_process") == [entry]
    assert manager.rollback(entry) is True
    assert runner.suspended == []
    assert manager.entries == []


def test_dry_run_records_without_effect():
    runner = FakeRunner()
    manager = ContainmentManager(dry_run=True, runner=runner)
    manager.apply(_freeze_action())
    assert runner.suspended == []
    assert len(manager.entries) == 1


def test_block_ip_uses_nftables_and_undoes():
    runner = FakeRunner()
    manager = ContainmentManager(dry_run=False, runner=runner)
    entry = manager.apply(_block_action("203.0.113.9"))
    assert runner.calls and runner.calls[0][:4] == ["nft", "add", "element", "ip filter"]
    assert manager.rollback(entry) is True
    assert any(call[0] == "nft" and call[1] == "delete" for call in runner.calls)


def test_kill_is_not_reversible():
    runner = FakeRunner()
    manager = ContainmentManager(dry_run=False, runner=runner)
    entry = manager.apply(_kill_action())
    assert runner.terminated == [42]
    assert entry.reversible is False
    assert manager.rollback(entry) is False
    assert len(manager.entries) == 1  # kept for the audit trail


def test_quarantine_moves_and_restores(tmp_path):
    runner = FakeRunner()
    src = tmp_path / "payload.sh"
    src.write_text("evil")
    manager = ContainmentManager(
        dry_run=False, runner=runner, quarantine_dir=str(tmp_path / "q")
    )
    entry = manager.apply(
        ResponseAction(
            action_type="quarantine_file",
            description="q",
            destructive=False,
            requires_approval=True,
            target={"path": str(src)},
        )
    )
    assert runner.moves and runner.moves[0][0] == str(src)
    assert manager.rollback(entry) is True
    assert any(dst == str(src) for _, dst in runner.moves)


def test_rollback_all_filters_by_report_id():
    runner = FakeRunner()
    manager = ContainmentManager(dry_run=True, runner=runner)
    manager.apply(_freeze_action(), report_id="r1")
    manager.apply(_freeze_action(pid=99), report_id="r2")
    assert manager.rollback_all(report_id="r1") == 1
    assert len(manager.entries) == 1
    assert manager.entries[0].report_id == "r2"


def test_rollback_all_ignores_non_reversible():
    manager = ContainmentManager(dry_run=True, runner=FakeRunner())
    manager.apply(_kill_action())
    assert manager.rollback_all() == 0
    assert len(manager.entries) == 1
