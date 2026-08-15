"""Low-level data sources for kernel telemetry (M3, hardened in M8).

* :class:`AuditLogSource` - tails an auditd log file, returning only lines
  appended since the previous call (pull-based, matching the provider
  contract). Survives ``logrotate``: when the file is rotated (renamed and
  recreated, or truncated in place) the source transparently re-opens the
  new file instead of silently tailing a stale inode.
* :class:`SubprocessLineSource` - consumes stdout lines from a long-running
  child process (e.g. ``tracee-ebpf --json``) via background reader threads,
  so reads never block the pipeline. The queue is bounded (configurable),
  stderr is captured for diagnostics, and the child is restarted with
  exponential backoff when ``auto_restart`` is enabled.
"""

from __future__ import annotations

import contextlib
import queue
import subprocess
import sys
import threading
from collections import deque
from io import TextIOWrapper
from pathlib import Path
from typing import Any

from backend.core.logging import get_logger
from backend.telemetry.base import TelemetryError

logger = get_logger("telemetry.sources")


def require_linux(provider_name: str) -> None:
    """Raise TelemetryError unless running on Linux (kernel sources are Linux-only)."""
    if sys.platform != "linux":
        raise TelemetryError(
            f"{provider_name} requires Linux (current platform is {sys.platform!r}); "
            "use telemetry.provider=process_monitor for development"
        )


class AuditLogSource:
    """Tails an auditd log file and hands back only newly appended lines.

    Detects log rotation by comparing the path's device/inode on each read
    against the inode of the open handle:

    * *rename* rotation (default ``logrotate``): the old inode disappears, a
      new file appears - the source closes the stale handle and re-opens the
      new file at its end.
    * *copytruncate* rotation: the inode is unchanged but the file shrinks
      underneath us - the source detects the size falling below the read
      cursor and seeks back to the start.

    Rotation and truncation are counted and exposed via :meth:`status` so
    operators can confirm the tailer is keeping up with ``auditd``.
    """

    def __init__(self, path: str, *, encoding: str = "utf-8", errors: str = "replace") -> None:
        self._path = Path(path)
        self._encoding = encoding
        self._errors = errors
        self._fh: TextIOWrapper | None = None
        self._inode: tuple[int, int] | None = None
        self._rotations = 0
        self._truncations = 0

    @property
    def path(self) -> Path:
        return self._path

    @property
    def rotations(self) -> int:
        return self._rotations

    @property
    def truncations(self) -> int:
        return self._truncations

    def start(self) -> None:
        if not self._path.exists():
            raise TelemetryError(f"audit log not found: {self._path}")
        self._fh = self._path.open("r", encoding=self._encoding, errors=self._errors)
        self._fh.seek(0, 2)  # tail: start at the end, only future lines are new
        self._inode = self._stat_inode()

    def read_new_lines(self) -> list[str]:
        if self._fh is None:
            raise TelemetryError("AuditLogSource.read_new_lines() called before start()")
        self._handle_rotation()
        self._handle_truncation()
        lines = [line.rstrip("\n") for line in self._fh if line]
        # Rotation can land mid-read (rename + recreate); re-check afterwards.
        self._handle_rotation()
        return lines

    def stop(self) -> None:
        if self._fh is not None:
            self._fh.close()
            self._fh = None
        self._inode = None

    def status(self) -> dict[str, Any]:
        return {
            "path": str(self._path),
            "inode": self._inode,
            "rotations": self._rotations,
            "truncations": self._truncations,
        }

    # -- internals --------------------------------------------------------
    def _stat_inode(self) -> tuple[int, int] | None:
        try:
            stat = self._path.stat()
        except OSError:
            return None
        return (stat.st_dev, stat.st_ino)

    def _handle_rotation(self) -> None:
        assert self._fh is not None
        current = self._stat_inode()
        if current is None or self._inode is None or current == self._inode:
            return
        with contextlib.suppress(OSError):
            self._fh.close()
        self._fh = self._path.open("r", encoding=self._encoding, errors=self._errors)
        self._fh.seek(0, 2)
        self._inode = current
        self._rotations += 1
        logger.info("AuditLogSource: %s rotated (count=%d)", self._path, self._rotations)

    def _handle_truncation(self) -> None:
        assert self._fh is not None
        try:
            size = self._path.stat().st_size
        except OSError:
            return
        if size < self._fh.tell():
            self._fh.seek(0)
            self._truncations += 1
            logger.info("AuditLogSource: %s truncated in place (count=%d)", self._path, self._truncations)


class SubprocessLineSource:
    """Consumes stdout lines from a long-running child process non-blockingly.

    Robustness features added in M8 for long-lived kernel tools (Tracee,
    ``tracee-ebpf``):

    * bounded stdout queue with drop accounting - a stalled pipeline can
      never balloon memory;
    * stderr captured into a bounded tail for diagnostics (previously lost);
    * automatic restart with exponential backoff when the child dies
      unexpectedly (``auto_restart=True``);
    * an operational :meth:`status` snapshot (alive, exit code, restarts,
      drops, stderr tail) surfaced through the provider health endpoint.
    """

    def __init__(
        self,
        command: list[str],
        *,
        encoding: str = "utf-8",
        max_queue: int | None = None,
        auto_restart: bool = True,
        restart_backoff: float = 1.0,
    ) -> None:
        self._command = list(command)
        self._encoding = encoding
        self._queue: queue.Queue[str] = queue.Queue(maxsize=max_queue or 0)
        self._auto_restart = auto_restart
        self._restart_backoff = max(0.1, float(restart_backoff))
        self._proc: subprocess.Popen | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._alive = False
        self._exit_code: int | None = None
        self._restart_count = 0
        self._dropped_lines = 0
        self._stderr_tail: deque[str] = deque(maxlen=200)
        self._stderr_lock = threading.Lock()
        self._spawn_error: str | None = None

    def start(self) -> None:
        with self._lock:
            if self._proc is not None:
                return
            self._stop.clear()
            self._spawn_locked()
        self._thread = threading.Thread(target=self._pump, name="line-source", daemon=True)
        self._thread.start()

    def _spawn_locked(self) -> None:
        try:
            self._proc = subprocess.Popen(
                self._command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding=self._encoding,
                bufsize=1,
            )
        except FileNotFoundError as exc:
            raise TelemetryError(
                f"subprocess not found: {self._command[0]!r}; is it installed and on PATH?"
            ) from exc
        self._alive = True
        self._exit_code = None

    def _pump(self) -> None:
        """Supervisor loop: spawn, drain streams, restart with backoff."""
        while not self._stop.is_set():
            with self._lock:
                proc = self._proc
                needs_spawn = proc is None or (proc.poll() is not None)
            if needs_spawn:
                with self._lock:
                    try:
                        self._spawn_locked()
                    except TelemetryError as exc:
                        self._spawn_error = str(exc)
                        logger.error("SubprocessLineSource: %s", exc)
                        break
            out_thread = threading.Thread(target=self._drain_stdout, name="line-out", daemon=True)
            err_thread = threading.Thread(target=self._drain_stderr, name="line-err", daemon=True)
            out_thread.start()
            err_thread.start()
            out_thread.join()
            err_thread.join(timeout=2)
            self._mark_exited()
            if not self._auto_restart or self._stop.is_set():
                break
            with self._lock:
                attempt = self._restart_count
                self._restart_count += 1
            delay = min(self._restart_backoff * (2**attempt), 60.0)
            logger.warning(
                "SubprocessLineSource: %s exited (code=%s); restarting in %.1fs (attempt %d)",
                self._command[0],
                self._exit_code,
                delay,
                attempt + 1,
            )
            self._stop.wait(delay)

    def _drain_stdout(self) -> None:
        with self._lock:
            proc = self._proc
        if proc is None or proc.stdout is None:
            return
        for line in proc.stdout:
            if self._stop.is_set():
                break
            try:
                self._queue.put_nowait(line.rstrip("\n"))
            except queue.Full:
                self._dropped_lines += 1

    def _drain_stderr(self) -> None:
        with self._lock:
            proc = self._proc
        if proc is None or proc.stderr is None:
            return
        for line in proc.stderr:
            if self._stop.is_set():
                break
            with self._stderr_lock:
                self._stderr_tail.append(line.rstrip("\n"))

    def _mark_exited(self) -> None:
        with self._lock:
            proc = self._proc
        if proc is not None:
            # stdout EOF can precede process reaping; wait briefly so the
            # real exit code is recorded instead of a transient None.
            with contextlib.suppress(subprocess.TimeoutExpired):
                proc.wait(timeout=5)
        with self._lock:
            if self._proc is not None:
                self._exit_code = self._proc.poll()
                self._alive = self._exit_code is None

    def read_lines(self) -> list[str]:
        if self._proc is None:
            raise TelemetryError("SubprocessLineSource.read_lines() called before start()")
        lines: list[str] = []
        while True:
            try:
                lines.append(self._queue.get_nowait())
            except queue.Empty:
                break
        return lines

    def stop(self) -> None:
        self._stop.set()
        with self._lock:
            proc = self._proc
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
        if self._thread is not None:
            self._thread.join(timeout=5)
        with self._lock:
            self._proc = None
            self._alive = False
            self._thread = None

    def status(self) -> dict[str, Any]:
        with self._lock:
            alive = self._alive
            exit_code = self._exit_code
            restarts = self._restart_count
        with self._stderr_lock:
            stderr_tail = list(self._stderr_tail)[-10:]
        return {
            "command": " ".join(self._command),
            "alive": alive,
            "exit_code": exit_code,
            "restarts": restarts,
            "queue_size": self._queue.qsize(),
            "dropped_lines": self._dropped_lines,
            "auto_restart": self._auto_restart,
            "spawn_error": self._spawn_error,
            "stderr_tail": stderr_tail,
        }
