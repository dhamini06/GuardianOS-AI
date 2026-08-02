"""Low-level data sources for kernel telemetry (M3).

* :class:`AuditLogSource` - tails an auditd log file, returning only lines
  appended since the previous call (pull-based, matching the provider
  contract).
* :class:`SubprocessLineSource` - consumes stdout lines from a long-running
  child process (e.g. ``tracee-ebpf --json``) via a background reader thread,
  so reads never block the pipeline.
"""

from __future__ import annotations

import queue
import subprocess
import sys
import threading
from pathlib import Path

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
    """Tails an auditd log file and hands back only newly appended lines."""

    def __init__(self, path: str, *, encoding: str = "utf-8", errors: str = "replace") -> None:
        self._path = Path(path)
        self._encoding = encoding
        self._errors = errors
        self._fh = None

    @property
    def path(self) -> Path:
        return self._path

    def start(self) -> None:
        if not self._path.exists():
            raise TelemetryError(f"audit log not found: {self._path}")
        self._fh = self._path.open("r", encoding=self._encoding, errors=self._errors)
        self._fh.seek(0, 2)  # tail: start at the end, only future lines are new

    def read_new_lines(self) -> list[str]:
        if self._fh is None:
            raise TelemetryError("AuditLogSource.read_new_lines() called before start()")
        return [line.rstrip("\n") for line in self._fh if line]

    def stop(self) -> None:
        if self._fh is not None:
            self._fh.close()
            self._fh = None


class SubprocessLineSource:
    """Consumes stdout lines from a long-running child process non-blockingly."""

    def __init__(self, command: list[str], *, encoding: str = "utf-8") -> None:
        self._command = list(command)
        self._encoding = encoding
        self._proc: subprocess.Popen | None = None
        self._thread: threading.Thread | None = None
        self._queue: queue.Queue[str] = queue.Queue()

    def start(self) -> None:
        if self._proc is not None:
            return
        try:
            self._proc = subprocess.Popen(
                self._command,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                encoding=self._encoding,
                bufsize=1,
            )
        except FileNotFoundError as exc:
            raise TelemetryError(
                f"subprocess not found: {self._command[0]!r}; is it installed and on PATH?"
            ) from exc
        self._thread = threading.Thread(target=self._pump, name="line-source", daemon=True)
        self._thread.start()

    def _pump(self) -> None:
        assert self._proc is not None and self._proc.stdout is not None
        for line in self._proc.stdout:
            self._queue.put(line.rstrip("\n"))

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
        if self._proc is not None and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        if self._thread is not None:
            self._thread.join(timeout=2)
        self._proc = None
        self._thread = None
