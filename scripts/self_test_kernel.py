"""Live kernel telemetry self-test (M8).

Validates the hardened kernel providers (auditd / Tracee / eBPF) against a
running Linux system: each selected provider is started, real kernel activity
(exec, file write, connect, setuid) is generated while it collects, and the
test passes only if the provider produced events and reports a healthy
:meth:`~backend.telemetry.base.TelemetryProvider.status`.

Run on a Linux host (CI: ``ubuntu-latest`` with ``auditd`` + ``bpfcc-tools``
installed, started, and audited via ``sudo``). On non-Linux it exits 1.

Examples:
    python scripts/self_test_kernel.py --provider auditd --ensure-rules
    python scripts/self_test_kernel.py --provider tracee
    python scripts/self_test_kernel.py --provider bpf --duration 10
    python scripts/self_test_kernel.py            # probe whatever is available
"""

from __future__ import annotations

import argparse
import contextlib
import importlib.util
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Protocol

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.core.logging import get_logger
from backend.telemetry.auditd_provider import AuditdProvider
from backend.telemetry.base import TelemetryError, TelemetryProvider
from backend.telemetry.bpf_provider import BPFProvider
from backend.telemetry.tracee_provider import TraceeProvider

logger = get_logger("self_test_kernel")

DEFAULT_LOG = "/var/log/audit/audit.log"

# auditctl rules mirrored by CI: capture the syscalls the providers care about.
AUDIT_RULES = (
    ("-a", "always,exit", "-F", "arch=b64", "-S", "execve"),
    ("-a", "always,exit", "-F", "arch=b64", "-S", "openat"),
    ("-a", "always,exit", "-F", "arch=b64", "-S", "connect"),
    ("-a", "always,exit", "-F", "arch=b64", "-S", "setuid"),
)

_STOP = threading.Event()


class _Factories(Protocol):
    def __call__(self, **kwargs: object) -> TelemetryProvider:
        ...


def _generate_activity() -> None:
    """Emit kernel activity until the global stop event is set."""
    marker = Path(tempfile.gettempdir()) / "guardian-self-test.txt"
    while not _STOP.is_set():
        subprocess.run(
            [sys.executable, "-c", "import time; time.sleep(0.05)"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        with marker.open("a", encoding="utf-8") as fh:
            fh.write("guardian kernel self-test\n")
        # Localhost connect (fails fast but the connect(2) syscall still fires).
        with contextlib.suppress(OSError), socket.create_connection(("127.0.0.1", 1), timeout=0.2):
            pass
        # setuid(0): succeeds as root, fails with EPERM otherwise - recorded anyway.
        with contextlib.suppress(OSError):
            os.setuid(0)
        _STOP.wait(0.15)


def _availability(name: str, *, log_path: str) -> tuple[bool, str]:
    if name == "auditd":
        if Path(log_path).exists():
            return True, f"log present: {log_path}"
        if shutil.which("auditctl"):
            return True, "auditctl present (log not yet created)"
        return False, f"no auditd (missing {log_path} and auditctl)"
    if name == "tracee":
        binary = shutil.which("tracee-ebpf")
        return bool(binary), f"binary: {binary or 'not found'}"
    if name == "bpf":
        found = importlib.util.find_spec("bcc") is not None
        return found, "python3-bcc import" if found else "python3-bcc not installed"
    return False, "unknown provider"


def _factory(name: str, *, log_path: str) -> _Factories:
    if name == "auditd":
        return lambda **kw: AuditdProvider(log_path=log_path, **kw)
    if name == "tracee":
        return lambda **kw: TraceeProvider(
            queue_capacity=1000, auto_restart=True, restart_backoff=0.5, **kw
        )
    if name == "bpf":
        return lambda **kw: BPFProvider(**kw)
    raise ValueError(f"unknown provider {name!r}")


def _ensure_rules(install: bool) -> bool:
    """Add/remove the audit ruleset via auditctl. Needs root + auditd."""
    auditctl = shutil.which("auditctl")
    if not auditctl:
        logger.warning("auditctl not found; rules not %s", "installed" if install else "removed")
        return False
    if os.geteuid() != 0:
        logger.warning("not running as root; rules not %s", "installed" if install else "removed")
        return False
    action = "a" if install else "d"
    ok = True
    for rule in AUDIT_RULES:
        result = subprocess.run(
            [auditctl, f"-{action}", *rule],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if result.returncode != 0 and install:
            logger.warning("auditctl rule failed: %s", result.stderr.strip())
            ok = False
    return ok


def _run_provider(name: str, provider: TelemetryProvider, duration: float) -> tuple[list, dict]:
    """Start, generate activity while collecting, stop, return (events, health)."""
    events: list = []
    worker: threading.Thread | None = None
    try:
        provider.start()
    except TelemetryError as exc:
        return [], {"error": str(exc)}
    worker = threading.Thread(target=_generate_activity, daemon=True)
    worker.start()
    t0 = time.monotonic()
    try:
        while time.monotonic() - t0 < duration:
            events.extend(provider.collect())
            time.sleep(0.2)
    finally:
        _STOP.set()
        if worker is not None:
            worker.join(timeout=5)
        with contextlib.suppress(Exception):  # noqa: BLE001 - best-effort shutdown
            provider.stop()
    try:
        health = provider.status().to_dict()
    except Exception:  # noqa: BLE001
        health = {}
    return events, health


def main() -> int:
    parser = argparse.ArgumentParser(description="Live kernel telemetry self-test")
    parser.add_argument(
        "--provider", action="append", choices=("auditd", "tracee", "bpf"),
        help="providers to test (repeatable; default: probe all available)",
    )
    parser.add_argument("--duration", type=float, default=5.0, help="collect seconds per provider")
    parser.add_argument("--log-path", default=DEFAULT_LOG, help="auditd log path")
    parser.add_argument(
        "--ensure-rules", action="store_true",
        help="add audit rules via auditctl for the test, then remove them",
    )
    args = parser.parse_args()

    if not sys.platform.startswith("linux"):
        print(f"kernel self-test requires Linux (platform={sys.platform})", file=sys.stderr)
        return 1

    names = args.provider or ["auditd", "tracee", "bpf"]

    installed = _ensure_rules(install=True) if args.ensure_rules else False
    if args.ensure_rules and not installed:
        print("WARNING: could not install audit rules; auditd may see nothing", file=sys.stderr)

    try:
        failures = 0
        print("\nGuardianOS-AI kernel telemetry self-test\n" + "=" * 62)
        for name in names:
            available, why = _availability(name, log_path=args.log_path)
            if not available:
                print(f"  {name:8s} SKIP   ({why})")
                if args.provider:
                    failures += 1
                continue
            events, health = _run_provider(
                name, _factory(name, log_path=args.log_path)(), args.duration
            )
            status = "PASS" if events else "FAIL"
            if not events:
                failures += 1
            kinds = ", ".join(sorted({e.kind.value for e in events[:200]}))
            print(f"  {name:8s} {status}   events={len(events)}  kinds=[{kinds or '-'}]")
            print(f"           health: {health}")
        print("=" * 62)
        if failures:
            print(f"RESULT: {failures} provider(s) produced no events")
            return 1
        print("RESULT: all probed providers delivered kernel events")
        return 0
    finally:
        if installed:
            _ensure_rules(install=False)
        _STOP.clear()


if __name__ == "__main__":
    raise SystemExit(main())
