"""eBPF probe provider via BCC (Linux, M3 - experimental).

Attaches kprobes for ``execve``, ``tcp_v4_connect`` and ``setuid`` and streams
perf-buffer samples into :class:`KernelEvent` records through the shared
:func:`normalize_kernel_record` normaliser.

Requires Linux and the ``python3-bcc`` package
(``apt install python3-bcc bpfcc-tools``). Kprobe symbol names vary by kernel;
the provider tries common spellings and warns on misses. Prefer the
:class:`~backend.telemetry.tracee_provider.TraceeProvider` for production -
it exposes the same events with a maintained, well-tested tool.
"""

from __future__ import annotations

import ctypes
import io
import ipaddress
import socket
from collections import deque
from contextlib import redirect_stderr
from typing import Any

from backend.core.logging import get_logger
from backend.telemetry.base import TelemetryError
from backend.telemetry.parsers import normalize_kernel_record
from backend.telemetry.ring import BoundedProviderMixin, BoundedRing, DropCounter, RateLimiter
from backend.telemetry.sources import require_linux

logger = get_logger("telemetry.bpf")

BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/socket.h>
#include <net/inet_sock.h>

#define NAME_MAX 64
#define PATH_MAX 256

struct data_t {
    u64 ts;
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 code;             // 1 execve, 2 connect, 3 setuid
    u32 ret;
    char exe[NAME_MAX];
    char path[PATH_MAX];
    u16 saddr_family;
    u16 saddr_port;
    u32 saddr_addr;
};
BPF_PERF_OUTPUT(events);

int trace_execve(struct pt_regs *ctx, const char __user *filename) {
    struct data_t d = {};
    d.ts = bpf_ktime_get_ns();
    d.pid = bpf_get_current_pid_tgid() >> 32;
    d.uid = bpf_get_current_uid_gid() & 0xffffffff;
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    d.ppid = t->parent->tgid;
    d.code = 1;
    bpf_get_current_comm(&d.exe, sizeof(d.exe));
    if (filename) bpf_probe_read_user_str(&d.path, sizeof(d.path), filename);
    events.perf_submit(ctx, &d, sizeof(d));
    return 0;
}

int trace_connect(struct pt_regs *ctx, struct sockaddr_in *uaddr) {
    struct data_t d = {};
    d.ts = bpf_ktime_get_ns();
    d.pid = bpf_get_current_pid_tgid() >> 32;
    d.uid = bpf_get_current_uid_gid() & 0xffffffff;
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    d.ppid = t->parent->tgid;
    d.code = 2;
    bpf_get_current_comm(&d.exe, sizeof(d.exe));
    if (uaddr) {
        bpf_probe_read_user(&d.saddr_family, 2, &uaddr->sin_family);
        bpf_probe_read_user(&d.saddr_port, 2, &uaddr->sin_port);
        bpf_probe_read_user(&d.saddr_addr, 4, &uaddr->sin_addr.s_addr);
    }
    events.perf_submit(ctx, &d, sizeof(d));
    return 0;
}

int trace_setuid(struct pt_regs *ctx, uid_t uid) {
    struct data_t d = {};
    d.ts = bpf_ktime_get_ns();
    d.pid = bpf_get_current_pid_tgid() >> 32;
    d.uid = bpf_get_current_uid_gid() & 0xffffffff;
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    d.ppid = t->parent->tgid;
    d.code = 3;
    d.saddr_addr = (u32)uid;
    bpf_get_current_comm(&d.exe, sizeof(d.exe));
    events.perf_submit(ctx, &d, sizeof(d));
    return 0;
}
"""


class _Sample(ctypes.Structure):
    _fields_ = [
        ("ts", ctypes.c_uint64),
        ("pid", ctypes.c_uint32),
        ("ppid", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
        ("code", ctypes.c_uint32),
        ("ret", ctypes.c_uint32),
        ("exe", ctypes.c_char * 64),
        ("path", ctypes.c_char * 256),
        ("saddr_family", ctypes.c_uint16),
        ("saddr_port", ctypes.c_uint16),
        ("saddr_addr", ctypes.c_uint32),
    ]


class BPFProvider(BoundedProviderMixin):
    """BCC eBPF probe provider behind the :class:`TelemetryProvider` contract."""

    def __init__(
        self,
        *,
        ring_capacity: int = 10_000,
        max_events: int = 500,
        rate_limit: float = 0.0,
    ) -> None:
        self._bpf: Any = None
        self._samples: deque[_Sample] = deque()
        self._ring = BoundedRing(ring_capacity)
        self._drops = DropCounter()
        self._limiter = RateLimiter(rate_limit) if rate_limit and rate_limit > 0 else None
        self._max_events = max_events
        self._started = False
        self._provider_name = "bpf"

    # -- lifecycle --------------------------------------------------------
    def start(self) -> None:
        require_linux("BPFProvider")
        try:
            from bcc import BPF  # noqa: PLC0415
        except ImportError as exc:
            raise TelemetryError(
                "BPFProvider needs the python3-bcc package (apt install python3-bcc bpfcc-tools)"
            ) from exc
        try:
            # BCC's compile errors go to stderr; capture them so the failure
            # message explains the actual clang/kernel incompatibility instead
            # of swallowing it into "<text>".
            with redirect_stderr(_bcc_stderr := io.StringIO()):
                self._bpf = BPF(text=BPF_PROGRAM)
        except Exception as exc:  # noqa: BLE001 - bcc raises varied kernel errors
            diagnostics = "\n".join(_bcc_stderr.getvalue().splitlines()[-8:])
            detail = f": {diagnostics}" if diagnostics else ""
            raise TelemetryError(
                f"BPF load failed (kernel too old / missing headers?){detail}"
            ) from exc
        self._attach(self._bpf)
        self._bpf["events"].open_perf_buffer(self._on_sample)
        self._started = True
        self.mark_started()
        logger.info("BPFProvider started (kprobes: execve, tcp_v4_connect, setuid)")

    def stop(self) -> None:
        self._bpf = None
        self._started = False
        self.mark_stopped()

    # -- core -------------------------------------------------------------
    def collect(self) -> list:
        if not self._started or self._bpf is None:
            raise TelemetryError("BPFProvider.collect() called before start()")
        try:
            self._bpf.perf_buffer_poll(timeout=50)
        except Exception as exc:  # noqa: BLE001 - kernel polls can fail under pressure
            self._mark_error(exc)
            raise TelemetryError(f"BPFProvider perf poll failed: {exc}") from exc
        parsed: list = []
        while self._samples and len(parsed) < self._max_events:
            record = self._decode(self._samples.popleft())
            parsed.extend(normalize_kernel_record(record))
        return self._deliver(parsed)

    def _source_status(self) -> dict:
        return {"bpf_loaded": self._bpf is not None, "kprobes": ["execve", "tcp_v4_connect", "setuid"]}

    # -- internals --------------------------------------------------------
    def _on_sample(self, _cpu: int, data: Any, _size: int) -> None:
        sample = ctypes.cast(data, ctypes.POINTER(_Sample)).contents
        self._samples.append(sample)

    @staticmethod
    def _attach(bpf) -> None:
        probes = {
            "trace_execve": ("do_execve", "__do_execve"),
            "trace_connect": ("tcp_v4_connect", "__sys_connect", "sys_connect"),
            "trace_setuid": ("__sys_setuid", "__x64_sys_setuid", "sys_setuid"),
        }
        for fn_name, symbols in probes.items():
            attached = False
            for symbol in symbols:
                try:
                    bpf.attach_kprobe(event=symbol, fn_name=fn_name)
                    attached = True
                    break
                except Exception:  # noqa: BLE001
                    continue
            if not attached:
                logger.warning("Could not attach kprobe %s (symbols %s)", fn_name, symbols)

    @staticmethod
    def _decode(sample: _Sample) -> dict:
        code = sample.code
        record: dict = {
            "timestamp": sample.ts,
            "pid": sample.pid,
            "ppid": sample.ppid,
            "uid": sample.uid,
            "return_value": sample.ret,
        }
        exe = sample.exe.decode(errors="replace") or "unknown"
        if code == 1:
            path = sample.path.decode(errors="replace") or exe
            record["name"] = "execve"
            record["exe"] = path
            record["argv"] = ""
        elif code == 2:
            record["name"] = "connect"
            ip = str(ipaddress.IPv4Address(sample.saddr_addr))
            record["sockaddr"] = f"{ip}:{socket.ntohs(sample.saddr_port)}"
            record["exe"] = exe
        else:
            record["name"] = "setuid"
            record["to_uid"] = sample.saddr_addr
            record["exe"] = exe
        return record
