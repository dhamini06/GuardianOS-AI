"""Normalisation of raw kernel-observable records into :class:`KernelEvent`.

Each provider (auditd, Tracee, eBPF) emits a different raw representation;
this module turns them into the canonical event model so downstream layers
never depend on the source.

* :func:`AuditRecordParser` - stateful parser for auditd ``audit.log``
  records. A kernel event is spread over several *records* that share an
  audit serial (``SYSCALL`` + ``EXECVE``/``PATH``/``SOCKADDR``); the parser
  reassembles them and emits a complete event when the serial changes or on
  :meth:`~AuditRecordParser.flush`.
* :func:`normalize_kernel_record` - one-shot normalisation for dict-shaped
  records (Tracee JSON, eBPF perf-buffer samples).
"""

from __future__ import annotations

import re
import time
from typing import Any

from backend.core.events import EventKind, KernelEvent, make_event

# x86_64 syscall numbers relevant to behavioural detection.
_SYSCALLS: dict[int, str] = {
    2: "open",
    42: "connect",
    59: "execve",
    85: "creat",
    105: "setuid",
    106: "setgid",
    113: "setreuid",
    114: "setregid",
    117: "setresuid",
    119: "setresgid",
    257: "openat",
    322: "execveat",
}
_EXEC_SYSCALLS = {59, 322}
_CONNECT_SYSCALLS = {42}
_OPEN_SYSCALLS = {2, 85, 257}
_PRIV_SYSCALLS = {105, 106, 113, 114, 117, 119}

SUSPICIOUS_DIRS = ("/tmp", "/dev/shm", "/var/tmp", "/run/user")

# O_WRONLY=1, O_RDWR=2, O_CREAT=64 (octal 0100).
_O_CREAT = 64
_O_WRITE = 1 | 2

_MSG_RE = re.compile(r"^type=(\w+)\s+msg=audit\(([\d.]+):(\d+)\)")
_PAIR_RE = re.compile(r"(\w+)=(\"(?:[^\"\\]|\\.)*\"|\([^)]*\)|[^=\s]+)")


def _pairs(body: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for key, value in _PAIR_RE.findall(body):
        out[key] = _clean(value)
    return out


def _clean(value: str) -> str:
    if value.startswith('"') and value.endswith('"'):
        return value[1:-1].replace('\\"', '"').replace("\\\\", "\\")
    if value.startswith("(") and value.endswith(")"):
        return value[1:-1]
    return value


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _parse_saddr(hexstr: str) -> tuple[str, int] | None:
    """Decode an audit ``SOCKADDR saddr=...`` hex blob into (ip, port)."""
    if not hexstr:
        return None
    try:
        blob = bytes.fromhex(hexstr)
    except ValueError:
        return None
    if len(blob) < 8:
        return None
    family = int.from_bytes(blob[0:2], "little")
    port = int.from_bytes(blob[2:4], "big")
    if family == 2 and len(blob) >= 8:  # AF_INET
        ip = ".".join(str(b) for b in blob[4:8])
        return ip, port
    if family == 10 and len(blob) >= 24:  # AF_INET6
        ip = ":".join(f"{int.from_bytes(blob[i : i + 2], 'big'):x}" for i in range(8, 24, 2))
        return ip, port
    return None


class _UsernameCache:
    """Maps uid -> username lazily; degrades to the numeric uid off-Linux."""

    def __init__(self) -> None:
        self._pwd = None
        self._cache: dict[int, str] = {}
        try:
            import pwd  # noqa: PLC0415 - Linux-only stdlib

            self._pwd = pwd
        except ImportError:
            pass

    def get(self, uid: int) -> str:
        if self._pwd is None:
            return "unknown"
        if uid not in self._cache:
            try:
                self._cache[uid] = self._pwd.getpwuid(uid).pw_name
            except KeyError:
                self._cache[uid] = str(uid)
        return self._cache[uid]


_USERNAMES = _UsernameCache()


def _is_suspicious_path(path: str | None) -> bool:
    return bool(path) and path.startswith(SUSPICIOUS_DIRS)


class AuditRecordParser:
    """Stateful parser that reassembles multi-record auditd events."""

    def __init__(self) -> None:
        self._ctx: dict[str, Any] | None = None

    def feed(self, line: str) -> list[KernelEvent]:
        """Consume one audit.log line; may complete the previous event."""
        record = self._parse_record(line)
        if record is None:
            return []
        out: list[KernelEvent] = []
        if self._ctx is not None and self._ctx["serial"] != record["serial"]:
            out.extend(self._emit(self._ctx))
            self._ctx = None
        self._ctx = self._merge(self._ctx, record)
        if record["type"] == "EOE":
            out.extend(self._emit(self._ctx))
            self._ctx = None
        return out

    def flush(self) -> list[KernelEvent]:
        """Emit any partially assembled event (end of a collect batch)."""
        if self._ctx is None:
            return []
        out = self._emit(self._ctx)
        self._ctx = None
        return out

    # -- internals --------------------------------------------------------
    def _parse_record(self, line: str) -> dict[str, Any] | None:
        match = _MSG_RE.match(line)
        if not match:
            return None
        record_type = match.group(1)
        timestamp = float(match.group(2))
        serial = int(match.group(3))
        body = line[match.end():].lstrip(": ")
        kv = _pairs(body)
        return {
            "type": record_type,
            "serial": serial,
            "timestamp": timestamp,
            **kv,
        }

    def _merge(self, ctx: dict[str, Any] | None, record: dict[str, Any]) -> dict[str, Any]:
        if ctx is None:
            ctx = {
                "serial": record["serial"],
                "timestamp": record["timestamp"],
                "type": record["type"],
                "pid": 0,
                "ppid": 0,
                "uid": 0,
                "ses": None,
                "exe": None,
                "syscall": 0,
                "success": None,
                "argv": [],
                "path": None,
                "saddr": None,
                "a0": None,
                "key": None,
                "comm": None,
            }
        rtype = record["type"]
        if rtype == "SYSCALL":
            ctx.update(
                serial=record["serial"],
                timestamp=record["timestamp"],
                pid=_int(record.get("pid")),
                ppid=_int(record.get("ppid")),
                uid=_int(record.get("uid")),
                ses=record.get("ses"),
                exe=None if record.get("exe") == "(null)" else record.get("exe"),
                syscall=_int(record.get("syscall")),
                success=record.get("success"),
                a0=record.get("a0"),
                key=record.get("key"),
                comm=record.get("comm"),
            )
        elif rtype == "EXECVE":
            argc = _int(record.get("argc"))
            ctx["argv"] = [record.get(f"a{i}", "") for i in range(argc)]
        elif rtype == "PATH":
            ctx["path"] = None if record.get("name") == "(null)" else record.get("name")
        elif rtype == "SOCKADDR":
            ctx["saddr"] = record.get("saddr")
        elif rtype == "CONNECT":
            ctx["success"] = record.get("success")
        return ctx

    def _emit(self, ctx: dict[str, Any]) -> list[KernelEvent]:
        syscall = ctx.get("syscall", 0)
        if syscall in _EXEC_SYSCALLS:
            if ctx.get("success") == "no":
                return []
            return self._exec_events(ctx)
        if syscall in _CONNECT_SYSCALLS:
            if ctx.get("success") == "no":
                return []
            peer = _parse_saddr(ctx.get("saddr") or "")
            if peer is None:
                return []
            ip, port = peer
            return [
                make_event(
                    EventKind.NETWORK_CONNECT,
                    pid=ctx["pid"],
                    ppid=ctx["ppid"],
                    exe=ctx.get("exe") or ctx.get("comm") or "unknown",
                    uid=ctx["uid"],
                    username=_USERNAMES.get(ctx["uid"]),
                    details={"remote_ip": ip, "remote_port": port, "protocol": "tcp", "syscall": syscall},
                    timestamp=ctx["timestamp"],
                    session_leader=ctx.get("ses"),
                )
            ]
        if syscall in _OPEN_SYSCALLS:
            if ctx.get("success") == "no":
                return []
            path = ctx.get("path")
            if not path:
                return []
            kind = EventKind.FILE_WRITE if (_is_suspicious_path(path) or syscall == 85) else EventKind.FILE_READ
            return [
                make_event(
                    kind,
                    pid=ctx["pid"],
                    ppid=ctx["ppid"],
                    exe=ctx.get("exe") or ctx.get("comm") or "unknown",
                    uid=ctx["uid"],
                    username=_USERNAMES.get(ctx["uid"]),
                    details={"path": path, "syscall": syscall},
                    timestamp=ctx["timestamp"],
                    session_leader=ctx.get("ses"),
                )
            ]
        if syscall in _PRIV_SYSCALLS:
            if ctx.get("success") == "no":
                return []
            to_uid = _int(ctx.get("a0"), 0)
            return [
                make_event(
                    EventKind.PRIVILEGE_ESCALATION,
                    pid=ctx["pid"],
                    ppid=ctx["ppid"],
                    exe=ctx.get("exe") or ctx.get("comm") or "unknown",
                    uid=ctx["uid"],
                    username=_USERNAMES.get(ctx["uid"]),
                    details={
                        "from_uid": ctx["uid"],
                        "to_uid": to_uid,
                        "syscall": syscall,
                        "syscall_name": _SYSCALLS.get(syscall, "?"),
                    },
                    timestamp=ctx["timestamp"],
                    session_leader=ctx.get("ses"),
                )
            ]
        return []

    def _exec_events(self, ctx: dict[str, Any]) -> list[KernelEvent]:
        exe = ctx.get("exe")
        if not exe and ctx.get("path"):
            exe = ctx["path"]
        exe = exe or ctx.get("comm") or "unknown"
        cmdline = tuple(ctx.get("argv") or [])
        base = {
            "pid": ctx["pid"],
            "ppid": ctx["ppid"],
            "exe": exe,
            "cmdline": cmdline,
            "uid": ctx["uid"],
            "username": _USERNAMES.get(ctx["uid"]),
            "details": {"syscall": ctx.get("syscall"), "audit_key": ctx.get("key"), "comm": ctx.get("comm")},
            "timestamp": ctx["timestamp"],
            "session_leader": ctx.get("ses"),
        }
        return [
            make_event(EventKind.PROCESS_CREATED, **base),
            make_event(EventKind.EXEC, **base),
        ]


def normalize_kernel_record(record: dict[str, Any]) -> list[KernelEvent]:
    """Normalise a dict-shaped kernel record (Tracee JSON / eBPF sample).

    Accepted keys (both tracee-style and bpf-style): ``eventName``/``name``,
    ``processId``/``pid``, ``parentProcessId``/``ppid``, ``userId``/``uid``,
    ``returnValue``/``return_value``, plus a per-event ``args`` list or flat
    keys for path/argv/sockaddr.
    """
    name = record.get("eventName") or record.get("name") or ""
    pid = _int(record.get("processId", record.get("pid")))
    ppid = _int(record.get("parentProcessId", record.get("ppid")))
    uid = _int(record.get("userId", record.get("uid")))
    # A negative return value is an error; a non-negative one is success
    # (open/openat return a positive fd, others return 0).
    if _int(record.get("returnValue", record.get("return_value", 0)), 0) < 0:
        return []

    args = _args_map(record)
    argv = args.get("argv") or record.get("argv")
    cmdline = _argv_to_tuple(argv)
    ts = _timestamp(record)

    if name in ("execve", "execveat"):
        exe = args.get("pathname") or record.get("exe") or "unknown"
        base = {
            "pid": pid,
            "ppid": ppid,
            "exe": exe,
            "cmdline": cmdline,
            "uid": uid,
            "details": {"source": name},
            "timestamp": ts,
        }
        return [make_event(EventKind.PROCESS_CREATED, **base), make_event(EventKind.EXEC, **base)]

    # Non-exec records don't carry the process binary; the upstream sampler
    # can enrich it, but scoring never depends on it for these kinds.
    exe = record.get("exe") or "unknown"

    if name in ("connect", "tcp_v4_connect", "tcp_v6_connect"):
        peer = _sockaddr(args.get("sockaddr") or record.get("sockaddr"))
        if peer is None:
            return []
        ip, port = peer
        return [
            make_event(
                EventKind.NETWORK_CONNECT,
                pid=pid,
                ppid=ppid,
                exe=exe,
                uid=uid,
                details={"remote_ip": ip, "remote_port": port, "protocol": "tcp", "source": name},
                timestamp=ts,
            )
        ]

    if name in ("open", "openat", "creat", "security_file_open"):
        path = args.get("pathname") or record.get("path")
        if not path:
            return []
        flags = _flags(args.get("flags"))
        write = name == "creat" or flags & _O_CREAT or flags & _O_WRITE or _is_suspicious_path(path)
        kind = EventKind.FILE_WRITE if write else EventKind.FILE_READ
        return [
            make_event(
                kind,
                pid=pid,
                ppid=ppid,
                exe=exe,
                uid=uid,
                details={"path": path, "flags": flags, "source": name},
                timestamp=ts,
            )
        ]

    if name in ("setuid", "setgid", "setresuid", "setresgid", "setreuid", "setregid"):
        to_uid = _int(args.get("uid", args.get("rgid", args.get("ruid", record.get("to_uid", 0)))))
        return [
            make_event(
                EventKind.PRIVILEGE_ESCALATION,
                pid=pid,
                ppid=ppid,
                exe=exe,
                uid=uid,
                details={"from_uid": uid, "to_uid": to_uid, "syscall_name": name, "source": name},
                timestamp=ts,
            )
        ]

    return []


def _args_map(record: dict[str, Any]) -> dict[str, Any]:
    args = record.get("args")
    if not isinstance(args, list):
        return {}
    out: dict[str, Any] = {}
    for item in args:
        if isinstance(item, dict) and "name" in item:
            out[item["name"]] = item.get("value")
    return out


def _argv_to_tuple(argv: Any) -> tuple[str, ...]:
    if isinstance(argv, str):
        return tuple(argv.split())
    if isinstance(argv, (list, tuple)):
        return tuple(str(a) for a in argv)
    return ()


def _sockaddr(value: Any) -> tuple[str, int] | None:
    if not value:
        return None
    if isinstance(value, str) and value.count(":") >= 1:
        host, _, port = value.rpartition(":")
        if port.isdigit():
            return host, int(port)
    if isinstance(value, str):  # hex blob from eBPF
        return _parse_saddr(value)
    if isinstance(value, (list, tuple)) and len(value) >= 2:
        return str(value[0]), _int(value[1])
    return None


def _flags(value: Any) -> int:
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return value
    text = str(value or "")
    if not text:
        return 0
    try:
        return int(text, 10)
    except ValueError:
        pass
    try:
        return int(text, 0)
    except ValueError:
        pass
    flags = 0
    if "WRONLY" in text:
        flags |= 1
    if "RDWR" in text:
        flags |= 2
    if "CREAT" in text:
        flags |= 64
    return flags


def _timestamp(record: dict[str, Any]) -> float:
    raw = record.get("timestamp")
    if raw is None:
        return time.time()
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return time.time()
    if value > 1e15:  # nanoseconds -> seconds
        value /= 1e9
    return value
