"""Run the GuardianOS-AI web dashboard and API.

By default a demo telemetry source (DemoGenerator) learns a normal baseline
from scripted sessions, then replays the attack chain live. Pass ``--provider``
to collect and analyse *real* logs instead:

* ``auditd``   - tail /var/log/audit/audit.log (needs auditd + rules; root to read)
* ``bpf``      - BCC eBPF probes (needs bcc, root; depends on kernel headers)
* ``tracee``   - Tracee eBPF subprocess (needs tracee-ebpf)
* ``process_monitor`` - cross-platform psutil process events (no kernel access)

Live providers run in two phases: the pipeline learns a behavioural baseline
for ``--baseline-windows`` ticks (default 10, i.e. ~20s at the default 2s
polling interval; ``telemetry.window_seconds``), then continuously scores
rolling windows and streams detections to the dashboard.

Usage:
    python scripts/run_server.py [--normal-runs 40] [--learn-speed 1000]
                                 [--replay-speed 1] [--host 127.0.0.1]
                                 [--port 8000] [--auth]
    python scripts/run_server.py --provider auditd --host 0.0.0.0 --auth
                                 [--baseline-windows 30]

Open http://127.0.0.1:8000/ for the dashboard (REST API under /api, docs at
/docs). With --auth, use the tokens from config/auth (or GUARDIAN_TOKEN_<NAME>
env vars): admin / analyst / viewer.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.api.server import create_app
from backend.core.config import AppConfig
from backend.core.logging import get_logger
from backend.pipeline import GuardianPipeline
from backend.telemetry.demo_generator import DemoGenerator

logger = get_logger("run_server")

PROVIDERS = ("demo_generator", "process_monitor", "auditd", "bpf", "tracee")


def make_demo_tick(
    generator: DemoGenerator,
    normal_runs: int,
    learn_speed: float,
    replay_speed: float,
) -> Callable:
    """Driver tick: drain normal sessions into the baseline, then replay
    the attack chain and score windows until it is exhausted."""
    phase = {"name": "learn"}

    def tick(pipeline: GuardianPipeline) -> list[dict]:
        if phase["name"] == "learn":
            if not generator.exhausted:
                pipeline.ingest_tick()
                return []
            pipeline.complete_learning()
            logger.info("Baseline built from %d normal sessions", normal_runs)
            phase["name"] = "replay"
            generator.reset("attack")
            generator.speed = replay_speed
            return []
        if not generator.exhausted:
            return [report.to_dict() for report in pipeline.analyze_window()]
        return []

    return tick


def main() -> int:
    parser = argparse.ArgumentParser(description="GuardianOS-AI web dashboard demo")
    parser.add_argument("--normal-runs", type=int, default=40, help="normal sessions for the baseline")
    parser.add_argument("--learn-speed", type=float, default=1000.0, help="baseline replay speed")
    parser.add_argument("--replay-speed", type=float, default=1.0, help="attack replay speed (live pacing)")
    parser.add_argument("--provider", choices=PROVIDERS, default="demo_generator",
                        help="telemetry source; use a live provider (auditd/bpf/tracee/"
                        "process_monitor) to collect and analyse real logs")
    parser.add_argument("--baseline-windows", type=int, default=10,
                        help="live providers: learning ticks before detection starts "
                        "(default 10; ~20s at the 2s polling interval)")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--auth", action="store_true", help="enable token-based RBAC")
    args = parser.parse_args()

    config = AppConfig.load(
        overrides={
            "server.host": args.host,
            "server.port": args.port,
            "auth.enabled": args.auth,
            "telemetry.provider": args.provider,
            "detection.min_learning_windows": args.baseline_windows,
        }
    )

    if args.provider == "demo_generator":
        generator = DemoGenerator("normal", speed=args.learn_speed, normal_runs=args.normal_runs)
        pipeline = GuardianPipeline(config, telemetry=generator)
        tick = make_demo_tick(generator, args.normal_runs, args.learn_speed, args.replay_speed)
        app = create_app(pipeline, config, tick=tick)
        print(f"\nGuardianOS-AI demo: learning {args.normal_runs} normal sessions, "
              f"then replaying the attack chain live\n")
    else:
        # Live mode: GuardianPipeline(config) picks the provider from
        # telemetry.provider via create_provider(). The default driver tick
        # learns for --baseline-windows ticks, then scores windows live.
        pipeline = GuardianPipeline(config)
        app = create_app(pipeline, config)
        print(f"\nGuardianOS-AI live mode: provider={args.provider!r}\n"
              f"  learning baseline for {args.baseline_windows} ticks "
              f"(window={config.telemetry.window_seconds}s), then detecting\n"
              f"  system logs: {config.telemetry.audit_log_path if args.provider == 'auditd' else 'n/a'}\n")

    print(f"GuardianOS-AI web dashboard: http://{args.host}:{args.port}/")
    print(f"API docs: http://{args.host}:{args.port}/docs")
    if args.auth:
        print("RBAC enabled - demo tokens: change-me-admin / change-me-analyst / change-me-viewer\n")
    else:
        print("RBAC disabled (open access). Restart with --auth for token-based roles.\n")

    import uvicorn

    uvicorn.run(app, host=args.host, port=args.port, log_level="info")
    return 0


if __name__ == "__main__":
    sys.exit(main())
