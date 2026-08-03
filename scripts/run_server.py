"""Run the GuardianOS-AI web dashboard and API demo.

Learns a normal baseline from scripted telemetry, then replays the attack
chain live while a FastAPI app (REST + WebSocket) serves the web dashboard.

Usage:
    python scripts/run_server.py [--normal-runs 40] [--learn-speed 1000]
                                 [--replay-speed 1] [--host 127.0.0.1]
                                 [--port 8000] [--auth]

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
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--auth", action="store_true", help="enable token-based RBAC")
    args = parser.parse_args()

    config = AppConfig.load(
        overrides={
            "server.host": args.host,
            "server.port": args.port,
            "auth.enabled": args.auth,
        }
    )
    generator = DemoGenerator("normal", speed=args.learn_speed, normal_runs=args.normal_runs)
    pipeline = GuardianPipeline(config, telemetry=generator)
    tick = make_demo_tick(generator, args.normal_runs, args.learn_speed, args.replay_speed)
    app = create_app(pipeline, config, tick=tick)

    print(f"\nGuardianOS-AI web dashboard: http://{args.host}:{args.port}/")
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
