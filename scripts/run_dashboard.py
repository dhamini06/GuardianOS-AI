"""Run the live terminal dashboard.

Usage:
    python scripts/run_dashboard.py [--scenario mixed] [--seconds 30]
                                    [--normal-runs 40] [--speed 100]

The dashboard streams scripted telemetry: it learns the normal phase live,
then shows threats as the attack phase replays.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.core.config import AppConfig
from backend.dashboard.cli import CliDashboard
from backend.pipeline import GuardianPipeline
from backend.telemetry.demo_generator import DemoGenerator


def main() -> int:
    parser = argparse.ArgumentParser(description="GuardianOS-AI live dashboard")
    parser.add_argument("--scenario", default="mixed", choices=["normal", "attack", "mixed"])
    parser.add_argument("--seconds", type=float, default=30.0, help="run duration")
    parser.add_argument("--normal-runs", type=int, default=40, help="normal sessions for baseline")
    parser.add_argument("--speed", type=float, default=100.0, help="replay speed")
    args = parser.parse_args()

    config = AppConfig.load()
    generator = DemoGenerator(args.scenario, speed=args.speed, normal_runs=args.normal_runs)
    pipeline = GuardianPipeline(config, telemetry=generator)
    dashboard = CliDashboard(pipeline, refresh_seconds=config.dashboard.refresh_seconds)
    dashboard.run(duration_seconds=args.seconds)
    return 0


if __name__ == "__main__":
    sys.exit(main())
