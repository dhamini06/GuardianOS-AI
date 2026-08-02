"""GuardianOS-AI MVP demo runner.

Demonstrates the full vertical slice using deterministic scripted telemetry:

  1. LEARNING   - feed N normal sessions, fit the Isolation Forest baseline.
  2. DETECTION  - replay the attack chain, detect, explain, recommend responses.

Usage:
    python scripts/run_mvp.py [--speed 100] [--normal-runs 8] [--verbose]

The ``mixed`` scenario (--scenario mixed) plays a normal session interrupted
by the attack chain in one stream.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.core.config import AppConfig
from backend.core.logging import get_logger
from backend.pipeline import GuardianPipeline
from backend.telemetry.demo_generator import DemoGenerator

logger = get_logger("demo")


def drain(generator: DemoGenerator, *, pause: float = 0.002) -> list:
    """Pull every event from the generator as fast as its clock allows."""
    events = []
    while not generator.exhausted:
        events.extend(generator.collect())
        if generator.remaining:
            time.sleep(pause)
    return events


def learn_phase(pipeline: GuardianPipeline, generator: DemoGenerator, runs: int) -> int:
    print("\n[1/2] LEARNING - teaching the model what is NORMAL...\n")
    generator.reset("normal")
    generator.speed = 100.0
    generator.normal_runs = runs
    samples = 0
    while not generator.exhausted:
        samples += pipeline.ingest_tick()
        time.sleep(0.002)
    pipeline.complete_learning()
    print(f"      Baseline built from {runs} normal sessions "
          f"({len(pipeline._baseline)} feature vectors).")
    return samples


def detect_phase(pipeline: GuardianPipeline, generator: DemoGenerator) -> int:
    print("\n[2/2] DETECTION - replaying an ATTACK chain...\n")
    generator.reset("attack")
    generator.speed = 100.0
    threats = 0
    while not generator.exhausted:
        new = pipeline.analyze_window()
        threats += len(new)
        time.sleep(0.002)
    return threats


def main() -> int:
    parser = argparse.ArgumentParser(description="GuardianOS-AI MVP demo")
    parser.add_argument("--speed", type=float, default=100.0, help="replay speed")
    parser.add_argument("--normal-runs", type=int, default=40, help="normal sessions for baseline")
    parser.add_argument("--scenario", default="two_phase", choices=["two_phase", "mixed"])
    args = parser.parse_args()

    config = AppConfig.load()

    if args.scenario == "mixed":
        generator = DemoGenerator("mixed", speed=args.speed, normal_runs=args.normal_runs)
    else:
        generator = DemoGenerator("normal", speed=args.speed, normal_runs=args.normal_runs)

    pipeline = GuardianPipeline(config, telemetry=generator)
    pipeline.start()

    if args.scenario == "two_phase":
        learn_phase(pipeline, generator, args.normal_runs)
        generator.speed = args.speed
        threats = detect_phase(pipeline, generator)
    else:
        # Mixed: normal sessions first, then the attack interrupts.
        generator.speed = args.speed
        threats = 0
        while not generator.exhausted:
            if pipeline.learning:
                pipeline.ingest_tick()
                if generator.elapsed_seconds >= (generator.normal_phase_ends or float("inf")):
                    pipeline.complete_learning()
                    print(f"      Baseline built from {args.normal_runs} normal "
                          f"sessions ({len(pipeline._baseline)} feature vectors).")
            else:
                threats += len(pipeline.analyze_window())
            time.sleep(0.002)

    pipeline.stop()
    print_summary(pipeline)
    return 0 if threats > 0 else 1


def print_summary(pipeline: GuardianPipeline) -> None:
    print("\n" + "=" * 78)
    print(f"THREAT REPORT SUMMARY  ({len(pipeline.reports)} threat(s) detected)")
    print("=" * 78)
    for report in pipeline.reports:
        d = report.detection
        ex = report.explanation
        print(f"\n[THREAT] {d.exe} (pid {d.pid})  severity={d.severity.value}  "
              f"score={d.anomaly_score:.2f}  confidence={ex.confidence:.0%}")
        print(f"  {ex.summary}")
        for reason in ex.reasons:
            print(f"    - {reason}")
        for mitre in ex.mitre:
            print(f"    MITRE {mitre.technique_id} {mitre.name}  {mitre.url}")
        for action in report.actions:
            print(f"    ACTION {action.action_type}: {action.description} [{action.status.value}]")


if __name__ == "__main__":
    sys.exit(main())
