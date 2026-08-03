"""GuardianOS-AI security scans: SBOM generation + dependency audit.

Thin wrapper around ``cyclonedx-py`` (SBOM) and ``pip-audit`` (vulnerability
scan) so CI and developers run the same reproducible scans with one command.

Usage:
    python scripts/scan_security.py [--sbom] [--audit] [--output-dir DIR]
                                    [--no-fail]

Flags:
    --sbom        emit a CycloneDX 1.6 JSON SBOM for ``requirements.txt``
    --audit       scan the pinned requirements against the vulnerability DB
    --output-dir  where artifacts are written (default ``build/security``)
    --no-fail     always exit 0, even when vulnerabilities are found

Exit codes:
    0  all requested scans completed (vulnerabilities still print if any)
    1  a scan failed or vulnerabilities were found (unless ``--no-fail``)
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REQUIREMENTS = ROOT / "requirements.txt"
PYPROJECT = ROOT / "pyproject.toml"


def _run(cmd: list[str]) -> int:
    print(f"+ {' '.join(cmd)}", flush=True)
    proc = subprocess.run(cmd, cwd=ROOT)
    return proc.returncode


def sbom(output_dir: Path) -> int:
    out = output_dir / "sbom.json"
    cmd = [
        sys.executable,
        "-m",
        "cyclonedx_py",
        "requirements",
        str(REQUIREMENTS),
        "--pyproject",
        str(PYPROJECT),
        "--of",
        "JSON",
        "--output-reproducible",
        "-o",
        str(out),
    ]
    code = _run(cmd)
    print(f"SBOM: {'ok' if code == 0 else 'failed'} -> {out}\n")
    return code


def audit(output_dir: Path, fail: bool) -> int:
    out = output_dir / "pip-audit.json"
    cmd = [
        sys.executable,
        "-m",
        "pip_audit",
        "-r",
        str(REQUIREMENTS),
        "--format",
        "json",
        "-o",
        str(out),
    ]
    code = _run(cmd)
    print(f"Audit: exit={code} -> {out}")
    if code != 0 and not fail:
        print("NOTE: vulnerabilities found; continuing because --no-fail is set.\n")
        return 0
    return code


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sbom", action="store_true", help="generate an SBOM")
    parser.add_argument("--audit", action="store_true", help="run a dependency audit")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=ROOT / "build" / "security",
        help="artifact output directory (default: build/security)",
    )
    parser.add_argument(
        "--no-fail",
        action="store_true",
        help="report results without failing on vulnerabilities",
    )
    args = parser.parse_args()

    if not args.sbom and not args.audit:
        args.sbom = True
        args.audit = True

    output_dir = args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    codes = []
    if args.sbom:
        codes.append(sbom(output_dir))
    if args.audit:
        codes.append(audit(output_dir, fail=not args.no_fail))
    return 1 if any(codes) else 0


if __name__ == "__main__":
    raise SystemExit(main())
