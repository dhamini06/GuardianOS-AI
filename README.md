# GuardianOS-AI

**AI-powered, explainable Linux security assistant for kernel-level intrusion
and behavioural threat detection.**

GuardianOS-AI is not an antivirus. It is not a signature-based IDS. It is not a
log viewer. It is an AI security analyst that runs on Linux, learns what normal
behaviour *looks like for your specific machine*, detects when behaviour stops
making sense, explains *why*, and recommends safe remediation.

Instead of asking *"does this match a known attack?"*, GuardianOS-AI asks
*"does this behaviour make sense for this machine?"*

---

## Highlights

- **Behavioural, not signature-based** - learns patterns (process chains, tool
  use, network behaviour), never exact keystrokes or command history.
- **Kernel-aware telemetry** - pluggable providers (psutil MVP, with eBPF /
  auditd / Tracee on the roadmap) that normalise into one event model.
- **Unsupervised ML detection** - Isolation Forest builds a per-machine
  baseline of normal behaviour with no attack labels required.
- **Hybrid detection** - ML baseline deviation is blended with hard behavioural
  signals (exec from `/tmp`, high-port egress, privilege escalation,
  interpreter chains) so classic kill chains are never missed.
- **Explainable by design** - every threat ships with human-readable reasons,
  the reconstructed behaviour chain, and MITRE ATT&CK mappings.
- **Safe response** - remediation is recommended first and destructive actions
  always require human approval. The MVP runs in `dry_run` mode by default.
- **Live dashboard** - real-time view of events, threats, severity, AI
  explanations, MITRE mapping, response actions and system health.

## Architecture at a glance

```
Kernel Telemetry ─► Behavioural Features ─► AI Detection ─► Explainability
      (Layer 1)          (Layer 2)            (Layer 3)         (Layer 4)
                                                                   │
Live Dashboard ◄──────── Decision & Response ◄────────────────────┘
   (Layer 6)                    (Layer 5)
```

Full design: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
Interfaces between modules: [docs/INTERFACES.md](docs/INTERFACES.md).
Roadmap: [docs/MILESTONES.md](docs/MILESTONES.md).

## Quick start

### Requirements

- Python 3.11+

### Install

```bash
python -m venv .venv
source .venv/bin/activate        # Linux/macOS
# .\.venv\Scripts\activate       # Windows

pip install -r requirements.txt
```

### Run the MVP demo

The demo teaches the model a varied set of normal sessions, then replays a
realistic attack chain (`python -> bash -> curl download -> chmod +x ->
run /tmp payload -> reverse shell`):

```bash
python scripts/run_mvp.py
```

Expected outcome: normal activity is not flagged; the attack chain is detected
as a single **critical** threat with an explanation, MITRE mappings
(T1059.006, T1105, T1204.002, T1059.004, T1548.003) and pending-approval
response actions.

### Run the live terminal dashboard

```bash
python scripts/run_dashboard.py --scenario mixed
```

### Run the web dashboard

```bash
python scripts/run_server.py          # serves the SPA + API at http://localhost:8000
```

The React frontend lives in `frontend/`; production builds are committed to
`backend/dashboard/web/` and served by the API. For frontend development:

```bash
cd frontend
npm install
npm run dev                          # Vite dev server, proxies /api to :8000
npm run build                        # tsc + Vite -> ../backend/dashboard/web
```

### Run the tests

```bash
pip install -e ".[dev]"        # pytest + ruff + httpx
pytest
```

## Quality gates

```bash
pip install -e ".[dev-full]"   # adds mypy, pip-audit, cyclonedx-bom, build

ruff check backend tests scripts
mypy                           # static typing, clean across backend/
python scripts/scan_security.py   # CycloneDX SBOM + pip-audit vulnerability scan
GUARDIAN_BENCHMARK=1 pytest tests/test_benchmark.py   # opt-in perf floors
```

## Packaging & deployment

The wheel is self-contained: YAML defaults and playbook rules
(`backend/config/`) and the dashboard static assets ship as package data, and
console entry points are registered (`guardian-server`, `guardian-security-scan`).

```bash
python -m build --wheel --outdir dist
pip install dist/guardianos_ai-0.1.0-py3-none-any.whl
guardian-server --host 0.0.0.0 --auth
```

Deployment artifacts live in `packaging/`: a systemd unit
(`guardian-os.service`), an AppArmor confinement profile
(`guardian-os.apparmor`), a `Dockerfile`, an RPM spec and Debian control
metadata. CI (GitHub Actions) runs lint/type gates, a pytest matrix on Python
3.11/3.12, the security scan and a wheel build.

## Repository layout

```
.
├── backend/
│   ├── config/          # Bundled YAML defaults + playbook rules (package data)
│   ├── core/            # Domain models, events, config, logging (no deps)
│   ├── telemetry/       # Layer 1 - kernel event collection (psutil MVP, demo)
│   ├── features/        # Layer 2 - behavioural feature engineering
│   ├── detection/       # Layer 3 - Isolation Forest + hybrid scoring
│   ├── explainability/  # Layer 4 - reasons, chain, MITRE, narrative
│   ├── response/        # Layer 5 - decision engine, approval gate, executor
│   ├── storage/         # SQLite persistence for events and reports
│   ├── api/             # Layer 6 - FastAPI REST + WebSocket + driver
│   └── dashboard/       # Web dashboard static assets + CLI dashboard
├── packaging/           # systemd unit, AppArmor profile, rpm/deb metadata
├── .github/workflows/   # CI: lint, types, test matrix, security, wheel
├── docs/                # Architecture, interfaces, milestones
├── scripts/             # Demo runners, server, security scans, benchmarks
├── tests/               # 173 tests across every layer (+ opt-in benchmarks)
├── pyproject.toml       # Packaging + tooling config (ruff/mypy/pip-audit)
├── requirements.txt
├── Dockerfile
└── docker-compose.yml
```

## Project philosophy

- **Modules are independent.** Each layer talks to the next through small,
  explicit contracts (Protocols in `backend/core`).
- **One complete vertical slice first.** The MVP implements the full chain
  from kernel event to dashboard before any advanced capability is added.
- **Deterministic and testable.** A scripted demo telemetry source makes the
  whole pipeline reproducible in CI.
- **Safe by construction.** Response actions never run without approval and the
  MVP is dry-run by default.

## Security notes

- The MVP telemetry uses `psutil` polling and works identically on developer
  machines and the Linux target. Kernel-level collection (eBPF / auditd /
  Tracee) lands behind the same provider interface (see milestones).
- Automated remediation is *opt-in*. All destructive actions
  (`kill_process`, `block_ip`, ...) are gated behind human approval and
  `dry_run` defaults to `true`.
- GuardianOS-AI is a defensive monitoring tool. Use only on systems you are
  authorised to monitor.

## License

Apache-2.0. See [LICENSE](LICENSE).
