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

- **Behavioural, not signature-based** — learns patterns (process chains, tool
  use, network behaviour), never exact keystrokes or command history.
- **Kernel-aware telemetry** — pluggable providers: auditd, eBPF (BCC),
  Tracee, psutil process monitor, and a scripted demo generator.
- **Unsupervised ML detection** — Isolation Forest builds a per-machine
  baseline of normal behaviour with no attack labels required.
- **Hybrid detection** — ML baseline deviation is blended with hard behavioural
  signals (exec from `/tmp`, high-port egress, privilege escalation,
  interpreter chains) so classic kill chains are never missed.
- **Explainable by design** — every threat ships with human-readable reasons,
  the reconstructed behaviour chain, and MITRE ATT&CK mappings.
- **Safe response** — remediation is recommended first and destructive actions
  always require human approval. `dry_run` defaults to `true`.
- **SOC-style live dashboard** — React 19 + Tailwind + ApexCharts SPA with
  real-time events, threats, severity, AI explanations, MITRE mapping, response
  actions and system health.
- **Production-ready** — systemd service, Docker support, CI/CD (GitHub
  Actions), audit trail with HMAC signing, RBAC auth.

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
- Node.js 18+ (for frontend development only)

### Install

```bash
python -m venv .venv
source .venv/bin/activate        # Linux/macOS
# .\.venv\Scripts\activate       # Windows

pip install -e ".[dev]"
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

### Analyse real logs (live providers)

By default the server demo replays scripted telemetry. To collect and analyse
**real system logs**, point it at a live provider (Linux):

```bash
# auditd (recommended): tail /var/log/audit/audit.log
sudo apt install -y auditd
sudo systemctl start auditd
sudo auditctl -a always,exit -F arch=b64 -S execve,openat,connect,setuid
sudo python scripts/run_server.py --provider auditd --host 0.0.0.0 --auth

# eBPF via BCC (kernel-headers dependent) or Tracee:
sudo python scripts/run_server.py --provider bpf --host 0.0.0.0
sudo python scripts/run_server.py --provider tracee --host 0.0.0.0
```

Live providers learn a behavioural baseline for `--baseline-windows` ticks
(default 10, ~20s at the 2s polling interval), then continuously score rolling
windows of real activity.

```bash
# Validate a provider before running the server:
python scripts/self_test_kernel.py --provider auditd --ensure-rules --duration 10
```

### Authentication

Enable token-based RBAC with `--auth`:

```bash
# Tokens are read from config or overridden via env vars:
export GUARDIAN_TOKEN_ADMIN=your-secret-admin-token
export GUARDIAN_TOKEN_ANALYST=your-secret-analyst-token
export GUARDIAN_TOKEN_VIEWER=your-secret-viewer-token
python scripts/run_server.py --auth
```

Roles: `viewer` (read) < `analyst` (label threats) < `admin` (approve/reject/rollback).

### Run the tests

```bash
pip install -e ".[dev]"        # pytest + ruff + httpx
pytest                         # 196 tests across every layer
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

### Production configuration

Before deploying, override these defaults:

```yaml
# backend/config/defaults.yaml overrides
auth:
  enabled: true                  # disable open access

response:
  dry_run: false                 # enable real containment actions
  signing_secret: <hmac-secret>  # sign the audit trail

# Or use env vars:
export GUARDIAN_TOKEN_ADMIN=<random>
export GUARDIAN_SIGNING_SECRET=<random>
```

## Repository layout

```
.
├── backend/
│   ├── config/          # Bundled YAML defaults + playbook rules (package data)
│   ├── core/            # Domain models, events, config, logging (no deps)
│   ├── telemetry/       # Layer 1 - kernel event collection (auditd, bpf, tracee, demo)
│   ├── features/        # Layer 2 - behavioural feature engineering
│   ├── detection/       # Layer 3 - Isolation Forest + hybrid scoring
│   ├── explainability/  # Layer 4 - reasons, chain, MITRE, optional LLM narrative
│   ├── response/        # Layer 5 - decision engine, approval gate, executor, rollback
│   ├── feedback/        # Analyst feedback ledger (false positive / true positive)
│   ├── storage/         # SQLite persistence for events and reports
│   ├── api/             # Layer 6 - FastAPI REST + WebSocket + RBAC + driver
│   └── dashboard/       # Web dashboard static assets + CLI dashboard
├── frontend/            # React 19 + Vite 6 + Tailwind 4 + ApexCharts SPA
├── packaging/           # systemd unit, AppArmor profile, rpm/deb metadata
├── .github/workflows/   # CI: lint, types, test matrix, security, wheel
├── docs/                # Architecture, interfaces, milestones
├── scripts/             # Demo runners, server, security scans, benchmarks
├── tests/               # 196 tests across every layer (+ opt-in benchmarks)
├── pyproject.toml       # Packaging + tooling config (ruff/mypy/pip-audit)
├── requirements.txt
├── Dockerfile
└── docker-compose.yml
```

## Security notes

- **Audit trail** — every approve/reject/execute/rollback is recorded in an
  append-only, hash-chained JSONL file with optional HMAC-SHA256 signatures.
- **RBAC** — viewer/analyst/admin roles enforced on every endpoint. Auth
  disabled by default for local development.
- **Response safety** — `dry_run` defaults to `true`. Destructive actions
  (`kill_process`, `block_ip`) require admin approval. Rollback is supported
  for freeze, block and quarantine actions.
- **Bounded memory** — event buffer (100k), report history (1000), change log
  (1000) all capped to prevent unbounded growth.
- GuardianOS-AI is a defensive monitoring tool. Use only on systems you are
  authorised to monitor.

## License

Apache-2.0. See [LICENSE](LICENSE).
