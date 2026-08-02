# GuardianOS-AI Milestones

Milestones are ordered so that every step is a working, verifiable system.
Each milestone ends with tests passing (`pytest`) and a runnable demo.

## Milestone 0 - Foundation (DONE)

- Project scaffold, package layout, `pyproject.toml`, `requirements.txt`,
  `config/defaults.yaml`, `.gitignore`, LICENSE, README.
- Dependency-free core contracts: `KernelEvent`, analysis models, config,
  structured logging.
- Verifiable: `pytest` collects and passes core model tests.

## Milestone 1 - MVP vertical slice (DONE)

One complete working chain:

```
Kernel Event -> Behaviour Features -> Anomaly Detection -> Explanation
             -> Response Recommendation -> Threat Report -> Dashboard
```

- `ProcessMonitor` (psutil) and deterministic `DemoGenerator` telemetry.
- `FeatureExtractor` producing 13 per-chain behavioural features.
- `IsolationForestDetector` with hybrid hard-signal scoring.
- `RuleBasedExplainer` (reasons + behaviour chain + MITRE mapping).
- `DecisionEngine` / `ApprovalGate` / `ActionExecutor` (dry-run).
- `GuardianPipeline` composition root + `CliDashboard`.
- Demo: `python scripts/run_mvp.py` learns 40 normal sessions, detects the
  scripted attack chain as one critical threat.
- 44 tests green.

## Milestone 2 - Baseline persistence and lifecycle (DONE)

- Persist/load trained detector (`detector.save/load`) and auto-load on boot.
  Models carry a `FEATURE_SCHEMA_VERSION`; mismatched schemas are rejected on
  load so stale models can never be silently mis-used.
- Online learning: the detector is periodically refit from a sliding window of
  normal windows (capped by `baseline_max_samples`); non-flagged chains fold
  into the baseline during detection, and a refit every
  `refit_interval_windows` invalidates the per-chain score cache.
- Analysts feedback loop: `label_chain(report, benign|malicious)` records
  verdicts in a persistent JSONL ledger and reweights the baseline -
  `benign` folds the chain back into normality, `malicious` excludes it. The
  detector is refit immediately after a verdict so the model converges on
  analyst ground truth.

## Milestone 3 - Kernel-level telemetry (Linux) (DONE)

- `auditd` provider (`AuditdProvider`): tails `audit.log`, reassembles
  multi-record events (`SYSCALL` + `EXECVE`/`PATH`/`SOCKADDR`) into
  `KernelEvent`s, decodes `SOCKADDR` hex to IP:port.
- eBPF provider (`BPFProvider`): BCC kprobes for `execve`,
  `tcp_v4_connect`, `setuid` streaming into a perf buffer (experimental).
- Tracee provider (`TraceeProvider`): consumes `tracee-ebpf --json` output.
- All three share `normalize_kernel_record` for dict-shaped records and
  low-overhead primitives: bounded-ring aggregation, drop accounting, and
  token-bucket rate limits (`backend/telemetry/ring.py`).
- Provider registry: `create_provider(config)` maps `telemetry.provider`;
  kernel sources raise a clear error off-Linux.

## Milestone 4 - Deeper explainability

- SHAP-style feature attribution for the Isolation Forest.
- Execution-chain visualisation (DAG) in the dashboard.
- Expanded MITRE mapping with confidence per technique.
- Optional LLM narrative generation (offline/local models) for analyst prose.

## Milestone 5 - Production-grade response

- Playbook engine: configurable responses per severity/technique.
- Containment (cgroup/network namespaces, `nftables` sets) with rollback.
- Full audit trail of every approved action; signed approvals.
- On-host persistence of events and reports (SQLite/Postgres schema).

## Milestone 6 - Web dashboard and API

- FastAPI service exposing events, threats, reports, actions over REST + WS.
- Web dashboard (live view, timeline, chain graph, approval buttons).
- RBAC and multi-tenant deployment.

## Milestone 7 - Hardening, packaging, CI/CD

- SBOM, vulnerability scanning, `pip-audit`, ruff + mypy gates.
- Packaging: wheel, `.deb`/`.rpm`, systemd unit, SELinux/AppArmor profile.
- GitHub Actions CI (test matrix on Linux + containerised integration).
- Performance and load benchmarks for the telemetry layer.

---

### Guiding rules

- "After every milestone verify the project still runs." - each milestone is
  gated by `pytest` and a runnable demo.
- Keep commits modular: one milestone (or one logical slice of it) per commit.
- Don't build Milestone N+2 before N is proven end-to-end.
