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

## Milestone 4 - Deeper explainability (DONE)

- SHAP-style feature attribution for the Isolation Forest: the detector keeps a
  bounded reservoir of baseline rows (persisted with the model) and attributes
  each feature with the Strumbej-Kononenko sampling estimator - the average
  marginal contribution of swapping that feature against baseline samples,
  measured in both directions. Deterministic and cheaper than full Shapley
  values; models trained before M4 fall back to a single median probe.
- Execution-chain DAG: `build_dag` turns a chain into a graph (process
  vertices, `spawn` edges for lineage, `attach` edges for connections/writes/
  escalations) rendered as an ASCII process tree in the CLI dashboard and
  serialised in `ThreatReport.to_dict()`.
- Expanded MITRE mapping with per-technique confidence (`MitreReference.
  confidence`): confidence grows with the strength of the evidence, and new
  persistence techniques were added (`T1053.003` Cron, `T1543.002` Systemd
  service) mapped from file writes into those paths.
- Optional LLM narrative generation: `LlmNarrativeGenerator` talks to a local
  Ollama-compatible endpoint (`/api/generate`); failures degrade to the
  rule-based summary. Enabled via `explainability.narrative_provider: llm`.

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
