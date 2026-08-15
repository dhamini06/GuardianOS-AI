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

## Milestone 5 - Production-grade response (DONE)

- Playbook engine: declarative YAML rules (`config/playbooks.yaml`) keyed by
  severity and/or MITRE technique expand into concrete remediation actions
  (kill, freeze, block IP, quarantine) with targets derived from the chain.
  `DecisionEngine` is driven entirely by the playbook (built-in default rules
  preserve the pre-M5 severity behaviour when no file is configured), and
  actions are de-duplicated across rules.
- Containment with rollback: `ContainmentManager` performs the platform effect
  and records a reversible handle - `nftables` set add/delete for IP blocking,
  SIGSTOP/CONT for freezing, move-to-quarantine for files. Killing is
  deliberately non-reversible. `rollback(report_id)` undoes everything applied
  for a report, so a response can be reversed after the fact.
- Signed, append-only audit trail: every approval, execution and rollback is
  written to a hash-chained JSONL file. Each record carries an HMAC-SHA256
  signature (when `response.signing_secret` / `GUARDIAN_SIGNING_SECRET` is
  set) plus the digest of the previous record, so tampering with any record
  breaks the chain and fails `verify_all()`.
- On-host SQLite persistence: `SqliteStorage` writes every ingested event and
  every threat report to `data/guardian.db` (sliding cap on events); the
  pipeline and dashboard read/write it as the durable record.
- Detection performance fix: SHAP-style attribution is now computed lazily for
  flagged chains only, so normal windows score in milliseconds instead of
  tens of seconds (semantics unchanged - attribution is explainability for
  alerts).

## Milestone 6 - Web dashboard and API (DONE)

- FastAPI service (`backend/api/server.py::create_app`) exposing events,
  threats, reports and response actions over REST (`/api/health`, `/api/events`,
  `/api/threats`, approve/reject/rollback/label) plus a WebSocket live stream
  (`/api/ws`) that pushes threat reports and health snapshots as they happen.
- Web dashboard (no-build vanilla HTML/CSS/JS served by the API): live threat
  timeline, AI explanation with behaviour-chain DAG, approval/reject/rollback
  buttons and analyst labelling, and a recent-events table - all updating in
  real time over the WebSocket.
- Pipeline driver: a background thread (`backend/api/driver.py`) advances the
  pipeline loop and streams changes through a thread-safe `ChangeLog`; a
  customisable `tick` supports deterministic demo scenarios.
- RBAC: token-based roles (`viewer < analyst < admin`) from `config/auth`
  (`GUARDIAN_TOKEN_<NAME>` env overrides); read endpoints are viewer+,
  analyst feedback analyst+, and destructive remediation (approve / reject /
  rollback) admin-only. `auth.enabled: false` grants open local access.
- Demo: `python scripts/run_server.py` learns a normal baseline from scripted
  telemetry, then replays the attack chain live against the dashboard.

## Milestone 7 - Hardening, packaging, CI/CD (DONE)

- Quality gates: `ruff` + `mypy` (strict-ish: `check_untyped_defs`,
  `warn_unused_ignores`, `warn_redundant_casts`, `no_implicit_optional`) are
  configured in `pyproject.toml`; `mypy backend scripts` is clean (55+ source
  files), which included annotating every module touched and correcting real
  latent issues (None-typed handles, `**dict[str, Any]` keyword splats,
  `object`-typed pipeline results, `callable` vs `Callable`).
- Dependency security: `scripts/scan_security.py` emits a reproducible
  CycloneDX JSON SBOM (`cyclonedx-py`) and audits pinned requirements against
  the vulnerability database (`pip-audit`); local run reports no known
  vulnerabilities. Runs identically in CI.
- Packaging: `backend/config/` now ships the YAML defaults + playbook inside
  the wheel (`[tool.setuptools.package-data]`), dashboard static assets are
  bundled, and console entry points (`guardian-server`,
  `guardian-security-scan`) are registered. Verified end-to-end: the wheel
  builds, installs into a clean venv, and resolves config/playbooks from the
  installed package. Deployment artifacts live in `packaging/`: systemd unit
  (`guardian-os.service`), AppArmor profile (`guardian-os.apparmor`),
  `Dockerfile`, RPM spec and Debian control metadata.
- GitHub Actions CI (`.github/workflows/ci.yml`): lint+types, a pytest matrix
  on Python 3.11/3.12, the security scan (SBOM + vuln audit) with artifact
  upload, and a wheel build job. (Note: the workflow lives under
  `GuardianOS-AI/.github/workflows/`; if the sub-project is tracked inside a
  parent repository, copy it to the parent root so GitHub Actions picks it up.)
- Performance benchmarks: `scripts/benchmark_telemetry.py` measures the
  telemetry hot paths - ring push+drain (~2M events/s), thread-safe buffer
  transfer (~10M events/s), bounded `_deliver` (~2M events/s) and cold/steady
  `analyze_window` latency (first window ~0.16 s with lazy attribution). The
  same floors are enforced by opt-in tests (`GUARDIAN_BENCHMARK=1 pytest
  tests/test_benchmark.py`), skipped in the default suite.
- Full suite: 173 tests pass; 4 opt-in benchmark tests.

## Milestone 8 - Real kernel telemetry test (DONE)

- Provider hardening for real-world conditions. `AuditLogSource` now survives
  `logrotate`: it detects rename-rotation (new inode -> re-open and seek to
  end) and copytruncate (file shrinks under the cursor -> rewind), counting
  each as `rotations`/`truncations`. `SubprocessLineSource` (Tracee) gained a
  bounded stdout queue with drop accounting, stderr tail capture for
  diagnostics, and automatic restart with exponential backoff (capped at 60 s)
  so a crashed child can never wedge the pipeline.
- Fault containment: providers (`auditd`, `tracee`, `bpf`) wrap collect-time
  faults in `TelemetryError`, record the last error, and the pipeline
  `_ingest` treats a dead source as a degraded-but-running condition instead
  of a crash. New config knobs `subprocess_queue_capacity`,
  `subprocess_auto_restart` and `subprocess_restart_backoff_seconds` tune the
  subprocess source.
- Real-world audit parsing: `_open_flags` decodes `open`/`openat` register
  args so `O_CREAT|O_WRONLY` classifies file *writes* correctly (not just
  suspicious paths); `_path_name` picks informative `nametype` records
  (NORMAL/CREATE/DELETE/PARENT) over UNKNOWN; `_execve_args` truncates argv
  to the recorded `argc` and skips `(null)`/missing entries.
- Operational health: `ProviderHealth.status()` reports running state,
  events delivered, ring drops, rate-limited events, restarts and last error
  per provider; surfaced on `/api/health` as `telemetry` via
  `pipeline.telemetry_status()`.
- Tests for all of the above: rotation (rename + copytruncate), auto-restart,
  bounded queue, stderr capture, open-flag write detection, PATH nametype
  filtering, execve argv truncation, a realistic multi-record audit log replayed
  end-to-end through `AuditdProvider`, and status tracking for the ring mixin,
  `DemoGenerator` and `ProcessMonitor`.
- Live validation: `scripts/self_test_kernel.py` starts each requested kernel
  provider, generates real activity (exec, file write, connect, setuid) while
  collecting, and passes only if the provider delivered events with a healthy
  `status()`; `--ensure-rules` installs/removes the auditd ruleset via
  `auditctl`. Wired into CI as an informational
  `kernel-self-test` job (ubuntu-latest, `continue-on-error: true`) so flaky
  runner kernels (BPF symbols/headers) can never block a PR.
- Full suite: 188 tests pass on Linux; 4 opt-in benchmarks + 2 rotation tests
  (logrotate is Linux-only) skipped on other platforms.

---

### Guiding rules

- "After every milestone verify the project still runs." - each milestone is
  gated by `pytest` and a runnable demo.
- Keep commits modular: one milestone (or one logical slice of it) per commit.
- Don't build Milestone N+2 before N is proven end-to-end.
