# GuardianOS-AI Architecture

This document describes the layered architecture of GuardianOS-AI, the
data flow of the MVP, and how each layer will evolve.

## 1. Design principles

1. **Clean architecture, decoupled layers.** Every layer depends only on the
   small, dependency-free contracts in `backend/core`. Replacing a telemetry
   source or the ML model must not ripple through the codebase.
2. **Pull-based, windowed processing.** The pipeline repeatedly asks the
   telemetry provider for new events, aggregates them into time windows, and
   scores the resulting behavioural units (process chains).
3. **Everything explainable.** No layer may emit a bare "threat detected".
   Scores must be traceable to features, features to events, events to a
   chain, and chains to MITRE ATT&CK techniques.
4. **Safe by construction.** Response actions are recommendations first;
   destructive execution is human-gated and dry-run by default.
5. **Deterministic development.** A scripted telemetry source makes the entire
   pipeline reproducible in tests and CI.

## 2. The six layers

| Layer | Package | Responsibility | MVP implementation | Future |
|-------|---------|----------------|--------------------|--------|
| 1. Kernel Telemetry | `backend/telemetry` | Collect OS/security events | `ProcessMonitor` (psutil) + `DemoGenerator` | eBPF, auditd, Tracee, fanotify |
| 2. Feature Engineering | `backend/features` | Raw events -> behaviour vectors | `FeatureExtractor` (per process chain per window) | behaviour graphs, session profiling |
| 3. AI Detection | `backend/detection` | Learn normal, flag deviation | `IsolationForestDetector` + hybrid signal scoring | autoencoder, supervised classifier, graph anomaly |
| 4. Explainability | `backend/explainability` | Why + chain + MITRE + narrative | `RuleBasedExplainer` | SHAP-style attribution, LLM narrative |
| 5. Response | `backend/response` | Recommend / perform remediation | `DecisionEngine` + `ApprovalGate` + `ActionExecutor` | playbooks, containment policies |
| 6. Dashboard | `backend/dashboard` | Live operator view | `CliDashboard` (rich) | web dashboard, REST/WS API |

## 3. Data flow (MVP vertical slice)

```
psutil / demo events
        │  collect()
        ▼
  KernelEvent (backend/core/events.py)
        │  FeatureExtractor.extract(window)
        ▼
  ProcessFeatures  (one per behaviour chain)
        │  IsolationForestDetector.predict()
        ▼
  DetectionResult  (anomaly score, confidence, severity, attribution)
        │  RuleBasedExplainer.explain()
        ▼
  Explanation      (reasons, chain, MITRE, narrative)
        │  DecisionEngine.decide()
        ▼
  ResponseAction[] (recommendations)
        │  ApprovalGate -> ActionExecutor
        ▼
  ThreatReport     -> dashboard / API / persistence
```

### Behavioural units

Detection operates on **process chains** (a family of processes rooted at a
session/process-group leader), not individual commands. This is what lets the
system reason about the whole sequence `python -> bash -> curl -> chmod ->
/tmp payload -> reverse shell` as a single event of interest.

### Hybrid detection model

`anomaly_score = max(ML baseline score, hard-signal score)`:

- **ML baseline score**: normalised Isolation Forest score vs. the machine's
  learned baseline (contamination-boundary calibration).
- **Hard-signal score**: composition of well-known malicious primitives
  (exec from `/tmp`/`/dev/shm`, egress on non-standard high ports, privilege
  escalation, interpreter spawning interpreter).

This guarantees classic kill chains are always surfaced while the unsupervised
model still captures long-tail behavioural drift.

## 4. Configuration

Hierarchical: `config/defaults.yaml` <- user file <- dotted overrides
(e.g. `{"telemetry.window_seconds": 120}`). Exposed as `AppConfig`
(`backend/core/config.py`).

## 4a. Baseline lifecycle (M2)

The unsupervised baseline is a living model, not a one-shot fit:

- **Persistence**: trained detectors are saved/loaded via joblib; the payload
  carries `FEATURE_SCHEMA_VERSION` and mismatches are rejected on load.
  `detection.model_path` enables auto-load on boot (`start()`) and auto-save
  after learning/refits.
- **Online learning**: every unscored window, non-flagged chains fold into a
  sliding baseline capped by `baseline_max_samples`; every
  `refit_interval_windows` the detector is refit and the per-chain score cache
  is invalidated.
- **Feedback loop** (`backend/feedback/`): analyst verdicts
  (`label_chain(report_id, benign|malicious)`) are persisted in a JSONL ledger
  under `<data_dir>/feedback.jsonl`; `benign` folds the chain into normality,
  `malicious` excludes it from the training set, and the detector refits
  immediately. This is the raw material for the future supervised classifier.

## 4b. Explainability (M4)

Every detection ships with four layers of evidence:

- **SHAP-style attribution** (`feature_contributions`): the detector stores a
  bounded reservoir of baseline rows alongside the model and computes each
  feature's marginal contribution with the Strumbej-Kononenko sampling
  estimator (swapping the feature against sampled baseline rows in both
  directions). Deterministic, and attribution is only non-zero where the ML
  model itself deviates - hard-signal anomalies are explained by the signal
  rules instead, so attribution is always honest about its source.
- **Behaviour-chain DAG** (`build_dag`): process vertices + `spawn`/`attach`
  edges, serialised in the report and rendered as an ASCII process tree in the
  CLI dashboard.
- **MITRE mapping with confidence** (`map_techniques`): every technique carries
  `0..1` confidence from the strength of its evidence; persistence techniques
  (cron, systemd) are mapped from file-write targets.
- **LLM narrative** (optional): `LlmNarrativeGenerator` queries a local
  Ollama-compatible endpoint for analyst prose and degrades gracefully to the
  rule-based narrative on any failure (`explainability.narrative_provider`).

## 5. Extensibility points

- **New telemetry source**: implement `TelemetryProvider` (Protocol) and
  register it under `telemetry.provider`. Kernel sources (`auditd`, `tracee`,
  `bpf`) normalise into the same `KernelEvent` model via
  `backend/telemetry/parsers.py` and share bounded-ring / drop / rate-limit
  primitives (`backend/telemetry/ring.py`). No other layer changes.
- **New detector**: implement `AnomalyDetector` (Protocol). Reuse
  `compute_detection_result` for scoring semantics.
- **New response action**: add a builder + executor handler. Approval rules
  remain centralised in `ApprovalGate`.
- **New dashboard**: consume `ThreatReport.to_dict()` and the `EventBuffer`.

## 6. Runtime layout

```
data/        persisted models, quarantined artifacts
logs/        structured logs (guardianos.log)
quarantine/  quarantined executables (when approved)
config/      YAML configuration
```
