# GuardianOS-AI Interfaces

The interfaces below are the contracts between layers. They live in
`backend/core` (dependency-free) and `backend/*/base.py`. Keeping them small
and explicit is what makes each layer independently replaceable and testable.

## 1. Kernel event (Layer 1 output)

`backend/core/events.py` -> `KernelEvent`

```python
@dataclass(slots=True)
class KernelEvent:
    kind: EventKind            # PROCESS_CREATED | EXEC | NETWORK_CONNECT | ...
    pid: int
    ppid: int
    exe: str                   # absolute path of the executable
    cmdline: tuple[str, ...]
    timestamp: float
    event_id: str
    uid: int
    username: str
    cwd: str | None
    details: dict[str, Any]    # e.g. {"remote_ip", "remote_port"} for connects
```

Every telemetry source must normalise into `KernelEvent`. `EventKind` is an
enum in the same module.

## 2. Telemetry provider (Layer 1 interface)

`backend/telemetry/base.py` -> `TelemetryProvider` (Protocol)

```python
class TelemetryProvider(Protocol):
    def start(self) -> None: ...
    def stop(self) -> None: ...
    def collect(self) -> list[KernelEvent]: ...   # events since last call
```

Implementations: `ProcessMonitor` (psutil), `DemoGenerator` (scripted),
`AuditdProvider` (audit.log tail, Linux), `TraceeProvider`
(`tracee-ebpf --json`, Linux), `BPFProvider` (BCC kprobes, Linux). Kernel
providers share `create_provider(config)` selection
(`backend/telemetry/factory.py`), the record normalisers in
`backend/telemetry/parsers.py`, and bounded-ring / drop-accounting /
rate-limit primitives in `backend/telemetry/ring.py`. Kernel providers also
expose `drop_stats()` -> `{"dropped_total", "dropped_recent"}`.

## 3. Feature vector (Layer 2 output)

`backend/features/extractor.py` -> `ProcessFeatures`

```python
@dataclass(slots=True)
class ProcessFeatures:
    pid: int
    exe: str
    chain_key: str
    window_start: float
    window_end: float
    values: dict[str, float]      # 13 features, keys in FEATURE_NAMES
    related_events: list[KernelEvent]

    def to_vector(self) -> list[float]: ...   # FEATURE_NAMES order
    @property
    def basename(self) -> str: ...
```

`FEATURE_NAMES` (13 features) is the stable model schema:
`num_children, exec_frequency, unique_binaries_spawned, script_interpreters,
tmp_execs, downloads, unique_remote_ips, connections_per_min,
suspicious_ports, file_writes_per_min, privilege_escalations, process_depth,
chain_length`.

## 4. Detection layer (Layer 3)

`backend/detection/base.py` -> `AnomalyDetector` (Protocol)

```python
class AnomalyDetector(Protocol):
    @property
    def is_trained(self) -> bool: ...
    def fit(self, vectors: list[ProcessFeatures]) -> AnomalyDetector: ...
    def predict(self, vector: ProcessFeatures) -> DetectionResult: ...
    def feature_contributions(self, vector: ProcessFeatures) -> dict[str, float]: ...
    def save(self, path: str) -> None: ...
    @classmethod
    def load(cls, path: str) -> AnomalyDetector: ...
```

Output: `backend/core/analysis.py` -> `DetectionResult`

```python
@dataclass(slots=True)
class DetectionResult:
    pid: int
    exe: str
    raw_score: float          # model raw score
    anomaly_score: float      # 0..1, blended ML + hard-signal
    confidence: float         # 0..1
    severity: Severity        # INFO | LOW | MEDIUM | HIGH | CRITICAL
    flagged: bool
    contributing_features: dict[str, float]
    context: dict[str, Any]
```

## 5. Explainability layer (Layer 4)

`backend/explainability/base.py` -> `Explainer` (Protocol)

```python
class Explainer(Protocol):
    def explain(self, vector: ProcessFeatures, result: DetectionResult) -> Explanation: ...
```

Output: `Explanation`

```python
@dataclass(slots=True)
class Explanation:
    summary: str
    reasons: list[str]            # why this is anomalous
    chain: list[ChainStep]        # ordered behaviour chain with suspicious flags
    mitre: list[MitreReference]   # technique_id, name, tactic, url, confidence
    dag: ChainDAG | None          # behaviour-chain DAG (M4)
    confidence: float
    severity: Severity
```

## 5a. Behaviour-chain DAG (Layer 4, M4)

`backend/explainability/chain.py` -> `build_dag(events)` -> `ChainDAG`

```python
@dataclass(slots=True)
class ChainNode:
    id: str; pid: int; ppid: int; exe: str
    kind: str; timestamp: float; description: str; suspicious: bool

@dataclass(slots=True)
class ChainEdge:
    source: str; target: str; kind: str   # "spawn" | "attach"

@dataclass(slots=True)
class ChainDAG:
    nodes: list[ChainNode]
    edges: list[ChainEdge]
    roots: list[str]
```

Process vertices are linked by `spawn` edges; connections/writes/escalations
are leaf nodes `attach`ed to the process that performed them. The DAG is
serialised into `ThreatReport.to_dict()["explanation"]["dag"]`.

## 5b. SHAP-style attribution (Layer 3, M4)

`IsolationForestDetector.feature_contributions(vector)` returns
`dict[feature, float]` from the Strumbej-Kononenko sampling estimator against
a persisted reservoir of baseline rows. `MitreReference` gained a
`confidence: float` (0..1) populated by `map_techniques`. Optional analyst
prose comes from `backend/explainability/llm.py` (`LlmNarrativeGenerator`,
Ollama-compatible endpoint, graceful fallback).

## 6. Response layer (Layer 5)

`backend/response/base.py` -> `ActionExecutor` (Protocol)

```python
class ActionExecutor(Protocol):
    def execute(self, action: ResponseAction) -> ResponseAction: ...
```

Output: `ResponseAction`

```python
@dataclass(slots=True)
class ResponseAction:
    action_type: str          # kill_process | freeze_process | block_ip | quarantine_file
    description: str
    destructive: bool
    requires_approval: bool
    target: dict[str, Any]
    status: ActionStatus      # RECOMMENDED -> PENDING_APPROVAL -> APPROVED -> EXECUTED/REJECTED
    rationale: str | None
```

Lifecycle (enforced by `ApprovalGate` + `ActionExecutor`):

```
DecisionEngine creates RECOMMENDED
   │
   ▼
ApprovalGate: destructive + no auto-approve  → PENDING_APPROVAL (human)
              otherwise                      → APPROVED
   │
   ▼
ActionExecutor.execute: only APPROVED actions run
   │
   ▼
EXECUTED (dry-run logs the intent) | FAILED
```

### 6a. Response playbook (Layer 5, M5)

`backend/response/playbook.py` -> `PlaybookEngine` replaces hard-coded severity
branches with declarative rules:

```python
engine = PlaybookEngine.load()               # backend/config/playbooks.yaml (or built-in defaults)
actions = engine.decide(vector, result, explanation)   # de-duplicated ResponseActions
```

Rules match on `when.severity` and/or `when.techniques` (MITRE ids present in
the explanation) and expand to `actions` whose targets (pid, IPs, payload
paths) are derived from the chain. `DecisionEngine` is driven by the playbook.

### 6b. Containment with rollback (Layer 5, M5)

`backend/response/containment.py` -> `ContainmentManager`

```python
entry = manager.apply(action, report_id=...)   # performs effect + records undo
manager.rollback(entry)                        # undoes one operation
manager.rollback_all(report_id=...)            # undo everything for a report
```

Freeze/block/quarantine record a reversible handle (`ContainmentEntry`);
kill is non-reversible. Effects go through a `SystemRunner` (subprocess/psutil/
shutil) so tests inject a fake runner.

### 6c. Signed audit trail (Layer 5, M5)

`backend/response/audit.py` -> `AuditTrail` + `Signer`. Every approval,
execution and rollback is appended to a hash-chained JSONL file; with
`response.signing_secret` / `GUARDIAN_SIGNING_SECRET` set, each record carries
an HMAC-SHA256 signature. `verify_all(signer)` detects tampering.

## 6d. Web dashboard and API (Layer 6, M6)

`backend/api/server.py` -> `create_app(pipeline, config, *, start_driver=True,
tick=None)` builds the FastAPI application: REST + WebSocket under `/api` and
the built React dashboard served from `backend/dashboard/web` (source in
`frontend/`, SPA catch-all for deep links). A background
`PipelineDriver` (customisable `tick`) advances the pipeline and streams
changes to connected clients.

```python
app = create_app(pipeline, config)          # driver thread runs the pipeline loop
uvicorn.run(app, host=config.server.host, port=config.server.port)
```

Endpoints (roles: viewer < analyst < admin):

| Method | Path | Role | Purpose |
|--------|------|------|---------|
| GET | `/api/health` | public | learning state, baseline, threat/event counts |
| GET | `/api/events?limit=` | viewer+ | recent persisted events |
| GET | `/api/threats` `/api/threats/{id}` | viewer+ | threat reports (full `to_dict()`) |
| POST | `/api/threats/{id}/label` | analyst+ | `{"verdict": "benign"\|"malicious"}` feedback |
| POST | `/api/threats/{id}/actions/{i}/approve` | admin | approve + execute an action |
| POST | `/api/threats/{id}/actions/{i}/reject` | admin | reject an action |
| POST | `/api/threats/{id}/rollback` | admin | undo reversible containment |
| WS | `/api/ws?token=` | viewer+ | live `{"seq","items":[{seq,kind,data}]}` deltas |

Authentication: `backend/api/security.py` `Authenticator` maps
`X-GUARDIAN-TOKEN` (or `?token=` for WS) to a `User` with roles. Users come
from `config/auth/users`, tokens overridable via `GUARDIAN_TOKEN_<NAME>` env
vars; `auth.enabled: false` grants every request all roles (local demo).
Dependency aliases: `GuardianState`, `ViewerUser`, `AnalystUser`, `AdminUser`.

## 7. Threat report (dashboard/API input)

`backend/core/analysis.py` -> `ThreatReport`

```python
@dataclass(slots=True)
class ThreatReport:
    report_id: str
    timestamp: float
    detection: DetectionResult
    explanation: Explanation
    actions: list[ResponseAction]

    def to_dict(self) -> dict[str, Any]: ...
```

`to_dict()` is the stable serialisation contract for any dashboard or API.

## 8. Composition root

`backend/pipeline.py` -> `GuardianPipeline` wires the layers together:

```python
pipeline = GuardianPipeline(config, telemetry=provider)
pipeline.start()                         # auto-loads a persisted model if configured
pipeline.ingest_tick()                   # learning phase
pipeline.complete_learning()             # fits + persists the baseline model
pipeline.analyze_window(on_report=...)   # detection phase (periodically refits)
pipeline.execute_action(report_id, action_index, actor="analyst")  # human approves an action
pipeline.rollback_actions(report_id)               # undo all executed containment (M5)
pipeline.label_chain(report_id, "benign" | "malicious", note=...)  # feedback loop
pipeline.stop()
```

The pipeline also exposes `is_ready_to_detect()`, `learning_step()`, and
`feedback` (a `FeedbackLedger` persisted under `<data_dir>/feedback.jsonl`).
M5 additions: `playbook`, `signer`/`audit` (signed trail under
`<data_dir>/audit.jsonl`), `containment` (reversible responses) and `storage`
(SQLite under `<data_dir>/guardian.db`). M6: `create_app()` (see 6d) runs the
pipeline loop via a `PipelineDriver` thread; `execute_action` accepts an
`actor` for audit attribution.

## 9. Configuration contract

`backend/core/config.py` -> `AppConfig` (from `backend/config/defaults.yaml`)

| Section | Key | Default | Meaning |
|---------|-----|---------|---------|
| telemetry | provider | `process_monitor` | telemetry source name |
| telemetry | window_seconds | 60 | analysis window |
| telemetry | audit_log_path | `/var/log/audit/audit.log` | auditd provider source |
| telemetry | ring_capacity | 10000 | bounded ring of parsed events |
| telemetry | max_events_per_collect | 500 | per-collect budget |
| telemetry | rate_limit_per_second | 0 | token-bucket delivery cap |
| detection | contamination | 0.01 | expected anomaly share |
| detection | flagged_threshold | 0.60 | anomaly score threshold |
| detection | min_baseline_samples | 25 | vectors needed before fit |
| detection | attribution_background_samples | 64 | SHAP-style attribution budget |
| explainability | narrative_provider | `rules` | `rules` or `llm` (local model) |
| explainability | llm_endpoint | `http://127.0.0.1:11434` | Ollama-compatible endpoint |
| explainability | llm_model | `llama3.2:1b` | local model name |
| explainability | llm_timeout_seconds | 10.0 | LLM request timeout |
| detection | model_path | `null` | persisted model location (auto-load/save) |
| detection | autoload | true | load persisted model on boot if present |
| detection | refit_interval_windows | 10 | online refit cadence |
| detection | baseline_max_samples | 400 | sliding baseline cap |
| response | dry_run | true | never perform, only log |
| response | auto_approve_destructive | false | require human approval |
| response | playbook_path | `null` | YAML playbook file (null = built-in defaults) |
| response | audit_path | `audit.jsonl` | signed audit trail under data_dir |
| response | signing_secret | `null` | HMAC secret (env `GUARDIAN_SIGNING_SECRET`) |
| storage | enabled | true | persist events/reports to SQLite |
| storage | path | `guardian.db` | SQLite file under data_dir |
| storage | save_events | true | write telemetry events |
| storage | save_reports | true | write threat reports |
| storage | max_events | 100000 | sliding cap for persisted events |
| server | host | `127.0.0.1` | API/dashboard bind address |
| server | port | 8000 | API/dashboard port |
| server | refresh_seconds | 1.0 | driver tick + WebSocket push cadence |
| auth | enabled | false | require tokens (false = open local access) |
| auth | token_header | `X-GUARDIAN-TOKEN` | header carrying the bearer token |
| auth | default_role | `viewer` | role when a user lists none |
| auth | users | `[]` | `{name, token, roles:[...]}` (env `GUARDIAN_TOKEN_<NAME>`) |
