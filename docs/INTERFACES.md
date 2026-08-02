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

Implementations: `ProcessMonitor` (psutil), `DemoGenerator` (scripted).

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
    mitre: list[MitreReference]   # technique_id, name, tactic, url
    confidence: float
    severity: Severity
```

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
pipeline.execute_action(report_id, action_index)   # human approves an action
pipeline.label_chain(report_id, "benign" | "malicious", note=...)  # feedback loop
pipeline.stop()
```

The pipeline also exposes `is_ready_to_detect()`, `learning_step()`, and
`feedback` (a `FeedbackLedger` persisted under `<data_dir>/feedback.jsonl`).

## 9. Configuration contract

`backend/core/config.py` -> `AppConfig` (from `config/defaults.yaml`)

| Section | Key | Default | Meaning |
|---------|-----|---------|---------|
| telemetry | provider | `process_monitor` | telemetry source name |
| telemetry | window_seconds | 60 | analysis window |
| detection | contamination | 0.01 | expected anomaly share |
| detection | flagged_threshold | 0.60 | anomaly score threshold |
| detection | min_baseline_samples | 25 | vectors needed before fit |
| detection | model_path | `null` | persisted model location (auto-load/save) |
| detection | autoload | true | load persisted model on boot if present |
| detection | refit_interval_windows | 10 | online refit cadence |
| detection | baseline_max_samples | 400 | sliding baseline cap |
| response | dry_run | true | never perform, only log |
| response | auto_approve_destructive | false | require human approval |
