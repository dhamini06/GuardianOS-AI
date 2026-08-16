/**
 * TypeScript mirrors of the GuardianOS-AI REST/WS contracts.
 *
 * Field shapes are produced by the backend `to_dict()` serializers
 * (backend/core/analysis.py, backend/core/events.py, backend/telemetry/base.py).
 */

export type Severity = "info" | "low" | "medium" | "high" | "critical";

export type ActionType = "kill_process" | "freeze_process" | "block_ip" | "quarantine_file";

export type ActionStatus =
  | "recommended"
  | "pending_approval"
  | "approved"
  | "rejected"
  | "executed"
  | "failed";

export type EventKind =
  | "process_created"
  | "process_exited"
  | "exec"
  | "network_connect"
  | "file_write"
  | "file_read"
  | "privilege_escalation"
  | "authentication"
  | "module_load"
  | "socket_bind"
  | "signal";

export interface KernelEvent {
  event_id: string;
  kind: EventKind;
  timestamp: number;
  pid: number;
  ppid: number;
  exe: string;
  cmdline: string[];
  uid?: number;
  username?: string;
  cwd?: string;
  details: Record<string, unknown>;
}

export interface ChainStep {
  position: number;
  description: string;
  kind: string;
  exe: string;
  pid: number;
  suspicious: boolean;
  detail: string | null;
}

export interface ChainNode {
  id: string;
  pid: number;
  ppid: number;
  exe: string;
  kind: string;
  timestamp: number;
  description: string;
  suspicious: boolean;
}

export interface ChainEdge {
  source: string;
  target: string;
  kind: "spawn" | "attach";
}

export interface ChainDAG {
  nodes: ChainNode[];
  edges: ChainEdge[];
  roots: string[];
}

export interface MitreReference {
  technique_id: string;
  name: string;
  tactic: string;
  url: string;
  confidence: number;
}

export interface Explanation {
  summary: string;
  reasons: string[];
  chain: ChainStep[];
  mitre: MitreReference[];
  dag: ChainDAG | null;
  confidence: number;
  severity: Severity;
}

export interface DetectionResult {
  pid: number;
  exe: string;
  raw_score: number;
  anomaly_score: number;
  confidence: number;
  severity: Severity;
  flagged: boolean;
  contributing_features: Record<string, number>;
  context: {
    chain_key: string;
    window: [number, number];
    ml_score: number;
    signal_score: number;
  };
}

export interface ResponseAction {
  action_type: ActionType;
  description: string;
  destructive: boolean;
  requires_approval: boolean;
  target: Record<string, unknown>;
  status: ActionStatus;
  rationale: string;
}

export interface ThreatReport {
  report_id: string;
  timestamp: number;
  detection: DetectionResult;
  explanation: Explanation;
  actions: ResponseAction[];
}

export interface ProviderHealth {
  provider: string;
  running: boolean;
  started_at: number | null;
  last_collect_at: number | null;
  events_delivered: number;
  drops_total: number;
  drops_recent: number;
  rate_limited: number;
  restarts: number;
  last_error: string | null;
  source: Record<string, unknown>;
}

export interface Health {
  status: string;
  learning: boolean;
  baseline: number;
  threats: number;
  events_in_window: number;
  ready: boolean;
  telemetry: ProviderHealth;
}

export interface WsHealth {
  learning: boolean;
  baseline: number;
  threats: number;
  events_in_window: number;
  ready: boolean;
  telemetry: ProviderHealth;
}

export interface WsFrame {
  seq: number;
  items: Array<
    | { kind: "report"; data: { report: ThreatReport } }
    | { kind: "health"; data: { health: WsHealth } }
  >;
}

export interface LabelRequest {
  verdict: "benign" | "malicious";
  note?: string | null;
}

export interface RollbackResponse {
  report_id: string;
  rolled_back: number;
}
