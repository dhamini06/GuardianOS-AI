import type { ActionStatus, Severity, ThreatReport } from "../api/types";

export function formatTime(epoch: number): string {
  return new Date(epoch * 1000).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export function formatDateTime(epoch: number): string {
  return new Date(epoch * 1000).toLocaleString([], {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export function formatRelative(epoch: number, now = Date.now() / 1000): string {
  const delta = Math.max(0, Math.round(now - epoch));
  if (delta < 60) return `${delta}s ago`;
  if (delta < 3600) return `${Math.floor(delta / 60)}m ago`;
  if (delta < 86400) return `${Math.floor(delta / 3600)}h ago`;
  return `${Math.floor(delta / 86400)}d ago`;
}

export function shortExe(exe: string): string {
  return exe.split("/").pop() ?? exe;
}

export const SEVERITY_ORDER: Severity[] = ["info", "low", "medium", "high", "critical"];

export type Tone = "gray" | "blue" | "amber" | "orange" | "red" | "green";

export const SEVERITY_TONE: Record<Severity, Tone> = {
  info: "gray",
  low: "blue",
  medium: "amber",
  high: "orange",
  critical: "red",
};

export const ACTION_STATUS_TONE: Record<ActionStatus, Tone> = {
  recommended: "blue",
  pending_approval: "amber",
  approved: "blue",
  executed: "green",
  rejected: "gray",
  failed: "red",
};

export interface ThreatLevel {
  label: string;
  tone: Tone;
}

/** Derive the overall posture from real report data - never fabricated. */
export function threatLevel(threats: ThreatReport[], learning: boolean): ThreatLevel {
  if (learning) return { label: "LEARNING", tone: "blue" };
  const open = threats.filter((t) =>
    t.actions.some((a) =>
      ["recommended", "pending_approval", "approved"].includes(a.status),
    ),
  );
  if (open.some((t) => t.detection.severity === "critical" || t.detection.severity === "high")) {
    return { label: "THREAT ACTIVE", tone: "red" };
  }
  if (open.some((t) => t.detection.severity === "medium" || t.detection.severity === "low")) {
    return { label: "ELEVATED", tone: "amber" };
  }
  return { label: "PROTECTED", tone: "green" };
}

export function severityCounts(
  threats: ThreatReport[],
): Record<Severity, number> {
  const counts: Record<Severity, number> = {
    info: 0,
    low: 0,
    medium: 0,
    high: 0,
    critical: 0,
  };
  for (const t of threats) {
    counts[t.detection.severity] = (counts[t.detection.severity] ?? 0) + 1;
  }
  return counts;
}
