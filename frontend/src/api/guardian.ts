/**
 * Endpoint wrappers for the GuardianOS-AI API. Kept separate from components so
 * presentation never touches fetch directly.
 */

import { api } from "./client";
import type {
  Health,
  KernelEvent,
  LabelRequest,
  RollbackResponse,
  ThreatReport,
} from "./types";

export function fetchHealth(): Promise<Health> {
  return api.get<Health>("/api/health");
}

export function fetchThreats(limit = 200): Promise<ThreatReport[]> {
  return api.get<ThreatReport[]>(`/api/threats?limit=${limit}`);
}

export function fetchThreat(reportId: string): Promise<ThreatReport> {
  return api.get<ThreatReport>(`/api/threats/${reportId}`);
}

export function fetchEvents(limit = 200): Promise<KernelEvent[]> {
  return api.get<KernelEvent[]>(`/api/events?limit=${limit}`);
}

export function labelThreat(
  reportId: string,
  body: LabelRequest,
): Promise<ThreatReport> {
  return api.post<ThreatReport>(`/api/threats/${reportId}/label`, body);
}

export function approveAction(
  reportId: string,
  actionIndex: number,
): Promise<ThreatReport> {
  return api.post<ThreatReport>(
    `/api/threats/${reportId}/actions/${actionIndex}/approve`,
  );
}

export function rejectAction(
  reportId: string,
  actionIndex: number,
): Promise<ThreatReport> {
  return api.post<ThreatReport>(
    `/api/threats/${reportId}/actions/${actionIndex}/reject`,
  );
}

export function rollbackReport(reportId: string): Promise<RollbackResponse> {
  return api.post<RollbackResponse>(`/api/threats/${reportId}/rollback`);
}
