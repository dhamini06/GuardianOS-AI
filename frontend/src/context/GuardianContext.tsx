/**
 * Global runtime state for the GuardianOS-AI UI.
 *
 * Owns the WebSocket subscription (/api/ws), HTTP polling fallbacks and all
 * threat mutations (label / approve / reject / rollback). Components consume
 * this context only; they never call fetch directly.
 */

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
  type ReactNode,
} from "react";
import {
  approveAction,
  fetchEvents,
  fetchHealth,
  fetchThreats,
  labelThreat,
  rejectAction,
  rollbackReport,
} from "../api/guardian";
import { useGuardianSocket } from "../api/ws";
import type { Health, KernelEvent, LabelRequest, ThreatReport } from "../api/types";

interface GuardianContextValue {
  connected: boolean;
  health: Health | null;
  healthError: string | null;
  threats: ThreatReport[];
  threatsError: string | null;
  events: KernelEvent[];
  eventsError: string | null;
  refresh: () => void;
  labelReport: (reportId: string, body: LabelRequest) => Promise<ThreatReport>;
  approve: (reportId: string, actionIndex: number) => Promise<ThreatReport>;
  reject: (reportId: string, actionIndex: number) => Promise<ThreatReport>;
  rollback: (reportId: string) => Promise<number>;
  mutationError: string | null;
}

const GuardianContext = createContext<GuardianContextValue | null>(null);

function upsertThreat(list: ThreatReport[], report: ThreatReport): ThreatReport[] {
  const rest = list.filter((r) => r.report_id !== report.report_id);
  return [report, ...rest];
}

export function GuardianProvider({ children }: { children: ReactNode }) {
  const [connected, setConnected] = useState(false);
  const [health, setHealth] = useState<Health | null>(null);
  const [healthError, setHealthError] = useState<string | null>(null);
  const [threats, setThreats] = useState<ThreatReport[]>([]);
  const [threatsError, setThreatsError] = useState<string | null>(null);
  const [events, setEvents] = useState<KernelEvent[]>([]);
  const [eventsError, setEventsError] = useState<string | null>(null);
  const [mutationError, setMutationError] = useState<string | null>(null);
  const refreshSeq = useRef(0);

  const refreshHealth = useCallback(async () => {
    try {
      const next = await fetchHealth();
      setHealth(next);
      setHealthError(null);
    } catch (err) {
      setHealthError(err instanceof Error ? err.message : "health fetch failed");
    }
  }, []);

  const refreshThreats = useCallback(async () => {
    try {
      const list = await fetchThreats();
      setThreats(list);
      setThreatsError(null);
    } catch (err) {
      setThreatsError(err instanceof Error ? err.message : "threats fetch failed");
    }
  }, []);

  const refreshEvents = useCallback(async () => {
    try {
      const list = await fetchEvents();
      setEvents(list);
      setEventsError(null);
    } catch (err) {
      setEventsError(err instanceof Error ? err.message : "events fetch failed");
    }
  }, []);

  const refresh = useCallback(() => {
    refreshSeq.current += 1;
    void refreshHealth();
    void refreshThreats();
    void refreshEvents();
  }, [refreshHealth, refreshThreats, refreshEvents]);

  const onFrame = useCallback(
    (frame: { seq: number; items: Array<unknown> }) => {
      for (const item of frame.items as Array<{
        kind?: string;
        data?: { report?: ThreatReport; health?: unknown };
      }>) {
        if (item.kind === "report" && item.data?.report) {
          setThreats((prev) => upsertThreat(prev, item.data!.report!));
          void refreshEvents();
        } else if (item.kind === "health" && item.data?.health) {
          setHealth((prev) => {
            const patch = item.data!.health as Partial<Health>;
            return prev ? { ...prev, ...patch } : (patch as Health);
          });
          setHealthError(null);
        }
      }
    },
    [refreshEvents],
  );

  useGuardianSocket(onFrame, setConnected);

  // Initial load.
  useEffect(() => {
    void refresh();
  }, [refresh]);

  // Polling fallback so the UI stays live even without WebSocket support.
  useEffect(() => {
    const healthTimer = setInterval(() => void refreshHealth(), 10_000);
    const eventsTimer = setInterval(() => void refreshEvents(), 5_000);
    return () => {
      clearInterval(healthTimer);
      clearInterval(eventsTimer);
    };
  }, [refreshHealth, refreshEvents]);

  const labelReport = useCallback(
    async (reportId: string, body: LabelRequest): Promise<ThreatReport> => {
      try {
        const updated = await labelThreat(reportId, body);
        setThreats((prev) => upsertThreat(prev, updated));
        setMutationError(null);
        return updated;
      } catch (err) {
        setMutationError(err instanceof Error ? err.message : "label failed");
        throw err;
      }
    },
    [],
  );

  const approve = useCallback(
    async (reportId: string, actionIndex: number): Promise<ThreatReport> => {
      try {
        const updated = await approveAction(reportId, actionIndex);
        setThreats((prev) => upsertThreat(prev, updated));
        setMutationError(null);
        return updated;
      } catch (err) {
        setMutationError(err instanceof Error ? err.message : "approve failed");
        throw err;
      }
    },
    [],
  );

  const reject = useCallback(
    async (reportId: string, actionIndex: number): Promise<ThreatReport> => {
      try {
        const updated = await rejectAction(reportId, actionIndex);
        setThreats((prev) => upsertThreat(prev, updated));
        setMutationError(null);
        return updated;
      } catch (err) {
        setMutationError(err instanceof Error ? err.message : "reject failed");
        throw err;
      }
    },
    [],
  );

  const rollback = useCallback(async (reportId: string): Promise<number> => {
    try {
      const result = await rollbackReport(reportId);
      setMutationError(null);
      return result.rolled_back;
    } catch (err) {
      setMutationError(err instanceof Error ? err.message : "rollback failed");
      throw err;
    }
  }, []);

  return (
    <GuardianContext.Provider
      value={{
        connected,
        health,
        healthError,
        threats,
        threatsError,
        events,
        eventsError,
        refresh,
        labelReport,
        approve,
        reject,
        rollback,
        mutationError,
      }}
    >
      {children}
    </GuardianContext.Provider>
  );
}

export function useGuardian(): GuardianContextValue {
  const ctx = useContext(GuardianContext);
  if (!ctx) {
    throw new Error("useGuardian must be used within a GuardianProvider");
  }
  return ctx;
}
