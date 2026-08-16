import { useMemo } from "react";
import { Link } from "react-router";
import PageMeta from "../components/common/PageMeta";
import PageHeader from "../components/ui/PageHeader";
import Panel from "../components/ui/Panel";
import ToneBadge from "../components/ui/ToneBadge";
import EmptyState from "../components/ui/EmptyState";
import { useGuardian } from "../context/GuardianContext";
import {
  SEVERITY_TONE,
  formatDateTime,
  formatRelative,
  formatTime,
  severityCounts,
  shortExe,
  threatLevel,
} from "../lib/format";
import { EventChart } from "../components/charts/EventChart";

const SEVERITY_LABELS = ["critical", "high", "medium", "low", "info"] as const;

function StatCard({
  label,
  value,
  detail,
}: {
  label: string;
  value: number | string;
  detail?: string;
}) {
  return (
    <div className="rounded-xl border border-gray-200 bg-white p-4 shadow-theme-xs dark:border-gray-800 dark:bg-gray-900">
      <p className="text-xs font-medium uppercase tracking-wide text-gray-400 dark:text-gray-500">
        {label}
      </p>
      <p className="mt-2 text-2xl font-semibold text-gray-900 dark:text-white">{value}</p>
      {detail && (
        <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">{detail}</p>
      )}
    </div>
  );
}

export default function Overview() {
  const { health, threats, events, connected } = useGuardian();
  const counts = useMemo(() => severityCounts(threats), [threats]);
  const level = threatLevel(threats, health?.learning ?? true);
  const latest = threats[0];

  const suspiciousProcesses = useMemo(() => {
    const seen = new Map<number, { exe: string; pid: number; severity: string; ts: number }>();
    for (const t of threats) {
      if (!seen.has(t.detection.pid)) {
        seen.set(t.detection.pid, {
          exe: t.detection.exe,
          pid: t.detection.pid,
          severity: t.detection.severity,
          ts: t.timestamp,
        });
      }
    }
    return [...seen.values()].slice(0, 8);
  }, [threats]);

  return (
    <>
      <PageMeta
        title="Overview"
        description="Live security posture, threat timeline and kernel activity."
      />
      <PageHeader
        title="Security Overview"
        description="Live posture derived from the GuardianOS-AI detection pipeline."
        actions={
          <ToneBadge tone={level.tone} className="px-3 py-1">
            SYSTEM STATUS: {level.label}
          </ToneBadge>
        }
      />

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard
          label="Threats"
          value={health ? health.threats : threats.length}
          detail={health ? `baseline ${health.baseline} chains` : undefined}
        />
        <StatCard
          label="Critical"
          value={counts.critical}
          detail={`${counts.high} high`}
        />
        <StatCard
          label="Kernel events"
          value={health ? health.events_in_window : 0}
          detail="in current window"
        />
        <StatCard
          label="Processes"
          value={events.length > 0 ? new Set(events.map((e) => e.pid)).size : "—"}
          detail="observed in stream"
        />
      </div>

      <div className="mt-4 grid gap-4 lg:grid-cols-3">
        <div className="lg:col-span-2">
          <Panel
            title="Threat activity timeline"
            subtitle="Flagged reports over time (real detections)"
          >
            <EventChart threats={threats} />
            {threats.length === 0 && (
              <EmptyState
                title="No detections yet"
                detail={
                  health?.learning
                    ? "The engine is still learning the baseline. Detections will appear once it switches to detection mode."
                    : "The engine is monitoring but has not flagged any behavior yet."
                }
              />
            )}
          </Panel>
        </div>
        <Panel title="Recent suspicious processes" subtitle="Processes implicated in detections">
          {suspiciousProcesses.length > 0 ? (
            <ul className="space-y-2">
              {suspiciousProcesses.map((p) => (
                <li
                  key={p.pid}
                  className="flex items-center justify-between gap-2 rounded-lg border border-gray-200 px-3 py-2 dark:border-gray-800"
                >
                  <div className="min-w-0">
                    <p className="truncate font-mono text-sm text-gray-800 dark:text-gray-100">
                      {shortExe(p.exe)}
                    </p>
                    <p className="text-[11px] text-gray-400">
                      pid {p.pid} · {formatRelative(p.ts)}
                    </p>
                  </div>
                  <ToneBadge tone={SEVERITY_TONE[p.severity as keyof typeof SEVERITY_TONE]}>
                    {p.severity}
                  </ToneBadge>
                </li>
              ))}
            </ul>
          ) : (
            <EmptyState title="No suspicious processes" />
          )}
        </Panel>
      </div>

      <div className="mt-4 grid gap-4 lg:grid-cols-2">
        <Panel
          title="Recent kernel activity"
          subtitle="Latest events from the telemetry stream"
          actions={
            <Link
              to="/kernel"
              className="text-xs font-medium text-brand-600 hover:underline dark:text-brand-400"
            >
              View all →
            </Link>
          }
        >
          {events.length > 0 ? (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead>
                  <tr className="border-b border-gray-200 text-[11px] uppercase tracking-wide text-gray-400 dark:border-gray-800">
                    <th className="py-2 pr-3">PID</th>
                    <th className="py-2 pr-3">Process</th>
                    <th className="py-2 pr-3">Event</th>
                    <th className="py-2 pr-3">Time</th>
                  </tr>
                </thead>
                <tbody>
                  {events.slice(0, 8).map((e) => (
                    <tr
                      key={e.event_id}
                      className="border-b border-gray-100 last:border-0 dark:border-gray-800/60"
                    >
                      <td className="py-2 pr-3 font-mono text-xs text-gray-500">{e.pid}</td>
                      <td className="py-2 pr-3 font-mono text-xs text-gray-700 dark:text-gray-300">
                        {shortExe(e.exe)}
                      </td>
                      <td className="py-2 pr-3 text-xs text-gray-500 dark:text-gray-400">
                        {e.kind}
                      </td>
                      <td className="py-2 pr-3 text-xs text-gray-400">{formatTime(e.timestamp)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <EmptyState
              title="No kernel events received"
              detail={
                connected
                  ? "Waiting for telemetry…"
                  : "Not connected to the engine. Start `python scripts/run_server.py`."
              }
            />
          )}
        </Panel>

        <Panel
          title="AI security analysis"
          subtitle="Latest detection, explained"
          actions={
            <Link
              to="/analysis"
              className="text-xs font-medium text-brand-600 hover:underline dark:text-brand-400"
            >
              Open analysis →
            </Link>
          }
        >
          {latest ? (
            <div className="space-y-3">
              <div className="flex items-center gap-2">
                <ToneBadge tone={SEVERITY_TONE[latest.detection.severity]}>
                  {latest.detection.severity}
                </ToneBadge>
                <span className="font-mono text-xs text-gray-500">
                  {shortExe(latest.detection.exe)} · pid {latest.detection.pid}
                </span>
                <span className="text-xs text-gray-400">
                  {formatDateTime(latest.timestamp)}
                </span>
              </div>
              <p className="text-sm leading-5 text-gray-700 dark:text-gray-300">
                “{latest.explanation.summary}”
              </p>
              {latest.explanation.reasons[0] && (
                <p className="text-xs text-gray-500 dark:text-gray-400">
                  <span className="font-semibold">Why:</span> {latest.explanation.reasons[0]}
                </p>
              )}
              {latest.actions[0] && (
                <p className="text-xs text-gray-500 dark:text-gray-400">
                  <span className="font-semibold">Recommended:</span>{" "}
                  {latest.actions[0].description}
                </p>
              )}
              <Link
                to={`/threats/${latest.report_id}`}
                className="inline-flex rounded-md bg-brand-600 px-3 py-1.5 text-xs font-medium text-white transition-colors hover:bg-brand-700"
              >
                Investigate
              </Link>
            </div>
          ) : (
            <EmptyState
              title="No AI analysis yet"
              detail="Analysis appears when the engine flags behavior that deviates from the baseline."
            />
          )}
        </Panel>
      </div>

      <p className="mt-4 text-right text-[11px] text-gray-400 dark:text-gray-500">
        {SEVERITY_LABELS.map((s) => (
          <span key={s} className="ml-2">
            {s}: {counts[s]}
          </span>
        ))}
      </p>
    </>
  );
}
