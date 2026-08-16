import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router";
import PageMeta from "../components/common/PageMeta";
import PageHeader from "../components/ui/PageHeader";
import Panel from "../components/ui/Panel";
import ToneBadge from "../components/ui/ToneBadge";
import EmptyState from "../components/ui/EmptyState";
import { useGuardian } from "../context/GuardianContext";
import { SEVERITY_TONE, formatRelative, shortExe } from "../lib/format";

interface ProcRow {
  pid: number;
  exe: string;
  eventCount: number;
  lastSeen: number;
  severity: string | null;
  reportId: string | null;
  kinds: Set<string>;
}

export default function Processes() {
  const { events, threats, refresh } = useGuardian();
  const [showSuspiciousOnly, setShowSuspiciousOnly] = useState(false);

  useEffect(() => {
    const t = setInterval(() => void refresh(), 10_000);
    return () => clearInterval(t);
  }, [refresh]);

  const rows = useMemo(() => {
    const byPid = new Map<number, ProcRow>();
    for (const e of events) {
      const row = byPid.get(e.pid) ?? {
        pid: e.pid,
        exe: e.exe,
        eventCount: 0,
        lastSeen: 0,
        severity: null,
        reportId: null,
        kinds: new Set<string>(),
      };
      row.eventCount += 1;
      row.kinds.add(e.kind);
      if (e.timestamp > row.lastSeen) {
        row.lastSeen = e.timestamp;
        row.exe = e.exe;
      }
      byPid.set(e.pid, row);
    }
    for (const t of threats) {
      const row = byPid.get(t.detection.pid) ?? {
        pid: t.detection.pid,
        exe: t.detection.exe,
        eventCount: 0,
        lastSeen: t.timestamp,
        severity: null,
        reportId: null,
        kinds: new Set<string>(),
      };
      row.severity = t.detection.severity;
      row.reportId = t.report_id;
      if (t.timestamp > row.lastSeen) row.lastSeen = t.timestamp;
      byPid.set(t.detection.pid, row);
    }
    let list = [...byPid.values()];
    if (showSuspiciousOnly) list = list.filter((r) => r.severity !== null);
    return list.sort((a, b) => b.lastSeen - a.lastSeen);
  }, [events, threats, showSuspiciousOnly]);

  return (
    <>
      <PageMeta
        title="Processes"
        description="Processes observed in the telemetry stream, cross-referenced with detections."
      />
      <PageHeader
        title="Processes"
        description="Processes observed in the telemetry stream, cross-referenced with detections."
        actions={
          <label className="flex cursor-pointer items-center gap-2 text-xs text-gray-600 dark:text-gray-300">
            <input
              type="checkbox"
              checked={showSuspiciousOnly}
              onChange={(e) => setShowSuspiciousOnly(e.target.checked)}
              className="size-3.5 accent-brand-600"
            />
            Suspicious only
          </label>
        }
      />

      <Panel title={`Observed processes (${rows.length})`}>
        {rows.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="border-b border-gray-200 text-[11px] uppercase tracking-wide text-gray-400 dark:border-gray-800">
                  <th className="py-2 pr-3">PID</th>
                  <th className="py-2 pr-3">Process</th>
                  <th className="py-2 pr-3">Events</th>
                  <th className="py-2 pr-3">Kinds</th>
                  <th className="py-2 pr-3">Last seen</th>
                  <th className="py-2">Status</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => (
                  <tr
                    key={row.pid}
                    className="border-b border-gray-100 last:border-0 dark:border-gray-800/60"
                  >
                    <td className="py-2 pr-3 font-mono text-xs text-gray-500">{row.pid}</td>
                    <td className="py-2 pr-3 font-mono text-xs text-gray-700 dark:text-gray-300">
                      {shortExe(row.exe)}
                      <span className="block text-[10px] text-gray-400">{row.exe}</span>
                    </td>
                    <td className="py-2 pr-3 text-xs text-gray-500">{row.eventCount}</td>
                    <td className="py-2 pr-3 text-[11px] text-gray-400">
                      {[...row.kinds].slice(0, 3).join(", ")}
                      {row.kinds.size > 3 ? "…" : ""}
                    </td>
                    <td className="py-2 pr-3 text-xs text-gray-400">
                      {formatRelative(row.lastSeen)}
                    </td>
                    <td className="py-2">
                      {row.severity ? (
                        <Link to={`/threats/${row.reportId}`}>
                          <ToneBadge tone={SEVERITY_TONE[row.severity as keyof typeof SEVERITY_TONE]}>
                            {row.severity}
                          </ToneBadge>
                        </Link>
                      ) : (
                        <span className="text-xs text-gray-400">normal</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState
            title="No processes observed"
            detail="The process list is derived from the live telemetry stream."
          />
        )}
      </Panel>
    </>
  );
}
