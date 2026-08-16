import { useEffect, useMemo, useState } from "react";
import { Link, useParams } from "react-router";
import PageMeta from "../components/common/PageMeta";
import PageHeader from "../components/ui/PageHeader";
import Panel from "../components/ui/Panel";
import ToneBadge from "../components/ui/ToneBadge";
import EmptyState from "../components/ui/EmptyState";
import ThreatDetail from "../components/ThreatDetail";
import { useGuardian } from "../context/GuardianContext";
import {
  SEVERITY_TONE,
  SEVERITY_ORDER,
  formatDateTime,
  formatRelative,
  shortExe,
} from "../lib/format";
import type { Severity } from "../api/types";

export default function Threats() {
  const { threats, threatsError, refresh } = useGuardian();
  const { reportId } = useParams();
  const [filter, setFilter] = useState<Severity | "all">("all");

  useEffect(() => {
    const t = setInterval(() => void refresh(), 15_000);
    return () => clearInterval(t);
  }, [refresh]);

  const sorted = useMemo(() => {
    const list = [...threats].sort((a, b) => b.timestamp - a.timestamp);
    if (filter === "all") return list;
    return list.filter((t) => t.detection.severity === filter);
  }, [threats, filter]);

  const selected = reportId ? threats.find((t) => t.report_id === reportId) : undefined;

  return (
    <>
      <PageMeta
        title="Threats"
        description="All detected threats with severity, evidence and recommended response."
      />
      <PageHeader
        title="Threats"
        description="Every behavior the engine flagged, with evidence and recommended response."
        actions={
          <div className="flex flex-wrap gap-1.5">
            {(["all", ...SEVERITY_ORDER] as const).map((sev) => (
              <button
                key={sev}
                onClick={() => setFilter(sev)}
                className={`rounded-md px-2.5 py-1 text-xs font-medium transition-colors ${
                  filter === sev
                    ? "bg-gray-900 text-white dark:bg-gray-100 dark:text-gray-900"
                    : "border border-gray-200 text-gray-600 hover:bg-gray-100 dark:border-gray-800 dark:text-gray-300 dark:hover:bg-gray-800"
                }`}
              >
                {sev}
              </button>
            ))}
          </div>
        }
      />

      {threatsError && (
        <div className="mb-4 rounded-md bg-error-50 px-3 py-2 text-xs text-error-700 dark:bg-error-950 dark:text-error-300">
          {threatsError}
        </div>
      )}

      <div className="grid gap-4 lg:grid-cols-5">
        <Panel title={`Reports (${sorted.length})`} className="lg:col-span-2">
          {sorted.length > 0 ? (
            <ul className="max-h-[70vh] space-y-2 overflow-y-auto pr-1">
              {sorted.map((t) => (
                <li key={t.report_id}>
                  <Link
                    to={`/threats/${t.report_id}`}
                    className={`block rounded-lg border px-3 py-2.5 transition-colors ${
                      t.report_id === reportId
                        ? "border-brand-500 bg-brand-50/60 dark:border-brand-600 dark:bg-brand-950/40"
                        : "border-gray-200 hover:bg-gray-50 dark:border-gray-800 dark:hover:bg-gray-800/50"
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="truncate font-mono text-sm text-gray-800 dark:text-gray-100">
                        {shortExe(t.detection.exe)}
                        <span className="text-gray-400"> · pid {t.detection.pid}</span>
                      </span>
                      <ToneBadge tone={SEVERITY_TONE[t.detection.severity]}>
                        {t.detection.severity}
                      </ToneBadge>
                    </div>
                    <p className="mt-1 text-[11px] text-gray-400">
                      {formatDateTime(t.timestamp)} · {formatRelative(t.timestamp)} ·{" "}
                      {t.detection.anomaly_score.toFixed(2)}
                    </p>
                    <p className="mt-1 line-clamp-2 text-xs text-gray-500 dark:text-gray-400">
                      {t.explanation.summary}
                    </p>
                  </Link>
                </li>
              ))}
            </ul>
          ) : (
            <EmptyState
              title={filter === "all" ? "No threats reported" : `No ${filter} threats`}
              detail="The engine reports threats only when the detection pipeline flags behavior."
            />
          )}
        </Panel>

        <div className="lg:col-span-3">
          {selected ? (
            <ThreatDetail report={selected} />
          ) : (
            <Panel>
              <EmptyState
                title="Select a report"
                detail="Choose a report from the list to inspect its AI analysis, evidence and response actions."
              />
            </Panel>
          )}
        </div>
      </div>
    </>
  );
}
