import { useMemo, useState } from "react";
import PageMeta from "../components/common/PageMeta";
import PageHeader from "../components/ui/PageHeader";
import Panel from "../components/ui/Panel";
import ToneBadge from "../components/ui/ToneBadge";
import EmptyState from "../components/ui/EmptyState";
import ThreatDetail from "../components/ThreatDetail";
import { useGuardian } from "../context/GuardianContext";
import { SEVERITY_TONE, formatRelative, shortExe } from "../lib/format";

export default function AIAnalysis() {
  const { threats } = useGuardian();
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const sorted = useMemo(
    () => [...threats].sort((a, b) => b.timestamp - a.timestamp),
    [threats],
  );
  const selected = sorted.find((t) => t.report_id === (selectedId ?? sorted[0]?.report_id));
  const report = selected ?? sorted[0];

  return (
    <>
      <PageMeta
        title="AI Analysis"
        description="Explainable analysis of every detection: what, why, evidence and recommended action."
      />
      <PageHeader
        title="AI Analysis"
        description="Explainable investigation: what happened, why it is suspicious, the evidence, and the recommended response."
      />

      <div className="grid gap-4 lg:grid-cols-5">
        <Panel title="Reports" className="lg:col-span-2">
          {sorted.length > 0 ? (
            <ul className="max-h-[70vh] space-y-2 overflow-y-auto pr-1">
              {sorted.map((t) => (
                <li key={t.report_id}>
                  <button
                    onClick={() => setSelectedId(t.report_id)}
                    className={`w-full rounded-lg border px-3 py-2.5 text-left transition-colors ${
                      report?.report_id === t.report_id
                        ? "border-brand-500 bg-brand-50/60 dark:border-brand-600 dark:bg-brand-950/40"
                        : "border-gray-200 hover:bg-gray-50 dark:border-gray-800 dark:hover:bg-gray-800/50"
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="truncate font-mono text-sm text-gray-800 dark:text-gray-100">
                        {shortExe(t.detection.exe)}
                      </span>
                      <ToneBadge tone={SEVERITY_TONE[t.detection.severity]}>
                        {t.detection.severity}
                      </ToneBadge>
                    </div>
                    <p className="mt-1 text-[11px] text-gray-400">
                      {formatRelative(t.timestamp)} · confidence {t.detection.confidence.toFixed(2)}
                    </p>
                  </button>
                </li>
              ))}
            </ul>
          ) : (
            <EmptyState
              title="No analysis available"
              detail="The AI explainer produces an investigation once the detection engine flags behavior."
            />
          )}
        </Panel>

        <div className="lg:col-span-3">
          {report ? (
            <ThreatDetail report={report} />
          ) : (
            <Panel>
              <EmptyState title="No report selected" />
            </Panel>
          )}
        </div>
      </div>
    </>
  );
}
