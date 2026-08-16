import { useState } from "react";
import type { ThreatReport } from "../api/types";
import { useGuardian } from "../context/GuardianContext";
import {
  ACTION_STATUS_TONE,
  formatDateTime,
  formatRelative,
  shortExe,
} from "../lib/format";
import ToneBadge from "./ui/ToneBadge";
import Panel from "./ui/Panel";

function ActionRow({
  report,
  actionIndex,
}: {
  report: ThreatReport;
  actionIndex: number;
}) {
  const { approve, reject } = useGuardian();
  const [busy, setBusy] = useState(false);
  const action = report.actions[actionIndex];
  const actionable = action.status === "recommended" || action.status === "pending_approval";

  const run = async (fn: () => Promise<unknown>) => {
    setBusy(true);
    try {
      await fn();
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex items-start justify-between gap-3 rounded-lg border border-gray-200 px-3 py-2.5 dark:border-gray-800">
      <div className="min-w-0">
        <div className="flex items-center gap-2">
          <span className="font-mono text-xs font-semibold text-gray-800 dark:text-gray-100">
            {action.action_type}
          </span>
          <ToneBadge tone={ACTION_STATUS_TONE[action.status]}>{action.status}</ToneBadge>
          {action.destructive && (
            <ToneBadge tone="red" className="uppercase">
              destructive
            </ToneBadge>
          )}
        </div>
        <p className="mt-1 text-xs leading-4 text-gray-500 dark:text-gray-400">
          {action.description}
        </p>
        <p className="mt-0.5 text-[11px] text-gray-400 dark:text-gray-500">{action.rationale}</p>
      </div>
      {actionable && (
        <div className="flex shrink-0 gap-2">
          <button
            disabled={busy}
            onClick={() => void run(() => approve(report.report_id, actionIndex))}
            className="rounded-md bg-success-600 px-2.5 py-1 text-xs font-medium text-white transition-colors hover:bg-success-700 disabled:opacity-50"
          >
            Approve
          </button>
          <button
            disabled={busy}
            onClick={() => void run(() => reject(report.report_id, actionIndex))}
            className="rounded-md border border-gray-300 px-2.5 py-1 text-xs font-medium text-gray-700 transition-colors hover:bg-gray-100 disabled:opacity-50 dark:border-gray-700 dark:text-gray-300 dark:hover:bg-gray-800"
          >
            Reject
          </button>
        </div>
      )}
    </div>
  );
}

export default function ThreatDetail({ report }: { report: ThreatReport }) {
  const { labelReport, rollback, mutationError } = useGuardian();
  const [labelBusy, setLabelBusy] = useState(false);
  const { detection, explanation } = report;
  const hasExecuted = report.actions.some((a) => a.status === "executed");

  const label = async (verdict: "benign" | "malicious") => {
    setLabelBusy(true);
    try {
      await labelReport(report.report_id, { verdict });
    } finally {
      setLabelBusy(false);
    }
  };

  return (
    <div className="space-y-4">
      {mutationError && (
        <div className="rounded-md bg-error-50 px-3 py-2 text-xs text-error-700 dark:bg-error-950 dark:text-error-300">
          {mutationError}
        </div>
      )}

      <Panel title="What happened" subtitle="AI-generated detection narrative">
        <p className="text-sm leading-5 text-gray-700 dark:text-gray-300">
          {explanation.summary}
        </p>
      </Panel>

      <Panel title="Why is it suspicious" subtitle="Behavior that deviates from the learned baseline">
        <ul className="space-y-1.5">
          {explanation.reasons.map((reason, i) => (
            <li key={i} className="flex gap-2 text-sm text-gray-600 dark:text-gray-300">
              <span className="mt-1.5 size-1.5 shrink-0 rounded-full bg-brand-500" />
              {reason}
            </li>
          ))}
          {explanation.reasons.length === 0 && (
            <li className="text-sm text-gray-400">No deviation reasons were produced.</li>
          )}
        </ul>
      </Panel>

      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Risk assessment" subtitle="Score, severity and contributing features">
          <div className="space-y-2 text-sm">
            <div className="flex justify-between">
              <span className="text-gray-500 dark:text-gray-400">Severity</span>
              <ToneBadge tone="red">{detection.severity}</ToneBadge>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-500 dark:text-gray-400">Anomaly score</span>
              <span className="font-mono text-gray-800 dark:text-gray-200">
                {detection.anomaly_score.toFixed(3)}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-500 dark:text-gray-400">Confidence</span>
              <span className="font-mono text-gray-800 dark:text-gray-200">
                {explanation.confidence.toFixed(3)}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-500 dark:text-gray-400">ML score</span>
              <span className="font-mono text-gray-800 dark:text-gray-200">
                {detection.context.ml_score.toFixed(3)}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-500 dark:text-gray-400">Hard signal score</span>
              <span className="font-mono text-gray-800 dark:text-gray-200">
                {detection.context.signal_score.toFixed(3)}
              </span>
            </div>
            <div className="pt-1">
              <p className="mb-1 text-xs font-medium uppercase tracking-wide text-gray-400">
                Contributing features
              </p>
              <div className="flex flex-wrap gap-1.5">
                {Object.entries(detection.contributing_features).map(([name, value]) => (
                  <span
                    key={name}
                    className="rounded-md bg-gray-100 px-2 py-0.5 font-mono text-[11px] text-gray-600 dark:bg-gray-800 dark:text-gray-300"
                    title={`${value.toFixed(3)}`}
                  >
                    {name} {value.toFixed(2)}
                  </span>
                ))}
              </div>
            </div>
          </div>
        </Panel>

        <Panel title="Evidence" subtitle="Attack chain and MITRE ATT&CK mapping">
          {explanation.chain.length > 0 ? (
            <ol className="space-y-1.5">
              {explanation.chain.map((step) => (
                <li key={step.position} className="flex items-start gap-2 text-xs">
                  <span
                    className={`mt-0.5 shrink-0 rounded px-1.5 py-0.5 font-mono ${
                      step.suspicious
                        ? "bg-error-50 text-error-700 dark:bg-error-950 dark:text-error-300"
                        : "bg-gray-100 text-gray-500 dark:bg-gray-800 dark:text-gray-400"
                    }`}
                  >
                    {step.kind}
                  </span>
                  <span className="text-gray-600 dark:text-gray-300">
                    {step.description}
                    <span className="text-gray-400"> · pid {step.pid}</span>
                  </span>
                </li>
              ))}
            </ol>
          ) : (
            <p className="text-xs text-gray-400">No chain steps produced.</p>
          )}
          {explanation.mitre.length > 0 && (
            <div className="mt-3 flex flex-wrap gap-1.5">
              {explanation.mitre.map((m) => (
                <a
                  key={m.technique_id}
                  href={m.url}
                  target="_blank"
                  rel="noreferrer"
                  title={`${m.name} (${m.tactic})`}
                  className="rounded-md border border-brand-200 px-2 py-0.5 font-mono text-[11px] text-brand-600 transition-colors hover:bg-brand-50 dark:border-brand-900 dark:text-brand-300 dark:hover:bg-brand-950"
                >
                  {m.technique_id}
                </a>
              ))}
            </div>
          )}
        </Panel>
      </div>

      <Panel title="Recommended action" subtitle="Approval-gated response actions">
        <div className="space-y-2">
          {report.actions.map((_, i) => (
            <ActionRow key={i} report={report} actionIndex={i} />
          ))}
          {report.actions.length === 0 && (
            <p className="text-sm text-gray-400">No actions were recommended for this report.</p>
          )}
        </div>
        {hasExecuted && (
          <div className="mt-3 flex justify-end">
            <button
              onClick={() => void rollback(report.report_id)}
              className="rounded-md border border-gray-300 px-3 py-1.5 text-xs font-medium text-gray-700 transition-colors hover:bg-gray-100 dark:border-gray-700 dark:text-gray-300 dark:hover:bg-gray-800"
            >
              Roll back executed actions
            </button>
          </div>
        )}
      </Panel>

      <Panel title="Analyst verdict" subtitle="Feed back into the learning baseline">
        <div className="flex items-center justify-between gap-3">
          <p className="text-xs text-gray-500 dark:text-gray-400">
            Marking a chain <strong>benign</strong> folds it into the baseline;
            <strong> malicious</strong> excludes it and refits the detector.
          </p>
          <div className="flex shrink-0 gap-2">
            <button
              disabled={labelBusy}
              onClick={() => void label("benign")}
              className="rounded-md border border-success-600 px-3 py-1.5 text-xs font-medium text-success-700 transition-colors hover:bg-success-50 disabled:opacity-50 dark:text-success-400 dark:hover:bg-success-950"
            >
              Mark benign
            </button>
            <button
              disabled={labelBusy}
              onClick={() => void label("malicious")}
              className="rounded-md bg-error-600 px-3 py-1.5 text-xs font-medium text-white transition-colors hover:bg-error-700 disabled:opacity-50"
            >
              Mark malicious
            </button>
          </div>
        </div>
      </Panel>

      <p className="text-right text-[11px] text-gray-400 dark:text-gray-500">
        {report.report_id} · {shortExe(detection.exe)} (pid {detection.pid}) ·{" "}
        {formatDateTime(report.timestamp)} · {formatRelative(report.timestamp)}
      </p>
    </div>
  );
}
