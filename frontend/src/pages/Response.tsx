import { useMemo, useState } from "react";
import { Link } from "react-router";
import PageMeta from "../components/common/PageMeta";
import PageHeader from "../components/ui/PageHeader";
import Panel from "../components/ui/Panel";
import ToneBadge from "../components/ui/ToneBadge";
import EmptyState from "../components/ui/EmptyState";
import { useGuardian } from "../context/GuardianContext";
import {
  ACTION_STATUS_TONE,
  formatRelative,
  shortExe,
} from "../lib/format";
import type { ActionStatus } from "../api/types";

const STATUSES: Array<ActionStatus | "all"> = [
  "all",
  "pending_approval",
  "recommended",
  "executed",
  "rejected",
  "failed",
];

export default function Response() {
  const { threats } = useGuardian();
  const [filter, setFilter] = useState<(typeof STATUSES)[number]>("all");

  const rows = useMemo(() => {
    const out: Array<{ reportId: string; exe: string; pid: number; ts: number; actionIndex: number; status: ActionStatus; actionType: string; description: string; destructive: boolean }> = [];
    for (const t of threats) {
      t.actions.forEach((a, i) => {
        out.push({
          reportId: t.report_id,
          exe: t.detection.exe,
          pid: t.detection.pid,
          ts: t.timestamp,
          actionIndex: i,
          status: a.status,
          actionType: a.action_type,
          description: a.description,
          destructive: a.destructive,
        });
      });
    }
    out.sort((a, b) => b.ts - a.ts);
    if (filter !== "all") return out.filter((r) => r.status === filter);
    return out;
  }, [threats, filter]);

  return (
    <>
      <PageMeta
        title="Response"
        description="Recommended and executed response actions, approval-gated."
      />
      <PageHeader
        title="Response"
        description="Recommended corrective actions. Destructive actions never run without explicit approval."
        actions={
          <div className="flex flex-wrap gap-1.5">
            {STATUSES.map((s) => (
              <button
                key={s}
                onClick={() => setFilter(s)}
                className={`rounded-md px-2.5 py-1 text-xs font-medium transition-colors ${
                  filter === s
                    ? "bg-gray-900 text-white dark:bg-gray-100 dark:text-gray-900"
                    : "border border-gray-200 text-gray-600 hover:bg-gray-100 dark:border-gray-800 dark:text-gray-300 dark:hover:bg-gray-800"
                }`}
              >
                {s}
              </button>
            ))}
          </div>
        }
      />

      <Panel title={`Response actions (${rows.length})`}>
        {rows.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="border-b border-gray-200 text-[11px] uppercase tracking-wide text-gray-400 dark:border-gray-800">
                  <th className="py-2 pr-3">Action</th>
                  <th className="py-2 pr-3">Target</th>
                  <th className="py-2 pr-3">Status</th>
                  <th className="py-2 pr-3">Report</th>
                  <th className="py-2">When</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <tr
                    key={`${r.reportId}-${r.actionIndex}`}
                    className="border-b border-gray-100 last:border-0 dark:border-gray-800/60"
                  >
                    <td className="py-2 pr-3">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-xs font-semibold text-gray-800 dark:text-gray-100">
                          {r.actionType}
                        </span>
                        {r.destructive && (
                          <ToneBadge tone="red" className="text-[10px]">
                            destructive
                          </ToneBadge>
                        )}
                      </div>
                      <p className="mt-0.5 max-w-[300px] truncate text-[11px] text-gray-400">
                        {r.description}
                      </p>
                    </td>
                    <td className="py-2 pr-3 font-mono text-xs text-gray-500">
                      {shortExe(r.exe)} · pid {r.pid}
                    </td>
                    <td className="py-2 pr-3">
                      <ToneBadge tone={ACTION_STATUS_TONE[r.status]}>{r.status}</ToneBadge>
                    </td>
                    <td className="py-2 pr-3">
                      <Link
                        to={`/threats/${r.reportId}`}
                        className="font-mono text-xs text-brand-600 hover:underline dark:text-brand-400"
                      >
                        {r.reportId}
                      </Link>
                    </td>
                    <td className="py-2 text-xs text-gray-400">{formatRelative(r.ts)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState
            title="No response actions"
            detail="Response actions are generated from the playbook when behavior is flagged."
          />
        )}
      </Panel>
    </>
  );
}
