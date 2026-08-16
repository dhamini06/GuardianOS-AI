import { useEffect, useMemo, useState } from "react";
import PageMeta from "../components/common/PageMeta";
import PageHeader from "../components/ui/PageHeader";
import Panel from "../components/ui/Panel";
import EmptyState from "../components/ui/EmptyState";
import { useGuardian } from "../context/GuardianContext";
import { formatTime, shortExe } from "../lib/format";
import type { EventKind } from "../api/types";

const EVENT_KINDS: Array<EventKind | "all"> = [
  "all",
  "process_created",
  "exec",
  "network_connect",
  "file_write",
  "file_read",
  "privilege_escalation",
  "process_exited",
  "socket_bind",
  "module_load",
  "authentication",
  "signal",
];

export default function KernelActivity() {
  const { events, eventsError, refresh } = useGuardian();
  const [kind, setKind] = useState<(typeof EVENT_KINDS)[number]>("all");
  const [search, setSearch] = useState("");

  useEffect(() => {
    const t = setInterval(() => void refresh(), 5_000);
    return () => clearInterval(t);
  }, [refresh]);

  const filtered = useMemo(() => {
    let list = events;
    if (kind !== "all") list = list.filter((e) => e.kind === kind);
    if (search.trim()) {
      const q = search.trim().toLowerCase();
      list = list.filter(
        (e) =>
          e.exe.toLowerCase().includes(q) ||
          String(e.pid).includes(q) ||
          (e.details && JSON.stringify(e.details).toLowerCase().includes(q)),
      );
    }
    return list;
  }, [events, kind, search]);

  return (
    <>
      <PageMeta
        title="Kernel Activity"
        description="Raw kernel-level telemetry from the audit/eBPF/process providers."
      />
      <PageHeader
        title="Kernel Activity"
        description="Raw telemetry stream as collected from the kernel providers."
        actions={
          <button
            onClick={() => void refresh()}
            className="rounded-md border border-gray-200 px-3 py-1.5 text-xs font-medium text-gray-600 transition-colors hover:bg-gray-100 dark:border-gray-800 dark:text-gray-300 dark:hover:bg-gray-800"
          >
            Refresh
          </button>
        }
      />

      <Panel
        title="Telemetry stream"
        subtitle={`${filtered.length} events shown${kind !== "all" ? ` · kind: ${kind}` : ""}`}
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <select
              value={kind}
              onChange={(e) => setKind(e.target.value as (typeof EVENT_KINDS)[number])}
              className="rounded-lg border border-gray-200 bg-white px-2.5 py-1.5 text-xs text-gray-700 focus:outline-none dark:border-gray-800 dark:bg-gray-900 dark:text-gray-200"
            >
              {EVENT_KINDS.map((k) => (
                <option key={k} value={k}>
                  {k}
                </option>
              ))}
            </select>
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search pid / exe / details…"
              className="w-52 rounded-lg border border-gray-200 bg-white px-2.5 py-1.5 text-xs text-gray-700 placeholder:text-gray-400 focus:outline-none dark:border-gray-800 dark:bg-gray-900 dark:text-gray-200"
            />
          </div>
        }
      >
        {filtered.length > 0 ? (
          <div className="max-h-[65vh] overflow-auto">
            <table className="w-full text-left text-sm">
              <thead className="sticky top-0 bg-white dark:bg-gray-900">
                <tr className="border-b border-gray-200 text-[11px] uppercase tracking-wide text-gray-400 dark:border-gray-800">
                  <th className="py-2 pr-3">Time</th>
                  <th className="py-2 pr-3">PID</th>
                  <th className="py-2 pr-3">Process</th>
                  <th className="py-2 pr-3">Event</th>
                  <th className="py-2 pr-3">Command</th>
                  <th className="py-2">Detail</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((e) => (
                  <tr
                    key={e.event_id}
                    className="border-b border-gray-100 align-top last:border-0 dark:border-gray-800/60"
                  >
                    <td className="py-2 pr-3 whitespace-nowrap font-mono text-xs text-gray-400">
                      {formatTime(e.timestamp)}
                    </td>
                    <td className="py-2 pr-3 font-mono text-xs text-gray-500">{e.pid}</td>
                    <td className="py-2 pr-3 font-mono text-xs text-gray-700 dark:text-gray-300">
                      {shortExe(e.exe)}
                    </td>
                    <td className="py-2 pr-3">
                      <span
                        className={`rounded px-1.5 py-0.5 font-mono text-[11px] ${
                          e.kind === "privilege_escalation"
                            ? "bg-error-50 text-error-700 dark:bg-error-950 dark:text-error-300"
                            : e.kind === "network_connect"
                              ? "bg-blue-light-50 text-blue-light-700 dark:bg-blue-light-950 dark:text-blue-light-300"
                              : e.kind === "file_write"
                                ? "bg-warning-50 text-warning-700 dark:bg-warning-950 dark:text-warning-300"
                                : "bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400"
                        }`}
                      >
                        {e.kind}
                      </span>
                    </td>
                    <td className="max-w-[240px] truncate py-2 pr-3 font-mono text-xs text-gray-500 dark:text-gray-400">
                      {e.cmdline?.slice(0, 3).join(" ") || shortExe(e.exe)}
                    </td>
                    <td className="max-w-[260px] truncate py-2 font-mono text-[11px] text-gray-400">
                      {e.details ? JSON.stringify(e.details) : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState
            title="No events match"
            detail={eventsError ?? "Try clearing the filter, or confirm the engine is running."}
          />
        )}
      </Panel>
    </>
  );
}
