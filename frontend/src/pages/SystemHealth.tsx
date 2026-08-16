import PageMeta from "../components/common/PageMeta";
import PageHeader from "../components/ui/PageHeader";
import Panel from "../components/ui/Panel";
import ToneBadge from "../components/ui/ToneBadge";
import EmptyState from "../components/ui/EmptyState";
import { useGuardian } from "../context/GuardianContext";

function StatusRow({
  label,
  ok,
  detail,
}: {
  label: string;
  ok: boolean | null;
  detail?: string;
}) {
  return (
    <div className="flex items-center justify-between gap-3 rounded-lg border border-gray-200 px-3 py-2.5 dark:border-gray-800">
      <div>
        <p className="text-sm font-medium text-gray-800 dark:text-gray-100">{label}</p>
        {detail && <p className="text-[11px] text-gray-400">{detail}</p>}
      </div>
      {ok === null ? (
        <ToneBadge tone="gray">unknown</ToneBadge>
      ) : ok ? (
        <ToneBadge tone="green">up</ToneBadge>
      ) : (
        <ToneBadge tone="red">down</ToneBadge>
      )}
    </div>
  );
}

function Metric({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="rounded-lg border border-gray-200 px-3 py-2.5 dark:border-gray-800">
      <p className="text-[11px] uppercase tracking-wide text-gray-400">{label}</p>
      <p className="mt-1 font-mono text-sm text-gray-800 dark:text-gray-100">{value}</p>
    </div>
  );
}

export default function SystemHealth() {
  const { health, healthError, connected, refresh } = useGuardian();
  const tel = health?.telemetry;

  return (
    <>
      <PageMeta
        title="System Health"
        description="Status of the GuardianOS-AI monitoring pipeline and kernel providers."
      />
      <PageHeader
        title="System Health"
        description="Status of the GuardianOS-AI monitoring pipeline."
        actions={
          <button
            onClick={() => void refresh()}
            className="rounded-md border border-gray-200 px-3 py-1.5 text-xs font-medium text-gray-600 transition-colors hover:bg-gray-100 dark:border-gray-800 dark:text-gray-300 dark:hover:bg-gray-800"
          >
            Refresh
          </button>
        }
      />

      {healthError && (
        <div className="mb-4 rounded-md bg-error-50 px-3 py-2 text-xs text-error-700 dark:bg-error-950 dark:text-error-300">
          {healthError}
        </div>
      )}

      {!health ? (
        <Panel>
          <EmptyState
            title="No health data"
            detail="Start the engine with `python scripts/run_server.py` to see pipeline health."
          />
        </Panel>
      ) : (
        <>
          <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
            <Metric label="Learning" value={health.learning ? "baseline" : "detecting"} />
            <Metric label="Baseline chains" value={health.baseline} />
            <Metric label="Threat reports" value={health.threats} />
            <Metric label="Events in window" value={health.events_in_window} />
          </div>

          <div className="mt-4 grid gap-4 lg:grid-cols-2">
            <Panel title="Monitoring pipeline" subtitle="Detection readiness">
              <div className="space-y-2">
                <StatusRow
                  label="Stream connection"
                  detail={connected ? "WebSocket live" : "WebSocket disconnected (polling)"}
                  ok={connected}
                />
                <StatusRow
                  label="Event ingestion"
                  detail={`${health.events_in_window} events in the current analysis window`}
                  ok={health.events_in_window >= 0}
                />
                <StatusRow
                  label="Detection engine"
                  detail={
                    health.learning
                      ? "still learning the behavioral baseline"
                      : `ready (${health.baseline} baseline chains)`
                  }
                  ok={health.ready}
                />
              </div>
            </Panel>

            <Panel
              title="Kernel provider"
              subtitle={tel ? `provider: ${tel.provider}` : "no provider reported"}
            >
              {tel ? (
                <div className="space-y-2">
                  <StatusRow
                    label="Provider running"
                    detail={tel.last_error ?? undefined}
                    ok={tel.running}
                  />
                  <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
                    <Metric label="Events delivered" value={tel.events_delivered} />
                    <Metric label="Drops (total)" value={tel.drops_total} />
                    <Metric label="Drops (recent)" value={tel.drops_recent} />
                    <Metric label="Rate limited" value={tel.rate_limited} />
                    <Metric label="Restarts" value={tel.restarts} />
                    <Metric
                      label="Last collect"
                      value={tel.last_collect_at ? new Date(tel.last_collect_at * 1000).toLocaleTimeString() : "—"}
                    />
                  </div>
                  {Object.keys(tel.source).length > 0 && (
                    <div className="pt-1">
                      <p className="mb-1 text-[11px] uppercase tracking-wide text-gray-400">
                        Provider source
                      </p>
                      <pre className="overflow-x-auto rounded-md bg-gray-50 p-2 font-mono text-[11px] text-gray-600 dark:bg-gray-800 dark:text-gray-300">
                        {JSON.stringify(tel.source, null, 2)}
                      </pre>
                    </div>
                  )}
                </div>
              ) : (
                <EmptyState
                  title="No telemetry health"
                  detail="The pipeline did not report provider health."
                />
              )}
            </Panel>
          </div>

          <p className="mt-3 text-xs text-gray-400">
            CPU/memory/uptime are not currently exposed by the API; they are reported by the
            kernel providers themselves. Telemetry here reflects the real provider health.
          </p>
        </>
      )}
    </>
  );
}
