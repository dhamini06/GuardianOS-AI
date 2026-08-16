import { useEffect, useState } from "react";
import PageMeta from "../components/common/PageMeta";
import PageHeader from "../components/ui/PageHeader";
import Panel from "../components/ui/Panel";
import { getToken, setToken } from "../api/client";
import { useGuardian } from "../context/GuardianContext";

export default function Settings() {
  const { connected, refresh } = useGuardian();
  const [token, setTokenValue] = useState(getToken() ?? "");

  useEffect(() => {
    setTokenValue(getToken() ?? "");
  }, []);

  const saveToken = () => {
    setToken(token.trim());
    // allow state to settle, then reconnect
    setTimeout(() => void refresh(), 100);
  };

  const clearToken = () => {
    setToken("");
    setTokenValue("");
  };

  return (
    <>
      <PageMeta title="Settings" description="Connection and authentication settings." />
      <PageHeader
        title="Settings"
        description="Client connection settings for the GuardianOS-AI engine."
      />

      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Engine connection" subtitle="Live status">
          <div className="space-y-3 text-sm">
            <div className="flex items-center justify-between">
              <span className="text-gray-600 dark:text-gray-300">WebSocket</span>
              <span className={connected ? "text-success-600" : "text-warning-600"}>
                {connected ? "connected" : "disconnected (polling)"}
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-gray-600 dark:text-gray-300">API base</span>
              <span className="font-mono text-xs text-gray-400">{window.location.origin}</span>
            </div>
          </div>
        </Panel>

        <Panel
          title="API token"
          subtitle="Optional X-GUARDIAN-TOKEN sent with REST calls and /api/ws"
        >
          <div className="space-y-3">
            <input
              type="password"
              value={token}
              onChange={(e) => setTokenValue(e.target.value)}
              placeholder="Guardian API token"
              className="w-full rounded-lg border border-gray-200 bg-white px-3 py-2 font-mono text-sm text-gray-700 placeholder:text-gray-400 focus:border-brand-300 focus:outline-none dark:border-gray-800 dark:bg-gray-900 dark:text-gray-200"
            />
            <div className="flex gap-2">
              <button
                onClick={saveToken}
                className="rounded-md bg-brand-600 px-3 py-1.5 text-xs font-medium text-white transition-colors hover:bg-brand-700"
              >
                Save & reconnect
              </button>
              <button
                onClick={clearToken}
                className="rounded-md border border-gray-300 px-3 py-1.5 text-xs font-medium text-gray-600 transition-colors hover:bg-gray-100 dark:border-gray-700 dark:text-gray-300 dark:hover:bg-gray-800"
              >
                Clear
              </button>
            </div>
            <p className="text-[11px] text-gray-400">
              The token is stored in localStorage on this browser only. When the engine runs
              without auth (`auth.enabled: false`) no token is required.
            </p>
          </div>
        </Panel>
      </div>
    </>
  );
}
