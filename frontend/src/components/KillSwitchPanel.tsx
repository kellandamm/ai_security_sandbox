import { useState, useEffect, useCallback } from "react";
import { Zap, Power, RefreshCw, ShieldOff } from "lucide-react";
import { KillSwitch, KillSwitchesResponse } from "../types";
import clsx from "clsx";

interface Props {
  apiBase?: string;
  getAuthHeaders?: () => Promise<Record<string, string>>;
}

const SCOPE_LABELS: Record<string, string> = {
  global: "Global",
  capability: "Capability",
  "agent-type": "Agent Type",
};

const SCOPE_COLORS: Record<string, string> = {
  global: "badge-red",
  capability: "badge-orange",
  "agent-type": "badge-blue",
};

const DEFAULT_SWITCHES: KillSwitch[] = [
  {
    name: "agent-execution-enabled",
    label: "Agent Execution",
    enabled: true,
    description: "Global master switch — disabling halts ALL agent runs within 10 seconds.",
    scope: "global",
  },
  {
    name: "file-write-enabled",
    label: "File Write",
    enabled: true,
    description: "Controls whether agents may write files to the sandbox workspace.",
    scope: "capability",
  },
  {
    name: "network-egress-enabled",
    label: "Network Egress",
    enabled: true,
    description: "Enables or disables all outbound HTTP calls from agents.",
    scope: "capability",
  },
  {
    name: "openai-calls-enabled",
    label: "OpenAI Calls",
    enabled: true,
    description: "Gates all Azure OpenAI inference calls. Disable to cut spend instantly.",
    scope: "capability",
  },
  {
    name: "agent-data-analyst-enabled",
    label: "Data Analyst Agent",
    enabled: true,
    description: "Per-agent-type kill switch for the data-analyst agent.",
    scope: "agent-type",
  },
  {
    name: "agent-web-researcher-enabled",
    label: "Web Researcher Agent",
    enabled: true,
    description: "Per-agent-type kill switch for the web-researcher agent.",
    scope: "agent-type",
  },
];

export default function KillSwitchPanel({ apiBase = "/api", getAuthHeaders }: Props) {
  const [switches, setSwitches] = useState<KillSwitch[]>(DEFAULT_SWITCHES);
  const [loading, setLoading] = useState(false);
  const [toggling, setToggling] = useState<string | null>(null);
  const [lastAction, setLastAction] = useState<string | null>(null);

  const fetchSwitches = useCallback(async () => {
    setLoading(true);
    try {
      const authHeaders = getAuthHeaders ? await getAuthHeaders() : {};
      const resp = await fetch(`${apiBase}/kill-switches`, { headers: authHeaders });
      if (resp.ok) {
        const data = (await resp.json()) as KillSwitchesResponse;
        if (data.flags.length > 0) setSwitches(data.flags);
      }
    } catch {
      // keep defaults
    } finally {
      setLoading(false);
    }
  }, [apiBase, getAuthHeaders]);

  useEffect(() => {
    fetchSwitches();
  }, [fetchSwitches]);

  async function handleToggle(sw: KillSwitch) {
    setToggling(sw.name);
    const newEnabled = !sw.enabled;
    try {
      const authHeaders = getAuthHeaders ? await getAuthHeaders() : {};
      const resp = await fetch(`${apiBase}/kill-switches/${sw.name}`, {
        method: "PUT",
        headers: { ...authHeaders, "Content-Type": "application/json" },
        body: JSON.stringify({ enabled: newEnabled }),
      });

      if (resp.ok) {
        setSwitches((prev) =>
          prev.map((s) => (s.name === sw.name ? { ...s, enabled: newEnabled } : s))
        );
        setLastAction(
          `${sw.label} ${newEnabled ? "ENABLED" : "DISABLED"} at ${new Date().toLocaleTimeString()}`
        );
      }
    } catch {
      setLastAction(`Failed to toggle ${sw.label}`);
    } finally {
      setToggling(null);
    }
  }

  const disabledCount = switches.filter((s) => !s.enabled).length;
  const globalKilled = switches.find((s) => s.scope === "global")?.enabled === false;

  return (
    <div className="panel flex flex-col h-full">
      <div className="panel-header">
        <div className="flex items-center gap-2">
          <Zap className="w-4 h-4 text-soc-yellow" />
          <span className="font-semibold text-soc-text">Kill Switches</span>
          {disabledCount > 0 && (
            <span className="badge badge-orange">{disabledCount} off</span>
          )}
          {globalKilled && (
            <span className="badge badge-red flex items-center gap-1">
              <ShieldOff className="w-3 h-3" /> SANDBOX HALTED
            </span>
          )}
        </div>
        <button
          className={clsx(
            "p-1.5 rounded hover:bg-soc-accent text-soc-muted hover:text-soc-text transition-colors",
            loading && "animate-spin"
          )}
          onClick={fetchSwitches}
          disabled={loading}
          title="Refresh kill switch states"
        >
          <RefreshCw className="w-3.5 h-3.5" />
        </button>
      </div>

      {/* App Configuration badge */}
      <div className="px-4 py-2 border-b border-soc-border bg-blue-500/5">
        <p className="text-xs text-soc-muted">
          Backed by{" "}
          <span className="text-soc-cyan">Azure App Configuration</span> ·{" "}
          10s TTL cache · Fail-closed on unreachable
        </p>
      </div>

      <div className="flex-1 overflow-y-auto divide-y divide-soc-border">
        {switches.map((sw) => (
          <div
            key={sw.name}
            className={clsx(
              "px-4 py-3 flex items-start gap-3 hover:bg-soc-accent/20 transition-colors",
              !sw.enabled && "bg-red-500/5"
            )}
          >
            {/* Toggle */}
            <button
              className={clsx(
                "relative inline-flex h-5 w-9 items-center rounded-full transition-all duration-200 shrink-0 mt-0.5",
                sw.enabled ? "bg-soc-green" : "bg-soc-muted",
                toggling === sw.name && "opacity-50 cursor-wait"
              )}
              onClick={() => handleToggle(sw)}
              disabled={toggling !== null}
              role="switch"
              aria-checked={sw.enabled}
              aria-label={`Toggle ${sw.label}`}
            >
              <span
                className={clsx(
                  "inline-block h-3 w-3 rounded-full bg-white shadow transition-transform duration-200",
                  sw.enabled ? "translate-x-5" : "translate-x-1"
                )}
              />
            </button>

            {/* Info */}
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="font-medium text-soc-text">{sw.label}</span>
                <span className={clsx("badge", SCOPE_COLORS[sw.scope])}>
                  {SCOPE_LABELS[sw.scope]}
                </span>
                {!sw.enabled && (
                  <span className="badge badge-red flex items-center gap-1">
                    <Power className="w-2.5 h-2.5" /> OFF
                  </span>
                )}
              </div>
              <p className="text-xs text-soc-muted mt-0.5 leading-relaxed">
                {sw.description}
              </p>
              <code className="text-xs text-soc-muted/70 font-mono">{sw.name}</code>
            </div>
          </div>
        ))}
      </div>

      {/* Last action bar */}
      {lastAction && (
        <div className="px-4 py-2 border-t border-soc-border bg-soc-bg/60">
          <p className="text-xs text-soc-cyan font-mono">{lastAction}</p>
        </div>
      )}
    </div>
  );
}
