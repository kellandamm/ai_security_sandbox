import { useState, useEffect, useCallback } from "react";
import { Bell, RefreshCw, ExternalLink, ChevronDown } from "lucide-react";
import { AlertSeverity, AlertsResponse, SentinelAlert } from "../types";
import clsx from "clsx";

interface Props {
  apiBase?: string;
  getAuthHeaders?: () => Promise<Record<string, string>>;
}

const SEVERITY_COLORS: Record<AlertSeverity, string> = {
  High: "border-soc-red text-soc-red bg-red-500/10",
  Medium: "border-soc-orange text-soc-orange bg-orange-500/10",
  Low: "border-soc-yellow text-soc-yellow bg-yellow-500/10",
  Informational: "border-soc-blue text-soc-blue bg-blue-500/10",
};

const SEVERITY_DOT: Record<AlertSeverity, string> = {
  High: "bg-soc-red animate-pulse",
  Medium: "bg-soc-orange animate-pulse",
  Low: "bg-soc-yellow",
  Informational: "bg-soc-blue",
};

const TACTIC_COLORS: Record<string, string> = {
  DefenseEvasion: "badge-orange",
  Impact: "badge-red",
  Persistence: "badge-red",
  Exfiltration: "badge-red",
  Discovery: "badge-yellow",
  Execution: "badge-orange",
  LateralMovement: "badge-red",
};

function formatRelative(ts: string): string {
  const diff = Date.now() - new Date(ts).getTime();
  if (diff < 60_000) return `${Math.round(diff / 1000)}s ago`;
  if (diff < 3_600_000) return `${Math.round(diff / 60_000)}m ago`;
  return `${Math.round(diff / 3_600_000)}h ago`;
}

function AlertCard({ alert, defaultOpen }: { alert: SentinelAlert; defaultOpen?: boolean }) {
  const [open, setOpen] = useState(defaultOpen ?? false);

  const tactics = alert.tactics
    .split(",")
    .map((t) => t.trim())
    .filter(Boolean);

  return (
    <div
      className={clsx(
        "rounded-lg border-l-4 bg-soc-panel overflow-hidden animate-fade-in",
        SEVERITY_COLORS[alert.severity]
      )}
    >
      <button
        className="w-full text-left px-4 py-3 flex items-start gap-3"
        onClick={() => setOpen(!open)}
      >
        <span
          className={clsx("pulse-dot mt-1.5 shrink-0", SEVERITY_DOT[alert.severity])}
        />
        <div className="flex-1 min-w-0">
          <div className="flex items-center justify-between gap-2">
            <span className="font-medium text-soc-text text-sm truncate">{alert.name}</span>
            <span className="text-xs text-soc-muted shrink-0">
              {formatRelative(alert.timestamp)}
            </span>
          </div>
          <div className="flex items-center gap-2 mt-1 flex-wrap">
            <span
              className={clsx(
                "badge text-xs border",
                SEVERITY_COLORS[alert.severity]
              )}
            >
              {alert.severity}
            </span>
            {tactics.map((tactic) => (
              <span
                key={tactic}
                className={clsx(
                  "badge text-xs",
                  TACTIC_COLORS[tactic] ?? "badge-gray"
                )}
              >
                {tactic}
              </span>
            ))}
          </div>
        </div>
        <ChevronDown
          className={clsx(
            "w-4 h-4 text-soc-muted shrink-0 transition-transform",
            open && "rotate-180"
          )}
        />
      </button>

      {open && (
        <div className="px-4 pb-3 space-y-2 animate-fade-in">
          <p className="text-xs text-soc-muted leading-relaxed">{alert.description}</p>
          <div className="flex items-center justify-between text-xs">
            <span className="text-soc-muted">
              Status:{" "}
              <span
                className={clsx(
                  "font-medium",
                  alert.status === "New" && "text-soc-orange",
                  alert.status === "Active" && "text-soc-red",
                  alert.status === "Closed" && "text-soc-green"
                )}
              >
                {alert.status}
              </span>
            </span>
            <span className="text-soc-muted font-mono">{alert.id}</span>
          </div>
        </div>
      )}
    </div>
  );
}

export default function SecurityEventFeed({ apiBase = "/api", getAuthHeaders }: Props) {
  const [alerts, setAlerts] = useState<SentinelAlert[]>([]);
  const [loading, setLoading] = useState(false);
  const [lastFetched, setLastFetched] = useState<Date | null>(null);

  const fetchAlerts = useCallback(async () => {
    setLoading(true);
    try {
      const authHeaders = getAuthHeaders ? await getAuthHeaders() : {};
      const resp = await fetch(`${apiBase}/alerts`, { headers: authHeaders });
      if (resp.ok) {
        const data = (await resp.json()) as AlertsResponse;
        setAlerts(data.alerts);
        setLastFetched(new Date());
      }
    } catch {
      // network error — keep stale data
    } finally {
      setLoading(false);
    }
  }, [apiBase, getAuthHeaders]);

  // Auto-refresh every 30 seconds
  useEffect(() => {
    fetchAlerts();
    const interval = setInterval(fetchAlerts, 30_000);
    return () => clearInterval(interval);
  }, [fetchAlerts]);

  const highCount = alerts.filter((a) => a.severity === "High").length;
  const medCount = alerts.filter((a) => a.severity === "Medium").length;

  return (
    <div className="panel flex flex-col h-full">
      <div className="panel-header">
        <div className="flex items-center gap-2">
          <Bell className="w-4 h-4 text-soc-orange" />
          <span className="font-semibold text-soc-text">Sentinel Alerts</span>
          {highCount > 0 && (
            <span className="badge badge-red">{highCount} high</span>
          )}
          {medCount > 0 && (
            <span className="badge badge-orange">{medCount} medium</span>
          )}
        </div>
        <div className="flex items-center gap-2">
          {lastFetched && (
            <span className="text-xs text-soc-muted">
              {formatRelative(lastFetched.toISOString())}
            </span>
          )}
          <button
            className={clsx(
              "p-1.5 rounded hover:bg-soc-accent text-soc-muted hover:text-soc-text transition-colors",
              loading && "animate-spin"
            )}
            onClick={fetchAlerts}
            disabled={loading}
            title="Refresh alerts"
          >
            <RefreshCw className="w-3.5 h-3.5" />
          </button>
          <a
            href="https://portal.azure.com/#blade/Microsoft_Azure_Security_Insights/MainMenuBlade"
            target="_blank"
            rel="noopener noreferrer"
            className="p-1.5 rounded hover:bg-soc-accent text-soc-muted hover:text-soc-text transition-colors"
            title="Open Microsoft Sentinel"
          >
            <ExternalLink className="w-3.5 h-3.5" />
          </a>
        </div>
      </div>

      {/* Sentinel info banner */}
      <div className="px-4 py-2 border-b border-soc-border bg-blue-500/5">
        <p className="text-xs text-soc-muted">
          Connected to{" "}
          <span className="text-soc-cyan">Microsoft Sentinel</span> ·{" "}
          <span className="text-soc-blue">AiAgentAudit_CL</span> · 4 analytics rules active
        </p>
      </div>

      <div className="flex-1 overflow-y-auto p-3 space-y-3">
        {loading && alerts.length === 0 && (
          <div className="flex items-center justify-center h-24 text-soc-muted text-xs">
            <RefreshCw className="w-4 h-4 animate-spin mr-2" /> Fetching Sentinel alerts…
          </div>
        )}

        {!loading && alerts.length === 0 && (
          <div className="flex flex-col items-center justify-center h-24 text-soc-muted gap-2">
            <Bell className="w-6 h-6 opacity-30" />
            <span className="text-xs">No alerts — sandbox is quiet</span>
          </div>
        )}

        {alerts.map((alert, i) => (
          <AlertCard key={alert.id} alert={alert} defaultOpen={i === 0} />
        ))}
      </div>

      {/* Legend */}
      <div className="panel-header border-t border-b-0 text-xs text-soc-muted">
        <div className="flex gap-3">
          <span className="flex items-center gap-1">
            <span className="pulse-dot bg-soc-red" /> High
          </span>
          <span className="flex items-center gap-1">
            <span className="pulse-dot bg-soc-orange" /> Medium
          </span>
          <span className="flex items-center gap-1">
            <span className="pulse-dot bg-soc-yellow" /> Low
          </span>
        </div>
        <span>Auto-refresh 30s</span>
      </div>
    </div>
  );
}
