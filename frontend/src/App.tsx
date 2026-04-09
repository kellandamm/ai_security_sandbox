import { useState, useCallback, useRef } from "react";
import {
  Shield,
  Activity,
  LayoutDashboard,
  Layers,
  Info,
  CheckCircle,
  XCircle,
} from "lucide-react";
import AttackLibrary from "./components/AttackLibrary";
import ExecutionTrace from "./components/ExecutionTrace";
import SecurityEventFeed from "./components/SecurityEventFeed";
import KillSwitchPanel from "./components/KillSwitchPanel";
import { useSSE } from "./hooks/useSSE";
import { AttackTemplate, TimelineResponse } from "./types";
import clsx from "clsx";

// In production, VITE_API_BASE is set to the backend URL.
// During local dev the Vite proxy rewrites /api → http://localhost:8000.
const API_BASE = import.meta.env.VITE_API_BASE ?? "/api";

type View = "dashboard" | "trace" | "alerts" | "switches";

const NAV_ITEMS: { id: View; label: string; icon: React.ElementType }[] = [
  { id: "dashboard", label: "Dashboard", icon: LayoutDashboard },
  { id: "trace", label: "Execution Trace", icon: Layers },
  { id: "alerts", label: "Sentinel Alerts", icon: Activity },
  { id: "switches", label: "Kill Switches", icon: Shield },
];

interface ToastProps {
  message: string;
  type: "success" | "error";
}

function Toast({ message, type }: ToastProps) {
  return (
    <div
      className={clsx(
        "fixed bottom-6 right-6 z-50 flex items-center gap-2 px-4 py-3 rounded-lg border text-sm shadow-xl animate-slide-in",
        type === "success"
          ? "bg-green-900/80 border-green-700 text-green-200"
          : "bg-red-900/80 border-red-700 text-red-200"
      )}
    >
      {type === "success" ? (
        <CheckCircle className="w-4 h-4 text-green-400" />
      ) : (
        <XCircle className="w-4 h-4 text-red-400" />
      )}
      {message}
    </div>
  );
}

export default function App() {
  const [view, setView] = useState<View>("dashboard");
  const [activeRunId, setActiveRunId] = useState<string | null>(null);
  const [isRunning, setIsRunning] = useState(false);
  const [toast, setToast] = useState<ToastProps | null>(null);
  const [kqlQuery, setKqlQuery] = useState<string | undefined>(undefined);
  const toastTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const { events, status, connected } = useSSE(activeRunId, API_BASE);

  function showToast(message: string, type: "success" | "error") {
    setToast({ message, type });
    if (toastTimer.current) clearTimeout(toastTimer.current);
    toastTimer.current = setTimeout(() => setToast(null), 5000);
  }

  // Fetch KQL / Log Analytics timeline once run completes
  const fetchTimeline = useCallback(
    async (runId: string) => {
      try {
        const resp = await fetch(`${API_BASE}/runs/${runId}/timeline`);
        if (resp.ok) {
          const data = (await resp.json()) as TimelineResponse;
          setKqlQuery(data.kql_query);
        }
      } catch {
        // non-critical — KQL display is best-effort
      }
    },
    []
  );

  // Called when the run completes
  const handleRunComplete = useCallback(
    (runId: string) => {
      setIsRunning(false);
      fetchTimeline(runId);
    },
    [fetchTimeline]
  );

  // Track status transitions
  const prevStatusRef = useRef<typeof status>(null);
  if (status !== prevStatusRef.current) {
    prevStatusRef.current = status;
    if (status === "completed" || status === "failed" || status === "killed") {
      if (activeRunId) handleRunComplete(activeRunId);
    }
  }

  const handleLaunch = useCallback(
    async (template: AttackTemplate, file: File | null) => {
      setIsRunning(true);
      setKqlQuery(undefined);
      setActiveRunId(null);

      try {
        let body: BodyInit;
        let headers: HeadersInit = {};

        if (file) {
          const fd = new FormData();
          fd.append("agent_type", template.agentType);
          fd.append("task", template.task);
          fd.append("file", file);
          body = fd;
          // Don't set Content-Type for FormData — browser sets it with boundary
        } else {
          body = JSON.stringify({
            agent_type: template.agentType,
            task: template.task,
          });
          headers = { "Content-Type": "application/json" };
        }

        const resp = await fetch(`${API_BASE}/runs`, {
          method: "POST",
          headers,
          body,
        });

        if (!resp.ok) {
          const err = await resp.text();
          showToast(`Run failed to start: ${resp.status} ${err}`, "error");
          setIsRunning(false);
          return;
        }

        const data = await resp.json();
        const runId: string = data.run_id;
        setActiveRunId(runId);
        setView("trace");
        showToast(`Run started: ${runId.slice(0, 8)}…`, "success");
      } catch (err) {
        showToast(`Network error: ${String(err)}`, "error");
        setIsRunning(false);
      }
    },
    []
  );

  return (
    <div className="h-screen flex flex-col bg-soc-bg overflow-hidden">
      {/* Top bar */}
      <header className="shrink-0 border-b border-soc-border bg-soc-panel">
        <div className="flex items-center h-12 px-4 gap-4">
          {/* Logo */}
          <div className="flex items-center gap-2">
            <Shield className="w-5 h-5 text-soc-blue" />
            <span className="font-bold text-soc-text text-sm tracking-tight">
              AI Security Sandbox
            </span>
            <span className="badge badge-blue text-xs hidden sm:inline-flex">SOC Console</span>
          </div>

          {/* Nav */}
          <nav className="flex items-center gap-1 ml-4">
            {NAV_ITEMS.map((item) => {
              const Icon = item.icon;
              return (
                <button
                  key={item.id}
                  onClick={() => setView(item.id)}
                  className={clsx(
                    "flex items-center gap-1.5 px-3 py-1.5 rounded text-sm transition-colors",
                    view === item.id
                      ? "bg-soc-blue text-white"
                      : "text-soc-muted hover:text-soc-text hover:bg-soc-accent"
                  )}
                >
                  <Icon className="w-3.5 h-3.5" />
                  <span className="hidden sm:inline">{item.label}</span>
                </button>
              );
            })}
          </nav>

          <div className="ml-auto flex items-center gap-3 text-xs text-soc-muted">
            {isRunning && (
              <span className="flex items-center gap-1.5 text-soc-orange">
                <span className="pulse-dot bg-soc-orange animate-pulse" />
                Agent running
              </span>
            )}
            {!isRunning && activeRunId && status && (
              <span
                className={clsx(
                  "flex items-center gap-1.5",
                  status === "completed" ? "text-soc-green" : "text-soc-red"
                )}
              >
                <span
                  className={clsx(
                    "pulse-dot",
                    status === "completed" ? "bg-soc-green" : "bg-soc-red"
                  )}
                />
                {status}
              </span>
            )}
            <span className="hidden md:inline text-soc-muted">
              Azure Container Apps · OPA · Sentinel
            </span>
          </div>
        </div>
      </header>

      {/* Main content */}
      <main className="flex-1 overflow-hidden">
        {view === "dashboard" && (
          <div className="h-full grid grid-cols-1 lg:grid-cols-2 gap-0 divide-x divide-soc-border">
            <AttackLibrary onLaunch={handleLaunch} isRunning={isRunning} />
            <ExecutionTrace
              runId={activeRunId}
              events={events}
              status={status}
              connected={connected}
              kqlQuery={kqlQuery}
            />
          </div>
        )}

        {view === "trace" && (
          <div className="h-full flex flex-col">
            <div className="h-full">
              <ExecutionTrace
                runId={activeRunId}
                events={events}
                status={status}
                connected={connected}
                kqlQuery={kqlQuery}
              />
            </div>
          </div>
        )}

        {view === "alerts" && (
          <div className="h-full">
            <SecurityEventFeed apiBase={API_BASE} />
          </div>
        )}

        {view === "switches" && (
          <div className="h-full">
            <KillSwitchPanel apiBase={API_BASE} />
          </div>
        )}
      </main>

      {/* Legend bar */}
      <footer className="shrink-0 border-t border-soc-border bg-soc-panel px-4 py-1.5 flex items-center justify-between text-xs text-soc-muted">
        <div className="flex items-center gap-4">
          <span className="flex items-center gap-1">
            <span className="w-2 h-2 rounded-full bg-soc-green" /> ALLOW
          </span>
          <span className="flex items-center gap-1">
            <span className="w-2 h-2 rounded-full bg-soc-red" /> DENY
          </span>
          <span className="flex items-center gap-1">
            <span className="w-2 h-2 rounded-full bg-soc-orange" /> APPROVAL REQUIRED
          </span>
        </div>
        <div className="flex items-center gap-1 text-soc-muted/60">
          <Info className="w-3 h-3" />
          <span>
            Security events flow: Agent → OPA sidecar → Log Analytics → Sentinel
          </span>
        </div>
      </footer>

      {/* Toast notification */}
      {toast && <Toast message={toast.message} type={toast.type} />}
    </div>
  );
}
