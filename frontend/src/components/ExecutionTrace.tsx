import { useRef, useEffect } from "react";
import {
  Terminal,
  CheckCircle,
  XCircle,
  Clock,
  AlertTriangle,
  Lock,
  Cpu,
  Globe,
  FileText,
  Zap,
} from "lucide-react";
import { AuditEvent, ActionType, PolicyDecision, Outcome, RunStatus } from "../types";
import clsx from "clsx";

interface Props {
  runId: string | null;
  events: AuditEvent[];
  status: RunStatus | null;
  connected: boolean;
  kqlQuery?: string;
  strictMode?: boolean;
  expectedBlocks?: string[];
  scenarioName?: string;
}

type StrictVerdict = "pending" | "blocked" | "failed_safe" | "inconclusive";

const ACTION_ICONS: Record<ActionType, React.ElementType> = {
  file_read: FileText,
  file_write: FileText,
  file_delete: FileText,
  network_call: Globe,
  openai_call: Cpu,
  http_get: Globe,
  http_post: Globe,
  kill_switch_check: Zap,
  policy_check: Lock,
  approval_request: AlertTriangle,
  approval_response: AlertTriangle,
  run_start: Clock,
  run_complete: CheckCircle,
  run_abort: XCircle,
};

const DECISION_COLORS: Record<PolicyDecision, string> = {
  allow: "text-soc-green",
  deny: "text-soc-red",
  requires_approval: "text-soc-orange",
};

const OUTCOME_ICONS: Record<Outcome, React.ElementType> = {
  success: CheckCircle,
  failure: XCircle,
  blocked: XCircle,
  timeout: Clock,
};

const OUTCOME_COLORS: Record<Outcome, string> = {
  success: "text-soc-green",
  failure: "text-soc-red",
  blocked: "text-soc-red",
  timeout: "text-soc-orange",
};

function formatTime(ts: string): string {
  const d = new Date(ts);
  return d.toLocaleTimeString("en-GB", { hour12: false }) + "." + String(d.getMilliseconds()).padStart(3, "0");
}

function EventRow({ event, index }: { event: AuditEvent; index: number }) {
  const ActionIcon = ACTION_ICONS[event.action_type] ?? FileText;
  const OutcomeIcon = OUTCOME_ICONS[event.outcome] ?? CheckCircle;

  const isBlocked = event.outcome === "blocked" || event.policy_decision === "deny";

  return (
    <div
      className={clsx(
        "event-row animate-slide-in",
        isBlocked && "border-l-2 border-soc-red bg-red-500/5"
      )}
    >
      {/* Index */}
      <span className="text-xs text-soc-muted w-5 shrink-0 pt-0.5 text-right">{index + 1}</span>

      {/* Timestamp */}
      <span className="text-xs font-mono text-soc-muted shrink-0 pt-0.5">
        {formatTime(event.timestamp)}
      </span>

      {/* Action icon */}
      <ActionIcon
        className={clsx(
          "w-3.5 h-3.5 shrink-0 mt-0.5",
          DECISION_COLORS[event.policy_decision]
        )}
      />

      {/* Main content */}
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-soc-text font-medium">
            {event.action_type.replace(/_/g, " ")}
          </span>

          {/* Policy decision badge */}
          <span
            className={clsx(
              "text-xs px-1.5 py-0.5 rounded border font-mono",
              event.policy_decision === "allow" &&
                "bg-green-500/10 border-green-500/30 text-green-400",
              event.policy_decision === "deny" &&
                "bg-red-500/10 border-red-500/30 text-red-400",
              event.policy_decision === "requires_approval" &&
                "bg-orange-500/10 border-orange-500/30 text-orange-400"
            )}
          >
            {event.policy_decision}
          </span>

          {/* Risk score */}
          {event.risk_score > 0 && (
            <span
              className={clsx(
                "text-xs px-1.5 py-0.5 rounded font-mono",
                event.risk_score >= 0.7 && "text-soc-red",
                event.risk_score >= 0.4 && event.risk_score < 0.7 && "text-soc-orange",
                event.risk_score < 0.4 && "text-soc-muted"
              )}
            >
              risk: {event.risk_score.toFixed(2)}
            </span>
          )}
        </div>

        {/* Path or destination */}
        {(event.path || event.destination) && (
          <div className="text-xs text-soc-muted font-mono mt-0.5 truncate">
            {event.path && <span className="text-soc-cyan">{event.path}</span>}
            {event.destination && (
              <span className="text-soc-orange"> → {event.destination}</span>
            )}
          </div>
        )}

        {/* Error code */}
        {event.error_code && (
          <div className="text-xs text-soc-red font-mono mt-0.5">{event.error_code}</div>
        )}

        {/* Token count */}
        {event.token_count != null && event.token_count > 0 && (
          <div className="text-xs text-soc-muted mt-0.5">
            tokens: {event.token_count.toLocaleString()}
          </div>
        )}
      </div>

      {/* Outcome icon */}
      <OutcomeIcon
        className={clsx("w-3.5 h-3.5 shrink-0 mt-0.5", OUTCOME_COLORS[event.outcome])}
      />
    </div>
  );
}

export default function ExecutionTrace({
  runId,
  events,
  status,
  connected,
  kqlQuery,
  strictMode = false,
  expectedBlocks = [],
  scenarioName,
}: Props) {
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [events.length]);

  const blocked = events.filter(
    (e) => e.outcome === "blocked" || e.policy_decision === "deny"
  ).length;

  const hasBlockedEvent = blocked > 0;
  const hasInputPolicyBlock = events.some(
    (e) => (e.error_code ?? "").startsWith("input_policy_violation:")
  );
  const hasExplicitPolicyPass = events.some(
    (e) => (e.error_code ?? "") === "input_policy_passed"
  );

  let strictVerdict: StrictVerdict = "pending";
  if (status && ["completed", "failed", "killed"].includes(status)) {
    if (hasBlockedEvent || hasInputPolicyBlock) {
      strictVerdict = "blocked";
    } else if (status === "failed" || status === "killed") {
      strictVerdict = "failed_safe";
    } else {
      strictVerdict = "inconclusive";
    }
  }

  const strictBadgeClass: Record<StrictVerdict, string> = {
    pending: "badge-gray",
    blocked: "badge-red",
    failed_safe: "badge-orange",
    inconclusive: "badge-yellow",
  };

  const strictLabel: Record<StrictVerdict, string> = {
    pending: "STRICT: PENDING",
    blocked: "STRICT: BLOCKED",
    failed_safe: "STRICT: FAILED SAFE",
    inconclusive: "STRICT: INCONCLUSIVE",
  };

  return (
    <div className="panel flex flex-col h-full">
      {/* Header */}
      <div className="panel-header">
        <div className="flex items-center gap-2">
          <Terminal className="w-4 h-4 text-soc-blue" />
          <span className="font-semibold text-soc-text">Execution Trace</span>
          {strictMode && (
            <span className={`badge ${strictBadgeClass[strictVerdict]}`}>
              {strictLabel[strictVerdict]}
            </span>
          )}
          {connected && (
            <span className="flex items-center gap-1 text-xs text-soc-green">
              <span className="pulse-dot-green" />
              LIVE
            </span>
          )}
          {!connected && status && (
            <span
              className={clsx(
                "badge",
                status === "completed" ? "badge-green" : "badge-red"
              )}
            >
              {status.toUpperCase()}
            </span>
          )}
        </div>
        <div className="flex items-center gap-3 text-xs">
          <span className="text-soc-muted">{events.length} events</span>
          {blocked > 0 && (
            <span className="text-soc-red font-medium">{blocked} blocked</span>
          )}
        </div>
      </div>

      {/* Run ID bar */}
      {runId && (
        <div className="px-4 py-2 border-b border-soc-border bg-soc-bg/50">
          <span className="text-xs text-soc-muted">run_id: </span>
          <span className="text-xs font-mono text-soc-cyan">{runId}</span>
        </div>
      )}

      {strictMode && (
        <div className="px-4 py-2 border-b border-soc-border bg-soc-bg/40 space-y-1">
          <div className="text-xs text-soc-muted">
            strict scenario: <span className="text-soc-text">{scenarioName ?? "attack test"}</span>
          </div>
          {expectedBlocks.length > 0 && (
            <div className="text-xs text-soc-muted">
              expected controls: <span className="text-soc-cyan">{expectedBlocks.join(" | ")}</span>
            </div>
          )}
          <div className="text-xs text-soc-muted">
            input preflight: <span className={hasExplicitPolicyPass ? "text-soc-green" : "text-soc-orange"}>{hasExplicitPolicyPass ? "passed" : "not observed"}</span>
          </div>
        </div>
      )}

      {/* Events */}
      <div className="flex-1 overflow-y-auto">
        {!runId && (
          <div className="h-full flex flex-col items-center justify-center text-soc-muted gap-3">
            <Terminal className="w-8 h-8 opacity-30" />
            <span className="text-sm">Launch an attack to see the execution trace</span>
          </div>
        )}

        {runId && events.length === 0 && (
          <div className="h-full flex flex-col items-center justify-center text-soc-muted gap-2">
            <span className="text-xs cursor-blink">Waiting for agent events</span>
          </div>
        )}

        {events.map((event, i) => (
          <EventRow key={event.event_id} event={event} index={i} />
        ))}
        <div ref={bottomRef} />
      </div>

      {/* KQL query footer */}
      {kqlQuery && (
        <details className="border-t border-soc-border">
          <summary className="px-4 py-2 text-xs text-soc-muted hover:text-soc-text cursor-pointer select-none">
            View Log Analytics KQL query
          </summary>
          <pre className="px-4 py-3 text-xs font-mono text-soc-cyan bg-soc-bg/60 overflow-x-auto leading-relaxed">
            {kqlQuery}
          </pre>
        </details>
      )}
    </div>
  );
}
