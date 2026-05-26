// ── Audit event from SSE stream or Log Analytics ──────────────────────────────

export type ActionType =
  | "file_read"
  | "file_write"
  | "file_delete"
  | "network_call"
  | "openai_call"
  | "http_get"
  | "http_post"
  | "dlp_scan"
  | "data_classification"
  | "content_safety_check"
  | "grounding_check"
  | "delegation_check"
  | "kill_switch_check"
  | "policy_check"
  | "approval_request"
  | "approval_response"
  | "run_start"
  | "run_complete"
<<<<<<< HEAD
  | "run_abort"
  | "prompt_shield_scan"
  | "retrieved_content_scan"
  | "agent_spawn"
  | "agent_delegation"
  | "governance_attestation"
  | "anomaly_ml_score"
  | "dsar_purge"
  | "admin_dsar_export"
  | "mcp_tool_call"
  | "mcp_tool_discovery"
  | "excessive_agency_block"
  | "loop_detected"
  | "cost_threshold_breach"
  | "rate_limit_exceeded";
=======
  | "run_abort";
>>>>>>> origin/main

export type PolicyDecision = "allow" | "deny" | "requires_approval";
export type Outcome = "success" | "failure" | "blocked" | "timeout";

export interface AuditEvent {
  event_id: string;
  timestamp: string;
  run_id: string;
  agent_type: string;
  action_type: ActionType;
  policy_decision: PolicyDecision;
  path?: string;
  destination?: string;
  content_hash?: string;
  token_count?: number;
  risk_score: number;
  outcome: Outcome;
  error_code?: string;
  classification_label?: string;
  dlp_patterns?: string;
  content_safety_category?: string;
  grounding_score?: number;
  parent_run_id?: string;
  correlation_id: string;
}

// ── Agent run ─────────────────────────────────────────────────────────────────

export type RunStatus =
  | "queued"
  | "running"
  | "awaiting_approval"
  | "completed"
  | "failed"
  | "killed";

export interface AgentRun {
  run_id: string;
  status: RunStatus;
  agent_type: string;
  task: string;
  created_at: string;
  completed_at?: string;
  result?: string;
  error?: string;
  token_usage: number;
  events: AuditEvent[];
}

// ── Sentinel alert ────────────────────────────────────────────────────────────

export type AlertSeverity = "Informational" | "Low" | "Medium" | "High";

export interface SentinelAlert {
  id: string;
  name: string;
  severity: AlertSeverity;
  description: string;
  timestamp: string;
  status: "New" | "Active" | "Closed";
  tactics: string;
  entities: string;
}

// ── Kill switch ───────────────────────────────────────────────────────────────

export interface KillSwitch {
  name: string;
  label: string;
  enabled: boolean;
  description: string;
  scope: "global" | "capability" | "agent-type";
}

// ── Attack template ───────────────────────────────────────────────────────────

export type AttackCategory =
  | "prompt-injection"
  | "path-traversal"
  | "credential-harvest"
  | "token-bomb"
  | "ssrf"
<<<<<<< HEAD
  | "policy-bypass"
  | "loop"
  | "anomaly"
  | "egress"
  | "high-risk-action";
=======
  | "policy-bypass";
>>>>>>> origin/main

export interface AttackTemplate {
  id: string;
  name: string;
  category: AttackCategory;
  severity: AlertSeverity;
  description: string;
  /** Controls that should fire */
  expectedBlocks: string[];
  agentType: "data-analyst" | "web-researcher";
  task: string;
  /** Optional file to upload alongside the task */
  fileTemplate?: {
    filename: string;
    mimeType: string;
    publicPath: string; // path under /templates/ for download
  };
  /** Badge color for the category */
  color: string;
}

export interface WorkflowTemplate {
  id: string;
  name: string;
  industry: string;
  description: string;
  outcomeLabel: string;
  agentType: "data-analyst" | "web-researcher";
  task: string;
  output: string;
  sampleInputs: string[];
  acceptedFileTypes?: string;
  highlights: string[];
  ctaLabel: string;
}

// ── SSE ───────────────────────────────────────────────────────────────────────

export type SSEMessage =
  | { type: "event"; data: AuditEvent }
  | { type: "run_complete"; data: { run_id: string; status: RunStatus } }
  | { type: "keepalive" };

// ── Timeline response from /runs/{id}/timeline ────────────────────────────────

export interface TimelineResponse {
  run_id: string;
  events: AuditEvent[];
  kql_query: string;
  source: "log_analytics" | "local_cache";
}

export interface AlertsResponse {
  alerts: SentinelAlert[];
}

export interface KillSwitchesResponse {
  flags: KillSwitch[];
}
