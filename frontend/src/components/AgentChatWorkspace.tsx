import { useMemo, useRef, useState } from "react";
import { Bot, Paperclip, Send, Shield, User, X } from "lucide-react";
import clsx from "clsx";

type AgentType = "data-analyst" | "web-researcher";

type ChatRole = "user" | "assistant" | "system";

interface ChatMessage {
  id: string;
  role: ChatRole;
  text: string;
  ts: string;
}

interface Props {
  apiBase: string;
  getAuthHeaders: () => Promise<Record<string, string>>;
}

function nowIso(): string {
  return new Date().toISOString();
}

function shortTime(ts: string): string {
  return new Date(ts).toLocaleTimeString("en-GB", { hour12: false });
}

function uid(prefix: string): string {
  return `${prefix}_${Math.random().toString(36).slice(2, 10)}`;
}

function formatRunResult(result: unknown): string {
  if (result == null) return "Completed.";
  if (typeof result === "string") return result;
  if (typeof result === "number" || typeof result === "boolean") return String(result);
  if (typeof result === "object") {
    const record = result as Record<string, unknown>;
    const output = record.output;
    const tokensUsed = record.tokens_used;
    const primaryText = typeof output === "string" ? output : JSON.stringify(result, null, 2);
    return typeof tokensUsed === "number" ? `${primaryText}\n\nTokens used: ${tokensUsed}` : primaryText;
  }
  return String(result);
}

export default function AgentChatWorkspace({ apiBase, getAuthHeaders }: Props) {
  const [agentType, setAgentType] = useState<AgentType>("data-analyst");
  const [input, setInput] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [isRunning, setIsRunning] = useState(false);
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      id: uid("m"),
      role: "system",
      text:
        "Secure chat ready. Every message and upload is enforced by kill-switch checks, capability policy, OPA sidecar decisions, and sandbox validation before execution.",
      ts: nowIso(),
    },
  ]);

  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const canSend = useMemo(() => input.trim().length > 0 && !isRunning, [input, isRunning]);

  async function waitForCompletion(runId: string, authHeaders: Record<string, string>) {
    for (let i = 0; i < 40; i += 1) {
      const resp = await fetch(`${apiBase}/runs/${runId}`, {
        headers: authHeaders,
      });

      if (!resp.ok) {
        throw new Error(`Could not read run status (HTTP ${resp.status})`);
      }

      const run = await resp.json();
      if (["completed", "failed", "killed"].includes(run.status)) {
        return run;
      }

      await new Promise((resolve) => setTimeout(resolve, 1500));
    }

    throw new Error("Run is still processing. Check Azure logs/telemetry for current state.");
  }

  async function sendMessage() {
    if (!canSend) return;

    const task = input.trim();
    const userMessage: ChatMessage = {
      id: uid("u"),
      role: "user",
      text: task,
      ts: nowIso(),
    };

    setMessages((prev) => [...prev, userMessage]);
    setInput("");
    setIsRunning(true);

    try {
      const authHeaders = await getAuthHeaders();
      let body: BodyInit;
      const headers: Record<string, string> = { ...authHeaders };

      if (file) {
        const fd = new FormData();
        fd.append("agent_type", agentType);
        fd.append("task", task);
        fd.append("file", file);
        body = fd;
      } else {
        headers["Content-Type"] = "application/json";
        body = JSON.stringify({ agent_type: agentType, task });
      }

      const createResp = await fetch(`${apiBase}/runs`, {
        method: "POST",
        headers,
        body,
      });

      if (!createResp.ok) {
        const errText = await createResp.text();
        throw new Error(`Run start failed (HTTP ${createResp.status}): ${errText}`);
      }

      const { run_id: runId } = await createResp.json();

      setMessages((prev) => [
        ...prev,
        {
          id: uid("s"),
          role: "system",
          text: `Run ${runId} started with ${agentType}. Use this ID in Azure for investigation.`,
          ts: nowIso(),
        },
      ]);

      const finalRun = await waitForCompletion(runId, authHeaders);

      const responseText =
        finalRun.status === "completed"
          ? formatRunResult(finalRun.result)
          : `Run ${finalRun.status}: ${finalRun.error || "No error details returned."}`;

      setMessages((prev) => [
        ...prev,
        {
          id: uid("a"),
          role: "assistant",
          text: responseText,
          ts: nowIso(),
        },
      ]);
    } catch (err) {
      setMessages((prev) => [
        ...prev,
        {
          id: uid("e"),
          role: "assistant",
          text: `Execution error: ${String(err)}`,
          ts: nowIso(),
        },
      ]);
    } finally {
      setIsRunning(false);
      setFile(null);
      if (fileInputRef.current) fileInputRef.current.value = "";
    }
  }

  return (
    <div className="h-full p-5">
      <div className="panel flex h-full flex-col overflow-hidden">
        <div className="panel-header">
          <div className="flex items-center gap-2">
            <Shield className="h-4 w-4 text-soc-blue" />
            <span className="font-semibold text-soc-text">Agent Chat</span>
          </div>
          <div className="flex items-center gap-2">
            <label htmlFor="agentType" className="text-xs text-soc-muted">
              Agent
            </label>
            <select
              id="agentType"
              className="rounded-lg border border-soc-border bg-white px-2 py-1 text-xs text-soc-text"
              value={agentType}
              onChange={(e) => setAgentType(e.target.value as AgentType)}
              disabled={isRunning}
            >
              <option value="data-analyst">data-analyst</option>
              <option value="web-researcher">web-researcher</option>
            </select>
          </div>
        </div>

        <div className="flex-1 overflow-y-auto bg-slate-50/70 p-4">
          <div className="mx-auto flex max-w-4xl flex-col gap-3">
            {messages.map((m) => (
              <div
                key={m.id}
                className={clsx(
                  "max-w-[88%] rounded-2xl border px-3 py-2 text-sm",
                  m.role === "user" && "ml-auto border-blue-200 bg-blue-50",
                  m.role === "assistant" && "mr-auto border-slate-200 bg-white",
                  m.role === "system" && "mx-auto border-amber-200 bg-amber-50 text-xs"
                )}
              >
                <div className="mb-1 flex items-center gap-2 text-[11px] text-soc-muted">
                  {m.role === "user" && <User className="h-3 w-3" />}
                  {m.role !== "user" && <Bot className="h-3 w-3" />}
                  <span>{m.role}</span>
                  <span>{shortTime(m.ts)}</span>
                </div>
                <div className="whitespace-pre-wrap break-words text-soc-text">{m.text}</div>
              </div>
            ))}
          </div>
        </div>

        <div className="border-t border-soc-border bg-white p-3">
          <div className="mx-auto flex max-w-4xl flex-col gap-2">
            <div className="flex items-center gap-2">
              <label className="btn btn-ghost !py-1.5 text-xs cursor-pointer">
                <Paperclip className="h-3.5 w-3.5" /> Upload file
                <input
                  ref={fileInputRef}
                  type="file"
                  className="hidden"
                  onChange={(e) => setFile(e.target.files?.[0] ?? null)}
                  disabled={isRunning}
                />
              </label>
              {file && (
                <span className="inline-flex items-center gap-1 rounded-full border border-soc-border bg-slate-100 px-2 py-1 text-xs text-soc-text">
                  {file.name}
                  <button
                    type="button"
                    onClick={() => {
                      setFile(null);
                      if (fileInputRef.current) fileInputRef.current.value = "";
                    }}
                    className="rounded p-0.5 hover:bg-slate-200"
                    title="Remove file"
                    disabled={isRunning}
                  >
                    <X className="h-3 w-3" />
                  </button>
                </span>
              )}
            </div>

            <div className="flex items-end gap-2">
              <textarea
                className="min-h-[70px] flex-1 rounded-xl border border-soc-border px-3 py-2 text-sm text-soc-text outline-none focus:border-blue-300 focus:ring-2 focus:ring-blue-100"
                placeholder="Ask the agent a question or provide instructions..."
                value={input}
                onChange={(e) => setInput(e.target.value)}
                disabled={isRunning}
              />
              <button
                className="btn btn-primary h-[42px]"
                onClick={sendMessage}
                disabled={!canSend}
              >
                <Send className="h-3.5 w-3.5" />
                {isRunning ? "Running..." : "Send"}
              </button>
            </div>
            <p className="text-[11px] text-soc-muted">
              No alerting or reporting is shown in this app. Use run IDs in Azure Security and Monitor to review policy blocks,
              audit trails, and detections.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
