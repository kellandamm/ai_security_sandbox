import { useEffect, useRef, useState, useCallback } from "react";
import { AuditEvent, RunStatus } from "../types";

export interface SSEState {
  events: AuditEvent[];
  status: RunStatus | null;
  connected: boolean;
  error: string | null;
}

/**
 * Subscribe to the SSE event stream for a given run_id.
 * Automatically reconnects if the connection drops (up to 5 times).
 * Stops subscribing when runId is null.
 */
export function useSSE(runId: string | null, apiBase: string = "/api"): SSEState {
  const [state, setState] = useState<SSEState>({
    events: [],
    status: null,
    connected: false,
    error: null,
  });

  const esRef = useRef<EventSource | null>(null);
  const retryRef = useRef(0);
  const runIdRef = useRef(runId);
  runIdRef.current = runId;

  const cleanup = useCallback(() => {
    if (esRef.current) {
      esRef.current.close();
      esRef.current = null;
    }
  }, []);

  useEffect(() => {
    if (!runId) {
      cleanup();
      setState({ events: [], status: null, connected: false, error: null });
      return;
    }

    // Reset for new run
    setState({ events: [], status: null, connected: false, error: null });
    retryRef.current = 0;

    function connect() {
      cleanup();

      const url = `${apiBase}/stream/runs/${runId}`;
      const es = new EventSource(url);
      esRef.current = es;

      es.onopen = () => {
        retryRef.current = 0;
        setState((s) => ({ ...s, connected: true, error: null }));
      };

      es.onmessage = (evt) => {
        try {
          const msg = JSON.parse(evt.data);
          if (msg.type === "event") {
            setState((s) => ({ ...s, events: [...s.events, msg.data as AuditEvent] }));
          } else if (msg.type === "run_complete") {
            setState((s) => ({
              ...s,
              status: msg.data.status as RunStatus,
              connected: false,
            }));
            cleanup();
          }
          // keepalive — no state change needed
        } catch {
          // malformed message — ignore
        }
      };

      es.onerror = () => {
        cleanup();
        setState((s) => ({ ...s, connected: false }));

        if (retryRef.current < 5 && runIdRef.current === runId) {
          retryRef.current += 1;
          const delay = Math.min(1000 * 2 ** retryRef.current, 30_000);
          setTimeout(connect, delay);
        } else {
          setState((s) => ({
            ...s,
            error: "SSE connection failed — check backend connectivity.",
          }));
        }
      };
    }

    connect();
    return cleanup;
  }, [runId, apiBase, cleanup]);

  return state;
}
