import { useEffect, useRef, useState, useCallback } from "react";
import { fetchEventSource } from "@microsoft/fetch-event-source";
import { AuditEvent, RunStatus } from "../types";

export interface SSEState {
  events: AuditEvent[];
  status: RunStatus | null;
  connected: boolean;
  error: string | null;
}

/**
 * Subscribe to the SSE event stream for a given run_id.
 * Uses @microsoft/fetch-event-source so we can send Authorization headers
 * when APIM protects the backend.
 *
 * Automatically reconnects if the connection drops (up to 5 times).
 * Stops subscribing when runId is null.
 */
export function useSSE(
  runId: string | null,
  apiBase: string = "/api",
  getAuthHeaders?: () => Promise<Record<string, string>>,
): SSEState {
  const [state, setState] = useState<SSEState>({
    events: [],
    status: null,
    connected: false,
    error: null,
  });

  const abortRef = useRef<AbortController | null>(null);
  const retryRef = useRef(0);
  const runIdRef = useRef(runId);

  useEffect(() => {
    runIdRef.current = runId;
  }, [runId]);

  const cleanup = useCallback(() => {
    if (abortRef.current) {
      abortRef.current.abort();
      abortRef.current = null;
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

    async function connect() {
      cleanup();

      const ctrl = new AbortController();
      abortRef.current = ctrl;

      const url = `${apiBase}/stream/runs/${runId}`;
      const headers: Record<string, string> = {};
      if (getAuthHeaders) {
        Object.assign(headers, await getAuthHeaders());
      }

      await fetchEventSource(url, {
        headers,
        signal: ctrl.signal,

        onopen: async (response) => {
          if (response.ok) {
            retryRef.current = 0;
            setState((s) => ({ ...s, connected: true, error: null }));
          } else {
            throw new Error(`SSE open failed: ${response.status}`);
          }
        },

        onmessage: (evt) => {
          try {
            const msg = JSON.parse(evt.data);
            if (msg.type === "event") {
              setState((s) => ({ ...s, events: [...s.events, msg.data as AuditEvent] }));
            } else if (msg.event_id) {
              setState((s) => ({ ...s, events: [...s.events, msg as AuditEvent] }));
            } else if (msg.type === "run_complete") {
              setState((s) => ({
                ...s,
                status: msg.data?.status as RunStatus ?? (msg.status as RunStatus),
                connected: false,
              }));
              cleanup();
            }
            // keepalive / ping — no state change needed
          } catch {
            // malformed message — ignore
          }
        },

        onerror: (err) => {
          setState((s) => ({ ...s, connected: false }));

          if (retryRef.current < 5 && runIdRef.current === runId) {
            retryRef.current += 1;
            const delay = Math.min(1000 * 2 ** retryRef.current, 30_000);
            // Return the delay to let fetchEventSource retry
            return delay;
          }

          setState((s) => ({
            ...s,
            error: "SSE connection failed — check backend connectivity.",
          }));
          // Throw to stop retrying
          throw err;
        },

        openWhenHidden: true,
      }).catch(() => {
        // Stream ended (either by cleanup abort or exhausted retries)
      });
    }

    connect();
    return cleanup;
  }, [runId, apiBase, getAuthHeaders, cleanup]);

  return state;
}
