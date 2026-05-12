import { Copy, ExternalLink, Search } from "lucide-react";
import clsx from "clsx";
import { AuditEvent, RunStatus } from "../types";

interface Props {
  runId: string | null;
  status: RunStatus | null;
  events: AuditEvent[];
}

function getPortalLinks(runId: string) {
  const encoded = encodeURIComponent(runId);
  return {
    sentinel:
      "https://portal.azure.com/#blade/Microsoft_Azure_Security_Insights/MainMenuBlade",
    logAnalytics:
      "https://portal.azure.com/#blade/Microsoft_Azure_Monitoring_Logs/LogsBlade",
    appInsights:
      "https://portal.azure.com/#blade/AppInsightsExtension/UsageAnalysisBlade",
    apim:
      "https://portal.azure.com/#view/Microsoft_Azure_ApiManagement/ApiManagementMenuBlade/~/overview",
    searchHint: `run_id == "${encoded}"`,
  };
}

export default function AzureEvidencePanel({ runId, status, events }: Props) {
  const latestCorrelationId = events.length > 0 ? events[events.length - 1].correlation_id : null;
  const finished = status === "completed" || status === "failed" || status === "killed";

  const links = runId ? getPortalLinks(runId) : null;

  async function copyText(text: string) {
    await navigator.clipboard.writeText(text);
  }

  return (
    <section className="border-t border-soc-border bg-white px-4 py-3">
      <div className="mb-2 flex items-center justify-between gap-2">
        <div>
          <div className="text-[11px] uppercase tracking-[0.22em] text-soc-muted">Azure Evidence Handoff</div>
          <div className="text-sm font-semibold text-soc-text">Investigate in Azure, not in-app</div>
        </div>
        <span
          className={clsx(
            "badge",
            finished ? "badge-green" : "badge-orange"
          )}
        >
          {finished ? "ready" : "waiting"}
        </span>
      </div>

      <div className="grid gap-3 md:grid-cols-2">
        <div className="space-y-2">
          <div className="rounded-lg border border-soc-border bg-slate-50 px-3 py-2 text-xs">
            <div className="text-soc-muted">run_id</div>
            <div className="mt-1 flex items-center gap-2">
              <span className="font-mono text-soc-cyan break-all">{runId ?? "(start a run)"}</span>
              {runId && (
                <button
                  onClick={() => copyText(runId)}
                  className="btn btn-ghost !px-2 !py-1 text-xs"
                  title="Copy run_id"
                >
                  <Copy className="h-3 w-3" />
                </button>
              )}
            </div>
          </div>

          <div className="rounded-lg border border-soc-border bg-slate-50 px-3 py-2 text-xs">
            <div className="text-soc-muted">correlation_id</div>
            <div className="mt-1 flex items-center gap-2">
              <span className="font-mono text-soc-cyan break-all">
                {latestCorrelationId ?? "(available once events stream)"}
              </span>
              {latestCorrelationId && (
                <button
                  onClick={() => copyText(latestCorrelationId)}
                  className="btn btn-ghost !px-2 !py-1 text-xs"
                  title="Copy correlation_id"
                >
                  <Copy className="h-3 w-3" />
                </button>
              )}
            </div>
          </div>
        </div>

        <div className="space-y-2">
          <div className="text-xs text-soc-muted">Open Azure surfaces and search by identifiers:</div>
          <div className="flex flex-wrap gap-2">
            <a className="btn btn-ghost text-xs" href={links?.sentinel} target="_blank" rel="noopener noreferrer">
              Sentinel <ExternalLink className="h-3 w-3" />
            </a>
            <a className="btn btn-ghost text-xs" href={links?.logAnalytics} target="_blank" rel="noopener noreferrer">
              Log Analytics <ExternalLink className="h-3 w-3" />
            </a>
            <a className="btn btn-ghost text-xs" href={links?.appInsights} target="_blank" rel="noopener noreferrer">
              App Insights <ExternalLink className="h-3 w-3" />
            </a>
            <a className="btn btn-ghost text-xs" href={links?.apim} target="_blank" rel="noopener noreferrer">
              APIM <ExternalLink className="h-3 w-3" />
            </a>
          </div>
          {runId && (
            <button
              onClick={() => copyText(`run_id == "${runId}"`)}
              className="btn btn-primary text-xs"
              title="Copy KQL filter"
            >
              <Search className="h-3 w-3" /> Copy KQL filter
            </button>
          )}
        </div>
      </div>
    </section>
  );
}
