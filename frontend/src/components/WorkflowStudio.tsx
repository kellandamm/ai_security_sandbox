import { useState } from "react";
import {
  ArrowRight,
  Briefcase,
  CheckCircle2,
  FileUp,
  Globe,
  Play,
  Sparkles,
} from "lucide-react";
import clsx from "clsx";
import { WORKFLOW_TEMPLATES } from "../data/workflowTemplates";
import { WorkflowTemplate } from "../types";

interface Props {
  onLaunch: (template: WorkflowTemplate, file: File | null) => void;
  isRunning: boolean;
}

const WORKFLOW_ICONS: Record<WorkflowTemplate["agentType"], React.ElementType> = {
  "data-analyst": Briefcase,
  "web-researcher": Globe,
};

export default function WorkflowStudio({ onLaunch, isRunning }: Props) {
  const [selectedFiles, setSelectedFiles] = useState<Record<string, File | null>>({});

  function setSelectedFile(workflowId: string, file: File | null) {
    setSelectedFiles((current) => ({
      ...current,
      [workflowId]: file,
    }));
  }

  function handleLaunch(workflow: WorkflowTemplate) {
    onLaunch(workflow, selectedFiles[workflow.id] ?? null);
  }

  return (
    <div className="h-full overflow-y-auto px-5 py-5">
      <div className="space-y-5">
        <section className="hero-panel subtle-grid animate-rise">
          <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
            <div className="max-w-3xl space-y-4">
              <span className="stat-chip">
                <Sparkles className="h-3.5 w-3.5" />
                Customer-facing secure AI workflows
              </span>
              <div className="space-y-3">
                <h1 className="text-3xl font-semibold tracking-tight text-soc-text md:text-4xl">
                  Show the product people would actually buy.
                </h1>
                <p className="max-w-xl text-sm leading-6 text-soc-muted md:text-base">
                  This workspace demonstrates how teams can review documents, summarize operations,
                  and research external topics with enterprise controls built in by default.
                </p>
              </div>
              <p className="text-sm leading-6 text-soc-muted">
                Choose a workflow below, optionally attach a document, and run it through the
                same governed backend pipeline used in the live demo environment.
              </p>
            </div>
          </div>
        </section>

        <section>
          <div className="panel overflow-hidden">
            <div className="panel-header">
              <div>
                <div className="text-xs uppercase tracking-[0.22em] text-soc-muted">Workflow Studio</div>
                <div className="mt-1 text-base font-semibold text-soc-text">Launch a real customer scenario</div>
              </div>
              <span className="text-xs text-soc-muted">Same backend pipeline, better product framing</span>
            </div>

            <div className="divide-y divide-soc-border/80">
              {WORKFLOW_TEMPLATES.map((workflow, index) => {
                const AgentIcon = WORKFLOW_ICONS[workflow.agentType];
                const selectedFile = selectedFiles[workflow.id] ?? null;

                return (
                  <article
                    key={workflow.id}
                    className="workflow-card animate-rise px-5 py-5"
                    style={{ animationDelay: `${index * 80}ms` }}
                  >
                    <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
                      <div className="space-y-3">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="badge badge-blue">{workflow.industry}</span>
                          <span className="badge badge-gray">{workflow.agentType}</span>
                          <span className="badge badge-green">{workflow.outcomeLabel}</span>
                        </div>

                        <div>
                          <h2 className="text-lg font-semibold text-soc-text">{workflow.name}</h2>
                          <p className="mt-1 max-w-2xl text-sm leading-6 text-soc-muted">
                            {workflow.description}
                          </p>
                        </div>

                        <div className="rounded-2xl border border-soc-border bg-slate-50 px-4 py-3">
                          <div className="text-[11px] uppercase tracking-[0.22em] text-soc-muted">
                            What the agent does
                          </div>
                          <p className="mt-2 text-sm leading-6 text-soc-text">{workflow.task}</p>
                        </div>

                        <div className="grid gap-3 md:grid-cols-2">
                          <div>
                            <div className="text-[11px] uppercase tracking-[0.22em] text-soc-muted">
                              Output
                            </div>
                            <p className="mt-2 text-sm text-soc-text">{workflow.output}</p>
                          </div>
                          <div>
                            <div className="text-[11px] uppercase tracking-[0.22em] text-soc-muted">
                              Ideal inputs
                            </div>
                            <ul className="mt-2 space-y-1.5 text-sm text-soc-text">
                              {workflow.sampleInputs.map((item) => (
                                <li key={item} className="flex items-start gap-2">
                                  <CheckCircle2 className="mt-0.5 h-3.5 w-3.5 shrink-0 text-soc-green" />
                                  <span>{item}</span>
                                </li>
                              ))}
                            </ul>
                          </div>
                        </div>
                      </div>

                      <div className="w-full shrink-0 rounded-2xl border border-soc-border bg-slate-50 p-4 lg:w-[260px]">
                        <div className="flex items-center gap-2 text-sm font-medium text-soc-text">
                          <AgentIcon className="h-4 w-4 text-soc-blue" />
                          Ready to run
                        </div>
                        <p className="mt-2 text-xs leading-5 text-soc-muted">
                          {workflow.agentType === "web-researcher"
                            ? "Runs without a file upload using the approved public-source researcher profile."
                            : "Optionally attach a customer document to make the workflow concrete during the demo."}
                        </p>

                        {workflow.acceptedFileTypes && (
                          <label className="mt-4 flex cursor-pointer items-center justify-center gap-2 rounded-xl border border-dashed border-soc-border px-3 py-3 text-xs text-soc-muted transition-colors hover:border-soc-blue hover:text-soc-text">
                            <FileUp className="h-3.5 w-3.5" />
                            {selectedFile ? selectedFile.name : workflow.acceptedFileTypes}
                            <input
                              type="file"
                              className="hidden"
                              onChange={(event) =>
                                setSelectedFile(workflow.id, event.target.files?.[0] ?? null)
                              }
                            />
                          </label>
                        )}

                        <div className="mt-4 space-y-2 text-xs text-soc-muted">
                          {workflow.highlights.map((highlight) => (
                            <div key={highlight} className="flex items-start gap-2">
                              <ArrowRight className="mt-0.5 h-3.5 w-3.5 shrink-0 text-soc-orange" />
                              <span>{highlight}</span>
                            </div>
                          ))}
                        </div>

                        <button
                          className={clsx(
                            "btn mt-5 w-full justify-center",
                            isRunning ? "btn-ghost opacity-50" : "btn-primary"
                          )}
                          disabled={isRunning}
                          onClick={() => handleLaunch(workflow)}
                        >
                          <Play className="h-3.5 w-3.5" />
                          {isRunning ? "Workflow running..." : workflow.ctaLabel}
                        </button>
                      </div>
                    </div>
                  </article>
                );
              })}
            </div>
          </div>
        </section>
      </div>
    </div>
  );
}