import { useState } from "react";
import {
  Shield,
  AlertTriangle,
  ChevronDown,
  ChevronUp,
  Upload,
  Play,
  Download,
} from "lucide-react";
import { ATTACK_TEMPLATES, CATEGORY_LABELS } from "../data/attackTemplates";
import { AttackTemplate, AlertSeverity } from "../types";
import clsx from "clsx";

interface Props {
  onLaunch: (template: AttackTemplate, file: File | null) => void;
  isRunning: boolean;
}

const SEVERITY_BADGE: Record<AlertSeverity, string> = {
  High: "badge-red",
  Medium: "badge-orange",
  Low: "badge-yellow",
  Informational: "badge-blue",
};

const CATEGORY_ICON: Record<string, string> = {
  "prompt-injection": "💉",
  "path-traversal": "🗂️",
  "credential-harvest": "🔑",
  "token-bomb": "💣",
  ssrf: "🌐",
  "policy-bypass": "🔓",
};

export default function AttackLibrary({ onLaunch, isRunning }: Props) {
  const [expanded, setExpanded] = useState<string | null>(ATTACK_TEMPLATES[0].id);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);

  function handleFileChange(e: React.ChangeEvent<HTMLInputElement>) {
    setSelectedFile(e.target.files?.[0] ?? null);
  }

  function handleLaunch(template: AttackTemplate) {
    onLaunch(template, selectedFile);
    setSelectedFile(null);
  }

  return (
    <div className="panel flex flex-col h-full">
      <div className="panel-header">
        <div className="flex items-center gap-2">
          <Shield className="w-4 h-4 text-soc-red" />
          <span className="font-semibold text-soc-text">Guardrails Lab</span>
          <span className="badge badge-gray">{ATTACK_TEMPLATES.length} adversarial scenarios</span>
        </div>
        <span className="text-xs text-soc-muted">Fallback demo mode for exploit and policy validation</span>
      </div>

      <div className="flex-1 overflow-y-auto divide-y divide-soc-border">
        {ATTACK_TEMPLATES.map((t) => {
          const isOpen = expanded === t.id;
          return (
            <div key={t.id} className="transition-colors">
              {/* Collapsed header */}
              <button
                className="w-full text-left px-4 py-3 flex items-center gap-3 hover:bg-soc-accent/30 transition-colors"
                onClick={() => setExpanded(isOpen ? null : t.id)}
              >
                <span className="text-base leading-none" aria-hidden>
                  {CATEGORY_ICON[t.category]}
                </span>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-medium text-soc-text truncate">{t.name}</span>
                    <span className={clsx("badge", SEVERITY_BADGE[t.severity])}>
                      {t.severity}
                    </span>
                    <span className="badge badge-gray text-xs">
                      {CATEGORY_LABELS[t.category]}
                    </span>
                  </div>
                </div>
                {isOpen ? (
                  <ChevronUp className="w-3.5 h-3.5 text-soc-muted shrink-0" />
                ) : (
                  <ChevronDown className="w-3.5 h-3.5 text-soc-muted shrink-0" />
                )}
              </button>

              {/* Expanded body */}
              {isOpen && (
                <div className="px-4 pb-4 space-y-3 animate-fade-in bg-soc-bg/40">
                  <p className="text-soc-muted text-xs leading-relaxed">{t.description}</p>

                  {/* Task preview */}
                  <div>
                    <div className="text-xs text-soc-muted mb-1 uppercase tracking-wider">
                      Agent task
                    </div>
                    <div className="bg-soc-panel rounded p-2 text-xs text-soc-cyan border border-soc-border font-mono leading-relaxed">
                      {t.task}
                    </div>
                  </div>

                  {/* Expected blocks */}
                  <div>
                    <div className="text-xs text-soc-muted mb-1 uppercase tracking-wider">
                      Controls that should fire
                    </div>
                    <ul className="space-y-1">
                      {t.expectedBlocks.map((b) => (
                        <li key={b} className="flex items-center gap-2 text-xs text-soc-text">
                          <AlertTriangle className="w-3 h-3 text-soc-orange shrink-0" />
                          {b}
                        </li>
                      ))}
                    </ul>
                  </div>

                  {/* File upload */}
                  {t.fileTemplate && (
                    <div>
                      <div className="text-xs text-soc-muted mb-1 uppercase tracking-wider">
                        Tainted document
                      </div>
                      <div className="flex items-center gap-2 flex-wrap">
                        <a
                          href={`/templates/${t.fileTemplate.publicPath}`}
                          download={t.fileTemplate.filename}
                          className="btn btn-ghost text-xs gap-1"
                        >
                          <Download className="w-3 h-3" />
                          {t.fileTemplate.filename}
                        </a>
                        <label className="btn btn-ghost text-xs gap-1 cursor-pointer">
                          <Upload className="w-3 h-3" />
                          {selectedFile ? selectedFile.name : "Upload custom file"}
                          <input
                            type="file"
                            className="hidden"
                            onChange={handleFileChange}
                            accept={t.fileTemplate.mimeType}
                          />
                        </label>
                        {selectedFile && (
                          <span className="text-xs text-soc-green truncate max-w-[140px]">
                            ✓ {selectedFile.name}
                          </span>
                        )}
                      </div>
                    </div>
                  )}

                  {/* Agent type */}
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2 text-xs text-soc-muted">
                      Agent:{" "}
                      <span className="text-soc-cyan font-mono">{t.agentType}</span>
                    </div>
                    <button
                      className={clsx(
                        "btn",
                        isRunning ? "btn-ghost opacity-50" : "btn-primary"
                      )}
                      disabled={isRunning}
                      onClick={() => handleLaunch(t)}
                    >
                      <Play className="w-3.5 h-3.5" />
                      {isRunning ? "Running..." : "Run Scenario"}
                    </button>
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
