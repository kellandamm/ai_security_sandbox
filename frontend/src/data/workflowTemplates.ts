import { WorkflowTemplate } from "../types";

export const WORKFLOW_TEMPLATES: WorkflowTemplate[] = [
  {
    id: "vendor-risk-review",
    name: "Vendor Risk Review",
    industry: "Procurement",
    description:
      "Turn a questionnaire or security addendum into a concise risk summary that account teams and reviewers can act on immediately.",
    outcomeLabel: "Structured summary",
    agentType: "data-analyst",
    task:
      "Review the uploaded vendor document and produce a concise assessment covering major risks, control gaps, follow-up questions, and a recommended disposition for the reviewer.",
    output:
      "A decision-ready brief with risk themes, missing controls, and next steps.",
    sampleInputs: [
      "Security questionnaires or SIG responses",
      "Vendor onboarding packets or policy attachments",
      "Customer-specific due diligence notes",
    ],
    acceptedFileTypes: "Upload PDF, DOCX, TXT, or CSV",
    highlights: [
      "Keeps uploaded documents inside the run workspace",
      "Makes every file read and model call auditable",
      "Lets reviewers escalate high-risk findings with evidence",
    ],
    ctaLabel: "Run vendor review",
  },
  {
    id: "exec-ops-summary",
    name: "Executive Operations Summary",
    industry: "Operations",
    description:
      "Convert escalation notes, project updates, or issue logs into an executive-ready brief without losing the audit trail.",
    outcomeLabel: "Leadership brief",
    agentType: "data-analyst",
    task:
      "Analyze the uploaded operating notes and generate an executive summary with key themes, business impact, unresolved risks, and the top actions leaders should review this week.",
    output:
      "A short leadership readout with priorities, blockers, and recommended actions.",
    sampleInputs: [
      "Support escalations and incident notes",
      "Weekly program update documents",
      "Customer health or delivery review spreadsheets",
    ],
    acceptedFileTypes: "Upload PDF, DOCX, TXT, or CSV",
    highlights: [
      "Summarizes across long documents without exposing raw data externally",
      "Produces consistent output for leadership reporting",
      "Creates a clean handoff into trace and monitoring views",
    ],
    ctaLabel: "Generate summary",
  },
  {
    id: "policy-rollout-digest",
    name: "Policy Rollout Digest",
    industry: "Compliance",
    description:
      "Translate dense policy content into action-oriented guidance for operations, support, and delivery teams.",
    outcomeLabel: "Action checklist",
    agentType: "data-analyst",
    task:
      "Summarize the uploaded policy or procedure into key obligations, decision points, owner-specific actions, and a rollout checklist that teams can execute.",
    output:
      "A rollout digest that turns policy language into concrete operating tasks.",
    sampleInputs: [
      "Internal standards and procedures",
      "Customer contractual obligations",
      "New regulatory guidance or policy memos",
    ],
    acceptedFileTypes: "Upload PDF, DOCX, TXT, or CSV",
    highlights: [
      "Helps non-experts consume policy changes faster",
      "Maintains approval hooks for higher-risk outputs",
      "Pairs naturally with audit and kill-switch evidence",
    ],
    ctaLabel: "Create digest",
  },
  {
    id: "market-briefing",
    name: "Market Briefing",
    industry: "Strategy",
    description:
      "Use the approved web researcher profile to gather a fast public-source briefing on a customer, supplier, or emerging topic.",
    outcomeLabel: "Research brief",
    agentType: "web-researcher",
    task:
      "Research recent public information about the target company or topic using approved sources and return a concise briefing with notable developments, potential risks, and suggested follow-up questions.",
    output:
      "A sourced briefing that fits account planning, vendor reviews, and executive prep.",
    sampleInputs: [
      "Customer name or company profile",
      "Supplier or partner under review",
      "Public topic that needs a fast background brief",
    ],
    highlights: [
      "Restricts outbound access to approved public sources",
      "Separates research capability from document-analysis workflows",
      "Shows a safe networked use case without weakening policy",
    ],
    ctaLabel: "Start research brief",
  },
];