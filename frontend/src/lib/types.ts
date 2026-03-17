// ── Backend Pydantic schema mirrors ──────────────────────────────────

export interface RuleOut {
  id: string;
  ruleset_id: string;
  name: string;
  description: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  category: string;
  logic: string;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface RuleSetOut {
  id: string;
  name: string;
  description: string;
  vendor: string;
  version: string;
  rules: RuleOut[];
  created_at: string;
  updated_at: string;
}

export interface RuleExplainResponse {
  rule_id: string;
  rule_name: string;
  plain_english: string;
  risk_assessment: string;
  remediation: string;
}

export interface FindingOut {
  id: string;
  audit_id: string;
  rule_id: string;
  rule_name: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  message: string;
  line_number: number | null;
  context: string | null;
  remediation: string | null;
  created_at: string;
}

export interface AuditResponse {
  id: string;
  filename: string;
  vendor: string;
  status: "pending" | "running" | "completed" | "failed";
  findings: FindingOut[];
  summary: Record<string, number>;
  created_at: string;
  completed_at: string | null;
}

export interface UploadResponse {
  audit_id: string;
  filename: string;
  vendor: string;
  status: string;
  message: string;
}

export interface ComplianceCheckOut {
  id: string;
  audit_id: string;
  framework: string;
  control_id: string;
  control_name: string;
  status: "pass" | "fail" | "partial" | "not_applicable";
  details: string;
  created_at: string;
}

export interface ComplianceSummary {
  framework: string;
  total_controls: number;
  passed: number;
  failed: number;
  partial: number;
  not_applicable: number;
  score: number;
  checks: ComplianceCheckOut[];
}

export interface RuleGenRequest {
  description: string;
  vendor: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  category: string;
}

export interface RuleGenResponse {
  rule: RuleOut;
  explanation: string;
  confidence: number;
}

export interface ChatRequest {
  message: string;
  audit_id?: string;
  conversation_id?: string;
}

export interface ChatResponse {
  reply: string;
  conversation_id: string;
  sources: string[];
}
