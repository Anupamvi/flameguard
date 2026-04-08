// ── Backend Pydantic schema mirrors ──────────────────────────────────

export interface RuleOut {
  id: string;
  original_id: string;
  name: string;
  vendor: string;
  action: string;
  direction: string;
  protocol: string | null;
  source_addresses: string[];
  source_ports: string[];
  destination_addresses: string[];
  destination_ports: string[];
  priority: number | null;
  collection_name: string | null;
  collection_priority: number | null;
  description: string;
  enabled: boolean;
  risk_score: number | null;
  tags: Record<string, string>;
}

export interface RuleSetOut {
  id: string;
  filename: string;
  vendor: string;
  rule_count: number;
  uploaded_at: string;
}

export interface RuleExplainResponse {
  rule_id: string;
  explanation: string;
  concerns: string[];
}

export interface FindingOut {
  id: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  category: string;
  title: string;
  description: string;
  recommendation: string | null;
  confidence: number | null;
  source: "llm" | "deterministic" | "verified";
  affected_rule_ids: string[];
}

export interface AuditResponse {
  id: string;
  ruleset_id: string;
  filename: string;
  vendor: string;
  rule_count: number;
  status: "pending" | "parsing" | "auditing" | "scoring" | "completed" | "failed";
  summary: string | null;
  error_message: string | null;
  findings: FindingOut[];
  total_findings: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  created_at: string;
  completed_at: string | null;
}

export interface UploadResponse {
  ruleset_id: string;
  audit_id: string;
  status: string;
  rule_count: number;
  vendor: string;
  parse_warnings: string[];
}

export interface DeleteAuditsResponse {
  deleted_audit_ids: string[];
  deleted_ruleset_ids: string[];
}

export interface ComplianceCheckOut {
  id: string;
  framework: string;
  control_id: string;
  control_title: string;
  status: "pass" | "fail" | "not_applicable";
  evidence: string | null;
  affected_rule_ids: string[];
}

export interface ComplianceSummary {
  framework: string;
  total_controls: number;
  passed: number;
  failed: number;
  not_applicable: number;
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
  warnings: string[];
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
