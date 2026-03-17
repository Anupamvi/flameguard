import type {
  AuditResponse,
  ComplianceSummary,
  RuleExplainResponse,
  RuleGenRequest,
  RuleGenResponse,
  RuleOut,
  UploadResponse,
} from "./types";

const BASE_URL =
  process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000/api/v1";

// ── Error class ──────────────────────────────────────────────────────

export class ApiError extends Error {
  status: number;
  body: unknown;

  constructor(message: string, status: number, body: unknown) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.body = body;
  }
}

// ── Generic fetch helper ─────────────────────────────────────────────

async function apiFetch<T>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  const url = `${BASE_URL}${path}`;

  const res = await fetch(url, {
    headers: {
      "Content-Type": "application/json",
      ...options.headers,
    },
    ...options,
  });

  if (!res.ok) {
    let body: unknown;
    try {
      body = await res.json();
    } catch {
      body = await res.text();
    }
    throw new ApiError(
      `API ${res.status}: ${res.statusText}`,
      res.status,
      body,
    );
  }

  return res.json() as Promise<T>;
}

// ── Public API object ────────────────────────────────────────────────

export const api = {
  /** Upload a firewall config file for auditing. */
  async uploadFile(
    file: File,
    vendorHint?: string,
  ): Promise<UploadResponse> {
    const formData = new FormData();
    formData.append("file", file);
    if (vendorHint) formData.append("vendor_hint", vendorHint);

    const url = `${BASE_URL}/audits/upload`;
    const res = await fetch(url, {
      method: "POST",
      body: formData,
    });

    if (!res.ok) {
      let body: unknown;
      try {
        body = await res.json();
      } catch {
        body = await res.text();
      }
      throw new ApiError(
        `API ${res.status}: ${res.statusText}`,
        res.status,
        body,
      );
    }

    return res.json() as Promise<UploadResponse>;
  },

  /** Fetch a single audit by ID. */
  getAudit(id: string): Promise<AuditResponse> {
    return apiFetch<AuditResponse>(`/audits/${id}`);
  },

  /** List audits with optional pagination. */
  listAudits(page = 1, perPage = 20): Promise<AuditResponse[]> {
    return apiFetch<AuditResponse[]>(
      `/audits?page=${page}&per_page=${perPage}`,
    );
  },

  /** Get rules belonging to a ruleset. */
  getRules(rulesetId: string): Promise<RuleOut[]> {
    return apiFetch<RuleOut[]>(`/rulesets/${rulesetId}/rules`);
  },

  /** Get a plain-english explanation of a rule. */
  explainRule(ruleId: string): Promise<RuleExplainResponse> {
    return apiFetch<RuleExplainResponse>(`/rules/${ruleId}/explain`);
  },

  /** Get compliance summary for an audit. */
  getCompliance(auditId: string): Promise<ComplianceSummary[]> {
    return apiFetch<ComplianceSummary[]>(
      `/audits/${auditId}/compliance`,
    );
  },

  /** Generate a new rule via LLM. */
  generateRule(request: RuleGenRequest): Promise<RuleGenResponse> {
    return apiFetch<RuleGenResponse>("/rules/generate", {
      method: "POST",
      body: JSON.stringify(request),
    });
  },
};
