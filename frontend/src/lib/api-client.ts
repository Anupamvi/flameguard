import type {
  AuditResponse,
  ComplianceSummary,
  DeleteAuditsResponse,
  RuleExplainResponse,
  RuleGenRequest,
  RuleGenResponse,
  RuleOut,
  UploadResponse,
} from "./types";

const BASE_URL =
  process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000/api/v1";

const COMPRESSION_STATUS_THRESHOLD_BYTES = 1024 * 1024;

export type UploadStage = "compressing" | "uploading";

// ── Error class ──────────────────────────────────────────────────────

export class ApiError extends Error {
  status: number;
  body: unknown;
  headers: Headers;

  constructor(message: string, status: number, body: unknown, headers: Headers) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.body = body;
    this.headers = headers;
  }
}

function extractApiErrorDetail(error: ApiError): string | null {
  if (typeof error.body === "string" && error.body.trim()) {
    return error.body;
  }

  if (error.body && typeof error.body === "object" && "detail" in error.body) {
    const detail = (error.body as { detail?: unknown }).detail;
    if (typeof detail === "string" && detail.trim()) {
      return detail;
    }
  }

  return null;
}

export function getApiErrorMessage(
  error: unknown,
  fallback = "An unexpected error occurred",
): string {
  if (error instanceof ApiError) {
    const detail = extractApiErrorDetail(error);
    if (error.status === 403 && detail === "Administrative routes are disabled on this deployment.") {
      return "This action is disabled on the public deployment.";
    }
    if (error.status === 403 && detail === "Administrative token required for this route.") {
      return "This action requires an administrative token.";
    }
    if (error.status === 429) {
      return detail || "Too many requests. Wait a bit and try again.";
    }
    return detail || error.message;
  }

  if (error instanceof Error) {
    return error.message;
  }

  return fallback;
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
      res.headers,
    );
  }

  return res.json() as Promise<T>;
}

async function maybeCompressUpload(
  file: File,
  onStageChange?: (stage: UploadStage) => void,
): Promise<File> {
  if (
    typeof CompressionStream === "undefined" ||
    file.size < COMPRESSION_STATUS_THRESHOLD_BYTES
  ) {
    return file;
  }

  onStageChange?.("compressing");

  const compressedStream = file.stream().pipeThrough(
    new CompressionStream("gzip"),
  );
  const compressedBlob = await new Response(compressedStream).blob();

  if (compressedBlob.size >= file.size) {
    return file;
  }

  return new File([compressedBlob], `${file.name}.gz`, {
    type: "application/gzip",
  });
}

// ── Public API object ────────────────────────────────────────────────

export const api = {
  /** Upload a security configuration or supported log export for auditing. */
  async uploadFile(
    file: File,
    vendorHint?: string,
    onStageChange?: (stage: UploadStage) => void,
  ): Promise<UploadResponse> {
    const uploadFile = await maybeCompressUpload(file, onStageChange);
    const formData = new FormData();
    formData.append("file", uploadFile);

    const query = vendorHint
      ? `?vendor_hint=${encodeURIComponent(vendorHint)}`
      : "";

    onStageChange?.("uploading");

    const res = await fetch(`${BASE_URL}/upload${query}`, {
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
        res.headers,
      );
    }

    return res.json() as Promise<UploadResponse>;
  },

  /** Fetch a single audit by ID. */
  getAudit(id: string): Promise<AuditResponse> {
    return apiFetch<AuditResponse>(`/audit/${id}`);
  },

  /** List audits with optional pagination. */
  listAudits(page = 1, perPage = 20): Promise<AuditResponse[]> {
    return apiFetch<AuditResponse[]>(
      `/audits?page=${page}&per_page=${perPage}`,
    );
  },

  /** Delete a single audit. */
  deleteAudit(auditId: string): Promise<DeleteAuditsResponse> {
    return apiFetch<DeleteAuditsResponse>(`/audit/${auditId}`, {
      method: "DELETE",
    });
  },

  /** Delete multiple audits. */
  deleteAudits(auditIds: string[]): Promise<DeleteAuditsResponse> {
    return apiFetch<DeleteAuditsResponse>("/audits", {
      method: "DELETE",
      body: JSON.stringify({ audit_ids: auditIds }),
    });
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
      `/audit/${auditId}/compliance`,
    );
  },

  /** Generate a new rule via LLM. */
  generateRule(request: RuleGenRequest): Promise<RuleGenResponse> {
    return apiFetch<RuleGenResponse>("/rules/generate", {
      method: "POST",
      body: JSON.stringify(request),
    });
  },

  /** Generate a safer rule directly from an audit finding. */
  generateRuleFromFinding(auditId: string, findingId: string): Promise<RuleGenResponse> {
    return apiFetch<RuleGenResponse>(`/audit/${auditId}/findings/${findingId}/generate-rule`, {
      method: "POST",
    });
  },
};
