"use client";

import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api-client";

export function useAudits() {
  return useQuery({
    queryKey: ["audits"],
    queryFn: () => api.listAudits(),
  });
}

export function useAudit(id: string) {
  return useQuery({
    queryKey: ["audit", id],
    queryFn: () => api.getAudit(id),
    refetchInterval: (query) => {
      const status = query.state.data?.status;
      if (status === "completed" || status === "failed") return false;
      return 2000;
    },
  });
}

export function useAuditRules(rulesetId: string | undefined) {
  return useQuery({
    queryKey: ["rules", rulesetId],
    queryFn: () => api.getRules(rulesetId!),
    enabled: !!rulesetId,
  });
}

export function useAuditCompliance(auditId: string) {
  return useQuery({
    queryKey: ["compliance", auditId],
    queryFn: () => api.getCompliance(auditId),
  });
}
