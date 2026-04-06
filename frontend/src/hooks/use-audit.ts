"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api-client";
import type { DeleteAuditsResponse } from "@/lib/types";

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
    retry: 2,
    refetchInterval: (query) => {
      if (query.state.error) return false;
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

export function useDeleteAudits() {
  const queryClient = useQueryClient();

  return useMutation<DeleteAuditsResponse, Error, string[]>({
    mutationFn: (auditIds) => {
      if (auditIds.length === 1) {
        return api.deleteAudit(auditIds[0]);
      }
      return api.deleteAudits(auditIds);
    },
    onSuccess: async (_, auditIds) => {
      await queryClient.invalidateQueries({ queryKey: ["audits"] });
      await Promise.all(
        auditIds.map((auditId) => queryClient.removeQueries({ queryKey: ["audit", auditId] }))
      );
      queryClient.removeQueries({ queryKey: ["rules"] });
      queryClient.removeQueries({ queryKey: ["compliance"] });
    },
  });
}
