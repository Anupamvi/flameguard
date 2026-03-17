"use client";

import { useQuery } from "@tanstack/react-query";
import type { RuleOut } from "@/lib/types";
import { api } from "@/lib/api-client";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import { Badge } from "@/components/ui/badge";
import { Loader2 } from "lucide-react";

interface RuleExplainDialogProps {
  rule: RuleOut | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function RuleExplainDialog({ rule, open, onOpenChange }: RuleExplainDialogProps) {
  const { data: explanation, isLoading } = useQuery({
    queryKey: ["rule-explain", rule?.id],
    queryFn: () => api.explainRule(rule!.id),
    enabled: !!rule && open,
  });

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{rule?.name ?? "Rule Details"}</DialogTitle>
          <DialogDescription>
            {rule?.description ?? "Loading rule details..."}
          </DialogDescription>
        </DialogHeader>

        {rule && (
          <div className="space-y-4">
            <div className="flex flex-wrap gap-2">
              <Badge variant="outline">{rule.category}</Badge>
              <Badge
                className={
                  rule.severity === "critical"
                    ? "bg-red-100 text-red-800"
                    : rule.severity === "high"
                      ? "bg-orange-100 text-orange-800"
                      : rule.severity === "medium"
                        ? "bg-yellow-100 text-yellow-800"
                        : "bg-blue-100 text-blue-800"
                }
              >
                {rule.severity}
              </Badge>
              <Badge variant={rule.enabled ? "default" : "secondary"}>
                {rule.enabled ? "Enabled" : "Disabled"}
              </Badge>
            </div>

            {rule.logic && (
              <div>
                <p className="mb-1 text-xs font-medium text-slate-500">Rule Logic</p>
                <pre className="rounded-md bg-slate-100 p-3 text-xs text-slate-700">
                  {rule.logic}
                </pre>
              </div>
            )}

            <div className="border-t pt-4">
              <p className="mb-2 text-sm font-medium text-slate-800">AI Explanation</p>
              {isLoading ? (
                <div className="flex items-center gap-2 text-sm text-slate-500">
                  <Loader2 className="h-4 w-4 animate-spin" />
                  Generating explanation...
                </div>
              ) : explanation ? (
                <div className="space-y-3">
                  <div>
                    <p className="text-xs font-medium text-slate-500">Plain English</p>
                    <p className="mt-1 text-sm text-slate-700">{explanation.plain_english}</p>
                  </div>
                  <div>
                    <p className="text-xs font-medium text-slate-500">Risk Assessment</p>
                    <p className="mt-1 text-sm text-slate-700">{explanation.risk_assessment}</p>
                  </div>
                  <div>
                    <p className="text-xs font-medium text-slate-500">Remediation</p>
                    <p className="mt-1 text-sm text-slate-700">{explanation.remediation}</p>
                  </div>
                </div>
              ) : (
                <p className="text-sm text-slate-500">
                  Click on a rule to see its AI-generated explanation.
                </p>
              )}
            </div>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}
