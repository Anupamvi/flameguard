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

function formatList(values: string[]) {
  return values.length > 0 ? values.join(", ") : "Any";
}

function actionColor(action: string) {
  switch (action) {
    case "allow":
      return "bg-sev-pass/10 text-sev-pass";
    case "deny":
      return "bg-sev-critical/10 text-sev-critical";
    default:
      return "bg-gray-500/10 text-gray-400";
  }
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
              <Badge variant="outline">{rule.vendor}</Badge>
              <Badge className={actionColor(rule.action)}>{rule.action}</Badge>
              <Badge variant="outline">{rule.direction}</Badge>
              <Badge variant="outline">{rule.protocol ?? "Any"}</Badge>
              {rule.priority !== null && (
                <Badge variant="secondary">Priority {rule.priority}</Badge>
              )}
              <Badge variant={rule.enabled ? "default" : "secondary"}>
                {rule.enabled ? "Enabled" : "Disabled"}
              </Badge>
            </div>

            <div className="grid gap-4 sm:grid-cols-2">
              <div>
                <p className="mb-1 text-sm font-medium text-gray-500">Source</p>
                <p className="text-sm text-gray-300">
                  {formatList(rule.source_addresses)}:{formatList(rule.source_ports)}
                </p>
              </div>
              <div>
                <p className="mb-1 text-sm font-medium text-gray-500">Destination</p>
                <p className="text-sm text-gray-300">
                  {formatList(rule.destination_addresses)}:{formatList(rule.destination_ports)}
                </p>
              </div>
            </div>

            <div className="border-t pt-4">
              <p className="mb-2 text-sm font-medium text-gray-200">AI Explanation</p>
              {isLoading ? (
                <div className="flex items-center gap-2 text-sm text-gray-500">
                  <Loader2 className="h-4 w-4 animate-spin" />
                  Generating explanation...
                </div>
              ) : explanation ? (
                <div className="space-y-3">
                  <div>
                    <p className="text-sm font-medium text-gray-500">Summary</p>
                    <p className="mt-1 text-base text-gray-300">{explanation.explanation}</p>
                  </div>
                  {explanation.concerns.length > 0 && (
                    <div>
                      <p className="text-sm font-medium text-gray-500">Key Concerns</p>
                      <ul className="mt-1 list-disc space-y-1 pl-5 text-base text-gray-300">
                        {explanation.concerns.map((concern) => (
                          <li key={concern}>{concern}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              ) : (
                <p className="text-sm text-gray-500">
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
