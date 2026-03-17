"use client";

import type { FindingOut } from "@/lib/types";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { AlertTriangle, AlertCircle, Info, ShieldAlert, ShieldX } from "lucide-react";

interface FindingsPanelProps {
  findings: FindingOut[];
}

function severityConfig(severity: string) {
  switch (severity) {
    case "critical":
      return { color: "bg-red-100 text-red-800", icon: ShieldX, border: "border-red-200" };
    case "high":
      return { color: "bg-orange-100 text-orange-800", icon: ShieldAlert, border: "border-orange-200" };
    case "medium":
      return { color: "bg-yellow-100 text-yellow-800", icon: AlertTriangle, border: "border-yellow-200" };
    case "low":
      return { color: "bg-blue-100 text-blue-800", icon: AlertCircle, border: "border-blue-200" };
    default:
      return { color: "bg-gray-100 text-gray-800", icon: Info, border: "border-gray-200" };
  }
}

const severityOrder = ["critical", "high", "medium", "low", "info"];

export function FindingsPanel({ findings }: FindingsPanelProps) {
  if (findings.length === 0) {
    return (
      <div className="flex h-32 items-center justify-center text-sm text-slate-500">
        No findings for this audit.
      </div>
    );
  }

  const grouped = severityOrder
    .map((sev) => ({
      severity: sev,
      items: findings.filter((f) => f.severity === sev),
    }))
    .filter((g) => g.items.length > 0);

  return (
    <div className="space-y-6">
      {grouped.map(({ severity, items }) => {
        const config = severityConfig(severity);
        return (
          <div key={severity} className="space-y-3">
            <div className="flex items-center gap-2">
              <Badge className={config.color}>
                {severity.toUpperCase()}
              </Badge>
              <span className="text-sm text-slate-500">
                {items.length} finding{items.length !== 1 ? "s" : ""}
              </span>
            </div>
            <div className="space-y-2">
              {items.map((finding) => {
                const Icon = config.icon;
                return (
                  <Card key={finding.id} className={`border ${config.border}`}>
                    <CardHeader className="pb-2">
                      <div className="flex items-start gap-3">
                        <Icon className="mt-0.5 h-4 w-4 shrink-0 text-slate-500" />
                        <div className="flex-1">
                          <CardTitle className="text-sm">{finding.rule_name}</CardTitle>
                        </div>
                      </div>
                    </CardHeader>
                    <CardContent className="space-y-2">
                      <p className="text-sm text-slate-700">{finding.message}</p>
                      {finding.context && (
                        <pre className="rounded-md bg-slate-100 p-2 text-xs text-slate-600">
                          {finding.context}
                        </pre>
                      )}
                      {finding.remediation && (
                        <div className="rounded-md bg-green-50 p-2">
                          <p className="text-xs font-medium text-green-800">Remediation</p>
                          <p className="mt-1 text-xs text-green-700">{finding.remediation}</p>
                        </div>
                      )}
                      {finding.line_number && (
                        <p className="text-xs text-slate-400">Line {finding.line_number}</p>
                      )}
                    </CardContent>
                  </Card>
                );
              })}
            </div>
          </div>
        );
      })}
    </div>
  );
}
