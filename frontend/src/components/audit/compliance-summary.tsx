"use client";

import { useState } from "react";
import type { ComplianceSummary, ComplianceCheckOut } from "@/lib/types";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ChevronDown, ChevronRight, Check, X, Minus } from "lucide-react";

const FRAMEWORK_LABELS: Record<string, string> = {
  cis_azure_v2: "CIS Azure Benchmark v2.0",
  pci_dss_v4: "PCI DSS v4.0",
  nist_800_53: "NIST 800-53",
  soc2: "SOC 2",
};

function frameworkLabel(id: string): string {
  return FRAMEWORK_LABELS[id] ?? id;
}

interface ComplianceSummaryPanelProps {
  summaries: ComplianceSummary[];
}

function statusIcon(status: ComplianceCheckOut["status"]) {
  switch (status) {
    case "pass":
      return <Check className="h-4 w-4 text-sev-pass" />;
    case "fail":
      return <X className="h-4 w-4 text-sev-critical" />;
    case "not_applicable":
      return <Minus className="h-4 w-4 text-gray-600" />;
  }
}

function scoreColor(score: number) {
  if (score >= 80) return "text-sev-pass";
  if (score >= 50) return "text-sev-medium";
  return "text-sev-critical";
}

export function ComplianceSummaryPanel({ summaries }: ComplianceSummaryPanelProps) {
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});

  if (summaries.length === 0) {
    return (
      <div className="flex h-32 items-center justify-center text-sm text-gray-500">
        No compliance data available.
      </div>
    );
  }

  function toggleExpanded(framework: string) {
    setExpanded((prev) => ({ ...prev, [framework]: !prev[framework] }));
  }

  return (
    <div className="space-y-4">
      {summaries.map((summary) => {
        const isExpanded = expanded[summary.framework] ?? false;
        const applicableControls = summary.total_controls - summary.not_applicable;
        const score = applicableControls > 0 ? (summary.passed / applicableControls) * 100 : 100;

        return (
          <Card key={summary.framework}>
            <CardHeader
              className="cursor-pointer"
              onClick={() => toggleExpanded(summary.framework)}
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  {isExpanded ? (
                    <ChevronDown className="h-4 w-4 text-gray-500" />
                  ) : (
                    <ChevronRight className="h-4 w-4 text-gray-500" />
                  )}
                  <CardTitle className="text-base">{frameworkLabel(summary.framework)}</CardTitle>
                </div>
                <span className={`text-2xl font-bold ${scoreColor(score)}`}>
                  {Math.round(score)}%
                </span>
              </div>
              <div className="ml-7 flex gap-3">
                <Badge className="bg-sev-pass/10 text-sev-pass">
                  {summary.passed} passed
                </Badge>
                <Badge className="bg-sev-critical/10 text-sev-critical">
                  {summary.failed} failed
                </Badge>
                <Badge className="bg-gray-500/10 text-gray-400">
                  {summary.not_applicable} N/A
                </Badge>
              </div>
            </CardHeader>
            {isExpanded && (
              <CardContent>
                <div className="space-y-1">
                  {summary.checks.map((check) => (
                    <div
                      key={check.id}
                      className="flex items-start gap-3 rounded-md px-3 py-2 hover:bg-white/[0.04]"
                    >
                      <span className="mt-0.5 shrink-0">{statusIcon(check.status)}</span>
                      <div className="flex-1">
                        <p className="text-sm font-medium text-gray-300">
                          {check.control_id}: {check.control_title}
                        </p>
                        {check.evidence && (
                          <p className="mt-1 text-sm text-gray-500">{check.evidence}</p>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            )}
          </Card>
        );
      })}
    </div>
  );
}
