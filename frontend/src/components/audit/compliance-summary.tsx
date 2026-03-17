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

interface ComplianceSummaryPanelProps {
  summaries: ComplianceSummary[];
}

function statusIcon(status: ComplianceCheckOut["status"]) {
  switch (status) {
    case "pass":
      return <Check className="h-4 w-4 text-green-600" />;
    case "fail":
      return <X className="h-4 w-4 text-red-600" />;
    case "partial":
      return <Minus className="h-4 w-4 text-yellow-600" />;
    case "not_applicable":
      return <Minus className="h-4 w-4 text-gray-400" />;
  }
}

function scoreColor(score: number) {
  if (score >= 80) return "text-green-600";
  if (score >= 50) return "text-yellow-600";
  return "text-red-600";
}

export function ComplianceSummaryPanel({ summaries }: ComplianceSummaryPanelProps) {
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});

  if (summaries.length === 0) {
    return (
      <div className="flex h-32 items-center justify-center text-sm text-slate-500">
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

        return (
          <Card key={summary.framework}>
            <CardHeader
              className="cursor-pointer"
              onClick={() => toggleExpanded(summary.framework)}
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  {isExpanded ? (
                    <ChevronDown className="h-4 w-4 text-slate-400" />
                  ) : (
                    <ChevronRight className="h-4 w-4 text-slate-400" />
                  )}
                  <CardTitle className="text-base">{summary.framework}</CardTitle>
                </div>
                <span className={`text-2xl font-bold ${scoreColor(summary.score)}`}>
                  {Math.round(summary.score)}%
                </span>
              </div>
              <div className="ml-7 flex gap-3">
                <Badge className="bg-green-100 text-green-800">
                  {summary.passed} passed
                </Badge>
                <Badge className="bg-red-100 text-red-800">
                  {summary.failed} failed
                </Badge>
                {summary.partial > 0 && (
                  <Badge className="bg-yellow-100 text-yellow-800">
                    {summary.partial} partial
                  </Badge>
                )}
                <Badge className="bg-gray-100 text-gray-600">
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
                      className="flex items-start gap-3 rounded-md px-3 py-2 hover:bg-slate-50"
                    >
                      <span className="mt-0.5 shrink-0">{statusIcon(check.status)}</span>
                      <div className="flex-1">
                        <p className="text-sm font-medium text-slate-700">
                          {check.control_id}: {check.control_name}
                        </p>
                        <p className="mt-0.5 text-xs text-slate-500">{check.details}</p>
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
