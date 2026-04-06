"use client";

import type { FindingOut } from "@/lib/types";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { AlertTriangle, AlertCircle, Info, ShieldAlert, ShieldX, CheckCircle2, Cpu, BrainCircuit } from "lucide-react";

interface FindingsPanelProps {
  findings: FindingOut[];
}

function severityConfig(severity: string) {
  switch (severity) {
    case "critical":
      return { color: "bg-sev-critical/10 text-sev-critical", icon: ShieldX, border: "border-sev-critical/25", leftBorder: "border-l-[3px] border-l-sev-critical" };
    case "high":
      return { color: "bg-sev-high/10 text-sev-high", icon: ShieldAlert, border: "border-sev-high/25", leftBorder: "border-l-[3px] border-l-sev-high" };
    case "medium":
      return { color: "bg-sev-medium/10 text-sev-medium", icon: AlertTriangle, border: "border-sev-medium/25", leftBorder: "border-l-[3px] border-l-sev-medium" };
    case "low":
      return { color: "bg-sev-low/10 text-sev-low", icon: AlertCircle, border: "border-sev-low/25", leftBorder: "border-l-[3px] border-l-sev-low" };
    default:
      return { color: "bg-gray-500/10 text-gray-400", icon: Info, border: "border-gray-500/25", leftBorder: "" };
  }
}

function sourceConfig(source: string) {
  switch (source) {
    case "verified":
      return {
        label: "Verified",
        tooltip: "Confirmed by both pattern analysis and AI",
        color: "bg-emerald-500/10 text-emerald-400 border-emerald-500/25",
        icon: CheckCircle2,
      };
    case "deterministic":
      return {
        label: "Pattern match",
        tooltip: "Detected by deterministic rule analysis",
        color: "bg-violet-500/10 text-violet-400 border-violet-500/25",
        icon: Cpu,
      };
    default:
      return {
        label: "AI analysis",
        tooltip: "Identified by LLM analysis",
        color: "bg-sky-500/10 text-sky-400 border-sky-500/25",
        icon: BrainCircuit,
      };
  }
}

function confidenceColor(confidence: number): string {
  if (confidence >= 0.9) return "text-emerald-400 bg-emerald-500/10 border-emerald-500/25";
  if (confidence >= 0.7) return "text-sky-400 bg-sky-500/10 border-sky-500/25";
  if (confidence >= 0.5) return "text-amber-400 bg-amber-500/10 border-amber-500/25";
  return "text-red-400 bg-red-500/10 border-red-500/25";
}

const severityOrder = ["critical", "high", "medium", "low", "info"];

export function FindingsPanel({ findings }: FindingsPanelProps) {
  if (findings.length === 0) {
    return (
      <div className="flex h-32 items-center justify-center text-sm text-gray-500">
        No findings for this audit.
      </div>
    );
  }

  const verifiedCount = findings.filter((f) => f.source === "verified").length;
  const detCount = findings.filter((f) => f.source === "deterministic").length;
  const llmCount = findings.filter((f) => f.source === "llm" || !f.source).length;

  const grouped = severityOrder
    .map((sev) => ({
      severity: sev,
      items: findings.filter((f) => f.severity === sev),
    }))
    .filter((g) => g.items.length > 0);

  return (
    <div className="space-y-6">
      {/* Source summary bar */}
      {(verifiedCount > 0 || detCount > 0) && (
        <div className="flex flex-wrap gap-3 rounded-lg border border-white/[0.06] bg-surface-700 p-3 text-sm">
          {verifiedCount > 0 && (
            <span className="flex items-center gap-1.5">
              <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
              <span className="font-medium text-emerald-400">{verifiedCount} verified</span>
              <span className="text-gray-500">(AI + pattern match agree)</span>
            </span>
          )}
          {detCount > 0 && (
            <span className="flex items-center gap-1.5">
              <Cpu className="h-3.5 w-3.5 text-violet-400" />
              <span className="font-medium text-violet-400">{detCount} pattern-only</span>
            </span>
          )}
          {llmCount > 0 && (
            <span className="flex items-center gap-1.5">
              <BrainCircuit className="h-3.5 w-3.5 text-sky-400" />
              <span className="font-medium text-sky-400">{llmCount} AI-only</span>
            </span>
          )}
        </div>
      )}

      {grouped.map(({ severity, items }) => {
        const config = severityConfig(severity);
        return (
          <div key={severity} className="space-y-3">
            <div className="flex items-center gap-2">
              <Badge className={config.color}>
                {severity.toUpperCase()}
              </Badge>
              <span className="text-sm text-gray-500">
                {items.length} finding{items.length !== 1 ? "s" : ""}
              </span>
            </div>
            <div className="space-y-2">
              {items.map((finding) => {
                const Icon = config.icon;
                const src = sourceConfig(finding.source || "llm");
                const SrcIcon = src.icon;
                return (
                  <Card key={finding.id} className={`border ${config.border} ${config.leftBorder}`}>
                    <CardHeader className="pb-2">
                      <div className="flex items-start gap-3">
                        <Icon className="mt-0.5 h-4 w-4 shrink-0 text-gray-500" />
                        <div className="flex-1">
                          <CardTitle className="text-base">{finding.title}</CardTitle>
                          <div className="mt-2 flex flex-wrap gap-2">
                            <Badge variant="outline">{finding.category}</Badge>
                            <Badge variant="outline" className={src.color} title={src.tooltip}>
                              <SrcIcon className="mr-1 h-3 w-3" />
                              {src.label}
                            </Badge>
                            {finding.confidence !== null && (
                              <Badge
                                variant="outline"
                                className={confidenceColor(finding.confidence)}
                              >
                                {Math.round(finding.confidence * 100)}% confidence
                              </Badge>
                            )}
                          </div>
                        </div>
                      </div>
                    </CardHeader>
                    <CardContent className="space-y-2">
                      <p className="text-sm text-gray-300">{finding.description}</p>
                      {finding.affected_rule_ids.length > 0 && (
                        <p className="text-sm text-gray-500">
                          Affected rules: {finding.affected_rule_ids.length}
                        </p>
                      )}
                      {finding.recommendation && (
                        <div className="rounded-md border border-sev-pass/25 bg-sev-pass/[0.08] p-2">
                          <p className="text-sm font-medium text-sev-pass">Remediation</p>
                          <p className="mt-1 text-sm text-emerald-300/80">{finding.recommendation}</p>
                        </div>
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
