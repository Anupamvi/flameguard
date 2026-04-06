"use client";

import Link from "next/link";
import React from "react";
import { useSearchParams } from "next/navigation";
import { useAudit, useAuditRules, useAuditCompliance } from "@/hooks/use-audit";
import type { AuditResponse, ComplianceSummary, FindingOut, RuleOut } from "@/lib/types";
import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { RuleTable } from "@/components/audit/rule-table";
import { FindingsPanel } from "@/components/audit/findings-panel";
import { RiskHeatmap } from "@/components/audit/risk-heatmap";
import { ComplianceSummaryPanel } from "@/components/audit/compliance-summary";
import {
  Loader2,
  ShieldAlert,
  ShieldX,
  AlertTriangle,
  AlertCircle,
  ArrowRight,
  BarChart3,
  Clock3,
  Eye,
  FileWarning,
  Lock,
  Radar,
  Upload,
  Wand2,
  ChevronRight,
} from "lucide-react";

type AuditTab = "overview" | "rules" | "findings" | "compliance" | "riskmap";

function isAuditTab(value: string | null): value is AuditTab {
  return value === "overview" || value === "rules" || value === "findings" || value === "compliance" || value === "riskmap";
}

const INTERNET_SOURCES = new Set(["*", "0.0.0.0/0", "0.0.0.0", "internet", "any"]);
const FRAMEWORK_LABELS: Record<string, string> = {
  cis_azure_v2: "CIS Azure Benchmark v2.0",
  pci_dss_v4: "PCI DSS v4.0",
  nist_800_53: "NIST 800-53",
  soc2: "SOC 2",
};
const SENSITIVE_PORTS = [
  { port: "22", label: "SSH" },
  { port: "23", label: "Telnet" },
  { port: "3389", label: "RDP" },
  { port: "1433", label: "SQL Server" },
  { port: "3306", label: "MySQL" },
  { port: "5432", label: "PostgreSQL" },
  { port: "6379", label: "Redis" },
  { port: "9200", label: "Elasticsearch" },
];

function statusColor(status: string) {
  switch (status) {
    case "completed":
      return "bg-sev-pass/10 text-sev-pass";
    case "failed":
      return "bg-sev-critical/10 text-sev-critical";
    default:
      return "bg-sev-medium/10 text-sev-medium";
  }
}

function frameworkLabel(value: string) {
  return FRAMEWORK_LABELS[value] ?? value;
}

function queryErrorMessage(error: unknown) {
  return error instanceof Error ? error.message : "Failed to load data.";
}

function truncateText(value: string | null | undefined, maxLength: number) {
  if (!value) return "";
  if (value.length <= maxLength) return value;
  return `${value.slice(0, maxLength).trimEnd()}...`;
}

function formatDateTime(timestamp: string | null | undefined) {
  if (!timestamp) return "Not available";
  return new Intl.DateTimeFormat("en", {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  }).format(new Date(timestamp));
}

function relativeTime(timestamp: string | null | undefined) {
  if (!timestamp) return "just now";

  const now = Date.now();
  const value = new Date(timestamp).getTime();
  const diffMinutes = Math.round((value - now) / 60000);
  const formatter = new Intl.RelativeTimeFormat("en", { numeric: "auto" });

  if (Math.abs(diffMinutes) < 60) {
    return formatter.format(diffMinutes, "minute");
  }

  const diffHours = Math.round(diffMinutes / 60);
  if (Math.abs(diffHours) < 24) {
    return formatter.format(diffHours, "hour");
  }

  return formatter.format(Math.round(diffHours / 24), "day");
}

function percent(part: number, whole: number) {
  if (whole <= 0) return 0;
  return Math.round((part / whole) * 100);
}

function calculatePostureScore(audit: AuditResponse) {
  const severityPressure =
    audit.critical_count * 5 +
    audit.high_count * 3 +
    audit.medium_count * 2 +
    audit.low_count;
  const denominator = Math.max(1, audit.rule_count * 3);
  return Math.max(0, Math.min(100, 100 - Math.round((severityPressure / denominator) * 100)));
}

function isWildcardPort(value: string) {
  const normalized = value.trim().toLowerCase();
  return normalized === "*" || normalized === "any" || normalized === "0-65535";
}

function portMatches(ports: string[], targetPort: string) {
  const target = Number(targetPort);
  return ports.some((portValue) => {
    const normalized = portValue.trim();

    if (isWildcardPort(normalized)) {
      return true;
    }

    if (normalized.includes("-")) {
      const [start, end] = normalized.split("-").map(Number);
      return Number.isFinite(start) && Number.isFinite(end) && target >= start && target <= end;
    }

    return Number(normalized) === target;
  });
}

function isInboundAllow(rule: RuleOut) {
  const action = rule.action.toLowerCase();
  const direction = rule.direction.toLowerCase();
  return action === "allow" && (direction === "inbound" || direction === "both");
}

function isOutboundAllow(rule: RuleOut) {
  const action = rule.action.toLowerCase();
  const direction = rule.direction.toLowerCase();
  return action === "allow" && (direction === "outbound" || direction === "both");
}

function isInternetSource(addresses: string[]) {
  return addresses.some((address) => INTERNET_SOURCES.has(address.trim().toLowerCase()));
}

function exposedSensitiveServices(rule: RuleOut) {
  return SENSITIVE_PORTS.filter(({ port }) => portMatches(rule.destination_ports, port)).map(
    ({ label, port }) => `${label} (${port})`,
  );
}

function exposurePriority(rule: RuleOut) {
  const sensitiveCount = exposedSensitiveServices(rule).length;
  const wildcardCount = rule.destination_ports.filter(isWildcardPort).length;
  return sensitiveCount * 10 + wildcardCount * 5 + rule.destination_ports.length;
}

function sortPriorityFindings(findings: FindingOut[]) {
  const severityRank: Record<FindingOut["severity"], number> = {
    critical: 4,
    high: 3,
    medium: 2,
    low: 1,
    info: 0,
  };

  return [...findings].sort((left, right) => {
    const severityDelta = severityRank[right.severity] - severityRank[left.severity];
    if (severityDelta !== 0) return severityDelta;

    const confidenceDelta = (right.confidence ?? 0) - (left.confidence ?? 0);
    if (confidenceDelta !== 0) return confidenceDelta;

    const affectedRuleDelta = right.affected_rule_ids.length - left.affected_rule_ids.length;
    if (affectedRuleDelta !== 0) return affectedRuleDelta;

    return left.title.localeCompare(right.title);
  });
}

function findingSourceLabel(source: FindingOut["source"]) {
  switch (source) {
    case "verified":
      return "Verified";
    case "deterministic":
      return "Pattern";
    default:
      return "AI";
  }
}

function findingTone(severity: FindingOut["severity"]) {
  switch (severity) {
    case "critical":
      return {
        accent: "#EF4444",
        labelClass: "bg-sev-critical/10 text-sev-critical",
        borderClass: "border-sev-critical/20",
        tint: "rgba(239,68,68,0.12)",
      };
    case "high":
      return {
        accent: "#F97316",
        labelClass: "bg-sev-high/10 text-sev-high",
        borderClass: "border-sev-high/20",
        tint: "rgba(249,115,22,0.12)",
      };
    case "medium":
      return {
        accent: "#EAB308",
        labelClass: "bg-sev-medium/10 text-sev-medium",
        borderClass: "border-sev-medium/20",
        tint: "rgba(234,179,8,0.1)",
      };
    case "low":
      return {
        accent: "#3B82F6",
        labelClass: "bg-sev-low/10 text-sev-low",
        borderClass: "border-sev-low/20",
        tint: "rgba(59,130,246,0.1)",
      };
    default:
      return {
        accent: "#94A3B8",
        labelClass: "bg-white/[0.06] text-gray-300",
        borderClass: "border-white/[0.08]",
        tint: "rgba(148,163,184,0.08)",
      };
  }
}

function SignalCard({
  label,
  value,
  note,
  icon: Icon,
  accent,
}: {
  label: string;
  value: string | number;
  note: string;
  icon: React.ElementType;
  accent: string;
}) {
  return (
    <div className="relative overflow-hidden rounded-2xl border border-white/[0.08] bg-surface-800/80 p-4">
      <div
        className="absolute inset-x-0 top-0 h-px"
        style={{ background: `linear-gradient(90deg, transparent 0%, ${accent} 50%, transparent 100%)` }}
      />
      <div className="relative flex items-start justify-between gap-4">
        <div>
          <p className="text-sm font-medium text-gray-400">{label}</p>
          <p className="mt-2 text-3xl font-semibold leading-none text-white tabular-nums">{value}</p>
          <p className="mt-2 text-sm leading-relaxed text-gray-500">{note}</p>
        </div>
        <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl" style={{ background: `${accent}15` }}>
          <Icon className="h-5 w-5" style={{ color: accent }} strokeWidth={1.5} />
        </div>
      </div>
    </div>
  );
}

function QuickJumpButton({
  label,
  value,
  note,
  onClick,
}: {
  label: string;
  value: string;
  note: string;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="group flex items-center justify-between rounded-xl border border-white/[0.08] bg-white/[0.04] px-3 py-3 text-left transition-colors hover:border-white/[0.14] hover:bg-white/[0.08]"
    >
      <div>
        <p className="text-sm font-semibold text-gray-100">{label}</p>
        <p className="mt-1 text-xs uppercase tracking-[0.14em] text-gray-500">{note}</p>
      </div>
      <div className="flex items-center gap-2">
        <span className="text-lg font-semibold text-white tabular-nums">{value}</span>
        <ChevronRight className="h-4 w-4 text-gray-600 transition-colors group-hover:text-gray-400" />
      </div>
    </button>
  );
}

function FrameworkSummaryRow({ summary }: { summary: ComplianceSummary }) {
  const applicableControls = summary.total_controls - summary.not_applicable;
  const passingRate = applicableControls > 0 ? percent(summary.passed, applicableControls) : 100;

  return (
    <div className="rounded-xl border border-white/[0.06] bg-black/20 p-4">
      <div className="flex items-center justify-between gap-4">
        <div>
          <p className="text-sm font-semibold text-gray-100">{frameworkLabel(summary.framework)}</p>
          <p className="mt-1 text-xs text-gray-500">
            {summary.failed} failed, {summary.passed} passed, {summary.not_applicable} not applicable
          </p>
        </div>
        <div className="text-right">
          <p className="text-lg font-semibold text-white tabular-nums">{passingRate}%</p>
          <p className="text-xs uppercase tracking-[0.12em] text-gray-500">Passing</p>
        </div>
      </div>
      <div className="mt-3 h-2 overflow-hidden rounded-full bg-white/[0.06]">
        <div className="h-full rounded-full bg-sev-pass" style={{ width: `${passingRate}%` }} />
      </div>
    </div>
  );
}

function ExposureRuleRow({
  rule,
  onReview,
}: {
  rule: RuleOut;
  onReview: () => void;
}) {
  const services = exposedSensitiveServices(rule);
  const serviceLabel = services.length > 0 ? services.join(", ") : rule.destination_ports.join(", ");

  return (
    <button
      type="button"
      onClick={onReview}
      className="group flex w-full items-center justify-between rounded-xl border border-white/[0.06] bg-white/[0.03] px-3 py-3 text-left transition-colors hover:border-white/[0.12] hover:bg-white/[0.06]"
    >
      <div className="min-w-0">
        <p className="truncate text-sm font-semibold text-gray-100">{rule.name}</p>
        <p className="mt-1 truncate text-xs leading-relaxed text-gray-500">
          {rule.action} {rule.direction} {serviceLabel}
        </p>
      </div>
      <ChevronRight className="ml-3 h-4 w-4 shrink-0 text-gray-600 transition-colors group-hover:text-gray-400" />
    </button>
  );
}

function PriorityFindingCard({
  finding,
  onReview,
}: {
  finding: FindingOut;
  onReview: () => void;
}) {
  const tone = findingTone(finding.severity);

  return (
    <div
      className={`relative overflow-hidden rounded-2xl border p-5 ${tone.borderClass}`}
      style={{
        background: `linear-gradient(150deg, ${tone.tint} 0%, rgba(17,24,39,0.78) 45%, rgba(11,15,26,0.98) 100%)`,
        boxShadow: "inset 0 1px 0 rgba(255,255,255,0.04), 0 20px 50px rgba(0,0,0,0.16)",
      }}
    >
      <div className="absolute bottom-0 left-0 top-0 w-1" style={{ backgroundColor: tone.accent }} />
      <div className="ml-1 space-y-4">
        <div className="flex flex-wrap items-center gap-2">
          <span className={`rounded-full px-2.5 py-1 text-xs font-semibold uppercase tracking-[0.14em] ${tone.labelClass}`}>
            {finding.severity}
          </span>
          <span className="rounded-full border border-white/[0.08] bg-white/[0.04] px-2.5 py-1 text-xs font-medium text-gray-300">
            {finding.category}
          </span>
          <span className="rounded-full border border-white/[0.08] bg-white/[0.04] px-2.5 py-1 text-xs font-medium text-gray-400">
            {findingSourceLabel(finding.source)}
          </span>
          {finding.confidence !== null && (
            <span className="rounded-full border border-white/[0.08] bg-white/[0.04] px-2.5 py-1 text-xs font-medium text-gray-400">
              {Math.round(finding.confidence * 100)}% confidence
            </span>
          )}
        </div>

        <div>
          <h3 className="text-lg font-semibold text-gray-100">{finding.title}</h3>
          <p className="mt-2 text-sm leading-relaxed text-gray-300">{truncateText(finding.description, 220)}</p>
        </div>

        <div className="grid gap-3 text-sm sm:grid-cols-2">
          <div className="rounded-xl border border-white/[0.06] bg-black/20 p-3">
            <p className="text-xs font-semibold uppercase tracking-[0.14em] text-gray-500">Impact</p>
            <p className="mt-2 text-gray-200">
              {finding.affected_rule_ids.length} linked rule{finding.affected_rule_ids.length === 1 ? "" : "s"}
            </p>
          </div>
          <div className="rounded-xl border border-white/[0.06] bg-black/20 p-3">
            <p className="text-xs font-semibold uppercase tracking-[0.14em] text-gray-500">Recommended Action</p>
            <p className="mt-2 text-gray-200">
              {truncateText(finding.recommendation, 120) || "Inspect the affected rule set and remove unnecessary exposure."}
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <button
            type="button"
            onClick={onReview}
            className="inline-flex items-center gap-2 rounded-xl bg-white px-3.5 py-2 text-sm font-semibold text-slate-900 transition-colors hover:bg-slate-100"
          >
            Review Finding
            <ArrowRight className="h-4 w-4" />
          </button>
          <Link
            href="/generate"
            className="inline-flex items-center gap-2 rounded-xl border border-white/[0.08] bg-white/[0.04] px-3.5 py-2 text-sm font-semibold text-gray-200 transition-colors hover:bg-white/[0.08]"
          >
            Generate Safer Rule
            <Wand2 className="h-4 w-4 text-flame-400" />
          </Link>
        </div>
      </div>
    </div>
  );
}

export default function AuditDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const searchParams = useSearchParams();
  const requestedTab = searchParams.get("tab");
  const [activeTab, setActiveTab] = React.useState<AuditTab>(isAuditTab(requestedTab) ? requestedTab : "overview");
  const { id } = React.use(params);
  const { data: audit, isLoading: auditLoading } = useAudit(id);
  const {
    data: rules,
    isLoading: rulesLoading,
    error: rulesError,
  } = useAuditRules(audit?.ruleset_id);
  const {
    data: compliance,
    isLoading: complianceLoading,
    error: complianceError,
  } = useAuditCompliance(id);

  React.useEffect(() => {
    if (isAuditTab(requestedTab)) {
      setActiveTab(requestedTab);
    }
  }, [requestedTab]);

  const auditFindings = audit?.findings ?? [];
  const ruleList = rules ?? [];
  const postureScore = audit ? calculatePostureScore(audit) : 100;
  const priorityFindings = React.useMemo(
    () => sortPriorityFindings(auditFindings).slice(0, 3),
    [auditFindings],
  );
  const flaggedRuleIds = React.useMemo(
    () => new Set(auditFindings.flatMap((finding) => finding.affected_rule_ids)),
    [auditFindings],
  );
  const internetExposedRules = React.useMemo(
    () => ruleList.filter((rule) => isInboundAllow(rule) && isInternetSource(rule.source_addresses)),
    [ruleList],
  );
  const sensitiveExposureRules = React.useMemo(
    () => internetExposedRules.filter((rule) => exposedSensitiveServices(rule).length > 0),
    [internetExposedRules],
  );
  const broadOutboundRules = React.useMemo(
    () => ruleList.filter((rule) => isOutboundAllow(rule) && isInternetSource(rule.destination_addresses)),
    [ruleList],
  );
  const surfaceRules = React.useMemo(
    () => [...internetExposedRules].sort((left, right) => exposurePriority(right) - exposurePriority(left)).slice(0, 4),
    [internetExposedRules],
  );
  const complianceStats = React.useMemo(() => {
    if (!compliance || compliance.length === 0) return null;

    const failed = compliance.reduce((sum, summary) => sum + summary.failed, 0);
    const applicable = compliance.reduce(
      (sum, summary) => sum + (summary.total_controls - summary.not_applicable),
      0,
    );

    return {
      failed,
      applicable,
      passingRate: applicable > 0 ? percent(applicable - failed, applicable) : 100,
    };
  }, [compliance]);

  if (auditLoading) {
    return (
      <div className="flex h-64 items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin text-gray-500" />
      </div>
    );
  }

  if (!audit) {
    return (
      <div className="flex h-64 items-center justify-center text-sm text-gray-500">
        Audit not found.
      </div>
    );
  }

  return (
    <div className="max-w-[1280px] space-y-6" style={{ animation: "fadeIn 0.5s ease-out" }}>
      <div
        className="relative overflow-hidden rounded-[28px] border border-white/[0.08] px-7 py-7"
        style={{ background: "linear-gradient(140deg, #151C2F 0%, #0B0F1A 56%, #201321 100%)" }}
      >
        <div
          className="absolute inset-0 opacity-[0.04]"
          style={{
            backgroundImage: "radial-gradient(circle at 1px 1px, white 1px, transparent 0)",
            backgroundSize: "22px 22px",
          }}
        />
        <div className="absolute -left-16 top-14 h-64 w-64 rounded-full bg-sev-critical/10 blur-[110px]" />
        <div className="absolute -right-14 top-0 h-72 w-72 rounded-full bg-flame-500/15 blur-[120px]" />

        <div className="relative grid gap-6 xl:grid-cols-[1.18fr_0.82fr] xl:items-start">
          <div>
            <div className="flex flex-wrap items-center gap-3">
              <div className="flex h-11 w-11 items-center justify-center rounded-2xl bg-flame-500/15">
                <Radar className="h-5 w-5 text-flame-400" strokeWidth={1.5} />
              </div>
              <div>
                <p className="text-xs font-semibold uppercase tracking-[0.22em] text-flame-300/80">Audit Investigation</p>
                <h1 className="mt-1 text-3xl font-bold tracking-tight text-white">{audit.filename}</h1>
              </div>
            </div>

            <div className="mt-4 flex flex-wrap items-center gap-2">
              <Badge className={statusColor(audit.status)}>{audit.status}</Badge>
              <span className="rounded-full border border-white/[0.08] bg-white/[0.04] px-2.5 py-1 text-xs font-medium text-gray-300">
                {audit.vendor || "unknown vendor"}
              </span>
              <span className="rounded-full border border-white/[0.08] bg-white/[0.04] px-2.5 py-1 text-xs font-medium text-gray-400">
                {audit.total_findings} findings
              </span>
              <span title={audit.id} className="rounded-full border border-white/[0.08] bg-white/[0.04] px-2.5 py-1 text-xs font-medium text-gray-400">
                ID {audit.id.slice(0, 8)}...
              </span>
              <span className="rounded-full border border-white/[0.08] bg-white/[0.04] px-2.5 py-1 text-xs font-medium text-gray-400">
                Opened {relativeTime(audit.created_at)}
              </span>
            </div>

            <p className="mt-5 max-w-3xl text-base leading-relaxed text-gray-300">
              {truncateText(audit.summary, 260) || "Use this view to triage exposed services, review rule logic, and translate findings into safer policy changes without leaving the investigation workflow."}
            </p>

            {audit.status !== "completed" && audit.status !== "failed" && (
              <div className="mt-5 flex flex-wrap items-center gap-3 rounded-2xl border border-sev-medium/20 bg-sev-medium/[0.08] px-4 py-3 text-sm text-amber-100">
                <Loader2 className="h-4 w-4 animate-spin text-sev-medium" />
                <span className="font-medium text-sev-medium">Analysis in progress</span>
                <span className="text-amber-50/80">This audit is currently {audit.status}. Findings and compliance data will fill in automatically.</span>
              </div>
            )}

            {audit.status === "failed" && audit.error_message && (
              <div className="mt-5 rounded-2xl border border-sev-critical/25 bg-sev-critical/[0.08] px-4 py-3 text-sm text-red-400">
                {audit.error_message}
              </div>
            )}

            <div className="mt-6 grid gap-3 md:grid-cols-2 xl:grid-cols-4">
              <SignalCard
                label="Posture Score"
                value={`${postureScore}%`}
                note={`${audit.critical_count + audit.high_count} urgent findings across ${audit.rule_count} rules`}
                icon={BarChart3}
                accent={postureScore >= 80 ? "#10B981" : postureScore >= 50 ? "#EAB308" : "#EF4444"}
              />
              <SignalCard
                label="Internet Exposure"
                value={rulesLoading ? "..." : internetExposedRules.length}
                note={rulesLoading ? "Calculating from parsed rules" : "Inbound allow rules reachable from the internet"}
                icon={FileWarning}
                accent={internetExposedRules.length > 0 ? "#F97316" : "#10B981"}
              />
              <SignalCard
                label="Sensitive Services"
                value={rulesLoading ? "..." : sensitiveExposureRules.length}
                note={rulesLoading ? "Checking ports 22, 3389, 1433 and more" : "Management or database services exposed externally"}
                icon={ShieldAlert}
                accent={sensitiveExposureRules.length > 0 ? "#EF4444" : "#10B981"}
              />
              <SignalCard
                label="Failing Controls"
                value={complianceLoading ? "..." : complianceStats ? complianceStats.failed : "--"}
                note={complianceLoading ? "Loading compliance coverage" : complianceStats ? `${complianceStats.applicable} applicable controls reviewed` : "Available after compliance mapping loads"}
                icon={Lock}
                accent={complianceStats && complianceStats.failed > 0 ? "#F97316" : "#10B981"}
              />
            </div>
          </div>

          <div className="relative overflow-hidden rounded-[24px] border border-white/[0.08] bg-surface-800/80 p-5" style={{ boxShadow: "0 24px 60px rgba(0,0,0,0.16)" }}>
            <div className="absolute -right-12 -top-12 h-40 w-40 rounded-full bg-flame-500/20 blur-[90px]" />
            <div className="relative">
              <p className="fg-section-label">Investigation Scope</p>
              <div className="mt-4 grid gap-3 sm:grid-cols-2">
                <div className="rounded-xl border border-white/[0.06] bg-black/20 p-3">
                  <p className="text-xs font-semibold uppercase tracking-[0.14em] text-gray-500">Opened</p>
                  <p className="mt-2 text-lg font-semibold text-white">{formatDateTime(audit.created_at)}</p>
                  <p className="mt-1 text-xs text-gray-500">{relativeTime(audit.created_at)}</p>
                </div>
                <div className="rounded-xl border border-white/[0.06] bg-black/20 p-3">
                  <p className="text-xs font-semibold uppercase tracking-[0.14em] text-gray-500">Completed</p>
                  <p className="mt-2 text-lg font-semibold text-white">{formatDateTime(audit.completed_at)}</p>
                  <p className="mt-1 text-xs text-gray-500">Latest milestone</p>
                </div>
                <div className="rounded-xl border border-white/[0.06] bg-black/20 p-3">
                  <p className="text-xs font-semibold uppercase tracking-[0.14em] text-gray-500">Rules Flagged</p>
                  <p className="mt-2 text-lg font-semibold text-white tabular-nums">{flaggedRuleIds.size}</p>
                  <p className="mt-1 text-xs text-gray-500">{percent(flaggedRuleIds.size, audit.rule_count)}% of the parsed rule inventory</p>
                </div>
                <div className="rounded-xl border border-white/[0.06] bg-black/20 p-3">
                  <p className="text-xs font-semibold uppercase tracking-[0.14em] text-gray-500">Framework Passing</p>
                  <p className="mt-2 text-lg font-semibold text-white tabular-nums">
                    {complianceStats ? `${complianceStats.passingRate}%` : complianceLoading ? "..." : "--"}
                  </p>
                  <p className="mt-1 text-xs text-gray-500">Across mapped compliance frameworks</p>
                </div>
              </div>

              <div className="mt-5 rounded-2xl border border-white/[0.06] bg-black/20 p-4">
                <div className="flex items-center gap-2 text-sm font-medium text-gray-300">
                  <Eye className="h-4 w-4 text-flame-400" strokeWidth={1.5} />
                  Analyst Summary
                </div>
                <p className="mt-3 text-sm leading-relaxed text-gray-300">
                  {truncateText(audit.summary, 220) || "Open the findings and rules tabs to understand why the highest-risk paths are being prioritized."}
                </p>
              </div>

              <div className="mt-5">
                <p className="text-xs font-semibold uppercase tracking-[0.14em] text-gray-500">Jump to</p>
                <div className="mt-3 grid gap-2 sm:grid-cols-2">
                  <QuickJumpButton
                    label="Findings"
                    value={String(audit.total_findings)}
                    note="Priority queue"
                    onClick={() => setActiveTab("findings")}
                  />
                  <QuickJumpButton
                    label="Rules"
                    value={String(audit.rule_count)}
                    note="Parsed inventory"
                    onClick={() => setActiveTab("rules")}
                  />
                  <QuickJumpButton
                    label="Compliance"
                    value={String(compliance?.length ?? 0)}
                    note="Framework sets"
                    onClick={() => setActiveTab("compliance")}
                  />
                  <QuickJumpButton
                    label="Risk Map"
                    value={rulesLoading ? "..." : String(rules?.length ?? 0)}
                    note="Rule scoring"
                    onClick={() => setActiveTab("riskmap")}
                  />
                </div>
              </div>

              <div className="mt-5 flex flex-wrap gap-3">
                <Link
                  href="/audit"
                  className="inline-flex items-center gap-2 rounded-xl bg-white px-4 py-2.5 text-sm font-semibold text-slate-900 transition-colors hover:bg-slate-100"
                >
                  All Audits
                  <ArrowRight className="h-4 w-4" />
                </Link>
                <Link
                  href="/upload"
                  className="inline-flex items-center gap-2 rounded-xl border border-white/[0.08] bg-white/[0.04] px-4 py-2.5 text-sm font-semibold text-gray-200 transition-colors hover:bg-white/[0.08]"
                >
                  Upload Fresh Export
                  <Upload className="h-4 w-4 text-flame-400" />
                </Link>
              </div>
            </div>
          </div>
        </div>
      </div>

      <Tabs value={activeTab} onValueChange={(value) => setActiveTab(value as AuditTab)}>
        <div className="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
          <div>
            <p className="fg-section-label">Investigation Workspace</p>
            <h2 className="mt-2 text-2xl font-semibold text-white">Triage findings, inspect rules, and confirm compliance drift</h2>
          </div>
          <div className="overflow-x-auto pb-1">
            <TabsList>
              <TabsTrigger value="overview">Overview</TabsTrigger>
              <TabsTrigger value="findings">Findings ({audit.total_findings})</TabsTrigger>
              <TabsTrigger value="rules">Rules</TabsTrigger>
              <TabsTrigger value="compliance">Compliance</TabsTrigger>
              <TabsTrigger value="riskmap">Risk Map</TabsTrigger>
            </TabsList>
          </div>
        </div>

        <TabsContent value="overview" className="mt-4 space-y-6">
          <div className="grid gap-6 xl:grid-cols-[1.08fr_0.92fr]">
            <div className="space-y-6">
              <div className="flex flex-wrap items-end justify-between gap-4">
                <div>
                  <p className="fg-section-label">Needs Attention Now</p>
                  <h3 className="mt-2 text-2xl font-semibold text-white">Immediate queue from this audit</h3>
                </div>
                <div className="rounded-full border border-white/[0.08] bg-surface-800/80 px-3 py-1.5 text-sm text-gray-400">
                  {priorityFindings.length > 0 ? `${priorityFindings.length} high-signal issues ready to review` : "Priority cards appear once the audit returns findings"}
                </div>
              </div>

              {priorityFindings.length > 0 ? (
                <div className="space-y-4">
                  {priorityFindings.map((finding) => (
                    <PriorityFindingCard
                      key={finding.id}
                      finding={finding}
                      onReview={() => setActiveTab("findings")}
                    />
                  ))}
                </div>
              ) : (
                <div className="rounded-[24px] border border-white/[0.08] bg-surface-800/80 p-6 text-sm text-gray-400">
                  No prioritized findings are available yet. Completed audits populate this queue automatically.
                </div>
              )}
            </div>

            <div className="space-y-6">
              <Card className="border-white/[0.08] bg-surface-800/80">
                <CardHeader>
                  <div className="flex items-center justify-between gap-3">
                    <div>
                      <p className="fg-section-label">Compliance Watch</p>
                      <CardTitle className="mt-2">Framework coverage in scope</CardTitle>
                    </div>
                    <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-white/[0.04]">
                      <Lock className="h-5 w-5 text-gray-300" strokeWidth={1.5} />
                    </div>
                  </div>
                </CardHeader>
                <CardContent>
                  {complianceLoading ? (
                    <div className="flex items-center gap-2 text-sm text-gray-500">
                      <Loader2 className="h-4 w-4 animate-spin" />
                      Loading compliance results...
                    </div>
                  ) : complianceError ? (
                    <div className="rounded-xl border border-sev-critical/25 bg-sev-critical/[0.08] p-4 text-sm text-red-400">
                      Failed to load compliance results. {queryErrorMessage(complianceError)}
                    </div>
                  ) : compliance && compliance.length > 0 ? (
                    <div className="space-y-3">
                      {[...compliance].sort((left, right) => right.failed - left.failed).map((summary) => (
                        <FrameworkSummaryRow key={summary.framework} summary={summary} />
                      ))}
                    </div>
                  ) : (
                    <p className="text-sm text-gray-500">Compliance summaries appear once framework mappings are available for this audit.</p>
                  )}
                </CardContent>
              </Card>

              <Card className="border-white/[0.08] bg-surface-800/80">
                <CardHeader>
                  <div className="flex items-center justify-between gap-3">
                    <div>
                      <p className="fg-section-label">Exposed Surface</p>
                      <CardTitle className="mt-2">Rule paths most likely to need containment</CardTitle>
                    </div>
                    <div className="rounded-full border border-white/[0.08] bg-white/[0.04] px-3 py-1 text-sm text-gray-400">
                      {rulesLoading ? "Calculating..." : `${internetExposedRules.length} internet-facing`}
                    </div>
                  </div>
                </CardHeader>
                <CardContent className="space-y-4">
                  {rulesLoading ? (
                    <div className="flex items-center gap-2 text-sm text-gray-500">
                      <Loader2 className="h-4 w-4 animate-spin" />
                      Inspecting parsed rule paths...
                    </div>
                  ) : rulesError ? (
                    <div className="rounded-xl border border-sev-critical/25 bg-sev-critical/[0.08] p-4 text-sm text-red-400">
                      Failed to load rules. {queryErrorMessage(rulesError)}
                    </div>
                  ) : (
                    <>
                      <div className="grid gap-3 sm:grid-cols-3">
                        <div className="rounded-xl border border-white/[0.06] bg-black/20 p-3">
                          <p className="text-xs font-semibold uppercase tracking-[0.14em] text-gray-500">Internet-facing</p>
                          <p className="mt-2 text-2xl font-semibold text-white tabular-nums">{internetExposedRules.length}</p>
                          <p className="mt-1 text-xs text-gray-500">Inbound allow rules reachable externally</p>
                        </div>
                        <div className="rounded-xl border border-white/[0.06] bg-black/20 p-3">
                          <p className="text-xs font-semibold uppercase tracking-[0.14em] text-gray-500">Sensitive services</p>
                          <p className="mt-2 text-2xl font-semibold text-white tabular-nums">{sensitiveExposureRules.length}</p>
                          <p className="mt-1 text-xs text-gray-500">Management or data ports exposed</p>
                        </div>
                        <div className="rounded-xl border border-white/[0.06] bg-black/20 p-3">
                          <p className="text-xs font-semibold uppercase tracking-[0.14em] text-gray-500">Wide outbound</p>
                          <p className="mt-2 text-2xl font-semibold text-white tabular-nums">{broadOutboundRules.length}</p>
                          <p className="mt-1 text-xs text-gray-500">Outbound allow rules reaching the internet</p>
                        </div>
                      </div>

                      {surfaceRules.length > 0 ? (
                        <div className="space-y-2">
                          {surfaceRules.map((rule) => (
                            <ExposureRuleRow key={rule.id} rule={rule} onReview={() => setActiveTab("rules")} />
                          ))}
                        </div>
                      ) : (
                        <p className="text-sm text-gray-500">No obvious internet-facing inbound allow rules were detected in the parsed rule set.</p>
                      )}
                    </>
                  )}
                </CardContent>
              </Card>
            </div>
          </div>
        </TabsContent>

        <TabsContent value="findings" className="mt-4 space-y-4">
          <div className="flex flex-wrap items-end justify-between gap-4">
            <div>
              <p className="fg-section-label">Findings</p>
              <h3 className="mt-2 text-2xl font-semibold text-white">Detailed issue breakdown and remediation guidance</h3>
            </div>
            <div className="rounded-full border border-white/[0.08] bg-surface-800/80 px-3 py-1.5 text-sm text-gray-400">
              {audit.total_findings} total findings
            </div>
          </div>
          <FindingsPanel findings={audit.findings} />
        </TabsContent>

        <TabsContent value="rules" className="mt-4 space-y-4">
          <div className="flex flex-wrap items-end justify-between gap-4">
            <div>
              <p className="fg-section-label">Rule Inventory</p>
              <h3 className="mt-2 text-2xl font-semibold text-white">Inspect the parsed policy surface behind this audit</h3>
            </div>
            <div className="rounded-full border border-white/[0.08] bg-surface-800/80 px-3 py-1.5 text-sm text-gray-400">
              {audit.rule_count} parsed rules
            </div>
          </div>

          {rulesLoading ? (
            <div className="flex h-32 items-center justify-center">
              <Loader2 className="h-5 w-5 animate-spin text-gray-500" />
            </div>
          ) : rulesError ? (
            <div className="rounded-lg border border-sev-critical/25 bg-sev-critical/[0.08] p-4 text-sm text-red-400">
              Failed to load rules. {queryErrorMessage(rulesError)}
            </div>
          ) : (
            <RuleTable rules={rules ?? []} />
          )}
        </TabsContent>

        <TabsContent value="compliance" className="mt-4 space-y-4">
          <div className="flex flex-wrap items-end justify-between gap-4">
            <div>
              <p className="fg-section-label">Compliance Mapping</p>
              <h3 className="mt-2 text-2xl font-semibold text-white">Framework evidence aligned to this audit</h3>
            </div>
            <div className="rounded-full border border-white/[0.08] bg-surface-800/80 px-3 py-1.5 text-sm text-gray-400">
              {compliance?.length ?? 0} frameworks
            </div>
          </div>

          {complianceLoading ? (
            <div className="flex h-32 items-center justify-center">
              <Loader2 className="h-5 w-5 animate-spin text-gray-500" />
            </div>
          ) : complianceError ? (
            <div className="rounded-lg border border-sev-critical/25 bg-sev-critical/[0.08] p-4 text-sm text-red-400">
              Failed to load compliance results. {queryErrorMessage(complianceError)}
            </div>
          ) : (
            <ComplianceSummaryPanel summaries={compliance ?? []} />
          )}
        </TabsContent>

        <TabsContent value="riskmap" className="mt-4 space-y-4">
          <div className="flex flex-wrap items-end justify-between gap-4">
            <div>
              <p className="fg-section-label">Risk Map</p>
              <h3 className="mt-2 text-2xl font-semibold text-white">How risk clusters across the parsed rule set</h3>
            </div>
            <div className="rounded-full border border-white/[0.08] bg-surface-800/80 px-3 py-1.5 text-sm text-gray-400">
              Rule severity derived from linked findings
            </div>
          </div>

          {rulesLoading ? (
            <div className="flex h-32 items-center justify-center">
              <Loader2 className="h-5 w-5 animate-spin text-gray-500" />
            </div>
          ) : rulesError ? (
            <div className="rounded-lg border border-sev-critical/25 bg-sev-critical/[0.08] p-4 text-sm text-red-400">
              Failed to load rules for the risk map. {queryErrorMessage(rulesError)}
            </div>
          ) : (
            <RiskHeatmap rules={rules ?? []} findings={audit.findings} />
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
}
