"use client";

import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { useAudits } from "@/hooks/use-audit";
import { api } from "@/lib/api-client";
import type { AuditResponse, ComplianceSummary, FindingOut } from "@/lib/types";
import { PieChart, Pie, Cell } from "recharts";
import {
  FileSearch,
  Loader2,
  ChevronRight,
  Upload,
  Wand2,
  MessageSquare,
  ShieldX,
  Shield,
  ArrowRight,
  ShieldCheck,
  Lock,
  Flame,
  Eye,
  BarChart3,
  ShieldAlert,
  Clock3,
} from "lucide-react";

const SEV = {
  critical: { color: "#EF4444", label: "Critical" },
  high: { color: "#F97316", label: "High" },
  medium: { color: "#EAB308", label: "Medium" },
  low: { color: "#3B82F6", label: "Low" },
};
const PASS_COLOR = "#10B981";
const EMPTY_ARC = "rgba(255,255,255,0.06)";
const SEVERITY_RANK: Record<FindingOut["severity"], number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

function sortAuditsByCreatedAt(audits: AuditResponse[]) {
  return [...audits].sort(
    (left, right) =>
      new Date(right.created_at).getTime() - new Date(left.created_at).getTime(),
  );
}

function relativeTime(timestamp: string) {
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

  const diffDays = Math.round(diffHours / 24);
  if (Math.abs(diffDays) < 30) {
    return formatter.format(diffDays, "day");
  }

  const diffMonths = Math.round(diffDays / 30);
  if (Math.abs(diffMonths) < 12) {
    return formatter.format(diffMonths, "month");
  }

  return formatter.format(Math.round(diffMonths / 12), "year");
}

function truncateText(value: string | null | undefined, maxLength: number) {
  if (!value) return "";
  if (value.length <= maxLength) return value;
  return `${value.slice(0, maxLength).trimEnd()}...`;
}

function percent(part: number, whole: number) {
  if (whole <= 0) return 0;
  return Math.round((part / whole) * 100);
}

function focusAuditStatusStyle(status: AuditResponse["status"]) {
  switch (status) {
    case "completed":
      return "bg-sev-pass/10 text-sev-pass";
    case "failed":
      return "bg-sev-critical/10 text-sev-critical";
    default:
      return "bg-sev-medium/10 text-sev-medium";
  }
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

function findingSurface(finding: FindingOut) {
  switch (finding.severity) {
    case "critical":
      return {
        accent: SEV.critical.color,
        labelClass: "bg-sev-critical/10 text-sev-critical",
        borderClass: "border-sev-critical/20",
        tint: "rgba(239,68,68,0.12)",
      };
    case "high":
      return {
        accent: SEV.high.color,
        labelClass: "bg-sev-high/10 text-sev-high",
        borderClass: "border-sev-high/20",
        tint: "rgba(249,115,22,0.12)",
      };
    case "medium":
      return {
        accent: SEV.medium.color,
        labelClass: "bg-sev-medium/10 text-sev-medium",
        borderClass: "border-sev-medium/20",
        tint: "rgba(234,179,8,0.1)",
      };
    case "low":
      return {
        accent: SEV.low.color,
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

function PostureRing({ score }: { score: number }) {
  const data = [{ value: score }, { value: Math.max(0, 100 - score) }];
  const color = score >= 80 ? PASS_COLOR : score >= 50 ? SEV.medium.color : SEV.critical.color;

  return (
    <div className="relative mx-auto h-[140px] w-[140px]">
      <PieChart width={140} height={140}>
        <Pie
          data={data}
          cx={70}
          cy={70}
          innerRadius={46}
          outerRadius={62}
          cornerRadius={4}
          dataKey="value"
          startAngle={90}
          endAngle={-270}
          stroke="none"
        >
          <Cell fill={color} />
          <Cell fill={EMPTY_ARC} />
        </Pie>
      </PieChart>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-3xl font-bold tabular-nums" style={{ color }}>
          {score}%
        </span>
        <span className="text-sm text-gray-500">Posture</span>
      </div>
    </div>
  );
}

function SeverityDonut({ data }: { data: { name: string; value: number; color: string }[] }) {
  const total = data.reduce((sum, item) => sum + item.value, 0);

  if (total === 0) {
    return (
      <div className="flex items-center justify-center py-6">
        <p className="text-sm text-gray-500">No findings yet</p>
      </div>
    );
  }

  return (
    <div className="flex items-center gap-5">
      <div className="relative h-[130px] w-[130px] shrink-0">
        <PieChart width={130} height={130}>
          <Pie
            data={data}
            cx={65}
            cy={65}
            innerRadius={40}
            outerRadius={56}
            dataKey="value"
            stroke="rgba(11,15,26,0.8)"
            strokeWidth={2}
          >
            {data.map((item) => (
              <Cell key={item.name} fill={item.color} />
            ))}
          </Pie>
        </PieChart>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-xl font-bold tabular-nums text-white">{total}</span>
          <span className="text-sm text-gray-500">findings</span>
        </div>
      </div>
      <div className="flex min-w-0 flex-col gap-2">
        {data
          .filter((item) => item.value > 0)
          .map((item) => (
            <div key={item.name} className="flex items-center gap-2.5">
              <span className="h-2.5 w-2.5 shrink-0 rounded-sm" style={{ background: item.color }} />
              <span className="w-16 text-xs text-gray-400">{item.name}</span>
              <span className="w-6 text-right text-xs font-semibold tabular-nums text-gray-200">
                {item.value}
              </span>
              <div className="h-1.5 w-16 rounded-full bg-white/[0.06]">
                <div
                  className="h-full rounded-full transition-all"
                  style={{ width: `${(item.value / total) * 100}%`, background: item.color }}
                />
              </div>
            </div>
          ))}
      </div>
    </div>
  );
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

function QuickAction({ href, icon: Icon, title, desc }: {
  href: string;
  icon: React.ElementType;
  title: string;
  desc: string;
}) {
  return (
    <Link href={href} className="group relative overflow-hidden rounded-2xl border border-white/[0.08] bg-surface-800/80 p-5 transition-all hover:border-white/[0.14] hover:bg-surface-700/90">
      <div className="absolute inset-x-0 bottom-0 h-px bg-gradient-to-r from-transparent via-white/[0.14] to-transparent opacity-0 transition-opacity group-hover:opacity-100" />
      <div className="relative flex items-start gap-4">
        <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-flame-500/10">
          <Icon className="h-5 w-5 text-flame-400" strokeWidth={1.5} />
        </div>
        <div className="min-w-0">
          <p className="flex items-center gap-1.5 text-base font-semibold text-gray-100">
            {title}
            <ArrowRight className="h-3.5 w-3.5 -translate-x-1 text-flame-400 opacity-0 transition-all group-hover:translate-x-0 group-hover:opacity-100" />
          </p>
          <p className="mt-1 text-sm leading-relaxed text-gray-500">{desc}</p>
        </div>
      </div>
    </Link>
  );
}

function AuditQueueRow({ audit, focused }: { audit: AuditResponse; focused: boolean }) {
  return (
    <Link
      href={`/audit/${audit.id}`}
      className={`group flex items-center justify-between rounded-xl border px-4 py-3 transition-all hover:border-white/[0.14] hover:bg-surface-700 ${
        focused ? "border-flame-500/25 bg-flame-500/[0.06]" : "border-white/[0.06] bg-surface-800/70"
      }`}
    >
      <div className="flex min-w-0 items-center gap-3">
        <div className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-lg ${
          audit.status === "completed" ? "bg-sev-pass/10" : audit.status === "failed" ? "bg-sev-critical/10" : "bg-sev-medium/10"
        }`}>
          {audit.status === "completed" ? (
            <Shield className="h-4 w-4 text-sev-pass" strokeWidth={1.5} />
          ) : audit.status === "failed" ? (
            <ShieldX className="h-4 w-4 text-sev-critical" strokeWidth={1.5} />
          ) : (
            <Loader2 className="h-4 w-4 animate-spin text-sev-medium" />
          )}
        </div>
        <div className="min-w-0">
          <p className="truncate text-base font-medium text-gray-200">{audit.filename}</p>
          <p className="text-sm text-gray-500">{audit.vendor} &middot; {relativeTime(audit.created_at)}</p>
        </div>
      </div>
      <div className="flex shrink-0 items-center gap-4">
        <div className="flex items-center gap-2 text-xs tabular-nums">
          {audit.critical_count > 0 && <span className="rounded bg-sev-critical/10 px-1.5 py-0.5 font-medium text-sev-critical">{audit.critical_count}C</span>}
          {audit.high_count > 0 && <span className="rounded bg-sev-high/10 px-1.5 py-0.5 font-medium text-sev-high">{audit.high_count}H</span>}
          {audit.medium_count > 0 && <span className="rounded bg-sev-medium/10 px-1.5 py-0.5 font-medium text-sev-medium">{audit.medium_count}M</span>}
        </div>
        <span className="text-sm text-gray-500">{audit.total_findings} findings</span>
        <ChevronRight className="h-4 w-4 text-gray-600 transition-colors group-hover:text-gray-400" />
      </div>
    </Link>
  );
}

function PriorityFindingCard({ finding, auditId }: { finding: FindingOut; auditId: string }) {
  const surface = findingSurface(finding);

  return (
    <div
      className={`relative overflow-hidden rounded-2xl border p-5 ${surface.borderClass}`}
      style={{
        background: `linear-gradient(150deg, ${surface.tint} 0%, rgba(17,24,39,0.78) 45%, rgba(11,15,26,0.98) 100%)`,
        boxShadow: "inset 0 1px 0 rgba(255,255,255,0.04), 0 20px 50px rgba(0,0,0,0.16)",
      }}
    >
      <div className="absolute bottom-0 left-0 top-0 w-1" style={{ backgroundColor: surface.accent }} />
      <div className="ml-1 space-y-4">
        <div className="flex flex-wrap items-center gap-2">
          <span className={`rounded-full px-2.5 py-1 text-xs font-semibold uppercase tracking-[0.14em] ${surface.labelClass}`}>
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
          <p className="mt-2 text-sm leading-relaxed text-gray-300">{truncateText(finding.description, 190)}</p>
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
              {truncateText(finding.recommendation, 110) || "Investigate the affected rule set and reduce unnecessary exposure."}
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <Link href={`/audit/${auditId}`} className="inline-flex items-center gap-2 rounded-xl bg-white px-3.5 py-2 text-sm font-semibold text-slate-900 transition-colors hover:bg-slate-100">
            Investigate
            <ArrowRight className="h-4 w-4" />
          </Link>
          <Link href="/generate" className="inline-flex items-center gap-2 rounded-xl border border-white/[0.08] bg-white/[0.04] px-3.5 py-2 text-sm font-semibold text-gray-200 transition-colors hover:bg-white/[0.08]">
            Generate Safer Rule
            <Wand2 className="h-4 w-4 text-flame-400" />
          </Link>
        </div>
      </div>
    </div>
  );
}

function FrameworkRow({ summary }: { summary: ComplianceSummary }) {
  const passingRate = percent(summary.passed, summary.total_controls);

  return (
    <div className="rounded-xl border border-white/[0.06] bg-surface-800/80 p-4">
      <div className="flex items-center justify-between gap-4">
        <div>
          <p className="text-sm font-semibold text-gray-100">{summary.framework}</p>
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

function EmptyDashboard() {
  return (
    <div className="max-w-[1280px] space-y-6" style={{ animation: "fadeIn 0.5s ease-out" }}>
      <div className="relative overflow-hidden rounded-[28px] border border-white/[0.08] p-7" style={{ background: "linear-gradient(135deg, #151C2F 0%, #0B0F1A 56%, #201321 100%)" }}>
        <div className="absolute inset-0 opacity-[0.04]" style={{ backgroundImage: "radial-gradient(circle at 1px 1px, white 1px, transparent 0)", backgroundSize: "22px 22px" }} />
        <div className="absolute -right-16 -top-10 h-56 w-56 rounded-full bg-flame-500/20 blur-[90px]" />
        <div className="relative grid gap-8 lg:grid-cols-[1.2fr_0.8fr] lg:items-start">
          <div>
            <div className="flex items-center gap-2.5">
              <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-flame-500/15">
                <Flame className="h-5 w-5 text-flame-400" strokeWidth={1.5} />
              </div>
              <div>
                <p className="text-xs font-semibold uppercase tracking-[0.22em] text-flame-300/80">Security Command Center</p>
                <h1 className="mt-1 text-3xl font-bold tracking-tight text-white">Start with one export, then triage like a real SOC workflow.</h1>
              </div>
            </div>

            <p className="mt-5 max-w-2xl text-base leading-relaxed text-gray-300">
              FlameGuard is strongest when it has live audit data to prioritize. Upload an Azure Firewall or NSG export and the dashboard will reorganize itself around risk, compliance drift, and the next actions your team should take.
            </p>

            <div className="mt-6 flex flex-wrap gap-3">
              <Link href="/upload" className="inline-flex items-center gap-2 rounded-xl bg-flame-500 px-4 py-3 text-sm font-semibold text-white transition-colors hover:bg-flame-600">
                <Upload className="h-4 w-4" />
                Upload Your First Config
              </Link>
              <Link href="/generate" className="inline-flex items-center gap-2 rounded-xl border border-white/[0.08] bg-white/[0.04] px-4 py-3 text-sm font-semibold text-gray-200 transition-colors hover:bg-white/[0.08]">
                <Wand2 className="h-4 w-4 text-flame-400" />
                Try Rule Generator
              </Link>
            </div>
          </div>

          <div className="rounded-[24px] border border-white/[0.08] bg-surface-800/75 p-5">
            <p className="fg-section-label">What appears after the first audit</p>
            <div className="mt-4 grid gap-3 sm:grid-cols-2">
              <SignalCard label="Posture" value="Live" note="A single score backed by audit context, not generic vanity metrics." icon={ShieldCheck} accent={PASS_COLOR} />
              <SignalCard label="Triage Queue" value="Top 3" note="Immediate investigation cards for the most urgent findings." icon={ShieldAlert} accent={SEV.critical.color} />
            </div>
          </div>
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-3">
        <QuickAction href="/upload" icon={Upload} title="Upload Export" desc="Start the command center with a real Azure Firewall or NSG export." />
        <QuickAction href="/generate" icon={Wand2} title="Generate Rule" desc="Draft a safer rule with natural language before you deploy it." />
        <QuickAction href="/chat" icon={MessageSquare} title="Ask Security Questions" desc="Use the assistant to explore remediation strategy and policy intent." />
      </div>
    </div>
  );
}

export default function DashboardPage() {
  const { data: audits, isLoading } = useAudits();

  const orderedAudits = sortAuditsByCreatedAt(audits ?? []);
  const latestAudit = orderedAudits[0] ?? null;
  const focusAuditSummary = orderedAudits.find((audit) => audit.status === "completed") ?? latestAudit;
  const focusAuditId = focusAuditSummary?.id;

  const { data: focusAuditDetail, isLoading: focusAuditLoading } = useQuery<AuditResponse>({
    queryKey: ["dashboard", "focus-audit", focusAuditId],
    queryFn: () => api.getAudit(focusAuditId!),
    enabled: Boolean(focusAuditId) && focusAuditSummary?.status === "completed",
  });

  const { data: focusCompliance, isLoading: complianceLoading } = useQuery<ComplianceSummary[]>({
    queryKey: ["dashboard", "focus-compliance", focusAuditId],
    queryFn: () => api.getCompliance(focusAuditId!),
    enabled: Boolean(focusAuditId) && focusAuditSummary?.status === "completed",
  });

  const focusAudit = focusAuditDetail ?? focusAuditSummary ?? null;
  const totalAudits = orderedAudits.length;
  const criticalTotal = orderedAudits.reduce((sum, audit) => sum + audit.critical_count, 0);
  const highTotal = orderedAudits.reduce((sum, audit) => sum + audit.high_count, 0);
  const mediumTotal = orderedAudits.reduce((sum, audit) => sum + audit.medium_count, 0);
  const lowTotal = orderedAudits.reduce((sum, audit) => sum + audit.low_count, 0);
  const rulesTotal = orderedAudits.reduce((sum, audit) => sum + audit.rule_count, 0);
  const urgentFindings = criticalTotal + highTotal;
  const postureScore = rulesTotal > 0 ? Math.max(0, Math.min(100, Math.round(100 - (urgentFindings / rulesTotal) * 100))) : 100;
  const focusSeverityData = [
    { name: "Critical", value: focusAudit?.critical_count ?? 0, color: SEV.critical.color },
    { name: "High", value: focusAudit?.high_count ?? 0, color: SEV.high.color },
    { name: "Medium", value: focusAudit?.medium_count ?? 0, color: SEV.medium.color },
    { name: "Low", value: focusAudit?.low_count ?? 0, color: SEV.low.color },
  ];
  const priorityFindings = [...(focusAudit?.findings ?? [])]
    .sort((left, right) => {
      const severityDelta = SEVERITY_RANK[right.severity] - SEVERITY_RANK[left.severity];
      if (severityDelta !== 0) return severityDelta;

      const confidenceDelta = (right.confidence ?? 0) - (left.confidence ?? 0);
      if (confidenceDelta !== 0) return confidenceDelta;

      return right.affected_rule_ids.length - left.affected_rule_ids.length;
    })
    .slice(0, 3);
  const failedControls = (focusCompliance ?? []).reduce((sum, summary) => sum + summary.failed, 0);
  const totalControls = (focusCompliance ?? []).reduce((sum, summary) => sum + summary.total_controls, 0);
  const frameworkPassingRate = percent(totalControls - failedControls, totalControls);
  const focusUrgentCount = (focusAudit?.critical_count ?? 0) + (focusAudit?.high_count ?? 0);
  const activeAnalysis = latestAudit && latestAudit.status !== "completed" && latestAudit.status !== "failed" ? latestAudit : null;

  if (isLoading) {
    return (
      <div className="flex h-64 items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin text-gray-600" />
      </div>
    );
  }

  if (!latestAudit) {
    return <EmptyDashboard />;
  }

  return (
    <div className="max-w-[1280px] space-y-6" style={{ animation: "fadeIn 0.5s ease-out" }}>
      <div className="relative overflow-hidden rounded-[28px] border border-white/[0.08] px-7 py-7" style={{ background: "linear-gradient(140deg, #151C2F 0%, #0B0F1A 56%, #201321 100%)" }}>
        <div className="absolute inset-0 opacity-[0.04]" style={{ backgroundImage: "radial-gradient(circle at 1px 1px, white 1px, transparent 0)", backgroundSize: "22px 22px" }} />
        <div className="absolute -left-16 top-14 h-64 w-64 rounded-full bg-sev-critical/10 blur-[110px]" />
        <div className="absolute -right-14 top-0 h-72 w-72 rounded-full bg-flame-500/15 blur-[120px]" />

        <div className="relative grid gap-6 xl:grid-cols-[1.25fr_0.95fr] xl:items-start">
          <div>
            <div className="flex flex-wrap items-center gap-3">
              <div className="flex h-11 w-11 items-center justify-center rounded-2xl bg-flame-500/15">
                <Flame className="h-5 w-5 text-flame-400" strokeWidth={1.5} />
              </div>
              <div>
                <p className="text-xs font-semibold uppercase tracking-[0.22em] text-flame-300/80">Security Command Center</p>
                <h1 className="mt-1 text-3xl font-bold tracking-tight text-white">Prioritize what matters before the next rule change ships.</h1>
              </div>
            </div>

            <p className="mt-5 max-w-3xl text-base leading-relaxed text-gray-300">
              FlameGuard now opens like a triage console: one investigation focus, one clear queue, and one set of next actions. The goal is the same pattern used by stronger cloud-security products: reduce operator hesitation and make the highest-risk work obvious.
            </p>

            {activeAnalysis && (
              <div className="mt-5 flex flex-wrap items-center gap-3 rounded-2xl border border-sev-medium/20 bg-sev-medium/[0.08] px-4 py-3 text-sm text-amber-100">
                <Loader2 className="h-4 w-4 animate-spin text-sev-medium" />
                <span className="font-medium text-sev-medium">Active analysis</span>
                <span className="text-amber-50/80">{activeAnalysis.filename} is currently {activeAnalysis.status}. Results refresh automatically.</span>
                <Link href={`/audit/${activeAnalysis.id}`} className="font-semibold text-white hover:text-gray-200">Open live audit</Link>
              </div>
            )}

            <div className="mt-6 grid gap-3 md:grid-cols-2 xl:grid-cols-4">
              <SignalCard
                label="Posture Score"
                value={`${postureScore}%`}
                note={`${urgentFindings} urgent findings across ${totalAudits} audits`}
                icon={ShieldCheck}
                accent={postureScore >= 80 ? PASS_COLOR : postureScore >= 50 ? SEV.medium.color : SEV.critical.color}
              />
              <SignalCard
                label="Immediate Queue"
                value={focusUrgentCount}
                note="Critical and high findings in the current investigation focus"
                icon={ShieldAlert}
                accent={focusUrgentCount > 0 ? SEV.critical.color : PASS_COLOR}
              />
              <SignalCard
                label="Controls Failing"
                value={focusCompliance ? failedControls : "--"}
                note={focusCompliance ? `Across ${focusCompliance.length} mapped frameworks` : "Available on completed audits with compliance mapping"}
                icon={Lock}
                accent={focusCompliance && failedControls > 0 ? SEV.high.color : PASS_COLOR}
              />
              <SignalCard
                label="Latest Scan"
                value={relativeTime(latestAudit.created_at)}
                note={`${latestAudit.vendor} audit is ${latestAudit.status}`}
                icon={Clock3}
                accent={latestAudit.status === "completed" ? PASS_COLOR : SEV.medium.color}
              />
            </div>
          </div>

          <div className="relative overflow-hidden rounded-[24px] border border-white/[0.08] bg-surface-800/80 p-5" style={{ boxShadow: "0 24px 60px rgba(0,0,0,0.16)" }}>
            <div className="absolute -right-12 -top-12 h-40 w-40 rounded-full blur-[90px]" style={{ background: `${focusUrgentCount > 0 ? SEV.critical.color : PASS_COLOR}22` }} />
            <div className="relative">
              <div className="flex items-start justify-between gap-4">
                <div>
                  <p className="fg-section-label">Investigation Focus</p>
                  <h2 className="mt-2 text-xl font-semibold text-white">{focusAudit?.filename ?? "No audit selected"}</h2>
                  <p className="mt-2 text-sm leading-relaxed text-gray-400">
                    {focusAudit?.vendor ?? "Unknown vendor"} &middot; Selected for triage {relativeTime(focusAudit?.created_at ?? latestAudit.created_at)}
                  </p>
                </div>
                <span className={`rounded-full px-2.5 py-1 text-xs font-semibold uppercase tracking-[0.16em] ${focusAuditStatusStyle(focusAudit?.status ?? "pending")}`}>
                  {focusAudit?.status ?? "pending"}
                </span>
              </div>

              <div className="mt-5 grid gap-3 sm:grid-cols-3">
                <div className="rounded-xl border border-white/[0.06] bg-black/20 p-3">
                  <p className="text-xs font-semibold uppercase tracking-[0.14em] text-gray-500">Rules</p>
                  <p className="mt-2 text-2xl font-semibold text-white tabular-nums">{focusAudit?.rule_count ?? 0}</p>
                </div>
                <div className="rounded-xl border border-white/[0.06] bg-black/20 p-3">
                  <p className="text-xs font-semibold uppercase tracking-[0.14em] text-gray-500">Findings</p>
                  <p className="mt-2 text-2xl font-semibold text-white tabular-nums">{focusAudit?.total_findings ?? 0}</p>
                </div>
                <div className="rounded-xl border border-white/[0.06] bg-black/20 p-3">
                  <p className="text-xs font-semibold uppercase tracking-[0.14em] text-gray-500">Framework Passing</p>
                  <p className="mt-2 text-2xl font-semibold text-white tabular-nums">{focusCompliance ? `${frameworkPassingRate}%` : "--"}</p>
                </div>
              </div>

              <div className="mt-5 rounded-2xl border border-white/[0.06] bg-black/20 p-4">
                <div className="flex items-center gap-2 text-sm font-medium text-gray-300">
                  <Eye className="h-4 w-4 text-flame-400" strokeWidth={1.5} />
                  Analyst Summary
                </div>
                {focusAuditLoading ? (
                  <div className="mt-3 flex items-center gap-2 text-sm text-gray-500">
                    <Loader2 className="h-4 w-4 animate-spin" />
                    Loading audit context...
                  </div>
                ) : (
                  <p className="mt-3 text-sm leading-relaxed text-gray-300">
                    {truncateText(focusAudit?.summary, 260) || "Open this audit to inspect rule inventory, linked findings, and remediation-ready guidance."}
                  </p>
                )}
              </div>

              <div className="mt-5 flex flex-wrap gap-3">
                <Link href={`/audit/${focusAudit?.id ?? latestAudit.id}`} className="inline-flex items-center gap-2 rounded-xl bg-white px-4 py-2.5 text-sm font-semibold text-slate-900 transition-colors hover:bg-slate-100">
                  Open Audit
                  <ArrowRight className="h-4 w-4" />
                </Link>
                <Link href="/upload" className="inline-flex items-center gap-2 rounded-xl border border-white/[0.08] bg-white/[0.04] px-4 py-2.5 text-sm font-semibold text-gray-200 transition-colors hover:bg-white/[0.08]">
                  Upload Another Export
                  <Upload className="h-4 w-4 text-flame-400" />
                </Link>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="grid gap-5 xl:grid-cols-[1.15fr_0.85fr]">
        <div className="space-y-5">
          <div className="flex flex-wrap items-end justify-between gap-4">
            <div>
              <p className="fg-section-label">Needs Attention Now</p>
              <h2 className="mt-2 text-2xl font-semibold text-white">Priority queue from the current focus audit</h2>
            </div>
            <div className="rounded-full border border-white/[0.08] bg-surface-800/80 px-3 py-1.5 text-sm text-gray-400">
              {priorityFindings.length > 0 ? `${priorityFindings.length} high-signal findings ready for review` : "Completed audits populate this queue automatically"}
            </div>
          </div>

          {priorityFindings.length > 0 ? (
            <div className="space-y-4">
              {priorityFindings.map((finding) => (
                <PriorityFindingCard key={finding.id} finding={finding} auditId={focusAudit!.id} />
              ))}
            </div>
          ) : (
            <div className="rounded-[24px] border border-white/[0.08] bg-surface-800/80 p-6 text-sm text-gray-400">
              No prioritized findings yet. Complete an audit to surface the most urgent issues here.
            </div>
          )}

          <div className="grid gap-4 md:grid-cols-3">
            <QuickAction href="/upload" icon={Upload} title="Ingest New Config" desc="Upload the next Azure Firewall or NSG export without leaving the investigation flow." />
            <QuickAction href="/generate" icon={Wand2} title="Generate Safer Rule" desc="Turn remediation intent into a draft rule while the risky pattern is still in view." />
            <QuickAction href="/audit" icon={FileSearch} title="Review Audit Queue" desc="Jump across prior investigations, compare severity patterns, and reopen earlier scans." />
          </div>
        </div>

        <div className="space-y-5">
          <div className="rounded-[24px] border border-white/[0.08] bg-surface-800/80 p-5">
            <div className="flex items-center justify-between gap-3">
              <div>
                <p className="fg-section-label">Risk Distribution</p>
                <h3 className="mt-2 text-xl font-semibold text-white">Current risk posture</h3>
              </div>
              <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-white/[0.04]">
                <BarChart3 className="h-5 w-5 text-gray-300" strokeWidth={1.5} />
              </div>
            </div>

            <div className="mt-5 grid gap-5 md:grid-cols-[150px_1fr] md:items-center">
              <PostureRing score={postureScore} />
              <SeverityDonut data={focusSeverityData} />
            </div>
          </div>

          <div className="rounded-[24px] border border-white/[0.08] bg-surface-800/80 p-5">
            <div className="flex items-center justify-between gap-3">
              <div>
                <p className="fg-section-label">Framework Coverage</p>
                <h3 className="mt-2 text-xl font-semibold text-white">Compliance mapping</h3>
              </div>
              <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-white/[0.04]">
                <Lock className="h-5 w-5 text-gray-300" strokeWidth={1.5} />
              </div>
            </div>

            {complianceLoading ? (
              <div className="mt-5 flex items-center gap-2 text-sm text-gray-500">
                <Loader2 className="h-4 w-4 animate-spin" />
                Loading framework coverage...
              </div>
            ) : focusCompliance && focusCompliance.length > 0 ? (
              <div className="mt-5 space-y-3">
                {[...focusCompliance].sort((left, right) => right.failed - left.failed).map((summary) => (
                  <FrameworkRow key={summary.framework} summary={summary} />
                ))}
              </div>
            ) : (
              <div className="mt-5 rounded-xl border border-white/[0.06] bg-black/20 p-4 text-sm text-gray-400">
                Compliance summaries appear once a completed audit has framework mappings available.
              </div>
            )}
          </div>

          <div className="rounded-[24px] border border-white/[0.08] bg-surface-800/80 p-5">
            <div className="flex items-end justify-between gap-3">
              <div>
                <p className="fg-section-label">Audit Queue</p>
                <h3 className="mt-2 text-xl font-semibold text-white">Recent investigations</h3>
              </div>
              <div className="rounded-full border border-white/[0.08] bg-white/[0.04] px-3 py-1 text-sm text-gray-400">
                {totalAudits} total audits
              </div>
            </div>

            <div className="mt-5 space-y-2">
              {orderedAudits.slice(0, 5).map((audit) => (
                <AuditQueueRow key={audit.id} audit={audit} focused={audit.id === focusAudit?.id} />
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}