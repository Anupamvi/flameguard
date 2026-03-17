"use client";

import Link from "next/link";
import { useAudits } from "@/hooks/use-audit";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { FileSearch, Shield, ScrollText, Loader2, ExternalLink } from "lucide-react";

function statusColor(status: string) {
  switch (status) {
    case "completed":
      return "bg-green-100 text-green-800";
    case "failed":
      return "bg-red-100 text-red-800";
    default:
      return "bg-yellow-100 text-yellow-800";
  }
}

export default function DashboardPage() {
  const { data: audits, isLoading } = useAudits();

  const totalAudits = audits?.length ?? 0;
  const criticalFindings =
    audits?.reduce(
      (sum, a) => sum + a.findings.filter((f) => f.severity === "critical").length,
      0
    ) ?? 0;
  const rulesAnalyzed =
    audits?.reduce((sum, a) => {
      const rc = a.summary?.rule_count;
      return sum + (typeof rc === "number" ? rc : 0);
    }, 0) ?? 0;

  const stats = [
    {
      title: "Total Audits",
      value: totalAudits.toString(),
      description: "Firewall configs analyzed",
      icon: FileSearch,
    },
    {
      title: "Critical Findings",
      value: criticalFindings.toString(),
      description: "Requiring immediate attention",
      icon: Shield,
    },
    {
      title: "Rules Analyzed",
      value: rulesAnalyzed.toString(),
      description: "Across all rulesets",
      icon: ScrollText,
    },
  ];

  return (
    <div className="space-y-8">
      <div>
        <h2 className="text-2xl font-bold tracking-tight text-slate-900">
          Welcome to FlameGuard
        </h2>
        <p className="mt-1 text-sm text-slate-500">
          LLM-powered firewall rule auditor and policy generator
        </p>
      </div>

      {/* Stat cards */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {stats.map(({ title, value, description, icon: Icon }) => (
          <Card key={title}>
            <CardHeader>
              <div className="flex items-center justify-between">
                <CardTitle>{title}</CardTitle>
                <Icon className="h-5 w-5 text-slate-400" />
              </div>
              <CardDescription>{description}</CardDescription>
            </CardHeader>
            <CardContent>
              {isLoading ? (
                <Loader2 className="h-6 w-6 animate-spin text-slate-300" />
              ) : (
                <p className="text-3xl font-bold text-slate-900">{value}</p>
              )}
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Recent Audits */}
      {audits && audits.length > 0 ? (
        <Card>
          <CardHeader>
            <CardTitle>Recent Audits</CardTitle>
            <CardDescription>Your latest firewall configuration audits</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {audits.slice(0, 5).map((audit) => (
                <Link
                  key={audit.id}
                  href={`/audit/${audit.id}`}
                  className="flex items-center justify-between rounded-lg border border-slate-200 p-3 transition-colors hover:bg-slate-50"
                >
                  <div className="flex items-center gap-3">
                    <div>
                      <p className="text-sm font-medium text-slate-900">
                        {audit.filename}
                      </p>
                      <p className="text-xs text-slate-500">
                        {audit.vendor} &middot;{" "}
                        {new Date(audit.created_at).toLocaleDateString()}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-3">
                    <Badge className={statusColor(audit.status)}>
                      {audit.status}
                    </Badge>
                    <span className="text-xs text-slate-400">
                      {audit.findings.length} findings
                    </span>
                    <ExternalLink className="h-4 w-4 text-slate-400" />
                  </div>
                </Link>
              ))}
            </div>
          </CardContent>
        </Card>
      ) : (
        <Card>
          <CardHeader>
            <CardTitle>Get Started</CardTitle>
            <CardDescription>
              Upload a firewall configuration file to begin your first audit.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Link
              href="/upload"
              className="inline-flex items-center rounded-md bg-slate-900 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-slate-800"
            >
              Upload Config
            </Link>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
