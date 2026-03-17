"use client";

import React from "react";
import { useAudit, useAuditRules, useAuditCompliance } from "@/hooks/use-audit";
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
import { Loader2, ShieldAlert, ShieldX, AlertTriangle, AlertCircle } from "lucide-react";

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

interface SeverityCardProps {
  label: string;
  count: number;
  colorClass: string;
  icon: React.ReactNode;
}

function SeverityCard({ label, count, colorClass, icon }: SeverityCardProps) {
  return (
    <Card>
      <CardContent className="flex items-center gap-3 pt-4">
        <div className={`rounded-lg p-2 ${colorClass}`}>{icon}</div>
        <div>
          <p className="text-2xl font-bold text-slate-900">{count}</p>
          <p className="text-xs text-slate-500">{label}</p>
        </div>
      </CardContent>
    </Card>
  );
}

export default function AuditDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = React.use(params);
  const { data: audit, isLoading: auditLoading } = useAudit(id);
  const { data: rules } = useAuditRules(audit?.id);
  const { data: compliance } = useAuditCompliance(id);

  if (auditLoading) {
    return (
      <div className="flex h-64 items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin text-slate-400" />
      </div>
    );
  }

  if (!audit) {
    return (
      <div className="flex h-64 items-center justify-center text-sm text-slate-500">
        Audit not found.
      </div>
    );
  }

  const criticalCount = audit.findings.filter((f) => f.severity === "critical").length;
  const highCount = audit.findings.filter((f) => f.severity === "high").length;
  const mediumCount = audit.findings.filter((f) => f.severity === "medium").length;
  const lowCount = audit.findings.filter((f) => f.severity === "low").length;

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <h2 className="text-2xl font-bold tracking-tight text-slate-900">
            Audit: {audit.filename}
          </h2>
          <p className="mt-1 text-sm text-slate-500">
            Vendor: {audit.vendor} &middot; ID: {audit.id}
          </p>
        </div>
        <Badge className={statusColor(audit.status)}>{audit.status}</Badge>
      </div>

      <Tabs defaultValue="overview">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="rules">Rules</TabsTrigger>
          <TabsTrigger value="findings">
            Findings ({audit.findings.length})
          </TabsTrigger>
          <TabsTrigger value="compliance">Compliance</TabsTrigger>
          <TabsTrigger value="riskmap">Risk Map</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="mt-4 space-y-6">
          {audit.status !== "completed" && audit.status !== "failed" && (
            <div className="flex items-center gap-2 rounded-lg bg-yellow-50 p-3 text-sm text-yellow-700">
              <Loader2 className="h-4 w-4 animate-spin" />
              Audit is currently {audit.status}... Results will appear automatically.
            </div>
          )}

          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <SeverityCard
              label="Critical"
              count={criticalCount}
              colorClass="bg-red-100"
              icon={<ShieldX className="h-5 w-5 text-red-600" />}
            />
            <SeverityCard
              label="High"
              count={highCount}
              colorClass="bg-orange-100"
              icon={<ShieldAlert className="h-5 w-5 text-orange-500" />}
            />
            <SeverityCard
              label="Medium"
              count={mediumCount}
              colorClass="bg-yellow-100"
              icon={<AlertTriangle className="h-5 w-5 text-yellow-500" />}
            />
            <SeverityCard
              label="Low"
              count={lowCount}
              colorClass="bg-blue-100"
              icon={<AlertCircle className="h-5 w-5 text-blue-500" />}
            />
          </div>

          {audit.summary && Object.keys(audit.summary).length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle>Summary</CardTitle>
              </CardHeader>
              <CardContent>
                <dl className="grid grid-cols-2 gap-4 sm:grid-cols-3">
                  {Object.entries(audit.summary).map(([key, value]) => (
                    <div key={key}>
                      <dt className="text-xs text-slate-500">{key}</dt>
                      <dd className="text-lg font-semibold text-slate-900">{value}</dd>
                    </div>
                  ))}
                </dl>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        <TabsContent value="rules" className="mt-4">
          {rules ? (
            <RuleTable rules={rules} />
          ) : (
            <div className="flex h-32 items-center justify-center">
              <Loader2 className="h-5 w-5 animate-spin text-slate-400" />
            </div>
          )}
        </TabsContent>

        <TabsContent value="findings" className="mt-4">
          <FindingsPanel findings={audit.findings} />
        </TabsContent>

        <TabsContent value="compliance" className="mt-4">
          {compliance ? (
            <ComplianceSummaryPanel summaries={compliance} />
          ) : (
            <div className="flex h-32 items-center justify-center">
              <Loader2 className="h-5 w-5 animate-spin text-slate-400" />
            </div>
          )}
        </TabsContent>

        <TabsContent value="riskmap" className="mt-4">
          {rules ? (
            <RiskHeatmap rules={rules} />
          ) : (
            <div className="flex h-32 items-center justify-center">
              <Loader2 className="h-5 w-5 animate-spin text-slate-400" />
            </div>
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
}
