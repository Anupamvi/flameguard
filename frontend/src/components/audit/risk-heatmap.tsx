"use client";

import { useState } from "react";
import type { FindingOut, RuleOut } from "@/lib/types";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from "recharts";

interface RiskHeatmapProps {
  rules: RuleOut[];
  findings: FindingOut[];
}

type RuleSeverity = "critical" | "high" | "medium" | "low" | "info" | "unflagged";

const severityRank: Record<RuleSeverity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
  unflagged: -1,
};

const severityColors: Record<RuleSeverity, string> = {
  critical: "#dc2626",
  high: "#ea580c",
  medium: "#eab308",
  low: "#3b82f6",
  info: "#64748b",
  unflagged: "#cbd5e1",
};

const severityScores: Record<RuleSeverity, number> = {
  critical: 10,
  high: 7,
  medium: 5,
  low: 3,
  info: 2,
  unflagged: 1,
};

function maxSeverity(findings: FindingOut[]): RuleSeverity {
  let highest: RuleSeverity = "unflagged";
  for (const finding of findings) {
    if (severityRank[finding.severity] > severityRank[highest]) {
      highest = finding.severity;
    }
  }
  return highest;
}

function formatList(values: string[]) {
  return values.length > 0 ? values.join(", ") : "Any";
}

interface BarItem {
  name: string;
  score: number;
  severity: RuleSeverity;
  color: string;
  action: string;
  direction: string;
  protocol: string;
  target: string;
  findingCount: number;
  findingTitles: string;
}

interface TooltipPayloadItem {
  payload?: BarItem;
}

function CustomTooltip({ active, payload }: { active?: boolean; payload?: TooltipPayloadItem[] }) {
  if (!active || !payload?.length) return null;
  const d = payload[0].payload;
  if (!d) return null;
  return (
    <div className="rounded-md border border-white/[0.06] bg-surface-700 px-3 py-2 text-sm shadow-lg">
      <p className="font-semibold text-gray-100">{d.name}</p>
      <p className="mt-1 text-gray-500">
        {d.action} {d.direction} {d.protocol}
      </p>
      <p className="text-gray-500">Target: {d.target}</p>
      <div className="mt-1.5 flex items-center gap-1.5">
        <span
          className="inline-block h-2.5 w-2.5 rounded-full"
          style={{ backgroundColor: d.color }}
        />
        <span className="font-medium capitalize" style={{ color: d.color }}>
          {d.severity}
        </span>
        <span className="text-gray-500">(score {d.score})</span>
      </div>
      {d.findingCount > 0 && (
        <p className="mt-1 text-gray-500">
          {d.findingCount} linked finding{d.findingCount !== 1 ? "s" : ""}
        </p>
      )}
      {d.findingTitles && (
        <p className="mt-0.5 max-w-[260px] text-gray-600">{d.findingTitles}</p>
      )}
    </div>
  );
}

const LEGEND_ITEMS: { severity: RuleSeverity; label: string }[] = [
  { severity: "critical", label: "Critical" },
  { severity: "high", label: "High" },
  { severity: "medium", label: "Medium" },
  { severity: "low", label: "Low" },
  { severity: "info", label: "Info" },
  { severity: "unflagged", label: "Unflagged" },
];

export function RiskHeatmap({ rules, findings }: RiskHeatmapProps) {
  const [showAll, setShowAll] = useState(false);

  if (rules.length === 0) {
    return (
      <div className="flex h-48 items-center justify-center text-sm text-gray-500">
        Risk scores pending
      </div>
    );
  }

  const findingsByRuleId = new Map<string, FindingOut[]>();
  for (const finding of findings) {
    for (const ruleId of finding.affected_rule_ids) {
      const existing = findingsByRuleId.get(ruleId) ?? [];
      existing.push(finding);
      findingsByRuleId.set(ruleId, existing);
    }
  }

  const allData: BarItem[] = rules
    .map((rule) => {
      const linked = findingsByRuleId.get(rule.id) ?? [];
      const severity = maxSeverity(linked);
      return {
        name: rule.name,
        score: severityScores[severity],
        severity,
        color: severityColors[severity],
        action: rule.action,
        direction: rule.direction,
        protocol: rule.protocol ?? "Any",
        target: `${formatList(rule.destination_addresses)}:${formatList(rule.destination_ports)}`,
        findingCount: linked.length,
        findingTitles: linked
          .slice(0, 2)
          .map((f) => f.title)
          .join(" | "),
      };
    })
    .sort((a, b) => b.score - a.score || a.name.localeCompare(b.name));

  const MAX_VISIBLE = 20;
  const data = showAll ? allData : allData.slice(0, MAX_VISIBLE);
  const barHeight = Math.max(28, Math.min(36, 500 / data.length));
  const chartHeight = Math.max(200, data.length * barHeight + 40);

  // Severity distribution summary
  const counts = new Map<RuleSeverity, number>();
  for (const d of allData) {
    counts.set(d.severity, (counts.get(d.severity) ?? 0) + 1);
  }

  return (
    <div className="space-y-3">
      {/* Title + Legend */}
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h3 className="text-base font-semibold text-gray-300">
          Rule Risk Distribution
        </h3>
        <div className="flex flex-wrap items-center gap-3">
          {LEGEND_ITEMS.filter((l) => counts.has(l.severity)).map(({ severity, label }) => (
            <div key={severity} className="flex items-center gap-1.5 text-sm text-gray-400">
              <span
                className="inline-block h-2.5 w-2.5 rounded-sm"
                style={{ backgroundColor: severityColors[severity] }}
              />
              {label}
              <span className="text-gray-600">({counts.get(severity)})</span>
            </div>
          ))}
        </div>
      </div>

      {/* Summary bar */}
      <div className="flex h-3 w-full overflow-hidden rounded-full">
        {LEGEND_ITEMS.filter((l) => counts.has(l.severity)).map(({ severity }) => (
          <div
            key={severity}
            style={{
              backgroundColor: severityColors[severity],
              width: `${((counts.get(severity) ?? 0) / allData.length) * 100}%`,
            }}
            title={`${severity}: ${counts.get(severity)}`}
          />
        ))}
      </div>

      {/* Chart */}
      <div style={{ height: chartHeight }} className="w-full">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data} layout="vertical" margin={{ top: 4, right: 24, bottom: 4, left: 8 }}>
            <XAxis
              type="number"
              domain={[0, 10]}
              ticks={[0, 2, 4, 6, 8, 10]}
              tick={{ fontSize: 12, fill: "#94a3b8" }}
              axisLine={{ stroke: "#e2e8f0" }}
              tickLine={false}
              label={{
                value: "Risk Score",
                position: "insideBottomRight",
                offset: -4,
                style: { fontSize: 12, fill: "#94a3b8" },
              }}
            />
            <YAxis
              type="category"
              dataKey="name"
              width={140}
              tick={{ fontSize: 12, fill: "#475569" }}
              axisLine={false}
              tickLine={false}
              tickFormatter={(v: string) => (v.length > 18 ? v.slice(0, 17) + "\u2026" : v)}
            />
            <Tooltip content={<CustomTooltip />} cursor={{ fill: "rgba(255,255,255,0.04)" }} />
            <Bar dataKey="score" radius={[0, 4, 4, 0]} barSize={barHeight - 8}>
              {data.map((entry, i) => (
                <Cell key={i} fill={entry.color} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>

      {/* Show more / less toggle */}
      {allData.length > MAX_VISIBLE && (
        <button
          type="button"
          onClick={() => setShowAll((v) => !v)}
          className="text-sm font-medium text-gray-500 hover:text-gray-300"
        >
          {showAll
            ? "Show top 20 only"
            : `Show all ${allData.length} rules`}
        </button>
      )}
    </div>
  );
}
