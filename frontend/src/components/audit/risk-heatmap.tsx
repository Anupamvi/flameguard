"use client";

import type { RuleOut } from "@/lib/types";
import { Treemap, ResponsiveContainer, Tooltip } from "recharts";

interface RiskHeatmapProps {
  rules: RuleOut[];
}

interface TreeNode {
  [key: string]: string | number;
  name: string;
  size: number;
  severity: string;
  fill: string;
}

function severityToScore(severity: string): number {
  switch (severity) {
    case "critical":
      return 10;
    case "high":
      return 7;
    case "medium":
      return 5;
    case "low":
      return 3;
    default:
      return 1;
  }
}

function scoreToColor(score: number): string {
  if (score >= 8) return "#dc2626";
  if (score >= 6) return "#ea580c";
  if (score >= 4) return "#eab308";
  if (score >= 2) return "#65a30d";
  return "#16a34a";
}

interface CustomContentProps {
  x?: number;
  y?: number;
  width?: number;
  height?: number;
  name?: string;
  fill?: string;
}

function CustomTreemapContent({ x = 0, y = 0, width = 0, height = 0, name = "", fill = "#ccc" }: CustomContentProps) {
  if (width < 4 || height < 4) return null;
  return (
    <g>
      <rect
        x={x}
        y={y}
        width={width}
        height={height}
        fill={fill}
        stroke="#fff"
        strokeWidth={2}
        rx={4}
      />
      {width > 40 && height > 20 && (
        <text
          x={x + width / 2}
          y={y + height / 2}
          textAnchor="middle"
          dominantBaseline="central"
          fill="#fff"
          fontSize={11}
          fontWeight={500}
        >
          {name.length > width / 8 ? name.slice(0, Math.floor(width / 8)) + "..." : name}
        </text>
      )}
    </g>
  );
}

interface TooltipPayloadItem {
  payload?: TreeNode;
}

function CustomTooltip({ active, payload }: { active?: boolean; payload?: TooltipPayloadItem[] }) {
  if (!active || !payload?.length) return null;
  const data = payload[0].payload;
  if (!data) return null;
  return (
    <div className="rounded-md bg-slate-900 px-3 py-2 text-xs text-white shadow-lg">
      <p className="font-medium">{data.name}</p>
      <p className="mt-1 text-slate-300">
        Severity: {data.severity} (score: {data.size})
      </p>
    </div>
  );
}

export function RiskHeatmap({ rules }: RiskHeatmapProps) {
  if (rules.length === 0) {
    return (
      <div className="flex h-48 items-center justify-center text-sm text-slate-500">
        Risk scores pending
      </div>
    );
  }

  const data: TreeNode[] = rules.map((rule) => {
    const score = severityToScore(rule.severity);
    return {
      name: rule.name,
      size: score,
      severity: rule.severity,
      fill: scoreToColor(score),
    };
  });

  return (
    <div className="h-[400px] w-full">
      <ResponsiveContainer width="100%" height="100%">
        <Treemap
          data={data}
          dataKey="size"
          aspectRatio={4 / 3}
          content={<CustomTreemapContent />}
        >
          <Tooltip content={<CustomTooltip />} />
        </Treemap>
      </ResponsiveContainer>
    </div>
  );
}
