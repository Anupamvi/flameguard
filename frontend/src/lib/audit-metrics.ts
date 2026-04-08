import type { AuditResponse, ComplianceSummary } from "@/lib/types";

export function percent(part: number, whole: number) {
  if (whole <= 0) return 0;
  return Math.round((part / whole) * 100);
}

export function calculatePostureScore(
  audit: Pick<AuditResponse, "critical_count" | "high_count" | "medium_count" | "low_count" | "rule_count">,
) {
  const severityPressure =
    audit.critical_count * 5 +
    audit.high_count * 3 +
    audit.medium_count * 2 +
    audit.low_count;
  const denominator = Math.max(1, audit.rule_count * 3);
  return Math.max(0, Math.min(100, 100 - Math.round((severityPressure / denominator) * 100)));
}

export function calculateComplianceStats(summaries: ComplianceSummary[] | null | undefined) {
  if (!summaries || summaries.length === 0) {
    return null;
  }

  const failed = summaries.reduce((sum, summary) => sum + summary.failed, 0);
  const applicable = summaries.reduce(
    (sum, summary) => sum + (summary.total_controls - summary.not_applicable),
    0,
  );

  return {
    failed,
    applicable,
    passingRate: applicable > 0 ? percent(applicable - failed, applicable) : 100,
  };
}

export function calculateFrameworkPassingRate(summary: ComplianceSummary) {
  const applicableControls = summary.total_controls - summary.not_applicable;
  return applicableControls > 0 ? percent(summary.passed, applicableControls) : 100;
}