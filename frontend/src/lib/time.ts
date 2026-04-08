const HAS_TIMEZONE_SUFFIX_RE = /(Z|[+-]\d{2}:\d{2})$/i;

export function parseTimestamp(timestamp: string | null | undefined) {
  if (!timestamp) {
    return null;
  }

  const normalized = HAS_TIMEZONE_SUFFIX_RE.test(timestamp) ? timestamp : `${timestamp}Z`;
  const parsed = new Date(normalized);
  if (Number.isNaN(parsed.getTime())) {
    return null;
  }

  return parsed;
}

export function formatRelativeTime(timestamp: string | null | undefined) {
  if (!timestamp) return "just now";

  const now = Date.now();
  const parsed = parseTimestamp(timestamp);
  if (!parsed) return "just now";

  const value = parsed.getTime();
  const diffMinutes = Math.round((now - value) / 60000);
  const formatter = new Intl.RelativeTimeFormat("en", { numeric: "auto" });

  if (Math.abs(diffMinutes) < 60) {
    return formatter.format(-diffMinutes, "minute");
  }

  const diffHours = Math.round(diffMinutes / 60);
  if (Math.abs(diffHours) < 24) {
    return formatter.format(-diffHours, "hour");
  }

  const diffDays = Math.round(diffHours / 24);
  if (Math.abs(diffDays) < 30) {
    return formatter.format(-diffDays, "day");
  }

  const diffMonths = Math.round(diffDays / 30);
  if (Math.abs(diffMonths) < 12) {
    return formatter.format(-diffMonths, "month");
  }

  return formatter.format(-Math.round(diffMonths / 12), "year");
}