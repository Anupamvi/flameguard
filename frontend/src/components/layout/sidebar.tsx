"use client";

import React from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useAudits } from "@/hooks/use-audit";
import type { AuditResponse } from "@/lib/types";
import {
  ChevronRight,
  FileSearch,
  LayoutDashboard,
  Loader2,
  MessageSquare,
  ShieldAlert,
  Upload,
  Wand2,
} from "lucide-react";

const analyzeItems = [
  { href: "/", label: "Dashboard", icon: LayoutDashboard },
  { href: "/upload", label: "Upload", icon: Upload },
  { href: "/audit", label: "Audits", icon: FileSearch },
] as const;

const toolItems = [
  { href: "/generate", label: "Generate", icon: Wand2 },
  { href: "/chat", label: "Chat", icon: MessageSquare },
] as const;

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

  return formatter.format(Math.round(diffHours / 24), "day");
}

function statusDotClass(status: AuditResponse["status"]) {
  switch (status) {
    case "completed":
      return "bg-sev-pass";
    case "failed":
      return "bg-sev-critical";
    default:
      return "bg-sev-medium animate-pulse";
  }
}

function AuditShortcut({
  audit,
  active,
}: {
  audit: AuditResponse;
  active: boolean;
}) {
  return (
    <Link
      href={`/audit/${audit.id}`}
      className={`group flex items-center justify-between rounded-xl border px-3 py-2.5 transition-all ${
        active
          ? "border-flame-500/25 bg-flame-500/[0.06]"
          : "border-white/[0.06] bg-white/[0.03] hover:border-white/[0.12] hover:bg-white/[0.05]"
      }`}
    >
      <div className="min-w-0">
        <p className="truncate text-sm font-medium text-gray-200">{audit.filename}</p>
        <div className="mt-1 flex items-center gap-2 text-xs text-gray-500">
          <span className={`h-1.5 w-1.5 rounded-full ${statusDotClass(audit.status)}`} />
          <span>{audit.status}</span>
          <span>&middot;</span>
          <span>{relativeTime(audit.created_at)}</span>
        </div>
      </div>
      <div className="ml-3 flex items-center gap-2">
        <div className="flex items-center gap-1 text-[11px] font-semibold">
          {audit.critical_count > 0 && (
            <span className="rounded bg-sev-critical/10 px-1.5 py-0.5 text-sev-critical">
              {audit.critical_count}C
            </span>
          )}
          {audit.high_count > 0 && (
            <span className="rounded bg-sev-high/10 px-1.5 py-0.5 text-sev-high">
              {audit.high_count}H
            </span>
          )}
          {audit.critical_count === 0 && audit.high_count === 0 && (
            <span className="rounded bg-white/[0.06] px-1.5 py-0.5 text-gray-300">
              {audit.total_findings}
            </span>
          )}
        </div>
        <ChevronRight className="h-4 w-4 shrink-0 text-gray-600 transition-colors group-hover:text-gray-400" />
      </div>
    </Link>
  );
}

export function Sidebar() {
  const pathname = usePathname();
  const { data: audits, isLoading } = useAudits();

  const orderedAudits = React.useMemo(
    () => sortAuditsByCreatedAt(audits ?? []),
    [audits],
  );
  const currentAuditId = pathname.startsWith("/audit/") ? pathname.split("/")[2] : null;
  const urgentTotal = orderedAudits.reduce(
    (sum, audit) => sum + audit.critical_count + audit.high_count,
    0,
  );
  const criticalTotal = orderedAudits.reduce((sum, audit) => sum + audit.critical_count, 0);
  const highTotal = orderedAudits.reduce((sum, audit) => sum + audit.high_count, 0);
  const activeInvestigation = orderedAudits.find(
    (audit) => audit.status !== "completed" && audit.status !== "failed",
  );
  const watchlist = React.useMemo(() => {
    const base = orderedAudits
      .filter((audit) => audit.total_findings > 0 || audit.status !== "completed")
      .slice(0, 3);

    if (!currentAuditId) {
      return base;
    }

    const currentAudit = orderedAudits.find((audit) => audit.id === currentAuditId);
    if (!currentAudit || base.some((audit) => audit.id === currentAudit.id)) {
      return base;
    }

    return [currentAudit, ...base].slice(0, 3);
  }, [currentAuditId, orderedAudits]);

  function isActive(href: string) {
    if (href === "/") return pathname === "/";
    return pathname.startsWith(href);
  }

  function NavLink({ href, label, icon: Icon }: { href: string; label: string; icon: React.ElementType }) {
    const active = isActive(href);
    return (
      <Link
        href={href}
        className={`flex items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors ${
          active
            ? "border-l-[3px] border-flame-500 bg-flame-500/10 pl-[9px] font-medium text-flame-400"
            : "border-l-[3px] border-transparent pl-[9px] text-gray-400 hover:bg-white/[0.04] hover:text-gray-200"
        }`}
      >
        <Icon className="h-[18px] w-[18px] shrink-0" strokeWidth={1.5} />
        {label}
      </Link>
    );
  }

  return (
    <aside className="fixed inset-y-0 left-0 z-30 flex w-56 flex-col overflow-hidden border-r border-white/[0.06] bg-surface-800">
      {/* Brand */}
      <div className="flex h-14 items-center gap-2.5 border-b border-white/[0.06] px-4">
        <span className="text-xl" role="img" aria-label="flame">
          🔥
        </span>
        <span className="text-lg font-bold tracking-tight text-white">
          FlameGuard
        </span>
      </div>

      {/* Nav links */}
      <nav className="flex flex-1 flex-col gap-1 overflow-y-auto px-3 py-4">
        <p className="mb-1 px-3 text-xs font-medium uppercase tracking-wider text-gray-600">
          Analyze
        </p>
        {analyzeItems.map(({ href, label, icon }) => (
          <NavLink key={href} href={href} label={label} icon={icon} />
        ))}

        <p className="mb-1 mt-5 px-3 text-xs font-medium uppercase tracking-wider text-gray-600">
          Tools
        </p>
        {toolItems.map(({ href, label, icon }) => (
          <NavLink key={href} href={href} label={label} icon={icon} />
        ))}

        <div className="mt-6 border-t border-white/[0.06] pt-4">
          <p className="mb-2 px-3 text-xs font-medium uppercase tracking-wider text-gray-600">
            Live Queue
          </p>

          {isLoading ? (
            <div className="flex items-center gap-2 px-3 py-2 text-sm text-gray-500">
              <Loader2 className="h-4 w-4 animate-spin" />
              Loading audit context...
            </div>
          ) : orderedAudits.length > 0 ? (
            <>
              <div className="px-3">
                <div className="rounded-2xl border border-white/[0.08] bg-white/[0.03] p-3">
                  <div className="flex items-center justify-between gap-3">
                    <div>
                      <p className="text-xs font-semibold uppercase tracking-[0.16em] text-gray-500">
                        Urgent Findings
                      </p>
                      <p className="mt-2 text-2xl font-semibold text-white tabular-nums">{urgentTotal}</p>
                    </div>
                    <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-sev-critical/10">
                      <ShieldAlert className="h-4 w-4 text-sev-critical" strokeWidth={1.5} />
                    </div>
                  </div>
                  <p className="mt-2 text-xs leading-relaxed text-gray-500">
                    {criticalTotal} critical and {highTotal} high across {orderedAudits.length} audits.
                  </p>

                  {activeInvestigation && (
                    <div className="mt-3 rounded-xl border border-white/[0.06] bg-black/20 px-2.5 py-2">
                      <div className="flex items-center gap-2 text-[11px] font-semibold uppercase tracking-[0.16em] text-gray-500">
                        <span className={`h-2 w-2 rounded-full ${statusDotClass(activeInvestigation.status)}`} />
                        Active Scan
                      </div>
                      <p className="mt-1 truncate text-sm font-medium text-gray-200">
                        {activeInvestigation.filename}
                      </p>
                      <p className="mt-1 text-xs text-gray-500">
                        {relativeTime(activeInvestigation.created_at)}
                      </p>
                    </div>
                  )}
                </div>
              </div>

              <div className="mt-3 space-y-1 px-3">
                {watchlist.map((audit) => (
                  <AuditShortcut
                    key={audit.id}
                    audit={audit}
                    active={Boolean(currentAuditId) && audit.id === currentAuditId}
                  />
                ))}
              </div>
            </>
          ) : (
            <p className="px-3 py-2 text-sm leading-relaxed text-gray-500">
              Upload a config to populate live investigation context and recent risk shortcuts.
            </p>
          )}
        </div>
      </nav>

      {/* Footer */}
      <div className="border-t border-white/[0.06] px-4 py-3">
        <span className="text-[10px] text-gray-600">v0.1.0</span>
      </div>
    </aside>
  );
}
