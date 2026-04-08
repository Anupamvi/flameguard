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
  Menu,
  MessageSquare,
  ShieldAlert,
  Upload,
  Wand2,
  X,
} from "lucide-react";
import { formatRelativeTime, parseTimestamp } from "@/lib/time";

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
      (parseTimestamp(right.created_at)?.getTime() ?? 0) - (parseTimestamp(left.created_at)?.getTime() ?? 0),
  );
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
  onSelect,
}: {
  audit: AuditResponse;
  active: boolean;
  onSelect: () => void;
}) {
  const urgentLabel = [
    audit.critical_count > 0 ? `${audit.critical_count} critical` : null,
    audit.high_count > 0 ? `${audit.high_count} high` : null,
    audit.medium_count > 0 ? `${audit.medium_count} medium` : null,
    audit.total_findings > 0 ? `${audit.total_findings} total findings` : null,
  ]
    .filter(Boolean)
    .join(", ");

  return (
    <Link
      href={`/audit/${audit.id}`}
      onClick={onSelect}
      aria-label={`${audit.filename}. ${audit.status}. ${formatRelativeTime(audit.created_at)}. ${urgentLabel}`}
      className={`group flex items-start justify-between rounded-xl border px-3 py-2.5 transition-all ${
        active
          ? "border-flame-500/25 bg-flame-500/[0.06]"
          : "border-white/[0.06] bg-white/[0.03] hover:border-white/[0.12] hover:bg-white/[0.05]"
      }`}
    >
      <div className="min-w-0 flex-1">
        <p title={audit.filename} aria-label={audit.filename} className="truncate text-sm font-medium text-gray-200">{audit.filename}</p>
        <div className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-gray-500">
          <span className={`h-1.5 w-1.5 rounded-full ${statusDotClass(audit.status)}`} />
          <span>{audit.status}</span>
          <span>&middot;</span>
          <span>{formatRelativeTime(audit.created_at)}</span>
        </div>
        <div className="mt-2 flex flex-wrap items-center gap-1 text-[11px] font-semibold">
          {audit.critical_count > 0 && (
            <span aria-label={`${audit.critical_count} critical findings`} className="rounded bg-sev-critical/10 px-1.5 py-0.5 text-sev-critical">
              {audit.critical_count}C
            </span>
          )}
          {audit.high_count > 0 && (
            <span aria-label={`${audit.high_count} high findings`} className="rounded bg-sev-high/10 px-1.5 py-0.5 text-sev-high">
              {audit.high_count}H
            </span>
          )}
          {audit.critical_count === 0 && audit.high_count === 0 && (
            <span aria-label={`${audit.total_findings} total findings`} className="rounded bg-white/[0.06] px-1.5 py-0.5 text-gray-300">
              {audit.total_findings}
            </span>
          )}
        </div>
      </div>
      <ChevronRight className="ml-3 mt-0.5 h-4 w-4 shrink-0 text-gray-600 transition-colors group-hover:text-gray-400" />
    </Link>
  );
}

export function Sidebar() {
  const pathname = usePathname();
  const { data: audits, isLoading } = useAudits();
  const [mobileOpen, setMobileOpen] = React.useState(false);

  React.useEffect(() => {
    setMobileOpen(false);
  }, [pathname]);

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
        onClick={() => setMobileOpen(false)}
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
    <>
      <button
        type="button"
        onClick={() => setMobileOpen((open) => !open)}
        aria-label={mobileOpen ? "Close navigation" : "Open navigation"}
        aria-controls="fg-sidebar"
        aria-expanded={mobileOpen}
        className="fixed left-3 top-3 z-40 inline-flex h-11 w-11 items-center justify-center rounded-xl border border-white/[0.08] bg-surface-800/90 text-gray-200 shadow-lg transition-colors hover:bg-surface-700 md:hidden"
      >
        {mobileOpen ? <X className="h-5 w-5" strokeWidth={1.5} /> : <Menu className="h-5 w-5" strokeWidth={1.5} />}
      </button>

      {mobileOpen && (
        <button
          type="button"
          aria-label="Close navigation overlay"
          onClick={() => setMobileOpen(false)}
          className="fixed inset-0 z-30 bg-black/60 md:hidden"
        />
      )}

      <aside
        id="fg-sidebar"
        className={`fixed inset-y-0 left-0 z-40 flex w-64 max-w-[82vw] flex-col overflow-hidden border-r border-white/[0.06] bg-surface-800 transition-transform duration-100 ease-out md:z-30 md:w-56 ${
          mobileOpen ? "translate-x-0" : "-translate-x-full md:translate-x-0"
        }`}
      >
      {/* Brand */}
        <div className="flex h-14 items-center justify-between gap-2.5 border-b border-white/[0.06] px-4">
          <div className="flex items-center gap-2.5">
            <span className="text-xl" role="img" aria-label="flame">
              🔥
            </span>
            <span className="text-lg font-bold tracking-tight text-white">
              FlameGuard
            </span>
          </div>
          <button
            type="button"
            onClick={() => setMobileOpen(false)}
            aria-label="Close navigation"
            className="inline-flex h-9 w-9 items-center justify-center rounded-lg text-gray-400 transition-colors hover:bg-white/[0.04] hover:text-gray-200 md:hidden"
          >
            <X className="h-4 w-4" strokeWidth={1.5} />
          </button>
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
                        {formatRelativeTime(activeInvestigation.created_at)}
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
                    onSelect={() => setMobileOpen(false)}
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
    </>
  );
}
