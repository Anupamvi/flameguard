"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { getApiErrorMessage } from "@/lib/api-client";
import { useAudits, useDeleteAudits } from "@/hooks/use-audit";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { FileSearch, Loader2, ExternalLink, Trash2 } from "lucide-react";

function getErrorMessage(error: unknown) {
  return getApiErrorMessage(error, "Failed to delete audits.");
}

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

export default function AuditsPage() {
  const auditDeleteEnabled = process.env.NEXT_PUBLIC_ENABLE_AUDIT_DELETE === "true";
  const { data: audits, isLoading, isError } = useAudits();
  const deleteAudits = useDeleteAudits();
  const [selectedAuditIds, setSelectedAuditIds] = useState<string[]>([]);
  const [feedbackMessage, setFeedbackMessage] = useState<string | null>(null);
  const [deleteError, setDeleteError] = useState<string | null>(null);

  useEffect(() => {
    if (!audits) return;

    setSelectedAuditIds((current) => current.filter((auditId) => audits.some((audit) => audit.id === auditId)));
  }, [audits]);

  const allSelected = !!audits && audits.length > 0 && audits.every((audit) => selectedAuditIds.includes(audit.id));

  function toggleAuditSelection(auditId: string) {
    setSelectedAuditIds((current) =>
      current.includes(auditId)
        ? current.filter((selectedId) => selectedId !== auditId)
        : [...current, auditId]
    );
  }

  function toggleSelectAll(checked: boolean) {
    if (!audits) return;
    setSelectedAuditIds(checked ? audits.map((audit) => audit.id) : []);
  }

  async function handleDelete(auditIds: string[]) {
    if (auditIds.length === 0 || deleteAudits.isPending) {
      return;
    }

    const confirmed = window.confirm(
      auditIds.length === 1
        ? "Delete this audit and its related data? This cannot be undone."
        : `Delete ${auditIds.length} audits and their related data? This cannot be undone.`
    );
    if (!confirmed) {
      return;
    }

    setFeedbackMessage(null);
    setDeleteError(null);

    try {
      const result = await deleteAudits.mutateAsync(auditIds);
      setSelectedAuditIds((current) => current.filter((auditId) => !auditIds.includes(auditId)));
      setFeedbackMessage(
        result.deleted_audit_ids.length === 1
          ? "Deleted 1 audit."
          : `Deleted ${result.deleted_audit_ids.length} audits.`
      );
    } catch (error) {
      setDeleteError(getErrorMessage(error));
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
        <div>
          <h2 className="fg-page-title">
            Audit History
          </h2>
          <p className="fg-page-subtitle max-w-none">
            View past network security configuration and log audits
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {auditDeleteEnabled && selectedAuditIds.length > 0 && (
            <Button
              variant="destructive"
              onClick={() => handleDelete(selectedAuditIds)}
              disabled={deleteAudits.isPending}
            >
              {deleteAudits.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Trash2 className="h-4 w-4" />}
              Delete selected ({selectedAuditIds.length})
            </Button>
          )}
          <Link
            href="/upload"
            className="inline-flex items-center rounded-md bg-flame-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-flame-500"
          >
            Upload Config
          </Link>
        </div>
      </div>

      {feedbackMessage && (
        <div className="rounded-lg border border-sev-pass/25 bg-sev-pass/[0.08] p-4 text-sm text-sev-pass">
          {feedbackMessage}
        </div>
      )}

      {deleteError && (
        <div className="rounded-lg border border-sev-critical/25 bg-sev-critical/[0.08] p-4 text-sm text-red-400">
          {deleteError}
        </div>
      )}

      {isLoading && (
        <div className="flex h-48 items-center justify-center">
          <Loader2 className="h-6 w-6 animate-spin text-gray-500" />
        </div>
      )}

      {isError && (
        <div className="rounded-lg border border-sev-critical/25 bg-sev-critical/[0.08] p-4 text-sm text-red-400">
          Failed to load audits. Please try again.
        </div>
      )}

      {audits && audits.length === 0 && (
        <div className="flex h-48 flex-col items-center justify-center rounded-lg border border-white/[0.06] bg-surface-700 p-8 text-center">
          <FileSearch className="mb-3 h-8 w-8 text-gray-600" />
          <p className="text-sm text-gray-500">No audits yet. Upload a config to get started.</p>
        </div>
      )}

      {audits && audits.length > 0 && (
        <div className="rounded-lg border border-white/[0.06] bg-surface-700">
          <Table>
            <TableHeader>
              <TableRow>
                {auditDeleteEnabled && (
                  <TableHead>
                    <input
                      type="checkbox"
                      aria-label="Select all audits"
                      className="h-4 w-4 rounded border-white/[0.1]"
                      checked={allSelected}
                      onChange={(event) => toggleSelectAll(event.target.checked)}
                    />
                  </TableHead>
                )}
                <TableHead>Vendor</TableHead>
                <TableHead>Filename</TableHead>
                <TableHead>Findings</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Date</TableHead>
                <TableHead>Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {audits.map((audit) => (
                <TableRow key={audit.id} data-state={selectedAuditIds.includes(audit.id) ? "selected" : undefined}>
                  {auditDeleteEnabled && (
                    <TableCell>
                      <input
                        type="checkbox"
                        aria-label={`Select audit ${audit.filename}`}
                        className="h-4 w-4 rounded border-white/[0.1]"
                        checked={selectedAuditIds.includes(audit.id)}
                        onChange={() => toggleAuditSelection(audit.id)}
                      />
                    </TableCell>
                  )}
                  <TableCell className="font-medium">{audit.vendor}</TableCell>
                  <TableCell className="max-w-[200px] truncate text-gray-400">
                    {audit.filename}
                  </TableCell>
                  <TableCell>{audit.total_findings}</TableCell>
                  <TableCell>
                    <Badge className={statusColor(audit.status)}>
                      {audit.status}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-gray-500">
                    {new Date(audit.created_at).toLocaleDateString()}
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      <Link
                        href={`/audit/${audit.id}`}
                        className="inline-flex items-center gap-1 text-sm font-medium text-blue-600 hover:text-blue-800"
                      >
                        View <ExternalLink className="h-3 w-3" />
                      </Link>
                      {auditDeleteEnabled && (
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => handleDelete([audit.id])}
                          disabled={deleteAudits.isPending}
                        >
                          <Trash2 className="h-4 w-4" /> Delete
                        </Button>
                      )}
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
    </div>
  );
}
