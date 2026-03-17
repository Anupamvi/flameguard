"use client";

import Link from "next/link";
import { useAudits } from "@/hooks/use-audit";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { FileSearch, Loader2, ExternalLink } from "lucide-react";

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

export default function AuditsPage() {
  const { data: audits, isLoading, isError } = useAudits();

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold tracking-tight text-slate-900">
            Audit History
          </h2>
          <p className="mt-1 text-sm text-slate-500">
            View past firewall configuration audits
          </p>
        </div>
        <Link
          href="/upload"
          className="inline-flex items-center rounded-md bg-slate-900 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-slate-800"
        >
          Upload Config
        </Link>
      </div>

      {isLoading && (
        <div className="flex h-48 items-center justify-center">
          <Loader2 className="h-6 w-6 animate-spin text-slate-400" />
        </div>
      )}

      {isError && (
        <div className="rounded-lg border border-red-200 bg-red-50 p-4 text-sm text-red-600">
          Failed to load audits. Please try again.
        </div>
      )}

      {audits && audits.length === 0 && (
        <div className="flex h-48 flex-col items-center justify-center rounded-lg border border-slate-200 bg-white p-8 text-center">
          <FileSearch className="mb-3 h-8 w-8 text-slate-400" />
          <p className="text-sm text-slate-500">No audits yet. Upload a config to get started.</p>
        </div>
      )}

      {audits && audits.length > 0 && (
        <div className="rounded-lg border border-slate-200 bg-white">
          <Table>
            <TableHeader>
              <TableRow>
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
                <TableRow key={audit.id}>
                  <TableCell className="font-medium">{audit.vendor}</TableCell>
                  <TableCell className="max-w-[200px] truncate text-slate-600">
                    {audit.filename}
                  </TableCell>
                  <TableCell>{audit.findings.length}</TableCell>
                  <TableCell>
                    <Badge className={statusColor(audit.status)}>
                      {audit.status}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-slate-500">
                    {new Date(audit.created_at).toLocaleDateString()}
                  </TableCell>
                  <TableCell>
                    <Link
                      href={`/audit/${audit.id}`}
                      className="inline-flex items-center gap-1 text-sm font-medium text-blue-600 hover:text-blue-800"
                    >
                      View <ExternalLink className="h-3 w-3" />
                    </Link>
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
