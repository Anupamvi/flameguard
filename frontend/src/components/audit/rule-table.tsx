"use client";

import { useState } from "react";
import type { RuleOut } from "@/lib/types";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { RuleExplainDialog } from "./rule-explain-dialog";

interface RuleTableProps {
  rules: RuleOut[];
}

function severityColor(severity: string) {
  switch (severity) {
    case "critical":
      return "bg-red-100 text-red-800";
    case "high":
      return "bg-orange-100 text-orange-800";
    case "medium":
      return "bg-yellow-100 text-yellow-800";
    case "low":
      return "bg-blue-100 text-blue-800";
    default:
      return "bg-gray-100 text-gray-800";
  }
}

export function RuleTable({ rules }: RuleTableProps) {
  const [selectedRule, setSelectedRule] = useState<RuleOut | null>(null);
  const [dialogOpen, setDialogOpen] = useState(false);

  function handleRowClick(rule: RuleOut) {
    setSelectedRule(rule);
    setDialogOpen(true);
  }

  if (rules.length === 0) {
    return (
      <div className="flex h-32 items-center justify-center text-sm text-slate-500">
        No rules found for this audit.
      </div>
    );
  }

  return (
    <>
      <div className="rounded-lg border border-slate-200 bg-white">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Name</TableHead>
              <TableHead>Severity</TableHead>
              <TableHead>Category</TableHead>
              <TableHead>Enabled</TableHead>
              <TableHead>Description</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {rules.map((rule) => (
              <TableRow
                key={rule.id}
                className="cursor-pointer"
                onClick={() => handleRowClick(rule)}
              >
                <TableCell className="font-medium">{rule.name}</TableCell>
                <TableCell>
                  <Badge className={severityColor(rule.severity)}>
                    {rule.severity}
                  </Badge>
                </TableCell>
                <TableCell>
                  <Badge variant="outline">{rule.category}</Badge>
                </TableCell>
                <TableCell>
                  <span
                    className={`inline-block h-2 w-2 rounded-full ${
                      rule.enabled ? "bg-green-500" : "bg-slate-300"
                    }`}
                  />
                </TableCell>
                <TableCell className="max-w-[300px] truncate text-slate-600">
                  {rule.description}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>

      <RuleExplainDialog
        rule={selectedRule}
        open={dialogOpen}
        onOpenChange={setDialogOpen}
      />
    </>
  );
}
