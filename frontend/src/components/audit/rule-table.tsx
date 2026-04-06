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

function actionColor(action: string) {
  switch (action) {
    case "allow":
      return "bg-sev-pass/10 text-sev-pass";
    case "deny":
      return "bg-sev-critical/10 text-sev-critical";
    default:
      return "bg-gray-500/10 text-gray-400";
  }
}

function formatList(values: string[]) {
  return values.length > 0 ? values.join(", ") : "Any";
}

function formatEndpoint(addresses: string[], ports: string[]) {
  return `${formatList(addresses)}:${formatList(ports)}`;
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
      <div className="flex h-32 items-center justify-center text-sm text-gray-500">
        No rules found for this audit.
      </div>
    );
  }

  return (
    <>
      <div className="rounded-lg border border-white/[0.06] bg-surface-700">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Name</TableHead>
              <TableHead>Action</TableHead>
              <TableHead>Direction</TableHead>
              <TableHead>Protocol</TableHead>
              <TableHead>Source</TableHead>
              <TableHead>Destination</TableHead>
              <TableHead>Priority</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {rules.map((rule) => (
              <TableRow
                key={rule.id}
                className="cursor-pointer"
                onClick={() => handleRowClick(rule)}
              >
                <TableCell>
                  <div className="text-base font-medium text-gray-100">{rule.name}</div>
                  {rule.description && (
                    <div className="mt-1 max-w-[260px] truncate text-sm text-gray-500">
                      {rule.description}
                    </div>
                  )}
                </TableCell>
                <TableCell>
                  <Badge className={actionColor(rule.action)}>{rule.action}</Badge>
                </TableCell>
                <TableCell>
                  <Badge variant="outline">{rule.direction}</Badge>
                </TableCell>
                <TableCell className="text-gray-400">{rule.protocol ?? "Any"}</TableCell>
                <TableCell>
                  <div
                    className="max-w-[220px] truncate text-gray-400"
                    title={formatEndpoint(rule.source_addresses, rule.source_ports)}
                  >
                    {formatEndpoint(rule.source_addresses, rule.source_ports)}
                  </div>
                </TableCell>
                <TableCell>
                  <div
                    className="max-w-[220px] truncate text-gray-400"
                    title={formatEndpoint(rule.destination_addresses, rule.destination_ports)}
                  >
                    {formatEndpoint(rule.destination_addresses, rule.destination_ports)}
                  </div>
                </TableCell>
                <TableCell className="text-gray-400">
                  {rule.priority ?? "default"}
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
