"use client";

import Link from "next/link";
import { useEffect, useRef, useState } from "react";
import { useSearchParams } from "next/navigation";
import { api, getApiErrorMessage } from "@/lib/api-client";
import type { FindingOut, RuleGenResponse } from "@/lib/types";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Loader2, Copy, Check, AlertTriangle, CheckCircle2, Lightbulb, Wand2, Terminal, ClipboardCopy, ShieldCheck } from "lucide-react";

const VENDORS = ["Azure NSG", "Azure Firewall", "Azure WAF"] as const;

const EXAMPLE_PROMPTS = [
  {
    label: "Block SSH except VPN",
    description: "Block all inbound SSH (port 22) except from VPN subnet 10.5.0.0/16",
    vendor: "Azure NSG",
    severity: "high" as const,
    category: "network-access",
  },
  {
    label: "Web tier HTTPS only",
    description: "Allow HTTPS from the public internet to the web tier at 10.1.0.0/24, deny everything else inbound",
    vendor: "Azure NSG",
    severity: "medium" as const,
    category: "web-security",
  },
  {
    label: "Restrict outbound DNS",
    description: "Create an outbound rule allowing DNS queries (UDP 53) only to internal resolvers at 168.63.129.16, block all other DNS",
    vendor: "Azure NSG",
    severity: "medium" as const,
    category: "egress-control",
  },
  {
    label: "Database segmentation",
    description: "Allow SQL Server (port 1433) access to 10.3.0.0/24 only from the application subnet 10.1.0.0/24, deny from all other sources",
    vendor: "Azure Firewall",
    severity: "critical" as const,
    category: "data-protection",
  },
] as const;

const VENDOR_LABELS: Record<string, string> = {
  azure_nsg: "Azure NSG",
  azure_firewall: "Azure Firewall",
  azure_waf: "Azure WAF",
};

type FindingGenerationSource = {
  auditId: string;
  filename: string;
  vendor: string;
  finding: FindingOut;
};

function toVendorLabel(vendor: string) {
  return VENDOR_LABELS[vendor] ?? vendor;
}

function buildFindingDraftDescription(finding: FindingOut) {
  return [
    `Generate a safer rule to remediate this ${finding.severity} ${finding.category} finding.`,
    `Issue: ${finding.title}.`,
    finding.description,
    finding.recommendation ? `Recommended action: ${finding.recommendation}.` : "",
  ]
    .filter(Boolean)
    .join(" ");
}

function errorMessage(err: unknown) {
  return getApiErrorMessage(err);
}

export default function GeneratePage() {
  const searchParams = useSearchParams();
  const auditId = searchParams.get("auditId");
  const findingId = searchParams.get("findingId");
  const autoGenerateKeyRef = useRef<string | null>(null);
  const [description, setDescription] = useState("");
  const [vendor, setVendor] = useState<string>(VENDORS[0]);
  const [severity, setSeverity] = useState<"critical" | "high" | "medium" | "low" | "info">("medium");
  const [category, setCategory] = useState("");
  const [isGenerating, setIsGenerating] = useState(false);
  const [result, setResult] = useState<RuleGenResponse | null>(null);
  const [error, setError] = useState("");
  const [copied, setCopied] = useState(false);
  const [sourceFinding, setSourceFinding] = useState<FindingGenerationSource | null>(null);

  useEffect(() => {
    const requestKey = auditId && findingId ? `${auditId}:${findingId}` : null;
    if (!requestKey || autoGenerateKeyRef.current === requestKey) {
      return;
    }

    autoGenerateKeyRef.current = requestKey;
    let isCancelled = false;

    async function generateFromFinding() {
      setIsGenerating(true);
      setError("");
      setResult(null);

      try {
        const audit = await api.getAudit(auditId!);
        const finding = audit.findings.find((item) => item.id === findingId);
        if (!finding) {
          throw new Error("The selected audit finding could not be loaded.");
        }
        if (isCancelled) {
          return;
        }

        setSourceFinding({
          auditId: auditId!,
          filename: audit.filename,
          vendor: toVendorLabel(audit.vendor),
          finding,
        });
        setDescription(buildFindingDraftDescription(finding));
        setVendor(toVendorLabel(audit.vendor));
        setSeverity(finding.severity);
        setCategory(finding.category);

        const response = await api.generateRuleFromFinding(auditId!, findingId!);
        if (isCancelled) {
          return;
        }
        setResult(response);
      } catch (err) {
        if (isCancelled) {
          return;
        }
        setError(errorMessage(err));
      } finally {
        if (!isCancelled) {
          setIsGenerating(false);
        }
      }
    }

    void generateFromFinding();

    return () => {
      isCancelled = true;
    };
  }, [auditId, findingId]);

  async function handleGenerate() {
    if (!description.trim()) return;
    setIsGenerating(true);
    setError("");
    setResult(null);

    try {
      const response = await api.generateRule({
        description: description.trim(),
        vendor,
        severity,
        category: category.trim() || "general",
      });
      setResult(response);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setIsGenerating(false);
    }
  }

  async function handleCopy() {
    if (!result) return;
    await navigator.clipboard.writeText(JSON.stringify(result.rule, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  return (
    <div className="mx-auto max-w-4xl space-y-6">
      <div>
        <h2 className="fg-page-title">
          Rule Generator
        </h2>
        <p className="fg-page-subtitle">
          {sourceFinding
            ? "Generate a remediation rule directly from the selected audit finding"
            : "Generate vendor policy rules using natural language descriptions"}
        </p>
      </div>

      {(auditId && findingId) && (
        <div className="rounded-xl border border-white/[0.08] bg-surface-800/80 p-5">
          <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
            <div>
              <div className="flex flex-wrap items-center gap-2">
                <Badge className="bg-flame-500/10 text-flame-300">Audit finding</Badge>
                {sourceFinding && (
                  <Badge className="bg-white/[0.06] text-gray-300">{sourceFinding.vendor}</Badge>
                )}
                {sourceFinding && (
                  <Badge className="bg-white/[0.06] text-gray-300">{sourceFinding.finding.severity}</Badge>
                )}
              </div>
              <h3 className="mt-3 text-lg font-semibold text-gray-100">
                {sourceFinding?.finding.title || "Generating from the selected finding"}
              </h3>
              <p className="mt-2 text-sm leading-relaxed text-gray-300">
                {sourceFinding?.finding.description || "FlameGuard is loading the finding context and drafting a safer rule automatically."}
              </p>
              {sourceFinding?.finding.recommendation && (
                <p className="mt-3 text-sm text-gray-400">
                  Recommended action: {sourceFinding.finding.recommendation}
                </p>
              )}
              {isGenerating && !result && (
                <p className="mt-3 text-sm font-medium text-flame-300">
                  Generating a safer rule from this finding now.
                </p>
              )}
            </div>

            {sourceFinding && (
              <Link
                href={`/audit/${sourceFinding.auditId}?tab=findings&finding=${sourceFinding.finding.id}`}
                className="inline-flex items-center rounded-lg border border-white/[0.08] bg-white/[0.04] px-3 py-2 text-sm font-medium text-gray-200 transition-colors hover:bg-white/[0.08]"
              >
                Back to {sourceFinding.filename}
              </Link>
            )}
          </div>
        </div>
      )}

      {/* What this tool does */}
      <div className="rounded-xl border border-white/[0.06] bg-gradient-to-br from-surface-700 to-surface-800 p-5">
        <div className="flex items-start gap-3 mb-4">
          <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-flame-500/10">
            <Wand2 className="h-5 w-5 text-flame-400" />
          </div>
          <div>
            <p className="fg-panel-title">AI-Powered Rule Generation</p>
            <p className="fg-panel-body">
              Describe the security rule you need in plain English and FlameGuard generates the correctly-formatted JSON rule for your Azure NSG, Firewall, or WAF. No need to memorize ARM property names or priority numbering &mdash; just state your intent and get a production-ready rule.
            </p>
          </div>
        </div>

        <div className="mb-3">
          <p className="fg-section-label mb-2.5">How to apply the generated rule</p>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="flex items-start gap-2.5">
              <div className="flex h-6 w-6 shrink-0 items-center justify-center rounded-md bg-flame-500/10 text-xs font-bold text-flame-400">1</div>
              <div>
                <p className="text-sm font-semibold text-gray-300">Generate &amp; copy the JSON</p>
                <p className="text-sm text-gray-500">Describe the rule below, click Generate, then use the Copy button on the output.</p>
              </div>
            </div>
            <div className="flex items-start gap-2.5">
              <div className="flex h-6 w-6 shrink-0 items-center justify-center rounded-md bg-flame-500/10 text-xs font-bold text-flame-400">2</div>
              <div>
                <p className="text-sm font-semibold text-gray-300">Apply via Azure Portal or CLI</p>
                <p className="text-sm text-gray-500">
                  <strong>Portal:</strong> NSG &rarr; Inbound/Outbound rules &rarr; Add &rarr; paste values.<br />
                  <strong>CLI:</strong> <code className="rounded bg-white/[0.06] px-1 py-0.5 text-sm font-mono text-flame-300">az network nsg rule create</code> with the generated fields.
                </p>
              </div>
            </div>
            <div className="flex items-start gap-2.5">
              <div className="flex h-6 w-6 shrink-0 items-center justify-center rounded-md bg-flame-500/10 text-xs font-bold text-flame-400">3</div>
              <div>
                <p className="text-sm font-semibold text-gray-300">For Firewall Policy rules</p>
                <p className="text-sm text-gray-500">
                  Firewall Manager &rarr; Policy &rarr; Network / Application Rules &rarr; Add rule collection &rarr; paste the generated rule properties.
                </p>
              </div>
            </div>
            <div className="flex items-start gap-2.5">
              <div className="flex h-6 w-6 shrink-0 items-center justify-center rounded-md bg-flame-500/10 text-xs font-bold text-flame-400">4</div>
              <div>
                <p className="text-sm font-semibold text-gray-300">Verify with FlameGuard</p>
                <p className="text-sm text-gray-500">Re-export and upload your config to FlameGuard to confirm the new rule passes audit checks.</p>
              </div>
            </div>
          </div>
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Describe Your Rule</CardTitle>
          <CardDescription>
            {sourceFinding
              ? "Review the finding-backed generation brief below, then refine and regenerate if needed"
              : "Enter a natural language description of the security rule or policy you need"}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Example prompts */}
          <div>
            <div className="mb-2 flex items-center gap-1.5 text-sm font-medium text-gray-500">
              <Lightbulb className="h-3.5 w-3.5" />
              Try an example
            </div>
            <div className="flex flex-wrap gap-2">
              {EXAMPLE_PROMPTS.map((ex) => (
                <button
                  key={ex.label}
                  type="button"
                  onClick={() => {
                    setDescription(ex.description);
                    setVendor(ex.vendor);
                    setSeverity(ex.severity);
                    setCategory(ex.category);
                  }}
                  className="rounded-full border border-white/[0.1] bg-surface-700 px-3 py-1.5 text-sm font-medium text-gray-400 transition-colors hover:border-flame-500/30 hover:bg-surface-700/80"
                >
                  {ex.label}
                </button>
              ))}
            </div>
          </div>

          <div>
            <label className="mb-1 block text-sm font-medium text-gray-300">
              Description
            </label>
            <Textarea
              placeholder="e.g., Block all inbound traffic from the internet to port 22 except from our VPN subnet 10.0.1.0/24"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              className="min-h-[100px]"
            />
          </div>

          <div className="grid gap-4 sm:grid-cols-3">
            <div>
              <label className="mb-1 block text-sm font-medium text-gray-300">
                Vendor
              </label>
              <select
                value={vendor}
                onChange={(e) => setVendor(e.target.value)}
                className="h-10 w-full rounded-lg border border-white/[0.1] bg-surface-700 px-3 text-base text-gray-300 outline-none focus:border-flame-500/50 focus:ring-2 focus:ring-flame-500/20"
              >
                {VENDORS.map((v) => (
                  <option key={v} value={v}>
                    {v}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="mb-1 block text-sm font-medium text-gray-300">
                Severity
              </label>
              <select
                value={severity}
                onChange={(e) => setSeverity(e.target.value as typeof severity)}
                className="h-10 w-full rounded-lg border border-white/[0.1] bg-surface-700 px-3 text-base text-gray-300 outline-none focus:border-flame-500/50 focus:ring-2 focus:ring-flame-500/20"
              >
                {(["critical", "high", "medium", "low", "info"] as const).map((s) => (
                  <option key={s} value={s}>
                    {s.charAt(0).toUpperCase() + s.slice(1)}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="mb-1 block text-sm font-medium text-gray-300">
                Category
              </label>
              <input
                type="text"
                placeholder="e.g., network-access"
                value={category}
                onChange={(e) => setCategory(e.target.value)}
                className="h-10 w-full rounded-lg border border-white/[0.1] bg-surface-700 px-3 text-base text-gray-300 outline-none focus:border-flame-500/50 focus:ring-2 focus:ring-flame-500/20"
              />
            </div>
          </div>

          <Button
            onClick={handleGenerate}
            disabled={isGenerating || !description.trim()}
          >
            {isGenerating ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin" />
                Generating...
              </>
            ) : (
              sourceFinding ? "Regenerate Rule" : "Generate Rule"
            )}
          </Button>
        </CardContent>
      </Card>

      {error && (
        <div className="flex items-start gap-3 rounded-lg border border-sev-critical/25 bg-sev-critical/[0.08] p-4">
          <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-sev-critical" />
          <div>
            <p className="text-sm font-medium text-sev-critical">Generation failed</p>
            <p className="mt-1 text-sm text-red-400">{error}</p>
          </div>
        </div>
      )}

      {result && (
        <div className="space-y-4">
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <CardTitle>Generated Rule</CardTitle>
                <div className="flex items-center gap-2">
                  <Badge className={result.warnings.length > 0 ? "bg-sev-medium/10 text-sev-medium" : "bg-sev-pass/10 text-sev-pass"}>
                    Confidence: {Math.round(result.confidence * 100)}%
                  </Badge>
                  <Button variant="outline" size="sm" onClick={handleCopy}>
                    {copied ? (
                      <>
                        <Check className="h-3 w-3" /> Copied
                      </>
                    ) : (
                      <>
                        <Copy className="h-3 w-3" /> Copy
                      </>
                    )}
                  </Button>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              <pre className="overflow-x-auto rounded-md bg-surface-900 p-4 text-sm text-sev-pass">
                {JSON.stringify(result.rule, null, 2)}
              </pre>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Explanation</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-sm text-gray-300">{result.explanation}</p>
            </CardContent>
          </Card>

          {result.warnings.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle>Warnings</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {result.warnings.map((warning) => (
                    <div key={warning} className="flex items-start gap-2 rounded-lg border border-sev-medium/25 bg-sev-medium/[0.08] p-3">
                      <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-sev-medium" />
                      <p className="text-sm text-amber-100/85">{warning}</p>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          <div className="flex items-center gap-2">
            {result.warnings.length > 0 ? (
              <>
                <AlertTriangle className="h-5 w-5 text-sev-medium" />
                <span className="text-sm font-medium text-sev-medium">
                  Rule generated with cautions
                </span>
              </>
            ) : (
              <>
                <CheckCircle2 className="h-5 w-5 text-sev-pass" />
                <span className="text-sm font-medium text-sev-pass">
                  Rule generated successfully
                </span>
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
