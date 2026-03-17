"use client";

import { useState } from "react";
import { api, ApiError } from "@/lib/api-client";
import type { RuleGenResponse } from "@/lib/types";
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
import { Loader2, Copy, Check, AlertTriangle, CheckCircle2 } from "lucide-react";

const VENDORS = ["Azure NSG", "Azure Firewall", "Azure WAF"] as const;

export default function GeneratePage() {
  const [description, setDescription] = useState("");
  const [vendor, setVendor] = useState<string>(VENDORS[0]);
  const [severity, setSeverity] = useState<"critical" | "high" | "medium" | "low" | "info">("medium");
  const [category, setCategory] = useState("");
  const [isGenerating, setIsGenerating] = useState(false);
  const [result, setResult] = useState<RuleGenResponse | null>(null);
  const [error, setError] = useState("");
  const [copied, setCopied] = useState(false);

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
      if (err instanceof ApiError) {
        const body = err.body as { detail?: string } | undefined;
        setError(body?.detail || err.message);
      } else if (err instanceof Error) {
        setError(err.message);
      } else {
        setError("An unexpected error occurred");
      }
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
    <div className="mx-auto max-w-3xl space-y-6">
      <div>
        <h2 className="text-2xl font-bold tracking-tight text-slate-900">
          Rule Generator
        </h2>
        <p className="mt-1 text-sm text-slate-500">
          Generate firewall rules using natural language descriptions
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Describe Your Rule</CardTitle>
          <CardDescription>
            Enter a natural language description of the firewall rule you need
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <label className="mb-1 block text-sm font-medium text-slate-700">
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
              <label className="mb-1 block text-sm font-medium text-slate-700">
                Vendor
              </label>
              <select
                value={vendor}
                onChange={(e) => setVendor(e.target.value)}
                className="h-8 w-full rounded-lg border border-slate-200 bg-white px-2.5 text-sm text-slate-700 outline-none focus:border-slate-400 focus:ring-2 focus:ring-slate-200"
              >
                {VENDORS.map((v) => (
                  <option key={v} value={v}>
                    {v}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="mb-1 block text-sm font-medium text-slate-700">
                Severity
              </label>
              <select
                value={severity}
                onChange={(e) => setSeverity(e.target.value as typeof severity)}
                className="h-8 w-full rounded-lg border border-slate-200 bg-white px-2.5 text-sm text-slate-700 outline-none focus:border-slate-400 focus:ring-2 focus:ring-slate-200"
              >
                {(["critical", "high", "medium", "low", "info"] as const).map((s) => (
                  <option key={s} value={s}>
                    {s.charAt(0).toUpperCase() + s.slice(1)}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="mb-1 block text-sm font-medium text-slate-700">
                Category
              </label>
              <input
                type="text"
                placeholder="e.g., network-access"
                value={category}
                onChange={(e) => setCategory(e.target.value)}
                className="h-8 w-full rounded-lg border border-slate-200 bg-white px-2.5 text-sm text-slate-700 outline-none focus:border-slate-400 focus:ring-2 focus:ring-slate-200"
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
              "Generate Rule"
            )}
          </Button>
        </CardContent>
      </Card>

      {error && (
        <div className="flex items-start gap-3 rounded-lg border border-red-200 bg-red-50 p-4">
          <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-red-500" />
          <div>
            <p className="text-sm font-medium text-red-800">Generation failed</p>
            <p className="mt-1 text-sm text-red-600">{error}</p>
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
                  <Badge className="bg-blue-100 text-blue-800">
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
              <pre className="overflow-x-auto rounded-md bg-slate-900 p-4 text-sm text-green-400">
                {JSON.stringify(result.rule, null, 2)}
              </pre>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Explanation</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-sm text-slate-700">{result.explanation}</p>
            </CardContent>
          </Card>

          <div className="flex items-center gap-2">
            <CheckCircle2 className="h-5 w-5 text-green-600" />
            <span className="text-sm font-medium text-green-700">
              Rule generated successfully
            </span>
          </div>
        </div>
      )}
    </div>
  );
}
