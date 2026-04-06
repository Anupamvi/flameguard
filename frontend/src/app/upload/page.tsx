"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { api, ApiError } from "@/lib/api-client";
import { FileDropzone } from "@/components/upload/file-dropzone";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { AlertCircle, CheckCircle2, Upload, FileJson, Shield, BarChart3 } from "lucide-react";

type UploadState = "idle" | "uploading" | "success" | "error";

export default function UploadPage() {
  const router = useRouter();
  const [state, setState] = useState<UploadState>("idle");
  const [errorMessage, setErrorMessage] = useState("");

  async function handleFileSelected(file: File) {
    setState("uploading");
    setErrorMessage("");

    try {
      const response = await api.uploadFile(file);
      setState("success");
      router.push(`/audit/${response.audit_id}`);
    } catch (err) {
      setState("error");
      if (err instanceof ApiError) {
        const body = err.body as { detail?: string } | undefined;
        setErrorMessage(body?.detail || err.message);
      } else if (err instanceof Error) {
        setErrorMessage(err.message);
      } else {
        setErrorMessage("An unexpected error occurred");
      }
    }
  }

  return (
    <div className="mx-auto max-w-3xl space-y-6">
      <div>
        <h2 className="fg-page-title">
          Upload Configuration
        </h2>
        <p className="fg-page-subtitle">
          Upload an Azure Firewall, NSG, or WAF JSON export, including supported Azure Firewall log exports
        </p>
      </div>

      {/* What this tool does */}
      <div className="rounded-xl border border-white/[0.06] bg-gradient-to-br from-surface-700 to-surface-800 p-5">
        <div className="flex items-start gap-3 mb-3">
          <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-flame-500/10">
            <Upload className="h-5 w-5 text-flame-400" />
          </div>
          <div>
            <p className="fg-panel-title">Automated Security Audit</p>
            <p className="fg-panel-body">
              Upload your Azure resource JSON export and FlameGuard automatically parses the rules, runs AI-powered security analysis, maps findings against CIS &amp; NIST compliance frameworks, and generates a detailed risk report &mdash; all in seconds.
            </p>
          </div>
        </div>
        <div className="grid gap-2.5 sm:grid-cols-3">
          <div className="flex items-center gap-2 rounded-lg bg-white/[0.03] px-3 py-2">
            <FileJson className="h-4 w-4 text-flame-400 shrink-0" />
            <span className="text-sm text-gray-400"><strong className="text-gray-300">Export:</strong> az network nsg show &rarr; JSON</span>
          </div>
          <div className="flex items-center gap-2 rounded-lg bg-white/[0.03] px-3 py-2">
            <Shield className="h-4 w-4 text-flame-400 shrink-0" />
            <span className="text-sm text-gray-400"><strong className="text-gray-300">Analyze:</strong> AI scans every rule for risks</span>
          </div>
          <div className="flex items-center gap-2 rounded-lg bg-white/[0.03] px-3 py-2">
            <BarChart3 className="h-4 w-4 text-flame-400 shrink-0" />
            <span className="text-sm text-gray-400"><strong className="text-gray-300">Report:</strong> Severity, compliance &amp; remediation</span>
          </div>
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Firewall / NSG Config</CardTitle>
          <CardDescription>
            Upload a JSON firewall or NSG configuration file for analysis
          </CardDescription>
        </CardHeader>
        <CardContent>
          <FileDropzone
            onFileSelected={handleFileSelected}
            isUploading={state === "uploading"}
          />
        </CardContent>
      </Card>

      {state === "error" && (
        <div className="flex items-start gap-3 rounded-lg border border-sev-critical/25 bg-sev-critical/[0.08] p-4">
          <AlertCircle className="mt-0.5 h-5 w-5 shrink-0 text-sev-critical" />
          <div>
            <p className="text-sm font-medium text-sev-critical">Upload failed</p>
            <p className="mt-1 text-sm text-red-400">{errorMessage}</p>
          </div>
        </div>
      )}

      {state === "success" && (
        <div className="flex items-start gap-3 rounded-lg border border-green-200 bg-green-50 p-4">
          <CheckCircle2 className="mt-0.5 h-5 w-5 shrink-0 text-green-500" />
          <div>
            <p className="text-sm font-medium text-green-800">Upload successful</p>
            <p className="mt-1 text-sm text-green-600">Redirecting to audit...</p>
          </div>
        </div>
      )}
    </div>
  );
}
