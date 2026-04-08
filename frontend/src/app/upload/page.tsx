"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { api, getApiErrorMessage, type UploadStage } from "@/lib/api-client";
import { FileDropzone } from "@/components/upload/file-dropzone";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { AlertCircle, CheckCircle2, Upload, FileJson, Shield, BarChart3 } from "lucide-react";

type UploadState =
  | "idle"
  | "preparing"
  | UploadStage
  | "success"
  | "error";

export default function UploadPage() {
  const router = useRouter();
  const [state, setState] = useState<UploadState>("idle");
  const [errorMessage, setErrorMessage] = useState("");
  const isBusy =
    state === "preparing" ||
    state === "compressing" ||
    state === "uploading";

  async function handleFileSelected(file: File) {
    setState("preparing");
    setErrorMessage("");

    try {
      const response = await api.uploadFile(
        file,
        undefined,
        (uploadStage) => setState(uploadStage),
      );
      setState("success");
      router.push(`/audit/${response.audit_id}`);
    } catch (err) {
      setState("error");
      if (err instanceof TypeError) {
        setErrorMessage("Network error while uploading. Retry once. If it persists, the connection likely dropped before the server responded.");
        return;
      }
      setErrorMessage(getApiErrorMessage(err));
    }
  }

  return (
    <div className="mx-auto max-w-3xl space-y-6">
      <div>
        <h2 className="fg-page-title">
          Upload Configuration
        </h2>
        <p className="fg-page-subtitle">
          Upload a network security configuration export or supported WAF log export for analysis
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
              Upload your network security configuration export or supported WAF log bundle and FlameGuard automatically parses the controls, runs AI-powered security analysis, maps findings against CIS &amp; NIST compliance frameworks, and generates a detailed risk report.
            </p>
          </div>
        </div>
        <div className="grid gap-2.5 sm:grid-cols-3">
          <div className="flex items-center gap-2 rounded-lg bg-white/[0.03] px-3 py-2">
            <FileJson className="h-4 w-4 text-flame-400 shrink-0" />
            <span className="text-sm text-gray-400"><strong className="text-gray-300">Input:</strong> NSG, Firewall, WAF config, or supported WAF logs</span>
          </div>
          <div className="flex items-center gap-2 rounded-lg bg-white/[0.03] px-3 py-2">
            <Shield className="h-4 w-4 text-flame-400 shrink-0" />
            <span className="text-sm text-gray-400"><strong className="text-gray-300">Analyze:</strong> AI scans controls and events for risk</span>
          </div>
          <div className="flex items-center gap-2 rounded-lg bg-white/[0.03] px-3 py-2">
            <BarChart3 className="h-4 w-4 text-flame-400 shrink-0" />
            <span className="text-sm text-gray-400"><strong className="text-gray-300">Report:</strong> Severity, compliance &amp; remediation</span>
          </div>
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Configuration / Log Upload</CardTitle>
          <CardDescription>
            Upload a JSON security configuration file or a supported Azure WAF CSV log export for analysis
          </CardDescription>
        </CardHeader>
        <CardContent>
          <FileDropzone
            onFileSelected={handleFileSelected}
            uploadState={isBusy ? state : "idle"}
          />
          <div className="mt-4 flex flex-wrap gap-x-4 gap-y-2 text-sm text-gray-500">
            <span>Accepted: .json, AppGW WAF .csv, Front Door WAF .csv</span>
            <span>Maximum size: 50 MB</span>
            <span>Keyboard: use the Browse files button to open the picker</span>
          </div>
        </CardContent>
      </Card>

      {state === "compressing" && (
        <div className="flex items-start gap-3 rounded-lg border border-flame-500/25 bg-flame-500/[0.08] p-4">
          <Upload className="mt-0.5 h-5 w-5 shrink-0 text-flame-400" />
          <div>
            <p className="text-sm font-medium text-flame-300">Compressing large upload</p>
            <p className="mt-1 text-sm text-gray-400">
              Large WAF and log exports are compressed in your browser before transfer to keep uploads stable.
            </p>
          </div>
        </div>
      )}

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
