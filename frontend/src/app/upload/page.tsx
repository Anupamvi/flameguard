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
import { AlertCircle, CheckCircle2 } from "lucide-react";

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
    <div className="mx-auto max-w-2xl space-y-6">
      <div>
        <h2 className="text-2xl font-bold tracking-tight text-slate-900">
          Upload Configuration
        </h2>
        <p className="mt-1 text-sm text-slate-500">
          Upload a firewall configuration file to start an audit
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Firewall Config</CardTitle>
          <CardDescription>
            Upload a JSON firewall configuration file for analysis
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
        <div className="flex items-start gap-3 rounded-lg border border-red-200 bg-red-50 p-4">
          <AlertCircle className="mt-0.5 h-5 w-5 shrink-0 text-red-500" />
          <div>
            <p className="text-sm font-medium text-red-800">Upload failed</p>
            <p className="mt-1 text-sm text-red-600">{errorMessage}</p>
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
