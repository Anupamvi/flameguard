"use client";

import { useCallback, useRef, useState } from "react";
import { Upload, Loader2 } from "lucide-react";

interface FileDropzoneProps {
  onFileSelected: (file: File) => void;
  uploadState: "idle" | "preparing" | "compressing" | "uploading";
}

const HELP_TEXT_ID = "fg-upload-help";

export function FileDropzone({ onFileSelected, uploadState }: FileDropzoneProps) {
  const [isDragOver, setIsDragOver] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const isBusy = uploadState !== "idle";

  let statusTitle = "Uploading...";
  let statusHint = "Please wait while we process your file";

  if (uploadState === "preparing") {
    statusTitle = "Preparing upload...";
    statusHint = "Checking the file and getting it ready for transfer";
  } else if (uploadState === "compressing") {
    statusTitle = "Compressing large upload...";
    statusHint = "Reducing transfer size in your browser before sending it";
  }

  const handleDragOver = useCallback((e: React.DragEvent) => {
    if (isBusy) {
      return;
    }
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(true);
  }, [isBusy]);

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(false);
  }, []);

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      if (isBusy) {
        return;
      }
      e.preventDefault();
      e.stopPropagation();
      setIsDragOver(false);

      const file = e.dataTransfer.files[0];
      if (file) {
        onFileSelected(file);
      }
    },
    [isBusy, onFileSelected]
  );

  const handleClick = useCallback(() => {
    if (isBusy) {
      return;
    }
    inputRef.current?.click();
  }, [isBusy]);

  const handleKeyDown = useCallback((e: React.KeyboardEvent<HTMLDivElement>) => {
    if (isBusy) {
      return;
    }
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      inputRef.current?.click();
    }
  }, [isBusy]);

  const handleChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      if (isBusy) {
        return;
      }
      const file = e.target.files?.[0];
      if (file) {
        onFileSelected(file);
      }
    },
    [isBusy, onFileSelected]
  );

  return (
    <div
      onClick={handleClick}
      onKeyDown={handleKeyDown}
      onDragOver={handleDragOver}
      onDragLeave={handleDragLeave}
      onDrop={handleDrop}
      role="button"
      tabIndex={isBusy ? -1 : 0}
      aria-describedby={HELP_TEXT_ID}
      className={`flex flex-col items-center justify-center rounded-lg border-2 border-dashed p-12 transition-colors ${
        isBusy ? "cursor-default" : "cursor-pointer"
      } ${
        isBusy
          ? "border-white/[0.1] bg-surface-700"
          : isDragOver
            ? "border-flame-500 bg-flame-500/[0.05]"
            : "border-white/[0.1] bg-surface-700/50 hover:border-flame-500/30 hover:bg-surface-700"
      }`}
    >
      <input
        ref={inputRef}
        type="file"
        accept=".json,.csv"
        disabled={isBusy}
        onChange={handleChange}
        aria-describedby={HELP_TEXT_ID}
        className="sr-only"
      />

      {isBusy ? (
        <>
          <Loader2 className="mb-4 h-12 w-12 animate-spin text-gray-500" />
          <p className="text-base font-semibold text-gray-300">{statusTitle}</p>
          <p className="mt-1 text-sm text-gray-500">{statusHint}</p>
        </>
      ) : (
        <>
          <Upload className="mb-4 h-12 w-12 text-gray-500" />
          <p className="text-base font-semibold text-gray-300">
            Drop your network security configuration or supported Azure WAF log export here
          </p>
          <p id={HELP_TEXT_ID} className="mt-1 text-sm text-gray-500">Supports .json files and supported AppGW / Front Door WAF .csv exports. Maximum 50 MB per upload.</p>
          <button
            type="button"
            onClick={(event) => {
              event.stopPropagation();
              handleClick();
            }}
            disabled={isBusy}
            className="mt-4 inline-flex items-center gap-2 rounded-lg bg-white px-4 py-2 text-sm font-semibold text-slate-900 transition-colors hover:bg-slate-100 disabled:cursor-not-allowed disabled:opacity-50"
          >
            Browse files
          </button>
        </>
      )}
    </div>
  );
}
