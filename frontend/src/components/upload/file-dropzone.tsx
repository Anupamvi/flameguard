"use client";

import { useCallback, useRef, useState } from "react";
import { Upload, Loader2 } from "lucide-react";

interface FileDropzoneProps {
  onFileSelected: (file: File) => void;
  isUploading: boolean;
}

export function FileDropzone({ onFileSelected, isUploading }: FileDropzoneProps) {
  const [isDragOver, setIsDragOver] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(true);
  }, []);

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(false);
  }, []);

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      e.stopPropagation();
      setIsDragOver(false);

      const file = e.dataTransfer.files[0];
      if (file) {
        onFileSelected(file);
      }
    },
    [onFileSelected]
  );

  const handleClick = useCallback(() => {
    inputRef.current?.click();
  }, []);

  const handleChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0];
      if (file) {
        onFileSelected(file);
      }
    },
    [onFileSelected]
  );

  return (
    <div
      onClick={handleClick}
      onDragOver={handleDragOver}
      onDragLeave={handleDragLeave}
      onDrop={handleDrop}
      className={`flex cursor-pointer flex-col items-center justify-center rounded-lg border-2 border-dashed p-12 transition-colors ${
        isUploading
          ? "border-white/[0.1] bg-surface-700"
          : isDragOver
            ? "border-flame-500 bg-flame-500/[0.05]"
            : "border-white/[0.1] bg-surface-700/50 hover:border-flame-500/30 hover:bg-surface-700"
      }`}
    >
      <input
        ref={inputRef}
        type="file"
        accept=".json"
        onChange={handleChange}
        className="hidden"
      />

      {isUploading ? (
        <>
          <Loader2 className="mb-4 h-12 w-12 animate-spin text-gray-500" />
          <p className="text-base font-semibold text-gray-300">Uploading...</p>
          <p className="mt-1 text-sm text-gray-500">Please wait while we process your file</p>
        </>
      ) : (
        <>
          <Upload className="mb-4 h-12 w-12 text-gray-500" />
          <p className="text-base font-semibold text-gray-300">
            Drop your Azure Firewall, NSG, WAF, or supported Azure Firewall log export here
          </p>
          <p className="mt-1 text-sm text-gray-500">Supports .json files</p>
        </>
      )}
    </div>
  );
}
