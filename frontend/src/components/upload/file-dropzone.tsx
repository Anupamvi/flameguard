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
          ? "border-slate-300 bg-slate-50"
          : isDragOver
            ? "border-blue-500 bg-blue-50"
            : "border-slate-300 bg-white hover:border-slate-400 hover:bg-slate-50"
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
          <Loader2 className="mb-4 h-10 w-10 animate-spin text-slate-400" />
          <p className="text-sm font-medium text-slate-600">Uploading...</p>
          <p className="mt-1 text-xs text-slate-400">Please wait while we process your file</p>
        </>
      ) : (
        <>
          <Upload className="mb-4 h-10 w-10 text-slate-400" />
          <p className="text-sm font-medium text-slate-600">
            Drop your firewall config here, or click to browse
          </p>
          <p className="mt-1 text-xs text-slate-400">Supports .json files</p>
        </>
      )}
    </div>
  );
}
