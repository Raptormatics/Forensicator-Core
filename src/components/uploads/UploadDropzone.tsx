"use client";

import { useCallback, useState } from "react";
import { useDropzone } from "react-dropzone";
import { FileArchive, Upload, X } from "lucide-react";

const DEFAULT_MAX_SIZE = 100 * 1024 * 1024; // 100 MB
const DEFAULT_EXTENSIONS = [".zip"];
const DEFAULT_ACCEPT = { "application/zip": [".zip"], "application/x-zip-compressed": [".zip"] };

export interface ValidatedFile {
  file: File;
  error: string | null;
}

interface Props {
  onFile: (result: ValidatedFile) => void;
  /** File extensions accepted (lowercase, with leading dot). Defaults to [".zip"]. */
  extensions?: string[];
  /** Dropzone MIME-type/extension accept map. Defaults to ZIP mime types. */
  accept?: Record<string, string[]>;
  /** Maximum file size in bytes. Defaults to 100 MB. */
  maxSizeBytes?: number;
  /** Label describing the accepted file kind, e.g. "collection archive". Defaults to "collection archive". */
  fileKindLabel?: string;
}

export function UploadDropzone({
  onFile,
  extensions = DEFAULT_EXTENSIONS,
  accept = DEFAULT_ACCEPT,
  maxSizeBytes = DEFAULT_MAX_SIZE,
  fileKindLabel = "collection archive",
}: Props) {
  const [dragActive, setDragActive] = useState(false);

  const validate = useCallback((file: File): string | null => {
    const lower = file.name.toLowerCase();
    if (!extensions.some((ext) => lower.endsWith(ext))) {
      return `Unsupported file type. Only ${extensions.join(", ")} files are accepted.`;
    }
    if (file.size === 0) {
      return "File appears to be empty.";
    }
    if (file.size > maxSizeBytes) {
      return `File is too large (${(file.size / 1024 / 1024).toFixed(1)} MB). Maximum is ${(maxSizeBytes / 1024 / 1024).toFixed(0)} MB.`;
    }
    return null;
  }, [extensions, maxSizeBytes]);

  const onDrop = useCallback(
    (accepted: File[], rejected: import("react-dropzone").FileRejection[]) => {
      if (rejected.length > 0) {
        const f = rejected[0].file;
        onFile({ file: f, error: validate(f) ?? "File was rejected." });
        return;
      }
      if (accepted.length > 0) {
        const f = accepted[0];
        onFile({ file: f, error: validate(f) });
      }
    },
    [onFile, validate]
  );

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    onDragEnter: () => setDragActive(true),
    onDragLeave: () => setDragActive(false),
    accept,
    maxFiles: 1,
    multiple: false,
  });

  return (
    <div
      {...getRootProps()}
      className={`relative flex flex-col items-center justify-center rounded-xl border-2 border-dashed px-8 py-16 text-center cursor-pointer transition-colors
        ${isDragActive || dragActive
          ? "border-teal-500 bg-teal-950/20"
          : "border-zinc-700 bg-zinc-900/50 hover:border-zinc-500 hover:bg-zinc-900"
        }`}
    >
      <input {...getInputProps()} />
      <div className={`mb-4 rounded-full p-4 ${isDragActive ? "bg-teal-900/40" : "bg-zinc-800"}`}>
        <Upload className={`h-8 w-8 ${isDragActive ? "text-teal-400" : "text-zinc-500"}`} />
      </div>
      {isDragActive ? (
        <p className="text-base font-medium text-teal-300">Drop the archive here</p>
      ) : (
        <>
          <p className="text-base font-medium text-zinc-200">
            Drag &amp; drop your {fileKindLabel}
          </p>
          <p className="mt-1 text-sm text-zinc-500">or click to browse files</p>
        </>
      )}
      <p className="mt-4 text-xs text-zinc-600">
        Supported: {extensions.join(", ").toUpperCase()} · Maximum size: {(maxSizeBytes / 1024 / 1024).toFixed(0)} MB
      </p>
    </div>
  );
}

interface SelectedFileProps {
  file: File;
  error: string | null;
  onClear: () => void;
}

export function SelectedFileCard({ file, error, onClear }: SelectedFileProps) {
  const size =
    file.size >= 1024 * 1024
      ? `${(file.size / 1024 / 1024).toFixed(2)} MB`
      : `${(file.size / 1024).toFixed(1)} KB`;

  return (
    <div
      className={`flex items-center gap-4 rounded-xl border p-4 ${
        error ? "border-red-800 bg-red-950/20" : "border-zinc-700 bg-zinc-900"
      }`}
    >
      <div className={`rounded-lg p-2.5 ${error ? "bg-red-900/40" : "bg-zinc-800"}`}>
        <FileArchive className={`h-6 w-6 ${error ? "text-red-400" : "text-teal-400"}`} />
      </div>
      <div className="flex-1 min-w-0">
        <p className="truncate font-medium text-zinc-100 text-sm">{file.name}</p>
        <div className="flex items-center gap-3 mt-0.5">
          <span className="text-xs text-zinc-500">{size}</span>
          {error ? (
            <span className="text-xs text-red-400">{error}</span>
          ) : (
            <span className="flex items-center gap-1 text-xs text-green-400">
              <span className="h-1.5 w-1.5 rounded-full bg-green-500 inline-block" />
              Ready to upload
            </span>
          )}
        </div>
      </div>
      <button
        onClick={(e) => { e.stopPropagation(); onClear(); }}
        className="shrink-0 rounded-md p-1.5 text-zinc-600 hover:bg-zinc-800 hover:text-zinc-300"
      >
        <X className="h-4 w-4" />
      </button>
    </div>
  );
}
