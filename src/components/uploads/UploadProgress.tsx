"use client";

import { CheckCircle, Loader2 } from "lucide-react";

export type UploadStage =
  | "uploading"
  | "processing"
  | "extracting"
  | "parsing"
  | "findings"
  | "timeline"
  | "completed"
  | "failed";

const STAGES: { key: UploadStage; label: string }[] = [
  { key: "uploading",   label: "Uploading" },
  { key: "extracting",  label: "Extracting" },
  { key: "parsing",     label: "Parsing Files" },
  { key: "findings",    label: "Generating Findings" },
  { key: "timeline",    label: "Creating Timeline" },
  { key: "completed",   label: "Completed" },
];

const STAGE_ORDER = STAGES.map((s) => s.key);

interface Props {
  stage: UploadStage;
  uploadPercent: number; // 0-100
  filename: string;
}

export function UploadProgress({ stage, uploadPercent, filename }: Props) {
  const currentIdx = STAGE_ORDER.indexOf(stage === "processing" ? "extracting" : stage);

  return (
    <div className="space-y-6">
      {/* Upload bar — only shown during upload phase */}
      {stage === "uploading" && (
        <div className="space-y-2">
          <div className="flex justify-between text-xs text-zinc-400">
            <span className="truncate max-w-xs">{filename}</span>
            <span>{uploadPercent}%</span>
          </div>
          <div className="h-2 w-full overflow-hidden rounded-full bg-zinc-800">
            <div
              className="h-full rounded-full bg-teal-500 transition-all duration-200"
              style={{ width: `${uploadPercent}%` }}
            />
          </div>
        </div>
      )}

      {/* Stage pipeline */}
      <div className="space-y-2">
        {STAGES.map(({ key, label }, idx) => {
          const isDone    = idx < currentIdx || stage === "completed";
          const isCurrent = idx === currentIdx && stage !== "completed";
          const isPending = idx > currentIdx && stage !== "completed";

          return (
            <div key={key} className={`flex items-center gap-3 rounded-lg px-4 py-2.5 ${
              isCurrent ? "bg-teal-950/30 border border-teal-800/50" :
              isDone    ? "opacity-60" : "opacity-30"
            }`}>
              {isDone ? (
                <CheckCircle className="h-4 w-4 shrink-0 text-teal-400" />
              ) : isCurrent ? (
                <Loader2 className="h-4 w-4 shrink-0 text-teal-400 animate-spin" />
              ) : (
                <span className="h-4 w-4 shrink-0 rounded-full border border-zinc-700" />
              )}
              <span className={`text-sm ${isCurrent ? "text-teal-300 font-medium" : isDone ? "text-zinc-400" : "text-zinc-600"}`}>
                {label}
              </span>
              {isCurrent && key === "uploading" && (
                <span className="ml-auto text-xs text-teal-500">{uploadPercent}%</span>
              )}
              {isCurrent && key !== "uploading" && (
                <span className="ml-auto text-xs text-zinc-600">In progress…</span>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
