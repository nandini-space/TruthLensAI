"use client";

import type { ChangeEvent } from "react";

import type { ScanModality } from "@/types/scan-result";

type FileModality = Exclude<ScanModality, "text" | "url">;

interface FileScanInputProps {
  modality: FileModality;
  file: File | null;
  error?: string;
  onChange: (file: File | null) => void;
}

const fileOptions: Record<FileModality, { accept: string; label: string; help: string }> = {
  image: {
    accept: "image/*",
    label: "Image or screenshot file",
    help: "Accepted: image files.",
  },
  audio: {
    accept: "audio/*",
    label: "Audio or voice file",
    help: "Accepted: audio files.",
  },
  video: {
    accept: "video/*",
    label: "Video file",
    help: "Accepted: video files.",
  },
};

export function FileScanInput({ modality, file, error, onChange }: FileScanInputProps) {
  const options = fileOptions[modality];

  function handleChange(event: ChangeEvent<HTMLInputElement>) {
    onChange(event.target.files?.[0] ?? null);
  }

  return (
    <div>
      <label htmlFor="scan-file" className="text-sm font-medium text-slate-900">
        {options.label}
      </label>
      <input
        key={modality}
        id="scan-file"
        type="file"
        accept={options.accept}
        onChange={handleChange}
        aria-describedby={error ? "scan-file-error" : "scan-file-help"}
        aria-invalid={Boolean(error)}
        className="mt-2 block w-full cursor-pointer rounded-lg border border-slate-300 bg-white text-sm text-slate-700 file:mr-4 file:border-0 file:border-r file:border-slate-200 file:bg-slate-50 file:px-4 file:py-2 file:text-sm file:font-medium file:text-slate-800 hover:file:bg-slate-100"
      />
      <p id="scan-file-help" className="mt-2 text-xs text-slate-500">
        {options.help}
      </p>
      {file ? <p className="mt-2 break-all text-sm text-slate-700">Selected: {file.name}</p> : null}
      {error ? (
        <p id="scan-file-error" className="mt-2 text-sm text-red-700" role="alert">
          {error}
        </p>
      ) : null}
    </div>
  );
}
