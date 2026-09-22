"use client";

import type { ScanModality } from "@/types/scan-result";

interface ScanTypeSelectorProps {
  value: ScanModality;
  onChange: (modality: ScanModality) => void;
}

const scanTypes: ReadonlyArray<{ value: ScanModality; label: string; description: string }> = [
  { value: "text", label: "Text", description: "Messages or written content" },
  { value: "url", label: "URL", description: "A URL or domain" },
  { value: "image", label: "Image", description: "Image or screenshot file" },
  { value: "audio", label: "Audio", description: "Audio or voice file" },
  { value: "video", label: "Video", description: "Video file" },
];

export function ScanTypeSelector({ value, onChange }: ScanTypeSelectorProps) {
  return (
    <fieldset>
      <legend className="text-sm font-medium text-slate-900">Scan type</legend>
      <div className="mt-3 grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
        {scanTypes.map((scanType) => {
          const isSelected = value === scanType.value;

          return (
            <button
              key={scanType.value}
              type="button"
              onClick={() => onChange(scanType.value)}
              aria-pressed={isSelected}
              className={`rounded-lg border p-4 text-left transition-colors focus:outline-none focus:ring-2 focus:ring-cyan-500 focus:ring-offset-2 ${
                isSelected
                  ? "border-cyan-500 bg-cyan-50"
                  : "border-slate-200 bg-white hover:border-slate-300"
              }`}
            >
              <span className="block text-sm font-semibold text-slate-950">{scanType.label}</span>
              <span className="mt-1 block text-xs text-slate-600">{scanType.description}</span>
            </button>
          );
        })}
      </div>
    </fieldset>
  );
}
