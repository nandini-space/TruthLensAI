"use client";

interface TextScanInputProps {
  value: string;
  error?: string;
  onChange: (value: string) => void;
}

export function TextScanInput({ value, error, onChange }: TextScanInputProps) {
  return (
    <div>
      <label htmlFor="scan-text" className="text-sm font-medium text-slate-900">
        Text to analyze
      </label>
      <textarea
        id="scan-text"
        value={value}
        onChange={(event) => onChange(event.target.value)}
        maxLength={100_000}
        rows={9}
        aria-describedby={error ? "scan-text-error" : "scan-text-help"}
        aria-invalid={Boolean(error)}
        className="mt-2 w-full resize-y rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm text-slate-950 outline-none focus:border-cyan-500 focus:ring-2 focus:ring-cyan-500/20"
        placeholder="Paste text or a message for analysis"
      />
      <p id="scan-text-help" className="mt-2 text-xs text-slate-500">
        Up to 100,000 characters.
      </p>
      {error ? (
        <p id="scan-text-error" className="mt-2 text-sm text-red-700" role="alert">
          {error}
        </p>
      ) : null}
    </div>
  );
}
