"use client";

interface UrlScanInputProps {
  value: string;
  error?: string;
  onChange: (value: string) => void;
}

export function UrlScanInput({ value, error, onChange }: UrlScanInputProps) {
  return (
    <div>
      <label htmlFor="scan-url" className="text-sm font-medium text-slate-900">
        URL or domain
      </label>
      <input
        id="scan-url"
        type="text"
        inputMode="url"
        value={value}
        onChange={(event) => onChange(event.target.value)}
        aria-describedby={error ? "scan-url-error" : "scan-url-help"}
        aria-invalid={Boolean(error)}
        className="mt-2 w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm text-slate-950 outline-none focus:border-cyan-500 focus:ring-2 focus:ring-cyan-500/20"
        placeholder="https://example.com or example.com"
      />
      <p id="scan-url-help" className="mt-2 text-xs text-slate-500">
        Enter a complete HTTP(S) URL or a domain.
      </p>
      {error ? (
        <p id="scan-url-error" className="mt-2 text-sm text-red-700" role="alert">
          {error}
        </p>
      ) : null}
    </div>
  );
}
