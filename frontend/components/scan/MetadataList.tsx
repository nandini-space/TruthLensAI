import type { JsonValue } from "@/types/scan-result";

interface MetadataListProps {
  metadata: Record<string, JsonValue>;
}

function formatMetadataValue(value: JsonValue): string {
  return typeof value === "string" ? value : JSON.stringify(value);
}

export function MetadataList({ metadata }: MetadataListProps) {
  const entries = Object.entries(metadata);

  if (entries.length === 0) {
    return null;
  }

  return (
    <details className="mt-3 text-xs text-slate-600">
      <summary className="cursor-pointer font-medium text-slate-700">Metadata</summary>
      <dl className="mt-2 space-y-2 rounded-md bg-slate-50 p-3">
        {entries.map(([key, value]) => (
          <div key={key}>
            <dt className="font-medium text-slate-700">{key}</dt>
            <dd className="mt-1 break-all text-slate-600">{formatMetadataValue(value)}</dd>
          </div>
        ))}
      </dl>
    </details>
  );
}
