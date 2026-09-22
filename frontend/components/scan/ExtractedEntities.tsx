import type { ExtractedEntity, ScanResult } from "@/types/scan-result";

interface ExtractedEntitiesProps {
  entities: ScanResult["entities"];
}

export function ExtractedEntities({ entities }: ExtractedEntitiesProps) {
  const values: ExtractedEntity[] = [
    ...entities.urls.map((value) => ({ kind: "url", value, context: null })),
    ...entities.domains.map((value) => ({ kind: "domain", value, context: null })),
    ...entities.email_addresses.map((value) => ({ kind: "email", value, context: null })),
    ...entities.phone_numbers.map((value) => ({ kind: "phone", value, context: null })),
    ...entities.usernames.map((value) => ({ kind: "username", value, context: null })),
    ...entities.indicators,
  ];
  return (
    <section aria-labelledby="extracted-entities-heading" className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
      <h3 id="extracted-entities-heading" className="text-base font-semibold text-slate-950">
        Extracted Entities
      </h3>
      {values.length === 0 ? (
        <p className="mt-3 text-sm text-slate-600">No extracted entities were returned.</p>
      ) : (
        <ul className="mt-4 divide-y divide-slate-200 rounded-lg border border-slate-200">
          {values.map((entity, index) => (
            <li key={`${entity.kind}-${entity.value}-${index}`} className="p-4">
              <p className="text-sm font-medium text-slate-950">{entity.kind}</p>
              <p className="mt-1 break-words text-sm text-slate-700">{entity.value}</p>
              {entity.context ? <p className="mt-1 break-words text-xs text-slate-500">Context: {entity.context}</p> : null}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
