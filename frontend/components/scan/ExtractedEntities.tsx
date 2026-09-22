import type { ExtractedEntity } from "@/types/scan-result";

import { MetadataList } from "./MetadataList";

interface ExtractedEntitiesProps {
  entities: ExtractedEntity[];
}

export function ExtractedEntities({ entities }: ExtractedEntitiesProps) {
  return (
    <section aria-labelledby="extracted-entities-heading" className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
      <h3 id="extracted-entities-heading" className="text-base font-semibold text-slate-950">
        Extracted Entities
      </h3>
      {entities.length === 0 ? (
        <p className="mt-3 text-sm text-slate-600">No extracted entities were returned.</p>
      ) : (
        <ul className="mt-4 divide-y divide-slate-200 rounded-lg border border-slate-200">
          {entities.map((entity, index) => (
            <li key={`${entity.entity_type}-${entity.value}-${index}`} className="p-4">
              <p className="text-sm font-medium text-slate-950">{entity.entity_type}</p>
              <p className="mt-1 break-words text-sm text-slate-700">{entity.value}</p>
              {entity.normalized_value ? (
                <p className="mt-1 break-words text-xs text-slate-500">
                  Normalized: {entity.normalized_value}
                </p>
              ) : null}
              {entity.confidence !== null ? (
                <p className="mt-1 text-xs text-slate-500">Confidence: {entity.confidence}</p>
              ) : null}
              <MetadataList metadata={entity.metadata} />
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
