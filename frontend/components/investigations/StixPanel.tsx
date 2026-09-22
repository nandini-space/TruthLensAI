import type { JsonValue } from "../../lib/module2-types";

type StixObject = { type?: unknown; id?: unknown; name?: unknown; relationship_type?: unknown; source_ref?: unknown; target_ref?: unknown };
type StixBundle = { type?: unknown; id?: unknown; spec_version?: unknown; objects?: unknown };

const isObject = (value: JsonValue | undefined): value is Record<string, JsonValue> => Boolean(value && typeof value === "object" && !Array.isArray(value));
const objectName = (object: StixObject) => typeof object.name === "string" ? object.name : typeof object.relationship_type === "string" ? `${object.relationship_type} relationship` : undefined;

export function StixPanel({ bundle }: { bundle: JsonValue | undefined }) {
  if (!isObject(bundle)) return <section className="panel"><h2>STIX 2.1 bundle</h2><p className="empty">No STIX bundle is available for this investigation.</p></section>;
  const value = bundle as StixBundle;
  if (value.type !== "bundle" || typeof value.id !== "string" || !Array.isArray(value.objects)) return <section className="panel"><h2>STIX 2.1 bundle</h2><p className="empty">STIX bundle data is malformed and could not be displayed.</p></section>;
  const objects = value.objects.filter((item): item is StixObject => Boolean(item && typeof item === "object" && !Array.isArray(item)));
  const types = objects.reduce<Record<string, number>>((counts, item) => { if (typeof item.type === "string") counts[item.type] = (counts[item.type] ?? 0) + 1; return counts; }, {});
  return <section className="panel"><h2>STIX 2.1 bundle</h2><dl className="detail-list"><div><dt>Bundle ID</dt><dd className="mono">{value.id}</dd></div>{typeof value.spec_version === "string" && <div><dt>STIX version</dt><dd>{value.spec_version}</dd></div>}<div><dt>Objects</dt><dd>{objects.length}</dd></div><div><dt>Object types</dt><dd>{Object.entries(types).map(([type, count]) => `${type} (${count})`).join(", ") || "No typed objects returned."}</dd></div></dl>{objects.length ? <details className="report-details"><summary>View STIX object summaries</summary><ul className="stix-objects">{objects.map((item, index) => <li key={typeof item.id === "string" ? item.id : index}><strong>{typeof item.type === "string" ? item.type : "Unknown type"}</strong>{objectName(item) && ` · ${objectName(item)}`}{typeof item.id === "string" && <><br /><span className="mono">{item.id}</span></>}</li>)}</ul></details> : <p className="empty">The returned bundle contains no objects.</p>}<p className="stix-note">This persisted bundle is shown in the investigation response. A separate STIX download or retrieval endpoint is not currently available.</p></section>;
}
