/** Incident center route placeholder. Its feature UI is deferred to a later task. */
import { EmptyState } from "@/components/common/EmptyState";

export default function IncidentsPage() {
  return (
    <EmptyState
      title="Incident center unavailable"
      description="Incident data will appear when its authoritative backend source is configured."
    />
  );
}
