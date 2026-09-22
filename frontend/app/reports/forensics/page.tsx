/** Forensic reports route placeholder. Its feature UI is deferred to a later task. */
import { EmptyState } from "@/components/common/EmptyState";

export default function ForensicReportsPage() {
  return (
    <EmptyState
      title="Forensic reports unavailable"
      description="Forensic reports will appear when their authoritative backend source is configured."
    />
  );
}
