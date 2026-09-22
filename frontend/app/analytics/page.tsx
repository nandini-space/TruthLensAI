/** Analytics route placeholder. Its feature UI is deferred to a later task. */
import { EmptyState } from "@/components/common/EmptyState";

export default function AnalyticsPage() {
  return (
    <EmptyState
      title="Analytics unavailable"
      description="Analytics will appear when authoritative backend data sources are configured."
    />
  );
}
