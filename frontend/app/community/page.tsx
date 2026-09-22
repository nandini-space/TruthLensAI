/** Community intelligence route placeholder. Its feature UI is deferred to a later task. */
import { EmptyState } from "@/components/common/EmptyState";

export default function CommunityPage() {
  return (
    <EmptyState
      title="Community intelligence unavailable"
      description="Community intelligence data will appear when its authoritative backend source is configured."
    />
  );
}
