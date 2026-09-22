import { ScanResultUnavailable } from "@/components/scan/ScanResultUnavailable";

interface ScanResultPageProps {
  params: Promise<{ scanId: string }>;
}

export default async function ScanResultPage({ params }: ScanResultPageProps) {
  const { scanId } = await params;

  return <ScanResultUnavailable scanId={scanId} />;
}
