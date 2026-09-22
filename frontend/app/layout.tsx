import type { Metadata } from "next";
import type { ReactNode } from "react";

import { DashboardShell } from "@/components/layout/DashboardShell";

import "./globals.css";

export const metadata: Metadata = {
  title: "TruthLensAI",
  description: "TruthLensAI security analysis dashboard",
};

interface RootLayoutProps {
  children: ReactNode;
}

export default function RootLayout({ children }: RootLayoutProps) {
  return (
    <html lang="en">
      <body>
        <DashboardShell>{children}</DashboardShell>
      </body>
    </html>
  );
}
