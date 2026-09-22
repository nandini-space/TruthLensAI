import type { Metadata } from "next";
<<<<<<< HEAD
import "./globals.css";

export const metadata: Metadata = {
  title: "TruthLensAI | Investigation Center",
  description: "Review in-memory Module 2 investigation results.",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en"><body>{children}</body></html>;
=======
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
>>>>>>> 5d2a9f64c85a66b65b6ef4e73a2d6ae7b75a4ee0
}
