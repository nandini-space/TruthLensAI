import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "TruthLensAI | Investigation Center",
  description: "Review in-memory Module 2 investigation results.",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en"><body>{children}</body></html>;
}
