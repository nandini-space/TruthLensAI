"use client";

import { useState, type ReactNode } from "react";
import { usePathname } from "next/navigation";

import { Navbar } from "./Navbar";
import { getPageTitle } from "./navigation";
import { Sidebar } from "./Sidebar";

interface DashboardShellProps {
  children: ReactNode;
}

export function DashboardShell({ children }: DashboardShellProps) {
  const pathname = usePathname();
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);

  const closeSidebar = () => setIsSidebarOpen(false);

  return (
    <div className="min-h-screen bg-slate-50 md:flex">
      {isSidebarOpen ? (
        <button
          type="button"
          className="fixed inset-0 z-30 bg-slate-950/40 md:hidden"
          onClick={closeSidebar}
          aria-label="Close navigation"
        />
      ) : null}
      <Sidebar isOpen={isSidebarOpen} onNavigate={closeSidebar} onClose={closeSidebar} />
      <div className="min-w-0 flex-1">
        <Navbar
          title={getPageTitle(pathname)}
          isNavigationOpen={isSidebarOpen}
          onMenuButtonClick={() => setIsSidebarOpen(true)}
        />
        <main className="min-h-[calc(100vh-4rem)] p-4 md:p-8">{children}</main>
      </div>
    </div>
  );
}
