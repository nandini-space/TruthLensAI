"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

import { navigationItems } from "./navigation";

interface SidebarProps {
  isOpen: boolean;
  onNavigate: () => void;
  onClose: () => void;
}

function isActivePath(pathname: string, href: string): boolean {
  return pathname === href || (href === "/dashboard" && pathname === "/");
}

export function Sidebar({ isOpen, onNavigate, onClose }: SidebarProps) {
  const pathname = usePathname();

  return (
    <aside
      id="primary-navigation"
      className={`fixed inset-y-0 left-0 z-40 flex w-72 -translate-x-full flex-col overflow-y-auto border-r border-slate-800 bg-slate-950 text-slate-100 transition-transform duration-200 md:static md:translate-x-0 ${
        isOpen ? "translate-x-0" : ""
      }`}
      aria-label="Primary navigation"
    >
      <div className="flex h-16 items-center justify-between border-b border-slate-800 px-6">
        <span className="text-lg font-semibold tracking-tight">TruthLensAI</span>
        <button
          type="button"
          onClick={onClose}
          className="rounded-md px-2 py-1 text-sm font-medium text-slate-200 hover:bg-slate-800 focus:outline-none focus:ring-2 focus:ring-cyan-300 focus:ring-inset md:hidden"
        >
          Close
        </button>
      </div>

      <nav className="flex-1 px-3 py-5">
        <ul className="space-y-1">
          {navigationItems.map((item) => {
            const isActive = isActivePath(pathname, item.href);

            return (
              <li key={item.href}>
                <Link
                  href={item.href}
                  onClick={onNavigate}
                  aria-current={isActive ? "page" : undefined}
                  className={`block rounded-md px-3 py-2 text-sm font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-inset focus:ring-cyan-300 ${
                    isActive
                      ? "bg-cyan-500/15 text-cyan-300"
                      : "text-slate-300 hover:bg-slate-900 hover:text-white"
                  }`}
                >
                  {item.label}
                </Link>
              </li>
            );
          })}
        </ul>
      </nav>
    </aside>
  );
}
