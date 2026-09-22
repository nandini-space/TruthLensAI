export interface NavigationItem {
  href: string;
  label: string;
}

export const navigationItems: readonly NavigationItem[] = [
  { href: "/dashboard", label: "Dashboard" },
  { href: "/scans/new", label: "New Scan" },
  { href: "/scans/history", label: "Scan History" },
  { href: "/community", label: "Community Intelligence" },
  { href: "/incidents", label: "Incident Center" },
  { href: "/analytics", label: "Analytics" },
  { href: "/reports/forensics", label: "Forensic Reports" },
];

export function getPageTitle(pathname: string): string {
  if (pathname === "/") {
    return "Dashboard";
  }

  const currentItem = navigationItems.find((item) => item.href === pathname);

  if (currentItem) {
    return currentItem.label;
  }

  return pathname.startsWith("/scans/") ? "Scan Result" : "TruthLensAI";
}
