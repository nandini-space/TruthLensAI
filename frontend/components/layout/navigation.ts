export interface NavigationItem {
  href: string;
  label: string;
}

export const navigationItems: readonly NavigationItem[] = [
  { href: "/dashboard", label: "Dashboard" },
  { href: "/scans/new", label: "New Scan" },
  { href: "/scans/history", label: "Scan History" },
  { href: "/investigations", label: "Investigation Center" },
  { href: "/community", label: "Community Intelligence" },
  { href: "/incidents", label: "Incident Center" },
  { href: "/analytics", label: "Analytics" },
  { href: "/reports/forensics", label: "Forensic Reports" },
];

export function getPageTitle(pathname: string): string {
  if (pathname === "/") {
    return "Investigation Center";
  }

  const currentItem = navigationItems.find((item) => item.href === pathname);

  if (currentItem) {
    return currentItem.label;
  }

  if (pathname.startsWith("/scans/")) return "Scan Result";
  if (pathname.startsWith("/investigations/")) return "Investigation Detail";
  return "TruthLensAI";
}
