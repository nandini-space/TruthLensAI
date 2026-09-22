"use client";

interface NavbarProps {
  title: string;
  isNavigationOpen: boolean;
  onMenuButtonClick: () => void;
}

export function Navbar({ title, isNavigationOpen, onMenuButtonClick }: NavbarProps) {
  return (
    <header className="flex min-h-16 items-center gap-4 border-b border-slate-200 bg-white px-4 py-2 md:px-8">
      <button
        type="button"
        onClick={onMenuButtonClick}
        className="min-h-11 min-w-11 rounded-md p-2 text-slate-700 hover:bg-slate-100 focus:outline-none focus:ring-2 focus:ring-cyan-500 focus:ring-offset-2 md:hidden"
        aria-label="Open navigation"
        aria-controls="primary-navigation"
        aria-expanded={isNavigationOpen}
      >
        <span aria-hidden="true">☰</span>
      </button>
      <h1 className="min-w-0 break-words text-lg font-semibold text-slate-950">{title}</h1>
    </header>
  );
}
