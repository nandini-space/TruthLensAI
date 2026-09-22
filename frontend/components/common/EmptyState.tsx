"use client";

import Link from "next/link";
import type { ReactNode } from "react";

type StateAction =
  | {
      label: string;
      href: string;
      onAction?: never;
    }
  | {
      label: string;
      href?: never;
      onAction: () => void;
    };

interface EmptyStateProps {
  title: string;
  description?: ReactNode;
  actions?: readonly StateAction[];
}

function isLinkAction(action: StateAction): action is Extract<StateAction, { href: string }> {
  return "href" in action;
}

/** A truthful no-data or unavailable-data state with optional explicit actions. */
export function EmptyState({ title, description, actions = [] }: EmptyStateProps) {
  return (
    <section className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
      <h2 className="text-lg font-semibold text-slate-950">{title}</h2>
      {description ? <div className="mt-3 text-sm leading-6 text-slate-700">{description}</div> : null}
      {actions.length > 0 ? (
        <div className="mt-6 flex flex-wrap gap-3">
          {actions.map((action) =>
            isLinkAction(action) ? (
              <Link
                key={action.label}
                href={action.href}
                className="rounded-lg bg-cyan-600 px-4 py-2 text-sm font-semibold text-white hover:bg-cyan-700 focus:outline-none focus:ring-2 focus:ring-cyan-500 focus:ring-offset-2"
              >
                {action.label}
              </Link>
            ) : (
              <button
                key={action.label}
                type="button"
                onClick={action.onAction}
                className="rounded-lg bg-cyan-600 px-4 py-2 text-sm font-semibold text-white hover:bg-cyan-700 focus:outline-none focus:ring-2 focus:ring-cyan-500 focus:ring-offset-2"
              >
                {action.label}
              </button>
            ),
          )}
        </div>
      ) : null}
    </section>
  );
}
