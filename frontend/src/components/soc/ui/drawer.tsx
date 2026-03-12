"use client";

import type { ReactNode } from "react";
import { X } from "lucide-react";

export function Drawer({
  open,
  title,
  onClose,
  children,
}: {
  open: boolean;
  title: string;
  onClose: () => void;
  children: ReactNode;
}) {
  return (
    <>
      <div
        className={`fixed inset-0 z-40 bg-black/40 transition ${
          open ? "pointer-events-auto opacity-100" : "pointer-events-none opacity-0"
        }`}
        onClick={onClose}
      />
      <aside
        className={`fixed right-0 top-0 z-50 h-screen w-full max-w-2xl transform border-l border-zinc-200 bg-white shadow-2xl transition dark:border-white/10 dark:bg-[#0f141b] ${
          open ? "translate-x-0" : "translate-x-full"
        }`}
      >
        <div className="flex h-16 items-center justify-between border-b border-zinc-200 px-5 dark:border-white/10">
          <div className="text-sm font-black">{title}</div>
          <button
            onClick={onClose}
            className="rounded-lg p-2 text-zinc-500 transition hover:bg-zinc-100 hover:text-zinc-900 dark:text-zinc-400 dark:hover:bg-white/[0.06] dark:hover:text-white"
          >
            <X size={16} />
          </button>
        </div>
        <div className="h-[calc(100vh-64px)] overflow-auto p-5">{children}</div>
      </aside>
    </>
  );
}