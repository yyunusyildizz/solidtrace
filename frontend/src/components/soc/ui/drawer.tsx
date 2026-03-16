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
        className={`fixed inset-0 z-40 bg-black/40 backdrop-blur-[2px] transition ${
          open ? "pointer-events-auto opacity-100" : "pointer-events-none opacity-0"
        }`}
        onClick={onClose}
      />

      <aside
        className={`fixed right-0 top-0 z-50 h-screen w-full max-w-2xl transform transition ${
          open ? "translate-x-0" : "translate-x-full"
        }`}
        style={{
          borderLeft: "1px solid var(--border)",
          background: "var(--panel-strong)",
          boxShadow: "0 20px 60px rgba(0, 0, 0, 0.22)",
        }}
      >
        <div
          className="flex h-16 items-center justify-between px-5"
          style={{ borderBottom: "1px solid var(--border)" }}
        >
          <div className="text-sm font-black">{title}</div>
          <button
            onClick={onClose}
            className="rounded-lg p-2 transition"
            style={{
              color: "var(--muted)",
            }}
          >
            <X size={16} />
          </button>
        </div>

        <div className="h-[calc(100vh-64px)] overflow-auto p-5">{children}</div>
      </aside>
    </>
  );
}