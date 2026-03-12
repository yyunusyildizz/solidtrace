"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import type { ReactNode } from "react";
import {
  Activity,
  AlertTriangle,
  BookOpen,
  LayoutDashboard,
  Moon,
  Package,
  Shield,
  Sun,
  Workflow,
} from "lucide-react";
import { useThemeMode } from "@/components/soc/providers/theme-provider";

const navItems = [
  { href: "/dashboard", label: "Overview", icon: LayoutDashboard },
  { href: "/alerts", label: "Alerts", icon: AlertTriangle },
  { href: "/assets", label: "Assets", icon: Package },
  { href: "/detections", label: "Detections", icon: BookOpen },
  { href: "/activity", label: "Activity", icon: Activity },
  { href: "/investigations", label: "Investigations", icon: Workflow },
];

export function AppShell({ children }: { children: ReactNode }) {
  const pathname = usePathname();
  const { theme, toggleTheme, mounted } = useThemeMode();

  return (
    <div className="min-h-screen bg-zinc-50 text-zinc-900 dark:bg-[#0b0f14] dark:text-zinc-100">
      <div className="flex min-h-screen">
        <aside className="hidden w-72 shrink-0 border-r border-zinc-200 bg-white/80 backdrop-blur dark:border-white/10 dark:bg-[#0f141b]/90 lg:block">
          <div className="flex h-16 items-center gap-3 border-b border-zinc-200 px-6 dark:border-white/10">
            <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-red-500/10 text-red-500 dark:bg-red-500/15">
              <Shield size={20} />
            </div>
            <div>
              <div className="text-sm font-black tracking-wide">SOLIDTRACE</div>
              <div className="text-[10px] uppercase tracking-[0.3em] text-zinc-500 dark:text-zinc-400">
                Security Ops Center
              </div>
            </div>
          </div>

          <div className="px-4 py-5">
            <div className="mb-3 px-3 text-[10px] font-bold uppercase tracking-[0.25em] text-zinc-400 dark:text-zinc-500">
              Navigation
            </div>

            <nav className="space-y-1">
              {navItems.map((item) => {
                const Icon = item.icon;
                const active = pathname === item.href || pathname?.startsWith(item.href + "/");

                return (
                  <Link
                    key={item.href}
                    href={item.href}
                    className={`flex items-center gap-3 rounded-xl px-3 py-3 text-sm font-medium transition ${
                      active
                        ? "bg-zinc-900 text-white dark:bg-white/10 dark:text-white"
                        : "text-zinc-600 hover:bg-zinc-100 hover:text-zinc-900 dark:text-zinc-300 dark:hover:bg-white/5 dark:hover:text-white"
                    }`}
                  >
                    <Icon size={16} />
                    <span>{item.label}</span>
                  </Link>
                );
              })}
            </nav>
          </div>

          <div className="mt-auto border-t border-zinc-200 p-4 dark:border-white/10">
            <div className="rounded-2xl border border-zinc-200 bg-zinc-50 p-4 dark:border-white/10 dark:bg-white/[0.03]">
              <div className="text-xs font-bold text-zinc-700 dark:text-zinc-200">Workspace</div>
              <div className="mt-1 text-xs text-zinc-500 dark:text-zinc-400">default-tenant</div>
            </div>
          </div>
        </aside>

        <div className="flex min-w-0 flex-1 flex-col">
          <header className="sticky top-0 z-20 flex h-16 items-center justify-between border-b border-zinc-200 bg-white/85 px-4 backdrop-blur dark:border-white/10 dark:bg-[#0b0f14]/85 lg:px-6">
            <div>
              <div className="text-base font-black">SolidTrace v2</div>
              <div className="text-xs text-zinc-500 dark:text-zinc-400">
                Analyst-first SOC cockpit
              </div>
            </div>

            <button
              onClick={toggleTheme}
              className="inline-flex items-center gap-2 rounded-xl border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-700 transition hover:bg-zinc-50 dark:border-white/10 dark:bg-white/[0.04] dark:text-zinc-200 dark:hover:bg-white/[0.08]"
            >
              {mounted && theme === "dark" ? <Sun size={15} /> : <Moon size={15} />}
              <span>{mounted ? (theme === "dark" ? "Light" : "Dark") : "Theme"}</span>
            </button>
          </header>

          <main className="flex-1 p-4 lg:p-6">{children}</main>
        </div>
      </div>
    </div>
  );
}