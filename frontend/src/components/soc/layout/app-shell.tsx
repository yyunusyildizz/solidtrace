"use client";

import { useMemo, useState } from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import {
  Activity,
  Blocks,
  Brain,
  ChevronRight,
  Globe2,
  LayoutDashboard,
  LogOut,
  Menu,
  Moon,
  Search,
  Shield,
  ShieldAlert,
  SunMedium,
  Workflow,
} from "lucide-react";
import { clearAuthSession, getUsername } from "@/lib/auth";
import { useTheme } from "@/components/soc/providers/theme-provider";

type NavItem = {
  href: string;
  label: string;
  icon: React.ReactNode;
  badge?: string;
};

const NAV_ITEMS: NavItem[] = [
  { href: "/dashboard", label: "Dashboard", icon: <LayoutDashboard size={16} /> },
  { href: "/alerts", label: "Alerts", icon: <ShieldAlert size={16} />, badge: "Live" },
  { href: "/investigations", label: "Investigations", icon: <Workflow size={16} /> },
  { href: "/assets", label: "Assets", icon: <Blocks size={16} /> },
  { href: "/detections", label: "Detections", icon: <Shield size={16} /> },
  { href: "/activity", label: "Activity", icon: <Activity size={16} /> },
];

const SHELL_TOPBAR_HEIGHT = 73;

export function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const { theme, toggleTheme } = useTheme();
  const [mobileOpen, setMobileOpen] = useState(false);

  const username = useMemo(() => getUsername() || "Analyst", []);
  const tenantLabel = "default_tenant";
  const liveStatus = "Connected";

  function handleLogout() {
    clearAuthSession();
    router.replace("/login");
  }

  return (
    <div className="min-h-screen text-[var(--foreground)]">
      <div className="flex min-h-screen bg-transparent">
        <aside
          className="shell-sidebar hidden w-72 shrink-0 lg:flex lg:flex-col"
          style={{ borderRight: "1px solid var(--border)" }}
        >
          <SidebarContent
            pathname={pathname}
            username={username}
            tenantLabel={tenantLabel}
            onLogout={handleLogout}
          />
        </aside>

        {mobileOpen ? (
          <div className="fixed inset-0 z-50 lg:hidden">
            <div
              className="absolute inset-0 bg-black/40 backdrop-blur-[2px]"
              onClick={() => setMobileOpen(false)}
            />
            <aside
              className="shell-sidebar absolute inset-y-0 left-0 flex w-[88%] max-w-80 flex-col"
              style={{ borderRight: "1px solid var(--border)" }}
            >
              <SidebarContent
                pathname={pathname}
                username={username}
                tenantLabel={tenantLabel}
                onLogout={() => {
                  setMobileOpen(false);
                  handleLogout();
                }}
                onNavigate={() => setMobileOpen(false)}
              />
            </aside>
          </div>
        ) : null}

        <div className="flex min-w-0 flex-1 flex-col">
          <header className="shell-header sticky top-0 z-30">
            <div
              className="flex items-center gap-3 px-4 lg:px-6"
              style={{
                height: `${SHELL_TOPBAR_HEIGHT}px`,
                borderBottom: "1px solid var(--border)",
              }}
            >
              <button
                onClick={() => setMobileOpen(true)}
                className="inline-flex h-10 w-10 items-center justify-center rounded-xl border px-0 py-0 transition lg:hidden"
                style={{
                  background: "var(--surface-1)",
                  borderColor: "var(--border-strong)",
                }}
                aria-label="Open navigation"
              >
                <Menu size={18} />
              </button>

              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <div className="text-sm font-black tracking-wide">
                    SolidTrace SOC
                  </div>
                  <span
                    className="inline-flex items-center gap-1 rounded-full border px-2 py-1 text-[10px] font-bold uppercase tracking-[0.14em]"
                    style={{
                      background: "color-mix(in srgb, var(--success) 12%, transparent)",
                      borderColor: "color-mix(in srgb, var(--success) 24%, transparent)",
                      color: "var(--success)",
                    }}
                  >
                    <span
                      className="h-1.5 w-1.5 rounded-full"
                      style={{ background: "var(--success)" }}
                    />
                    {liveStatus}
                  </span>
                </div>

                <div className="mt-1 text-xs" style={{ color: "var(--muted)" }}>
                  Analyst-first workspace · Tenant: {tenantLabel}
                </div>
              </div>

              <div
                className="hidden min-w-[240px] items-center gap-2 rounded-2xl border px-3 py-2 text-sm md:flex"
                style={{
                  background: "color-mix(in srgb, var(--surface-1) 88%, transparent)",
                  borderColor: "var(--border-strong)",
                  color: "var(--muted)",
                }}
              >
                <Search size={15} />
                <span>Search alerts, hosts, users, rules...</span>
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={toggleTheme}
                  className="inline-flex h-10 w-10 items-center justify-center rounded-xl border transition"
                  style={{
                    background: "var(--surface-1)",
                    borderColor: "var(--border-strong)",
                  }}
                  aria-label="Toggle theme"
                >
                  {theme === "dark" ? <SunMedium size={17} /> : <Moon size={17} />}
                </button>

                <div
                  className="hidden rounded-2xl border px-3 py-2 text-right md:block"
                  style={{
                    background: "var(--surface-1)",
                    borderColor: "var(--border-strong)",
                  }}
                >
                  <div className="text-xs" style={{ color: "var(--muted)" }}>
                    Signed in as
                  </div>
                  <div className="text-sm font-semibold">{username}</div>
                </div>

                <button
                  onClick={handleLogout}
                  className="inline-flex items-center gap-2 rounded-xl border px-3 py-2 text-sm font-medium transition"
                  style={{
                    background: "var(--surface-1)",
                    borderColor: "var(--border-strong)",
                  }}
                >
                  <LogOut size={15} />
                  <span className="hidden sm:inline">Logout</span>
                </button>
              </div>
            </div>
          </header>

          <main className="flex-1 px-4 py-4 lg:px-6 lg:py-6">{children}</main>
        </div>
      </div>
    </div>
  );
}

function SidebarContent({
  pathname,
  username,
  tenantLabel,
  onLogout,
  onNavigate,
}: {
  pathname: string;
  username: string;
  tenantLabel: string;
  onLogout: () => void;
  onNavigate?: () => void;
}) {
  return (
    <>
      <div
        className="flex items-center gap-3 px-5"
        style={{
          height: `${SHELL_TOPBAR_HEIGHT}px`,
          borderBottom: "1px solid var(--border)",
        }}
      >
        <div
          className="flex h-11 w-11 items-center justify-center rounded-2xl shadow-sm"
          style={{
            background: "var(--foreground)",
            color: "var(--background)",
          }}
        >
          <Shield size={18} />
        </div>
        <div>
          <div className="text-base font-black tracking-tight">SolidTrace</div>
          <div className="text-xs" style={{ color: "var(--muted)" }}>
            Unified SOC Workspace
          </div>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto px-4 py-4">
        <div
          className="mb-3 px-2 text-[11px] font-bold uppercase tracking-[0.22em]"
          style={{ color: "var(--muted)" }}
        >
          Operations
        </div>

        <nav className="space-y-1.5">
          {NAV_ITEMS.map((item) => {
            const active = pathname === item.href;

            return (
              <Link
                key={item.href}
                href={item.href}
                onClick={onNavigate}
                className="group flex items-center justify-between rounded-2xl border px-3 py-3 transition"
                style={
                  active
                    ? {
                        background: "var(--foreground)",
                        color: "var(--background)",
                        borderColor: "var(--foreground)",
                        boxShadow: "0 8px 24px rgba(15, 23, 42, 0.10)",
                      }
                    : {
                        background: "color-mix(in srgb, var(--surface-1) 82%, transparent)",
                        color: "var(--foreground)",
                        borderColor: "var(--border-strong)",
                      }
                }
              >
                <div className="flex items-center gap-3">
                  <span style={{ opacity: active ? 1 : 0.94 }}>{item.icon}</span>
                  <span
                    className="text-sm font-medium"
                    style={{ opacity: active ? 1 : 0.96 }}
                  >
                    {item.label}
                  </span>
                </div>

                <div className="flex items-center gap-2">
                  {item.badge ? (
                    <span
                      className="inline-flex rounded-full px-2 py-1 text-[10px] font-bold uppercase tracking-wide"
                      style={
                        active
                          ? {
                              background: "rgba(255,255,255,0.12)",
                              color: "inherit",
                            }
                          : {
                              background: "var(--surface-2)",
                              color: "var(--muted-strong)",
                            }
                      }
                    >
                      {item.badge}
                    </span>
                  ) : null}

                  <ChevronRight size={14} style={{ opacity: active ? 0.9 : 0.58 }} />
                </div>
              </Link>
            );
          })}
        </nav>

        <div className="mt-6 grid gap-3">
          <div
            className="rounded-3xl border p-4 shadow-sm"
            style={{
              background: "var(--surface-1)",
              borderColor: "var(--border)",
            }}
          >
            <div
              className="mb-2 flex items-center gap-2 text-xs font-bold uppercase tracking-[0.2em]"
              style={{ color: "var(--muted)" }}
            >
              <Globe2 size={13} />
              Workspace
            </div>
            <div className="text-sm font-semibold">{tenantLabel}</div>
            <div className="mt-1 text-xs" style={{ color: "var(--muted)" }}>
              Primary SOC environment for {username}
            </div>
          </div>

          <div
            className="rounded-3xl border p-4 shadow-sm"
            style={{
              background: "var(--surface-1)",
              borderColor: "var(--border)",
            }}
          >
            <div
              className="mb-2 flex items-center gap-2 text-xs font-bold uppercase tracking-[0.2em]"
              style={{ color: "var(--muted)" }}
            >
              <Brain size={13} />
              AI Assist
            </div>
            <div className="text-sm font-semibold">Ready for analyst workflows</div>
            <div className="mt-1 text-xs" style={{ color: "var(--muted)" }}>
              Investigation summarization and alert context can be layered next.
            </div>
          </div>
        </div>
      </div>

      <div className="border-t px-4 py-4" style={{ borderColor: "var(--border)" }}>
        <button
          onClick={onLogout}
          className="flex w-full items-center justify-center gap-2 rounded-2xl border px-4 py-3 text-sm font-medium transition"
          style={{
            background: "var(--surface-1)",
            borderColor: "var(--border)",
          }}
        >
          <LogOut size={15} />
          Logout
        </button>
      </div>
    </>
  );
}