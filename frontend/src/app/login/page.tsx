"use client";

import { FormEvent, useEffect, useMemo, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { AlertCircle, Shield } from "lucide-react";
import { login } from "@/lib/api/auth";
import { getToken, setAuthSession } from "@/lib/auth";

function sanitizeNext(next: string | null) {
  if (!next) return "/dashboard";
  if (!next.startsWith("/")) return "/dashboard";
  if (next.startsWith("//")) return "/dashboard";
  return next;
}

export default function LoginPage() {
  const router = useRouter();
  const searchParams = useSearchParams();

  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const next = useMemo(
    () => sanitizeNext(searchParams.get("next")),
    [searchParams],
  );

  useEffect(() => {
    if (getToken()) {
      router.replace(next);
    }
  }, [router, next]);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      const response = await login(username.trim(), password);

      if (!response.access_token) {
        throw new Error("Login başarılı ama access token dönmedi");
      }

      if (response.two_factor_required) {
        throw new Error("Two-factor authentication henüz bu arayüzde tamamlanmadı");
      }

      setAuthSession({
        accessToken: response.access_token,
        refreshToken: response.refresh_token ?? null,
        username: username.trim(),
      });

      router.replace(next);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Giriş başarısız");
    } finally {
      setLoading(false);
    }
  }

  return (
    <main
      className="min-h-screen px-6 py-10"
      style={{
        background:
          "radial-gradient(circle at 58% -10%, rgba(44, 100, 218, 0.06), transparent 22%), radial-gradient(circle at 82% 0%, rgba(13, 148, 136, 0.04), transparent 18%), linear-gradient(180deg, var(--background), var(--background))",
        color: "var(--foreground)",
      }}
    >
      <div className="mx-auto grid min-h-[80vh] max-w-6xl items-center gap-8 lg:grid-cols-[1.08fr_0.92fr]">
        <section className="space-y-6">
          <div
            className="inline-flex items-center gap-2 rounded-full border px-4 py-2 text-sm"
            style={{
              borderColor: "var(--border)",
              background: "var(--panel)",
            }}
          >
            <Shield size={16} />
            SolidTrace SOC Access
          </div>

          <div className="space-y-4">
            <h1 className="text-4xl font-black tracking-tight lg:text-6xl">
              Secure access to your SOC workspace
            </h1>
            <p
              className="max-w-2xl text-base leading-7"
              style={{ color: "var(--muted-strong)" }}
            >
              Sign in to access alerts, investigations, dashboards, assets and analyst workflows.
            </p>
          </div>

          <div className="grid gap-4 md:grid-cols-3">
            {[
              "Alert triage and workflow actions",
              "Live investigation graphing",
              "Asset, Sigma, and UEBA visibility",
            ].map((item) => (
              <div
                key={item}
                className="rounded-2xl border p-4 text-sm"
                style={{
                  borderColor: "var(--border)",
                  background: "var(--panel-strong)",
                  color: "var(--muted-strong)",
                  boxShadow: "var(--shadow-soft)",
                }}
              >
                {item}
              </div>
            ))}
          </div>
        </section>

        <section
          className="rounded-3xl border p-6"
          style={{
            borderColor: "var(--border)",
            background: "var(--panel-strong)",
            boxShadow: "var(--shadow-panel)",
          }}
        >
          <div className="mb-6">
            <div
              className="text-sm font-bold uppercase tracking-[0.22em]"
              style={{ color: "var(--muted)" }}
            >
              Login
            </div>
            <h2 className="mt-2 text-2xl font-black">Authenticate to continue</h2>
          </div>

          {error ? (
            <div className="mb-4 flex items-start gap-3 rounded-2xl border border-red-200 bg-red-50 p-4 text-sm text-red-700 dark:border-red-500/20 dark:bg-red-500/10 dark:text-red-300">
              <AlertCircle size={16} className="mt-0.5 shrink-0" />
              <span>{error}</span>
            </div>
          ) : null}

          <form onSubmit={onSubmit} className="space-y-4">
            <div>
              <label className="mb-2 block text-sm font-medium">Username</label>
              <input
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="w-full rounded-2xl border px-4 py-3 text-sm outline-none transition"
                style={{
                  borderColor: "var(--border)",
                  background: "var(--surface-0)",
                  color: "var(--foreground)",
                }}
                placeholder="admin"
              />
            </div>

            <div>
              <label className="mb-2 block text-sm font-medium">Password</label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full rounded-2xl border px-4 py-3 text-sm outline-none transition"
                style={{
                  borderColor: "var(--border)",
                  background: "var(--surface-0)",
                  color: "var(--foreground)",
                }}
                placeholder="••••••••"
              />
            </div>

            <button
              type="submit"
              disabled={loading || !username.trim() || !password}
              className="w-full rounded-2xl px-4 py-3 text-sm font-medium transition disabled:cursor-not-allowed disabled:opacity-60"
              style={{
                background: "var(--foreground)",
                color: "var(--background)",
              }}
            >
              {loading ? "Signing in..." : "Sign in"}
            </button>
          </form>
        </section>
      </div>
    </main>
  );
}