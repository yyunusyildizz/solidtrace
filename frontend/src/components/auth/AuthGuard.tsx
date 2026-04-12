"use client";

import { useEffect, useState } from "react";
import { usePathname, useRouter } from "next/navigation";
import { getToken } from "@/lib/auth";

export default function AuthGuard({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const pathname = usePathname();
  const [ready, setReady] = useState(false);

  useEffect(() => {
    const token = getToken();

    if (!token) {
      router.replace(`/login?next=${encodeURIComponent(pathname || "/dashboard")}`);
      return;
    }

    setReady(true);
  }, [pathname, router]);

  if (!ready) {
    return (
      <div className="flex min-h-[60vh] items-center justify-center">
        <div
          className="rounded-2xl border px-5 py-3 text-sm"
          style={{
            borderColor: "var(--border)",
            background: "var(--surface-1)",
            color: "var(--muted)",
          }}
        >
          Session checking...
        </div>
      </div>
    );
  }

  return <>{children}</>;
}
