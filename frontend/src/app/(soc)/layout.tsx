import type { ReactNode } from "react";
import { ThemeProvider } from "@/components/soc/providers/theme-provider";
import { AppShell } from "@/components/soc/layout/app-shell";

export default function SocLayout({ children }: { children: ReactNode }) {
  return (
    <ThemeProvider>
      <AppShell>{children}</AppShell>
    </ThemeProvider>
  );
}