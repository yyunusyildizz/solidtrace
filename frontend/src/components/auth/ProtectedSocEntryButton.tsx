"use client";

import { useRouter } from "next/navigation";
import { getToken } from "@/lib/auth";

export default function ProtectedSocEntryButton({
  href = "/dashboard",
  children,
}: {
  href?: string;
  children: React.ReactNode;
}) {
  const router = useRouter();

  const handleClick = () => {
    const token = getToken();

    if (!token) {
      router.push(`/login?next=${encodeURIComponent(href)}`);
      return;
    }

    router.push(href);
  };

  return <button onClick={handleClick}>{children}</button>;
}