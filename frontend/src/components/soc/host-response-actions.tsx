"use client";

import { useState } from "react";
import { Loader2, ShieldAlert, ShieldCheck, Usb, PowerOff } from "lucide-react";
import { getToken } from "@/lib/auth";
import {
  disableUsb,
  enableUsb,
  isolateHost,
  unisolateHost,
} from "@/lib/api/actions";

type Props = {
  hostname: string;
  compact?: boolean;
  onActionComplete?: () => void;
};

type BusyAction = "isolate" | "unisolate" | "usb_disable" | "usb_enable" | null;

export function HostResponseActions({
  hostname,
  compact = false,
  onActionComplete,
}: Props) {
  const [busy, setBusy] = useState<BusyAction>(null);
  const [message, setMessage] = useState<string | null>(null);

  const token = getToken();

  async function runAction(
    type: BusyAction,
    fn: () => Promise<{ action: string; command_id: string }>,
  ) {
    try {
      setBusy(type);
      setMessage(null);
      const result = await fn();
      setMessage(`${result.action} queued · ${result.command_id}`);
      onActionComplete?.();
    } catch (error) {
      const text =
        error instanceof Error ? error.message : "Action request failed";
      setMessage(text);
    } finally {
      setBusy(null);
    }
  }

const buttonClass = compact
  ? "inline-flex min-w-[88px] items-center justify-center gap-1.5 rounded-xl border px-2 py-2 text-[11px] font-semibold transition"
  : "inline-flex min-w-[112px] items-center justify-center gap-2 rounded-xl border px-3 py-2 text-sm font-semibold transition";

  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-2">
        <button
          className={buttonClass}
          style={{ background: "var(--surface-1)", borderColor: "var(--border-strong)" }}
          disabled={busy !== null}
          onClick={() =>
            runAction("isolate", () =>
              isolateHost(
                {
                  hostname,
                  rule: "manual isolate from assets",
                },
                token ?? undefined,
              ),
            )
          }
        >
          {busy === "isolate" ? <Loader2 size={14} className="animate-spin" /> : <ShieldAlert size={14} />}
          Isolate
        </button>

        <button
          className={buttonClass}
          style={{ background: "var(--surface-1)", borderColor: "var(--border-strong)" }}
          disabled={busy !== null}
          onClick={() =>
            runAction("unisolate", () =>
              unisolateHost(
                {
                  hostname,
                  rule: "manual unisolate from assets",
                },
                token ?? undefined,
              ),
            )
          }
        >
          {busy === "unisolate" ? <Loader2 size={14} className="animate-spin" /> : <ShieldCheck size={14} />}
          Unisolate
        </button>

        <button
          className={buttonClass}
          style={{ background: "var(--surface-1)", borderColor: "var(--border-strong)" }}
          disabled={busy !== null}
          onClick={() =>
            runAction("usb_disable", () =>
              disableUsb(
                {
                  hostname,
                  rule: "manual usb disable from assets",
                },
                token ?? undefined,
              ),
            )
          }
        >
          {busy === "usb_disable" ? <Loader2 size={14} className="animate-spin" /> : <Usb size={14} />}
          USB Off
        </button>

        <button
          className={buttonClass}
          style={{ background: "var(--surface-1)", borderColor: "var(--border-strong)" }}
          disabled={busy !== null}
          onClick={() =>
            runAction("usb_enable", () =>
              enableUsb(
                {
                  hostname,
                  rule: "manual usb enable from assets",
                },
                token ?? undefined,
              ),
            )
          }
        >
          {busy === "usb_enable" ? <Loader2 size={14} className="animate-spin" /> : <PowerOff size={14} />}
          USB On
        </button>
      </div>

      {message ? (
        <div className="text-xs" style={{ color: "var(--muted)" }}>
          {message}
        </div>
      ) : null}
    </div>
  );
}