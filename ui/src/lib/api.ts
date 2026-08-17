import { invoke } from "@tauri-apps/api/core";
import type {
  ApplicationReport,
  Manifest,
  AuditRecord,
  Scan,
  SystemStatus,
  Volume,
} from "./types";

/**
 * Typed wrappers over the Tauri commands.
 *
 * The frontend cannot open a named pipe, so everything here crosses into the
 * shell's Rust half, which then talks to the agent. Each of these is one
 * request on one connection.
 */
export const api = {
  status: () => invoke<SystemStatus>("agent_status"),
  recentAudit: (limit: number) => invoke<AuditRecord[]>("recent_audit", { limit }),
  volumes: () => invoke<Volume[]>("list_volumes"),
  scan: (path: string) => invoke<Scan>("scan_path", { path }),
  applications: (drive: string) =>
    invoke<ApplicationReport>("list_applications", { drive }),
  quarantine: (path: string, reason: string) =>
    invoke<Manifest>("quarantine_path", { path, reason }),
  quarantineList: () => invoke<Manifest[]>("list_quarantine"),
  restore: (id: string) => invoke<Manifest>("restore_quarantined", { id }),
  reveal: (path: string) => invoke<void>("reveal_in_explorer", { path }),
  protocolVersion: () => invoke<number>("protocol_version"),
};

/** Tauri rejects with a plain string; normalise anything else into one. */
export function reason(cause: unknown): string {
  if (typeof cause === "string") return cause;
  if (cause instanceof Error) return cause.message;
  return String(cause);
}
