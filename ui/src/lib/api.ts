import { invoke } from "@tauri-apps/api/core";
import type {
  ApplicationReport,
  DefenderReport,
  DuplicateReport,
  Manifest,
  MoveRecord,
  OrganiseReport,
  Threat,
  AuditRecord,
  Scan,
  SystemStatus,
  Volume,
  ProvenanceReport,
  RuleReport,
  Verdict,
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
  duplicates: (drive: string) =>
    invoke<DuplicateReport>("find_duplicates", { drive }),
  defenderStatus: () => invoke<DefenderReport>("defender_status"),
  defenderThreats: () => invoke<Threat[]>("defender_threats"),
  provenance: () => invoke<ProvenanceReport>("survey_provenance"),
  scanRules: (paths: string[]) => invoke<RuleReport>("scan_rules", { paths }),
  virustotalKeyPresent: () => invoke<boolean>("virustotal_key_present"),
  setVirustotalKey: (key: string) => invoke<boolean>("set_virustotal_key", { key }),
  virustotalLookup: (path: string) => invoke<Verdict>("virustotal_lookup", { path }),
  organise: (drive: string) =>
    invoke<OrganiseReport>("find_organise_proposals", { drive }),
  applyMove: (from: string, to: string) =>
    invoke<MoveRecord>("apply_move", { from, to }),
  undoMove: (id: string) => invoke<MoveRecord>("undo_move", { id }),
  moves: () => invoke<MoveRecord[]>("list_moves"),
  quarantine: (path: string, reason: string) =>
    invoke<Manifest>("quarantine_path", { path, reason }),
  quarantineList: () => invoke<Manifest[]>("list_quarantine"),
  restore: (id: string) => invoke<Manifest>("restore_quarantined", { id }),
  reveal: (path: string) => invoke<void>("reveal_in_explorer", { path }),
  uninstall: (name: string, command: string) =>
    invoke<void>("run_uninstaller", { name, command }),
  protocolVersion: () => invoke<number>("protocol_version"),
};

/** Tauri rejects with a plain string; normalise anything else into one. */
export function reason(cause: unknown): string {
  if (typeof cause === "string") return cause;
  if (cause instanceof Error) return cause.message;
  return String(cause);
}
