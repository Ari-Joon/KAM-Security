import { invoke } from "@tauri-apps/api/core";
import type {
  AppFootprint,
  StartState,
  UpdateCheck,
  CheckFinding,
  Cleared,
  DefenderReport,
  DuplicateGroup,
  Manifest,
  MoveRecord,
  Threat,
  AuditRecord,
  FolderScan,
  Growth,
  Volume,
  BehaviourReport,
  CanaryReport,
  ExtensionReport,
  HardeningReport,
  Verdict,
  FirewallReport,
  ConnectionReport,
  Remnants,
  Removal,
  Sweep,
  Kept,
  Schedule,
  DownloadsPage,
  DownloadRecord,
  DissectionView,
  Dissected,
  Extraction,
  MenuState,
  Launch,
  UnseenDownloads,
  TrafficReport,
  RootReport,
  WingetAsked,
  WindowsUpdateReport,
  DeviceFacts,
  DefenderExclusions,
} from "./types";
import type { ServiceChecked } from "./service";
import type { Asked, JobSlot, PageJob, PageJobOutcome } from "./jobs";

/**
 * Typed wrappers over the Tauri commands.
 *
 * The frontend cannot open a named pipe, so everything here crosses into the
 * shell's Rust half, which then talks to the agent. Each of these is one
 * request on one connection.
 */
export const api = {
  /**
   * Ask whether KAM Security's service is answering, with the smallest
   * request there is. One question at a time: see `service` in the shell.
   */
  serviceCheck: () => invoke<ServiceChecked>("service_check"),
  recentAudit: (limit: number) => invoke<AuditRecord[]>("recent_audit", { limit }),
  volumes: () => invoke<Volume[]>("list_volumes"),
  /**
   * Start a page's long job in the window's own half. Resolves once it is
   * under way, or rejects with why it could not be started: one of each job
   * runs at a time. See `usePageJob` for following it.
   */
  startPageJob: (asked: Asked) => invoke<PageJob>("start_job", { asked }),
  /** A page's job as it stands, or null when its place is empty. */
  pageJob: (slot: JobSlot) => invoke<PageJob | null>("job_state", { slot }),
  /** What a page's job came to, once it has ended. Asking does not take it. */
  pageJobOutcome: <T>(slot: JobSlot) =>
    invoke<PageJobOutcome<T> | null>("job_outcome", { slot }),
  /**
   * The page has what that run came to. The shell lets go of an answer the
   * page keeps for itself, and keeps any other for the page to show again.
   */
  pageJobTaken: (slot: JobSlot, job: string) => invoke<void>("job_taken", { slot, job }),
  /** Stop a page's job, when the service can stop it. */
  stopPageJob: (slot: JobSlot) => invoke<void>("stop_job", { slot }),
  /** One folder of the map, read on its own, below where a scan stops. */
  scanFolder: (path: string) => invoke<FolderScan>("scan_folder", { path }),
  /**
   * The person's own summaries of their scans of a drive, and what grew and
   * shrank between two: `later` (or the newest) against `earlier` (or the
   * one kept before it).
   */
  growth: (drive: string, later: number | null, earlier: number | null) =>
    invoke<Growth>("get_growth", { drive, later, earlier }),
  applicationsPreview: () => invoke<AppFootprint[]>("list_applications_preview"),
  /**
   * A set of identical files as it stands once one copy has gone, or null
   * when one file is all that is left. Worked out in the shell by the code
   * that judged the set, so its figures and sentences stay true.
   */
  duplicateSetWithout: (group: DuplicateGroup, path: string) =>
    invoke<DuplicateGroup | null>("duplicate_set_without", { group, path }),
  defenderStatus: () => invoke<DefenderReport>("defender_status"),
  defenderThreats: () => invoke<Threat[]>("defender_threats"),
  behaviourEvents: () => invoke<BehaviourReport>("behaviour_events"),
  browserExtensions: () => invoke<ExtensionReport>("browser_extensions"),
  hardening: () => invoke<HardeningReport>("hardening"),
  setHardening: (id: string, wanted: "audit" | "block" | "off") =>
    invoke<HardeningReport>("set_hardening", { id, wanted }),
  protection: () => invoke<boolean>("protection"),
  setProtection: (enabled: boolean) => invoke<boolean>("set_protection", { enabled }),
  canaries: () => invoke<CanaryReport>("canaries"),
  setCanaries: (planted: boolean) => invoke<CanaryReport>("set_canaries", { planted }),
  setCanaryAuditing: (enabled: boolean) =>
    invoke<CanaryReport>("set_canary_auditing", { enabled }),
  cancelJob: (job: string) => invoke<void>("cancel_job", { job }),
  findRemnants: (name: string, paths: string[], kinds: string[]) =>
    invoke<Remnants>("find_remnants", { name, paths, kinds }),
  firewall: () => invoke<FirewallReport>("firewall"),
  /**
   * The names a list of pointers stand for, in the same order. Looked up by the
   * window, as the person: see `display_names` in the shell.
   */
  displayNames: (names: string[]) => invoke<string[]>("display_names", { names }),
  connections: () => invoke<ConnectionReport>("connections"),
  /** The hosts file, hand-set DNS servers, this account's proxy and Windows' own. */
  trafficSettings: () => invoke<TrafficReport>("traffic_settings"),
  /** Every trusted root certificate by store, against Microsoft's cached list. */
  rootCertificates: () => invoke<RootReport>("root_certificates"),
  blockProgram: (path: string) => invoke<string>("block_program", { path }),
  unblockProgram: (rule: string) => invoke<void>("unblock_program", { rule }),
  virustotalKeyPresent: () => invoke<boolean>("virustotal_key_present"),
  setVirustotalKey: (key: string) => invoke<boolean>("set_virustotal_key", { key }),
  virustotalLookup: (path: string) => invoke<Verdict>("virustotal_lookup", { path }),
  applyMove: (from: string, to: string) =>
    invoke<MoveRecord>("apply_move", { from, to }),
  undoMove: (id: string) => invoke<MoveRecord>("undo_move", { id }),
  moves: () => invoke<MoveRecord[]>("list_moves"),
  quarantine: (path: string, reason: string) =>
    invoke<Manifest>("quarantine_path", { path, reason }),
  quarantineCopy: (path: string, keep: string, reason: string, chosen = false) =>
    invoke<Manifest>("quarantine_copy", { path, keep, reason, chosen }),
  checkStillTwins: (remove: string, keep: string) =>
    invoke<void>("check_still_twins", { remove, keep }),
  schedule: () => invoke<Schedule>("schedule"),
  setSchedule: (enabled: boolean, day: string, hour: number) =>
    invoke<Schedule>("set_schedule", { enabled, day, hour }),
  runCheck: () => invoke<CheckFinding[]>("run_check"),
  clearCache: (id: string) => invoke<Cleared>("clear_cache", { id }),
  quarantineList: () => invoke<Manifest[]>("list_quarantine"),
  restore: (id: string) => invoke<Manifest>("restore_quarantined", { id }),
  deleteQuarantined: (id: string) => invoke<Removal>("delete_quarantined", { id }),
  emptyQuarantine: () => invoke<Removal>("empty_quarantine"),
  /**
   * Send something to the Recycle Bin, or leave it exactly where it is.
   *
   * Done in this process rather than by the agent, and that is deliberate: the
   * Recycle Bin is per user, so a delete performed by the LocalSystem service
   * would land in SYSTEM's bin where nobody can reach it. Here it goes to the
   * person's own, and needs no privilege at all.
   *
   * Windows deletes an item outright, silently, when the bin cannot take it.
   * This stops that delete before it happens and rejects with why the item is
   * still there. Should it go all the same, `in_bin` is false and `warning`
   * says so; `in_bin` with a `warning` means the bin could not be counted to
   * confirm it arrived. Do not report a recycle without checking both.
   */
  recycleOrLeave: (path: string) =>
    invoke<{ in_bin: boolean; warning: string | null }>("recycle_or_leave", { path }),
  /** For each item, whether this account could remove it itself, without the agent. */
  canRecycleAll: (paths: string[]) => invoke<boolean[]>("can_recycle_all", { paths }),
  /**
   * Compare the machine with what it looked like last time.
   *
   * The only call here that answers what is *different* rather than what is
   * true. Each call also records a new baseline, so calling it twice in a row
   * legitimately reports nothing the second time.
   */
  sweepForChanges: () => invoke<Sweep>("sweep_for_changes"),
  /** One earlier comparison's list, read again as it was shown. Takes no comparison. */
  readComparison: (id: number) => invoke<Kept>("read_comparison", { id }),
  reveal: (path: string) => invoke<void>("reveal_in_explorer", { path }),
  uninstall: (name: string, command: string) =>
    invoke<void>("run_uninstaller", { name, command }),
  checkForUpdate: () => invoke<UpdateCheck>("check_for_update"),
  startAtSignIn: () => invoke<StartState>("start_at_sign_in"),
  setStartAtSignIn: (enabled: boolean) =>
    invoke<StartState>("set_start_at_sign_in", { enabled }),
  openReleasePage: (url: string) => invoke<void>("open_release_page", { url }),

  /** The Downloads page: history, files not checked yet, and the watcher. */
  downloadsPage: () => invoke<DownloadsPage>("downloads_page"),
  /**
   * Check one file as a new download is checked. Streams progress and can be
   * stopped; resolves to null when stopped. Defender only reports.
   */
  checkDownload: (path: string, job: string) =>
    invoke<DownloadRecord | null>("check_download", { path, job }),
  /** Quarantine one download. The agent fences it to the Downloads folder. */
  quarantineDownload: (path: string) => invoke<Manifest>("quarantine_download", { path }),
  /**
   * Remove one row from the download history, for good. The record goes and
   * the file is not touched. Resolves to how many rows went: none when it had
   * already gone.
   */
  removeDownloadRecord: (path: string, sha256: string) =>
    invoke<number>("remove_download_record", { path, sha256 }),
  /**
   * Remove every row the history held when the page read it (`upTo` is the
   * page's `read_at`), for good. A check recorded since is kept.
   */
  clearDownloadRecords: (upTo: string) =>
    invoke<number>("clear_download_records", { upTo }),
  /**
   * Take a zip apart. Quarantines the original first when Defender flagged it.
   * Nothing is extracted until extractClean. The answer carries no view when
   * it was stopped, and says what had become of the original by then.
   */
  dissectArchive: (path: string, job: string) =>
    invoke<Dissected>("dissect_archive", { path, job }),
  /** Stop taking an archive apart, in this program and in the agent. */
  stopDissection: (job: string) => invoke<void>("stop_dissection", { job }),
  /** The archive that is still open, after leaving the page and coming back. */
  openDissection: (token: string) =>
    invoke<DissectionView | null>("open_dissection", { token }),
  extractClean: (token: string) => invoke<Extraction>("extract_clean", { token }),
  discardDissection: (token: string) => invoke<void>("discard_dissection", { token }),
  /**
   * Check every file in Downloads that is not checked yet, as one job. It
   * resolves once the job is under way; the page then reads how far it has
   * got, and it goes on if the page is left or the window is closed.
   */
  checkBacklog: () => invoke<void>("check_backlog"),
  stopBacklog: () => invoke<void>("stop_backlog"),
  /** Let go of what that job came to, once it has been read. */
  closeBacklog: () => invoke<void>("close_backlog"),
  /**
   * How many download results this account has not looked at yet, or why
   * that could not be told. Kept per account and across restarts.
   */
  downloadsUnseen: () => invoke<UnseenDownloads>("downloads_unseen"),
  /**
   * Put it on record that Active downloads is in front of the person now,
   * which clears that count. Resolves to when it last was.
   */
  downloadsLooked: () => invoke<{ previous: string | null }>("downloads_looked"),
  setContextMenu: (enabled: boolean) => invoke<MenuState>("set_context_menu", { enabled }),
  /**
   * The next file asked about from Explorer or a notification, taken once.
   * A request to take an archive apart waits while `archiveFree` is false.
   */
  takeLaunch: (archiveFree: boolean) =>
    invoke<Launch | null>("take_launch", { archiveFree }),
  launchWaiting: () => invoke<boolean>("launch_waiting"),

  /**
   * Which installed apps winget says have a newer version. Runs winget as
   * the person: seconds, and its catalogue comes over the network. Lists
   * only; nothing is installed.
   */
  newerVersions: () => invoke<WingetAsked>("newer_versions"),
  /** What Windows says about its own updates, read by the window as the person. */
  windowsUpdate: () => invoke<WindowsUpdateReport>("windows_update"),
  /** Secure Boot, the TPM, drive C:'s encryption and Remote Desktop. */
  deviceFacts: () => invoke<DeviceFacts>("device_facts"),
  /**
   * What Defender has been told to skip. Goes through Windows' permission
   * prompt every time; the answer is for the page to hold, not to keep.
   */
  defenderExclusions: () => invoke<DefenderExclusions>("defender_exclusions"),
};

/** Tauri rejects with a plain string; normalise anything else into one. */
export function reason(cause: unknown): string {
  if (typeof cause === "string") return cause;
  if (cause instanceof Error) return cause.message;
  return String(cause);
}
