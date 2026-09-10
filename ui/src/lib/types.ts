export type SystemStatus = {
  protocol_version: number;
  agent_version: string;
  running_as_service: boolean;
  hostname: string;
};

export type Effect = "observed" | "changed" | "refused";

export type AuditRecord = {
  id: number;
  at: string;
  module: string;
  action: string;
  effect: Effect;
  detail: string;
  undo_token: string | null;
};

export type DriveKind = "fixed" | "removable" | "network" | "ram_disk" | "other";

export type Volume = {
  root: string;
  label: string;
  filesystem: string;
  kind: DriveKind;
  total_bytes: number;
  free_bytes: number;
  supports_mft: boolean;
};

export type TreeNode = {
  name: string;
  path: string;
  bytes: number;
  files: number;
  children: TreeNode[];
  is_aggregate?: boolean;
};

export type FileEntry = {
  path: string;
  bytes: number;
};

export type LocationKind = "install" | "program_data" | "local_data" | "roaming_data";

export type AppLocation = {
  path: string;
  bytes: number;
  kind: LocationKind;
  shared_with: number;
};

export type AppFootprint = {
  name: string;
  publisher: string;
  version: string;
  reported_bytes: number | null;
  actual_bytes: number;
  shared_bytes: number;
  locations: AppLocation[];
  uninstall_command: string | null;
  installed_on: string | null;
  last_used: number | null;
  launches: number | null;
};

export type FootprintSummary = {
  applications: number;
  measured_bytes: number;
  reported_bytes: number;
  without_reported_size: number;
};

export type Zone =
  | "local_machine"
  | "intranet"
  | "trusted"
  | "internet"
  | "restricted"
  | { other: number };

export type Download = {
  path: string;
  name: string;
  bytes: number;
  zone: Zone;
  host_url: string | null;
  referrer_url: string | null;
  days_since_arrival: number | null;
  days_since_access: number | null;
};

export type DownloadSummary = {
  found: number;
  total_bytes: number;
  last_access_tracked: boolean;
  examined: number;
};

/** Who put a copy where it is, which decides whether it can go. */
export type Owner =
  | "windows"
  | "servicing"
  | "program"
  | "program_data"
  | "yours"
  | "deleted"
  | "elsewhere";

/** What a set of identical files means, taken as a whole. */
export type DuplicateVerdict = "keep" | "deliberate" | "choose" | "unclear";

export type FileCopy = {
  path: string;
  owner: Owner;
  removable: boolean;
};

export type DuplicateGroup = {
  bytes: number;
  /** Everything past the first copy, whether or not any of it can go. */
  wasted_bytes: number;
  /** The part that could actually be freed. Often zero, and the honest number. */
  reclaimable_bytes: number;
  copies: FileCopy[];
  verdict: DuplicateVerdict;
  suggested_keep: number | null;
  reasons: string[];
};

export type DuplicateSummary = {
  groups: number;
  wasted_bytes: number;
  reclaimable_bytes: number;
  actionable: number;
  examined: number;
  head_hashed: number;
  fully_hashed: number;
  elapsed_ms: number;
  truncated: boolean;
};

/** What the weekly check is set to, if anything. */
export type Schedule = {
  enabled: boolean;
  day: string | null;
  /** Local time of day, HH:MM. */
  at: string | null;
  account: string | null;
  /** The program the task starts, shown so it can be seen rather than trusted. */
  command: string | null;
};

export type CheckFinding = {
  summary: string;
  /** True when this is a state to correct rather than a note. */
  serious: boolean;
};

/** What a deliberate deletion removed. There is no undo for it. */
export type Removal = {
  items: number;
  bytes_freed: number;
  /** Anything that could not be removed, phrased for a person. */
  refused: string[];
};

export type CacheSafety = "routine" | "considered";

export type CacheLocation = {
  path: string;
  bytes: number;
  files: number;
  partial: boolean;
};

export type Cache = {
  id: string;
  name: string;
  what: string;
  /** What clearing it costs you. Empty when the answer is genuinely nothing. */
  cost: string;
  safety: CacheSafety;
  locations: CacheLocation[];
  bytes: number;
  files: number;
};

export type Cleared = {
  id: string;
  bytes_freed: number;
  files_removed: number;
  files_in_use: number;
  refused: string[];
};

export type DuplicateReport = {
  groups: DuplicateGroup[];
  summary: DuplicateSummary;
};

export type Strength = "reasonable" | "strong";

export type Proposal = {
  from: string;
  to: string;
  name: string;
  bytes: number;
  strength: Strength;
  reason: string;
  destination_syncs: boolean;
};

export type OrganiseSummary = {
  proposals: number;
  bytes: number;
  examined: number;
};

export type OrganiseReport = {
  proposals: Proposal[];
  summary: OrganiseSummary;
};

export type MoveRecord = {
  id: string;
  from: string;
  to: string;
  bytes: number;
  moved_at: number;
  undone: boolean;
};

/** How long each stage of a measurement took, in milliseconds. */
export type Timings = {
  read_table: number;
  /** Of that, the part spent waiting on the disk rather than parsing. */
  read_table_io: number;
  /** File records the table held. */
  records: number;
  build_index: number;
  applications: number;
  orphans: number;
  downloads: number;
  total: number;
};

export type ApplicationReport = {
  apps: AppFootprint[];
  summary: FootprintSummary;
  orphans: Orphan[];
  orphan_summary: OrphanSummary;
  downloads: Download[];
  download_summary: DownloadSummary;
  timings: Timings;
};

export type ScanMethod = "master_file_table" | "directory_walk";

export type Scan = {
  root: string;
  method: ScanMethod;
  fallback_reason: string | null;
  total_bytes: number;
  file_count: number;
  directory_count: number;
  unreadable: number;
  elapsed_ms: number;
  tree: TreeNode;
  largest_files: FileEntry[];
};

export type Confidence = "low" | "medium" | "high";

export type Orphan = {
  path: string;
  name: string;
  bytes: number;
  kind: LocationKind;
  confidence: Confidence;
  days_since_modified: number | null;
  reasons: string[];
};

export type OrphanSummary = {
  found: number;
  total_bytes: number;
  confident_bytes: number;
};

export type Manifest = {
  id: string;
  original_path: string;
  kind: "file" | "directory";
  bytes: number;
  quarantined_at: number;
  reason: string;
  restored: boolean;
};

export type DefenderStatus = {
  healthy: boolean | null;
  antivirus_enabled: boolean | null;
  realtime_protection: boolean | null;
  behaviour_monitoring: boolean | null;
  cloud_protection: boolean | null;
  tamper_protection: boolean | null;
  antivirus_signature_version: string | null;
  engine_version: string | null;
  signature_age_days: number | null;
  last_quick_scan_age_days: number | null;
  last_full_scan_age_days: number | null;
  computer_state: number | null;
};

export type DefenderReport = {
  status: DefenderStatus;
  concerns: string[];
};

/**
 * A scan KAM asks Windows Defender to run.
 *
 * Serialised to match the Rust enum's tag, so the shape matters: `{ kind:
 * "quick" }`, `{ kind: "full" }`, or `{ kind: "path", path: "C:\..." }`.
 */
export type ScanKind =
  | { kind: "quick" }
  | { kind: "full" }
  | { kind: "path"; path: string };

/** What a Defender scan came to. */
export type ScanOutcome = {
  label: string;
  /**
   * False when it was stopped or timed out.
   *
   * Load-bearing: a scan that did not finish and found nothing has not
   * established that there is nothing, and the panel must not let it read that
   * way.
   */
  completed: boolean;
  exit_code: number | null;
  seconds: number;
  /**
   * Detections Defender recorded that it did not have before this scan.
   *
   * Read from Defender's own records rather than parsed out of its console
   * output, because a filename containing a line break can write a convincing
   * "no threats found" line into that output.
   */
  found: Threat[];
  /** Set when the result is worth less than it appears. */
  caveat: string | null;
};

export type Threat = {
  name: string;
  severity: number | null;
  category: number | null;
  action: number | null;
  status: number | null;
  resources: string[];
  detected_at: string | null;
};

/**
 * The provenance engine's view of one executable.
 *
 * Every field is evidence rather than judgement, and `reasons` is the reasoning
 * written out — the interface never re-derives why something was ranked where
 * it was, it shows what the agent said.
 */
export type Signature =
  | { state: "valid"; signer: string; catalogue: string | null }
  | { state: "invalid"; signer: string | null; reason: string }
  | { state: "unsigned" }
  | { state: "unknown"; reason: string };

export type Anchor =
  | "run_key"
  | "run_once_key"
  | "startup_folder"
  | "service"
  | "scheduled_task";

export type PersistenceEntry = {
  name: string;
  anchor: Anchor;
  location: string;
  command: string;
  executable: string | null;
  /** What a launcher (cmd, MSBuild, rundll32) is told to run, when it is one. */
  payload: string | null;
  /** The launcher's name, e.g. "cmd.exe", when the entry runs through one. */
  host: string | null;
  /** A scheduled task marked hidden from Task Scheduler's list. */
  hidden: boolean;
  machine_wide: boolean;
};

/**
 * The behaviour watcher's view: startup entries that appeared while the agent
 * was running, in the shape unwanted software uses to run unseen.
 *
 * `concern` is the watcher's own claim. `notable` is unusual and worth a line;
 * `strong` is a shape with very few innocent explanations. Neither is a verdict,
 * and the interface must not render either as a red alarm by default.
 */
export type Concern = "notable" | "strong";

export type ObservationKind =
  | "process_start"
  | "scheduled_task"
  | "sign_in_entry"
  | "startup_folder"
  | "service";

export type Observation = {
  at: string;
  kind: ObservationKind;
  concern: Concern;
  summary: string;
  evidence: string[];
  subject: string;
  command: string;
  pid: number | null;
};

export type BehaviourReport = {
  observations: Observation[];
  watching: boolean;
  since: string | null;
};

export type Origin = {
  zone: string | { other: number };
  host_url: string | null;
  referrer_url: string | null;
};

export type Attention = "ordinary" | "notable" | "unusual";

export type Location =
  | "system"
  | "installed"
  | "shared"
  | "user_writable"
  | "elsewhere";

export type Finding = {
  path: string;
  name: string;
  bytes: number;
  signature: Signature;
  origin: Origin | null;
  origin_host: string | null;
  arrived_days_ago: number | null;
  persistence: PersistenceEntry[];
  location: Location;
  attention: Attention;
  reasons: string[];
};

export type ProvenanceReport = {
  findings: Finding[];
  examined: number;
  swept_files: number;
  unreadable: string[];
  swept: string[];
};

/**
 * YARA rule matching, which runs in the shell rather than the agent.
 *
 * `confidence` is the rule author's own claim, carried through from the rule's
 * metadata. `informational` is a statement of fact about the file and implies
 * no wrongdoing; the interface must not render it as an alarm.
 */
export type RuleConfidence = "informational" | "notable" | "strong";

export type RuleMatch = {
  rule: string;
  category: string;
  confidence: RuleConfidence;
  explains: string;
  bundled: boolean;
  evidence: string[];
};

export type FileMatches = {
  path: string;
  matches: RuleMatch[];
};

export type RuleReport = {
  matches: FileMatches[];
  files_scanned: number;
  skipped: string[];
  rules_loaded: number;
  user_rules_directory: string;
  user_rules_loaded: number;
  problems: string[];
};

/**
 * A VirusTotal lookup.
 *
 * `summary` is written by the agent-side code and is the sentence to show. The
 * interface must not compute its own reading of the counts: a handful of
 * detections out of seventy is the ordinary signature of a false positive, and
 * rendering "3 threats found!" from those numbers would be the exact dishonesty
 * this product exists to avoid.
 */
export type Standing = "clean" | "not_known" | "isolated" | "substantial";

export type Detection = {
  engine: string;
  verdict: string;
};

export type Verdict = {
  sha256: string;
  standing: Standing;
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected: number;
  engines: number;
  detections: Detection[];
  reputation: number | null;
  first_seen: string | null;
  last_analysed: string | null;
  common_name: string | null;
  permalink: string;
  summary: string;
};

/** Windows Defender Firewall, read through its own interface. */
export type FirewallProfile = "domain" | "private" | "public";
export type FirewallDefault = "allow" | "block" | "unknown";
export type RuleDirection = "in" | "out" | "unknown";

export type ProfileState = {
  profile: FirewallProfile;
  enabled: boolean;
  active: boolean;
  inbound_default: FirewallDefault;
  outbound_default: FirewallDefault;
};

export type FirewallRule = {
  name: string;
  description: string | null;
  application: string | null;
  service: string | null;
  direction: RuleDirection;
  action: FirewallDefault;
  enabled: boolean;
  grouping: string | null;
  profiles: FirewallProfile[];
  protocol: number | null;
  local_ports: string | null;
  remote_ports: string | null;
  remote_addresses: string | null;
  /** True when this product created it, and so may remove it. */
  ours: boolean;
};

export type FirewallReport = {
  profiles: ProfileState[];
  rules: FirewallRule[];
  concerns: string[];
  total_rules: number;
  enabled_rules: number;
  blocking_rules: number;
  our_rules: number;
};

export type ConnectionState =
  | "listening"
  | "established"
  | "transient"
  | "connectionless";

export type Connection = {
  protocol: string;
  state: ConnectionState;
  local_address: string;
  local_port: number;
  remote_address: string | null;
  remote_port: number | null;
  process_id: number;
  image_path: string | null;
  name: string | null;
  /**
   * What the file says it is, from its own version resource.
   *
   * A claim and not evidence: anybody can type "Google Chrome" into a file's
   * resources. It is here so a list of forty `svchost.exe` rows can be read at
   * all. The verified half is `signer`, and the two must never be shown as
   * equal weight.
   */
  description: string | null;
  /** Who the file says wrote it. Also unverified — compare against `signer`. */
  company: string | null;
  signer: string | null;
  /** null means the owning program could not be identified — not "unsigned". */
  unsigned: boolean | null;
  external: boolean;
};

export type ConnectionReport = {
  connections: Connection[];
  established: number;
  listening: number;
  external: number;
  programs: number;
  /** Sockets left from connections that already finished; no owner. */
  closing: number;
};

/** What an uninstaller left behind, and the shortcuts pointing at it. */
export type ShortcutPlace = "start_menu" | "desktop" | "taskbar";

export type Shortcut = {
  path: string;
  name: string;
  place: ShortcutPlace;
  target: string | null;
  broken: boolean;
  machine_wide: boolean;
  bytes: number;
};

export type Remnant = {
  path: string;
  bytes: number;
  kind: string;
  /** True when the size is a floor because counting hit its ceiling. */
  partial: boolean;
  files: number;
};

export type Remnants = {
  name: string;
  locations: Remnant[];
  shortcuts: Shortcut[];
  total_bytes: number;
  /** Paths the agent declined to look at, reported rather than dropped. */
  refused: string[];
};

/**
 * Browser extensions, and what each one is allowed to read.
 *
 * `notes` are the agent's sentences, not the interface's. An extension that
 * reads every page is stating a fact about its permissions, not an accusation:
 * ad blockers and password managers legitimately do exactly that.
 */
export type ExtensionSource = "store" | "sideloaded";

export type BrowserExtension = {
  browser: string;
  profile: string;
  id: string;
  name: string;
  version: string;
  description: string;
  permissions: string[];
  hosts: string[];
  source: ExtensionSource;
  reads_every_page: boolean;
  notes: string[];
  path: string;
  added_days_ago: number | null;
};

export type ExtensionReport = {
  extensions: BrowserExtension[];
  examined: string[];
  unreadable: string[];
};

/**
 * Defender's free hardening rules, and whether they are doing anything.
 *
 * `mode` is what Defender is set to do when the rule matches. Auditing writes
 * an event and stops nothing, so the interface must not render it as protection.
 */
export type HardeningMode =
  | "off"
  | "block"
  | "audit"
  | "warn"
  | { unknown: number };

export type HardeningRule = {
  id: string;
  name: string;
  explains: string;
  mode: HardeningMode;
  recommended: boolean;
};

export type FolderAccess =
  | "off"
  | "on"
  | "audit_only"
  | "block_disk_modification_only"
  | "audit_disk_modification_only"
  | "not_configured"
  | "unreadable";

export type SwitchState = "on" | "off" | "not_configured" | "unrecognised";

/**
 * Whether Windows turns a protection on by itself.
 *
 * The distinction the panel turns on. A protection that is off because that is
 * the default is a suggestion; one that is off against the default means
 * something changed it, which is a different sentence entirely.
 */
export type SwitchDefault = "on" | "off" | "varies";

export type HardeningSwitch = {
  id: string;
  name: string;
  explains: string;
  state: SwitchState | { unrecognised: number };
  default: SwitchDefault;
  /** How to turn it on. Nothing here changes it. */
  how: string;
};

export type HardeningReport = {
  rules: HardeningRule[];
  controlled_folder_access: FolderAccess | null;
  switches: HardeningSwitch[];
  unreadable: string[];
};

/**
 * Decoy files that exist only to be stolen.
 *
 * A canary read is the one signal in this product that is not circumstantial:
 * these files are put there by KAM Security, nothing on the machine uses them,
 * and no ordinary program has a reason to open one.
 */
export type CanaryKind = "file" | "registry_key";

export type Canary = {
  /** A file on disk, or a key in the registry. */
  kind: CanaryKind;
  id: string;
  name: string;
  path: string;
  bait: string;
  /** True when Windows is actually set to record reads of it. */
  armed: boolean;
  problem: string | null;
};

export type CanaryTrip = {
  at: string;
  path: string;
  process: string | null;
  process_id: string | null;
  user: string | null;
};

export type CanaryReport = {
  canaries: Canary[];
  trips: CanaryTrip[];
  /** Whether Windows is recording file access at all. Without it, inert. */
  auditing: boolean;
  problems: string[];
};
