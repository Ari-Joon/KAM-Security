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
  /** Scanning of downloads and attachments, a separate switch. */
  download_scanning: boolean | null;
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

/** What happened to one thing between two sweeps. */
export type ChangeKind = "appeared" | "altered" | "vanished" | "recurring";

/** One difference between the machine now and the machine last time. */
export type Difference = {
  /**
   * When it was *noticed*, which is not when it happened.
   *
   * All this software can say is that a thing was there by this sweep and not
   * by the last one. Presenting a sweep time as the moment something was
   * installed would invent a precision nobody has.
   */
  at: string;
  change: ChangeKind;
  /**
   * "service" | "run_key" | "run_once_key" | "startup_item" |
   * "scheduled_task" | "administrator"
   *
   * Stable strings, not display labels: they are stored, so renaming one would
   * make every machine's history read as new at once.
   */
  kind: string;
  /** Where it lives, lowercased. Separates one account's entries from another's. */
  scope: string;
  name: string;
  /** What it actually runs. */
  detail: string;
  first_seen: string;
  last_seen: string;
  times_seen: number;
  /**
   * Who vouches for the file this runs: "signed by X", "not signed", or
   * "could not be checked".
   *
   * The last two are both *not vouched for* and are deliberately different
   * claims: one is a fact about the file, the other a limit of what could be
   * seen. Do not collapse them.
   */
  trust: string;
  /** What it used to be, set only when the trust has changed. */
  was_trusted: string | null;
};

/** What one sweep found, and what it could not look at. */
export type Sweep = {
  /** This sweep's differences, most notable first. */
  differences: Difference[];
  /**
   * Sources that could not be read, in plain words.
   *
   * Must be shown. A source that was skipped and not mentioned is a lie by
   * omission in a product whose whole claim is that it says what it did.
   */
  unreadable: string[];
  /** True on the very first sweep, when there was nothing to compare against. */
  baseline: boolean;
  /** The real date of the previous sweep. Say this, never "since last week". */
  previous_at: string | null;
  at: string;
  /** Every difference from the last twelve weeks, newest first. */
  history: Difference[];
  /**
   * When a sweep compared the machine with an earlier one, over the same
   * twelve weeks, newest first. The baseline sweep is not among them.
   *
   * What tells a week in which nothing changed from a week nobody looked at.
   * Without it both are the same empty bar.
   */
  swept: string[];
  /**
   * Things already present when the baseline was first taken that nothing
   * vouches for. Only ever populated on the first sweep.
   *
   * Not findings. A baseline learns whatever is on the machine at the moment
   * it is taken, so anything unwanted that was already there becomes part of
   * the furniture and never reports as having appeared. That cannot be fixed
   * in general; it can be said, and saying it is the difference between a
   * limitation and a lie.
   */
  unvouched: Difference[];
};

export type Threat = {
  name: string;
  severity: number | null;
  category: number | null;
  action: number | null;
  status: number | null;
  resources: string[];
  detected_at: string | null;
  /** What Defender did, in words, from the agent. */
  status_text: string;
  /** Defender's action failed or none was taken: it may still be here. */
  needs_attention: boolean;
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
  /**
   * Why what this runs could not be told, when the agent knows. An entry
   * carrying this has no file to judge, so none reaches a finding today.
   */
  missing: string | null;
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
  /** Files the rules were run over to the end. */
  files_scanned: number;
  /** Files passed over for being too large, each with its reason. */
  skipped: string[];
  /** Files that could not be read or whose matching did not finish. Not in `files_scanned`. */
  failed: string[];
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
export type Standing =
  | "clean"
  | "not_known"
  /** VirusTotal has the file but no engine has reported on it yet. Neither clean nor flagged. */
  | "not_analysed"
  | "isolated"
  | "substantial";

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
  /** null when Windows would not say. Never shown as "off". */
  enabled: boolean | null;
  /** Whether this profile is in force now; null when that could not be read. */
  active: boolean | null;
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
  /**
   * What could not be read, in plain words. When this is not empty the counts
   * above are of what was read, not of everything there is.
   */
  unread: string[];
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
  /** True when the program holding this socket is part of KAM Security. */
  ours: boolean;
};

export type ConnectionReport = {
  connections: Connection[];
  established: number;
  listening: number;
  external: number;
  programs: number;
  /** Sockets left from connections that already finished; no owner. */
  closing: number;
  /** Connection tables that could not be read, in plain words. */
  unread: string[];
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

/**
 * Whether quarantine would take a leftover, from the same fence the agent
 * applies when it is asked to. Absent means it was never asked, which reads as
 * "no" rather than "yes".
 */
export type QuarantineAnswer = {
  quarantinable?: boolean;
  /** The fence's own reason when it would not. */
  quarantine_refusal?: string | null;
};

export type Remnant = QuarantineAnswer & {
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
  shortcuts: (Shortcut & QuarantineAnswer)[];
  total_bytes: number;
  /**
   * Paths the agent declined to look at, reported rather than dropped: outside
   * the folders it will look in, or there but impossible to resolve.
   */
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

export type SwitchState = "on" | "off" | "audit" | "not_configured" | "unrecognised";

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
  /** Set by an organisation's policy, so a change made here would not stick. */
  managed_by_policy: boolean;
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
  /**
   * Why the Security log, where reads are recorded, could not be read or not
   * to the end. When set, an empty `trips` says nothing about whether a decoy
   * was read. Absent from agents older than this field.
   */
  trips_unread?: string | null;
  /** Whether Windows is recording file access at all. Without it, inert. */
  auditing: boolean;
  problems: string[];
  /**
   * How many decoys there would be if every one were planted. Absent from
   * agents older than this field, where "some are missing" cannot be told.
   */
  expected?: number;
};

/** A published release, as GitHub reports it. See ui/src-tauri/src/update.rs. */
export type Release = {
  version: string;
  name: string;
  published_at: string;
  /** Plain text. Never rendered as HTML: it came from the network. */
  notes: string;
  /** This repository's release page, already checked by the shell. */
  url: string;
};

/** Whether a newer release exists, or why that could not be established. */
export type UpdateCheck = {
  current: string;
  latest: Release | null;
  /** True only when the check completed and the published version is higher. */
  newer: boolean;
  /**
   * True only when the check completed and the running version is higher: a
   * build that has not been released yet. Not newer is not the same as level.
   */
  ahead: boolean;
  /** Why the answer is incomplete. Null means the answer is the whole answer. */
  problem: string | null;
};

/** Whether KAM Security starts when this person signs in. See startup.rs. */
export type StartState = {
  enabled: boolean;
  /** An entry named "KAM Security" exists but starts something else. */
  points_elsewhere: boolean;
  /** This launch turned it on by default, so say so once. */
  turned_on_now: boolean;
};

// ---------- Downloads -------------------------------------------------------

/**
 * Defender's answer to a report-only check of one file. "gone_before_check"
 * is not an answer from Defender at all: the file arrived and was gone before
 * it could be asked, and `threats` then holds what Defender's own history has
 * for that path, if anything.
 */
export type Answer = "nothing_found" | "flagged" | "not_finished" | "gone_before_check";

/** Where a file has got to on its way to being checked automatically. */
export type InFlight =
  | { state: "arriving" }
  | { state: "waiting"; ahead: number }
  | { state: "checking"; job: string; seconds: number };

/** One threat Defender flagged, with the resources it named. */
export type FlaggedThreat = {
  name: string;
  resources: string[];
};

/**
 * What one of Defender's names means, written by the scanner rather than
 * here, so the window never invents an explanation.
 */
export type ThreatNote = {
  name: string;
  /** The part before the colon, as Defender gives it: HackTool, PUA, Trojan. */
  category: string | null;
  meaning: string;
  /** Unwanted or dual-use rather than malware: the person's call, in Windows Security. */
  your_decision: boolean;
  /** The name ends in !ml: Defender's machine-learning model flagged it. */
  machine_learning: boolean;
};

export type FileScan = {
  answer: Answer;
  /** False when Defender did not finish. Never shown as clean. */
  completed: boolean;
  exit_code: number | null;
  seconds: number;
  threats: FlaggedThreat[];
  /** False when Defender's list did not add up to its own counts. */
  listing_consistent: boolean;
  caveat: string | null;
  definitions: string | null;
  notes: ThreatNote[];
};

/** Something done to a download, in the agent's words. */
export type DownloadAction = {
  at: string;
  what: string;
  undo: string | null;
};

export type MemberStatus =
  | { state: "nothing_found" }
  | { state: "flagged"; threats: string[] }
  | { state: "left_out"; reason: string }
  | { state: "folder" };

export type Member = {
  name: string;
  bytes: number;
  packed: number;
  status: MemberStatus;
};

export type DissectionTotals = {
  files: number;
  bytes: number;
  flagged: number;
  flagged_bytes: number;
  left_out: number;
  left_out_bytes: number;
  clean: number;
  clean_bytes: number;
};

/** An archive taken apart: every member with Defender's answer. */
export type Dissection = {
  archive: string;
  sha256: string;
  scan: FileScan;
  members: Member[];
  members_omitted: number;
  totals: DissectionTotals;
  whole_archive: string[];
  unmatched: string[];
  offered: boolean;
  not_offered: string | null;
  original: { quarantined: string | null; refused: string | null };
};

/**
 * What a history row says about an archive that was taken apart: the counts,
 * without the list of members, which stays in the store.
 */
export type DissectionSummary = {
  totals: DissectionTotals;
  offered: boolean;
  not_offered: string | null;
  original: { quarantined: string | null; refused: string | null };
};

export type RemovedFile = {
  name: string;
  /** The detection that names it, when Defender's history has one. */
  threat: string | null;
  /** What that detection's name means, from the scanner. */
  note: ThreatNote | null;
};

export type Extraction = {
  destination: string;
  files: number;
  bytes: number;
  left_out: number;
  left_out_bytes: number;
  failed: string[];
  /** Written, then gone or not whole when looked at again. Never counted. */
  removed: RemovedFile[];
  /**
   * Written and counted, but without the mark Windows puts on downloaded
   * files, which the archive carried: "name: why".
   */
  unmarked: string[];
};

/** One row of the download history. */
export type DownloadRecord = {
  path: string;
  name: string;
  bytes: number;
  sha256: string;
  arrived_at: string | null;
  origin: Origin | null;
  signature: Signature | null;
  scan: FileScan;
  checked_at: string;
  actions: DownloadAction[];
  dissection: DissectionSummary | null;
  first_check: boolean;
};

export type PageRecord = DownloadRecord & {
  /** Whether the file is still where it was checked. */
  present: boolean;
  archive: "zip" | "other" | null;
  /** The quarantine item it can be put back from, when it is being held. */
  held: string | null;
  /** A file is at that path, and it is not the one this row is about. */
  replaced: boolean;
  /** In the Downloads folder, the only place a download is quarantined from. */
  in_downloads: boolean;
  /** For a zip Defender found nothing in: what its own list says. */
  inside: Inside | null;
};

/**
 * What a zip's own list of files says about how much of it Defender could
 * look inside. Defender reports nothing about a file it could not open.
 */
export type Inside =
  | { state: "listed"; files: number; locked: number }
  | { state: "unread"; reason: string };

export type LooseFile = {
  path: string;
  name: string;
  bytes: number;
  arrived_at: string | null;
  archive: "zip" | "other" | null;
  changed_since_checked: boolean;
  /** Set when it is on its way to being checked, and not simply unchecked. */
  in_flight: InFlight | null;
};

export type WatchStatus =
  | { state: "starting" }
  | { state: "watching"; folder: string }
  | { state: "not_watching"; reason: string };

export type MenuState = {
  enabled: boolean;
  points_elsewhere: boolean;
};

export type DownloadsPage = {
  folder: string | null;
  folder_error: string | null;
  watch: WatchStatus;
  records: PageRecord[];
  /** How many checks are on record in all; can be more than `records` holds. */
  on_record: number;
  history_error: string | null;
  unchecked: LooseFile[];
  failures: { path: string; message: string }[];
  /** The archive taken apart and still open, to find again after leaving. */
  open: { token: string; archive: string } | null;
  /** Why it could not be told which quarantined downloads can be put back. */
  quarantine_error: string | null;
  /** How many files asked about from Explorer are still waiting their turn. */
  waiting: number;
  menu: MenuState;
  protection: boolean | null;
  notifications: string | null;
};

export type DissectionView = {
  token: string;
  dissection: Dissection;
  /** The folder the files would go into, as it stands now. */
  destination: string;
  /** Why extracted files will lack the download mark, when it could not be read. */
  mark_problem: string | null;
  /** Why what the archive holds is not on its row, when recording it failed. */
  record_problem: string | null;
};

/** What came of asking for an archive to be taken apart. */
export type Dissected = {
  /** Absent when it was stopped first. */
  view: DissectionView | null;
  /** What had happened to the original by then. */
  original: { quarantined: string | null; refused: string | null };
};

/** A file somebody asked about from Explorer or a notification. */
export type Launch = {
  action: "check" | "extract" | "show";
  path: string;
};
