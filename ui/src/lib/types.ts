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

export type DuplicateGroup = {
  bytes: number;
  wasted_bytes: number;
  paths: string[];
};

export type DuplicateSummary = {
  groups: number;
  wasted_bytes: number;
  examined: number;
  head_hashed: number;
  fully_hashed: number;
  elapsed_ms: number;
  truncated: boolean;
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

export type ApplicationReport = {
  apps: AppFootprint[];
  summary: FootprintSummary;
  orphans: Orphan[];
  orphan_summary: OrphanSummary;
  downloads: Download[];
  download_summary: DownloadSummary;
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
  machine_wide: boolean;
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
