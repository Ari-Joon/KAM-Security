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
