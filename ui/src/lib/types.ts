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
