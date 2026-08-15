const UNITS = ["B", "KB", "MB", "GB", "TB", "PB"];

/** Sizes as a person would say them. Matches the agent's own formatting. */
export function bytes(value: number): string {
  if (!Number.isFinite(value) || value <= 0) return "0 B";
  let size = value;
  let unit = 0;
  while (size >= 1024 && unit < UNITS.length - 1) {
    size /= 1024;
    unit += 1;
  }
  if (unit === 0) return `${Math.round(size)} B`;
  return `${size.toFixed(size >= 100 ? 0 : 1)} ${UNITS[unit]}`;
}

/** Split into number and unit so a card can size the two differently. */
export function bytesParts(value: number): [string, string] {
  const whole = bytes(value);
  const cut = whole.lastIndexOf(" ");
  return [whole.slice(0, cut), whole.slice(cut + 1)];
}

export function count(value: number): string {
  return value.toLocaleString();
}

export function duration(ms: number): string {
  if (ms < 1000) return `${ms} ms`;
  const seconds = ms / 1000;
  if (seconds < 60) return `${seconds.toFixed(1)} s`;
  const minutes = Math.floor(seconds / 60);
  return `${minutes}m ${Math.round(seconds % 60)}s`;
}

export function percent(part: number, whole: number): number {
  if (whole <= 0) return 0;
  return Math.min(100, Math.max(0, (part / whole) * 100));
}

/** The agent stores ISO 8601 in UTC; show it in local time. */
export function timestamp(iso: string): string {
  const parsed = new Date(iso);
  if (Number.isNaN(parsed.getTime())) return iso;
  return parsed.toLocaleString(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

export function relative(iso: string): string {
  const parsed = new Date(iso);
  if (Number.isNaN(parsed.getTime())) return "";
  const seconds = (Date.now() - parsed.getTime()) / 1000;
  if (seconds < 60) return "just now";
  if (seconds < 3600) return `${Math.floor(seconds / 60)} min ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} h ago`;
  return `${Math.floor(seconds / 86400)} d ago`;
}
