import type { ReactNode } from "react";

/**
 * Section icons, one per module, drawn from the alternate marks.
 *
 * These are simplified rather than scaled down. The full marks carry detail —
 * a radar sweep, eight treemap blocks — that turns to mud below about 40px, and
 * the sidebar shows them at 18. Each keeps only the silhouette and the one
 * feature that identifies it.
 *
 * They stroke in `currentColor` so they take the navigation item's state with
 * it, rather than needing a second set for the active row.
 */

const SHIELD = "M12 2.6 L20 6 L20 12 C20 16.4 16.6 19.3 12 21 C7.4 19.3 4 16.4 4 12 L4 6 Z";

function Frame({ children }: { children: ReactNode }) {
  return (
    <svg
      viewBox="0 0 24 24"
      className="section-icon"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.6"
      strokeLinejoin="round"
      strokeLinecap="round"
      aria-hidden="true"
    >
      {children}
    </svg>
  );
}

/** The main mark: broken ring around the subdivided triangle. */
export function OverviewIcon() {
  return (
    <Frame>
      <path d="M3.6 14.6 A9.5 9.5 0 1 1 20.4 14.6" />
      <path d="M5.2 17.6 A9.5 9.5 0 0 0 18.8 17.6" />
      <path d="M12 6.4 L16.4 14.4 L7.6 14.4 Z" />
      <path d="M9.8 10.4 L14.2 10.4 L12 14.4 Z" fill="currentColor" stroke="none" />
    </Frame>
  );
}

/** Treemap shield — the disk map, so: storage. */
export function StorageIcon() {
  return (
    <Frame>
      <path d={SHIELD} />
      <path d="M4 10.2 H20" />
      <path d="M11.4 6 V10.2" />
      <path d="M4.5 14.4 H19.5" />
      <path d="M9 10.2 V14.4" />
    </Frame>
  );
}

/**
 * Stacked plates — the Strata mark's idea, turned into rows.
 *
 * Chevrons read as "collapse" in a sidebar, which is the wrong verb for a list
 * of installed programs, so the layers are squared off into rows instead.
 */
export function ApplicationsIcon() {
  return (
    <Frame>
      <rect x="3.5" y="4.5" width="17" height="4.2" rx="1.2" />
      <rect x="3.5" y="9.9" width="17" height="4.2" rx="1.2" />
      <rect x="3.5" y="15.3" width="17" height="4.2" rx="1.2" />
      <path d="M6.4 6.6 h0.01" />
      <path d="M6.4 12 h0.01" />
      <path d="M6.4 17.4 h0.01" />
    </Frame>
  );
}

/**
 * A container with a lid, and an arrow going in.
 *
 * Deliberately not a bin: nothing here is thrown away, and an icon that says
 * "delete" would misdescribe the one screen in the application where being
 * misunderstood costs somebody their data.
 */
export function CleanupIcon() {
  return (
    <Frame>
      <path d="M4.2 8.4 h15.6 v10.2 a1.6 1.6 0 0 1 -1.6 1.6 h-12.4 a1.6 1.6 0 0 1 -1.6 -1.6 Z" />
      <path d="M12 3.4 v3.4" />
      <path d="M9.6 5.4 L12 3.2 L14.4 5.4" />
    </Frame>
  );
}

/** Aegis sweep — a radar arc and its blip, so: scanning. */
export function ScannerIcon() {
  return (
    <Frame>
      <path d={SHIELD} />
      <circle cx="12" cy="12" r="4.4" />
      <path d="M12 12 L15.5 8.9" />
      <circle cx="16.2" cy="8.2" r="1.2" fill="currentColor" stroke="none" />
    </Frame>
  );
}

/** Strata — layered barriers, so: firewall. */
export function FirewallIcon() {
  return (
    <Frame>
      <path d="M4 7.5 L12 12 L20 7.5" />
      <path d="M6 12.4 L12 15.8 L18 12.4" />
      <path d="M8 17 L12 19.3 L16 17" />
    </Frame>
  );
}

/** Sentinel monogram — the K, keeping watch: the record of what happened. */
export function ActivityIcon() {
  return (
    <Frame>
      <path d={SHIELD} />
      <path d="M10 7.6 V16.4" />
      <path d="M10.4 12 L14.4 7.9" />
      <path d="M10.4 12 L14.4 16.1" />
    </Frame>
  );
}
