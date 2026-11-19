import type { Change, SummaryHeader } from "./types";

/**
 * A folder that grew, with the folders inside it that grew too.
 *
 * Each summary lists every folder over its floor, and a folder holds at
 * least as much as anything inside it, so a flat list of what grew can be
 * opened one level at a time: each folder goes under the nearest folder
 * above it that also grew.
 */
export type GrowthNode = { change: Change; name: string; children: GrowthNode[] };

function lastPart(path: string): string {
  const cut = path.lastIndexOf("\\");
  return cut >= 0 ? path.slice(cut + 1) : path;
}

/** What grew, as a tree, each level largest growth first. */
export function growthTree(grew: Change[]): GrowthNode[] {
  const nodes: GrowthNode[] = grew.map((change) => ({
    change,
    name: lastPart(change.path),
    children: [],
  }));
  const byPath = new Map(nodes.map((node) => [node.change.path.toLowerCase(), node]));
  const top: GrowthNode[] = [];
  for (const node of nodes) {
    let parent: GrowthNode | undefined;
    let path = node.change.path.toLowerCase();
    // Up through the folders above it, stopping before the drive itself,
    // whose growth is the total.
    for (let cut = path.lastIndexOf("\\"); cut > 2; cut = path.lastIndexOf("\\")) {
      path = path.slice(0, cut);
      parent = byPath.get(path);
      if (parent) break;
    }
    (parent ? parent.children : top).push(node);
  }
  // The list arrives largest first, and each level keeps that order.
  return top;
}

/** When a summary was kept, by the clock of this window's computer. */
export function keptAt(summary: SummaryHeader): number {
  return new Date(summary.taken_at).getTime();
}

/**
 * A day, the way a person names one in a sentence: "23 September", with the
 * year when it is not this year, and "today" for today.
 */
export function dayOf(at: number): string {
  const day = new Date(at);
  const now = new Date();
  if (
    day.getFullYear() === now.getFullYear() &&
    day.getMonth() === now.getMonth() &&
    day.getDate() === now.getDate()
  ) {
    return "today";
  }
  return day.toLocaleDateString(
    undefined,
    day.getFullYear() === now.getFullYear()
      ? { day: "numeric", month: "long" }
      : { day: "numeric", month: "long", year: "numeric" },
  );
}
