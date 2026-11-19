import { count } from "./format";

/**
 * The download results nobody has looked at yet, in words.
 *
 * Said the same way wherever the count appears, and always as what Defender
 * said or as the plain fact that a check did not finish: never as a grade.
 */

/** "2 downloads Defender flagged and 1 check that did not finish". */
export function unseenSentence(flagged: number, unfinished: number): string | null {
  const parts: string[] = [];
  if (flagged > 0) {
    parts.push(`${count(flagged)} ${flagged === 1 ? "download" : "downloads"} Defender flagged`);
  }
  if (unfinished > 0) {
    parts.push(
      `${count(unfinished)} ${unfinished === 1 ? "check" : "checks"} that did not finish`,
    );
  }
  return parts.length > 0 ? parts.join(" and ") : null;
}

/** The same, short enough for the line under a name in the menu. */
export function unseenShort(flagged: number, unfinished: number): string | null {
  const parts: string[] = [];
  if (flagged > 0) parts.push(`${count(flagged)} flagged`);
  if (unfinished > 0) parts.push(`${count(unfinished)} not finished`);
  return parts.length > 0 ? `New: ${parts.join(", ")}` : null;
}
