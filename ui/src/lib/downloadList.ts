import type { DownloadsPage, LooseFile, PageRecord } from "./types";

/**
 * Finding things in the list of downloads: search, filters and sorting.
 *
 * All of it works over the rows the page has been given, and nothing here
 * asks for more. When the page holds fewer rows than are on record it says
 * so, and that a search covers only what is shown.
 *
 * The filters sort rows by facts already on them and add no judgement:
 * "flagged" is Defender's word, and which results count as flagged or
 * unfinished is decided once, by the scanner, for the page and the count in
 * the menu alike (`counted_as`).
 */

/** One line of the list: a check on record, or a file with none. */
export type Row =
  | { kind: "record"; at: string; record: PageRecord }
  | { kind: "loose"; at: string; file: LooseFile };

/** What a check came to, for the rows where that needs a look. */
export type Result = "flagged" | "unfinished" | "unchecked";

/** Whether the file a row is about is still where it was. */
export type Place = "here" | "gone";

export type Sort = "arrival" | "size" | "name";

/** What somebody has asked to see. Nothing chosen means everything. */
export type Finding = {
  /** Part of a file name, in any case. */
  query: string;
  /** Rows with any of these results. */
  results: Result[];
  /** Rows in any of these places. */
  places: Place[];
  sort: Sort;
};

export const EVERYTHING: Finding = { query: "", results: [], places: [], sort: "arrival" };

/** Whether anything narrows the list. The order alone does not. */
export function narrowed(finding: Finding): boolean {
  return (
    finding.query.trim() !== "" || finding.results.length > 0 || finding.places.length > 0
  );
}

/** Every row the page has, in no particular order. */
export function rowsOf(page: DownloadsPage): Row[] {
  return [
    ...page.records.map(
      (record): Row => ({ kind: "record", at: record.arrived_at ?? record.checked_at, record }),
    ),
    ...page.unchecked.map((file): Row => ({ kind: "loose", at: file.arrived_at ?? "", file })),
  ];
}

export function nameOf(row: Row): string {
  return row.kind === "record" ? row.record.name : row.file.name;
}

function bytesOf(row: Row): number {
  return row.kind === "record" ? row.record.bytes : row.file.bytes;
}

/** The result a row is filed under, when it is one of the three. */
export function resultOf(row: Row): Result | null {
  return row.kind === "loose" ? "unchecked" : row.record.counted_as;
}

/**
 * A file with no check on record is in Downloads now, which is why it is
 * listed. A checked one is here while it is still the file that was checked,
 * and gone once it has been moved, deleted, quarantined or replaced.
 */
export function placeOf(row: Row): Place {
  return row.kind === "loose" || row.record.present ? "here" : "gone";
}

/** How many of `rows` each filter would show, for the number on its button. */
export function tally(rows: Row[]): Record<Result | Place, number> {
  const counts = { flagged: 0, unfinished: 0, unchecked: 0, here: 0, gone: 0 };
  for (const row of rows) {
    const result = resultOf(row);
    if (result) counts[result] += 1;
    counts[placeOf(row)] += 1;
  }
  return counts;
}

/** Newest arrival first, which is the order the list has always had. */
function byArrival(a: Row, b: Row): number {
  return b.at.localeCompare(a.at);
}

/**
 * The rows that match, in the order asked for.
 *
 * A row has to match the search, one of the results chosen (if any are) and
 * one of the places chosen (if any are). Rows that tie on size or name keep
 * the newest first.
 */
export function find(rows: Row[], finding: Finding): Row[] {
  const query = finding.query.trim().toLowerCase();
  const matching = rows.filter((row) => {
    if (query !== "" && !nameOf(row).toLowerCase().includes(query)) return false;
    if (finding.results.length > 0) {
      const result = resultOf(row);
      if (result === null || !finding.results.includes(result)) return false;
    }
    return finding.places.length === 0 || finding.places.includes(placeOf(row));
  });
  switch (finding.sort) {
    case "arrival":
      return matching.sort(byArrival);
    case "size":
      return matching.sort((a, b) => bytesOf(b) - bytesOf(a) || byArrival(a, b));
    case "name":
      return matching.sort(
        (a, b) =>
          nameOf(a).localeCompare(nameOf(b), undefined, { sensitivity: "base", numeric: true }) ||
          byArrival(a, b),
      );
  }
}
