import { useEffect, useLayoutEffect, useRef, useState } from "react";
import { api, reason } from "../lib/api";
import * as fmt from "../lib/format";
import { squarify } from "../lib/treemap";
import { dayOf, growthTree, keptAt, type GrowthNode } from "../lib/growth";
import type { Change, Differences, Growth, ScanMethod, SummaryKept } from "../lib/types";
import { whenMeasured } from "./MeasuredAt";
import { GridLegend } from "./StateGrid";

/** One colour for every folder that grew: the area is the figure. */
const GREW = "#5a6fae";

/** How many of the folders that shrank are listed before "Show all". */
const SHRANK_SHOWN = 15;

const LABEL_MIN_WIDTH = 56;
const LABEL_MIN_HEIGHT = 26;

const READ: Record<ScanMethod, string> = {
  master_file_table: "read from the file table",
  directory_walk: "read by walking its folders",
};

const LONG_PATHS = { overflowWrap: "anywhere" } as const;

/** A size and whether it is the least it can be. */
function by(change: Change): string {
  return `${change.exact ? "" : "at least "}${fmt.bytes(change.by)}`;
}

/** What a folder held at one of the two scans, in words. */
function held(bytes: number | null, floor: number): string {
  return bytes === null ? `under ${fmt.bytes(floor)}` : fmt.bytes(bytes);
}

/**
 * What grew, drawn so that each rectangle's area is the bytes that folder
 * grew by: a real magnitude, which is the only thing area is used for. A
 * folder that shrank has no area to draw, and is listed instead.
 */
function GrowthMap({
  nodes,
  onOpen,
}: {
  nodes: GrowthNode[];
  onOpen: (node: GrowthNode) => void;
}) {
  const container = useRef<HTMLDivElement>(null);
  const [size, setSize] = useState({ width: 0, height: 0 });

  // Measured at once and then observed, as the drive's own map is.
  useLayoutEffect(() => {
    const element = container.current;
    if (!element) return;
    const measure = (width: number, height: number) =>
      setSize((previous) =>
        previous.width === width && previous.height === height ? previous : { width, height },
      );
    const rect = element.getBoundingClientRect();
    measure(rect.width, rect.height);
    const observer = new ResizeObserver(([entry]) => {
      measure(entry.contentRect.width, entry.contentRect.height);
    });
    observer.observe(element);
    return () => observer.disconnect();
  }, []);

  const cells = squarify(
    nodes.map((node) => ({ bytes: node.change.by, node })),
    size.width,
    size.height,
  );

  return (
    <>
      <div className="treemap" ref={container}>
        {cells.map((cell) => {
          const node = cell.item.node;
          const opens = node.children.length > 0;
          const showLabel = cell.width >= LABEL_MIN_WIDTH && cell.height >= LABEL_MIN_HEIGHT;
          return (
            <div
              key={node.change.path}
              className={"treemap-cell" + (opens ? " drillable" : "")}
              style={{
                left: cell.x,
                top: cell.y,
                width: Math.max(0, cell.width - 2),
                height: Math.max(0, cell.height - 2),
                background: GREW,
                outlineOffset: -2,
              }}
              {...(opens
                ? {
                    role: "button",
                    tabIndex: 0,
                    "aria-label": `${node.name} grew by ${by(node.change)}. Open to see which folders inside it grew.`,
                    onKeyDown: (event: React.KeyboardEvent<HTMLDivElement>) => {
                      if (event.key === "Enter" || event.key === " ") {
                        event.preventDefault();
                        onOpen(node);
                      }
                    },
                  }
                : {})}
              onClick={() => opens && onOpen(node)}
              title={`${node.change.path}\ngrew by ${by(node.change)}`}
            >
              {showLabel && (
                <>
                  <span className="treemap-name">{node.name}</span>
                  <span className="treemap-size">{by(node.change)}</span>
                </>
              )}
            </div>
          );
        })}
      </div>
      <GridLegend
        entries={[
          [
            GREW,
            "A folder that grew. Its area is how much it grew by. One with folders inside it that grew opens to show them.",
          ],
        ]}
      />
    </>
  );
}

function Compared({
  differences,
  since,
}: {
  differences: Differences;
  since: string;
}) {
  const [trail, setTrail] = useState<GrowthNode[]>([]);
  const [allShrank, setAllShrank] = useState(false);
  const tree = growthTree(differences.grew);
  const level = trail.length > 0 ? trail[trail.length - 1].children : tree;
  const change = differences.total_change;
  const floor = differences.floor;
  const shrank = allShrank ? differences.shrank : differences.shrank.slice(0, SHRANK_SHOWN);

  return (
    <>
      <p className="stat-value">
        Since {since}:{" "}
        {change === 0
          ? "the same total"
          : `${fmt.bytes(Math.abs(change))} ${change > 0 ? "more" : "less"}`}
      </p>
      <p className="muted">
        The total is what the drive's files add up to, measured the same way both
        times. Folders of {fmt.bytes(floor)} or more are compared: a folder that
        was under that at one of the two scans is said to have been, and not to
        be new or gone.
      </p>
      {differences.unplaced > 0 && (
        <p className="muted">
          {fmt.count(differences.unplaced)}{" "}
          {differences.unplaced === 1 ? "folder" : "folders"} of that size sat too many
          folders deep to be named, and {differences.unplaced === 1 ? "is" : "are"} not
          compared.
        </p>
      )}

      <p className="growth-head">What grew</p>
      {tree.length === 0 ? (
        <p className="muted">No folder of {fmt.bytes(floor)} or more grew.</p>
      ) : (
        <>
          <nav className="crumbs">
            <button className="crumb" disabled={trail.length === 0} onClick={() => setTrail([])}>
              Everywhere
            </button>
            {trail.map((node, index) => (
              <button
                key={node.change.path}
                className="crumb"
                disabled={index === trail.length - 1}
                onClick={() => setTrail(trail.slice(0, index + 1))}
              >
                {node.name}
              </button>
            ))}
          </nav>
          <GrowthMap nodes={level} onOpen={(node) => setTrail([...trail, node])} />
          <ul className="files growth-list" style={LONG_PATHS}>
            {level.map((node) => (
              <li key={node.change.path} title={node.change.path}>
                <strong>{node.change.path}</strong>: {held(node.change.before, floor)} then,{" "}
                {held(node.change.after, floor)} now, so {by(node.change)} more.
              </li>
            ))}
          </ul>
          {differences.grew_left_out > 0 && (
            <p className="muted">
              {fmt.count(differences.grew_left_out)} smaller{" "}
              {differences.grew_left_out === 1 ? "growth is" : "growths are"} not listed,
              so that the answer fits in one reply.
            </p>
          )}
        </>
      )}

      <p className="growth-head">What shrank</p>
      {differences.shrank.length === 0 ? (
        <p className="muted">No folder of {fmt.bytes(floor)} or more shrank.</p>
      ) : (
        <>
          <ul className="files growth-list" style={LONG_PATHS}>
            {shrank.map((item) => (
              <li key={item.path} title={item.path}>
                <strong>{item.path}</strong>: {held(item.before, floor)} then,{" "}
                {held(item.after, floor)} now, so {by(item)} less.
              </li>
            ))}
          </ul>
          {differences.shrank.length > SHRANK_SHOWN && (
            <button className="link-button" onClick={() => setAllShrank(!allShrank)}>
              {allShrank ? "Show fewer" : `Show all ${fmt.count(differences.shrank.length)}`}
            </button>
          )}
          {differences.shrank_left_out > 0 && (
            <p className="muted">
              {fmt.count(differences.shrank_left_out)} smaller{" "}
              {differences.shrank_left_out === 1 ? "one is" : "ones are"} not listed, so
              that the answer fits in one reply.
            </p>
          )}
        </>
      )}
    </>
  );
}

/**
 * What grew since an earlier scan of the same drive.
 *
 * The service keeps a small summary of each scan of a whole drive for the
 * person who asked, and compares two of them. Which earlier one is the
 * person's choice; the one kept just before this scan to begin with.
 */
export default function GrowthPanel({ drive, kept }: { drive: string; kept: SummaryKept }) {
  const [growth, setGrowth] = useState<Growth | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [earlier, setEarlier] = useState<number | null>(null);
  const asked = useRef(0);
  const later = kept.kind === "kept" ? kept.id : null;

  useEffect(() => {
    if (later === null) return;
    const number = ++asked.current;
    setError(null);
    api
      .growth(drive, later, earlier)
      .then((answer) => {
        if (asked.current === number) setGrowth(answer);
      })
      .catch((cause) => {
        if (asked.current === number) {
          setGrowth(null);
          setError(reason(cause));
        }
      });
  }, [drive, later, earlier]);

  if (kept.kind === "not_kept") {
    return (
      <div className="notice notice-warn">
        No summary of this scan could be kept ({kept.why}). It cannot be compared with
        an earlier scan, and the next scan will not be compared with it.
      </div>
    );
  }
  if (error) {
    return (
      <div className="notice notice-warn" style={LONG_PATHS}>
        What grew since an earlier scan could not be worked out: {error.replace(/\.$/, "")}.
      </div>
    );
  }
  if (!growth) {
    return (
      <p className="muted" role="status">
        Comparing with your earlier scans of {drive}…
      </p>
    );
  }

  const comparison = growth.comparison;
  const before = growth.earlier;
  // Every summary kept before this one can be chosen, comparable or not: the
  // ones that cannot be compared say why when chosen.
  const choices = growth.summaries.filter((summary) => summary.id < (growth.later?.id ?? 0));

  return (
    <>
      {choices.length > 0 && (
        <div className="scan-bar">
          <label className="muted" htmlFor="growth-earlier">
            Compared with the scan of
          </label>
          <select
            id="growth-earlier"
            value={before?.id ?? ""}
            onChange={(event) => setEarlier(Number(event.target.value))}
          >
            {choices.map((summary) => (
              <option key={summary.id} value={summary.id}>
                {whenMeasured(keptAt(summary))}, {READ[summary.method]},{" "}
                {fmt.bytes(summary.total_bytes)}
              </option>
            ))}
          </select>
        </div>
      )}

      {(comparison.kind === "nothing_kept" || comparison.kind === "nothing_earlier") && (
        <p className="muted">
          Nothing to compare with yet: this is the first scan of {drive} kept for you.
          The next scan will be compared with this one.
        </p>
      )}

      {comparison.kind === "not_comparable" && (
        <div className="notice notice-warn">{comparison.why}</div>
      )}

      {comparison.kind === "compared" && before && (
        <Compared
          // A different pair is a different picture: start it at the top.
          key={`${before.id}-${growth.later?.id ?? 0}`}
          differences={comparison}
          since={dayOf(keptAt(before)) === "today" ? whenMeasured(keptAt(before)) : dayOf(keptAt(before))}
        />
      )}
      {comparison.kind === "compared" && before && (
        <p className="muted">
          Both scans were {READ[before.method]}. The earlier one is from{" "}
          {whenMeasured(keptAt(before))}.
        </p>
      )}
    </>
  );
}
