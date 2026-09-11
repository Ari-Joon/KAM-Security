import { useLayoutEffect, useRef, useState } from "react";
import { squarify } from "../lib/treemap";
import * as fmt from "../lib/format";

/**
 * Where the reclaimable space actually is, drawn to scale.
 *
 * # Why this is a treemap and the Scanner's grid is not
 *
 * The tiles in the Scanner grid are all the same size, because the things it
 * shows have no magnitude and sizing them would invent one. Here the opposite
 * holds: every block is a number of bytes, area is that number, and the whole
 * point is that a person can see a forty-gigabyte cache dwarf thirty leftover
 * folders without reading a single figure. A list cannot do that — it gives the
 * forty-gigabyte item and the four-megabyte item the same row, and sorting only
 * tells you the order, never the ratio.
 *
 * That is the answer to "there is always going to be a lot to analyse in a hard
 * drive": the question is not what is on it, it is what is worth your time, and
 * that question is about size.
 *
 * # Why colour is reversibility and not risk
 *
 * The obvious thing to colour by is how safe each item is to remove, and it
 * would be an invention: the confidence on a leftover, the safety on a cache
 * and the ownership of a duplicate copy are three different classifications
 * that do not share a scale, and flattening them into one ramp would produce a
 * number nobody computed.
 *
 * What they do share is what happens when you press the button — whether the
 * thing can be brought back, and by what. That is the fact a person actually
 * needs before acting, it is the same fact for all three, and it is checkable.
 */

export type Reversal = "quarantine" | "recycle" | "permanent";

export type ReclaimNode = {
  key: string;
  label: string;
  /** Size on disk. This is the area, so it must be a real measurement. */
  bytes: number;
  reversal: Reversal;
  /** One line of plain fact, shown on hover. */
  detail: string;
  children?: ReclaimNode[];
};

const REVERSAL_COLOUR: Record<Reversal, string> = {
  // Held by this program, and back with one press for thirty days.
  quarantine: "#2f7d5b",
  // Windows' own bin, and back the way anything else comes back.
  recycle: "#3465de",
  // Gone. The one colour that warrants a second look before pressing.
  permanent: "#a8791f",
};

export const RECLAIM_LEGEND: [string, string][] = [
  [REVERSAL_COLOUR.quarantine, "Quarantine holds it, and puts it back for 30 days"],
  [REVERSAL_COLOUR.recycle, "Goes to the Recycle Bin, where Windows puts it back"],
  [REVERSAL_COLOUR.permanent, "Removed outright, with no way back"],
];

const LABEL_MIN_WIDTH = 64;
const LABEL_MIN_HEIGHT = 28;

export default function ReclaimMap({
  nodes,
  onOpen,
}: {
  nodes: ReclaimNode[];
  /** A node with children to drill into, or a leaf to reveal. */
  onOpen: (node: ReclaimNode) => void;
}) {
  const container = useRef<HTMLDivElement>(null);
  const [size, setSize] = useState({ width: 0, height: 0 });

  // Measured synchronously first, then observed. Waiting for the observer's
  // first callback leaves the panel blank for a frame, and if it never fires
  // the map stays empty and reads as a scan that found nothing.
  useLayoutEffect(() => {
    const element = container.current;
    if (!element) return;
    const measure = (width: number, height: number) =>
      setSize((previous) =>
        previous.width === width && previous.height === height
          ? previous
          : { width, height },
      );
    const rect = element.getBoundingClientRect();
    measure(rect.width, rect.height);
    const observer = new ResizeObserver(([entry]) =>
      measure(entry.contentRect.width, entry.contentRect.height),
    );
    observer.observe(element);
    return () => observer.disconnect();
  }, []);

  const total = nodes.reduce((sum, node) => sum + node.bytes, 0);
  const cells = squarify(
    [...nodes].sort((a, b) => b.bytes - a.bytes),
    size.width,
    size.height,
  );

  return (
    <div className="connmap" ref={container}>
      {cells.map((cell) => {
        const node = cell.item;
        const deeper = (node.children?.length ?? 0) > 0;
        // Of what is drawn, so the percentages on screen add to a hundred and
        // mean "how much of this picture is that".
        const share =
          total > 0 ? Math.max(1, Math.round((node.bytes / total) * 100)) : 0;
        return (
          <button
            key={node.key}
            className={"connmap-cell" + (deeper ? " connmap-deeper" : "")}
            style={{
              left: cell.x,
              top: cell.y,
              width: Math.max(0, cell.width - 2),
              height: Math.max(0, cell.height - 2),
              background: REVERSAL_COLOUR[node.reversal],
            }}
            onClick={() => onOpen(node)}
            title={`${node.label}\n${fmt.bytes(node.bytes)} — ${node.detail}${
              deeper ? "\n\nClick to see what is inside" : ""
            }`}
          >
            {cell.width >= LABEL_MIN_WIDTH && cell.height >= LABEL_MIN_HEIGHT && (
              <>
                <span className="connmap-name">
                  {deeper && <span className="connmap-into">▸</span>}
                  {node.label}
                </span>
                <span className="connmap-count">{fmt.bytes(node.bytes)}</span>
                {cell.height >= 48 && (
                  <span className="connmap-notes">{share}%</span>
                )}
              </>
            )}
          </button>
        );
      })}
      {cells.length === 0 && (
        <p className="treemap-empty">Nothing measured yet.</p>
      )}
    </div>
  );
}
