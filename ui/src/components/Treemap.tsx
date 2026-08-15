import { useLayoutEffect, useRef, useState } from "react";
import { squarify } from "../lib/treemap";
import * as fmt from "../lib/format";
import type { TreeNode } from "../lib/types";

type Props = {
  node: TreeNode;
  onDrill: (child: TreeNode) => void;
};

/** Enough room to print a name without it turning into an ellipsis smear. */
const LABEL_MIN_WIDTH = 56;
const LABEL_MIN_HEIGHT = 26;

/**
 * Colour is keyed to rank rather than to the value, so the eye can follow a
 * cell as it moves between levels. Sequential blues, largest darkest.
 */
const RAMP = [
  "#2b5bd7",
  "#3465de",
  "#3d6fe4",
  "#4a7cff",
  "#5a88ff",
  "#6b95ff",
  "#7ba1ff",
  "#8bacff",
  "#9ab7ff",
  "#a8c1ff",
];

export default function Treemap({ node, onDrill }: Props) {
  const container = useRef<HTMLDivElement>(null);
  const [size, setSize] = useState({ width: 0, height: 0 });

  // The layout is computed in pixels, so it has to be recomputed whenever the
  // panel resizes rather than assuming a fixed canvas.
  //
  // Measured synchronously first, then observed. Waiting for the observer's
  // first callback would leave the panel blank for a frame, and if the observer
  // never fires — a window that is not compositing, for instance — the map
  // would stay empty and look like a scan that found nothing.
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

    const observer = new ResizeObserver(([entry]) => {
      measure(entry.contentRect.width, entry.contentRect.height);
    });
    observer.observe(element);
    return () => observer.disconnect();
  }, []);

  const children = [...node.children].sort((a, b) => b.bytes - a.bytes);
  const cells = squarify(children, size.width, size.height);

  return (
    <div className="treemap" ref={container}>
      {cells.map((cell, index) => {
        const showLabel =
          cell.width >= LABEL_MIN_WIDTH && cell.height >= LABEL_MIN_HEIGHT;
        const drillable = !cell.item.is_aggregate && cell.item.children.length > 0;
        return (
          <div
            key={`${cell.item.path}-${index}`}
            className={
              "treemap-cell" +
              (drillable ? " drillable" : "") +
              (cell.item.is_aggregate ? " aggregate" : "")
            }
            style={{
              left: cell.x,
              top: cell.y,
              width: Math.max(0, cell.width - 2),
              height: Math.max(0, cell.height - 2),
              background: cell.item.is_aggregate
                ? "var(--surface-3)"
                : RAMP[Math.min(index, RAMP.length - 1)],
            }}
            onClick={() => drillable && onDrill(cell.item)}
            title={`${cell.item.path}\n${fmt.bytes(cell.item.bytes)}`}
          >
            {showLabel && (
              <>
                <span className="treemap-name">{cell.item.name}</span>
                <span className="treemap-size">{fmt.bytes(cell.item.bytes)}</span>
              </>
            )}
          </div>
        );
      })}
      {cells.length === 0 && (
        <p className="treemap-empty">Nothing measurable inside this folder.</p>
      )}
    </div>
  );
}
