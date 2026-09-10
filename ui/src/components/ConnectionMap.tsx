import { useLayoutEffect, useRef, useState } from "react";
import { squarify } from "../lib/treemap";

/**
 * What is on the network, as area rather than as a list.
 *
 * # Why a map and not more rows
 *
 * The list this sits above groups sockets under the program that owns them,
 * which was a real improvement and still not enough: one program is several
 * executables. Steam alone is `steam.exe` and `steamwebhelper.exe`. Grouping by
 * executable fragments exactly the things a person thinks of as one program,
 * and no amount of sorting fixes it, because the problem is that a list gives
 * every row the same visual weight whatever it is worth.
 *
 * Area does not. A publisher with forty sockets is forty times the size of one
 * with a single socket, and that is legible before anything is read.
 *
 * # One level at a time, like the storage map
 *
 * The first version drew publishers with their programs nested inside them, and
 * it was wrong twice over. Visually, small blocks could not hold their children
 * and the children spilled across their neighbours. And behaviourally, clicking
 * a block only highlighted it — there was nowhere to go, so the map showed the
 * shape of the answer and then refused to take you to it.
 *
 * So it drills, exactly as the storage map does: publishers first, click one to
 * see its programs filling the whole map, breadcrumb back out. Nothing is
 * nested, so nothing can overflow, and every rectangle has the room to say what
 * it is.
 *
 * # What the colours mean, and what they do not
 *
 * They are not a verdict, and the legend under the map says what each one is in
 * words. Each colour is a *pair of facts this software checked*: whether the
 * program carries a valid signature, and whether it is open to the network —
 * either reaching out, or listening somewhere the network can reach it. Both
 * are verifiable and neither is an opinion.
 *
 * So red is not "this is malware". Red is "nothing signed this, and it is open
 * to the network" — the combination worth a look, stated plainly. And grey is
 * not a mild accusation: it means the owning program could not be identified,
 * which is a limitation of the observer rather than a property of the observed.
 * Colouring that as a warning would be inventing a finding out of a permissions
 * failure, which is the single failure mode this product exists to avoid.
 */

/** Tones, keyed to what was checked rather than to how alarming it is. */
export type Tone = "quiet" | "normal" | "watch" | "look" | "unknown";

const TONE_COLOUR: Record<Tone, string> = {
  // Signed, and only talking to this machine.
  quiet: "#2f7d5b",
  // Signed, and open to the network. Almost everything, and ordinary.
  normal: "#3465de",
  // Not signed, but only talking to this machine.
  watch: "#a8791f",
  // Not signed, and open to the network.
  look: "#a33b45",
  // The owning program could not be read. Not a finding, and deliberately the
  // dullest colour here rather than a warning one.
  unknown: "#3a4459",
};

/** One rectangle: a publisher, or a program inside one. */
export type MapNode = {
  key: string;
  label: string;
  /** Socket count. Named `bytes` to satisfy the shared layout's constraint. */
  bytes: number;
  tone: Tone;
  external: number;
  /** Percentage of every open socket on screen. Adds to a hundred. */
  share: number;
  /**
   * What warrants a look, most notable first, and empty when nothing does.
   *
   * Deliberately a list rather than a rating. Nothing here knows whether a
   * program is dangerous, and collapsing several checked facts into one number
   * throws away the only thing that made them useful: that a person can read
   * each one and disagree with it.
   */
  notes: string[];
  detail: string;
};

export type MapGroup = MapNode & { children: MapNode[] };

const LABEL_MIN_WIDTH = 60;
const LABEL_MIN_HEIGHT = 24;

export default function ConnectionMap({
  nodes,
  selected,
  onActivate,
}: {
  nodes: MapNode[];
  selected: string | null;
  /** A publisher to open, or a program to go to. The view decides which. */
  onActivate: (node: MapNode) => void;
}) {
  const container = useRef<HTMLDivElement>(null);
  const [size, setSize] = useState({ width: 0, height: 0 });

  // Measured synchronously first, then observed — the same reasoning as the
  // storage treemap: waiting for the observer's first callback leaves the panel
  // blank for a frame, and if it never fires the map stays empty and reads as a
  // survey that found nothing.
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

  const cells = squarify(
    [...nodes].sort((a, b) => b.bytes - a.bytes),
    size.width,
    size.height,
  );

  return (
    <div className="connmap" ref={container}>
      {cells.map((cell) => {
        const node = cell.item;
        const deeper = "children" in node && (node as MapGroup).children.length > 1;
        return (
          <button
            key={node.key}
            className={
              "connmap-cell" +
              (selected === node.key ? " connmap-on" : "") +
              (deeper ? " connmap-deeper" : "")
            }
            style={{
              left: cell.x,
              top: cell.y,
              width: Math.max(0, cell.width - 2),
              height: Math.max(0, cell.height - 2),
              background: TONE_COLOUR[node.tone],
            }}
            onClick={() => onActivate(node)}
            title={`${node.label}\n${node.detail}${deeper ? "\n\nClick to see its programs" : ""}`}
          >
            {cell.width >= LABEL_MIN_WIDTH && cell.height >= LABEL_MIN_HEIGHT && (
              <>
                <span className="connmap-name">
                  {deeper && <span className="connmap-into">▸</span>}
                  {node.label}
                </span>
                {/*
                  Share of everything open, so a block's size has a number
                  against it rather than only a comparison with its neighbours.
                */}
                <span className="connmap-count">{node.share}%</span>
                {node.notes.length > 0 && cell.height >= 44 && (
                  <span className="connmap-notes">
                    {node.notes.length} to notice
                  </span>
                )}
              </>
            )}
          </button>
        );
      })}
      {cells.length === 0 && (
        <p className="treemap-empty">Nothing has a socket open.</p>
      )}
    </div>
  );
}

/**
 * What each colour means, in words, under the map.
 *
 * Not decoration. A coloured graphic without this is a verdict with no way to
 * check it, which is the thing this product is a reaction against — so the
 * legend states the two facts behind each colour, and the map is only honest
 * while it is on screen.
 */
export function ConnectionLegend() {
  const entries: [Tone, string][] = [
    ["normal", "Signed, and open to the network"],
    ["quiet", "Signed, and only talking to this machine"],
    ["look", "Not signed, and open to the network"],
    ["watch", "Not signed, but only talking to this machine"],
    ["unknown", "Could not be identified"],
  ];
  return (
    <ul className="connmap-legend">
      {entries.map(([tone, label]) => (
        <li key={tone}>
          <span
            className="connmap-swatch"
            style={{ background: TONE_COLOUR[tone] }}
          />
          {label}
        </li>
      ))}
    </ul>
  );
}
