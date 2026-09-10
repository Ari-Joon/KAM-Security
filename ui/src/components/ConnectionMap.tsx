import { useLayoutEffect, useRef, useState } from "react";
import { squarify } from "../lib/treemap";

/**
 * What is on the network, as area rather than as a list.
 *
 * # Why a map and not more rows
 *
 * The list before this grouped sockets under the program that owned them, which
 * was a real improvement and still not enough: one program is several
 * executables. Steam alone is `steam.exe` and `steamwebhelper.exe`; the browser
 * is one binary with dozens of sockets; the machine has a dozen more. Grouping
 * by executable therefore fragments exactly the things a person thinks of as
 * one program, and no amount of sorting fixes that, because the problem is that
 * a list gives every row the same visual weight whatever it is worth.
 *
 * Area does not. A publisher with forty sockets is forty times the size of one
 * with a single socket, and that is legible before anything is read.
 *
 * # Two levels, because that is what the data is
 *
 * Publisher outside, program inside. Steam's two executables sit together
 * inside one Valve block, which is the grouping people actually have in their
 * heads, and the individual programs stay visible inside it rather than being
 * summed away.
 *
 * # What the colours mean, and what they do not
 *
 * They are not a verdict, and the legend under the map says what each one is in
 * words. Each colour is a *pair of facts this software checked*: whether the
 * program carries a valid signature, and whether it is connected to something
 * outside this machine. Both are verifiable, and neither is an opinion.
 *
 * So red is not "this is malware". Red is "nothing signed this, and it is open
 * to the network" — the combination worth a look, stated plainly. And
 * grey is not a mild accusation: it means the owning program could not be
 * identified, which is a limitation of the observer, not a property of the
 * observed. Colouring that as a warning would be inventing a finding out of a
 * permissions failure, which is the single failure mode this product exists to
 * avoid.
 */

/**
 * Tones, keyed to what was checked rather than to how alarming it is.
 *
 * "Open to the network" covers both directions, and it has to. A program
 * *reaching out* is the obvious case; a program *listening on an address the
 * network can reach* is the one people least expect to find, and Windows
 * reports it as neither an outbound connection nor anything unusual. Counting
 * only the outbound half meant a service accepting connections from the whole
 * network was coloured as though it were staying put, which was not a
 * presentational choice but a false statement.
 */
export type Tone = "quiet" | "normal" | "watch" | "look" | "unknown";

const TONE_COLOUR: Record<Tone, string> = {
  // Signed, and staying on this machine.
  quiet: "#2f7d5b",
  // Signed, and talking to the internet. Almost everything, and normal.
  normal: "#3465de",
  // Not signed, but not reaching the internet.
  watch: "#a8791f",
  // Not signed, and reaching the internet.
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
  detail: string;
};

export type MapGroup = MapNode & { children: MapNode[] };

const LABEL_MIN_WIDTH = 54;
const LABEL_MIN_HEIGHT = 22;

export default function ConnectionMap({
  groups,
  selected,
  onSelect,
}: {
  groups: MapGroup[];
  selected: string | null;
  onSelect: (key: string | null) => void;
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

  const outer = squarify(
    [...groups].sort((a, b) => b.bytes - a.bytes),
    size.width,
    size.height,
  );

  return (
    <div className="connmap" ref={container}>
      {outer.map((cell) => {
        const group = cell.item;
        // A publisher with one program is just that program: nesting it would
        // draw a border around a single cell and say nothing.
        const inner =
          group.children.length > 1
            ? squarify(
                [...group.children].sort((a, b) => b.bytes - a.bytes),
                Math.max(0, cell.width - 2),
                Math.max(0, cell.height - 16),
              )
            : [];

        return (
          <div
            key={group.key}
            className="connmap-group"
            style={{
              left: cell.x,
              top: cell.y,
              width: Math.max(0, cell.width - 2),
              height: Math.max(0, cell.height - 2),
            }}
          >
            <button
              className={
                "connmap-cell" + (selected === group.key ? " connmap-on" : "")
              }
              style={{ background: TONE_COLOUR[group.tone] }}
              onClick={() => onSelect(selected === group.key ? null : group.key)}
              title={`${group.label}\n${group.detail}`}
            >
              {cell.width >= LABEL_MIN_WIDTH && cell.height >= LABEL_MIN_HEIGHT && (
                <>
                  <span className="connmap-name">{group.label}</span>
                  <span className="connmap-count">{group.bytes}</span>
                </>
              )}
            </button>

            {inner.map((child) => (
              <button
                key={child.item.key}
                className={
                  "connmap-child" +
                  (selected === child.item.key ? " connmap-on" : "")
                }
                style={{
                  left: child.x + 1,
                  top: child.y + 15,
                  width: Math.max(0, child.width - 2),
                  height: Math.max(0, child.height - 2),
                  background: TONE_COLOUR[child.item.tone],
                }}
                onClick={() =>
                  onSelect(selected === child.item.key ? null : child.item.key)
                }
                title={`${child.item.label}\n${child.item.detail}`}
              >
                {child.width >= LABEL_MIN_WIDTH &&
                  child.height >= LABEL_MIN_HEIGHT && (
                    <span className="connmap-name">{child.item.label}</span>
                  )}
              </button>
            ))}
          </div>
        );
      })}
      {outer.length === 0 && (
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
 * legend says the two facts behind each colour and the map is only honest while
 * it is on screen.
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
