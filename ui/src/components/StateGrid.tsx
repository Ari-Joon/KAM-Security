import { useState } from "react";

/**
 * A grid of equally sized tiles, coloured by state.
 *
 * # Why the tiles are all the same size
 *
 * The treemaps elsewhere in this product vary a block's area because the area
 * means something: bytes on disk, sockets held open. Area is the whole reason
 * to draw one — it lets a person see that one thing is eight times another
 * without reading a number.
 *
 * The things this grid shows have no magnitude. A Defender rule that blocks
 * Office spawning child processes is not "bigger" than one that blocks
 * credential theft from LSASS. Sizing those tiles differently would put a
 * number on the screen that does not exist, and the reader would believe it —
 * that is the whole trick of the software this replaces. So every tile is the
 * same size and only colour carries meaning, which is exactly as much as is
 * actually known.
 *
 * # Why a grid rather than the list it replaces
 *
 * Twenty rules in a vertical list is four screens of reading to answer "how
 * much of this is on", which is the only question most people arrive with. As a
 * grid it is one glance, and the detail is still one click away rather than
 * gone. Nothing is hidden: every tile that was a row is still a tile.
 */

export type GridTile = {
  key: string;
  /** What the thing is called, shown on the tile. */
  label: string;
  /** Its state in one or two words, shown under the label. */
  state: string;
  /** The colour for that state. The view owns the meaning; see `GridLegend`. */
  colour: string;
  /**
   * Anything worth flagging about this tile, most notable first.
   *
   * A count appears on the tile and the text appears when it is selected. A
   * list rather than a rating, for the reason the rest of this product gives
   * everywhere: collapsing several checked facts into one number destroys the
   * only thing that made them useful.
   */
  notes?: string[];
};

export default function StateGrid({
  tiles,
  selected,
  onSelect,
  empty,
}: {
  tiles: GridTile[];
  selected: string | null;
  onSelect: (key: string) => void;
  empty: string;
}) {
  if (tiles.length === 0) {
    return <p className="empty">{empty}</p>;
  }

  return (
    <div className="stategrid" role="list">
      {tiles.map((tile) => {
        const isOn = selected === tile.key;
        return (
          <button
            key={tile.key}
            role="listitem"
            type="button"
            className={"stategrid-tile" + (isOn ? " stategrid-on" : "")}
            style={{ borderTopColor: tile.colour }}
            aria-pressed={isOn}
            onClick={() => onSelect(tile.key)}
            title={`${tile.label} — ${tile.state}`}
          >
            <span className="stategrid-name">{tile.label}</span>
            <span className="stategrid-state" style={{ color: tile.colour }}>
              {tile.state}
            </span>
            {tile.notes && tile.notes.length > 0 && (
              <span className="stategrid-notes">
                {tile.notes.length} to notice
              </span>
            )}
          </button>
        );
      })}
    </div>
  );
}

/**
 * What each colour means, in words, beside the grid.
 *
 * Not decoration, and not optional. A coloured graphic with no key is a verdict
 * the reader cannot check, which is the thing this product exists as a reaction
 * against. The grid is only honest while this is on screen next to it.
 */
export function GridLegend({ entries }: { entries: [string, string][] }) {
  return (
    <ul className="stategrid-legend">
      {entries.map(([colour, label]) => (
        <li key={label}>
          <span className="stategrid-swatch" style={{ background: colour }} />
          {label}
        </li>
      ))}
    </ul>
  );
}

/**
 * The grid, plus whatever the view wants to show about the selected tile.
 *
 * A small convenience so the three views using this do not each re-implement
 * "nothing selected yet". Selection lives here rather than in the caller
 * because the only thing the caller does with it is render the detail.
 */
export function useGridSelection(tiles: GridTile[]) {
  const [selected, setSelected] = useState<string | null>(null);
  const present = tiles.some((tile) => tile.key === selected);
  return {
    selected: present ? selected : null,
    // Clicking the open tile closes it, which is what people expect and means
    // the detail panel is never stuck open on something they have stopped
    // caring about.
    onSelect: (key: string) =>
      setSelected((current) => (current === key ? null : key)),
  };
}
