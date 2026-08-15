/**
 * Squarified treemap layout (Bruls, Huizing, van Wijk).
 *
 * A naive slice-and-dice treemap produces slivers — cells one pixel wide and
 * the height of the panel — which are impossible to read or click. Squarifying
 * greedily fills rows along the shorter edge, keeping each cell's aspect ratio
 * as close to square as it can.
 */

export type Sized = { bytes: number };

export type Cell<T> = {
  item: T;
  x: number;
  y: number;
  width: number;
  height: number;
};

/** Worst aspect ratio in a candidate row. Lower is squarer. */
function worstRatio(areas: number[], sum: number, side: number): number {
  if (sum <= 0 || side <= 0) return Number.POSITIVE_INFINITY;
  let min = Number.POSITIVE_INFINITY;
  let max = 0;
  for (const area of areas) {
    if (area < min) min = area;
    if (area > max) max = area;
  }
  if (min <= 0) return Number.POSITIVE_INFINITY;
  const side2 = side * side;
  const sum2 = sum * sum;
  return Math.max((side2 * max) / sum2, sum2 / (side2 * min));
}

/**
 * Lay `items` out inside the given rectangle, largest first.
 *
 * Items with no size are dropped rather than given a zero-area cell, which
 * would be invisible but still catch clicks.
 */
export function squarify<T extends Sized>(
  items: T[],
  width: number,
  height: number,
): Cell<T>[] {
  const usable = items.filter((item) => item.bytes > 0);
  const total = usable.reduce((sum, item) => sum + item.bytes, 0);
  if (total <= 0 || width <= 0 || height <= 0) return [];

  const scale = (width * height) / total;
  const queue = usable.map((item) => ({ item, area: item.bytes * scale }));

  const cells: Cell<T>[] = [];
  let x = 0;
  let y = 0;
  let boxWidth = width;
  let boxHeight = height;
  let index = 0;

  while (index < queue.length) {
    // Fill along the shorter edge so rows stay wide and flat, not long and thin.
    const vertical = boxWidth >= boxHeight;
    const side = vertical ? boxHeight : boxWidth;

    const row: number[] = [];
    let rowSum = 0;
    let bestRatio = Number.POSITIVE_INFINITY;

    while (index + row.length < queue.length) {
      const next = queue[index + row.length].area;
      const candidateSum = rowSum + next;
      const ratio = worstRatio([...row, next], candidateSum, side);
      // Take the item only while it makes the row no worse.
      if (row.length === 0 || ratio <= bestRatio) {
        row.push(next);
        rowSum = candidateSum;
        bestRatio = ratio;
      } else {
        break;
      }
    }

    const thickness = side > 0 ? rowSum / side : 0;
    let offset = vertical ? y : x;

    for (let position = 0; position < row.length; position += 1) {
      const length = thickness > 0 ? row[position] / thickness : 0;
      const entry = queue[index + position];
      cells.push(
        vertical
          ? { item: entry.item, x, y: offset, width: thickness, height: length }
          : { item: entry.item, x: offset, y, width: length, height: thickness },
      );
      offset += length;
    }

    if (vertical) {
      x += thickness;
      boxWidth -= thickness;
    } else {
      y += thickness;
      boxHeight -= thickness;
    }
    index += row.length;
  }

  return cells;
}
