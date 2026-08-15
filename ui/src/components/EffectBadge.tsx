import type { Effect } from "../lib/types";

/**
 * The three outcomes the audit log distinguishes. Refusals are the ones worth
 * spotting from across the room, so they get the only strong colour.
 */
export default function EffectBadge({ effect }: { effect: Effect }) {
  return <span className={`badge badge-${effect}`}>{effect}</span>;
}
