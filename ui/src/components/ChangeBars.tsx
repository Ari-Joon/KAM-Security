import { useMemo } from "react";
import type { Difference } from "../lib/types";

/**
 * How much changed each week, drawn as a bar per week.
 *
 * The point of this shape is what it refuses to be. A score, a dial or a green
 * tick would all answer "is this machine safe", which is a verdict nobody here
 * is entitled to make. A bar per week answers "is this week like my other
 * weeks", which is a difference — the machine measured against its own history
 * rather than against an invented standard. There is no target, so there is
 * nothing to game toward, and a quiet week is quiet rather than good.
 *
 * Colour carries the *category* of what changed, never its severity. Red and
 * green would smuggle a judgement back in through the palette after the numbers
 * had carefully avoided making one, so the colours below are chosen to be
 * distinguishable and to mean nothing on their own.
 */

/**
 * Categorical, not sequential and not diverging.
 *
 * Deliberately avoids the palette's `--ok`, `--warn` and `--danger`: those
 * carry meaning, and a reader who learns that "pink means bad" has been given a
 * verdict the rest of this view was careful not to give.
 */
const CATEGORY: Record<string, { colour: string; label: string }> = {
  service: { colour: "#4a7cff", label: "Services" },
  scheduled_task: { colour: "#7b6cf6", label: "Scheduled tasks" },
  run_key: { colour: "#2ec4b6", label: "Startup registry" },
  run_once_key: { colour: "#2ec4b6", label: "Startup registry" },
  startup_item: { colour: "#e0a458", label: "Startup folder" },
  administrator: { colour: "#d96fa8", label: "Administrators" },
};

const OTHER = { colour: "#6b7a99", label: "Other" };

export function categoryOf(kind: string): { colour: string; label: string } {
  return CATEGORY[kind] ?? OTHER;
}

const WEEKS = 12;

/** Monday 00:00 of the week containing `when`, in local time. */
function weekStart(when: Date): number {
  const d = new Date(when.getFullYear(), when.getMonth(), when.getDate());
  const back = (d.getDay() + 6) % 7; // Monday = 0
  d.setDate(d.getDate() - back);
  return d.getTime();
}

/**
 * Monday 00:00 of the week `weeksBack` before the one starting at `start`.
 *
 * Stepped back in calendar days rather than by subtracting seven times a day's
 * milliseconds. A week that contains a clock change is an hour longer or
 * shorter than that, so the subtraction landed at 23:00 or 01:00 on the
 * Monday, matched no week start exactly, and every week before the change
 * showed "nothing changed" whatever had happened in it.
 */
function weeksBefore(start: number, weeksBack: number): number {
  const d = new Date(start);
  d.setDate(d.getDate() - weeksBack * 7);
  return d.getTime();
}

function shortDate(ms: number): string {
  return new Date(ms).toLocaleDateString(undefined, { day: "numeric", month: "short" });
}

type Week = {
  start: number;
  total: number;
  /** Count per category label, so one bar can be split by what changed. */
  parts: { label: string; colour: string; count: number }[];
  /**
   * Whether any sweep compared the machine during this week.
   *
   * A week with no changes is only "nothing changed" if somebody looked.
   * Otherwise nothing is known about it, and it is drawn that way.
   */
  looked: boolean;
};

function bucket(history: Difference[], swept: string[]): Week[] {
  const thisWeek = weekStart(new Date());
  const weeks: Week[] = [];
  for (let i = WEEKS - 1; i >= 0; i--) {
    weeks.push({ start: weeksBefore(thisWeek, i), total: 0, parts: [], looked: false });
  }
  const weekOf = (iso: string): Week | undefined => {
    const at = Date.parse(iso);
    if (Number.isNaN(at)) return undefined;
    const start = weekStart(new Date(at));
    // Undefined when older than the window, or somehow in the future.
    return weeks.find((w) => w.start === start);
  };

  for (const at of swept) {
    const week = weekOf(at);
    if (week) week.looked = true;
  }

  for (const item of history) {
    const week = weekOf(item.at);
    if (!week) continue;

    const { colour, label } = categoryOf(item.kind);
    week.total += 1;
    // A change was noticed by a sweep, so that week was looked at.
    week.looked = true;
    const part = week.parts.find((p) => p.label === label);
    if (part) part.count += 1;
    else week.parts.push({ label, colour, count: 1 });
  }
  return weeks;
}

export default function ChangeBars({
  history,
  swept,
}: {
  history: Difference[];
  /** When a sweep compared the machine, so an unlooked week is not called quiet. */
  swept: string[];
}) {
  const weeks = useMemo(() => bucket(history, swept), [history, swept]);
  const peak = useMemo(() => Math.max(1, ...weeks.map((w) => w.total)), [weeks]);

  if (!weeks.some((week) => week.looked)) {
    return (
      <p className="empty">
        No history yet. Each sweep adds a week, so these bars fill in as the
        machine is watched over time.
      </p>
    );
  }

  // Only categories actually present get a key — a legend full of zeroes
  // implies things were looked for and not found, which is a different claim.
  const present = new Map<string, string>();
  for (const week of weeks) {
    for (const part of week.parts) present.set(part.label, part.colour);
  }
  // The two kinds of empty bar are drawn differently, and each gets a key
  // only when it is on screen.
  const quietShown = weeks.some((week) => week.looked && week.total === 0);
  const unlookedShown = weeks.some((week) => !week.looked);

  return (
    <div className="changebars">
      <div
        style={{
          display: "flex",
          alignItems: "flex-end",
          gap: 6,
          height: 96,
          padding: "4px 0",
        }}
      >
        {weeks.map((week) => {
          const isNow = week.start === weekStart(new Date());
          const unlooked = !week.looked;
          const height = unlooked
            ? 10
            : week.total === 0
              ? 2
              : Math.max(4, (week.total / peak) * 88);
          const title = unlooked
            ? `Week of ${shortDate(week.start)}: no sweep compared the machine this week, so nothing is known about it`
            : week.total === 0
              ? `Week of ${shortDate(week.start)}: looked at, and nothing changed`
              : `Week of ${shortDate(week.start)}: ${week.total} ` +
                `${week.total === 1 ? "change" : "changes"}: ` +
                week.parts.map((p) => `${p.count} ${p.label.toLowerCase()}`).join(", ");

          return (
            <div
              key={week.start}
              title={title}
              style={{ flex: 1, display: "flex", flexDirection: "column", alignItems: "center", gap: 4 }}
            >
              <div
                style={{
                  width: "100%",
                  height,
                  display: "flex",
                  flexDirection: "column-reverse",
                  borderRadius: 3,
                  overflow: "hidden",
                  boxSizing: "border-box",
                  // A week with nothing in it is a flat line, not an absence
                  // and not a tick. It reads as "nothing changed". A week
                  // nobody looked at is a small empty dashed frame instead:
                  // not a bar, because there is no number to draw, and not
                  // the flat line, because nothing is known to be zero.
                  background:
                    !unlooked && week.total === 0 ? "var(--border)" : "transparent",
                  border: unlooked ? "1px dashed var(--border-strong)" : "none",
                  outline: isNow ? "1px solid var(--border-strong)" : "none",
                  outlineOffset: 2,
                }}
              >
                {week.parts.map((part) => (
                  <div
                    key={part.label}
                    style={{ height: `${(part.count / week.total) * 100}%`, background: part.colour }}
                  />
                ))}
              </div>
              <span className="small muted" style={{ fontSize: 10, whiteSpace: "nowrap" }}>
                {shortDate(week.start)}
              </span>
            </div>
          );
        })}
      </div>

      <div style={{ display: "flex", flexWrap: "wrap", gap: 12, marginTop: 10 }}>
        {[...present.entries()].map(([label, colour]) => (
          <span key={label} className="small muted" style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <span
              aria-hidden
              style={{ width: 9, height: 9, borderRadius: 2, background: colour, display: "inline-block" }}
            />
            {label}
          </span>
        ))}
        {quietShown && (
          <span className="small muted" style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <span
              aria-hidden
              style={{ width: 9, height: 2, background: "var(--border)", display: "inline-block" }}
            />
            Looked at, nothing changed
          </span>
        )}
        {unlookedShown && (
          <span className="small muted" style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <span
              aria-hidden
              style={{
                width: 9,
                height: 9,
                boxSizing: "border-box",
                border: "1px dashed var(--border-strong)",
                borderRadius: 2,
                display: "inline-block",
              }}
            />
            Not looked at that week
          </span>
        )}
      </div>
    </div>
  );
}
