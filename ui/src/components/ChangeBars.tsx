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
const DAY = 86_400_000;

/** Monday 00:00 of the week containing `when`, in local time. */
function weekStart(when: Date): number {
  const d = new Date(when.getFullYear(), when.getMonth(), when.getDate());
  const back = (d.getDay() + 6) % 7; // Monday = 0
  d.setDate(d.getDate() - back);
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
};

function bucket(history: Difference[]): Week[] {
  const thisWeek = weekStart(new Date());
  const weeks: Week[] = [];
  for (let i = WEEKS - 1; i >= 0; i--) {
    weeks.push({ start: thisWeek - i * 7 * DAY, total: 0, parts: [] });
  }

  for (const item of history) {
    const at = Date.parse(item.at);
    if (Number.isNaN(at)) continue;
    const start = weekStart(new Date(at));
    const week = weeks.find((w) => w.start === start);
    if (!week) continue; // older than the window, or somehow in the future

    const { colour, label } = categoryOf(item.kind);
    week.total += 1;
    const part = week.parts.find((p) => p.label === label);
    if (part) part.count += 1;
    else week.parts.push({ label, colour, count: 1 });
  }
  return weeks;
}

export default function ChangeBars({ history }: { history: Difference[] }) {
  const weeks = useMemo(() => bucket(history), [history]);
  const peak = useMemo(() => Math.max(1, ...weeks.map((w) => w.total)), [weeks]);

  const dated = history.filter((h) => !Number.isNaN(Date.parse(h.at)));
  if (dated.length === 0) {
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
          const height = week.total === 0 ? 2 : Math.max(4, (week.total / peak) * 88);
          const title =
            week.total === 0
              ? `Week of ${shortDate(week.start)}: nothing changed`
              : `Week of ${shortDate(week.start)}: ${week.total} ` +
                `${week.total === 1 ? "change" : "changes"} — ` +
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
                  // A week with nothing in it is a flat line, not an absence
                  // and not a tick. It reads as "nothing changed".
                  background: week.total === 0 ? "var(--border)" : "transparent",
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
      </div>
    </div>
  );
}
