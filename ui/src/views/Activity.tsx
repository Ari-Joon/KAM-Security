import { useMemo, useState } from "react";
import EffectBadge from "../components/EffectBadge";
import * as fmt from "../lib/format";
import type { AuditRecord, Effect } from "../lib/types";

type Filter = "all" | Effect;

const FILTERS: { key: Filter; label: string }[] = [
  { key: "all", label: "Everything" },
  { key: "changed", label: "Changes" },
  { key: "refused", label: "Refusals" },
  { key: "observed", label: "Observations" },
];

export default function Activity({ entries }: { entries: AuditRecord[] }) {
  const [filter, setFilter] = useState<Filter>("all");

  const shown = useMemo(
    () => (filter === "all" ? entries : entries.filter((e) => e.effect === filter)),
    [entries, filter],
  );

  return (
    <>
      <div className="view-head">
        <div>
          <h1>Activity</h1>
          <p className="lede">
            What the agent did, and what it refused. Append-only — the database
            rejects updates and deletes, so this cannot be quietly rewritten.
          </p>
        </div>
      </div>

      <section className="panel">
        <div className="tabs">
          {FILTERS.map((option) => (
            <button
              key={option.key}
              className={"tab" + (filter === option.key ? " active" : "")}
              onClick={() => setFilter(option.key)}
            >
              {option.label}
              <span className="tab-count">
                {option.key === "all"
                  ? entries.length
                  : entries.filter((e) => e.effect === option.key).length}
              </span>
            </button>
          ))}
        </div>

        {shown.length === 0 ? (
          <p className="empty">Nothing under this filter.</p>
        ) : (
          <ul className="entries">
            {shown.map((entry) => (
              <li key={entry.id} className="entry">
                <EffectBadge effect={entry.effect} />
                <div className="entry-body">
                  <div className="entry-title">
                    <span className="module">{entry.module}</span>
                    <span className="action">{entry.action}</span>
                  </div>
                  <div className="detail">{entry.detail}</div>
                </div>
                <time className="at" dateTime={entry.at} title={entry.at}>
                  {fmt.timestamp(entry.at)}
                </time>
              </li>
            ))}
          </ul>
        )}
      </section>
    </>
  );
}
