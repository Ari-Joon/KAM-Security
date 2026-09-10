import { useMemo } from "react";
import ChangeBars, { categoryOf } from "../components/ChangeBars";
import * as fmt from "../lib/format";
import type { ChangeKind, Difference, Sweep } from "../lib/types";

/**
 * What changed on this machine since the last time it was looked at.
 *
 * Everything else in this product answers "what is true now". This answers
 * "what is different", which is the question people actually have and which
 * Windows answers nowhere — there is no built-in view of new startup entries,
 * new administrators, or a service that has quietly disappeared.
 *
 * The discipline here is that a difference is not a verdict. A new scheduled
 * task is not malware. This names the thing, says what it runs, says when it
 * was noticed, and stops. Deciding whether it should be there is the reader's
 * job, and they are better placed to do it than any rule this software could
 * carry.
 */

const CHANGE_LABEL: Record<ChangeKind, string> = {
  appeared: "appeared",
  altered: "changed",
  vanished: "is gone",
  recurring: "comes and goes",
};

const KIND_LABEL: Record<string, string> = {
  service: "service",
  scheduled_task: "scheduled task",
  run_key: "startup registry entry",
  run_once_key: "run-once registry entry",
  startup_item: "startup folder item",
  administrator: "administrator",
};

/**
 * Windows' own scheduled tasks, which turn over about 9% a month as Windows
 * updates itself. Measured on a real machine: 233 of them, 22 changed in the
 * last 30 days. Listing those individually would be roughly 22 rows a month of
 * guaranteed noise, and a panel that cries wolf monthly is one people stop
 * opening.
 *
 * They are counted rather than hidden. A number with no rows is honest; a
 * silent filter is not.
 */
function isWindowsOwnTask(item: Difference): boolean {
  if (item.kind !== "scheduled_task") return false;
  const scope = item.scope.toLowerCase();
  return scope.startsWith("\\microsoft") || scope.startsWith("microsoft");
}

function longDate(iso: string): string {
  const when = Date.parse(iso);
  if (Number.isNaN(when)) return iso;
  return new Date(when).toLocaleDateString(undefined, {
    day: "numeric",
    month: "long",
  });
}

function Row({ item }: { item: Difference }) {
  const { colour, label: category } = categoryOf(item.kind);
  const kind = KIND_LABEL[item.kind] ?? item.kind.replace(/_/g, " ");

  return (
    <li className="entry">
      <span
        aria-hidden
        title={category}
        style={{
          width: 9,
          height: 9,
          borderRadius: 2,
          background: colour,
          flex: "0 0 auto",
          marginTop: 6,
        }}
      />
      <div className="entry-body">
        <div className="entry-title">
          <span className="module">{item.name}</span>
          <span className="action">{CHANGE_LABEL[item.change]}</span>
        </div>
        <div className="detail">{item.detail || <span className="muted">No command recorded.</span>}</div>
        <div className="small muted">
          {kind} in {item.scope}
          {item.change === "appeared" ? null : (
            <>
              {" · "}first seen {fmt.timestamp(item.first_seen)}
              {item.times_seen > 1 ? ` · seen ${fmt.count(item.times_seen)} times` : null}
            </>
          )}
        </div>
      </div>
    </li>
  );
}

export default function Changes({ sweep }: { sweep: Sweep | null }) {
  const groups = useMemo(() => {
    if (!sweep) return { shown: [] as Difference[], windowsTasks: 0 };
    const shown: Difference[] = [];
    let windowsTasks = 0;
    // The agent already orders these most-notable-first, with a disappearance
    // ranked above an appearance. That ordering is deliberate and is not
    // re-sorted here.
    for (const item of sweep.differences) {
      if (isWindowsOwnTask(item)) windowsTasks += 1;
      else shown.push(item);
    }
    return { shown, windowsTasks };
  }, [sweep]);

  if (!sweep) {
    return (
      <>
        <div className="view-head">
          <div>
            <h1>What changed</h1>
          </div>
        </div>
        <section className="panel">
          <p className="empty">Looking at the machine.</p>
        </section>
      </>
    );
  }

  const { shown, windowsTasks } = groups;
  const total = shown.length;

  return (
    <>
      <div className="view-head">
        <div>
          <h1>What changed</h1>
          <p className="lede">
            The things that start themselves or hold a privilege, compared
            against the last time this machine was looked at. A change is not a
            problem — software installs itself, updates move things. This says
            what is different and leaves the conclusion to you.
          </p>
        </div>
      </div>

      {sweep.baseline ? (
        /* Nothing to compare against yet. Reporting findings on a first run
           would mean inventing a past that was never observed. */
        <section className="panel">
          <div className="panel-head">
            <h2>Baseline recorded</h2>
          </div>
          <p className="panel-lede">
            This is the first look, taken {longDate(sweep.at)}. There is nothing
            to compare it against yet, so nothing is reported. Comparisons begin
            from the next sweep.
          </p>
        </section>
      ) : (
        <>
          <section className="panel">
            <div className="panel-head">
              <h2>
                {total === 0
                  ? "Nothing changed"
                  : `${fmt.count(total)} ${total === 1 ? "thing" : "things"} changed`}
              </h2>
              {total > 0 ? <span className="panel-count">{total}</span> : null}
            </div>
            <p className="panel-lede">
              {sweep.previous_at ? (
                <>
                  Since {longDate(sweep.previous_at)}, the last time this ran.
                  {/* Not "since last week". This machine is not always on, and
                      the gap between sweeps is frequently not seven days. */}
                </>
              ) : (
                <>Since the previous sweep.</>
              )}
            </p>

            {sweep.unreadable.length > 0 ? (
              /* A source that could not be read concludes nothing about what is
                 under it. Saying so out loud is the difference between an
                 honest gap and a silent one. */
              <p className="notice notice-warn">
                Could not check {sweep.unreadable.join(", ")}. Nothing is claimed
                about {sweep.unreadable.length === 1 ? "it" : "them"} either way.
              </p>
            ) : null}

            {total === 0 ? (
              <p className="empty">
                Nothing that starts itself or holds a privilege has changed since{" "}
                {sweep.previous_at ? longDate(sweep.previous_at) : "the last sweep"}.
              </p>
            ) : (
              <ul className="entries">
                {shown.map((item) => (
                  <Row key={`${item.kind}|${item.scope}|${item.name}|${item.change}`} item={item} />
                ))}
              </ul>
            )}

            {windowsTasks > 0 ? (
              <p className="footnote">
                {fmt.count(windowsTasks)} of Windows' own scheduled tasks also
                changed. Those turn over as Windows updates itself, so they are
                counted here rather than listed.
              </p>
            ) : null}
          </section>

          <section className="panel">
            <div className="panel-head">
              <h2>Week by week</h2>
            </div>
            <p className="panel-lede">
              How much changed each week. This compares the machine against its
              own history rather than against a standard, so there is no score
              and no target — only whether this week looks like the others.
              Colour shows what kind of thing changed, not how serious it was.
            </p>
            <ChangeBars history={sweep.history} />
          </section>
        </>
      )}
    </>
  );
}
