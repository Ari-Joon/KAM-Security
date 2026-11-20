import { useMemo, useState } from "react";
import ChangeBars, { categoryOf } from "../components/ChangeBars";
import { api, reason } from "../lib/api";
import * as fmt from "../lib/format";
import type { ChangeKind, Difference, Kept, Sweep, TakenBy } from "../lib/types";

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
  hosts_entry: "hosts file entry",
  dns_servers: "DNS servers set by hand",
  proxy: "proxy",
  root_certificate: "trusted root certificate",
  browser_extension: "browser extension",
  winlogon: "Windows sign-in program",
  image_debugger: "debugger redirection",
  exit_monitor: "program started when another closes",
  logon_script: "sign-in script",
  appinit_dll: "AppInit library",
  wmi_subscription: "WMI event subscription",
  com_override: "account's own COM registration",
};

/**
 * Kinds that are settings rather than files, so nobody's signature is ever
 * recorded for them and none is shown.
 */
const NOT_FILES = new Set([
  "hosts_entry",
  "dns_servers",
  "proxy",
  "root_certificate",
  "browser_extension",
]);

/**
 * The root store Windows fills by itself, adding certificates from
 * Microsoft's list as sites that use them are visited. Arrivals there are
 * Windows doing its job, so they are counted rather than listed, as Windows'
 * own tasks are. One leaving, or anything arriving in any other store, is
 * listed.
 */
function isWindowsOwnRoot(item: Difference): boolean {
  return (
    item.kind === "root_certificate" &&
    item.change === "appeared" &&
    item.scope.toLowerCase() === "hklm\\software\\microsoft\\systemcertificates\\authroot"
  );
}

/**
 * Windows' own scheduled tasks, which turn over about 9% a month as Windows
 * updates itself. Measured on a real machine: 233 of them, 22 changed in the
 * last 30 days. Listing those individually would be roughly 22 rows a month of
 * guaranteed noise, and a panel that cries wolf monthly is one people stop
 * opening.
 *
 * They are counted rather than hidden. A number with no rows is honest; a
 * silent filter is not.
 *
 * A task's scope is the full path of its definition file, lowercased, such as
 * `c:\windows\system32\tasks\microsoft\windows\defrag\scheduleddefrag`. The
 * test used to look for a scope *starting* with `\microsoft`, which no scope
 * does, so it never matched and every one of these was listed. What it means
 * is a file under the `Microsoft` folder of the task store, wherever Windows
 * is installed.
 */
function isWindowsOwnTask(item: Difference): boolean {
  if (item.kind !== "scheduled_task") return false;
  return item.scope.toLowerCase().includes("\\system32\\tasks\\microsoft\\");
}

function longDate(iso: string): string {
  const when = Date.parse(iso);
  if (Number.isNaN(when)) return iso;
  return new Date(when).toLocaleDateString(undefined, {
    day: "numeric",
    month: "long",
  });
}

function Row({ item, whole }: { item: Difference; whole: boolean }) {
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

        {item.was_trusted ? (
          /* The case a path comparison cannot see: the entry has not moved and
             the command is identical, but the file it points at is not the file
             it was. Said in its own line rather than folded into the metadata,
             because "was signed by somebody, now nothing vouches for it" is the
             plainest statement this software is able to make about a thing
             having been replaced where it stands.

             It is still not a verdict. Software gets re-signed, certificates
             expire, an installer swaps a binary for a legitimate update. What
             is shown is what was observed, and the reader decides. */
          <div className="notice notice-warn" style={{ marginTop: 6 }}>
            The file behind this was {item.was_trusted}. It is now {item.trust}.
          </div>
        ) : null}

        <div className="small muted">
          {kind} in {item.scope}
          {/* A list kept before these were kept with it has none of them, and
              an empty one shown would read as nobody having signed. The list
              says so once, above its rows. */}
          {item.change === "appeared" || !whole ? null : (
            <>
              {" · "}first seen {fmt.timestamp(item.first_seen)}
              {item.times_seen > 1 ? ` · seen ${fmt.count(item.times_seen)} times` : null}
            </>
          )}
          {item.was_trusted || !whole || NOT_FILES.has(item.kind) ? null : (
            <>
              {" · "}
              {item.trust}
            </>
          )}
        </div>
      </div>
    </li>
  );
}

/**
 * What took a comparison, finishing "taken ...". A comparison from before this
 * was kept says so, and what is true of all of those: only this page took them.
 */
function takenBy(by: TakenBy | null): string {
  switch (by) {
    case "page":
      return "when this page was opened";
    case "weekly_check":
      return "by the weekly check";
    default:
      return "before KAM kept what took each comparison (until then, only this page took them)";
  }
}

/** What one comparison's list needs, whether it is the newest or read again. */
type Shown = {
  at: string;
  taken_by: TakenBy | null;
  previous_at: string | null;
  differences: Difference[];
  unreadable: string[];
  afresh: string[];
  /** False for a list kept before who signed each thing was kept with it. */
  whole: boolean;
};

/**
 * One comparison's list.
 *
 * `newest` is when the newest comparison was taken, given only for a list
 * read again: such a list is about the machine as it was then, and is said to
 * be, with its date, so it is never read as what is true now.
 */
function List({
  list,
  newest,
  before,
  onNewest,
}: {
  list: Shown;
  newest: string | null;
  /** What took the comparison this one was compared against, when known. */
  before: TakenBy | null;
  onNewest: () => void;
}) {
  const { shown, windowsTasks, windowsRoots } = useMemo(() => {
    const shown: Difference[] = [];
    let windowsTasks = 0;
    let windowsRoots = 0;
    // The agent already orders these most-notable-first, with a disappearance
    // ranked above an appearance. That ordering is deliberate and is not
    // re-sorted here.
    for (const item of list.differences) {
      if (isWindowsOwnTask(item)) windowsTasks += 1;
      else if (isWindowsOwnRoot(item)) windowsRoots += 1;
      else shown.push(item);
    }
    return { shown, windowsTasks, windowsRoots };
  }, [list]);
  const windowsOwn = [
    windowsTasks > 0 ? "Windows' own tasks" : null,
    windowsRoots > 0 ? "the certificates Windows adds by itself" : null,
  ].filter((part): part is string => part !== null);

  const total = shown.length;
  const unread = list.unreadable.length > 0;
  const afresh = list.afresh;
  // "Nothing changed" is a claim about everything this looks at, so it is
  // only made when everything was read and compared.
  const complete = !unread && afresh.length === 0;
  const since = list.previous_at ? longDate(list.previous_at) : "the last sweep";
  const changed = newest !== null ? "had changed" : "has changed";

  return (
    <section className="panel">
      {newest !== null ? (
        <div className="notice notice-warn">
          <strong>A past comparison,</strong> taken {fmt.timestamp(list.at)}
          {list.taken_by ? " " : ", "}
          {takenBy(list.taken_by)}, and kept as it was shown then. It says what
          had changed by that day, not what the machine is like now: the newest
          comparison was taken {fmt.timestamp(newest)}.{" "}
          <button className="link-button" style={{ padding: 0 }} onClick={onNewest}>
            Show the newest
          </button>
        </div>
      ) : null}
      <div className="panel-head">
        <h2>
          {total > 0
            ? `${fmt.count(total)} ${total === 1 ? "thing" : "things"} changed`
            : unread && afresh.length > 0
              ? "Nothing changed in what could be read and compared"
              : unread
                ? "Nothing changed in what could be read"
                : !complete
                  ? "Nothing changed in what was compared"
                  : windowsOwn.length > 0
                    ? `Only ${windowsOwn.join(" and ")} changed`
                    : "Nothing changed"}
        </h2>
        {total > 0 ? <span className="panel-count">{total}</span> : null}
      </div>
      <p className="panel-lede">
        {list.previous_at ? (
          newest !== null ? (
            <>Since {longDate(list.previous_at)}, the comparison before it.</>
          ) : before === "weekly_check" ? (
            /* The weekly check has compared the machine since this page was
               last opened, and anything that changed before then is in its
               list, not this one. */
            <>
              Since {longDate(list.previous_at)}, when the weekly check compared
              the machine. What it found is kept under Earlier comparisons.
            </>
          ) : (
            <>
              Since {longDate(list.previous_at)}, the last time this ran.
              {/* Not "since last week". This machine is not always on, and
                  the gap between sweeps is frequently not seven days. */}
            </>
          )
        ) : (
          <>Since the previous sweep.</>
        )}{" "}
        {newest === null ? <>Taken {takenBy(list.taken_by)}.</> : null}
      </p>

      {!list.whole ? (
        /* Kept before a difference was kept with who signed it and when it
           was first seen. Those are not shown rather than shown empty, which
           would read as nobody having signed. */
        <p className="notice notice-warn">
          This list was kept before KAM kept who signed each thing, who signed
          it before and when it was first seen, so those are not shown for it.
          What was recorded afresh that time is among what could not be read,
          as it was shown then.
        </p>
      ) : null}

      {list.unreadable.length > 0 ? (
        /* A source that could not be read concludes nothing about what is
           under it. Saying so out loud is the difference between an
           honest gap and a silent one. */
        <>
          <p className="notice notice-warn">
            Some of what this looks at could not be read{" "}
            {newest !== null ? "that time" : "this time"}, so nothing under it
            is reported as having gone. Nothing is claimed about{" "}
            {list.unreadable.length === 1 ? "it" : "them"} either way.
          </p>
          <ul className="small muted" style={{ margin: "6px 0 0 18px" }}>
            {list.unreadable.map((reason) => (
              <li key={reason}>{reason}</li>
            ))}
          </ul>
        </>
      ) : null}

      {afresh.length > 0 ? (
        /* Read, and recorded as it is, but not compared with last time:
           usually because this version reads it more closely than the
           last did. Not a failure to read, so it is not listed with
           those, and nothing is claimed about it either way. */
        <>
          <p className="notice notice-warn" style={{ marginTop: unread ? 12 : undefined }}>
            Some of it was recorded afresh {newest !== null ? "that time" : "this time"}{" "}
            rather than compared with the time before, so nothing is reported
            about {afresh.length === 1 ? "it" : "them"} either way.
          </p>
          <ul className="small muted" style={{ margin: "6px 0 0 18px" }}>
            {afresh.map((note) => (
              <li key={note}>{note}</li>
            ))}
          </ul>
        </>
      ) : null}

      {total === 0 ? (
        <p className="empty">
          {complete ? (
            <>
              Nothing this looks at {changed} since {since}: what starts itself,
              who can administer the machine, where its traffic is sent, which
              root certificates it trusts and which extensions its browsers run.
            </>
          ) : unread && afresh.length > 0 ? (
            <>
              Nothing that could be read and compared {changed} since {since}.
              What could not be read, and what was recorded afresh, are listed
              above, and nothing is claimed about either.
            </>
          ) : unread ? (
            <>
              Nothing that could be read {changed} since {since}. What could not
              be read is listed above, and nothing is claimed about it.
            </>
          ) : (
            <>
              Nothing that was compared {changed} since {since}. What was
              recorded afresh is listed above, and nothing is claimed about it.
            </>
          )}
        </p>
      ) : (
        <ul className="entries">
          {shown.map((item) => (
            <Row
              key={`${item.kind}|${item.scope}|${item.name}|${item.change}`}
              item={item}
              whole={list.whole}
            />
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

      {windowsRoots > 0 ? (
        <p className="footnote">
          {fmt.count(windowsRoots)}{" "}
          {windowsRoots === 1 ? "certificate also arrived" : "certificates also arrived"} in
          the root store Windows fills by itself from Microsoft's list. Windows
          adds those as sites that use them are visited, so they are counted
          here rather than listed.
        </p>
      ) : null}
    </section>
  );
}

export default function Changes({
  sweep,
  error,
  onRetry,
}: {
  sweep: Sweep | null;
  /** Why the sweep did not answer, when it did not. */
  error: string | null;
  onRetry: () => void;
}) {
  /** An earlier comparison's list, read again, when one has been chosen. */
  const [past, setPast] = useState<Kept | null>(null);
  /** Which list is being fetched, so a second choice is not sent meanwhile. */
  const [opening, setOpening] = useState<number | null>(null);
  const [pastError, setPastError] = useState<string | null>(null);

  if (!sweep) {
    return (
      <>
        <div className="view-head">
          <div>
            <h1>What changed</h1>
          </div>
        </div>
        <section className="panel">
          {error ? (
            /* Said, with the reason, rather than left on "looking" for ever. A
               sweep that could not run has found nothing, which is not the
               same as having found nothing wrong. */
            <div className="notice notice-down">
              <strong>What changed could not be worked out.</strong> Nothing
              is claimed about the machine either way.
              <pre className="error">{error}</pre>
              <button onClick={onRetry}>Try again</button>
            </div>
          ) : (
            <p className="empty">Looking at the machine.</p>
          )}
        </section>
      </>
    );
  }

  const newest: Shown = {
    at: sweep.at,
    taken_by: sweep.taken_by ?? null,
    previous_at: sweep.previous_at,
    differences: sweep.differences,
    unreadable: sweep.unreadable,
    afresh: sweep.afresh ?? [],
    whole: true,
  };
  const kept = sweep.kept ?? [];
  const shownId = past ? past.id : sweep.id;
  const before = kept.find((one) => one.at === sweep.previous_at)?.taken_by ?? null;

  /** Read an earlier list again, or go back to the newest. */
  function open(id: number) {
    setPastError(null);
    if (!sweep || id === sweep.id) {
      setPast(null);
      return;
    }
    setOpening(id);
    api
      .readComparison(id)
      .then(setPast)
      .catch((cause) => setPastError(reason(cause)))
      .finally(() => setOpening(null));
  }

  return (
    <>
      <div className="view-head">
        <div>
          <h1>What changed</h1>
          <p className="lede">
            The things that start themselves or hold a privilege, where this
            machine's traffic is sent, the root certificates it trusts and the
            extensions its browsers run, compared against the last time this
            machine was looked at. A change is not a problem: software installs
            itself, updates move things, and people change these settings on
            purpose. This says what is different and leaves the conclusion to
            you.
          </p>
        </div>
      </div>

      {sweep.baseline ? (
        /* Nothing to compare against yet. Reporting findings on a first run
           would mean inventing a past that was never observed. */
        <>
          <section className="panel">
            <div className="panel-head">
              <h2>Baseline recorded</h2>
            </div>
            <p className="panel-lede">
              This is the first look, taken {longDate(sweep.at)}. There is
              nothing to compare it against yet, so nothing is reported.
              Comparisons begin from the next sweep.
            </p>
            {sweep.unreadable.length > 0 ? (
              <p className="notice notice-warn">
                Some of what this looks at could not be read, so the baseline
                does not cover it. Nothing is claimed about it either way.
              </p>
            ) : null}
            {sweep.unreadable.length > 0 ? (
              <ul className="small muted" style={{ margin: "6px 0 0 18px" }}>
                {sweep.unreadable.map((reason) => (
                  <li key={reason}>{reason}</li>
                ))}
              </ul>
            ) : null}
          </section>

          {sweep.unvouched.length > 0 ? (
            /* The unavoidable weakness of a baseline, stated rather than
               hidden: it learns whatever is on the machine at the moment it is
               taken. Something unwanted that was already here is recorded as
               ordinary and will never be reported as having appeared, because
               it did not appear.

               Nothing can be done about that in general. What can be done is to
               say so. This is not a list of findings and must never read as
               one — it is the caveat on the baseline, and every ordinary
               machine has plenty of entries on it. */
            <section className="panel">
              <div className="panel-head">
                <h2>Already here when this started watching</h2>
                <span className="panel-count">{sweep.unvouched.length}</span>
              </div>
              <p className="panel-lede">
                These were on the machine before the first look, and no valid
                signature vouches for the files behind them. That is not a
                finding and none of them is accused of anything: plenty of
                legitimate software is unsigned, and a great deal of it is
                older than this program.
              </p>
              <p className="panel-lede">
                It is here because a baseline can only learn what is in front of
                it. Anything already present was recorded as ordinary and will
                never be reported as having appeared, because it did not appear.
                This is the one moment that gap can be named, so it is named.
                Nothing here has immunity afterwards: if one of these changes
                later, it is reported like anything else.
              </p>
              <ul className="entries">
                {sweep.unvouched.map((item) => (
                  <li className="entry" key={`${item.kind}|${item.scope}|${item.name}`}>
                    <span
                      aria-hidden
                      title={categoryOf(item.kind).label}
                      style={{
                        width: 9,
                        height: 9,
                        borderRadius: 2,
                        background: categoryOf(item.kind).colour,
                        flex: "0 0 auto",
                        marginTop: 6,
                      }}
                    />
                    <div className="entry-body">
                      <div className="entry-title">
                        <span className="module">{item.name}</span>
                        {/* The phrase itself says which of the two this is:
                            "not signed" is a fact about the file, "could not be
                            checked" is a limit on what could be seen. They are
                            not collapsed into one word. */}
                        <span className="action">{item.trust}</span>
                      </div>
                      <div className="detail">
                        {item.detail || <span className="muted">No command recorded.</span>}
                      </div>
                      <div className="small muted">
                        {KIND_LABEL[item.kind] ?? item.kind.replace(/_/g, " ")} in{" "}
                        {item.scope}
                      </div>
                    </div>
                  </li>
                ))}
              </ul>
            </section>
          ) : null}
        </>
      ) : (
        <>
          {past ? (
            <List list={past} newest={sweep.at} before={null} onNewest={() => open(sweep.id)} />
          ) : (
            <List list={newest} newest={null} before={before} onNewest={() => open(sweep.id)} />
          )}

          <section className="panel">
            <div className="panel-head">
              <h2>Earlier comparisons</h2>
            </div>
            <p className="panel-lede">
              Each comparison's list is kept as it was shown, so looking uses
              nothing up. These are the comparisons from the last twelve weeks,
              the same weeks as the chart below. Choose one to read its list
              again.
            </p>
            {kept.length > 1 ? (
              <div className="tabs">
                {kept.map((one) => (
                  <button
                    key={one.id}
                    className={"tab" + (one.id === shownId ? " active" : "")}
                    onClick={() => open(one.id)}
                    disabled={opening !== null}
                  >
                    {fmt.timestamp(one.at)}
                    {one.id === sweep.id ? ", the newest" : ""}
                    {one.taken_by === "weekly_check"
                      ? " · weekly check"
                      : one.taken_by === "page"
                        ? " · this page"
                        : ""}
                    <span className="tab-count">
                      {opening === one.id
                        ? "opening"
                        : one.found === 0
                          ? "nothing found"
                          : `${fmt.count(one.found)} found`}
                    </span>
                  </button>
                ))}
              </div>
            ) : (
              <p className="empty">
                This is the only comparison from the last twelve weeks.
              </p>
            )}
            {pastError ? (
              <p className="notice notice-down" style={{ marginTop: 12 }}>
                That list could not be read: {pastError}
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
              and no target, only whether this week looks like the others.
              Colour shows what kind of thing changed, not how serious it was.
            </p>
            <ChangeBars history={sweep.history} swept={sweep.swept ?? []} />
          </section>
        </>
      )}
    </>
  );
}
