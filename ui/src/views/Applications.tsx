import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api, reason } from "../lib/api";
import * as fmt from "../lib/format";
import PathLink from "../components/PathLink";
import MeasuredAt, { whenMeasured } from "../components/MeasuredAt";
import { KeptNote, NotKeptNote, UnreadableNote } from "../components/Kept";
import NewerVersions from "../components/NewerVersions";
import type { PageJobOutcome } from "../lib/jobs";
import { recall, remember, type Kept } from "../lib/remembered";
import { usePageJob } from "../lib/usePageJob";
import type {
  AppFootprint,
  ApplicationReport,
  Remnants,
  Volume,
} from "../lib/types";

type Props = { volumes: Volume[]; onMeasured: () => void };

/**
 * A row with no measurement behind it yet.
 *
 * Shown as a waiting mark rather than as `0 B`, because a zero in that column
 * is a claim, and the claim would be wrong for every row on screen.
 */
const NOT_MEASURED = "being measured";

type SortKey = "size" | "name" | "publisher" | "installed" | "used";
type Filter = "all" | "unused" | "unknown" | "understated";

const SORT_LABEL: Record<SortKey, string> = {
  size: "Largest first",
  name: "Name",
  publisher: "Publisher",
  installed: "Recently installed",
  used: "Recently used",
};

const FILTER_LABEL: Record<Filter, string> = {
  all: "Everything",
  unused: "Not opened in a year",
  // Not "Never opened": the row itself says the absence of a record is not
  // proof, and the filter should not claim more than the row does.
  unknown: "No record of opening",
  understated: "Bigger than claimed",
};

/**
 * How long ago, in words.
 *
 * Days for the recent past, months and years beyond it. Nobody decides whether
 * to keep a program on whether it was 340 days or 350.
 */
function ago(seconds: number | null): string | null {
  if (seconds === null) return null;
  const days = Math.floor((Date.now() / 1000 - seconds) / 86400);
  if (days <= 0) return "today";
  if (days === 1) return "yesterday";
  if (days < 30) return `${days} days ago`;
  if (days < 60) return "a month ago";
  if (days < 365) return `${Math.floor(days / 30)} months ago`;
  const years = Math.floor(days / 365);
  return years === 1 ? "over a year ago" : `over ${years} years ago`;
}

function daysSince(seconds: number | null): number | null {
  if (seconds === null) return null;
  return Math.floor((Date.now() / 1000 - seconds) / 86400);
}

/** What this page keeps of its last measurement for the next time it opens. */
type KeptMeasurement = { drive: string; report: ApplicationReport };

/** Why a row of the registry's list has no size before anything is measured. */
const NOT_YET = "the drive has not been measured yet";

/**
 * The registry's list as it is now, with the sizes from a kept measurement
 * put beside the programs it measured.
 *
 * A size goes only to the same program, at the same version, from the same
 * publisher: one installed or updated since is not what was measured. Each
 * measured entry is used once, so two entries alike in all three do not
 * both take one size. Names, versions, dates and launches stay the
 * registry's own, read now.
 */
function withKeptSizes(
  listing: AppFootprint[],
  measured: AppFootprint[],
): { apps: AppFootprint[]; sized: Set<AppFootprint> } {
  const key = (app: AppFootprint) => `${app.name}\u0000${app.publisher}\u0000${app.version}`;
  const unclaimed = new Map<string, AppFootprint[]>();
  for (const app of measured) {
    const same = unclaimed.get(key(app));
    if (same) {
      same.push(app);
    } else {
      unclaimed.set(key(app), [app]);
    }
  }
  const sized = new Set<AppFootprint>();
  const apps = listing.map((app) => {
    const then = unclaimed.get(key(app))?.shift();
    if (!then) return app;
    const joined = {
      ...app,
      actual_bytes: then.actual_bytes,
      shared_bytes: then.shared_bytes,
      locations: then.locations,
    };
    sized.add(joined);
    return joined;
  });
  return { apps, sized };
}

const KIND_LABEL: Record<string, string> = {
  install: "Install",
  program_data: "ProgramData",
  local_data: "Local",
  roaming_data: "Roaming",
};

function Row({
  app,
  onReveal,
  onUninstall,
  measuring = false,
  notMeasured = null,
}: {
  app: AppFootprint;
  onReveal: (path: string) => void;
  onUninstall: (app: AppFootprint) => void;
  /** True while this row came from the registry and has no measurement yet. */
  measuring?: boolean;
  /** Why the measurement failed, when it did. The row is a claim, not a size. */
  notMeasured?: string | null;
}) {
  const [open, setOpen] = useState(false);
  // Zero measured bytes and zero directories found are different claims. The
  // first says an application uses no space; the second says we could not find
  // it -- usually because it lives on another drive. Two more cases join them:
  // nobody has looked yet, and somebody tried and could not.
  const unmeasured = measuring || notMeasured !== null;
  const notFound = !unmeasured && app.locations.length === 0;
  const ratio =
    !unmeasured && app.reported_bytes && app.reported_bytes > 0
      ? app.actual_bytes / app.reported_bytes
      : null;

  return (
    <li className="app-row">
      <button className="app-head" onClick={() => setOpen(!open)}>
        <span className="app-caret">{open ? "▾" : "▸"}</span>
        <span className="app-name">
          {app.name}
          <span className="app-meta">
            {app.publisher && <span className="app-publisher">{app.publisher}</span>}
            {app.version && <span className="app-version">v{app.version}</span>}
            {app.installed_on && (
              <span className="app-when">installed {app.installed_on}</span>
            )}
            <span
              className={`app-when${app.last_used === null ? " app-when-never" : ""}`}
              title={
                app.last_used === null
                  ? "Explorer has no record of this account launching it. Something started by a service, a terminal or another account leaves no trace, so this is not proof it was never run."
                  : `${app.launches ?? 0} ${app.launches === 1 ? "launch" : "launches"} recorded`
              }
            >
              {app.last_used === null
                ? "no record of opening it"
                : `opened ${ago(app.last_used)}`}
            </span>
          </span>
        </span>
        <span className="app-reported">
          {app.reported_bytes === null ? (
            <span className="app-none">not reported</span>
          ) : (
            fmt.bytes(app.reported_bytes)
          )}
        </span>
        <span className="app-actual">
          {measuring ? (
            <span className="app-none" title="Reading the file table">
              {NOT_MEASURED}
            </span>
          ) : notMeasured !== null ? (
            <span className="app-none" title={`Not measured: ${notMeasured}`}>
              not measured
            </span>
          ) : notFound ? (
            <span className="app-none">not found here</span>
          ) : (
            fmt.bytes(app.actual_bytes)
          )}
        </span>
        <span className="app-ratio">
          {ratio !== null && ratio >= 1.5 && (
            <span className="ratio-badge">{ratio.toFixed(1)}×</span>
          )}
        </span>
      </button>

      {open && (
        <>
          <div className="app-actions">
            {app.uninstall_command ? (
              <>
                <button onClick={() => onUninstall(app)}>Uninstall…</button>
                <span className="muted">
                  Runs this application's own uninstaller. Nothing here removes
                  files itself.
                </span>
              </>
            ) : (
              <span className="muted">
                This application publishes no uninstall command, so there is
                nothing to run. Store apps and package-manager installs are
                usually removed through whatever installed them.
              </span>
            )}
          </div>
          <ul className="app-locations">
          {notMeasured !== null && (
            <li className="app-location-empty">
              Where this application keeps its files was not measured:{" "}
              {notMeasured}
            </li>
          )}
          {notFound && (
            <li className="app-location-empty">
              No directories for this application were found on this drive. It
              is most likely installed on another one. Measure that drive to
              see it.
            </li>
          )}
          {app.locations.map((location) => (
            <li
              key={location.path}
              className={"app-location" + (location.shared_with > 0 ? " shared" : "")}
            >
              <span className="loc-kind">{KIND_LABEL[location.kind] ?? location.kind}</span>
              <button
                className="loc-path link"
                title={`Show ${location.path} in Explorer`}
                onClick={() => onReveal(location.path)}
              >
                {location.path}
              </button>
              <span className="loc-size">{fmt.bytes(location.bytes)}</span>
              {location.shared_with > 0 && (
                <span className="loc-shared">
                  shared with {location.shared_with} other
                  {location.shared_with === 1 ? "" : "s"}, not counted
                </span>
              )}
            </li>
          ))}
          </ul>
        </>
      )}
    </li>
  );
}

/**
 * Confirmation before an uninstaller runs.
 *
 * It shows the command verbatim. That string came out of the registry, written
 * by whoever built the installer, and the user is about to run it as
 * themselves — paraphrasing it would be hiding the only thing worth checking.
 */
function ConfirmUninstall({
  app,
  onCancel,
  onConfirm,
}: {
  app: AppFootprint;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  return (
    <div className="modal-ground" onClick={onCancel}>
      <div className="modal" onClick={(event) => event.stopPropagation()}>
        <h2>Uninstall {app.name}?</h2>
        <p className="muted">
          This hands over to the application's own uninstaller: KAM Security
          does not delete anything itself, and cannot undo what that uninstaller
          does. It may ask for administrator rights, and it may leave data
          behind, which Cleanup can find afterwards.
        </p>
        <p className="modal-label">The command that will run</p>
        <pre className="command">{app.uninstall_command}</pre>
        {app.actual_bytes > 0 && (
          <p className="muted">
            {fmt.bytes(app.actual_bytes)} measured across{" "}
            {app.locations.length} location
            {app.locations.length === 1 ? "" : "s"}.
          </p>
        )}
        <div className="modal-actions">
          <button onClick={onCancel}>Cancel</button>
          <button className="primary" onClick={onConfirm}>
            Run the uninstaller
          </button>
        </div>
      </div>
    </div>
  );
}

/**
 * Why a leftover has no box, or why moving it failed.
 *
 * The agent asks the quarantine fence about every leftover before listing it,
 * and the fence only takes a folder directly inside ProgramData or an AppData
 * root. Program Files folders, folders nested deeper and shortcuts were all
 * offered with a box anyway, and ticking them produced nothing but refusals.
 */
function LeftoverRefusal({
  quarantinable,
  why,
  failed,
}: {
  quarantinable?: boolean;
  why?: string | null;
  /** True when quarantine was asked and said no, rather than predicted to. */
  failed: boolean;
}) {
  if (failed) {
    return <span className="leftover-meta">Could not be moved: {why}</span>;
  }
  if (quarantinable) {
    return null;
  }
  return (
    <span className="leftover-meta">
      Quarantine will not take this:{" "}
      {why ?? "the agent did not say whether it would, so it is not offered"}
    </span>
  );
}

/** Keeps the text of a row with no box in line with the rows that have one. */
const NO_BOX = { flex: "none", width: 13 } as const;

/**
 * What could not be said about a removed program's shortcuts, in sentences.
 *
 * The window reads shortcuts itself, as you, because where one leads is a
 * question about your own session and the service is not in it. Two things
 * can still go unread: all of them, or some that would not open. Either is a
 * thing not known, and an empty list of leftover shortcuts is only "none
 * left" when this comes back empty too.
 */
function shortcutGaps(left: Remnants): string[] {
  const gaps: string[] = [];
  if (left.shortcuts_checked !== true) {
    gaps.push(
      `Shortcuts could not be read, so whether any of ${left.name}'s are left is not known.`,
    );
  }
  const unread = left.shortcuts_unread ?? 0;
  if (unread > 0) {
    gaps.push(
      unread === 1
        ? `1 shortcut on this PC would not open, so whether it was ${left.name}'s is not known.`
        : `${fmt.count(unread)} shortcuts on this PC would not open, so whether any of them was ${left.name}'s is not known.`,
    );
  }
  return gaps;
}

export default function Applications({ volumes, onMeasured }: Props) {
  const [drive, setDrive] = useState("C:\\");
  const [report, setReport] = useState<ApplicationReport | null>(null);
  /** When the measurement on screen finished, by this computer's clock. */
  const [measuredAt, setMeasuredAt] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const [confirming, setConfirming] = useState<AppFootprint | null>(null);

  // Names an uninstaller was launched for and whose result has not been
  // measured yet. A ref rather than state because the focus handler below
  // reads it from outside React's render cycle.
  const awaitingUninstall = useRef<AppFootprint | null>(null);
  // Whether this wait has already said the program is still installed. Said
  // once: every later return to the window looks again without repeating it.
  const toldStillInstalled = useRef(false);
  const [remnants, setRemnants] = useState<Remnants | null>(null);
  const [chosen, setChosen] = useState<Set<string>>(new Set());
  const [clearing, setClearing] = useState(false);
  /**
   * Leftovers quarantine refused when asked, by path, with its reason.
   *
   * Held beside the list rather than in `error`, because the re-measure that
   * follows a clear resets `error` before anybody could read it, and the
   * person was left with a success message for a move that did not happen.
   */
  const [refusedMoves, setRefusedMoves] = useState<Record<string, string>>({});
  /** What could not be said about an uninstall's leftovers, and why. */
  const [leftoverWarning, setLeftoverWarning] = useState<string | null>(null);
  /** Why the last measurement failed, while its preview is still on screen. */
  const [unmeasured, setUnmeasured] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [sort, setSort] = useState<SortKey>("size");
  const [filter, setFilter] = useState<Filter>("all");
  const [grouped, setGrouped] = useState(false);
  /** The registry's own list, shown while the disk is being read. */
  const [preview, setPreview] = useState<AppFootprint[] | null>(null);
  /** Why the registry's list could not be read when the page opened. */
  const [listError, setListError] = useState<string | null>(null);
  /** The last measurement, as kept for the next time the page opens. */
  const [kept, setKept] = useState<Kept<KeptMeasurement> | null>(null);
  /** Why the measurement kept from before could not be read back. */
  const [keptUnreadable, setKeptUnreadable] = useState<string | null>(null);
  /** Why the last measurement could not be kept for next time. */
  const [notKept, setNotKept] = useState<string | null>(null);
  /**
   * Whether a measurement has arrived since the page opened, so the one kept
   * from before, read back a moment later, is not put over it.
   */
  const arrived = useRef(false);

  /**
   * What a measurement came to, whether it ended while this page was open or
   * while it was not. It is kept for next time before this returns, because
   * the window's own half lets go of it once this has run.
   */
  async function measured(outcome: PageJobOutcome<ApplicationReport>) {
    const ended = outcome.view.ended;
    const result = outcome.answer;
    if (ended?.how === "finished" && result !== null) {
      arrived.current = true;
      const measuredDrive =
        outcome.view.asked.slot === "applications" ? outcome.view.asked.drive : drive;
      setReport(result);
      setMeasuredAt(ended.at);
      setPreview(null);
      setError(null);
      setUnmeasured(null);
      // Kept without the lists Cleanup shows, which this page does not.
      const keeping: KeptMeasurement = {
        drive: measuredDrive,
        report: { ...result, orphans: [], downloads: [], old_files: [] },
      };
      setKept({ measuredAt: ended.at, result: keeping });
      setKeptUnreadable(null);
      setNotKept(await remember("applications", ended.at, keeping));
    } else if (ended?.how === "failed") {
      setError(ended.reason);
      setUnmeasured(ended.reason);
      setReport(null);
      // The preview stays: knowing what is installed is still worth having
      // when the measurement is what failed. It is marked as not measured
      // rather than left saying it is being measured.
    }
    onMeasured();
  }
  const measureJob = usePageJob<ApplicationReport>("applications", measured);
  const running = measureJob.running;
  /** The drive being measured now, which the picker shows meanwhile. */
  const measuringDrive =
    measureJob.running && measureJob.view?.asked.slot === "applications"
      ? measureJob.view.asked.drive
      : null;

  // On opening: the registry's list at once, which is a fifth of a second
  // and needs nothing, and the sizes from the last measurement, as kept.
  useEffect(() => {
    let open = true;
    api
      .applicationsPreview()
      .then((listing) => {
        if (open) setPreview((current) => current ?? listing);
      })
      .catch((cause) => {
        if (open) setListError(reason(cause));
      });
    recall<KeptMeasurement>("applications")
      .then((found) => {
        if (!open || found === null || arrived.current) return;
        setKept(found);
        setDrive(found.result.drive);
      })
      .catch((cause) => {
        if (open) setKeptUnreadable(reason(cause));
      });
    return () => {
      open = false;
    };
  }, []);

  /**
   * Measure, in two parts, because the two halves cost wildly different
   * amounts.
   *
   * What an installer *claims* is a registry read: every name, publisher,
   * version, install date and claimed size on the machine, in about a fifth of
   * a second, needing no privileges. What it actually occupies needs the whole
   * master file table, which is over a second and a half.
   *
   * Waiting for the second before showing the first meant a second and a half
   * of nothing on screen for a list that already existed. Now the list appears
   * at once and can be searched, sorted and grouped immediately; only the size
   * column has to wait, and it says it is waiting rather than showing a zero.
   *
   * The measuring is the window's own half's to do, so it carries on if this
   * page is left, and `measured` takes what it came to. While one is going,
   * asking again (after an uninstaller, say) follows that one.
   */
  const startMeasuring = measureJob.start;
  const measure = useCallback(async () => {
    if (running) return;
    setError(null);
    setUnmeasured(null);
    setReport(null);

    // Not awaited: the point is that the expensive half is already underway
    // while this is being drawn.
    void api
      .applicationsPreview()
      .then((listing) => setPreview(listing))
      .catch(() => {
        // The measured list is the real answer; failing to preview it is not
        // worth an error message.
      });

    try {
      await startMeasuring({ slot: "applications", drive });
    } catch (cause) {
      setError(reason(cause));
    }
  }, [drive, running, startMeasuring]);

  /**
   * Re-measure when the window comes back after an uninstaller ran.
   *
   * An uninstaller is a separate program that takes as long as it takes, and
   * the list is a snapshot from before it started, so an entry stays on screen
   * for something that has already gone. Refreshing the instant the uninstaller
   * is launched would be worse than useless: nothing has been removed yet.
   *
   * Returning to this window is the honest signal that the uninstaller is
   * done with, and it costs nothing to watch for. Polling the registry would
   * be guessing at a moment the person can simply tell us by coming back.
   *
   * It is a signal that something may have happened, though, and no more.
   * The person may have cancelled the uninstaller, or clicked back here while
   * it was still running. This used to announce "was uninstalled" on that
   * signal alone and offer the program's own data folders for quarantine. So
   * the agent now looks the program up again first, and while Windows still
   * lists it this says so, offers nothing, and goes on waiting.
   */
  useEffect(() => {
    function recheck() {
      const app = awaitingUninstall.current;
      if (!app || document.hidden) {
        return;
      }
      awaitingUninstall.current = null;
      const firstLook = !toldStillInstalled.current;
      if (firstLook) {
        setNote(`Checking whether ${app.name} has gone…`);
      }

      // The footprint has to come from before the uninstall: afterwards the
      // registry entry is gone and there is nothing left to measure from.
      void api
        .findRemnants(
          app.name,
          app.locations.map((location) => location.path),
          app.locations.map((location) => location.kind),
        )
        .then((left) => {
          if (left.still_installed) {
            // Unless another uninstaller was started meanwhile, in which case
            // that one is what is being waited for.
            const stillWaiting = awaitingUninstall.current === null;
            if (stillWaiting) {
              awaitingUninstall.current = app;
            }
            if (firstLook) {
              toldStillInstalled.current = stillWaiting;
              setNote(
                `${app.name} is still installed. Its uninstaller was cancelled ` +
                  `or has not finished.` +
                  // Promised only where it is true: one program is waited
                  // for at a time.
                  (stillWaiting
                    ? ` KAM Security will look again when you come back to this window.`
                    : ""),
              );
            }
            // Nothing changed, so there is nothing to measure again.
            return false;
          }

          toldStillInstalled.current = false;
          setLeftoverWarning(null);
          setRefusedMoves({});
          setChosen(new Set());
          const anything = left.locations.length > 0 || left.shortcuts.length > 0;
          // "Left nothing behind" is a claim about every place it used and
          // every shortcut it had. A place that was not examined, or a
          // shortcut that could not be read, makes it a claim nobody checked.
          const unexamined = left.refused.length;
          const gaps = shortcutGaps(left);
          if (unexamined > 0) {
            gaps.unshift(
              `${unexamined} of the places ${app.name} used could not be examined, ` +
                `so whether anything is left there is not known.`,
            );
          }
          setRemnants(anything || unexamined > 0 ? left : null);
          setNote(
            anything
              ? `${app.name} was uninstalled, but some of it is still on disk.`
              : gaps.length > 0
                ? `${app.name} was uninstalled.`
                : `${app.name} was uninstalled and left nothing behind.`,
          );
          if (!anything && gaps.length > 0) {
            setLeftoverWarning(gaps.join(" "));
          }
          return true;
        })
        .catch((cause) => {
          // Neither half is known now: not whether it went, nor what it left.
          toldStillInstalled.current = false;
          setNote(null);
          setLeftoverWarning(
            `Whether ${app.name} was uninstalled, and what it left behind, ` +
              `could not be checked: ${reason(cause)}`,
          );
          return true;
        })
        .then((changed) => {
          if (changed) void measure();
        });
    }

    window.addEventListener("focus", recheck);
    document.addEventListener("visibilitychange", recheck);
    return () => {
      window.removeEventListener("focus", recheck);
      document.removeEventListener("visibilitychange", recheck);
    };
  }, [measure]);

  async function uninstall(app: AppFootprint) {
    setConfirming(null);
    setError(null);
    try {
      await api.uninstall(app.name, app.uninstall_command ?? "");
      awaitingUninstall.current = app;
      toldStillInstalled.current = false;
      setNote(
        `Started the uninstaller for ${app.name}. This list still shows what ` +
          `was there before it ran, and will measure again when you come back ` +
          `to this window.`,
      );
    } catch (cause) {
      setError(reason(cause));
    } finally {
      onMeasured();
    }
  }

  function toggle(path: string) {
    setChosen((current) => {
      const next = new Set(current);
      if (next.has(path)) {
        next.delete(path);
      } else {
        next.add(path);
      }
      return next;
    });
  }

  /**
   * Quarantine everything ticked.
   *
   * One item at a time and through quarantine, never a delete: each gets its
   * own manifest and its own thirty days, so a wrong choice here is one that
   * can be taken back.
   */
  async function clearChosen() {
    if (!remnants || chosen.size === 0) {
      return;
    }
    setClearing(true);
    setError(null);

    let reclaimed = 0;
    const moved = new Set<string>();
    const failures: Record<string, string> = {};

    for (const path of chosen) {
      const location = remnants.locations.find((item) => item.path === path);
      try {
        await api.quarantine(
          path,
          `left behind by ${remnants.name} after it was uninstalled`,
        );
        moved.add(path);
        reclaimed += location?.bytes ?? 0;
      } catch (cause) {
        failures[path] = reason(cause);
      }
    }
    const taken = moved.size;
    const failed = Object.keys(failures).length;

    setClearing(false);
    setChosen(new Set());
    setRefusedMoves(failures);
    if (failed > 0) {
      // What was moved leaves the list; what was not stays on it, with the
      // reason beside it, rather than the whole list vanishing as if it had
      // all gone.
      const remaining = remnants.locations.filter((item) => !moved.has(item.path));
      setRemnants({
        ...remnants,
        locations: remaining,
        shortcuts: remnants.shortcuts.filter((item) => !moved.has(item.path)),
        total_bytes: remaining.reduce((total, item) => total + item.bytes, 0),
      });
    } else {
      setRemnants(null);
    }
    // Only a move that happened is reported as one. Nothing moved is not a
    // success with a count of zero.
    setNote(
      taken > 0
        ? `Moved ${taken} item${taken === 1 ? "" : "s"} into quarantine` +
            (reclaimed > 0 ? `, reclaiming ${fmt.bytes(reclaimed)}` : "") +
            ". Restorable for 30 days from Cleanup." +
            (failed > 0
              ? ` ${failed} could not be moved and ${failed === 1 ? "is" : "are"} still listed below.`
              : "")
        : null,
    );
    void measure();
  }

  async function reveal(path: string) {
    try {
      await api.reveal(path);
    } catch (cause) {
      setError(reason(cause));
    }
  }

  /**
   * The list actually shown: filtered, then searched, then sorted.
   *
   * Done here rather than in the agent because it is a question about the
   * answer, not a question about the machine — re-measuring the disk to sort
   * by name would be absurd, and every one of these turns on data already in
   * hand.
   */
  // Showing the registry's list and not the measured one means one of two
  // things, and they must not look alike: the measurement is still running, or
  // it failed. This read `report === null && preview !== null` alone, so after
  // a failure the page went on saying it was measuring, indefinitely.
  const measuring = running && report === null && preview !== null;
  // The registry's list with the last measurement's sizes beside it: when
  // the page opens on a kept measurement, until it measures again. A
  // measurement that fails says so instead, rather than leaving older sizes
  // standing in for it.
  const showingKept =
    !running && report === null && unmeasured === null && kept !== null && preview !== null;
  const keptSizes = useMemo(
    () => (kept && preview ? withKeptSizes(preview, kept.result.report.apps) : null),
    [kept, preview],
  );
  /** The registry's list alone, before this account has measured anything. */
  const neverMeasured =
    !running && report === null && preview !== null && unmeasured === null && kept === null;
  const notMeasured =
    !running && report === null && preview !== null && !showingKept
      ? (unmeasured ?? NOT_YET)
      : null;
  /** Why one row of the list has no size beside it, or null when it has one. */
  const keptWhy = kept
    ? `it was not installed, or not at this version, when ${kept.result.drive} was measured at ${whenMeasured(kept.measuredAt)}`
    : NOT_YET;
  const rowNotMeasured = (app: AppFootprint): string | null =>
    showingKept ? (keptSizes?.sized.has(app) ? null : keptWhy) : notMeasured;
  /** Whichever list is in hand. */
  const listed: AppFootprint[] =
    report?.apps ?? (showingKept && keptSizes ? keptSizes.apps : preview) ?? [];
  /** Whichever list is in hand, for the counts beside the filters. */
  const everything = listed;

  const shown = useMemo(() => {
    const apps = listed;
    const needle = query.trim().toLowerCase();

    const kept = apps.filter((app) => {
      if (needle) {
        const haystack = `${app.name} ${app.publisher}`.toLowerCase();
        if (!haystack.includes(needle)) return false;
      }
      switch (filter) {
        case "unused": {
          const days = daysSince(app.last_used);
          return days !== null && days >= 365;
        }
        case "unknown":
          return app.last_used === null;
        case "understated":
          return (
            app.reported_bytes !== null &&
            app.reported_bytes > 0 &&
            app.actual_bytes / app.reported_bytes >= 1.5
          );
        default:
          return true;
      }
    });

    const order = [...kept];
    order.sort((a, b) => {
      switch (sort) {
        case "name":
          return a.name.localeCompare(b.name, undefined, { sensitivity: "base" });
        case "publisher":
          return (
            (a.publisher || "\uffff").localeCompare(b.publisher || "\uffff", undefined, {
              sensitivity: "base",
            }) || b.actual_bytes - a.actual_bytes
          );
        case "installed":
          // Unknown dates sort last rather than pretending to be old.
          return (b.installed_on ?? "").localeCompare(a.installed_on ?? "");
        case "used":
          // Never-opened sorts last: it is the absence of a date, not an old one.
          return (b.last_used ?? -1) - (a.last_used ?? -1);
        default:
          return b.actual_bytes - a.actual_bytes;
      }
    });
    return order;
  }, [listed, query, filter, sort]);

  const shownBytes = useMemo(
    () => shown.reduce((total, app) => total + app.actual_bytes, 0),
    [shown],
  );

  /** Publishers, largest first, when grouping is on. */
  const groups = useMemo(() => {
    if (!grouped) return null;
    const byPublisher = new Map<string, AppFootprint[]>();
    for (const app of shown) {
      const key = app.publisher || "No publisher named";
      const list = byPublisher.get(key);
      if (list) {
        list.push(app);
      } else {
        byPublisher.set(key, [app]);
      }
    }
    return [...byPublisher.entries()]
      .map(([publisher, apps]) => ({
        publisher,
        apps,
        bytes: apps.reduce((total, app) => total + app.actual_bytes, 0),
      }))
      .sort((a, b) => b.bytes - a.bytes);
  }, [shown, grouped]);

  /** The measurement the figures are from: this page's, or the one kept. */
  const measurement = report ?? (showingKept ? (kept?.result.report ?? null) : null);
  const summary = measurement?.summary;
  const figuresAt = report ? measuredAt : (kept?.measuredAt ?? 0);

  return (
    <>
      <div className="view-head">
        <div>
          <h1>Applications</h1>
          <p className="lede">
            What each installed program really occupies, against the size its
            own installer claimed.
          </p>
        </div>
      </div>

      <section className="panel">
        <div className="scan-bar">
          <select
            value={measuringDrive ?? drive}
            onChange={(event) => setDrive(event.target.value)}
            disabled={running}
          >
            {volumes
              .filter((volume) => volume.supports_mft)
              .map((volume) => (
                <option key={volume.root} value={volume.root}>
                  {volume.root} {volume.label ? `(${volume.label})` : ""}
                </option>
              ))}
          </select>
          <button className="primary" onClick={() => void measure()} disabled={running}>
            {running ? "Measuring…" : "Measure"}
          </button>
          <span className="muted">
            Reads the master file table, so the agent must be running with
            administrative rights.
          </span>
        </div>

        {error && <pre className="error">{error}</pre>}
        {listError && !report && (
          <div className="notice notice-warn">
            The list of installed programs could not be read from the registry:{" "}
            {listError.replace(/\.$/, "")}.
          </div>
        )}
        {keptUnreadable && !report && !running && (
          <UnreadableNote
            what="The last measurement"
            why={keptUnreadable}
            again="Press Measure to measure again."
          />
        )}
        {notKept && <NotKeptNote why={notKept} />}
        {showingKept && kept && (
          <KeptNote
            what={`the measurement of ${kept.result.drive}`}
            at={kept.measuredAt}
            again="The list of programs below is the registry's, read now; only the sizes are from then. Press Measure to measure them again."
          />
        )}
        {note && <div className="notice notice-ok">{note}</div>}
        {leftoverWarning && (
          <div className="notice notice-warn">{leftoverWarning}</div>
        )}

        {remnants && (
          <div className="notice notice-warn leftovers">
            <strong>
              {remnants.locations.length + remnants.shortcuts.length > 0
                ? `${remnants.name} is gone, but ${fmt.bytes(remnants.total_bytes)} of it is not.`
                : `${remnants.name} is gone, and some of what it used was not examined.`}
            </strong>
            {remnants.locations.length + remnants.shortcuts.length > 0 && (
              <p className="leftover-lede">
                Its uninstaller has finished and these are still on disk. Tick
                what should go: it moves to quarantine and can be restored for
                thirty days. Anything quarantine will not take has no box, and
                says why.
              </p>
            )}

            <ul className="leftover-list">
              {remnants.locations.map((item) => (
                <li key={item.path}>
                  <label>
                    {item.quarantinable ? (
                      <input
                        type="checkbox"
                        checked={chosen.has(item.path)}
                        onChange={() => toggle(item.path)}
                        disabled={clearing}
                      />
                    ) : (
                      <span style={NO_BOX} aria-hidden="true" />
                    )}
                    <span className="leftover-body">
                      <PathLink path={item.path} className="leftover-path" />
                      <span className="leftover-meta">
                        {fmt.bytes(item.bytes)}
                        {item.partial ? " or more" : ""} · {fmt.count(item.files)}{" "}
                        {item.files === 1 ? "file" : "files"}
                      </span>
                      <LeftoverRefusal
                        quarantinable={item.quarantinable}
                        why={refusedMoves[item.path] ?? item.quarantine_refusal}
                        failed={item.path in refusedMoves}
                      />
                    </span>
                  </label>
                </li>
              ))}

              {remnants.shortcuts.map((shortcut) => (
                <li key={shortcut.path}>
                  <label>
                    {shortcut.quarantinable ? (
                      <input
                        type="checkbox"
                        checked={chosen.has(shortcut.path)}
                        onChange={() => toggle(shortcut.path)}
                        disabled={clearing}
                      />
                    ) : (
                      <span style={NO_BOX} aria-hidden="true" />
                    )}
                    <span className="leftover-body">
                      <PathLink path={shortcut.path} className="leftover-path">
                        {shortcut.name}
                      </PathLink>
                      <span className="leftover-meta">
                        {shortcut.place === "start_menu"
                          ? "Start Menu"
                          : shortcut.place === "desktop"
                            ? "Desktop"
                            : "Taskbar"}{" "}
                        shortcut
                        {shortcut.broken ? " · points at something that is gone" : ""}
                        {/* Not the same as gone, and not said as if it were:
                            this one may still work. */}
                        {shortcut.target_unknown
                          ? " · what it points at could not be checked"
                          : ""}
                        {shortcut.machine_wide ? " · for everyone on this PC" : ""}
                      </span>
                      <LeftoverRefusal
                        quarantinable={shortcut.quarantinable}
                        why={refusedMoves[shortcut.path] ?? shortcut.quarantine_refusal}
                        failed={shortcut.path in refusedMoves}
                      />
                    </span>
                  </label>
                </li>
              ))}
            </ul>

            {remnants.refused.length > 0 && (
              <div className="footnote">
                {remnants.refused.length} location
                {remnants.refused.length === 1 ? " was" : "s were"} not examined:
                outside the folders this looks in, or there but impossible to
                resolve. Whether anything is left in{" "}
                {remnants.refused.length === 1 ? "it" : "them"} is not known.
                <ul className="leftover-list">
                  {remnants.refused.map((path) => (
                    <li key={path}>
                      <PathLink path={path} className="leftover-path" />
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {shortcutGaps(remnants).map((gap) => (
              <div key={gap} className="footnote">
                {gap}
              </div>
            ))}

            <div className="confirm-actions">
              <button
                onClick={() => void clearChosen()}
                disabled={clearing || chosen.size === 0}
              >
                {clearing
                  ? "Moving…"
                  : chosen.size === 0
                    ? "Nothing ticked"
                    : `Quarantine ${chosen.size} item${chosen.size === 1 ? "" : "s"}`}
              </button>
              <button
                className="link-button"
                onClick={() =>
                  setChosen(
                    new Set(
                      remnants.locations
                        .filter((item) => item.quarantinable)
                        .map((item) => item.path),
                    ),
                  )
                }
                disabled={clearing}
              >
                Tick every folder
              </button>
              <button
                className="link-button"
                onClick={() => {
                  setRemnants(null);
                  setRefusedMoves({});
                }}
                disabled={clearing}
              >
                Leave it
              </button>
            </div>
          </div>
        )}

        {summary && (
          <div className="stat-row tight">
            <div className="stat">
              <span className="stat-label">Applications</span>
              <span className="stat-value">{fmt.count(summary.applications)}</span>
            </div>
            <div className="stat">
              <span className="stat-label">Actually using</span>
              <span className="stat-value">{fmt.bytes(summary.measured_bytes)}</span>
            </div>
            <div className="stat">
              <span className="stat-label">Control Panel claims</span>
              <span className="stat-value">{fmt.bytes(summary.reported_bytes)}</span>
            </div>
            <div className="stat">
              <span className="stat-label">Report no size at all</span>
              <span className="stat-value">
                {fmt.count(summary.without_reported_size)}
              </span>
            </div>
            {measurement && (
              <div
                className="stat"
                title={
                  `File table ${measurement.timings.read_table} ms ` +
                  `(${measurement.timings.read_table_io} ms of it waiting on the disk), ` +
                  `index ${measurement.timings.build_index} ms, ` +
                  `applications ${measurement.timings.applications} ms, ` +
                  `leftovers ${measurement.timings.orphans} ms, ` +
                  `downloads ${measurement.timings.downloads} ms`
                }
              >
                <span className="stat-label">Measured in</span>
                <span className="stat-value">
                  {fmt.duration(measurement.timings.total)}
                  <span className="unit">
                    {fmt.count(measurement.timings.records)} records
                  </span>
                </span>
              </div>
            )}
            {measurement && <MeasuredAt at={figuresAt} />}
          </div>
        )}

        {summary && (summary.data_roots_elsewhere ?? []).length > 0 && (
          // A program's data is measured where it really is. Measuring
          // another drive used to look these folders up by name on the drive
          // it was given, and show whatever it found there under these paths.
          <div className="notice notice-warn">
            These sizes count only what is on the drive that was measured.
            Program data is kept in {summary.data_roots_elsewhere.join(", ")},
            on another drive, so none of it is included here. Measure that
            drive to see it.
          </div>
        )}
      </section>

      <NewerVersions />

      {(report || preview) && (
        <section className="panel">
          <div className="panel-head">
            <h2>
              {measuring || notMeasured !== null || showingKept
                ? "Installed applications"
                : "By real size"}
            </h2>
            {measuring && <span className="measuring">Measuring real sizes…</span>}
            {notMeasured !== null && (
              <span className="measuring">{neverMeasured ? "Not measured yet" : "Not measured"}</span>
            )}
            {showingKept && kept && (
              <span className="measuring">Sizes from {whenMeasured(kept.measuredAt)}</span>
            )}
          </div>
          <p className="muted">
            {measuring
              ? "This is what the installers say about themselves, read from the registry. The measured sizes are being read off the disk now and will replace the claims when they arrive; searching, sorting and grouping all work in the meantime."
              : neverMeasured
                ? "This is what the installers say about themselves, read from the registry just now. Their real sizes come from Measure, which reads them off the disk; until then the Actual column says they were not measured rather than showing a number nobody read."
                : notMeasured !== null
                  ? `This is what the installers say about themselves, read from the registry. Their real sizes were not measured: ${notMeasured}. The Actual column says so rather than showing a number nobody read.`
                  : showingKept && kept
                    ? `Names, publishers, versions, dates and launches are read from the registry now. Sizes are from the measurement of ${kept.result.drive} at ${whenMeasured(kept.measuredAt)}: a program installed or updated since then has none until you measure again, and says so. A folder matched by more than one application is listed but not added to any of their totals.`
                    : "A folder matched by more than one application (several NVIDIA packages sharing one data directory, for instance) is listed but not added to any of their totals. Totals understate rather than double-count."}
          </p>

          <div className="app-controls">
            <input
              type="search"
              className="app-search"
              placeholder="Filter by name or publisher"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
            />
            <select
              value={sort}
              onChange={(event) => setSort(event.target.value as SortKey)}
              aria-label="Sort by"
            >
              {(Object.keys(SORT_LABEL) as SortKey[]).map((key) => (
                <option key={key} value={key}>
                  {SORT_LABEL[key]}
                </option>
              ))}
            </select>
            <select
              value={filter}
              onChange={(event) => setFilter(event.target.value as Filter)}
              aria-label="Show"
            >
              {(Object.keys(FILTER_LABEL) as Filter[]).map((key) => (
                <option key={key} value={key}>
                  {FILTER_LABEL[key]}
                </option>
              ))}
            </select>
            <label className="app-group-toggle">
              <input
                type="checkbox"
                checked={grouped}
                onChange={(event) => setGrouped(event.target.checked)}
              />
              By publisher
            </label>
            <span className="app-count">
              {shown.length === everything.length
                ? `${fmt.count(shown.length)} shown`
                : `${fmt.count(shown.length)} of ${fmt.count(everything.length)}`}
              {shownBytes > 0 ? ` · ${fmt.bytes(shownBytes)}` : ""}
            </span>
          </div>

          <div className="app-header">
            <span />
            <span>Application</span>
            <span className="right">Reported</span>
            <span className="right">
              {measuring
                ? "Measuring…"
                : notMeasured !== null
                  ? "Not measured"
                  : showingKept && kept
                    ? `Measured ${whenMeasured(kept.measuredAt)}`
                    : "Actual"}
            </span>
            <span />
          </div>
          {shown.length === 0 ? (
            <p className="empty">
              Nothing matches. {everything.length > 0 && "Clear the filter to see everything again."}
            </p>
          ) : groups ? (
            groups.map((group) => (
              <div key={group.publisher} className="app-group-block">
                <div className="app-group-head">
                  <span className="app-group-name">{group.publisher}</span>
                  <span className="app-group-meta">
                    {fmt.count(group.apps.length)}{" "}
                    {group.apps.length === 1 ? "entry" : "entries"} · {fmt.bytes(group.bytes)}
                  </span>
                </div>
                <ul className="app-list">
                  {group.apps.map((app) => (
                    <Row
                      key={`${app.name}-${app.version}`}
                      app={app}
                      measuring={measuring}
                      notMeasured={rowNotMeasured(app)}
                      onReveal={(path) => void reveal(path)}
                      onUninstall={setConfirming}
                    />
                  ))}
                </ul>
              </div>
            ))
          ) : (
            <ul className="app-list">
              {shown.map((app) => (
                <Row
                  key={`${app.name}-${app.version}`}
                  app={app}
                  measuring={measuring}
                  notMeasured={rowNotMeasured(app)}
                  onReveal={(path) => void reveal(path)}
                  onUninstall={setConfirming}
                />
              ))}
            </ul>
          )}
        </section>
      )}

      {confirming && (
        <ConfirmUninstall
          app={confirming}
          onCancel={() => setConfirming(null)}
          onConfirm={() => void uninstall(confirming)}
        />
      )}

      {!report && !preview && !running && !error && !listError && !keptUnreadable && (
        <section className="panel">
          <p className="empty">Nothing measured yet. Pick a drive and press Measure.</p>
        </section>
      )}
    </>
  );
}
