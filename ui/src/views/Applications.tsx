import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api, reason } from "../lib/api";
import * as fmt from "../lib/format";
import PathLink from "../components/PathLink";
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
const NOT_MEASURED = "—";

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
  unknown: "Never opened",
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
  if (days < 365) return `${Math.floor(days / 30)} months ago`;
  const years = Math.floor(days / 365);
  return years === 1 ? "over a year ago" : `over ${years} years ago`;
}

function daysSince(seconds: number | null): number | null {
  if (seconds === null) return null;
  return Math.floor((Date.now() / 1000 - seconds) / 86400);
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
}: {
  app: AppFootprint;
  onReveal: (path: string) => void;
  onUninstall: (app: AppFootprint) => void;
  /** True while this row came from the registry and has no measurement yet. */
  measuring?: boolean;
}) {
  const [open, setOpen] = useState(false);
  // Zero measured bytes and zero directories found are different claims. The
  // first says an application uses no space; the second says we could not find
  // it -- usually because it lives on another drive. A third case joins them
  // while a measurement is running: nobody has looked yet.
  const notFound = !measuring && app.locations.length === 0;
  const ratio =
    !measuring && app.reported_bytes && app.reported_bytes > 0
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
                  : `${app.launches ?? 0} launches recorded`
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
          {notFound && (
            <li className="app-location-empty">
              No directories for this application were found on this drive. It
              is most likely installed on another one — measure that drive to
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
                  {location.shared_with === 1 ? "" : "s"} — not counted
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
          This hands over to the application's own uninstaller — KAM Security
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

export default function Applications({ volumes, onMeasured }: Props) {
  const [drive, setDrive] = useState("C:\\");
  const [report, setReport] = useState<ApplicationReport | null>(null);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const [confirming, setConfirming] = useState<AppFootprint | null>(null);

  // Names an uninstaller was launched for and whose result has not been
  // measured yet. A ref rather than state because the focus handler below
  // reads it from outside React's render cycle.
  const awaitingUninstall = useRef<AppFootprint | null>(null);
  const [remnants, setRemnants] = useState<Remnants | null>(null);
  const [chosen, setChosen] = useState<Set<string>>(new Set());
  const [clearing, setClearing] = useState(false);
  const [query, setQuery] = useState("");
  const [sort, setSort] = useState<SortKey>("size");
  const [filter, setFilter] = useState<Filter>("all");
  const [grouped, setGrouped] = useState(false);
  /** The registry's own list, shown while the disk is being read. */
  const [preview, setPreview] = useState<AppFootprint[] | null>(null);

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
   */
  const measure = useCallback(async () => {
    setRunning(true);
    setError(null);
    setReport(null);

    // Not awaited before the measurement starts: the point is that the
    // expensive half is already underway while this is being drawn.
    const showing = api
      .applicationsPreview()
      .then((listing) => setPreview(listing))
      .catch(() => {
        // The measured list is the real answer; failing to preview it is not
        // worth an error message.
      });

    try {
      const measured = await api.applications(drive);
      setReport(measured);
      setPreview(null);
    } catch (cause) {
      setError(reason(cause));
      setReport(null);
      // The preview stays: knowing what is installed is still worth having
      // when the measurement is what failed.
    } finally {
      await showing;
      setRunning(false);
      onMeasured();
    }
  }, [drive, onMeasured]);

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
   */
  useEffect(() => {
    function recheck() {
      const app = awaitingUninstall.current;
      if (!app || document.hidden) {
        return;
      }
      awaitingUninstall.current = null;
      setNote(`Checking what ${app.name} left behind…`);

      // The footprint has to come from before the uninstall: afterwards the
      // registry entry is gone and there is nothing left to measure from.
      void api
        .findRemnants(
          app.name,
          app.locations.map((location) => location.path),
          app.locations.map((location) => location.kind),
        )
        .then((left) => {
          const anything = left.locations.length > 0 || left.shortcuts.length > 0;
          setRemnants(anything ? left : null);
          setNote(
            anything
              ? `${app.name} was uninstalled, but some of it is still on disk.`
              : `${app.name} was uninstalled and left nothing behind.`,
          );
        })
        .catch(() => setNote(`${app.name} was uninstalled.`))
        .finally(() => void measure());
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

    let taken = 0;
    let reclaimed = 0;
    const failures: string[] = [];

    for (const path of chosen) {
      const location = remnants.locations.find((item) => item.path === path);
      try {
        await api.quarantine(
          path,
          `left behind by ${remnants.name} after it was uninstalled`,
        );
        taken += 1;
        reclaimed += location?.bytes ?? 0;
      } catch (cause) {
        failures.push(`${path}: ${reason(cause)}`);
      }
    }

    setClearing(false);
    setChosen(new Set());
    setRemnants(null);
    if (failures.length > 0) {
      setError(`Some items could not be moved:\n${failures.join("\n")}`);
    }
    setNote(
      `Moved ${taken} item${taken === 1 ? "" : "s"} into quarantine` +
        (reclaimed > 0 ? `, reclaiming ${fmt.bytes(reclaimed)}` : "") +
        ". Restorable for 30 days from Cleanup.",
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
  const measuring = report === null && preview !== null;
  /** Whichever list is in hand, for the counts beside the filters. */
  const everything = report?.apps ?? preview ?? [];

  const shown = useMemo(() => {
    const apps = report?.apps ?? preview ?? [];
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
  }, [report, preview, query, filter, sort]);

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

  const summary = report?.summary;

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
            value={drive}
            onChange={(event) => setDrive(event.target.value)}
            disabled={running}
          >
            {volumes
              .filter((volume) => volume.supports_mft)
              .map((volume) => (
                <option key={volume.root} value={volume.root}>
                  {volume.root} {volume.label ? `— ${volume.label}` : ""}
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
        {note && <div className="notice notice-ok">{note}</div>}

        {remnants && (
          <div className="notice notice-warn leftovers">
            <strong>
              {remnants.name} is gone, but {fmt.bytes(remnants.total_bytes)} of
              it is not.
            </strong>
            <p className="leftover-lede">
              Its own uninstaller cleared the install folder and left the rest.
              Tick what should go. Everything moves to quarantine and can be
              restored for thirty days, so nothing here is deleted.
            </p>

            <ul className="leftover-list">
              {remnants.locations.map((item) => (
                <li key={item.path}>
                  <label>
                    <input
                      type="checkbox"
                      checked={chosen.has(item.path)}
                      onChange={() => toggle(item.path)}
                      disabled={clearing}
                    />
                    <span className="leftover-body">
                      <PathLink path={item.path} className="leftover-path" />
                      <span className="leftover-meta">
                        {fmt.bytes(item.bytes)}
                        {item.partial ? " or more" : ""} · {fmt.count(item.files)} files
                      </span>
                    </span>
                  </label>
                </li>
              ))}

              {remnants.shortcuts.map((shortcut) => (
                <li key={shortcut.path}>
                  <label>
                    <input
                      type="checkbox"
                      checked={chosen.has(shortcut.path)}
                      onChange={() => toggle(shortcut.path)}
                      disabled={clearing}
                    />
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
                        {shortcut.machine_wide ? " · for everyone on this PC" : ""}
                      </span>
                    </span>
                  </label>
                </li>
              ))}
            </ul>

            {remnants.refused.length > 0 && (
              <p className="footnote">
                {remnants.refused.length} location
                {remnants.refused.length === 1 ? " was" : "s were"} outside the
                folders this will touch and {remnants.refused.length === 1 ? "was" : "were"}{" "}
                not examined.
              </p>
            )}

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
                  setChosen(new Set(remnants.locations.map((item) => item.path)))
                }
                disabled={clearing}
              >
                Tick every folder
              </button>
              <button
                className="link-button"
                onClick={() => setRemnants(null)}
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
            {report && (
              <div
                className="stat"
                title={
                  `File table ${report.timings.read_table} ms ` +
                  `(${report.timings.read_table_io} ms of it waiting on the disk), ` +
                  `index ${report.timings.build_index} ms, ` +
                  `applications ${report.timings.applications} ms, ` +
                  `leftovers ${report.timings.orphans} ms, ` +
                  `downloads ${report.timings.downloads} ms`
                }
              >
                <span className="stat-label">Measured in</span>
                <span className="stat-value">
                  {fmt.duration(report.timings.total)}
                  <span className="unit">
                    {fmt.count(report.timings.records)} records
                  </span>
                </span>
              </div>
            )}
          </div>
        )}
      </section>

      {(report || preview) && (
        <section className="panel">
          <div className="panel-head">
            <h2>{measuring ? "Installed applications" : "By real size"}</h2>
            {measuring && <span className="measuring">Measuring real sizes…</span>}
          </div>
          <p className="muted">
            {measuring
              ? "This is what the installers say about themselves, read from the registry. The measured sizes are being read off the disk now and will replace the claims when they arrive; searching, sorting and grouping all work in the meantime."
              : "A folder matched by more than one application — several NVIDIA packages sharing one data directory, for instance — is listed but not added to any of their totals. Totals understate rather than double-count."}
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
            <span className="right">{measuring ? "Measuring…" : "Actual"}</span>
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

      {!report && !preview && !running && !error && (
        <section className="panel">
          <p className="empty">Nothing measured yet. Pick a drive and press Measure.</p>
        </section>
      )}
    </>
  );
}
