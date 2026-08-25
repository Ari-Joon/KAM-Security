import { useCallback, useEffect, useRef, useState } from "react";
import { api, reason } from "../lib/api";
import * as fmt from "../lib/format";
import type { AppFootprint, ApplicationReport, Volume } from "../lib/types";

type Props = { volumes: Volume[]; onMeasured: () => void };

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
}: {
  app: AppFootprint;
  onReveal: (path: string) => void;
  onUninstall: (app: AppFootprint) => void;
}) {
  const [open, setOpen] = useState(false);
  // Zero measured bytes and zero directories found are different claims. The
  // first says an application uses no space; the second says we could not find
  // it -- usually because it lives on another drive.
  const notFound = app.locations.length === 0;
  const ratio = app.reported_bytes && app.reported_bytes > 0
    ? app.actual_bytes / app.reported_bytes
    : null;

  return (
    <li className="app-row">
      <button className="app-head" onClick={() => setOpen(!open)}>
        <span className="app-caret">{open ? "▾" : "▸"}</span>
        <span className="app-name">
          {app.name}
          {app.publisher && <span className="app-publisher">{app.publisher}</span>}
        </span>
        <span className="app-reported">
          {app.reported_bytes === null ? (
            <span className="app-none">not reported</span>
          ) : (
            fmt.bytes(app.reported_bytes)
          )}
        </span>
        <span className="app-actual">
          {notFound ? (
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
  const awaitingUninstall = useRef<string | null>(null);

  const measure = useCallback(async () => {
    setRunning(true);
    setError(null);
    try {
      setReport(await api.applications(drive));
    } catch (cause) {
      setError(reason(cause));
      setReport(null);
    } finally {
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
      const name = awaitingUninstall.current;
      if (!name || document.hidden) {
        return;
      }
      awaitingUninstall.current = null;
      setNote(`Checking whether ${name} is really gone…`);
      void measure().then(() => {
        setNote(`Measured again after uninstalling ${name}.`);
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
      awaitingUninstall.current = app.name;
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

  async function reveal(path: string) {
    try {
      await api.reveal(path);
    } catch (cause) {
      setError(reason(cause));
    }
  }

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
          </div>
        )}
      </section>

      {report && (
        <section className="panel">
          <div className="panel-head">
            <h2>By real size</h2>
          </div>
          <p className="muted">
            A folder matched by more than one application — several NVIDIA
            packages sharing one data directory, for instance — is listed but
            not added to any of their totals. Totals understate rather than
            double-count.
          </p>

          <div className="app-header">
            <span />
            <span>Application</span>
            <span className="right">Reported</span>
            <span className="right">Actual</span>
            <span />
          </div>
          <ul className="app-list">
            {report.apps.map((app) => (
              <Row
                key={`${app.name}-${app.version}`}
                app={app}
                onReveal={(path) => void reveal(path)}
                onUninstall={setConfirming}
              />
            ))}
          </ul>
        </section>
      )}

      {confirming && (
        <ConfirmUninstall
          app={confirming}
          onCancel={() => setConfirming(null)}
          onConfirm={() => void uninstall(confirming)}
        />
      )}

      {!report && !running && !error && (
        <section className="panel">
          <p className="empty">Nothing measured yet. Pick a drive and press Measure.</p>
        </section>
      )}
    </>
  );
}
