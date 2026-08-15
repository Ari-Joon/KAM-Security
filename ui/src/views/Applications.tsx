import { useState } from "react";
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

function Row({ app }: { app: AppFootprint }) {
  const [open, setOpen] = useState(false);
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
        <span className="app-actual">{fmt.bytes(app.actual_bytes)}</span>
        <span className="app-ratio">
          {ratio !== null && ratio >= 1.5 && (
            <span className="ratio-badge">{ratio.toFixed(1)}×</span>
          )}
        </span>
      </button>

      {open && (
        <ul className="app-locations">
          {app.locations.length === 0 && (
            <li className="app-location muted">
              No directories found on this drive. It may be installed elsewhere.
            </li>
          )}
          {app.locations.map((location) => (
            <li
              key={location.path}
              className={"app-location" + (location.shared_with > 0 ? " shared" : "")}
            >
              <span className="loc-kind">{KIND_LABEL[location.kind] ?? location.kind}</span>
              <span className="loc-path" title={location.path}>
                {location.path}
              </span>
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
      )}
    </li>
  );
}

export default function Applications({ volumes, onMeasured }: Props) {
  const [drive, setDrive] = useState("C:\\");
  const [report, setReport] = useState<ApplicationReport | null>(null);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function run() {
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
          <button className="primary" onClick={() => void run()} disabled={running}>
            {running ? "Measuring…" : "Measure"}
          </button>
          <span className="muted">
            Reads the master file table, so the agent must be running with
            administrative rights.
          </span>
        </div>

        {error && <pre className="error">{error}</pre>}

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
              <Row key={`${app.name}-${app.version}`} app={app} />
            ))}
          </ul>
        </section>
      )}

      {!report && !running && !error && (
        <section className="panel">
          <p className="empty">Nothing measured yet. Pick a drive and press Measure.</p>
        </section>
      )}
    </>
  );
}
