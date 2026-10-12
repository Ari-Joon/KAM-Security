import { useCallback, useEffect, useRef, useState } from "react";
import type { ReactElement } from "react";
import { api, reason } from "./lib/api";
import type { Sweep as SweepReport } from "./lib/types";
import type { AuditRecord, SystemStatus, Volume } from "./lib/types";
import Overview from "./views/Overview";
import Storage from "./views/Storage";
import Activity from "./views/Activity";
import Applications from "./views/Applications";
import Cleanup from "./views/Cleanup";
import Firewall from "./views/Firewall";
import Scanner from "./views/Scanner";
import Changes from "./views/Changes";
import {
  ActivityIcon,
  ApplicationsIcon,
  CleanupIcon,
  FirewallIcon,
  OverviewIcon,
  ScannerIcon,
  StorageIcon,
} from "./components/SectionIcons";
import "./styles.css";

type Section =
  | "overview"
  | "changes"
  | "storage"
  | "applications"
  | "cleanup"
  | "scanner"
  | "firewall"
  | "activity";

/** Each section carries the alternate mark that belongs to it. */
const NAV: {
  key: Section;
  label: string;
  hint: string;
  Icon: () => ReactElement;
}[] = [
  { key: "overview", label: "Overview", hint: "Drives and recent events", Icon: OverviewIcon },
  {
    key: "changes",
    label: "Changes",
    hint: "What is different since last time",
    Icon: ActivityIcon,
  },
  { key: "storage", label: "Storage", hint: "Where the space went", Icon: StorageIcon },
  {
    key: "applications",
    label: "Applications",
    hint: "Real size vs claimed",
    Icon: ApplicationsIcon,
  },
  { key: "cleanup", label: "Cleanup", hint: "Leftovers and quarantine", Icon: CleanupIcon },
  { key: "scanner", label: "Scanner", hint: "Defender status", Icon: ScannerIcon },
  { key: "firewall", label: "Firewall", hint: "Rules and connections", Icon: FirewallIcon },
  { key: "activity", label: "Activity", hint: "The audit log", Icon: ActivityIcon },
];

/**
 * How many audit entries are read, newest first.
 *
 * Passed to the views that count them, so a count of these is never shown as
 * a count of everything in the log.
 */
const AUDIT_LIMIT = 200;

function Mark() {
  return (
    <svg viewBox="0 0 256 256" className="mark" aria-hidden="true">
      <circle cx="128" cy="128" r="128" fill="#0a0d14" />
      <g fill="none" stroke="#4a7cff" strokeWidth="8" strokeLinecap="round">
        <path d="M21.6 146.8 A108 108 0 1 1 234.4 146.8" />
        <path d="M34.5 182 A108 108 0 0 0 221.5 182" />
      </g>
      <path
        d="M128 45 L180 135 L76 135 Z"
        fill="none"
        stroke="#4a7cff"
        strokeWidth="8"
        strokeLinejoin="round"
      />
      <path d="M102 90 L154 90 L128 135 Z" fill="#3a63d8" />
    </svg>
  );
}

export default function App() {
  const [section, setSection] = useState<Section>("overview");
  /**
   * What changed, fetched once and kept.
   *
   * Not polled. Each sweep records a new baseline, so asking twice in a row
   * legitimately reports nothing the second time — a poll would erase the
   * answer it had just given.
   */
  const [sweep, setSweep] = useState<SweepReport | null>(null);
  /** Why the sweep did not answer, kept so it can be shown with a retry. */
  const [sweepError, setSweepError] = useState<string | null>(null);
  /**
   * Whether a sweep has been asked for and not yet answered.
   *
   * A ref rather than state, because it has to stop a second request in the
   * same moment the first is sent. Switching away from Changes and back
   * before the agent answered used to send another sweep; each one records a
   * new baseline, so whichever answered second compared the machine with the
   * first and said nothing had changed.
   */
  const sweeping = useRef(false);
  const [status, setStatus] = useState<SystemStatus | null>(null);
  const [volumes, setVolumes] = useState<Volume[]>([]);
  const [entries, setEntries] = useState<AuditRecord[]>([]);
  /**
   * Whether the activity log has been read at all. An empty list from an
   * agent that never answered is not "nothing recorded".
   */
  const [auditRead, setAuditRead] = useState(false);
  const [shellProtocol, setShellProtocol] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [storageRoot, setStorageRoot] = useState<string | null>(null);

  /** Poll the cheap calls. The scan is deliberately not part of this. */
  const refresh = useCallback(async () => {
    try {
      const next = await api.status();
      setStatus(next);
      setError(null);
      const [audit, drives] = await Promise.all([
        api.recentAudit(AUDIT_LIMIT),
        api.volumes(),
      ]);
      setEntries(audit);
      setAuditRead(true);
      setVolumes(drives);
    } catch (cause) {
      setStatus(null);
      setError(reason(cause));
    }
  }, []);

  useEffect(() => {
    api.protocolVersion().then(setShellProtocol).catch(() => {});
    void refresh();
    const timer = setInterval(() => void refresh(), 5000);
    return () => clearInterval(timer);
  }, [refresh]);

  /** Ask for one sweep, unless one is already on its way. */
  const runSweep = useCallback(() => {
    if (sweeping.current) return;
    sweeping.current = true;
    setSweepError(null);
    api
      .sweepForChanges()
      .then(setSweep)
      .catch((cause) => {
        // Kept and shown with its reason, rather than leaving the view on
        // "looking at the machine" for ever. Not an alarm either: a sweep
        // that could not run has found nothing, which is not the same as
        // having found nothing wrong.
        setSweepError(reason(cause));
      })
      .finally(() => {
        sweeping.current = false;
      });
  }, []);

  // Swept the first time the section is opened, and not again.
  //
  // Every sweep records a new baseline, so a poll here would erase the answer
  // it had just given: the second call would compare the machine against the
  // state the first call had already recorded and find nothing.
  useEffect(() => {
    if (section !== "changes" || sweep !== null) return;
    runSweep();
  }, [section, sweep, runSweep]);

  const connected = status !== null;
  const mismatched =
    connected && shellProtocol !== null && shellProtocol !== status.protocol_version;

  function openStorage(root: string) {
    setStorageRoot(root);
    setSection("storage");
  }

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <Mark />
          <div>
            <span className="brand-name">KAM Security</span>
            <span className="brand-sub">
              {status ? `v${status.agent_version}` : "offline"}
            </span>
          </div>
        </div>

        <nav className="nav">
          {NAV.map((item) => (
            <button
              key={item.key}
              className={"nav-item" + (section === item.key ? " active" : "")}
              onClick={() => setSection(item.key)}
            >
              <item.Icon />
              <span className="nav-text">
                <span className="nav-label">{item.label}</span>
                <span className="nav-hint">{item.hint}</span>
              </span>
            </button>
          ))}
        </nav>

        <div className="sidebar-foot">
          <span className={connected ? "dot dot-ok" : "dot dot-down"} />
          <div>
            <span className="foot-title">
              {connected ? "Agent connected" : "Agent unreachable"}
            </span>
            <span className="foot-sub">
              {connected
                ? status.running_as_service
                  ? "Windows service · LocalSystem"
                  : "Console process"
                : "Not listening"}
            </span>
          </div>
        </div>
      </aside>

      <main className="content">
        {mismatched && (
          <div className="notice notice-warn">
            This shell speaks protocol {shellProtocol}, the agent speaks{" "}
            {status.protocol_version}. They were built from different versions —
            update both rather than trusting what is shown.
          </div>
        )}

        {!connected && error && (
          <div className="notice notice-down">
            <strong>Cannot reach the agent.</strong> Nothing is listening on its
            pipe, or it refused this program — it only serves clients installed
            in its own directory.
            <pre className="error">{error}</pre>
            <code>cargo run -p kam-agent -- --console</code>
          </div>
        )}

        {section === "overview" && (
          <Overview
            status={status}
            volumes={volumes}
            entries={entries}
            auditRead={auditRead}
            auditLimit={AUDIT_LIMIT}
            onOpenStorage={openStorage}
          />
        )}

        {section === "storage" && (
          <Storage
            volumes={volumes}
            initialRoot={storageRoot}
            onScanned={() => void refresh()}
          />
        )}

        {section === "applications" && (
          <Applications volumes={volumes} onMeasured={() => void refresh()} />
        )}

        {section === "cleanup" && (
          <Cleanup volumes={volumes} onChanged={() => void refresh()} />
        )}

        {section === "changes" && (
          <Changes sweep={sweep} error={sweepError} onRetry={runSweep} />
        )}

        {section === "activity" && (
          <Activity entries={entries} read={auditRead} limit={AUDIT_LIMIT} />
        )}

        {section === "scanner" && <Scanner />}

        {section === "firewall" && <Firewall />}
      </main>
    </div>
  );
}
