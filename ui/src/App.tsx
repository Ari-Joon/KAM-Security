import { useCallback, useEffect, useState } from "react";
import type { ReactElement } from "react";
import { api, reason } from "./lib/api";
import type { AuditRecord, SystemStatus, Volume } from "./lib/types";
import Overview from "./views/Overview";
import Storage from "./views/Storage";
import Activity from "./views/Activity";
import Planned from "./views/Planned";
import Applications from "./views/Applications";
import Cleanup from "./views/Cleanup";
import Scanner from "./views/Scanner";
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
  { key: "storage", label: "Storage", hint: "Where the space went", Icon: StorageIcon },
  {
    key: "applications",
    label: "Applications",
    hint: "Real size vs claimed",
    Icon: ApplicationsIcon,
  },
  { key: "cleanup", label: "Cleanup", hint: "Leftovers and quarantine", Icon: CleanupIcon },
  { key: "scanner", label: "Scanner", hint: "Defender status", Icon: ScannerIcon },
  { key: "firewall", label: "Firewall", hint: "Phase 4", Icon: FirewallIcon },
  { key: "activity", label: "Activity", hint: "The audit log", Icon: ActivityIcon },
];

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
  const [status, setStatus] = useState<SystemStatus | null>(null);
  const [volumes, setVolumes] = useState<Volume[]>([]);
  const [entries, setEntries] = useState<AuditRecord[]>([]);
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
        api.recentAudit(200),
        api.volumes(),
      ]);
      setEntries(audit);
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

        {section === "activity" && <Activity entries={entries} />}

        {section === "scanner" && <Scanner />}

        {section === "firewall" && (
          <Planned
            title="Firewall"
            phase="Phase 4"
            lede="A usable interface over Windows Defender Firewall, which already works."
            points={[
              "Read, group and explain the existing rules, including ones other software added without telling you.",
              "Show live connections joined to process, signer, and destination — what is this program talking to.",
              "Turn any observed connection into a scoped outbound rule in one click.",
              "Watch connections as they open via ETW. Prompting before connect would need a kernel driver, which this project will not ship.",
            ]}
          />
        )}
      </main>
    </div>
  );
}
