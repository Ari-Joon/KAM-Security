import { useCallback, useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import "./App.css";

type SystemStatus = {
  protocol_version: number;
  agent_version: string;
  running_as_service: boolean;
  hostname: string;
};

type Effect = "observed" | "changed" | "refused";

type AuditRecord = {
  id: number;
  at: string;
  module: string;
  action: string;
  effect: Effect;
  detail: string;
  undo_token: string | null;
};

const EFFECT_LABEL: Record<Effect, string> = {
  observed: "observed",
  changed: "changed",
  refused: "refused",
};

function Mark() {
  return (
    <svg viewBox="0 0 256 256" className="mark" aria-hidden="true">
      <circle cx="128" cy="128" r="128" fill="#0A0D14" />
      <g fill="none" stroke="#4A7CFF" strokeWidth="7" strokeLinecap="round">
        <path d="M21.6 146.8 A108 108 0 1 1 234.4 146.8" />
        <path d="M34.5 182 A108 108 0 0 0 221.5 182" />
      </g>
      <path
        d="M128 45 L180 135 L76 135 Z"
        fill="none"
        stroke="#4A7CFF"
        strokeWidth="7"
        strokeLinejoin="round"
      />
      <path d="M102 90 L154 90 L128 135 Z" fill="#3A63D8" />
    </svg>
  );
}

/** Renders the ISO 8601 timestamp the agent stored, in local time. */
function when(iso: string): string {
  const parsed = new Date(iso);
  if (Number.isNaN(parsed.getTime())) return iso;
  return parsed.toLocaleString(undefined, {
    dateStyle: "medium",
    timeStyle: "medium",
  });
}

export default function App() {
  const [status, setStatus] = useState<SystemStatus | null>(null);
  const [entries, setEntries] = useState<AuditRecord[]>([]);
  const [shellProtocol, setShellProtocol] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const next = await invoke<SystemStatus>("agent_status");
      setStatus(next);
      setError(null);
      // Only worth asking for history once we know the agent is answering.
      setEntries(await invoke<AuditRecord[]>("recent_audit", { limit: 100 }));
    } catch (cause) {
      setStatus(null);
      setEntries([]);
      setError(String(cause));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    invoke<number>("protocol_version").then(setShellProtocol).catch(() => {});
    void refresh();
    const timer = setInterval(() => void refresh(), 5000);
    return () => clearInterval(timer);
  }, [refresh]);

  const connected = status !== null;
  const mismatched =
    connected && shellProtocol !== null && shellProtocol !== status.protocol_version;

  return (
    <main className="app">
      <header className="header">
        <Mark />
        <div className="titles">
          <h1>KAM Security</h1>
          <p className="subtitle">Agent console</p>
        </div>
        <span className={connected ? "pill pill-ok" : "pill pill-down"}>
          {connected ? "agent connected" : "agent unreachable"}
        </span>
      </header>

      {mismatched && (
        <div className="notice notice-warn">
          This shell speaks protocol {shellProtocol} but the agent speaks{" "}
          {status.protocol_version}. They were built from different versions —
          update both rather than trusting what is shown below.
        </div>
      )}

      {error && (
        <section className="panel">
          <h2>Cannot reach the agent</h2>
          <p className="muted">
            Nothing is listening on the agent pipe, or it refused this program.
            The agent only serves clients installed in its own directory.
          </p>
          <pre className="error">{error}</pre>
          <p className="muted">Start it in a terminal with:</p>
          <pre className="command">cargo run -p kam-agent -- --console</pre>
        </section>
      )}

      {status && (
        <section className="panel">
          <h2>Agent</h2>
          <dl className="facts">
            <div>
              <dt>Running as</dt>
              <dd>
                {status.running_as_service
                  ? "Windows service (LocalSystem)"
                  : "console process"}
              </dd>
            </div>
            <div>
              <dt>Version</dt>
              <dd>{status.agent_version}</dd>
            </div>
            <div>
              <dt>Protocol</dt>
              <dd>{status.protocol_version}</dd>
            </div>
            <div>
              <dt>Host</dt>
              <dd>{status.hostname}</dd>
            </div>
          </dl>
        </section>
      )}

      <section className="panel">
        <div className="panel-head">
          <h2>Activity</h2>
          <button onClick={() => void refresh()} disabled={loading}>
            {loading ? "Refreshing…" : "Refresh"}
          </button>
        </div>
        <p className="muted">
          Every privileged action the agent takes, and every one it refuses. The
          log is append-only — the database rejects updates and deletes.
        </p>

        {entries.length === 0 ? (
          <p className="empty">
            {connected ? "Nothing recorded yet." : "Unavailable while disconnected."}
          </p>
        ) : (
          <ul className="entries">
            {entries.map((entry) => (
              <li key={entry.id} className="entry">
                <span className={`badge badge-${entry.effect}`}>
                  {EFFECT_LABEL[entry.effect]}
                </span>
                <div className="entry-body">
                  <div className="entry-title">
                    <span className="module">{entry.module}</span>
                    <span className="action">{entry.action}</span>
                  </div>
                  <div className="detail">{entry.detail}</div>
                </div>
                <time className="at" dateTime={entry.at}>
                  {when(entry.at)}
                </time>
              </li>
            ))}
          </ul>
        )}
      </section>
    </main>
  );
}
