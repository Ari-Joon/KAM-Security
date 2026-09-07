import { useCallback, useEffect, useState } from "react";
import * as fmt from "../lib/format";
import { api, reason } from "../lib/api";
import type {
  AuditRecord,
  CheckFinding,
  Schedule,
  SystemStatus,
  Volume,
} from "../lib/types";
import EffectBadge from "../components/EffectBadge";

const DAYS = [
  "Sunday",
  "Monday",
  "Tuesday",
  "Wednesday",
  "Thursday",
  "Friday",
  "Saturday",
];

type Props = {
  status: SystemStatus | null;
  volumes: Volume[];
  entries: AuditRecord[];
  onOpenStorage: (root: string) => void;
};

function UsageBar({ used, total }: { used: number; total: number }) {
  const pct = fmt.percent(used, total);
  // Colour is a judgement about headroom, not decoration: red only when the
  // drive is genuinely close to full.
  const tone = pct >= 92 ? "danger" : pct >= 80 ? "warn" : "accent";
  return (
    <div className="usage">
      <div className="usage-track">
        <div className={`usage-fill usage-${tone}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="usage-label">{pct.toFixed(0)}% used</span>
    </div>
  );
}


/**
 * The switch, and the only one there is.
 *
 * Protection is on from the moment the agent is installed and stays on across
 * reboots, crashes and closing this window — the agent is a Windows service, so
 * it does not depend on anything being open. This is the one place it can be
 * stopped deliberately.
 *
 * Turning it off does **not** stop the service, and that is on purpose twice
 * over: something has to still be running to switch it back on, and a security
 * tool that can be shut down through its own interface is one an attacker shuts
 * down. What stops is the watching. Stopping the service itself needs Task
 * Manager or an administrator, which is a deliberate act by somebody who is
 * already in charge of the machine.
 */
function Protection() {
  const [enabled, setEnabled] = useState<boolean | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      setEnabled(await api.protection());
      setError(null);
    } catch (cause) {
      setError(reason(cause));
      setEnabled(null);
    }
  }, []);

  useEffect(() => {
    void refresh();
    const timer = setInterval(() => void refresh(), 10000);
    return () => clearInterval(timer);
  }, [refresh]);

  async function toggle(next: boolean) {
    setBusy(true);
    setError(null);
    try {
      setEnabled(await api.setProtection(next));
    } catch (cause) {
      setError(reason(cause));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="panel">
      <div className="panel-head">
        <h2>Protection</h2>
        {enabled !== null && (
          <button
            onClick={() => void toggle(!enabled)}
            disabled={busy}
            className={enabled ? "ghost" : undefined}
          >
            {busy ? "Working…" : enabled ? "Turn protection off" : "Turn protection on"}
          </button>
        )}
      </div>

      {error && (
        <div className="notice notice-down">
          <strong>The agent did not answer.</strong>
          <pre className="error">{error}</pre>
        </div>
      )}

      {enabled === true && (
        <div className="notice notice-ok">
          <strong>Protection is on.</strong> The agent watches what newly starts
          itself and reports anything that reads a decoy. It runs as a Windows
          service, so it keeps working when this window is closed and starts
          again by itself after a reboot or a crash.
        </div>
      )}

      {enabled === false && (
        <div className="notice notice-warn">
          <strong>Protection is off.</strong> Nothing is being watched. The agent
          is still running so you can switch it back on here, but until you do,
          new startup entries and decoy reads go unnoticed.
        </div>
      )}

      <p className="muted small">
        Turning it off here stops the watching, not the service — something has
        to stay running to turn it back on. To stop the service itself, use Task
        Manager or an administrator terminal.
      </p>
    </section>
  );
}

/**
 * The one thing here that happens without being asked.
 *
 * It is off until somebody turns it on, and it is a Windows scheduled task
 * rather than a timer inside this program: the agent costs nothing while
 * nobody is asking it anything, and a thread waking every few minutes to check
 * the clock would throw that away. Windows also already knows how to hold a run
 * back until the machine is idle and on mains power.
 */
function WeeklyCheck() {
  const [schedule, setSchedule] = useState<Schedule | null>(null);
  const [day, setDay] = useState("Sunday");
  const [hour, setHour] = useState(3);
  const [busy, setBusy] = useState(false);
  const [findings, setFindings] = useState<CheckFinding[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void (async () => {
      try {
        const current = await api.schedule();
        setSchedule(current);
        if (current.day) setDay(current.day);
        if (current.at) setHour(parseInt(current.at.slice(0, 2), 10) || 3);
      } catch {
        // The panel is secondary; a failure here must not blank the Overview.
      }
    })();
  }, []);

  async function apply(enabled: boolean) {
    setBusy(true);
    setError(null);
    try {
      setSchedule(await api.setSchedule(enabled, day, hour));
    } catch (cause) {
      setError(reason(cause));
    } finally {
      setBusy(false);
    }
  }

  async function checkNow() {
    setBusy(true);
    setError(null);
    try {
      setFindings(await api.runCheck());
    } catch (cause) {
      setError(reason(cause));
    } finally {
      setBusy(false);
    }
  }

  const on = schedule?.enabled === true;

  return (
    <section className="panel">
      <div className="panel-head">
        <h2>Weekly check</h2>
        <button onClick={() => void checkNow()} disabled={busy}>
          {busy ? "Working…" : "Check now"}
        </button>
      </div>
      <p className="muted">
        Reads state rather than scanning: whether Defender is on and current,
        whether the firewall is up, whether anything unsigned has taken up
        residence in a startup location, and whether a drive is nearly full.
        Seconds, and almost no disk. It never pops anything up, because a weekly
        balloon saying everything is fine is how a program teaches you to ignore
        it.
      </p>

      <div className="schedule-row">
        <label>
          Every
          <select value={day} onChange={(event) => setDay(event.target.value)}>
            {DAYS.map((name) => (
              <option key={name} value={name}>
                {name}
              </option>
            ))}
          </select>
        </label>
        <label>
          at
          <select
            value={hour}
            onChange={(event) => setHour(Number(event.target.value))}
          >
            {Array.from({ length: 24 }, (_, n) => n).map((n) => (
              <option key={n} value={n}>
                {String(n).padStart(2, "0")}:00
              </option>
            ))}
          </select>
        </label>
        <button onClick={() => void apply(true)} disabled={busy}>
          {on ? "Change" : "Turn on"}
        </button>
        {on && (
          <button className="ghost" onClick={() => void apply(false)} disabled={busy}>
            Turn off
          </button>
        )}
      </div>

      <p className={on ? "schedule-state on" : "schedule-state"}>
        {on
          ? `Registered: every ${schedule?.day ?? day} at ${schedule?.at ?? ""}, only when the machine is idle and on mains power.`
          : "Nothing is registered. This program reports on what starts itself at boot, so it does not quietly add itself to that list."}
      </p>
      {on && schedule?.command && (
        <p className="muted small">
          Runs <code>{schedule.command}</code> as you, with administrator
          rights. It appears in Task Scheduler under <code>KAM Security</code>,
          and in this program's own list of what starts itself.
        </p>
      )}

      {error && <pre className="error">{error}</pre>}

      {findings && (
        <ul className="findings">
          {findings.length === 0 ? (
            <li className="finding ok">Nothing to report.</li>
          ) : (
            findings.map((finding) => (
              <li
                key={finding.summary}
                className={finding.serious ? "finding serious" : "finding"}
              >
                {finding.summary}
              </li>
            ))
          )}
        </ul>
      )}
    </section>
  );
}

export default function Overview({ status, volumes, entries, onOpenStorage }: Props) {
  const fixed = volumes.filter((volume) => volume.kind === "fixed");
  const totalCapacity = fixed.reduce((sum, v) => sum + v.total_bytes, 0);
  const totalFree = fixed.reduce((sum, v) => sum + v.free_bytes, 0);

  return (
    <>
      <div className="view-head">
        <div>
          <h1>Overview</h1>
          <p className="lede">
            {status
              ? `Agent ${status.agent_version} on ${status.hostname}, running as ${
                  status.running_as_service ? "a Windows service" : "a console process"
                }.`
              : "The agent is not answering, so nothing below is live."}
          </p>
        </div>
      </div>

      <Protection />

      <div className="stat-row">
        <div className="stat">
          <span className="stat-label">Fixed drives</span>
          <span className="stat-value">{fixed.length}</span>
        </div>
        <div className="stat">
          <span className="stat-label">Total capacity</span>
          <span className="stat-value">{fmt.bytes(totalCapacity)}</span>
        </div>
        <div className="stat">
          <span className="stat-label">Free</span>
          <span className="stat-value">{fmt.bytes(totalFree)}</span>
        </div>
        <div className="stat">
          <span className="stat-label">Recorded events</span>
          <span className="stat-value">{fmt.count(entries.length)}</span>
        </div>
      </div>

      <section className="panel">
        <div className="panel-head">
          <h2>Drives</h2>
        </div>
        {volumes.length === 0 ? (
          <p className="empty">No drives reported.</p>
        ) : (
          <div className="drive-grid">
            {volumes.map((volume) => (
              <button
                key={volume.root}
                className="drive"
                onClick={() => onOpenStorage(volume.root)}
              >
                <div className="drive-head">
                  <span className="drive-root">{volume.root}</span>
                  <span className="drive-fs">
                    {volume.filesystem || "unknown"}
                    {volume.supports_mft ? "" : " · walk only"}
                  </span>
                </div>
                <div className="drive-label">{volume.label || "Local disk"}</div>
                <UsageBar
                  used={volume.total_bytes - volume.free_bytes}
                  total={volume.total_bytes}
                />
                <div className="drive-numbers">
                  <span>{fmt.bytes(volume.total_bytes - volume.free_bytes)} used</span>
                  <span className="muted">{fmt.bytes(volume.free_bytes)} free</span>
                </div>
              </button>
            ))}
          </div>
        )}
      </section>

      <WeeklyCheck />

      <section className="panel">
        <div className="panel-head">
          <h2>Recent activity</h2>
        </div>
        {entries.length === 0 ? (
          <p className="empty">Nothing recorded yet.</p>
        ) : (
          <ul className="entries compact">
            {entries.slice(0, 6).map((entry) => (
              <li key={entry.id} className="entry">
                <EffectBadge effect={entry.effect} />
                <div className="entry-body">
                  <span className="action">{entry.action}</span>
                  <span className="detail">{entry.detail}</span>
                </div>
                <time className="at">{fmt.relative(entry.at)}</time>
              </li>
            ))}
          </ul>
        )}
      </section>
    </>
  );
}
