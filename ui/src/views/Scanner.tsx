import { useCallback, useEffect, useState } from "react";
import { api, reason } from "../lib/api";
import type { DefenderReport, Threat } from "../lib/types";

/**
 * What Defender is doing, read from Defender.
 *
 * Deliberately not a dashboard with a big green tick and a number. Every row
 * states a setting and its value, and a value Defender did not report says so
 * rather than defaulting to "off" — which would be an alarming claim to invent.
 */

function Setting({ label, value, explain }: { label: string; value: boolean | null; explain: string }) {
  const state = value === null ? "unknown" : value ? "on" : "off";
  return (
    <li className={`setting setting-${state}`}>
      <span className="setting-dot" />
      <span className="setting-body">
        <span className="setting-label">{label}</span>
        <span className="setting-explain">{explain}</span>
      </span>
      <span className="setting-state">
        {value === null ? "not reported" : value ? "On" : "Off"}
      </span>
    </li>
  );
}

function age(days: number | null, never: string): string {
  if (days === null) return never;
  if (days === 0) return "today";
  if (days === 1) return "yesterday";
  return `${days} days ago`;
}

export default function Scanner() {
  const [report, setReport] = useState<DefenderReport | null>(null);
  const [threats, setThreats] = useState<Threat[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      setReport(await api.defenderStatus());
      setError(null);
      try {
        setThreats(await api.defenderThreats());
      } catch {
        // A machine that has never detected anything may not publish the
        // class at all. Not an error worth showing.
        setThreats([]);
      }
    } catch (cause) {
      setError(reason(cause));
      setReport(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const status = report?.status;

  return (
    <>
      <div className="view-head">
        <div>
          <h1>Scanner</h1>
          <p className="lede">
            Microsoft Defender's own state, read from Defender. This does not
            replace it and does not scan anything itself.
          </p>
        </div>
        <button onClick={() => void refresh()} disabled={loading}>
          {loading ? "Reading…" : "Refresh"}
        </button>
      </div>

      {error && (
        <div className="notice notice-down">
          <strong>Defender did not answer.</strong> It may have been replaced by
          another antivirus product, which takes over the same interface.
          <pre className="error">{error}</pre>
        </div>
      )}

      {report && (
        <div
          className={
            report.concerns.length === 0 ? "notice notice-ok" : "notice notice-warn"
          }
        >
          {report.concerns.length === 0 ? (
            <>
              <strong>Nothing to flag.</strong> Every protection Defender
              publishes is on, its definitions are current, and it has scanned
              recently.
            </>
          ) : (
            <>
              <strong>Worth knowing:</strong>
              <ul className="concerns">
                {report.concerns.map((concern) => (
                  <li key={concern}>{concern}</li>
                ))}
              </ul>
            </>
          )}
        </div>
      )}

      {status && (
        <>
          <section className="panel">
            <div className="panel-head">
              <h2>Protection</h2>
            </div>
            <ul className="settings">
              <Setting
                label="Antivirus"
                value={status.antivirus_enabled}
                explain="Defender's engine is running at all."
              />
              <Setting
                label="Real-time protection"
                value={status.realtime_protection}
                explain="Files are checked as they are opened, not only during a scan."
              />
              <Setting
                label="Behaviour monitoring"
                value={status.behaviour_monitoring}
                explain="Watches what programs do, rather than what they look like."
              />
              <Setting
                label="Cloud-delivered protection"
                value={status.cloud_protection}
                explain="Checks suspicious files against Microsoft's live intelligence."
              />
              <Setting
                label="Tamper protection"
                value={status.tamper_protection}
                explain="Stops other software — including this one — changing these settings."
              />
            </ul>
          </section>

          <div className="stat-row">
            <div className="stat">
              <span className="stat-label">Definitions</span>
              <span className="stat-value small">
                {status.antivirus_signature_version ?? "not reported"}
              </span>
              <span className="stat-sub">
                updated {age(status.signature_age_days, "unknown")}
              </span>
            </div>
            <div className="stat">
              <span className="stat-label">Engine</span>
              <span className="stat-value small">
                {status.engine_version ?? "not reported"}
              </span>
            </div>
            <div className="stat">
              <span className="stat-label">Last quick scan</span>
              <span className="stat-value small">
                {age(status.last_quick_scan_age_days, "never")}
              </span>
            </div>
            <div className="stat">
              <span className="stat-label">Last full scan</span>
              <span className="stat-value small">
                {age(status.last_full_scan_age_days, "never")}
              </span>
            </div>
          </div>

          <section className="panel">
            <div className="panel-head">
              <h2>What Defender has found</h2>
            </div>
            {threats === null ? (
              <p className="empty">Reading…</p>
            ) : threats.length === 0 ? (
              <p className="empty">
                Defender has no detections on record for this machine.
              </p>
            ) : (
              <ul className="entries">
                {threats.map((threat, index) => (
                  <li key={`${threat.name}-${index}`} className="entry">
                    <span className={`badge severity-${threat.severity ?? 0}`}>
                      {threat.severity === 5
                        ? "severe"
                        : threat.severity === 4
                          ? "high"
                          : threat.severity === 2
                            ? "moderate"
                            : threat.severity === 1
                              ? "low"
                              : "unknown"}
                    </span>
                    <div className="entry-body">
                      <span className="action">{threat.name}</span>
                      <span className="detail">
                        {threat.status === 2
                          ? "cleaned"
                          : threat.status === 3
                            ? "quarantined"
                            : threat.status === 4
                              ? "removed"
                              : threat.status === 5
                                ? "allowed"
                                : threat.status === 6
                                  ? "blocked"
                                  : threat.status === 102
                                    ? "no longer present"
                                    : "status unknown"}
                      </span>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </section>
        </>
      )}

      <section className="panel">
        <div className="panel-head">
          <h2>Still to come</h2>
        </div>
        <ul className="planned">
          <li>Starting and stopping scans, with progress rather than a frozen button.</li>
          <li>
            Judging executables by provenance: who signed it, when it arrived,
            where it was downloaded from, and whether it survives a reboot.
          </li>
          <li>
            YARA rules aimed at what Defender tolerates — bundled adware,
            scareware optimisers, browser hijackers.
          </li>
          <li>Looking a single file up on VirusTotal, with your own API key.</li>
        </ul>
      </section>
    </>
  );
}
