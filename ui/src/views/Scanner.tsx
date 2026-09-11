import { useCallback, useEffect, useState } from "react";
import { api, reason } from "../lib/api";
import ProgressBar from "../components/ProgressBar";
import { newJobId, runJob, stopJob, type Progress } from "../lib/jobs";
import * as fmt from "../lib/format";
import type {
  Anchor,
  BehaviourReport,
  CanaryReport,
  ExtensionReport,
  HardeningMode,
  HardeningReport,
  Concern,
  DefenderReport,
  DefenderStatus,
  Location,
  Observation,
  ProvenanceReport,
  RuleReport,
  Signature,
  Verdict,
  ScanOutcome,
  Threat,
} from "../lib/types";

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

      {/* Above the tables on purpose. This is the one thing on the page that
          *does* something rather than reporting something, and it is what
          somebody opening this view has come to do. */}
      <DefenderScan status={status ?? null} />

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

      <Canaries />

      <Hardening />

      <Extensions />

      <BehaviourWatch />

      <Provenance />

      <section className="panel">
        <div className="panel-head">
          <h2>Still to come</h2>
        </div>
        <ul className="planned">
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

/**
 * A VirusTotal lookup for one file, on request.
 *
 * Deliberately per-file and never automatic. It reaches a third party, and
 * although only a hash crosses the network, telling an external service which
 * files sit on someone's machine is their decision to make each time — not a
 * background behaviour they have to discover.
 */
function VirusTotal({ path, hasKey }: { path: string; hasKey: boolean }) {
  const [verdict, setVerdict] = useState<Verdict | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [looking, setLooking] = useState(false);

  if (!hasKey) return null;

  const look = async () => {
    setLooking(true);
    setError(null);
    try {
      setVerdict(await api.virustotalLookup(path));
    } catch (cause) {
      setError(reason(cause));
    } finally {
      setLooking(false);
    }
  };

  return (
    <div className="vt">
      {!verdict && !error && (
        <button className="link-button" onClick={() => void look()} disabled={looking}>
          {looking ? "Asking VirusTotal…" : "Ask VirusTotal about this file"}
        </button>
      )}

      {error && (
        <p className="vt-error">
          {error}{" "}
          <button className="link-button" onClick={() => void look()}>
            Try again
          </button>
        </p>
      )}

      {verdict && (
        <div className={`vt-result vt-${verdict.standing}`}>
          <div className="vt-head">
            <span className="vt-score">
              {verdict.engines > 0
                ? `${verdict.malicious + verdict.suspicious} of ${verdict.engines}`
                : "no record"}
            </span>
            <span className="vt-standing">
              {verdict.standing === "clean"
                ? "nothing flagged it"
                : verdict.standing === "not_known"
                  ? "not known to VirusTotal"
                  : verdict.standing === "isolated"
                    ? "a few engines flagged it"
                    : "many engines flagged it"}
            </span>
          </div>

          {/* The agent's sentence, not one computed here from the counts. */}
          <p className="vt-summary">{verdict.summary}</p>

          {verdict.detections.length > 0 && (
            <ul className="vt-detections">
              {verdict.detections.map((d) => (
                <li key={d.engine}>
                  <span className="vt-engine">{d.engine}</span>
                  <span className="vt-verdict">{d.verdict}</span>
                </li>
              ))}
            </ul>
          )}

          <div className="vt-facts">
            {verdict.common_name && <span>usually called {verdict.common_name}</span>}
            {verdict.first_seen && <span>first seen {verdict.first_seen}</span>}
            {verdict.last_analysed && <span>last analysed {verdict.last_analysed}</span>}
          </div>
        </div>
      )}
    </div>
  );
}

/** Storing the user's own VirusTotal key. */
function VirusTotalKey({ hasKey, onChange }: { hasKey: boolean; onChange: () => void }) {
  const [editing, setEditing] = useState(false);
  const [value, setValue] = useState("");
  const [error, setError] = useState<string | null>(null);

  const save = async (key: string) => {
    setError(null);
    try {
      await api.setVirustotalKey(key);
      setValue("");
      setEditing(false);
      onChange();
    } catch (cause) {
      setError(reason(cause));
    }
  };

  return (
    <div className="vt-key">
      {hasKey ? (
        <p className="footnote">
          A VirusTotal key is stored, encrypted under your Windows account.{" "}
          <button className="link-button" onClick={() => void save("")}>
            Remove it
          </button>
        </p>
      ) : editing ? (
        <div className="vt-key-form">
          <input
            type="password"
            className="vt-key-input"
            placeholder="Paste your VirusTotal API key"
            value={value}
            onChange={(event) => setValue(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "Enter") void save(value);
            }}
          />
          <button onClick={() => void save(value)}>Save</button>
          <button className="link-button" onClick={() => setEditing(false)}>
            Cancel
          </button>
          {error && <p className="vt-error">{error}</p>}
        </div>
      ) : (
        <p className="footnote">
          With a free VirusTotal API key you can ask about individual files.
          Only the file's <strong>hash</strong> is sent — never the file itself.
          The key is stored encrypted under your Windows account.{" "}
          <button className="link-button" onClick={() => setEditing(true)}>
            Add a key
          </button>
        </p>
      )}
    </div>
  );
}

const ANCHOR_LABELS: Record<Anchor, string> = {
  run_key: "a sign-in entry",
  run_once_key: "a run-once entry",
  startup_folder: "a Startup folder item",
  service: "a Windows service",
  scheduled_task: "a scheduled task",
};

const LOCATION_LABELS: Record<Location, string> = {
  system: "a protected Windows folder",
  installed: "an installed program folder",
  shared: "a shared application folder",
  user_writable: "a folder any program can write to",
  elsewhere: "outside the usual program folders",
};

function signatureLabel(signature: Signature): string {
  switch (signature.state) {
    case "valid":
      return signature.catalogue ? `${signature.signer} (part of Windows)` : signature.signer;
    case "invalid":
      return signature.signer ? `${signature.signer} — not accepted` : "signature not accepted";
    case "unsigned":
      return "not signed";
    case "unknown":
      return "could not be checked";
  }
}

/**
 * Running Windows Defender's own scanner from here.
 *
 * This adds no detection. Defender is already installed, already has the
 * signatures, and is already better at this than anything this project could
 * write. What it lacks is reach: starting a scan means going and finding
 * another application, and the results then live somewhere nobody looks.
 *
 * Two things this panel must not do. It must not present a scan that was
 * stopped as though it came back clean, because a scan that did not finish and
 * found nothing has established nothing. And it must not imply the machine has
 * been cleaned: Defender is deliberately asked to report rather than to act, so
 * anything found is still exactly where it was.
 */
/**
 * How old a set of definitions is, in words a person uses.
 *
 * Shown because it is what makes a scan result mean anything. "Defender found
 * nothing" is a different sentence depending on whether it was looking with
 * this morning's definitions or with a set from three weeks ago, and nothing in
 * Windows' own interface puts the two facts next to each other.
 */
function definitionsAge(days: number | null): string {
  if (days === null) return "of unknown age";
  if (days <= 0) return "updated today";
  if (days === 1) return "updated yesterday";
  if (days < 7) return `updated ${days} days ago`;
  if (days < 14) return "updated over a week ago";
  return `updated ${Math.floor(days / 7)} weeks ago`;
}

/** What each kind of scan actually looks at, so the result can be read. */
const COVERS: Record<"quick" | "full", string> = {
  quick:
    "memory, the places programs start themselves from, and the folders \
     infections usually land in. Not every file on the disk.",
  full: "every file on every fixed drive, which is why it takes hours.",
};

function DefenderScan({ status }: { status: DefenderStatus | null }) {
  const [running, setRunning] = useState<null | "quick" | "full">(null);
  const [job, setJob] = useState<string | null>(null);
  const [elapsed, setElapsed] = useState(0);
  const [outcome, setOutcome] = useState<ScanOutcome | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Defender does not report progress in any form this can read, so the honest
  // thing to show is how long it has been going rather than a bar that would be
  // inventing a fraction.
  useEffect(() => {
    if (!running) return;
    setElapsed(0);
    const started = Date.now();
    const tick = window.setInterval(
      () => setElapsed(Math.round((Date.now() - started) / 1000)),
      1000,
    );
    return () => window.clearInterval(tick);
  }, [running]);

  async function start(which: "quick" | "full") {
    const id = newJobId();
    setRunning(which);
    setJob(id);
    setOutcome(null);
    setError(null);
    try {
      const result = await api.defenderScan({ kind: which }, id);
      // Null means stopped, which is not a result and must not be shown as one.
      setOutcome(result);
    } catch (cause) {
      setError(reason(cause));
    } finally {
      setRunning(null);
      setJob(null);
    }
  }

  async function stop() {
    if (job) await stopJob(job);
  }

  return (
    <section className="panel">
      <div className="panel-head">
        <h2>Scan with Defender</h2>
        {running ? (
          <button onClick={() => void stop()}>Stop</button>
        ) : (
          <div className="panel-actions">
            <button onClick={() => void start("quick")}>Quick scan</button>
            <button className="ghost" onClick={() => void start("full")}>
              Full scan
            </button>
          </div>
        )}
      </div>

      <p className="muted">
        This runs Windows Defender, not a scanner of ours — it already has the
        signatures and is already watching this machine. What it does not have
        is a way to start it from here and see the answer without going looking.
        A quick scan takes minutes; a full scan can take hours and can be
        stopped.
      </p>
      <p className="muted">
        Defender is asked to <strong>report</strong> rather than to remove.
        Anything it finds stays where it is, and what happens to it is decided
        here, where it can be undone.
      </p>

      {/* What it is looking with. A scan that finds nothing means one thing
          with this morning's definitions and something much weaker with a set
          from three weeks ago, and Windows never shows the two together. */}
      {status && (
        <div className="scan-definitions">
          <span className="muted">
            Looking with definitions{" "}
            {status.antivirus_signature_version ?? "of unknown version"},{" "}
            {definitionsAge(status.signature_age_days)}
            {status.engine_version
              ? `, engine ${status.engine_version}`
              : null}
            .
          </span>
          {(status.signature_age_days ?? 0) >= 7 && (
            <p className="held-warn">
              Definitions this old are the limit of what the scan can find.
              Anything newer than them is not being looked for at all.
            </p>
          )}
        </div>
      )}

      {error && <p className="error">{error}</p>}

      {running && (
        <div className="scan-running">
          <p>
            {running === "quick" ? "Quick scan" : "Full scan"} running —{" "}
            {fmt.duration(elapsed * 1000)} so far. You can leave this page.
          </p>
          <p className="small muted">Covering {COVERS[running]}</p>
          {/* No bar, and no percentage. Defender publishes neither, so any
              fraction shown here would be invented — and a progress bar that
              is making its number up is the single most common small lie in
              this category of software. */}
          <p className="small muted">
            Defender does not publish how far through it is, so this counts
            time rather than showing a bar it would have to invent.
          </p>
          {status && (
            <p className="small muted">
              Last {running === "quick" ? "quick" : "full"} scan:{" "}
              {age(
                running === "quick"
                  ? status.last_quick_scan_age_days
                  : status.last_full_scan_age_days,
                "never, as far as Defender records",
              )}
              .
            </p>
          )}
        </div>
      )}

      {outcome && (
        <div className="scan-outcome">
          <p>
            {outcome.label} {outcome.completed ? "finished" : "was stopped"} after{" "}
            {fmt.duration(outcome.seconds * 1000)}.
          </p>
          {!outcome.completed && (
            <p className="held-warn">
              It did not finish, so this says nothing about the parts it never
              reached.
            </p>
          )}
          {outcome.found.length === 0 ? (
            <p className="muted">
              {outcome.completed
                ? "Defender recorded nothing new."
                : "Nothing was recorded in the part that ran."}
            </p>
          ) : (
            <>
              <p>
                Defender recorded {outcome.found.length}{" "}
                {outcome.found.length === 1 ? "detection" : "detections"} it did
                not have before:
              </p>
              <ul className="threats">
                {outcome.found.map((threat) => (
                  <li key={`${threat.name}-${threat.detected_at ?? ""}`}>
                    <strong>{threat.name}</strong>
                    {threat.detected_at && (
                      <span className="muted"> — {threat.detected_at}</span>
                    )}
                  </li>
                ))}
              </ul>
            </>
          )}
          {/* Which definitions the answer came from. Without this, the
              result is undateable a week later. */}
          {status?.antivirus_signature_version && (
            <p className="small muted">
              Looked with definitions {status.antivirus_signature_version},{" "}
              {definitionsAge(status.signature_age_days)}.
            </p>
          )}
          {outcome.caveat && <p className="muted">{outcome.caveat}</p>}
        </div>
      )}
    </section>
  );
}

/**
 * Decoy files that exist only to be stolen.
 *
 * The one thing in this product that is not circumstantial. Everything else
 * weighs evidence; a canary read has no innocent explanation, because the file
 * was put there by this program and nothing on the machine knows it exists.
 *
 * Two switches rather than one, deliberately. Planting decoys only writes
 * files. Turning on auditing changes a Windows setting, machine-wide, and that
 * is a different kind of thing to ask for — so it is asked for separately and
 * says exactly what it does.
 */
function Canaries() {
  const [report, setReport] = useState<CanaryReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const refresh = useCallback(async () => {
    try {
      setReport(await api.canaries());
      setError(null);
    } catch (cause) {
      setError(reason(cause));
    }
  }, []);

  useEffect(() => {
    void refresh();
    const timer = setInterval(() => void refresh(), 20000);
    return () => clearInterval(timer);
  }, [refresh]);

  async function act(work: () => Promise<CanaryReport>) {
    setBusy(true);
    setError(null);
    try {
      setReport(await work());
    } catch (cause) {
      setError(reason(cause));
    } finally {
      setBusy(false);
    }
  }

  const planted = report?.canaries.length ?? 0;
  const trips = report?.trips ?? [];
  const watching = report?.auditing === true && (report?.canaries.some((c) => c.armed) ?? false);

  return (
    <section className="panel">
      <div className="panel-head">
        <h2>Decoy files</h2>
        <button
          onClick={() => void act(() => api.setCanaries(planted === 0))}
          disabled={busy}
        >
          {busy ? "Working…" : planted === 0 ? "Plant decoys" : "Remove decoys"}
        </button>
      </div>

      <p className="lede panel-lede">
        Decoys that exist only to be stolen: a fake saved-password database, a
        fake wallet, a fake recovery phrase, and fake saved connections in the
        registry where PuTTY, WinSCP and Remote Desktop keep theirs. Nothing on
        this machine uses any of them and no ordinary program has a reason to
        open one — so if something reads one, that is not evidence to be weighed
        against other evidence. It is close to proof that something is going
        through your machine looking for credentials, and Windows records which
        program did it.
      </p>

      {error && (
        <div className="notice notice-down">
          <strong>That did not work.</strong>
          <pre className="error">{error}</pre>
        </div>
      )}

      {report && (
        <>
          {trips.length > 0 && (
            <div className="notice notice-down">
              <strong>
                Something read {trips.length === 1 ? "a decoy" : "your decoys"}.
              </strong>{" "}
              This is worth acting on rather than reading past.
            </div>
          )}

          <div
            className={
              planted === 0
                ? "notice"
                : watching
                  ? "notice notice-ok"
                  : "notice notice-warn"
            }
          >
            {planted === 0 ? (
              <>Nothing is planted. Decoys are off until you turn them on.</>
            ) : watching ? (
              <>
                <strong>{planted}</strong> decoys planted and being watched.
              </>
            ) : (
              <>
                <strong>{planted}</strong> decoys are planted, but Windows is not
                recording file access, so reading one would go unnoticed. They
                are inert until auditing is on.
              </>
            )}
          </div>

          {planted > 0 && (
            <div className="schedule-row">
              <button
                onClick={() => void act(() => api.setCanaryAuditing(!report.auditing))}
                disabled={busy}
              >
                {report.auditing
                  ? "Stop recording file access"
                  : "Record reads of these files"}
              </button>
              <span className="muted small">
                {report.auditing
                  ? "Windows is recording access to files that ask for it. Turning this off makes the decoys inert."
                  : "Switches on Windows' File System auditing. It only produces events for files that ask to be watched — these five — so it does not fill your Security log."}
              </span>
            </div>
          )}

          {trips.length > 0 && (
            <ul className="findings">
              {trips.map((trip, index) => (
                <li key={`${trip.at}-${trip.path}-${index}`} className="finding finding-unusual">
                  <div className="finding-head">
                    <span className="finding-name">
                      {trip.process
                        ? `${trip.process.split("\\").pop()} read a decoy`
                        : "Something read a decoy"}
                    </span>
                    <span className="badge attention-unusual">worth a look</span>
                  </div>
                  <button
                    className="finding-path"
                    title="Open the containing folder"
                    onClick={() => void api.reveal(trip.path)}
                  >
                    {trip.path}
                  </button>
                  <dl className="finding-facts">
                    <div>
                      <dt>Read by</dt>
                      <dd>{trip.process ?? "not recorded"}</dd>
                    </div>
                    <div>
                      <dt>Running as</dt>
                      <dd>{trip.user ?? "not recorded"}</dd>
                    </div>
                    <div>
                      <dt>When</dt>
                      <dd>{fmtStamp(trip.at)}</dd>
                    </div>
                  </dl>
                </li>
              ))}
            </ul>
          )}

          {planted > 0 && (
            <ul className="finding-anchors">
              {report.canaries.map((canary) => (
                <li key={canary.id}>
                  <span className="anchor-kind">
                    {canary.armed ? "watched" : "not watched"}
                    {canary.kind === "registry_key" && " · registry"}
                  </span>
                  <span className="anchor-where">{canary.path}</span>
                </li>
              ))}
            </ul>
          )}

          {report.problems.length > 0 && (
            <div className="notice notice-warn">
              <ul className="concerns">
                {report.problems.map((problem) => (
                  <li key={problem}>{problem}</li>
                ))}
              </ul>
            </div>
          )}

          <p className="footnote">
            Decoys are written into your Documents folder and, for the saved
            connections, into your own registry hive. They contain nothing real
            and each one says so. Nothing already there is ever overwritten, and
            removal only deletes what this program wrote and marked as its own.
          </p>
        </>
      )}
    </section>
  );
}

function modeLabel(mode: HardeningMode): string {
  if (typeof mode === "object") return `an unrecognised value (${mode.unknown})`;
  switch (mode) {
    case "block":
      return "blocking";
    case "warn":
      return "warning";
    case "audit":
      return "auditing only";
    default:
      return "off";
  }
}

/** Auditing writes an event and stops nothing, so it is not protection. */
function isProtecting(mode: HardeningMode): boolean {
  return mode === "block" || mode === "warn";
}

/**
 * Protections Windows already has and leaves switched off.
 *
 * Nothing here can be turned on from this window, deliberately. A rule in
 * blocking mode changes what every program on the machine may do and can stop
 * software somebody depends on, which is why Microsoft ships them off and
 * offers an audit mode first. This says what each one would prevent and leaves
 * the decision where it belongs.
 */
function Hardening() {
  const [report, setReport] = useState<HardeningReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showAll, setShowAll] = useState(false);

  const refresh = useCallback(async () => {
    try {
      setReport(await api.hardening());
      setError(null);
    } catch (cause) {
      setError(reason(cause));
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const rules = report?.rules ?? [];
  const [changing, setChanging] = useState<string | null>(null);
  const [refusal, setRefusal] = useState<string | null>(null);

  /**
   * Ask Defender to change one protection.
   *
   * This module spent its life reading and explaining and never enabling,
   * because a rule in Block mode can stop software somebody depends on and
   * deciding that for them would be indefensible. The word carrying that
   * argument was *silently*: pressing a button having read what the rule
   * prevents is the informed decision the argument was protecting.
   *
   * Audit is offered first because it writes an event and blocks nothing, so
   * you can see what a rule would have stopped before it starts stopping it.
   *
   * The reply is a fresh survey, not an acknowledgement. Defender exiting
   * cleanly is not evidence: policy can override a setting the moment it is
   * written and Tamper Protection can refuse outright, so what gets drawn is
   * what Defender reports afterwards.
   */
  async function change(id: string, wanted: "audit" | "block" | "off") {
    setChanging(id);
    setRefusal(null);
    try {
      setReport(await api.setHardening(id, wanted));
    } catch (cause) {
      setRefusal(reason(cause));
    } finally {
      setChanging(null);
    }
  }

  const recommended = rules.filter((rule) => rule.recommended);
  const on = recommended.filter((rule) => isProtecting(rule.mode)).length;
  const shown = showAll ? rules : recommended;

  return (
    <section className="panel">
      <div className="panel-head">
        <h2>Protections Windows already has</h2>
        <button onClick={() => void refresh()}>Refresh</button>
      </div>

      <p className="lede panel-lede">
        Defender ships a set of Attack Surface Reduction rules — narrow blocks on
        things malware does and ordinary software almost never does. They are
        free, already installed, and off by default. This reports which are on
        and what each one would prevent. It cannot switch them on: a rule in
        blocking mode changes what every program may do, and that is your
        decision rather than this window's.
      </p>

      {error && (
        <div className="notice notice-down">
          <strong>The hardening state could not be read.</strong>
          <pre className="error">{error}</pre>
        </div>
      )}

      {report && (
        <>
          {refusal && (
            <div className="notice notice-warn">
              <strong>Defender declined.</strong> {refusal}
            </div>
          )}

          <div className={on === 0 ? "notice notice-warn" : "notice notice-ok"}>
            <strong>
              {on} of {recommended.length}
            </strong>{" "}
            recommended rules are switched on.
            {report.controlled_folder_access && (
              <>
                {" "}
                Controlled Folder Access, which stops unknown programs writing to
                your documents, is{" "}
                <strong>
                  {report.controlled_folder_access.replace(/_/g, " ")}
                </strong>
                .
              </>
            )}
          </div>

          {report.switches.length > 0 && (
            <ul className="findings">
              {report.switches.map((item) => {
                const on = item.state === "on";
                // Off against the Windows default is the only case worth
                // alarm: something turned it off. Off by default is ordinary,
                // and drawing it as a problem is how a tool becomes noise.
                const turnedOff = !on && item.default === "on" && item.state === "off";
                const tone = on ? "ordinary" : turnedOff ? "unusual" : "notable";
                return (
                  <li key={item.id} className={`finding finding-${tone}`}>
                    <div className="finding-head">
                      <span className="finding-name">{item.name}</span>
                      <span className={`badge attention-${tone}`}>
                        {typeof item.state === "string"
                          ? item.state.replace(/_/g, " ")
                          : "unrecognised"}
                      </span>
                    </div>
                    <p className="rule-explains">{item.explains}</p>
                    {turnedOff && (
                      <p className="rule-explains">
                        <strong>
                          Windows switches this on by itself, so something turned
                          it off.
                        </strong>
                      </p>
                    )}
                    {!on && item.id === "pua-protection" ? (
                      <div className="rule-actions">
                        <button
                          disabled={changing !== null}
                          onClick={() => void change(item.id, "block")}
                        >
                          {changing === item.id ? "Asking…" : "Turn on"}
                        </button>
                      </div>
                    ) : (
                      !on && <p className="footnote">{item.how}</p>
                    )}
                    {on && item.id === "pua-protection" && (
                      <div className="rule-actions">
                        <button
                          className="ghost"
                          disabled={changing !== null}
                          onClick={() => void change(item.id, "off")}
                        >
                          {changing === item.id ? "Asking…" : "Turn off"}
                        </button>
                      </div>
                    )}
                  </li>
                );
              })}
            </ul>
          )}

          <ul className="findings">
            {shown.map((rule) => (
              <li
                key={rule.id}
                className={`finding finding-${
                  isProtecting(rule.mode) ? "ordinary" : "notable"
                }`}
              >
                <div className="finding-head">
                  <span className="finding-name">{rule.name}</span>
                  <span
                    className={`badge attention-${
                      isProtecting(rule.mode) ? "ordinary" : "notable"
                    }`}
                  >
                    {modeLabel(rule.mode)}
                  </span>
                </div>
                <p className="rule-explains">{rule.explains}</p>
                <div className="rule-actions">
                  {isProtecting(rule.mode) ? (
                    <button
                      className="ghost"
                      disabled={changing !== null}
                      onClick={() => void change(rule.id, "off")}
                    >
                      {changing === rule.id ? "Asking…" : "Turn off"}
                    </button>
                  ) : (
                    <>
                      <button
                        disabled={changing !== null}
                        title="Writes an event and blocks nothing, so you can see what it would have stopped."
                        onClick={() => void change(rule.id, "audit")}
                      >
                        {changing === rule.id ? "Asking…" : "Try in audit mode"}
                      </button>
                      <button
                        className="ghost"
                        disabled={changing !== null}
                        title="Actually prevents the behaviour. This can stop software you depend on."
                        onClick={() => void change(rule.id, "block")}
                      >
                        Turn on
                      </button>
                    </>
                  )}
                </div>
                <p className="footnote">{rule.id}</p>
              </li>
            ))}
          </ul>

          {rules.length > recommended.length && (
            <button className="link-button" onClick={() => setShowAll(!showAll)}>
              {showAll
                ? "Show only the recommended ones"
                : `Show all ${rules.length} rules`}
            </button>
          )}

          <p className="footnote">
            Audit writes an event and blocks nothing, which is the sensible way
            to try a rule: you see what it would have stopped before it starts
            stopping it. Every change here goes through Defender's own interface
            rather than its settings in the registry, because Tamper Protection
            ignores the second — and what you see afterwards is Defender read
            back, not the fact that the request did not error.
          </p>
        </>
      )}
    </section>
  );
}

/**
 * What is installed in the browsers, and what it is allowed to read.
 *
 * An extension that reads every page is a statement about its permissions, not
 * an accusation: ad blockers and password managers do exactly that by design.
 * What is worth a second look is one that nobody installed from a store.
 */
function Extensions() {
  const [report, setReport] = useState<ExtensionReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [showAll, setShowAll] = useState(false);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      setReport(await api.browserExtensions());
      setError(null);
    } catch (cause) {
      setError(reason(cause));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const all = report?.extensions ?? [];
  const flagged = all.filter(
    (extension) => extension.source === "sideloaded" || extension.notes.length > 0,
  );
  const shown = showAll ? all : flagged;

  return (
    <section className="panel">
      <div className="panel-head">
        <h2>What your browsers are running</h2>
        <button onClick={() => void refresh()} disabled={loading}>
          {loading ? "Reading…" : "Refresh"}
        </button>
      </div>

      <p className="lede panel-lede">
        An extension that can read every page is, in practical terms, a program
        holding your passwords, your email and your session cookies. It carries
        no signature to check and starts nothing at boot, so the rest of this
        tool is structurally blind to it. Nothing here is called malicious —
        plenty of good extensions need exactly these permissions. What is listed
        is what each one is allowed to do.
      </p>

      {error && (
        <div className="notice notice-down">
          <strong>The browsers could not be read.</strong>
          <pre className="error">{error}</pre>
        </div>
      )}

      {report && (
        <>
          <div className="notice notice-ok">
            Found <strong>{all.length}</strong>{" "}
            {all.length === 1 ? "extension" : "extensions"} across{" "}
            {report.examined.length}{" "}
            {report.examined.length === 1 ? "profile" : "profiles"}
            {flagged.length > 0 && (
              <>
                , <strong>{flagged.length}</strong> of them with broad permissions
                or no store behind them
              </>
            )}
            .
          </div>

          {shown.length === 0 ? (
            <p className="empty">
              Nothing installed asks for more than it needs. That is the ordinary
              result.
            </p>
          ) : (
            <ul className="findings">
              {shown.map((extension) => (
                <li
                  key={`${extension.browser}-${extension.profile}-${extension.id}`}
                  className={`finding finding-${
                    extension.source === "sideloaded" ? "unusual" : "notable"
                  }`}
                >
                  <div className="finding-head">
                    <span className="finding-name">{extension.name}</span>
                    <span
                      className={`badge attention-${
                        extension.source === "sideloaded" ? "unusual" : "notable"
                      }`}
                    >
                      {extension.source === "sideloaded"
                        ? "not from a store"
                        : "from a store"}
                    </span>
                  </div>

                  <button
                    className="finding-path"
                    title="Open the containing folder"
                    onClick={() => void api.reveal(extension.path)}
                  >
                    {extension.browser} · {extension.profile} · {extension.id}
                  </button>

                  {extension.notes.length > 0 && (
                    <ul className="finding-reasons">
                      {extension.notes.map((note) => (
                        <li key={note}>{note}</li>
                      ))}
                    </ul>
                  )}

                  <dl className="finding-facts">
                    <div>
                      <dt>Version</dt>
                      <dd>{extension.version || "not stated"}</dd>
                    </div>
                    {extension.added_days_ago !== null && (
                      <div>
                        <dt>Added</dt>
                        <dd>
                          {extension.added_days_ago === 0
                            ? "today"
                            : extension.added_days_ago === 1
                              ? "yesterday"
                              : `${extension.added_days_ago} days ago`}
                        </dd>
                      </div>
                    )}
                    {extension.hosts.length > 0 && (
                      <div>
                        <dt>Sites</dt>
                        <dd>{extension.hosts.slice(0, 4).join(", ")}</dd>
                      </div>
                    )}
                  </dl>
                </li>
              ))}
            </ul>
          )}

          {all.length > flagged.length && (
            <button className="link-button" onClick={() => setShowAll(!showAll)}>
              {showAll
                ? "Show only the ones worth reading"
                : `Show all ${all.length} extensions`}
            </button>
          )}

          {report.unreadable.length > 0 && (
            <div className="notice notice-warn">
              <ul className="concerns">
                {report.unreadable.map((note) => (
                  <li key={note}>{note}</li>
                ))}
              </ul>
            </div>
          )}
        </>
      )}
    </section>
  );
}

const OBSERVATION_KINDS: Record<Observation["kind"], string> = {
  process_start: "a program started",
  scheduled_task: "a scheduled task appeared",
  sign_in_entry: "a sign-in entry appeared",
  startup_folder: "a Startup folder item appeared",
  service: "a service appeared",
};

function concernLabel(concern: Concern): string {
  return concern === "strong" ? "worth a look" : "worth knowing";
}

/**
 * What has started itself since the agent started watching.
 *
 * This is the half of the scanner that does not wait to be asked. The agent
 * takes a snapshot of what starts itself every couple of minutes, and anything
 * that appears in the shape unwanted software uses to run unseen — a hidden
 * task, a launcher running a script from a writable folder — is written down
 * here and in the audit log, with the evidence attached. It never acts on what
 * it finds; it makes sure a person can, before a day has gone by rather than
 * after.
 */
function BehaviourWatch() {
  const [report, setReport] = useState<BehaviourReport | null>(null);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      setReport(await api.behaviourEvents());
      setError(null);
    } catch (cause) {
      setError(reason(cause));
    }
  }, []);

  useEffect(() => {
    void refresh();
    // The watcher works on its own clock; a slow poll here just keeps the panel
    // current without asking the agent anything expensive.
    const timer = setInterval(() => void refresh(), 15000);
    return () => clearInterval(timer);
  }, [refresh]);

  const observations = report?.observations ?? [];

  return (
    <section className="panel">
      <div className="panel-head">
        <h2>What has started itself lately</h2>
        <button onClick={() => void refresh()}>Refresh</button>
      </div>

      <p className="lede panel-lede">
        The agent watches what newly registers itself to run at boot and notes
        anything that appears in the shape unwanted software uses to run unseen:
        a hidden scheduled task, or a launcher like <code>cmd.exe</code> or{" "}
        <code>MSBuild.exe</code> running a script from a folder any program can
        write to. It only ever reads and writes it down. Nothing here is deleted
        or blocked.
      </p>

      {error && (
        <div className="notice notice-down">
          <strong>The watcher could not be read.</strong>
          <pre className="error">{error}</pre>
        </div>
      )}

      {report && (
        <p className={report.watching ? "schedule-state on" : "schedule-state"}>
          {report.watching
            ? report.since
              ? `Watching since ${fmtStamp(report.since)}.`
              : "Watching."
            : "The watcher is not running."}
        </p>
      )}

      {observations.length === 0 ? (
        <p className="empty">
          Nothing has started itself in an unusual way since watching began. That
          is the ordinary result.
        </p>
      ) : (
        <ul className="findings">
          {observations.map((observation, index) => (
            <li
              key={`${observation.subject}-${observation.at}-${index}`}
              className={`finding finding-${
                observation.concern === "strong" ? "unusual" : "notable"
              }`}
            >
              <div className="finding-head">
                <span className="finding-name">{observation.summary}</span>
                <span
                  className={`badge attention-${
                    observation.concern === "strong" ? "unusual" : "notable"
                  }`}
                >
                  {concernLabel(observation.concern)}
                </span>
              </div>

              <button
                className="finding-path"
                title="Open the containing folder"
                onClick={() => void api.reveal(observation.subject)}
              >
                {observation.subject}
              </button>

              <ul className="finding-reasons">
                {observation.evidence.map((why) => (
                  <li key={why}>{why}</li>
                ))}
              </ul>

              <dl className="finding-facts">
                <div>
                  <dt>Seen</dt>
                  <dd>{fmtStamp(observation.at)}</dd>
                </div>
                <div>
                  <dt>Kind</dt>
                  <dd>{OBSERVATION_KINDS[observation.kind]}</dd>
                </div>
              </dl>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

/** A timestamp shown as local time, tolerant of anything odd. */
function fmtStamp(iso: string): string {
  const when = new Date(iso);
  return Number.isNaN(when.getTime()) ? iso : when.toLocaleString();
}

/**
 * Where a file came from and what it does at boot.
 *
 * The ordering is the agent's and so is the reasoning; this renders both and
 * adds no judgement of its own. There is no action button, because the evidence
 * here is circumstantial by construction and offering to delete things on the
 * strength of it would be exactly the behaviour this is meant to be an
 * alternative to.
 */
function Provenance() {
  const [report, setReport] = useState<ProvenanceReport | null>(null);
  const [rules, setRules] = useState<RuleReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [running, setRunning] = useState(false);
  const [progress, setProgress] = useState<Progress | null>(null);
  const [job, setJob] = useState<string | null>(null);
  const [stopped, setStopped] = useState(false);
  const [showAll, setShowAll] = useState(false);
  const [hasKey, setHasKey] = useState(false);

  const refreshKey = useCallback(() => {
    void api.virustotalKeyPresent().then(setHasKey).catch(() => setHasKey(false));
  }, []);

  useEffect(() => {
    refreshKey();
  }, [refreshKey]);

  const run = useCallback(async () => {
    setRunning(true);
    setError(null);
    setRules(null);
    setStopped(false);
    setProgress(null);
    try {
      // The agent finds the candidates, which needs privilege, and streams what
      // it is doing as it goes. The rules then run here in the shell, which
      // does not — see `kam-rules` for why that split is deliberate.
      const { job, result: survey } = await runJob(
        (job) => {
          setJob(job);
          return api.provenance(job);
        },
        setProgress,
      );
      void job;

      if (survey === null) {
        // Stopped, which is not a failure.
        setStopped(true);
        return;
      }
      setReport(survey);

      setProgress({
        stage: "Matching rules",
        done: 0,
        total: survey.findings.length,
        detail: null,
      });
      try {
        setRules(await api.scanRules(survey.findings.map((f) => f.path)));
      } catch (cause) {
        // The rule pass is an addition, not a prerequisite. Losing it should
        // not throw away a provenance report that already succeeded.
        setRules({
          matches: [],
          files_scanned: 0,
          skipped: [],
          rules_loaded: 0,
          user_rules_directory: "",
          user_rules_loaded: 0,
          problems: [`The rule scan did not run: ${reason(cause)}`],
        });
      }
    } catch (cause) {
      setError(reason(cause));
    } finally {
      setProgress(null);
      setJob(null);
      setRunning(false);
    }
  }, []);

  const matchesFor = useCallback(
    (path: string) =>
      rules?.matches.find(
        (entry) => entry.path.toLowerCase() === path.toLowerCase(),
      )?.matches ?? [],
    [rules],
  );

  // A rule match promotes a file into the list even when its provenance was
  // unremarkable: "this is a miner" is a stronger statement than anything the
  // provenance signals produce, and burying it under an "ordinary" badge
  // because the file happened to be signed would be perverse.
  const flagged =
    report?.findings.filter(
      (f) =>
        f.attention !== "ordinary" ||
        matchesFor(f.path).some((m) => m.confidence !== "informational"),
    ) ?? [];
  const shown = showAll ? (report?.findings ?? []) : flagged;

  return (
    <section className="panel">
      <div className="panel-head">
        <h2>Where your programs came from</h2>
        <button onClick={() => void run()} disabled={running}>
          {running ? "Examining…" : report ? "Run again" : "Examine"}
        </button>
      </div>

      {running && progress && (
        <ProgressBar
          progress={progress}
          onStop={job ? () => void stopJob(job) : undefined}
        />
      )}

      {stopped && (
        <p className="empty">
          Stopped. Nothing was changed — this only ever reads.
        </p>
      )}

      <p className="lede panel-lede">
        Every program that starts itself, and everything that arrived from
        outside this machine, judged on who signed it, when it appeared, where
        it came from and how it holds on. This is not a virus scan and finds
        nothing Defender would — it answers a different question, and none of it
        is proof of anything on its own.
      </p>

      {error && (
        <div className="notice notice-down">
          <strong>The examination did not finish.</strong>
          <pre className="error">{error}</pre>
        </div>
      )}

      {report && (
        <>
          <div className="notice notice-ok">
            Judged <strong>{report.examined}</strong>{" "}
            {report.examined === 1 ? "program" : "programs"}
            {report.swept_files > 0 && <> after passing over {report.swept_files} files</>}.{" "}
            {flagged.length === 0 ? (
              <>Nothing stood out.</>
            ) : (
              <>
                <strong>{flagged.length}</strong>{" "}
                {flagged.length === 1 ? "is" : "are"} worth reading.
              </>
            )}
            {rules && rules.rules_loaded > 0 && (
              <>
                {" "}
                Matched <strong>{rules.rules_loaded}</strong> rules against{" "}
                {rules.files_scanned} of them
                {rules.user_rules_loaded > 0 && (
                  <>, including {rules.user_rules_loaded} of your own</>
                )}
                .
              </>
            )}
          </div>

          {rules && rules.problems.length > 0 && (
            <div className="notice notice-warn">
              <strong>Rules:</strong>
              <ul className="concerns">
                {rules.problems.map((problem) => (
                  <li key={problem}>{problem}</li>
                ))}
              </ul>
            </div>
          )}

          {report.unreadable.length > 0 && (
            <div className="notice notice-warn">
              <strong>Not everything could be read:</strong>
              <ul className="concerns">
                {report.unreadable.map((note) => (
                  <li key={note}>{note}</li>
                ))}
              </ul>
            </div>
          )}

          {shown.length === 0 ? (
            <p className="empty">
              Nothing on this machine looks out of place. That is the ordinary
              result.
            </p>
          ) : (
            <ul className="findings">
              {shown.map((finding) => (
                <li key={finding.path} className={`finding finding-${finding.attention}`}>
                  <div className="finding-head">
                    <span className="finding-name">{finding.name}</span>
                    <span className={`badge attention-${finding.attention}`}>
                      {finding.attention === "unusual"
                        ? "worth a look"
                        : finding.attention === "notable"
                          ? "worth knowing"
                          : "nothing unusual"}
                    </span>
                  </div>

                  <button
                    className="finding-path"
                    title="Open the containing folder"
                    onClick={() => void api.reveal(finding.path)}
                  >
                    {finding.path}
                  </button>

                  {matchesFor(finding.path).map((hit) => (
                    <div key={hit.rule} className={`rule-hit rule-${hit.confidence}`}>
                      <div className="rule-hit-head">
                        <span className="rule-category">{hit.category}</span>
                        {!hit.bundled && <span className="rule-source">your rule</span>}
                        <span className="rule-name">{hit.rule}</span>
                      </div>
                      <p className="rule-explains">{hit.explains}</p>
                    </div>
                  ))}

                  <ul className="finding-reasons">
                    {finding.reasons.map((why) => (
                      <li key={why}>{why}</li>
                    ))}
                  </ul>

                  <dl className="finding-facts">
                    <div>
                      <dt>Signed by</dt>
                      <dd>{signatureLabel(finding.signature)}</dd>
                    </div>
                    <div>
                      <dt>Lives in</dt>
                      <dd>{LOCATION_LABELS[finding.location]}</dd>
                    </div>
                    {finding.origin_host && (
                      <div>
                        <dt>Came from</dt>
                        <dd>{finding.origin_host}</dd>
                      </div>
                    )}
                    {finding.arrived_days_ago !== null && (
                      <div>
                        <dt>Arrived</dt>
                        <dd>
                          {finding.arrived_days_ago === 0
                            ? "today"
                            : finding.arrived_days_ago === 1
                              ? "yesterday"
                              : `${finding.arrived_days_ago} days ago`}
                        </dd>
                      </div>
                    )}
                  </dl>

                  <VirusTotal path={finding.path} hasKey={hasKey} />

                  {finding.persistence.length > 0 && (
                    <ul className="finding-anchors">
                      {finding.persistence.map((entry, index) => (
                        <li key={`${entry.location}-${entry.name}-${index}`}>
                          <span className="anchor-kind">
                            {ANCHOR_LABELS[entry.anchor]}
                            {entry.hidden && " (hidden)"}
                            {entry.host && `, run by ${entry.host}`}
                          </span>
                          <span className="anchor-where">{entry.location}</span>
                        </li>
                      ))}
                    </ul>
                  )}
                </li>
              ))}
            </ul>
          )}

          {report.findings.length > flagged.length && (
            <button className="link-button" onClick={() => setShowAll(!showAll)}>
              {showAll
                ? "Show only what stands out"
                : `Show all ${report.findings.length} examined`}
            </button>
          )}

          <VirusTotalKey hasKey={hasKey} onChange={refreshKey} />

          {report.swept.length > 0 && (
            <p className="footnote">
              Folders swept for downloaded programs: {report.swept.join(", ")}.
              Programs that start themselves were found wherever they registered.
              {rules && rules.user_rules_directory && (
                <>
                  {" "}
                  Drop your own <code>.yar</code> files in{" "}
                  <button
                    className="inline-path"
                    onClick={() => void api.reveal(rules.user_rules_directory)}
                  >
                    {rules.user_rules_directory}
                  </button>{" "}
                  to have them matched too.
                </>
              )}
            </p>
          )}
        </>
      )}
    </section>
  );
}
