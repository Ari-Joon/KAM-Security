import { useCallback, useEffect, useState } from "react";
import { api, reason } from "../lib/api";
import type {
  Anchor,
  DefenderReport,
  Location,
  ProvenanceReport,
  RuleReport,
  Signature,
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

      <Provenance />

      <section className="panel">
        <div className="panel-head">
          <h2>Still to come</h2>
        </div>
        <ul className="planned">
          <li>Starting and stopping scans, with progress rather than a frozen button.</li>
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
  const [stage, setStage] = useState<string>("");
  const [showAll, setShowAll] = useState(false);

  const run = useCallback(async () => {
    setRunning(true);
    setError(null);
    setRules(null);
    try {
      // The agent finds the candidates, which needs privilege. The rules then
      // run here in the shell, which does not — see `kam-rules` for why that
      // split is deliberate rather than incidental.
      setStage("Looking for programs that start themselves…");
      const survey = await api.provenance();
      setReport(survey);

      setStage("Matching rules…");
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
      setStage("");
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

      {running && stage && <p className="empty">{stage}</p>}

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

                  {finding.persistence.length > 0 && (
                    <ul className="finding-anchors">
                      {finding.persistence.map((entry, index) => (
                        <li key={`${entry.location}-${entry.name}-${index}`}>
                          <span className="anchor-kind">{ANCHOR_LABELS[entry.anchor]}</span>
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
