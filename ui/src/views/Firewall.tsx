import { useCallback, useEffect, useState } from "react";
import { api, reason } from "../lib/api";
import type {
  Connection,
  ConnectionReport,
  FirewallReport,
  FirewallRule,
  ProfileState,
} from "../lib/types";

/**
 * Windows Defender Firewall, with a usable view over it.
 *
 * Two halves. What the firewall has been told to do — profiles and rules,
 * which `wf.msc` shows badly and only to administrators. And what is actually
 * happening — every open socket joined to the program that owns it and whether
 * that program is signed, which nothing in Windows shows at all.
 *
 * This is the first view in the product with a button that changes the
 * machine, so blocking asks first, says exactly what it will do, and is
 * undoable from the same screen.
 */

function profileLabel(profile: ProfileState["profile"]): string {
  return profile === "domain" ? "Domain" : profile === "private" ? "Private" : "Public";
}

function Profiles({ profiles }: { profiles: ProfileState[] }) {
  return (
    <ul className="settings">
      {profiles.map((profile) => (
        <li
          key={profile.profile}
          className={`setting setting-${profile.enabled ? "on" : "off"}`}
        >
          <span className="setting-dot" />
          <span className="setting-body">
            <span className="setting-label">
              {profileLabel(profile.profile)}
              {profile.active && <span className="chip">in force now</span>}
            </span>
            <span className="setting-explain">
              {profile.profile === "domain"
                ? "Networks joined to a company domain."
                : profile.profile === "private"
                  ? "Home or work networks you have marked as trusted."
                  : "Cafés, airports, and anything else. Windows locks down hardest here."}
              {profile.enabled && (
                <>
                  {" "}
                  Incoming is{" "}
                  {profile.inbound_default === "block" ? "blocked" : "allowed"} by
                  default, outgoing is{" "}
                  {profile.outbound_default === "block" ? "blocked" : "allowed"}.
                </>
              )}
            </span>
          </span>
          <span className="setting-state">{profile.enabled ? "On" : "Off"}</span>
        </li>
      ))}
    </ul>
  );
}

function ConnectionRow({
  connection,
  onBlock,
  busy,
}: {
  connection: Connection;
  onBlock: (path: string, name: string) => void;
  busy: boolean;
}) {
  const peer =
    connection.remote_address === null
      ? null
      : `${connection.remote_address}:${connection.remote_port ?? 0}`;

  return (
    <li className={`conn${connection.external ? " conn-external" : ""}`}>
      <div className="conn-head">
        <span className="conn-name">{connection.name ?? "unidentified program"}</span>
        <span className="conn-proto">
          {connection.protocol} · {connection.state === "established"
            ? "connected"
            : connection.state === "listening"
              ? "listening"
              : connection.state === "connectionless"
                ? "bound"
                : "opening"}
        </span>
        {connection.image_path && (
          <button
            className="link-button conn-block"
            disabled={busy}
            onClick={() =>
              onBlock(connection.image_path ?? "", connection.name ?? "this program")
            }
          >
            Block
          </button>
        )}
      </div>

      <div className="conn-detail">
        {peer ? (
          <span className="conn-peer">{peer}</span>
        ) : (
          <span className="conn-peer">port {connection.local_port}</span>
        )}
        <span className="conn-signer">
          {connection.signer
            ? connection.signer
            : connection.unsigned === null
              ? "could not identify the program"
              : "not signed"}
        </span>
      </div>

      {connection.image_path && (
        <button
          className="conn-path"
          title="Open the containing folder"
          onClick={() => void api.reveal(connection.image_path ?? "")}
        >
          {connection.image_path}
        </button>
      )}
    </li>
  );
}

function RuleRow({ rule, onRemove }: { rule: FirewallRule; onRemove: (name: string) => void }) {
  return (
    <li className={`fw-rule${rule.ours ? " fw-rule-ours" : ""}`}>
      <div className="fw-rule-head">
        <span className={`badge ${rule.action === "block" ? "attention-unusual" : "attention-ordinary"}`}>
          {rule.action === "block" ? "block" : "allow"}
        </span>
        <span className="fw-rule-name">{rule.name}</span>
        {rule.ours ? (
          <button className="link-button" onClick={() => onRemove(rule.name)}>
            Remove
          </button>
        ) : (
          !rule.enabled && <span className="fw-rule-off">disabled</span>
        )}
      </div>
      <div className="fw-rule-detail">
        <span>{rule.direction === "in" ? "incoming" : "outgoing"}</span>
        {rule.application && <span className="fw-rule-app">{rule.application}</span>}
        {rule.grouping && !rule.ours && <span>{rule.grouping}</span>}
      </div>
    </li>
  );
}

export default function Firewall() {
  const [report, setReport] = useState<FirewallReport | null>(null);
  const [live, setLive] = useState<ConnectionReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [confirming, setConfirming] = useState<{ path: string; name: string } | null>(null);
  const [showAllRules, setShowAllRules] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setReport(await api.firewall());
      setError(null);
    } catch (cause) {
      setError(reason(cause));
      setReport(null);
    } finally {
      setLoading(false);
    }
    try {
      setLive(await api.connections());
    } catch {
      // The connection table is the secondary half; losing it should not
      // take the rules with it.
      setLive(null);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function block(path: string) {
    setBusy(true);
    setError(null);
    try {
      const rule = await api.blockProgram(path);
      setNote(`Blocked. Added the rule "${rule}", which you can remove below.`);
      await load();
    } catch (cause) {
      setError(reason(cause));
    } finally {
      setConfirming(null);
      setBusy(false);
    }
  }

  async function unblock(rule: string) {
    setBusy(true);
    setError(null);
    try {
      await api.unblockProgram(rule);
      setNote(`Removed "${rule}".`);
      await load();
    } catch (cause) {
      setError(reason(cause));
    } finally {
      setBusy(false);
    }
  }

  const ourRules = report?.rules.filter((rule) => rule.ours) ?? [];
  const otherRules = report?.rules.filter((rule) => !rule.ours) ?? [];
  const shownRules = showAllRules ? otherRules : otherRules.slice(0, 25);

  return (
    <>
      <div className="view-head">
        <div>
          <h1>Firewall</h1>
          <p className="lede">
            Windows Defender Firewall's own state and rules, and every program
            currently holding a network connection. This does not replace the
            firewall — it is the interface it never shipped with.
          </p>
        </div>
        <button onClick={() => void load()} disabled={loading || busy}>
          {loading ? "Reading…" : "Refresh"}
        </button>
      </div>

      {error && (
        <div className="notice notice-down">
          <strong>Something did not work.</strong>
          <pre className="error">{error}</pre>
        </div>
      )}

      {note && (
        <div className="notice notice-ok">
          {note}{" "}
          <button className="link-button" onClick={() => setNote(null)}>
            Dismiss
          </button>
        </div>
      )}

      {confirming && (
        <div className="notice notice-warn">
          <strong>Block {confirming.name}?</strong>
          <p className="confirm-body">
            This adds one Windows Firewall rule stopping{" "}
            <code>{confirming.path}</code> from making outgoing connections, on
            every network. Incoming traffic and every other program are left
            alone. The rule is tagged as ours, so you can remove it from this
            screen — or from Windows Firewall, where it appears under "KAM
            Security".
          </p>
          <div className="confirm-actions">
            <button onClick={() => void block(confirming.path)} disabled={busy}>
              {busy ? "Blocking…" : "Block it"}
            </button>
            <button className="link-button" onClick={() => setConfirming(null)}>
              Cancel
            </button>
          </div>
        </div>
      )}

      {report && (
        <>
          <div
            className={`notice ${report.concerns.length === 0 ? "notice-ok" : "notice-warn"}`}
          >
            {report.concerns.length === 0 ? (
              <>
                <strong>The firewall is on for every profile.</strong> Incoming
                connections nothing asked for are blocked, which is how Windows
                ships and how it should be.
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

          <section className="panel">
            <div className="panel-head">
              <h2>Profiles</h2>
            </div>
            <Profiles profiles={report.profiles} />
          </section>

          <div className="stat-row">
            <div className="stat">
              <span className="stat-label">Rules</span>
              <span className="stat-value">{report.total_rules.toLocaleString()}</span>
              <span className="stat-sub">{report.enabled_rules.toLocaleString()} enabled</span>
            </div>
            <div className="stat">
              <span className="stat-label">Blocking</span>
              <span className="stat-value">{report.blocking_rules.toLocaleString()}</span>
              <span className="stat-sub">the rest permit traffic</span>
            </div>
            <div className="stat">
              <span className="stat-label">Connected now</span>
              <span className="stat-value">{live?.established.toLocaleString() ?? "—"}</span>
              <span className="stat-sub">
                {live ? `${live.external} reaching the internet` : "not read"}
              </span>
            </div>
            <div className="stat">
              <span className="stat-label">Programs</span>
              <span className="stat-value">{live?.programs.toLocaleString() ?? "—"}</span>
              <span className="stat-sub">holding a connection</span>
            </div>
          </div>
        </>
      )}

      <section className="panel">
        <div className="panel-head">
          <h2>What is connected right now</h2>
        </div>
        <p className="muted">
          Every open socket, joined to the program that owns it and to whoever
          signed that program. Sorted by what is reaching the internet first.
          Blocking here adds one rule and changes nothing else.
        </p>
        {live === null ? (
          <p className="empty">The connection table could not be read.</p>
        ) : live.connections.length === 0 ? (
          <p className="empty">Nothing has a socket open.</p>
        ) : (
          <ul className="conns">
            {live.connections
              .filter((connection) => connection.state !== "connectionless")
              .slice(0, 60)
              .map((connection, index) => (
                <ConnectionRow
                  key={`${connection.process_id}-${connection.local_port}-${index}`}
                  connection={connection}
                  busy={busy}
                  onBlock={(path, name) => setConfirming({ path, name })}
                />
              ))}
          </ul>
        )}
      </section>

      {ourRules.length > 0 && (
        <section className="panel">
          <div className="panel-head">
            <h2>Rules this app added</h2>
          </div>
          <p className="muted">
            Everything KAM Security has added to the firewall, and nothing else.
            Rules Windows or your other software created are listed below and are
            not removable here.
          </p>
          <ul className="fw-rules">
            {ourRules.map((rule) => (
              <RuleRow key={rule.name} rule={rule} onRemove={(name) => void unblock(name)} />
            ))}
          </ul>
        </section>
      )}

      {report && (
        <section className="panel">
          <div className="panel-head">
            <h2>Everything else</h2>
          </div>
          <p className="muted">
            The {otherRules.length.toLocaleString()} rules Windows, your
            installers, and you have accumulated. Shown read-only: this product
            does not edit rules it did not create.
          </p>
          <ul className="fw-rules">
            {shownRules.map((rule, index) => (
              <RuleRow
                key={`${rule.name}-${index}`}
                rule={rule}
                onRemove={(name) => void unblock(name)}
              />
            ))}
          </ul>
          {otherRules.length > shownRules.length && (
            <button className="link-button" onClick={() => setShowAllRules(true)}>
              Show all {otherRules.length.toLocaleString()}
            </button>
          )}
        </section>
      )}

      <section className="panel">
        <div className="panel-head">
          <h2>Still to come</h2>
        </div>
        <ul className="planned">
          <li>
            Live connection events rather than a snapshot, from an ETW session
            on the kernel's network provider.
          </li>
          <li>
            Blocking a single address or port rather than a whole program.
          </li>
        </ul>
        <p className="footnote">
          Prompting before a connection opens is not on this list. It needs a
          kernel driver, an EV certificate and Microsoft attestation signing,
          and it is permanently out of scope — observing and then blocking gets
          most of the value with none of that.
        </p>
      </section>
    </>
  );
}
