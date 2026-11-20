import { useState } from "react";
import { api, reason } from "../lib/api";
import type { DefenderExclusions as Found, ExclusionKind, ExclusionList } from "../lib/types";

/**
 * What Defender has been told to skip, shown only when asked.
 *
 * Windows hides this from anyone who is not an administrator, on purpose:
 * knowing it tells an attacker where to hide. So nothing about it is shown
 * here, not even how many there are, until the person asks, and asking goes
 * through Windows' own permission prompt, the one Windows Security uses. The
 * list lives in this panel's state alone: it is gone when the page is left,
 * and the Activity log records only that it was read and how many entries it
 * held. Nothing here adds, removes or judges an exclusion.
 */

const KINDS: { kind: ExclusionKind["kind"]; label: string }[] = [
  { kind: "paths", label: "Paths (folders and files)" },
  { kind: "extensions", label: "Extensions (kinds of file)" },
  { kind: "processes", label: "Processes (programs)" },
  { kind: "ip_addresses", label: "IP addresses" },
];

/** The lists of one kind, from Defender's own settings and from a policy. */
function Entries({ lists }: { lists: ExclusionList[] }) {
  const entries = lists.flatMap((list) =>
    list.entries.map((entry) => ({ ...entry, by_policy: list.by_policy })),
  );
  const partial = lists.some((list) => !list.whole);
  return (
    <>
      {entries.length === 0 ? (
        <p className="muted small">None.</p>
      ) : (
        <ul className="entries compact">
          {entries.map((entry, index) => (
            <li key={`${entry.by_policy}\u0000${entry.value}\u0000${index}`} className="entry">
              <div className="entry-body">
                <span className="action">
                  <code>{entry.value}</code>
                </span>
                {entry.by_policy && <span className="detail">Set by a policy.</span>}
                {!entry.exact && (
                  <span className="detail">
                    Part of this name is hidden, so it is shown as near as it can be.
                  </span>
                )}
              </div>
            </li>
          ))}
        </ul>
      )}
      {partial && (
        <p className="footnote">
          This list changed while it was being read, so it may not be all of it.
        </p>
      )}
    </>
  );
}

export default function DefenderExclusions() {
  const [found, setFound] = useState<Found | null>(null);
  const [refused, setRefused] = useState<string | null>(null);
  const [asking, setAsking] = useState(false);

  async function ask() {
    setAsking(true);
    setRefused(null);
    try {
      setFound(await api.defenderExclusions());
    } catch (cause) {
      setFound(null);
      setRefused(reason(cause));
    } finally {
      setAsking(false);
    }
  }

  const others = found
    ? [
        ...new Set(
          found.lists.flatMap((list) => (list.kind.kind === "other" ? [list.kind.name] : [])),
        ),
      ]
    : [];
  const total = found ? found.lists.reduce((sum, list) => sum + list.entries.length, 0) : 0;

  return (
    <section className="panel">
      <div className="panel-head">
        <h2>What Defender has been told to skip</h2>
        {found ? (
          <button className="ghost" onClick={() => setFound(null)}>
            Hide the list
          </button>
        ) : (
          <button onClick={() => void ask()} disabled={asking}>
            {asking ? "Waiting for permission…" : "Show them"}
          </button>
        )}
      </div>
      <p className="lede panel-lede">
        Defender can be told not to look at some folders and files, kinds of file, programs
        or network addresses. Windows shows that list only to an administrator, because
        knowing it tells an attacker where to hide. So KAM shows nothing about it until you
        ask, and then asks for Windows' permission first, as Windows Security does. The list
        stays on this page until you leave it and is not kept. The Activity log records that
        it was read and how many entries it held, not the entries.
      </p>

      {refused && (
        <div className="notice notice-warn">
          <strong>Nothing was shown.</strong> {refused}
        </div>
      )}

      {found && (
        <>
          <p>Defender does not look at anything listed here.</p>
          {total === 0 && found.unread.length === 0 && (
            <p className="muted">
              Defender has been told to skip nothing: no list holds an entry, in its own
              settings or set by a policy.
            </p>
          )}
          {KINDS.map(({ kind, label }) => (
            <div key={kind}>
              <p className="modal-label">{label}</p>
              <Entries lists={found.lists.filter((list) => list.kind.kind === kind)} />
            </div>
          ))}
          {others.map((name) => (
            <div key={`other-${name}`}>
              <p className="modal-label">Another list Defender keeps here, by its own name</p>
              <p className="small">
                <code>{name}</code>
              </p>
              <Entries
                lists={found.lists.filter(
                  (list) => list.kind.kind === "other" && list.kind.name === name,
                )}
              />
            </div>
          ))}
          {found.unread.length > 0 && (
            <div className="notice notice-warn">
              <strong>Not everything could be read.</strong>
              <ul className="concerns">
                {found.unread.map((why) => (
                  <li key={why}>{why}.</li>
                ))}
              </ul>
            </div>
          )}
          <p className="footnote">
            An entry marked as set by a policy comes from an organisation's policy, under
            HKLM\SOFTWARE\Policies, rather than from Windows Security or this PC's own
            settings.
          </p>
        </>
      )}
    </section>
  );
}
