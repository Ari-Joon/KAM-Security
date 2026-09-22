import { useCallback, useEffect, useState } from "react";
import { api, reason } from "../lib/api";
import type { UpdateCheck as Check } from "../lib/types";

/**
 * Whether a newer release of KAM Security has been published.
 *
 * It tells; it does not install. The program runs a service with the highest
 * privilege Windows has, so what an automatic installer puts on a machine runs
 * with that privilege too, and doing that safely needs signed releases first.
 * Until then this says a new version exists, shows its notes, and opens the
 * release page for the person to install it themselves.
 *
 * A check that could not be completed says so. It is never shown as "this is
 * the latest version", because that would be a failure presented as a clean
 * answer, which is the one thing this product is built not to do.
 */

const AUTO_KEY = "kam.update.auto";
const LAST_KEY = "kam.update.last";
/** Once a day is plenty for a program that releases every week or two. */
const DAY_MS = 24 * 60 * 60 * 1000;

type Remembered = { at: number; result: Check };

function read<T>(key: string): T | null {
  try {
    const raw = localStorage.getItem(key);
    return raw ? (JSON.parse(raw) as T) : null;
  } catch {
    return null;
  }
}

function write(key: string, value: unknown) {
  try {
    localStorage.setItem(key, JSON.stringify(value));
  } catch {
    // A preference that cannot be saved is a preference that resets; nothing
    // is lost that a second check would not recover.
  }
}

function when(iso: string): string {
  const at = Date.parse(iso);
  if (Number.isNaN(at)) return "on an unknown date";
  return new Date(at).toLocaleDateString(undefined, {
    day: "numeric",
    month: "long",
    year: "numeric",
  });
}

function ago(ms: number): string {
  const minutes = Math.round((Date.now() - ms) / 60000);
  if (minutes < 1) return "just now";
  if (minutes < 60) return `${minutes} minute${minutes === 1 ? "" : "s"} ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours} hour${hours === 1 ? "" : "s"} ago`;
  const days = Math.round(hours / 24);
  return `${days} day${days === 1 ? "" : "s"} ago`;
}

export default function UpdateCheck() {
  const [remembered, setRemembered] = useState<Remembered | null>(() =>
    read<Remembered>(LAST_KEY),
  );
  const [auto, setAuto] = useState<boolean>(() => read<boolean>(AUTO_KEY) ?? true);
  const [checking, setChecking] = useState(false);
  const [failure, setFailure] = useState<string | null>(null);
  const [showNotes, setShowNotes] = useState(false);

  const check = useCallback(async () => {
    setChecking(true);
    setFailure(null);
    try {
      const result = await api.checkForUpdate();
      const entry = { at: Date.now(), result };
      setRemembered(entry);
      write(LAST_KEY, entry);
    } catch (cause) {
      // The shell itself failed, not GitHub. Still not "up to date".
      setFailure(reason(cause));
    } finally {
      setChecking(false);
    }
  }, []);

  // Once a day when switched on, and never more: GitHub allows sixty
  // unauthenticated requests an hour from one address, which a household of
  // machines behind one router can use up.
  useEffect(() => {
    if (!auto) return;
    const last = read<Remembered>(LAST_KEY);
    if (!last || Date.now() - last.at > DAY_MS) void check();
  }, [auto, check]);

  const result = remembered?.result ?? null;
  const latest = result?.latest ?? null;

  return (
    <section className="panel">
      <div className="panel-head">
        <h2>Updates</h2>
        <button onClick={() => void check()} disabled={checking}>
          {checking ? "Checking…" : "Check now"}
        </button>
      </div>

      {checking && !result && (
        <p className="muted">Asking GitHub for the latest release.</p>
      )}

      {failure && (
        <div className="notice notice-warn">
          <strong>Could not check for updates.</strong> {failure}
        </div>
      )}

      {result && result.newer && latest && (
        <div className="notice notice-ok">
          <strong>KAM Security {latest.version} is available.</strong> You have{" "}
          {result.current}. It was published {when(latest.published_at)}.
          <div className="rule-actions">
            <button onClick={() => void api.openReleasePage(latest.url)}>
              See the release
            </button>
            {latest.notes && (
              <button className="ghost" onClick={() => setShowNotes(!showNotes)}>
                {showNotes ? "Hide what changed" : "What changed"}
              </button>
            )}
          </div>
          {showNotes && <pre className="update-notes">{latest.notes}</pre>}
          <p className="small muted">
            Follow the installation steps on the release page. The new version
            replaces this one in the same place, so the desktop shortcut keeps
            working.
          </p>
        </div>
      )}

      {result && !result.newer && result.problem && (
        <div className="notice notice-warn">
          <strong>Could not tell whether there is a newer version.</strong>{" "}
          {result.problem}
        </div>
      )}

      {result && !result.newer && !result.problem && (
        <p className="muted">
          {result.current} is the latest release
          {latest ? `, published ${when(latest.published_at)}` : ""}.
        </p>
      )}

      <p className="small muted">
        {remembered ? `Last checked ${ago(remembered.at)}. ` : "Not checked yet. "}
        Checking asks GitHub's public API for the newest release and sends
        nothing about this machine. Nothing is downloaded or installed.
      </p>

      <label className="small">
        <input
          type="checkbox"
          checked={auto}
          onChange={(event) => {
            setAuto(event.target.checked);
            write(AUTO_KEY, event.target.checked);
          }}
        />{" "}
        Check once a day when KAM Security opens
      </label>
    </section>
  );
}
