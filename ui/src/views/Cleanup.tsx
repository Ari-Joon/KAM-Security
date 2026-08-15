import { useEffect, useState } from "react";
import { api, reason } from "../lib/api";
import * as fmt from "../lib/format";
import type { Confidence, Manifest, Orphan, OrphanSummary, Volume } from "../lib/types";

type Props = { volumes: Volume[]; onChanged: () => void };

const CONFIDENCE_LABEL: Record<Confidence, string> = {
  high: "Very likely leftover",
  medium: "Possibly leftover",
  low: "Probably still in use",
};

function OrphanRow({
  orphan,
  onQuarantine,
  busy,
}: {
  orphan: Orphan;
  onQuarantine: (orphan: Orphan) => void;
  busy: boolean;
}) {
  const [open, setOpen] = useState(false);
  return (
    <li className={`orphan orphan-${orphan.confidence}`}>
      <div className="orphan-main">
        <button className="orphan-toggle" onClick={() => setOpen(!open)}>
          <span className="app-caret">{open ? "▾" : "▸"}</span>
          <span className="orphan-name">{orphan.name}</span>
          <span className={`conf conf-${orphan.confidence}`}>
            {CONFIDENCE_LABEL[orphan.confidence]}
          </span>
          <span className="orphan-size">{fmt.bytes(orphan.bytes)}</span>
        </button>
        <button
          className="orphan-action"
          disabled={busy}
          onClick={() => onQuarantine(orphan)}
        >
          Quarantine
        </button>
      </div>
      {open && (
        <div className="orphan-detail">
          <code className="orphan-path">{orphan.path}</code>
          <ul className="orphan-reasons">
            {orphan.reasons.map((why) => (
              <li key={why}>{why}</li>
            ))}
          </ul>
        </div>
      )}
    </li>
  );
}

export default function Cleanup({ volumes, onChanged }: Props) {
  const [drive, setDrive] = useState("C:\\");
  const [orphans, setOrphans] = useState<Orphan[] | null>(null);
  const [summary, setSummary] = useState<OrphanSummary | null>(null);
  const [held, setHeld] = useState<Manifest[]>([]);
  const [running, setRunning] = useState(false);
  const [busyPath, setBusyPath] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);

  async function loadQuarantine() {
    try {
      setHeld(await api.quarantineList());
    } catch {
      // The list is secondary; a failure here must not hide the orphan scan.
    }
  }

  useEffect(() => {
    void loadQuarantine();
  }, []);

  async function find() {
    setRunning(true);
    setError(null);
    setNote(null);
    try {
      const report = await api.applications(drive);
      setOrphans(report.orphans);
      setSummary(report.orphan_summary);
    } catch (cause) {
      setError(reason(cause));
      setOrphans(null);
    } finally {
      setRunning(false);
      onChanged();
    }
  }

  async function quarantine(orphan: Orphan) {
    setBusyPath(orphan.path);
    setError(null);
    try {
      const manifest = await api.quarantine(
        orphan.path,
        `left behind: ${orphan.reasons[0] ?? "no installed application matches it"}`,
      );
      setNote(
        `Moved ${orphan.name} (${fmt.bytes(orphan.bytes)}) into quarantine. ` +
          `Restorable for 30 days.`,
      );
      setOrphans((current) =>
        current ? current.filter((item) => item.path !== orphan.path) : current,
      );
      setHeld((current) => [manifest, ...current]);
    } catch (cause) {
      setError(reason(cause));
    } finally {
      setBusyPath(null);
      onChanged();
    }
  }

  async function restore(id: string) {
    setError(null);
    try {
      const manifest = await api.restore(id);
      setNote(`Restored to ${manifest.original_path}.`);
      await loadQuarantine();
    } catch (cause) {
      setError(reason(cause));
    } finally {
      onChanged();
    }
  }

  const active = held.filter((item) => !item.restored);

  return (
    <>
      <div className="view-head">
        <div>
          <h1>Cleanup</h1>
          <p className="lede">
            Directories left behind by software that is no longer installed.
            Nothing is deleted — items are moved aside and can be put back.
          </p>
        </div>
      </div>

      <div className="notice notice-warn">
        <strong>Read this before acting.</strong> These are suggestions produced
        from names and dates, not certainties. Quarantining moves a folder; an
        application that was still using it will misbehave until you restore it.
        Only <code>ProgramData</code> and the two <code>AppData</code> roots are
        ever examined, one level deep, and never a directory Windows owns.
      </div>

      <section className="panel">
        <div className="scan-bar">
          <select
            value={drive}
            onChange={(event) => setDrive(event.target.value)}
            disabled={running}
          >
            {volumes
              .filter((volume) => volume.supports_mft)
              .map((volume) => (
                <option key={volume.root} value={volume.root}>
                  {volume.root} {volume.label ? `— ${volume.label}` : ""}
                </option>
              ))}
          </select>
          <button className="primary" onClick={() => void find()} disabled={running}>
            {running ? "Looking…" : "Find leftovers"}
          </button>
          <span className="muted">Needs an agent with administrative rights.</span>
        </div>

        {error && <pre className="error">{error}</pre>}
        {note && <div className="notice notice-ok">{note}</div>}

        {summary && (
          <div className="stat-row tight">
            <div className="stat">
              <span className="stat-label">Found</span>
              <span className="stat-value">{fmt.count(summary.found)}</span>
            </div>
            <div className="stat">
              <span className="stat-label">Holding</span>
              <span className="stat-value">{fmt.bytes(summary.total_bytes)}</span>
            </div>
            <div className="stat">
              <span className="stat-label">Very likely leftover</span>
              <span className="stat-value">{fmt.bytes(summary.confident_bytes)}</span>
            </div>
          </div>
        )}
      </section>

      {orphans && (
        <section className="panel">
          <div className="panel-head">
            <h2>Candidates</h2>
          </div>
          {orphans.length === 0 ? (
            <p className="empty">
              Nothing unaccounted for above 64 MB. That is a good result.
            </p>
          ) : (
            <ul className="orphans">
              {orphans.map((orphan) => (
                <OrphanRow
                  key={orphan.path}
                  orphan={orphan}
                  busy={busyPath === orphan.path}
                  onQuarantine={(item) => void quarantine(item)}
                />
              ))}
            </ul>
          )}
        </section>
      )}

      <section className="panel">
        <div className="panel-head">
          <h2>Quarantine</h2>
          <button onClick={() => void loadQuarantine()}>Refresh</button>
        </div>
        {active.length === 0 ? (
          <p className="empty">Nothing held.</p>
        ) : (
          <ul className="files">
            {active.map((item) => (
              <li key={item.id} className="held">
                <div className="held-body">
                  <span className="held-path">{item.original_path}</span>
                  <span className="held-reason">{item.reason}</span>
                </div>
                <span className="held-size">{fmt.bytes(item.bytes)}</span>
                <button onClick={() => void restore(item.id)}>Restore</button>
              </li>
            ))}
          </ul>
        )}
      </section>
    </>
  );
}
