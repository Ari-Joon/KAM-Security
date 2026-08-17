import { useEffect, useState } from "react";
import { api, reason } from "../lib/api";
import * as fmt from "../lib/format";
import FileRow from "../components/FileRow";
import type {
  Confidence,
  Download,
  DownloadSummary,
  DuplicateGroup,
  DuplicateSummary,
  Manifest,
  Orphan,
  OrphanSummary,
  Volume,
} from "../lib/types";

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
  const [downloads, setDownloads] = useState<Download[] | null>(null);
  const [downloadSummary, setDownloadSummary] = useState<DownloadSummary | null>(null);
  const [duplicates, setDuplicates] = useState<DuplicateGroup[] | null>(null);
  const [duplicateSummary, setDuplicateSummary] = useState<DuplicateSummary | null>(null);
  const [findingDuplicates, setFindingDuplicates] = useState(false);
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
      setDownloads(report.downloads);
      setDownloadSummary(report.download_summary);
    } catch (cause) {
      setError(reason(cause));
      setOrphans(null);
      setDownloads(null);
    } finally {
      setRunning(false);
      onChanged();
    }
  }

  async function findDuplicates() {
    setFindingDuplicates(true);
    setError(null);
    try {
      const report = await api.duplicates(drive);
      setDuplicates(report.groups);
      setDuplicateSummary(report.summary);
    } catch (cause) {
      setError(reason(cause));
      setDuplicates(null);
    } finally {
      setFindingDuplicates(false);
      onChanged();
    }
  }

  async function reveal(path: string) {
    try {
      await api.reveal(path);
    } catch (cause) {
      setError(reason(cause));
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

      <section className="panel">
        <div className="panel-head">
          <h2>What this page does</h2>
        </div>
        <ol className="explain">
          <li>
            <strong>Leftovers</strong> are folders under <code>ProgramData</code>{" "}
            and the two <code>AppData</code> roots that no installed application
            accounts for — usually left behind when something was uninstalled
            years ago. Each says why it is listed.
          </li>
          <li>
            <strong>Downloads</strong> are large files Windows recorded as having
            come from the internet, with the site they came from and when they
            arrived. Nothing here is a suggestion to delete; it is a list of
            things you may have forgotten you kept.
          </li>
          <li>
            <strong>Duplicates</strong> are files that are byte-for-byte
            identical. Finding them reads file contents rather than the
            filesystem's index, so it has its own button. Copies inside an
            application's own folder are usually there on purpose — this only
            reports them.
          </li>
          <li>
            <strong>Quarantine</strong> is where anything you act on goes. Items
            are <em>moved</em>, never deleted, and can be put back for 30 days.
          </li>
        </ol>
        <p className="muted">
          Only those three folders are examined, one level deep, and never a
          directory Windows owns. These are suggestions from names and dates,
          not certainties — an application still using a folder will misbehave
          until you restore it.
        </p>
      </section>

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

      {downloads && (
        <section className="panel">
          <div className="panel-head">
            <h2>Downloads you may have forgotten</h2>
            {downloadSummary && (
              <span className="muted">
                {fmt.count(downloadSummary.found)} files ·{" "}
                {fmt.bytes(downloadSummary.total_bytes)}
              </span>
            )}
          </div>
          <p className="muted">
            Files over 32 MB carrying Windows' own record of having come from
            the internet. Click one to show it in Explorer.
            {downloadSummary && !downloadSummary.last_access_tracked && (
              <>
                {" "}
                This machine does not update last-access times, so there is no
                way to tell which of these were ever opened.
              </>
            )}
          </p>
          {downloads.length === 0 ? (
            <p className="empty">
              Nothing over 32 MB carries a download record.
            </p>
          ) : (
            <ul className="files">
              {downloads.slice(0, 25).map((download) => (
                <FileRow
                  key={download.path}
                  path={download.path}
                  bytes={download.bytes}
                  onReveal={(path) => void reveal(path)}
                  note={
                    <>
                      {fmt.host(download.host_url) ?? "source not recorded"}
                      {download.days_since_arrival !== null && (
                        <> · arrived {download.days_since_arrival} days ago</>
                      )}
                      {download.zone === "restricted" && (
                        <span className="zone-restricted"> · restricted zone</span>
                      )}
                    </>
                  }
                />
              ))}
            </ul>
          )}
        </section>
      )}

      <section className="panel">
        <div className="panel-head">
          <h2>Identical copies</h2>
          <button onClick={() => void findDuplicates()} disabled={findingDuplicates}>
            {findingDuplicates ? "Comparing…" : "Find duplicates"}
          </button>
        </div>
        <p className="muted">
          Compared by size, then by their first 64 KB, then in full — so
          "duplicate" means every byte, not a guess. Nothing here is removed for
          you; several copies of a file are often deliberate.
        </p>

        {duplicateSummary && (
          <div className="stat-row tight">
            <div className="stat">
              <span className="stat-label">Sets</span>
              <span className="stat-value">{fmt.count(duplicateSummary.groups)}</span>
            </div>
            <div className="stat">
              <span className="stat-label">Wasted</span>
              <span className="stat-value">
                {fmt.bytes(duplicateSummary.wasted_bytes)}
              </span>
            </div>
            <div className="stat">
              <span className="stat-label">Read in full</span>
              <span className="stat-value">
                {fmt.count(duplicateSummary.fully_hashed)}
              </span>
            </div>
            <div className="stat">
              <span className="stat-label">Took</span>
              <span className="stat-value">
                {fmt.duration(duplicateSummary.elapsed_ms)}
              </span>
            </div>
          </div>
        )}

        {duplicates && duplicates.length === 0 && (
          <p className="empty">No identical files over 8 MB.</p>
        )}

        {duplicates && duplicates.length > 0 && (
          <ul className="dupes">
            {duplicates.slice(0, 25).map((group) => (
              <li key={group.paths[0]} className="dupe">
                <div className="dupe-head">
                  <span className="dupe-count">
                    {group.paths.length} copies of {fmt.bytes(group.bytes)}
                  </span>
                  <span className="dupe-waste">
                    {fmt.bytes(group.wasted_bytes)} wasted
                  </span>
                </div>
                <ul className="files">
                  {group.paths.map((path) => (
                    <FileRow
                      key={path}
                      path={path}
                      bytes={group.bytes}
                      onReveal={(target) => void reveal(target)}
                    />
                  ))}
                </ul>
              </li>
            ))}
          </ul>
        )}
      </section>

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
