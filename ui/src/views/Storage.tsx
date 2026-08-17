import { useEffect, useMemo, useRef, useState } from "react";
import Treemap from "../components/Treemap";
import FileRow from "../components/FileRow";
import { api, reason } from "../lib/api";
import * as fmt from "../lib/format";
import type { Scan, TreeNode, Volume } from "../lib/types";

type Props = {
  volumes: Volume[];
  initialRoot: string | null;
  onScanned: () => void;
};

export default function Storage({ volumes, initialRoot, onScanned }: Props) {
  const [target, setTarget] = useState(initialRoot ?? "C:\\");
  const [scan, setScan] = useState<Scan | null>(null);
  const [running, setRunning] = useState(false);
  const [elapsed, setElapsed] = useState(0);
  const [error, setError] = useState<string | null>(null);
  // Path from the scanned root down to whatever the treemap is showing.
  const [trail, setTrail] = useState<TreeNode[]>([]);
  const startedAt = useRef(0);

  useEffect(() => {
    if (initialRoot) setTarget(initialRoot);
  }, [initialRoot]);

  // A full drive takes about a minute. A spinner with no numbers on it reads as
  // a hang, so the elapsed time keeps ticking where the user can see it.
  useEffect(() => {
    if (!running) return;
    const timer = setInterval(() => {
      setElapsed(Math.round((Date.now() - startedAt.current) / 1000));
    }, 250);
    return () => clearInterval(timer);
  }, [running]);

  /// Opening Explorer can fail if the item has since gone; say so rather than
  /// letting the click do nothing.
  async function reveal(path: string) {
    try {
      await api.reveal(path);
    } catch (cause) {
      setError(reason(cause));
    }
  }

  async function run() {
    setRunning(true);
    setError(null);
    setElapsed(0);
    startedAt.current = Date.now();
    try {
      const result = await api.scan(target);
      setScan(result);
      setTrail([result.tree]);
    } catch (cause) {
      setError(reason(cause));
      setScan(null);
      setTrail([]);
    } finally {
      setRunning(false);
      onScanned();
    }
  }

  const current = trail.length > 0 ? trail[trail.length - 1] : null;

  // The scanned drive, so the header can say "1.0 TB of 1.8 TB" rather than
  // leaving the measured figure without anything to compare against.
  const volume = useMemo(
    () => volumes.find((item) => item.root.toUpperCase() === target.toUpperCase()),
    [volumes, target],
  );

  const rows = useMemo(() => {
    if (!current) return [];
    return [...current.children].sort((a, b) => b.bytes - a.bytes);
  }, [current]);

  return (
    <>
      <div className="view-head">
        <div>
          <h1>Storage</h1>
          <p className="lede">
            Measure a drive or folder and see where the space actually went.
          </p>
        </div>
      </div>

      <section className="panel">
        <div className="scan-bar">
          <select
            value={target}
            onChange={(event) => setTarget(event.target.value)}
            disabled={running}
          >
            {volumes.map((volume) => (
              <option key={volume.root} value={volume.root}>
                {volume.root} {volume.label ? `— ${volume.label}` : ""}
              </option>
            ))}
            {!volumes.some((volume) => volume.root === target) && (
              <option value={target}>{target}</option>
            )}
          </select>
          <button className="primary" onClick={() => void run()} disabled={running}>
            {running ? `Scanning… ${elapsed}s` : "Scan"}
          </button>
          {running && (
            <span className="muted">
              A full drive takes about a minute. The agent stays responsive
              meanwhile.
            </span>
          )}
        </div>

        {error && <pre className="error">{error}</pre>}

        {scan && scan.method === "directory_walk" && scan.fallback_reason && (
          <div className="notice notice-warn">
            <strong>Read the slow way.</strong> The master file table gives the
            same answer in about two seconds and counts hard links correctly,
            but it needs administrative rights. Run the agent as a service, or
            elevated, to use it.
            <pre className="error">{scan.fallback_reason}</pre>
          </div>
        )}

        {scan && (
          <div className="stat-row tight">
            <div className="stat">
              <span className="stat-label">Measured</span>
              <span className="stat-value">{fmt.bytes(scan.total_bytes)}</span>
            </div>
            {volume && (
              <div className="stat stat-wide">
                <span className="stat-label">Drive</span>
                <span className="stat-value">
                  {fmt.bytes(volume.total_bytes - volume.free_bytes)}
                  <span className="stat-of"> of {fmt.bytes(volume.total_bytes)}</span>
                </span>
                <span className="usage-track">
                  <span
                    className="usage-fill usage-accent"
                    style={{
                      width: `${fmt.percent(
                        volume.total_bytes - volume.free_bytes,
                        volume.total_bytes,
                      )}%`,
                    }}
                  />
                </span>
                <span className="stat-sub">{fmt.bytes(volume.free_bytes)} free</span>
              </div>
            )}
            <div className="stat">
              <span className="stat-label">Method</span>
              <span className="stat-value small">
                {scan.method === "master_file_table"
                  ? "Master file table"
                  : "Directory walk"}
              </span>
            </div>
            <div className="stat">
              <span className="stat-label">Files</span>
              <span className="stat-value">{fmt.count(scan.file_count)}</span>
            </div>
            <div className="stat">
              <span className="stat-label">Folders</span>
              <span className="stat-value">{fmt.count(scan.directory_count)}</span>
            </div>
            <div className="stat">
              <span className="stat-label">Took</span>
              <span className="stat-value">{fmt.duration(scan.elapsed_ms)}</span>
            </div>
            <div className="stat">
              <span className="stat-label">Unreadable</span>
              <span className="stat-value">{fmt.count(scan.unreadable)}</span>
            </div>
          </div>
        )}
      </section>

      {scan && current && (
        <>
          <section className="panel">
            <div className="panel-head">
              <h2>Map</h2>
              <nav className="crumbs">
                {trail.map((node, index) => (
                  <button
                    key={node.path + index}
                    className="crumb"
                    disabled={index === trail.length - 1}
                    onClick={() => setTrail(trail.slice(0, index + 1))}
                  >
                    {index === 0 ? scan.root : node.name}
                  </button>
                ))}
              </nav>
            </div>
            <p className="muted">
              Each rectangle is sized by what it holds. Click one to go deeper.
            </p>
            <Treemap node={current} onDrill={(child) => setTrail([...trail, child])} />
          </section>

          <div className="split">
            <section className="panel">
              <div className="panel-head">
                <h2>Biggest folders here</h2>
              </div>
              <ul className="bars">
                {rows.slice(0, 10).map((row) => (
                  <li key={row.path} className="bar-row">
                    <button
                      className="bar-name link"
                      title={`Show ${row.path} in Explorer`}
                      onClick={() => void reveal(row.path)}
                    >
                      {row.name}
                    </button>
                    <span className="bar-track">
                      <span
                        className="bar-fill"
                        style={{ width: `${fmt.percent(row.bytes, current.bytes)}%` }}
                      />
                    </span>
                    <span className="bar-value">{fmt.bytes(row.bytes)}</span>
                  </li>
                ))}
                {rows.length === 0 && <p className="empty">No subfolders.</p>}
              </ul>
            </section>

            <section className="panel">
              <div className="panel-head">
                <h2>Largest single files</h2>
              </div>
              <ul className="files">
                {scan.largest_files.slice(0, 10).map((file) => (
                  <FileRow
                    key={file.path}
                    path={file.path}
                    bytes={file.bytes}
                    onReveal={(path) => void reveal(path)}
                  />
                ))}
                {scan.largest_files.length === 0 && (
                  <p className="empty">Nothing above 64 MB.</p>
                )}
              </ul>
            </section>
          </div>
        </>
      )}

      {!scan && !running && !error && (
        <section className="panel">
          <p className="empty">
            Nothing measured yet. Pick a drive and press Scan.
          </p>
        </section>
      )}
    </>
  );
}
