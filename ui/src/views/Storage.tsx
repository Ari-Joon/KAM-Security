import { useEffect, useMemo, useRef, useState } from "react";
import Treemap from "../components/Treemap";
import FileRow from "../components/FileRow";
import GrowthPanel from "../components/Growth";
import { KeptNote, NotKeptNote, UnreadableNote } from "../components/Kept";
import MeasuredAt, { whenMeasured } from "../components/MeasuredAt";
import { api, reason } from "../lib/api";
import { recall, remember } from "../lib/remembered";
import * as fmt from "../lib/format";
import type { FolderScan, Scan, ScanMethod, TreeNode, Volume } from "../lib/types";

type Props = {
  volumes: Volume[];
  initialRoot: string | null;
  onScanned: () => void;
};

/**
 * One folder read on its own, below where the scan of the drive stops.
 *
 * Kept with the moment it arrived. It is a second look at the drive, taken
 * later than the scan it was opened from, and the page says so wherever it
 * draws from one.
 */
type FolderRead = { folder: FolderScan; at: number };

/**
 * A step on the way down the map.
 *
 * `read` is the folder read this part of the map is drawn from, or null while
 * it is still the scan of the drive. `rectangle` is set only on the step a
 * read begins at: what the rectangle that was clicked showed, so that a figure
 * that differs from it is said to differ.
 */
type Step = { node: TreeNode; read: FolderRead | null; rectangle: number | null };

/** How many folder reads are kept at once. Each can be a few megabytes. */
const READS_KEPT = 24;

/** What this page keeps of its last scan for the next time it is opened. */
type KeptScan = { target: string; scan: Scan };

const METHOD: Record<ScanMethod, string> = {
  master_file_table: "from the file table",
  directory_walk: "by walking its folders",
};

/** A sentence with a whole path in it has to be able to break inside the path. */
const LONG_PATHS = { overflowWrap: "anywhere" } as const;

/**
 * What is said above a part of the map that came from a folder read.
 *
 * Three things a second read can leave unsaid, and each would mislead. When
 * it was taken, because it is not the scan's time. That its figure is not the
 * one on the rectangle it was opened from, where it is not, with why: the
 * folder changed, or the two were worked out differently. And how much of the
 * folder is in files sitting directly in it, which the map does not draw.
 */
function ReadNote({
  step,
  scan,
  scannedAt,
}: {
  step: Step;
  scan: Scan;
  scannedAt: number;
}) {
  const read = step.read;
  if (!read) return null;
  const { folder, at } = read;

  if (step.rectangle === null) {
    return (
      <p className="muted" style={LONG_PATHS}>
        This part of the map is from {folder.path}, read on its own at{" "}
        {whenMeasured(at)} {METHOD[folder.method]}.
      </p>
    );
  }

  const tree = folder.tree;
  const difference = tree.bytes - step.rectangle;
  const sameMethod = folder.method === scan.method;
  // Every folder inside it is in `children`, the smallest gathered into one,
  // so what is left of its total is the files directly in it.
  const direct = tree.bytes - tree.children.reduce((sum, child) => sum + child.bytes, 0);
  const unreadable = folder.unreadable ?? 0;

  return (
    <p className="muted" style={LONG_PATHS}>
      {folder.path} was read on its own at {whenMeasured(at)} {METHOD[folder.method]}:{" "}
      {fmt.bytes(tree.bytes)}.
      {difference !== 0 && (
        <>
          {" "}
          That is {fmt.bytes(Math.abs(difference))} {difference > 0 ? "more" : "less"} than
          the rectangle it was opened from, which is from the scan at{" "}
          {whenMeasured(scannedAt)}.
          {sameMethod && " The two were worked out the same way, so what is in the folder changed in between."}
        </>
      )}
      {!sameMethod && folder.method === "directory_walk" && (
        <>
          {" "}
          The file table could not be used for this read
          {folder.fallback_reason ? ` (${folder.fallback_reason})` : ""}, so the folder
          was walked. A walk counts a file with several names once for each name and
          cannot open every folder. The scan used the file table, which counts such a
          file once, so the two figures can differ for that reason alone.
        </>
      )}
      {!sameMethod && folder.method === "master_file_table" && (
        <>
          {" "}
          The scan walked the drive's folders, which counts a file with several names
          once for each name. This read used the file table, which counts it once, so
          the two figures can differ for that reason alone.
        </>
      )}
      {unreadable > 0 && (
        <>
          {" "}
          {fmt.count(unreadable)} {unreadable === 1 ? "folder" : "folders"} inside it
          could not be opened, and what {unreadable === 1 ? "it holds" : "they hold"}{" "}
          is not counted.
        </>
      )}
      {direct > 0 && (
        <>
          {" "}
          {fmt.bytes(direct)} of it is in the {fmt.count(tree.files)}{" "}
          {tree.files === 1 ? "file" : "files"} sitting directly in this folder, which
          the map does not draw.
        </>
      )}
    </p>
  );
}

export default function Storage({ volumes, initialRoot, onScanned }: Props) {
  const [target, setTarget] = useState(initialRoot ?? "C:\\");
  const [scan, setScan] = useState<Scan | null>(null);
  /** When the scan on screen arrived, by this window's clock. */
  const [scannedAt, setScannedAt] = useState(0);
  const [running, setRunning] = useState(false);
  const [elapsed, setElapsed] = useState(0);
  const [error, setError] = useState<string | null>(null);
  // Path from the scanned root down to whatever the treemap is showing.
  const [trail, setTrail] = useState<Step[]>([]);
  /** Folders read on their own since the scan on screen arrived, by path. */
  const [reads, setReads] = useState<Record<string, FolderRead>>({});
  /** The folder being read on its own now, if one is. */
  const [opening, setOpening] = useState<TreeNode | null>(null);
  /** The folder that could not be opened, and the service's reason. */
  const [notOpened, setNotOpened] = useState<{ name: string; why: string } | null>(null);
  /**
   * When the scan on screen was taken, if it is the one kept from before
   * this page was opened rather than one taken since.
   */
  const [keptAt, setKeptAt] = useState<number | null>(null);
  /** Why the scan kept from before could not be read back, when it could not. */
  const [unreadable, setUnreadable] = useState<string | null>(null);
  /** Why the last scan could not be kept for next time, when it could not. */
  const [notKept, setNotKept] = useState<string | null>(null);
  const startedAt = useRef(0);
  /**
   * Counts scans. A folder read belongs to the map it was clicked on, so one
   * that answers after a new scan has replaced that map is let go.
   */
  const scanNumber = useRef(0);

  useEffect(() => {
    if (initialRoot) setTarget(initialRoot);
  }, [initialRoot]);

  // The last scan, as it was kept, so the page does not open empty. Not over
  // a scan started meanwhile, and not in place of a drive handed over from
  // Overview, which is what the next press of Scan should measure.
  useEffect(() => {
    let open = true;
    recall<KeptScan>("storage")
      .then((kept) => {
        if (!open || kept === null || scanNumber.current !== 0) return;
        if (!initialRoot) setTarget(kept.result.target);
        setScan(kept.result.scan);
        setScannedAt(kept.measuredAt);
        setKeptAt(kept.measuredAt);
        setTrail([{ node: kept.result.scan.tree, read: null, rectangle: null }]);
      })
      .catch((cause) => {
        if (open && scanNumber.current === 0) setUnreadable(reason(cause));
      });
    return () => {
      open = false;
    };
    // Once, when the page opens: a drive handed over later changes only
    // what is selected, not which scan is shown.
  }, []);

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
    scanNumber.current += 1;
    const scanned = target;
    try {
      const result = await api.scan(scanned);
      const at = Date.now();
      setScan(result);
      setScannedAt(at);
      setKeptAt(null);
      setUnreadable(null);
      setTrail([{ node: result.tree, read: null, rectangle: null }]);
      // Kept without its list of large folders: the service keeps that, as
      // this scan's summary, and the page does not draw it.
      setNotKept(await remember<KeptScan>("storage", at, {
        target: scanned,
        scan: { ...result, folders: null },
      }));
    } catch (cause) {
      setError(reason(cause));
      setScan(null);
      setTrail([]);
    } finally {
      // Whatever was read below the old map went with it.
      setReads({});
      setNotOpened(null);
      setRunning(false);
      onScanned();
    }
  }

  /**
   * Go into a rectangle.
   *
   * Most of the way down this only moves within the tree already in hand. The
   * tree stops four folders down, though, and what a person is looking for is
   * usually below that: everything in AppData\Local, every game in a Steam
   * library. A rectangle at that floor is marked as having more beneath it,
   * and opening one asks the service to read the drive again for that folder
   * alone. Its own tree stops four folders further down and opens the same
   * way, so the map can be followed as far as the drive goes.
   */
  async function open(child: TreeNode) {
    const here = trail;
    const parent = here[here.length - 1];
    if (!parent) return;

    if (child.children.length > 0) {
      setNotOpened(null);
      setTrail([...here, { node: child, read: parent.read, rectangle: null }]);
      return;
    }
    // One at a time, and not under a scan that is about to replace the map.
    if (!child.folded || opening !== null || running) return;
    setNotOpened(null);

    const key = child.path.toLowerCase();
    const known = reads[key];
    if (known) {
      setTrail([...here, { node: known.folder.tree, read: known, rectangle: child.bytes }]);
      return;
    }

    const asked = scanNumber.current;
    setOpening(child);
    try {
      const folder = await api.scanFolder(child.path);
      if (scanNumber.current !== asked) return;
      const read: FolderRead = { folder, at: Date.now() };
      setReads((current) => {
        const kept = Object.entries(current)
          .sort(([, a], [, b]) => b.at - a.at)
          .slice(0, READS_KEPT - 1);
        return { ...Object.fromEntries(kept), [key]: read };
      });
      // Only where the person still is. If they have moved about the map
      // while it was being read, the folder is kept and opens at once when
      // they come back to it, instead of the map jumping under them.
      setTrail((current) =>
        current === here
          ? [...here, { node: folder.tree, read, rectangle: child.bytes }]
          : current,
      );
    } catch (cause) {
      if (scanNumber.current === asked) {
        setNotOpened({ name: child.name, why: reason(cause) });
      }
    } finally {
      setOpening(null);
      onScanned();
    }
  }

  const step = trail.length > 0 ? trail[trail.length - 1] : null;
  const current = step?.node ?? null;

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
                {volume.root} {volume.label ? `(${volume.label})` : ""}
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

        {unreadable && !scan && !running && (
          <UnreadableNote
            what="The last scan"
            why={unreadable}
            again="Press Scan to measure the drive again."
          />
        )}
        {notKept && <NotKeptNote why={notKept} />}
        {scan && keptAt !== null && (
          <KeptNote
            what={`the scan of ${scan.root}`}
            at={keptAt}
            again="Press Scan to see the drive as it is now."
          />
        )}

        {scan && scan.method === "directory_walk" && scan.fallback_reason && (
          // The reason is the service's own and is the only part that says
          // why. This used to say above it that the file table "needs
          // administrative rights", whatever the reason was: over "this
          // volume is not NTFS", and it would have said it over "the file
          // table is in too many pieces" as well.
          <div className="notice notice-warn">
            <strong>Read the slow way.</strong> The file table could not be
            used for this drive, for the reason below, so the folders were
            walked one by one instead. The file table gives its answer in
            about two seconds and counts a file with several names once; a
            walk takes longer and counts it once for each name.
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
            {/* "Drive" beside it is refreshed every few seconds and this scan
                is not, so the scan says how old it is. */}
            <MeasuredAt at={scannedAt} />
            <div className="stat">
              <span className="stat-label">Unreadable</span>
              <span className="stat-value">{fmt.count(scan.unreadable)}</span>
            </div>
          </div>
        )}
      </section>

      {scan?.summary && (
        <section className="panel">
          <div className="panel-head">
            <h2>Since an earlier scan</h2>
          </div>
          <GrowthPanel
            // A new scan is a new comparison, with its own choice of earlier.
            key={scan.summary.kind === "kept" ? scan.summary.id : scan.summary.why}
            drive={`${scan.root.slice(0, 1).toUpperCase()}:`}
            kept={scan.summary}
          />
        </section>
      )}

      {scan && step && current && (
        <>
          <section className="panel">
            <div className="panel-head">
              <h2>Map</h2>
              <nav className="crumbs">
                {trail.map((visited, index) => (
                  <button
                    key={visited.node.path + index}
                    className="crumb"
                    disabled={index === trail.length - 1}
                    onClick={() => {
                      setNotOpened(null);
                      setTrail(trail.slice(0, index + 1));
                    }}
                  >
                    {index === 0 ? scan.root : visited.node.name}
                  </button>
                ))}
              </nav>
            </div>
            <p className="muted">
              Each rectangle is sized by what it holds. Click one, or Tab to it
              and press Enter, to go deeper. The map arrives four folders
              deep. Opening a folder below that reads the drive again for that
              folder alone.
            </p>
            <ReadNote step={step} scan={scan} scannedAt={scannedAt} />
            {opening && (
              <p className="muted" style={LONG_PATHS} role="status">
                Reading {opening.path} from the drive…
              </p>
            )}
            {notOpened && (
              // The map is a picture of the drive as it was, and a folder on
              // it can have gone since. That is said, with the service's
              // reason, and the picture is dated: a click that does nothing
              // would leave the rectangle looking as though it were still
              // there to open.
              <div className="notice notice-warn" style={LONG_PATHS} role="alert">
                <strong>{notOpened.name} could not be opened:</strong> {notOpened.why}.
                The map shows the drive as it was when it was scanned at{" "}
                {whenMeasured(scannedAt)}. Scan again to see it as it is now.
              </div>
            )}
            <Treemap
              node={current}
              reading={opening?.path ?? null}
              onDrill={(child) => void open(child)}
            />
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

      {!scan && !running && !error && !unreadable && (
        <section className="panel">
          <p className="empty">
            Nothing measured yet. Pick a drive and press Scan.
          </p>
        </section>
      )}
    </>
  );
}
