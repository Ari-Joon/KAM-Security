import { useEffect, useMemo, useState } from "react";
import { api, reason } from "../lib/api";
import ProgressBar from "../components/ProgressBar";
import { runJob, stopJob, type Progress } from "../lib/jobs";
import * as fmt from "../lib/format";
import FileRow from "../components/FileRow";
import PathLink from "../components/PathLink";
import type {
  Cache,
  Cleared,
  Confidence,
  DuplicateVerdict,
  Owner,
  Download,
  DownloadSummary,
  DuplicateGroup,
  DuplicateSummary,
  MoveRecord,
  OrganiseSummary,
  Proposal,
  Manifest,
  Orphan,
  OrphanSummary,
  Volume,
} from "../lib/types";

type Props = { volumes: Volume[]; onChanged: () => void };


/** What the interface calls each verdict. */
const VERDICT_LABEL: Record<DuplicateVerdict, string> = {
  keep: "Windows keeps these",
  deliberate: "Shipped on purpose",
  choose: "You can pick one",
  unclear: "Cannot say",
};

/**
 * Which tone each verdict gets.
 *
 * "You can pick one" is the calm colour and the rest are neutral or warning,
 * which is the same way round as the leftovers list: the safe thing to act on
 * reads as safe, and everything else reads as a reason to stop.
 */
const VERDICT_TONE: Record<DuplicateVerdict, string> = {
  keep: "low",
  deliberate: "medium",
  choose: "high",
  unclear: "medium",
};

const OWNER_LABEL: Record<Owner, string> = {
  windows: "Windows",
  servicing: "Windows servicing",
  program: "a program",
  program_data: "program data",
  yours: "yours",
  deleted: "recycle bin",
  elsewhere: "unattributed",
};

const OWNER_WHY: Record<Owner, string> = {
  windows: "One of Windows' own files.",
  servicing: "Held by the component store, the driver store, or an installer so it can repair later.",
  program: "Inside a program's install folder, where that program looks for it.",
  program_data: "In a program's data folder.",
  yours: "In a folder of yours, so removing it is a choice rather than a hazard.",
  deleted: "Already deleted, and still occupying the space until the bin is emptied.",
  elsewhere: "Somewhere this cannot attribute, so nothing is suggested.",
};

const CONFIDENCE_LABEL: Record<Confidence, string> = {
  high: "Very likely leftover",
  medium: "Possibly leftover",
  low: "Probably still in use",
};

function OrphanRow({
  orphan,
  onQuarantine,
  onDelete,
  busy,
}: {
  orphan: Orphan;
  onQuarantine: (orphan: Orphan) => void;
  onDelete: (orphan: Orphan) => void;
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
        {/*
          Neither of these is a one-way door, so neither asks twice.
          A confirmation before a reversible act teaches people to click
          through confirmations, which is exactly the habit you want them
          not to have by the time something really is irreversible.
        */}
        <button
          className="orphan-action"
          disabled={busy}
          title="Move it aside where this program can put it back for 30 days"
          onClick={() => onQuarantine(orphan)}
        >
          Quarantine
        </button>
        <button
          className="ghost"
          disabled={busy}
          title="Send it to the Recycle Bin, where Windows can put it back"
          onClick={() => onDelete(orphan)}
        >
          Recycle Bin
        </button>
      </div>
      {open && (
        <div className="orphan-detail">
          <PathLink path={orphan.path} className="orphan-path" />
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
  const [duplicateProgress, setDuplicateProgress] = useState<Progress | null>(null);
  const [duplicateJob, setDuplicateJob] = useState<string | null>(null);
  const [proposals, setProposals] = useState<Proposal[] | null>(null);
  const [organiseSummary, setOrganiseSummary] = useState<OrganiseSummary | null>(null);
  const [organising, setOrganising] = useState(false);
  const [moves, setMoves] = useState<MoveRecord[]>([]);
  const [held, setHeld] = useState<Manifest[]>([]);
  const [running, setRunning] = useState(false);
  const [busyPath, setBusyPath] = useState<string | null>(null);
  const [onlyActionable, setOnlyActionable] = useState(true);
  const [caches, setCaches] = useState<Cache[] | null>(null);
  const [measuringCaches, setMeasuringCaches] = useState(false);
  const [clearingCache, setClearingCache] = useState<string | null>(null);
  /** The cache whose cost is being put to the reader before it is cleared. */
  const [confirmCache, setConfirmCache] = useState<string | null>(null);
  const [openCache, setOpenCache] = useState<string | null>(null);
  const [cleared, setCleared] = useState<Record<string, Cleared>>({});
  /**
   * Which held item is one press from being deleted for good.
   *
   * Only the quarantine list needs this now. Everything in the lists above is
   * reversible — quarantine puts it back, the Recycle Bin puts it back — and
   * confirming a reversible act teaches people to click through confirmations,
   * which is the habit you least want them to have by the time one is real.
   * This is the one that is real.
   */
  const [confirming, setConfirming] = useState<string | null>(null);
  const [emptying, setEmptying] = useState(false);
  /**
   * Which copy of a set the person has chosen to keep, by set.
   *
   * Keyed on the first copy's path, which is stable for as long as the set is
   * on screen. Absent means they have not chosen and the suggestion stands.
   */
  const [keeping, setKeeping] = useState<Record<string, string>>({});
  const [error, setError] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const [heldError, setHeldError] = useState<string | null>(null);
  const [movesError, setMovesError] = useState<string | null>(null);

  /**
   * What is being held, or why that could not be read.
   *
   * The failure was swallowed, which made an unreadable quarantine store render
   * identically to an empty one: the panel said "Nothing held." over a store
   * that might have held anything. That is the same mistake the persistence
   * readers were carrying -- a failure presented as an absence -- and it is
   * worse here, because the absence is of the user's own files.
   */
  async function loadQuarantine() {
    try {
      setHeld(await api.quarantineList());
      setHeldError(null);
    } catch (cause) {
      setHeldError(reason(cause));
    }
  }

  useEffect(() => {
    void loadQuarantine();
    void loadMoves();
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

  /** Moves that can still be undone, or why that could not be read. */
  async function loadMoves() {
    try {
      setMoves(await api.moves());
      setMovesError(null);
    } catch (cause) {
      setMovesError(reason(cause));
    }
  }

  async function findProposals() {
    setOrganising(true);
    setError(null);
    try {
      const report = await api.organise(drive);
      setProposals(report.proposals);
      setOrganiseSummary(report.summary);
    } catch (cause) {
      setError(reason(cause));
      setProposals(null);
    } finally {
      setOrganising(false);
    }
  }

  async function applyMove(proposal: Proposal) {
    setError(null);
    try {
      await api.applyMove(proposal.from, proposal.to);
      setNote(`Moved ${proposal.name}. It can be put back from the list below.`);
      setProposals((current) =>
        current ? current.filter((item) => item.from !== proposal.from) : current,
      );
      await loadMoves();
    } catch (cause) {
      setError(reason(cause));
    } finally {
      onChanged();
    }
  }

  async function undoMove(id: string) {
    setError(null);
    try {
      const record = await api.undoMove(id);
      setNote(`Put ${record.from} back.`);
      await loadMoves();
    } catch (cause) {
      setError(reason(cause));
    } finally {
      onChanged();
    }
  }

  async function findDuplicates() {
    setFindingDuplicates(true);
    setError(null);
    setDuplicateProgress(null);
    try {
      // The longest job in the product: it reads file contents rather than
      // the file table, so it is the one that most needs to say what it is
      // doing and to be stoppable.
      const { result } = await runJob(
        (job) => {
          setDuplicateJob(job);
          return api.duplicates(drive, job);
        },
        setDuplicateProgress,
      );

      if (result === null) {
        // Stopped, not failed.
        setDuplicates(null);
        setDuplicateSummary(null);
        return;
      }
      setDuplicates(result.groups);
      setDuplicateSummary(result.summary);
    } catch (cause) {
      setError(reason(cause));
      setDuplicates(null);
    } finally {
      setDuplicateProgress(null);
      setDuplicateJob(null);
      setFindingDuplicates(false);
      onChanged();
    }
  }


  /**
   * Sets worth looking at, by default.
   *
   * Most of what a whole-volume comparison finds is Windows keeping its own
   * copies, and a list led by forty of those buries the two that are actually
   * a choice. The filter is on to begin with and can be turned off, rather than
   * the results being trimmed where nobody can see it happen.
   */
  const shownDuplicates = useMemo(() => {
    if (!duplicates) return [];
    // "Something can go" used to mean "we would suggest removing one", which
    // was the same thing when the only removable copy was one in a folder you
    // own. Now that you can pick, a set is actionable whenever it holds two
    // copies that are not Windows' own — and hiding those would hide most of
    // what the comparison finds.
    return onlyActionable
      ? duplicates.filter(
          (group) =>
            group.copies.filter(
              (copy) => copy.owner !== "windows" && copy.owner !== "servicing",
            ).length > 1,
        )
      : duplicates;
  }, [duplicates, onlyActionable]);

  async function loadCaches() {
    setMeasuringCaches(true);
    setError(null);
    try {
      setCaches(await api.caches());
    } catch (cause) {
      setError(reason(cause));
    } finally {
      setMeasuringCaches(false);
    }
  }

  /**
   * Clear a cache, asking first when there is something to lose.
   *
   * This went straight to `remove_dir_all`, running as the system account, from
   * a button on a collapsed row whose cost text was hidden behind the caret --
   * and the page above it said "Nothing on this page destroys anything", which
   * was simply false. One of the entries is `C:\Windows.old`, whose cost is
   * that the machine can no longer be rolled back to its previous version of
   * Windows. That was one click, unconfirmed, with the sentence explaining it
   * folded away.
   *
   * Routine caches still clear on one press, because a browser cache genuinely
   * costs nothing and confirming everything teaches people to click through
   * confirmations. Anything with a stated cost states it, first.
   */
  async function clearOne(cache: Cache) {
    setConfirmCache(null);
    setClearingCache(cache.id);
    setError(null);
    try {
      const result = await api.clearCache(cache.id);
      setCleared((current) => ({ ...current, [cache.id]: result }));
      setNote(`Freed ${fmt.bytes(result.bytes_freed)} from ${cache.name}.`);
      // Measure again rather than subtracting: what was in use stayed, and
      // guessing at the new figure would put a number on screen that nothing
      // checked.
      setCaches(await api.caches());
    } catch (cause) {
      setError(reason(cause));
    } finally {
      setClearingCache(null);
      onChanged();
    }
  }

  /**
   * Hold one redundant copy.
   *
   * Quarantine, not deletion. The agent re-derives whether this copy may go
   * before it touches it, so a path from here is a request rather than an
   * instruction, and a mistake costs one press of "put back".
   *
   * `chosen` says whose decision this was. Acting on our own suggestion only
   * ever reaches a copy in a folder you own, because the suggestion came from
   * a classifier. Acting on your choice reaches what you picked, because you
   * looked at the set. Windows' own files are refused either way.
   */
  async function holdCopy(path: string, bytes: number, chosen: boolean) {
    setBusyPath(path);
    setError(null);
    try {
      await api.quarantineCopy(
        path,
        chosen
          ? "you chose which copy to keep, and this was not it"
          : "a redundant copy of an identical file",
        chosen,
      );
      setNote(
        `Held ${fmt.bytes(bytes)}: ${path}. It is in quarantine below and can be put back for 30 days.`,
      );
      setDuplicates((current) =>
        current
          ? current
              .map((group) => ({
                ...group,
                copies: group.copies.filter((copy) => copy.path !== path),
              }))
              // A set with one copy left is not a set any more.
              .filter((group) => group.copies.length > 1)
          : current,
      );
      await loadQuarantine();
    } catch (cause) {
      setError(reason(cause));
    } finally {
      setBusyPath(null);
      onChanged();
    }
  }


  /**
   * Send one redundant copy to the Recycle Bin.
   *
   * Same reasoning as `recycleOrphan`: the window does it, so the copy lands in
   * this person's bin rather than SYSTEM's, and no privilege is involved in
   * removing a file they own.
   */
  async function recycleCopy(path: string, bytes: number) {
    setBusyPath(path);
    setError(null);
    try {
      const outcome = await api.recycleItem(path);
      setNote(
        outcome.in_bin
          ? `Sent ${fmt.bytes(bytes)} to the Recycle Bin: ${path}`
          : (outcome.warning ?? `${path} was removed but did not reach the Recycle Bin.`),
      );
      setDuplicates((current) =>
        current
          ? current
              .map((group) => ({
                ...group,
                copies: group.copies.filter((copy) => copy.path !== path),
              }))
              .filter((group) => group.copies.length > 1)
          : current,
      );
    } catch (cause) {
      setError(
        `${reason(cause)} — if this copy is not yours to delete, hold it instead ` +
          `and it can be put back for 30 days.`,
      );
    } finally {
      setBusyPath(null);
      onChanged();
    }
  }

  /**
   * Delete one held item for good.
   *
   * The whole point of quarantine is that acting on a suggestion is reversible,
   * so the one operation that is not reversible asks first and says so in those
   * words. The agent does the deleting; nothing here removes a file.
   */
  async function deleteOne(id: string, bytes: number) {
    setBusyPath(id);
    setError(null);
    try {
      const removal = await api.deleteQuarantined(id);
      setNote(
        removal.items > 0
          ? `Deleted for good, freeing ${fmt.bytes(removal.bytes_freed || bytes)}.`
          : "Nothing was deleted.",
      );
      if (removal.refused.length > 0) {
        setError(removal.refused.join("\n"));
      }
      await loadQuarantine();
    } catch (cause) {
      setError(reason(cause));
    } finally {
      setConfirming(null);
      setBusyPath(null);
      onChanged();
    }
  }

  async function emptyAll() {
    setBusyPath("all");
    setError(null);
    try {
      const removal = await api.emptyQuarantine();
      setNote(
        `Deleted ${fmt.count(removal.items)} ${removal.items === 1 ? "item" : "items"}, ` +
          `freeing ${fmt.bytes(removal.bytes_freed)}.`,
      );
      if (removal.refused.length > 0) {
        setError(removal.refused.join("\n"));
      }
      await loadQuarantine();
    } catch (cause) {
      setError(reason(cause));
    } finally {
      setEmptying(false);
      setBusyPath(null);
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

  /**
   * Send a leftover directory to the Recycle Bin.
   *
   * The window does this itself rather than asking the agent, and that is the
   * point rather than a shortcut: the Recycle Bin is per user, so a delete
   * performed by a LocalSystem service lands in SYSTEM's bin, somewhere the
   * person can neither see nor restore from. Doing it here puts it in theirs,
   * where it comes back with a right-click in a program they already know.
   *
   * If it will not go — a path this account cannot write — the answer is
   * quarantine, never a privileged delete standing in for a recycle.
   */
  async function recycleOrphan(orphan: Orphan) {
    setBusyPath(orphan.path);
    setError(null);
    try {
      const outcome = await api.recycleItem(orphan.path);
      setNote(
        outcome.in_bin
          ? `Sent ${orphan.name} (${fmt.bytes(orphan.bytes)}) to the Recycle Bin. ` +
              `It is in there until you empty it.`
          : (outcome.warning ??
            `${orphan.name} was removed but did not reach the Recycle Bin.`),
      );
      setOrphans((current) =>
        current ? current.filter((item) => item.path !== orphan.path) : current,
      );
    } catch (cause) {
      setError(
        `${reason(cause)} — if this folder is not yours to delete, quarantine it ` +
          `instead and it can be put back for 30 days.`,
      );
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
            Nothing here is destroyed: quarantine holds it where this program
            can put it back, the Recycle Bin holds it where Windows can.
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
            filesystem's index, so it has its own button. Each set is then
            judged by where its copies live: Windows and installers keep
            duplicates deliberately, and only a copy in a folder of yours is
            ever offered for removal.
          </li>
          <li>
            <strong>Caches</strong> are places Windows and a few programs write
            data they can regenerate. Clearing one empties its contents and
            leaves the folder, and each says what it costs you — usually
            nothing, sometimes a slower first launch.
          </li>
          <li>
            <strong>Loose files</strong> are downloads sitting in{" "}
            <code>Downloads</code> or on the Desktop that match a folder you
            already keep that kind of file in. Only documents, images, audio,
            video and archives — never anything that runs.
          </li>
          <li>
            <strong>Quarantine</strong> is where anything you act on goes by
            default. Items are <em>moved</em>, not deleted, and can be put back
            for 30 days.
          </li>
          <li>
            <strong>Recycle Bin</strong> sits beside it and does the ordinary
            thing instead: the item goes where anything you delete in Explorer
            goes, and comes back the same way. Use it when you would rather not
            learn a second place things are kept. It is your bin, not the
            service's, so it appears where you expect — and this program records
            that it happened without pretending it did it for you.
          </li>
          <li>
            Deleting something so that it is <em>really</em> gone is a separate
            act. For anything that came out of a folder, that lives in the
            quarantine list below and is asked for twice.
          </li>
          <li>
            <strong>Clearing a cache is the exception</strong>, and it is worth
            being plain about: those files are removed outright rather than
            moved, because a cache is regenerated by the program that made it
            and filling the Recycle Bin with tens of gigabytes of it would free
            no space at all. Anything with a cost attached says what the cost is
            and asks before it does it.
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
                  onDelete={(item) => void recycleOrphan(item)}
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
          <h2>Loose files with a home</h2>
          <button onClick={() => void findProposals()} disabled={organising}>
            {organising ? "Looking…" : "Find loose files"}
          </button>
        </div>
        <p className="muted">
          A destination has to be a folder you already keep that kind of file
          in — this never invents one. Executables are excluded on purpose: a
          downloaded installer may be pointed at by a shortcut or a scheduled
          task, and none of that is visible from here.
        </p>

        {organiseSummary && (
          <p className="muted">
            {fmt.count(organiseSummary.proposals)} of{" "}
            {fmt.count(organiseSummary.examined)} loose files have an obvious
            home.
          </p>
        )}

        {proposals && proposals.length === 0 && (
          <p className="empty">Nothing loose that matches a folder you already use.</p>
        )}

        {proposals && proposals.length > 0 && (
          <ul className="proposals">
            {proposals.map((proposal) => (
              <li key={proposal.from} className="proposal">
                <div className="proposal-body">
                  <span className="proposal-name">{proposal.name}</span>
                  <span className="proposal-move">
                    → {proposal.to.slice(0, proposal.to.lastIndexOf("\\"))}
                  </span>
                  <span className="proposal-reason">
                    {proposal.reason}
                    {proposal.destination_syncs && (
                      <span className="proposal-sync">
                        {" "}
                        · that folder syncs to the cloud, so moving it there
                        will upload it
                      </span>
                    )}
                  </span>
                </div>
                <span className="proposal-size">{fmt.bytes(proposal.bytes)}</span>
                <button onClick={() => void applyMove(proposal)}>Move</button>
              </li>
            ))}
          </ul>
        )}

        {movesError && (
          <p className="held-warn">
            What has been moved could not be read, so anything moved earlier is
            not listed here and cannot be put back from this page:{" "}
            {movesError}
          </p>
        )}

        {moves.filter((move) => !move.undone).length > 0 && (
          <>
            <p className="modal-label">Moved by KAM Security</p>
            <ul className="files">
              {moves
                .filter((move) => !move.undone)
                .map((move) => (
                  <li key={move.id} className="held">
                    <div className="held-body">
                      <PathLink path={move.to} className="held-path" />
                      <span className="held-reason">was {move.from}</span>
                    </div>
                    <button onClick={() => void undoMove(move.id)}>Put back</button>
                  </li>
                ))}
            </ul>
          </>
        )}
      </section>

      <section className="panel">
        <div className="panel-head">
          <h2>Identical copies</h2>
          <button onClick={() => void findDuplicates()} disabled={findingDuplicates}>
            {findingDuplicates ? "Comparing…" : "Find duplicates"}
          </button>
        </div>
        <p className="muted">
          Compared by size, then by their first 64 KB, then in full — so
          "duplicate" means every byte, not a guess. Each set is then judged by
          where its copies live, because identical is not the same as spare:
          Windows keeps several copies of the same library on purpose, every
          installer keeps a second copy of itself so it can repair later, and
          two programs that ship the same runtime each look for it beside
          themselves. Only copies in folders of yours are ever offered.
        </p>

        {findingDuplicates && duplicateProgress && (
          <ProgressBar
            progress={duplicateProgress}
            onStop={duplicateJob ? () => void stopJob(duplicateJob) : undefined}
          />
        )}

        {duplicateSummary && (
          <div className="stat-row tight">
            <div className="stat">
              <span className="stat-label">Sets</span>
              <span className="stat-value">{fmt.count(duplicateSummary.groups)}</span>
            </div>
            <div className="stat">
              <span className="stat-label">Duplicated</span>
              <span className="stat-value">
                {fmt.bytes(duplicateSummary.wasted_bytes)}
              </span>
            </div>
            <div className="stat">
              <span className="stat-label">You can reclaim</span>
              <span className="stat-value strong">
                {fmt.bytes(duplicateSummary.reclaimable_bytes)}
              </span>
            </div>
            <div className="stat">
              <span className="stat-label">Worth a look</span>
              <span className="stat-value">
                {fmt.count(duplicateSummary.actionable)} sets
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
          <>
            <div className="dupe-filter">
              <label>
                <input
                  type="checkbox"
                  checked={onlyActionable}
                  onChange={(event) => setOnlyActionable(event.target.checked)}
                />
                Only sets you can choose between
              </label>
              <span className="muted">
                {fmt.count(shownDuplicates.length)} of{" "}
                {fmt.count(duplicates.length)} shown
              </span>
            </div>

            {shownDuplicates.length === 0 ? (
              <p className="empty">
                Every set found is one Windows or a program keeps deliberately.
                That is a good answer, not an empty one.
              </p>
            ) : (
              <ul className="dupes">
                {shownDuplicates.slice(0, 40).map((group) => (
                  <li
                    key={group.copies[0]?.path ?? String(group.bytes)}
                    className={`dupe dupe-${group.verdict}`}
                  >
                    <div className="dupe-head">
                      <span className="dupe-count">
                        {group.copies.length} copies of {fmt.bytes(group.bytes)}
                      </span>
                      <span className={`conf conf-${VERDICT_TONE[group.verdict]}`}>
                        {VERDICT_LABEL[group.verdict]}
                      </span>
                      <span className="dupe-waste">
                        {group.reclaimable_bytes > 0
                          ? `${fmt.bytes(group.reclaimable_bytes)} reclaimable`
                          : "nothing to reclaim"}
                      </span>
                    </div>

                    <ul className="dupe-reasons">
                      {group.reasons.map((why) => (
                        <li key={why}>{why}</li>
                      ))}
                    </ul>

                    {(() => {
                      // Which copy survives. Our suggestion until somebody
                      // says otherwise, and then theirs.
                      const setKey = group.copies[0]?.path ?? "";
                      const suggested =
                        group.suggested_keep === null
                          ? undefined
                          : group.copies[group.suggested_keep]?.path;
                      const keeper = keeping[setKey] ?? suggested;
                      // Whether the *person* picked the survivor, which is the
                      // only thing that may widen the agent's fence.
                      const theyChose = keeping[setKey] !== undefined;
                      // Windows keeps its own files whatever anybody picks, so
                      // a set made only of those offers no choice at all.
                      const choosable = group.copies.filter(
                        (copy) => copy.owner !== "windows" && copy.owner !== "servicing",
                      );
                      const canChoose = choosable.length > 1;

                      return (
                        <ul className="files">
                          {group.copies.map((copy) => {
                            const locked =
                              copy.owner === "windows" || copy.owner === "servicing";
                            const isKeeper = keeper === copy.path;
                            // Whether removing this was our suggestion or their
                            // decision.
                            //
                            // This read `copy.removable && suggested === keeper`,
                            // and on an untouched set `suggested === keeper` is
                            // true by construction -- so it collapsed to
                            // `copy.removable`, and the flag sent to the agent
                            // was its negation. Every first click on a copy the
                            // classifier had marked *not* removable therefore
                            // arrived claiming the person had chosen it, which
                            // is what selects the widened fence that permits
                            // quarantining out of Program Files and AppData.
                            // The flag meant "we would not have offered this",
                            // roughly the opposite of consent.
                            const ours = !theyChose;

                            return (
                              <FileRow
                                key={copy.path}
                                path={copy.path}
                                bytes={group.bytes}
                                onReveal={(target) => void reveal(target)}
                                note={
                                  <span className="dupe-copy-note">
                                    <span
                                      className={`owner owner-${copy.owner}`}
                                      title={OWNER_WHY[copy.owner]}
                                    >
                                      {OWNER_LABEL[copy.owner]}
                                    </span>

                                    {locked ? (
                                      <span
                                        className="owner"
                                        title="Windows puts these back and removing one breaks an update, so this is refused however it is asked for."
                                      >
                                        cannot be removed
                                      </span>
                                    ) : isKeeper ? (
                                      <span className="owner owner-keep">keeping this one</span>
                                    ) : (
                                      <>
                                        {canChoose && (
                                          <button
                                            className="dupe-take"
                                            disabled={busyPath !== null}
                                            onClick={(event) => {
                                              event.stopPropagation();
                                              setKeeping((current) => ({
                                                ...current,
                                                [setKey]: copy.path,
                                              }));
                                            }}
                                          >
                                            Keep this one instead
                                          </button>
                                        )}
                                        {keeper && (
                                            <>
                                              <button
                                                className="dupe-take"
                                                disabled={busyPath !== null}
                                                title={
                                                  ours
                                                    ? "Moved to quarantine, and restorable for 30 days."
                                                    : "This is not a copy we would have offered. It goes to quarantine and comes back with one press for 30 days."
                                                }
                                                onClick={(event) => {
                                                  event.stopPropagation();
                                                  void holdCopy(copy.path, group.bytes, !ours);
                                                }}
                                              >
                                                Remove this one
                                              </button>
                                              <button
                                                className="ghost"
                                                disabled={busyPath !== null}
                                                title="Send this copy to the Recycle Bin, where Windows can put it back"
                                                onClick={(event) => {
                                                  event.stopPropagation();
                                                  void recycleCopy(copy.path, group.bytes);
                                                }}
                                              >
                                                Recycle Bin
                                              </button>
                                            </>
                                          )}
                                      </>
                                    )}
                                  </span>
                                }
                              />
                            );
                          })}
                        </ul>
                      );
                    })()}
                  </li>
                ))}
              </ul>
            )}
          </>
        )}
      </section>

      <section className="panel">
        <div className="panel-head">
          <h2>Caches and scratch space</h2>
          <button onClick={() => void loadCaches()} disabled={measuringCaches}>
            {measuringCaches ? "Measuring…" : "Measure"}
          </button>
        </div>
        <p className="muted">
          Data that regenerates by itself, and which nothing ever removes. No
          registry cleaning and no health score: both are how this kind of
          software makes money and neither has ever made a machine faster. Only
          the contents go, never the folder, and nothing here touches history,
          passwords or sessions.
        </p>

        {caches && caches.length === 0 && (
          <p className="empty">Nothing worth clearing. Genuinely.</p>
        )}

        {caches && caches.length > 0 && (
          <>
            <div className="stat-row tight">
              <div className="stat">
                <span className="stat-label">Places</span>
                <span className="stat-value">{fmt.count(caches.length)}</span>
              </div>
              <div className="stat">
                <span className="stat-label">Holding</span>
                <span className="stat-value strong">
                  {fmt.bytes(caches.reduce((total, cache) => total + cache.bytes, 0))}
                </span>
              </div>
              <div className="stat">
                <span className="stat-label">Costs you nothing</span>
                <span className="stat-value">
                  {fmt.bytes(
                    caches
                      .filter((cache) => cache.safety === "routine")
                      .reduce((total, cache) => total + cache.bytes, 0),
                  )}
                </span>
              </div>
            </div>

            <ul className="caches">
              {caches.map((cache) => (
                <li key={cache.id} className={`cache cache-${cache.safety}`}>
                  <div className="cache-head">
                    <button
                      className="cache-toggle"
                      onClick={() =>
                        setOpenCache(openCache === cache.id ? null : cache.id)
                      }
                    >
                      <span className="app-caret">
                        {openCache === cache.id ? "▾" : "▸"}
                      </span>
                      <span className="cache-name">{cache.name}</span>
                      <span className={`conf conf-${cache.safety === "routine" ? "high" : "medium"}`}>
                        {cache.safety === "routine" ? "Costs nothing" : "Costs something"}
                      </span>
                    </button>
                    <span className="cache-size">{fmt.bytes(cache.bytes)}</span>
                    <button
                      className="orphan-action"
                      disabled={clearingCache !== null}
                      onClick={() =>
                        cache.safety === "routine"
                          ? void clearOne(cache)
                          : setConfirmCache(
                              confirmCache === cache.id ? null : cache.id,
                            )
                      }
                    >
                      {clearingCache === cache.id ? "Clearing…" : "Clear"}
                    </button>
                  </div>

                  {confirmCache === cache.id && (
                    /* The cost, in front of the button rather than behind a
                       caret. This is the whole of the fix: the information
                       already existed and was one fold away from the action it
                       was about. */
                    <div className="confirm">
                      <p>
                        Clear {cache.name}, removing {fmt.bytes(cache.bytes)}{" "}
                        outright? These files are not moved to the Recycle Bin
                        and there is no undo.
                      </p>
                      {cache.cost && (
                        <p className="cache-cost">
                          <strong>What it costs:</strong> {cache.cost}
                        </p>
                      )}
                      <div className="confirm-actions">
                        <button
                          disabled={clearingCache !== null}
                          onClick={() => void clearOne(cache)}
                        >
                          Clear it
                        </button>
                        <button
                          className="ghost"
                          onClick={() => setConfirmCache(null)}
                        >
                          Leave it
                        </button>
                      </div>
                    </div>
                  )}

                  {openCache === cache.id && (
                    <div className="cache-detail">
                      <p>{cache.what}</p>
                      {cache.cost && (
                        <p className="cache-cost">
                          <strong>What it costs:</strong> {cache.cost}
                        </p>
                      )}
                      <ul className="files">
                        {cache.locations.map((location) => (
                          <FileRow
                            key={location.path}
                            path={location.path}
                            bytes={location.bytes}
                            onReveal={(target) => void reveal(target)}
                            note={
                              <span>
                                {fmt.count(location.files)} files
                                {location.partial && " (measured to a ceiling)"}
                              </span>
                            }
                          />
                        ))}
                      </ul>
                    </div>
                  )}

                  {cleared[cache.id] && (
                    <p className="cache-result">
                      Freed {fmt.bytes(cleared[cache.id].bytes_freed)} across{" "}
                      {fmt.count(cleared[cache.id].files_removed)} files.
                      {cleared[cache.id].files_in_use > 0 &&
                        ` ${fmt.count(cleared[cache.id].files_in_use)} were open in another program and were left alone.`}
                      {cleared[cache.id].refused.length > 0 &&
                        ` ${fmt.count(cleared[cache.id].refused.length)} could not be read.`}
                    </p>
                  )}
                </li>
              ))}
            </ul>
          </>
        )}
      </section>

      <section className="panel">
        <div className="panel-head">
          <h2>Quarantine</h2>
          <button onClick={() => void loadQuarantine()}>Refresh</button>
          {active.length > 0 && (
            <button
              className="ghost"
              disabled={busyPath !== null}
              onClick={() => setEmptying(true)}
            >
              Empty it
            </button>
          )}
        </div>
        <p className="muted">
          Everything here was moved rather than deleted, and goes back where it
          came from with one press for thirty days. Deleting is the other
          direction and there is no undo for it, so both ways of doing it ask
          first.
        </p>

        {emptying && (
          <div className="confirm">
            <p>
              Delete all {fmt.count(active.length)} held{" "}
              {active.length === 1 ? "item" : "items"}, freeing{" "}
              {fmt.bytes(active.reduce((total, item) => total + item.bytes, 0))}?
              This cannot be undone.
            </p>
            <div className="confirm-actions">
              <button onClick={() => void emptyAll()} disabled={busyPath !== null}>
                Delete them
              </button>
              <button className="ghost" onClick={() => setEmptying(false)}>
                Keep them
              </button>
            </div>
          </div>
        )}
        {heldError && (
          <div className="notice notice-down">
            <strong>What is being held could not be read.</strong> This is not
            the same as nothing being held, and nothing below should be read as
            a list of what is there.
            <pre className="error">{heldError}</pre>
          </div>
        )}
        {active.length === 0 && !heldError ? (
          <p className="empty">Nothing held.</p>
        ) : active.length === 0 ? (
          <p className="empty">Nothing could be listed.</p>
        ) : (
          <ul className="files">
            {active.map((item) => (
              <li key={item.id} className="held">
                <div className="held-body">
                  <PathLink
                    path={item.restored ? item.original_path : ""}
                    className="held-path"
                    title={
                      item.restored
                        ? `Show ${item.original_path} in Explorer`
                        : "This is in quarantine; restore it to open where it was"
                    }
                  >
                    {item.original_path}
                  </PathLink>
                  <span className="held-reason">{item.reason}</span>
                </div>
                <span className="held-size">{fmt.bytes(item.bytes)}</span>
                {confirming === item.id ? (
                  <>
                    <span className="held-warn">Delete for good?</span>
                    <button
                      disabled={busyPath !== null}
                      onClick={() => void deleteOne(item.id, item.bytes)}
                    >
                      Yes
                    </button>
                    <button className="ghost" onClick={() => setConfirming(null)}>
                      No
                    </button>
                  </>
                ) : (
                  <>
                    <button onClick={() => void restore(item.id)}>Restore</button>
                    <button
                      className="ghost"
                      onClick={() => setConfirming(item.id)}
                      title="Delete this permanently. There is no undo."
                    >
                      Delete
                    </button>
                  </>
                )}
              </li>
            ))}
          </ul>
        )}
      </section>
    </>
  );
}
