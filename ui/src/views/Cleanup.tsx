import { useEffect, useMemo, useRef, useState } from "react";
import { api, reason } from "../lib/api";
import ProgressBar from "../components/ProgressBar";
import type { PageJobOutcome } from "../lib/jobs";
import { usePageJob } from "../lib/usePageJob";
import * as fmt from "../lib/format";
import { useRecyclable } from "../lib/recyclable";
import ReclaimMap, {
  reclaimLegend,
  type ReclaimNode,
} from "../components/ReclaimMap";
import { GridLegend } from "../components/StateGrid";
import FileRow from "../components/FileRow";
import PathLink from "../components/PathLink";
import MeasuredAt, { whenMeasured } from "../components/MeasuredAt";
import { KeptNote, NotKeptNote, UnreadableNote } from "../components/Kept";
import { recall, remember } from "../lib/remembered";
import type {
  AccessTimes,
  ApplicationReport,
  Cache,
  Cleared,
  Confidence,
  DuplicateVerdict,
  Owner,
  Download,
  DownloadSummary,
  DuplicateGroup,
  DuplicateReport,
  DuplicateSummary,
  MoveRecord,
  OldFile,
  OldFileSummary,
  OrganiseReport,
  OrganiseSummary,
  Proposal,
  Manifest,
  Orphan,
  Volume,
} from "../lib/types";

type Props = { volumes: Volume[]; onChanged: () => void };

/**
 * A set of identical files as this page holds it.
 *
 * `id` names the set for as long as it is on screen. It was the first copy's
 * path, read afresh on every render, so removing that copy renamed the set
 * and the person's choice of keeper, stored under the old name, was lost.
 *
 * `suggestedPath` is the agent's suggested keeper by path. The agent sends it
 * as an index into `copies`, and `copies` is filtered here as copies are
 * removed, so the same index came to point at a different file.
 */
type DupeSet = DuplicateGroup & { id: string; suggestedPath: string | null };

/**
 * What this page keeps of each of its searches for the next time it opens:
 * each list as it stands, so a row acted on does not come back.
 */
type KeptSurvey = {
  drive: string;
  orphans: Orphan[];
  rootsElsewhere: string[];
  downloads: Download[] | null;
  downloadSummary: DownloadSummary | null;
  oldFiles: OldFile[] | null;
  oldSummary: OldFileSummary | null;
  oldRest: { files: number; bytes: number };
};
type KeptDuplicates = { drive: string; sets: DupeSet[]; summary: DuplicateSummary | null };
type KeptCaches = { caches: Cache[] };

/**
 * A search for leftovers, downloads and large old files as this page holds
 * it, from what the search sent.
 *
 * What it found beyond the list of large old files it sent is worked out
 * here, once, so that the figures stay true as rows leave the list: what is
 * on screen is added up from the rows, and this is added to it.
 */
function surveyed(drive: string, report: ApplicationReport): KeptSurvey {
  return {
    drive,
    orphans: report.orphans,
    rootsElsewhere: report.orphan_summary.roots_elsewhere ?? [],
    downloads: report.downloads,
    downloadSummary: report.download_summary,
    oldFiles: report.old_files,
    oldSummary: report.old_file_summary,
    oldRest: {
      files: Math.max(0, report.old_file_summary.found - report.old_files.length),
      bytes: Math.max(
        0,
        report.old_file_summary.total_bytes -
          report.old_files.reduce((sum, file) => sum + file.bytes, 0),
      ),
    },
  };
}

/** The three searches whose answers this page keeps. */
type Search = "survey" | "duplicates" | "caches";

/** A record by search, without one search's entry. */
function without<V>(record: Partial<Record<Search, V>>, search: Search) {
  const next = { ...record };
  delete next[search];
  return next;
}

/** The agent's suggested keeper, as a path. */
function suggestedPathOf(group: DuplicateGroup): string | null {
  return group.suggested_keep === null
    ? null
    : (group.copies[group.suggested_keep]?.path ?? null);
}

function asSets(groups: DuplicateGroup[]): DupeSet[] {
  return groups.map((group, index) => ({
    ...group,
    id: group.copies[0]?.path ?? `set-${index}`,
    suggestedPath: suggestedPathOf(group),
  }));
}

/** What the window reported about something it sent to the Recycle Bin. */
type RecycleOutcome = { in_bin: boolean; warning: string | null };

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

/**
 * How many duplicate sets are drawn at once.
 *
 * A cap rather than a scroll, because forty sets is already more than anybody
 * works through in a sitting and the rest are smaller. Named rather than typed
 * into the `slice` so the counter above the list and the list itself cannot
 * disagree, which they did.
 */
const DUPE_LIMIT = 40;

/** The same, for downloads, which are informational rather than actionable. */
const DOWNLOAD_LIMIT = 25;

/**
 * What a download's last-opened date is worth on this PC, said before any is
 * shown.
 *
 * This was one sentence, printed whenever the service said Windows was not
 * recording opens, and the service read the setting backwards: it said so on
 * PCs where Windows was recording them. Three answers now, because "could not
 * be read" is neither of the other two.
 */
const ACCESS_TIMES: Record<AccessTimes, string> = {
  recorded:
    "Windows is recording when files are opened on this PC. Any program that " +
    "reads a file counts, including antivirus and backup, so an old date " +
    "means nothing has read it since, and a recent date means only that " +
    "something did.",
  not_recorded:
    "Windows is not recording when files are opened on this PC, so there is " +
    "no way to tell which of these were ever opened.",
  unknown:
    "Whether Windows records when files are opened on this PC could not be " +
    "read, so no last-opened dates are shown.",
};

/** How long ago, in whole days, the way a person would say it. */
function daysAgo(days: number): string {
  if (days <= 0) return "today";
  if (days === 1) return "yesterday";
  return `${fmt.count(days)} days ago`;
}

/** The orders the download list can be put in. */
type DownloadOrder = "largest" | "newest" | "oldest";

const DOWNLOAD_ORDER: Record<DownloadOrder, string> = {
  largest: "Largest first",
  newest: "Arrived most recently first",
  oldest: "Arrived longest ago first",
};

/** Which rows a shortened list holds, for the line that says so. */
const DOWNLOADS_SHOWN: Record<DownloadOrder, (shown: string, all: string) => string> = {
  largest: (shown, all) => `Showing the ${shown} largest of ${all}.`,
  newest: (shown, all) => `Showing the ${shown} that arrived most recently, of ${all}.`,
  oldest: (shown, all) => `Showing the ${shown} that arrived longest ago, of ${all}.`,
};

/**
 * The downloads in the order asked for.
 *
 * A download whose arrival date Windows did not record cannot be placed in
 * an order by arrival, so it goes last in both, and its row says the date
 * was not recorded.
 */
function ordered(downloads: Download[], order: DownloadOrder): Download[] {
  if (order === "largest") return downloads;
  const direction = order === "newest" ? 1 : -1;
  return [...downloads].sort((a, b) => {
    if (a.days_since_arrival === null || b.days_since_arrival === null) {
      return (
        Number(a.days_since_arrival === null) - Number(b.days_since_arrival === null)
      );
    }
    return direction * (a.days_since_arrival - b.days_since_arrival) || b.bytes - a.bytes;
  });
}

/** What the list of large old files can be sorted by: its four columns. */
type OldColumn = "bytes" | "created" | "modified" | "accessed";
type OldSort = { by: OldColumn; ascending: boolean };

/**
 * Where a large old file that is not listed sits, in the words the page uses.
 *
 * The service lists only files in the reader's own folders and counts the
 * rest by which of these it was. "Yours" is never among them.
 */
const LEFT_OUT_WHERE: Record<Owner, string> = {
  windows: "among Windows' own files",
  servicing: "kept by Windows or an installer for repairs and updates",
  program: "in program folders",
  program_data: "in program data folders",
  yours: "in your own folders",
  deleted: "already in a Recycle Bin",
  elsewhere: "in another account's profile, or somewhere else this cannot tell is yours",
};

/** A date as a column shows it. One that was not recorded says so. */
function recordedDate(seconds: number | null): string {
  if (seconds === null) return "not recorded";
  return new Date(seconds * 1000).toLocaleDateString(undefined, {
    day: "numeric",
    month: "short",
    year: "numeric",
  });
}

/**
 * The large old files in the order asked for.
 *
 * A date that was not recorded sorts last whichever way the column runs: it
 * is neither the oldest nor the newest.
 */
function sortedOldFiles(files: OldFile[], sort: OldSort): OldFile[] {
  const direction = sort.ascending ? 1 : -1;
  return [...files].sort((a, b) => {
    const left = a[sort.by];
    const right = b[sort.by];
    if (left === null || right === null) {
      return Number(left === null) - Number(right === null);
    }
    return direction * (left - right) || b.bytes - a.bytes;
  });
}

/**
 * How long quarantine keeps an item before the service deletes it for good.
 * The service's own figure is `RETENTION_DAYS` in `kam-quarantine`, and it is
 * the one that decides: this is only what the row says.
 */
const RETENTION_DAYS = 30;

/**
 * How long a quarantined item has left.
 *
 * The service looks four times a day, so an item whose thirty days are up can
 * sit here for a few hours more, still restorable. It is said as what it is,
 * rather than as nought days left beside a Restore button that still works.
 */
function timeLeft(quarantinedAt: number): string {
  const left = quarantinedAt + RETENTION_DAYS * 86_400 - Date.now() / 1000;
  if (left <= 0) return "due to be deleted";
  const days = Math.floor(left / 86_400);
  if (days >= 1) return `${fmt.count(days)} ${days === 1 ? "day" : "days"} left`;
  return "less than a day left";
}

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
  recyclable,
}: {
  orphan: Orphan;
  onQuarantine: (orphan: Orphan) => void;
  onDelete: (orphan: Orphan) => void;
  busy: boolean;
  /** False when this account cannot delete from the folder holding it. */
  recyclable: boolean;
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
        {/*
          Offered only where it can work. Leftovers live under `ProgramData`
          and the `AppData` roots, and an unprivileged account frequently
          cannot delete from those -- so this button was there, pressed, and
          failed with a raw error from inside the shell call. Offering an
          action that cannot work does not teach somebody that the folder is
          protected; it teaches them the button is unreliable, which is a far
          more expensive lesson.
        */}
        {recyclable ? (
          <button
            className="ghost"
            disabled={busy}
            title="Send it to the Recycle Bin, where Windows can put it back"
            onClick={() => onDelete(orphan)}
          >
            Recycle Bin
          </button>
        ) : (
          <span
            className="orphan-note"
            title="Windows will not let this account delete from the folder holding it, so quarantine is the way to move it aside."
          >
            Needs quarantine
          </span>
        )}
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
  /**
   * The places leftovers live that the last search could not look in,
   * because they are on another drive than the one searched.
   *
   * Searching a second drive used to answer "Nothing unaccounted for. That is
   * a good result." about three folders it had not opened. Before that was
   * fixed in the service it was worse: it found folders of the same names on
   * the drive it was given and listed them under these paths.
   */
  const [rootsElsewhere, setRootsElsewhere] = useState<string[]>([]);
  const [downloads, setDownloads] = useState<Download[] | null>(null);
  const [downloadSummary, setDownloadSummary] = useState<DownloadSummary | null>(null);
  const [downloadOrder, setDownloadOrder] = useState<DownloadOrder>("largest");
  const [allDownloads, setAllDownloads] = useState(false);
  /**
   * Large files in the reader's own folders whose dates are all more than a
   * year old, as the last search sent them: the largest, at most 200.
   */
  const [oldFiles, setOldFiles] = useState<OldFile[] | null>(null);
  const [oldSummary, setOldSummary] = useState<OldFileSummary | null>(null);
  /**
   * What the search found beyond the list it sent. Worked out once, when the
   * answer arrives, so that the figures stay true as rows leave the list:
   * what is on screen is added up from the rows, and this is added to it.
   */
  const [oldRest, setOldRest] = useState({ files: 0, bytes: 0 });
  const [oldSort, setOldSort] = useState<OldSort>({ by: "bytes", ascending: false });
  /**
   * What became of the last press on that list, said beside it. The line
   * under the controls is two screens up from this list.
   */
  const [oldNotice, setOldNotice] = useState<{ text: string; caution: boolean } | null>(
    null,
  );
  const [duplicates, setDuplicates] = useState<DupeSet[] | null>(null);
  const [duplicateSummary, setDuplicateSummary] = useState<DuplicateSummary | null>(null);
  /**
   * When each search on this page last answered, by this window's clock.
   *
   * The lists below shrink as things are removed and the figures above them
   * are worked out from what is left, so those stay true. What cannot stay
   * true by itself is the search: a folder that has grown since, or a copy
   * made since, is not here until somebody looks again. So each says when.
   */
  const [foundAt, setFoundAt] = useState(0);
  const [duplicatesAt, setDuplicatesAt] = useState(0);
  const [cachesAt, setCachesAt] = useState(0);
  /** The drive each search that is on screen looked at. */
  const [surveyDrive, setSurveyDrive] = useState("C:\\");
  const [duplicatesDrive, setDuplicatesDrive] = useState("C:\\");
  /**
   * When each answer kept from before this page opened was found. A search
   * answered since has a newer time, so an answer on screen is the kept one
   * exactly while its time is this one.
   */
  const [keptAt, setKeptAt] = useState<Partial<Record<Search, number>>>({});
  /** Why an answer kept from before could not be read back. */
  const [unreadableKept, setUnreadableKept] = useState<Partial<Record<Search, string>>>({});
  /** Why an answer could not be kept for the next time the page opens. */
  const [notKept, setNotKept] = useState<Partial<Record<Search, string>>>({});
  /** Searches started since the page opened, which a kept answer must not cover. */
  const searched = useRef<Record<Search, boolean>>({
    survey: false,
    duplicates: false,
    caches: false,
  });
  /** The sets as they are now, for a removal that finishes after a redraw. */
  const duplicatesNow = useRef<DupeSet[] | null>(null);
  duplicatesNow.current = duplicates;
  const [proposals, setProposals] = useState<Proposal[] | null>(null);
  const [organiseSummary, setOrganiseSummary] = useState<OrganiseSummary | null>(null);
  /** When the search for loose files on screen finished. */
  const [looseAt, setLooseAt] = useState(0);
  const [moves, setMoves] = useState<MoveRecord[]>([]);
  const [held, setHeld] = useState<Manifest[]>([]);
  /**
   * Every row with an action in flight, by key.
   *
   * This was one slot, `busyPath`, and three of the actions never set it --
   * Move, Put back and Restore -- so the double-click guard their buttons
   * relied on did not exist. And one slot cannot hold two actions: whichever
   * finished first emptied it, re-enabling a row whose own action was still
   * running.
   *
   * The ref is the guard and the state is the drawing. The ref is read and
   * written in the same event as the click, so a second click on the same row
   * is turned away even before React has redrawn the button as disabled.
   */
  const inFlightRef = useRef<Set<string>>(new Set());
  const [inFlight, setInFlight] = useState<ReadonlySet<string>>(new Set());
  const [onlyActionable, setOnlyActionable] = useState(true);
  const [caches, setCaches] = useState<Cache[] | null>(null);
  /**
   * Whether the measurement of caches running now was started by a clear, so
   * that a failure says it was the measuring again that failed.
   */
  const afterClear = useRef(false);
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
  /**
   * The line under the controls, and whether it is good news.
   *
   * A Recycle Bin outcome that did not reach the bin, or could not be
   * confirmed to have, is a caution rather than a success, and was drawn in
   * the same green as one.
   */
  const [notice, setNotice] = useState<{ text: string; caution: boolean } | null>(null);
  const setNote = (text: string | null) =>
    setNotice(text === null ? null : { text, caution: false });
  const setCaution = (text: string) => setNotice({ text, caution: true });
  const [explaining, setExplaining] = useState(false);
  /**
   * The block being looked inside, by key, or null for the whole picture.
   *
   * A key rather than the node: the node was a copy taken at the click, so
   * after a removal or a fresh measurement the drilled-in map went on drawing
   * blocks for bytes that were gone. The children are now read from the
   * current data on every render.
   */
  const [mapIntoKey, setMapIntoKey] = useState<string | null>(null);
  const duplicatesPanel = useRef<HTMLElement>(null);
  const [heldError, setHeldError] = useState<string | null>(null);
  const [movesError, setMovesError] = useState<string | null>(null);

  /** Mark a row busy, or say it already is. */
  function claim(key: string): boolean {
    if (inFlightRef.current.has(key)) return false;
    inFlightRef.current.add(key);
    setInFlight(new Set(inFlightRef.current));
    return true;
  }

  function release(key: string) {
    inFlightRef.current.delete(key);
    setInFlight(new Set(inFlightRef.current));
  }

  /** True while anything on the page is being acted on. */
  const anyBusy = inFlight.size > 0;

  /**
   * Say what happened to something sent to the Recycle Bin.
   *
   * Three answers, not two. It arrived; it did not, because Windows deleted it
   * outright; or the bin could not be counted, so nobody knows. The last was
   * reported as the first.
   */
  function reportRecycle(outcome: RecycleOutcome, sent: string, missed: string) {
    if (outcome.in_bin && !outcome.warning) {
      setNote(sent);
    } else {
      setCaution(outcome.warning ?? missed);
    }
  }

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

  // Each search's last answer, as it was kept, so the page does not open
  // empty. Never over an answer to a search started since the page opened.
  useEffect(() => {
    let open = true;
    const unreadable = (search: Search) => (cause: unknown) => {
      if (open && !searched.current[search]) {
        setUnreadableKept((current) => ({ ...current, [search]: reason(cause) }));
      }
    };
    recall<KeptSurvey>("cleanup-survey")
      .then((found) => {
        if (!open || found === null || searched.current.survey) return;
        const kept = found.result;
        setDrive(kept.drive);
        setSurveyDrive(kept.drive);
        setOrphans(kept.orphans);
        setRootsElsewhere(kept.rootsElsewhere);
        setDownloads(kept.downloads);
        setDownloadSummary(kept.downloadSummary);
        setOldFiles(kept.oldFiles);
        setOldSummary(kept.oldSummary);
        setOldRest(kept.oldRest);
        setFoundAt(found.measuredAt);
        setKeptAt((current) => ({ ...current, survey: found.measuredAt }));
      })
      .catch(unreadable("survey"));
    recall<KeptDuplicates>("cleanup-duplicates")
      .then((found) => {
        if (!open || found === null || searched.current.duplicates) return;
        setDuplicatesDrive(found.result.drive);
        setDuplicates(found.result.sets);
        setDuplicateSummary(found.result.summary);
        setDuplicatesAt(found.measuredAt);
        setKeptAt((current) => ({ ...current, duplicates: found.measuredAt }));
      })
      .catch(unreadable("duplicates"));
    recall<KeptCaches>("cleanup-caches")
      .then((found) => {
        if (!open || found === null || searched.current.caches) return;
        setCaches(found.result.caches);
        setCachesAt(found.measuredAt);
        setKeptAt((current) => ({ ...current, caches: found.measuredAt }));
      })
      .catch(unreadable("caches"));
    return () => {
      open = false;
    };
  }, []);

  /** Keep one search's answer as it now stands, and say if it could not be. */
  function keep<T>(search: Search, kind: Parameters<typeof remember>[0], at: number, result: T) {
    return remember(kind, at, result).then((failed) =>
      setNotKept((current) =>
        failed === null ? without(current, search) : { ...current, [search]: failed },
      ),
    );
  }

  // What each search came to, whether it ended while this page was open or
  // while it was not. The window's own half runs the searches, so they carry
  // on when the page is left. An answer this page keeps is kept here, before
  // the handler returns, as well as when it is drawn: the window's own half
  // lets go of it once the handler has run, and a page left before drawing it
  // would otherwise lose it.

  async function surveyArrived(outcome: PageJobOutcome<ApplicationReport>) {
    searched.current.survey = true;
    const ended = outcome.view.ended;
    if (ended?.how === "finished" && outcome.answer !== null) {
      const asked = outcome.view.asked;
      const searchedDrive = asked.slot === "cleanup-survey" ? asked.drive : drive;
      const found = surveyed(searchedDrive, outcome.answer);
      setSurveyDrive(found.drive);
      setUnreadableKept((current) => without(current, "survey"));
      setOrphans(found.orphans);
      setRootsElsewhere(found.rootsElsewhere);
      setDownloads(found.downloads);
      setDownloadSummary(found.downloadSummary);
      setOldFiles(found.oldFiles);
      setOldSummary(found.oldSummary);
      setOldRest(found.oldRest);
      setOldNotice(null);
      setFoundAt(ended.at);
      await keep<KeptSurvey>("survey", "cleanup-survey", ended.at, found);
    } else if (ended?.how === "failed") {
      setError(ended.reason);
      // Everything this run would have replaced goes, the totals included.
      // The totals stayed, so a failed re-run left the last run's numbers on
      // screen as though they were this one's.
      setOrphans(null);
      setRootsElsewhere([]);
      setDownloads(null);
      setDownloadSummary(null);
      setOldFiles(null);
      setOldSummary(null);
      setOldNotice(null);
    }
    onChanged();
  }
  const surveyJob = usePageJob<ApplicationReport>("cleanup-survey", surveyArrived);
  const running = surveyJob.running;

  async function duplicatesArrived(outcome: PageJobOutcome<DuplicateReport>) {
    searched.current.duplicates = true;
    const ended = outcome.view.ended;
    if (ended?.how === "finished" && outcome.answer !== null) {
      const asked = outcome.view.asked;
      const searchedDrive = asked.slot === "cleanup-duplicates" ? asked.drive : drive;
      const sets = asSets(outcome.answer.groups);
      setDuplicatesDrive(searchedDrive);
      setUnreadableKept((current) => without(current, "duplicates"));
      setDuplicates(sets);
      setDuplicateSummary(outcome.answer.summary);
      setDuplicatesAt(ended.at);
      await keep<KeptDuplicates>("duplicates", "cleanup-duplicates", ended.at, {
        drive: searchedDrive,
        sets,
        summary: outcome.answer.summary,
      });
    } else if (ended?.how === "stopped") {
      // Stopped, not failed.
      setDuplicates(null);
      setDuplicateSummary(null);
    } else if (ended?.how === "failed") {
      setError(ended.reason);
      // The summary feeds the stat row and the block on the map, and both went
      // on showing the previous run's figures after this one failed.
      setDuplicates(null);
      setDuplicateSummary(null);
    }
    onChanged();
  }
  // The longest job in the product: it reads file contents rather than the
  // file table, so it is the one that most needs to say what it is doing and
  // to be stoppable.
  const duplicatesJob = usePageJob<DuplicateReport>("cleanup-duplicates", duplicatesArrived);
  const findingDuplicates = duplicatesJob.running;

  async function cachesArrived(outcome: PageJobOutcome<Cache[]>) {
    searched.current.caches = true;
    const again = afterClear.current;
    afterClear.current = false;
    const ended = outcome.view.ended;
    if (ended?.how === "finished" && outcome.answer !== null) {
      setCaches(outcome.answer);
      setCachesAt(ended.at);
      setUnreadableKept((current) => without(current, "caches"));
      await keep<KeptCaches>("caches", "cleanup-caches", ended.at, {
        caches: outcome.answer,
      });
    } else if (ended?.how === "failed") {
      // After a clear, the figures from before it are wrong, so they go
      // rather than stay; and a failed measurement does not leave the last
      // one's figures standing in for it either.
      setError(
        again ? `Measuring again after the clear failed: ${ended.reason}` : ended.reason,
      );
      setCaches(null);
    }
  }
  const cachesJob = usePageJob<Cache[]>("cleanup-caches", cachesArrived);
  const measuringCaches = cachesJob.running;

  /**
   * What the search for loose files came to. This page does not keep it, so
   * the window's own half does, for as long as the program runs, and it is
   * handed over again each time the page opens.
   */
  function looseArrived(outcome: PageJobOutcome<OrganiseReport>) {
    const ended = outcome.view.ended;
    if (ended?.how === "finished" && outcome.answer !== null) {
      setProposals(outcome.answer.proposals);
      setOrganiseSummary(outcome.answer.summary);
      setLooseAt(ended.at);
    } else if (ended?.how === "failed") {
      setError(ended.reason);
      setProposals(null);
      setOrganiseSummary(null);
    }
  }
  const looseJob = usePageJob<OrganiseReport>("cleanup-loose", looseArrived);
  const organising = looseJob.running;

  // Each answer is kept as it stands: after a search, and again after every
  // row that leaves it, so a row acted on does not come back when the page
  // is next opened. A search that failed or was stopped leaves its lists
  // empty and keeps nothing, so the last answer that did finish stays kept.
  useEffect(() => {
    if (orphans === null || foundAt === 0) return;
    keep<KeptSurvey>("survey", "cleanup-survey", foundAt, {
      drive: surveyDrive,
      orphans,
      rootsElsewhere,
      downloads,
      downloadSummary,
      oldFiles,
      oldSummary,
      oldRest,
    });
  }, [orphans, rootsElsewhere, downloads, downloadSummary, oldFiles, oldSummary, oldRest, foundAt, surveyDrive]);

  useEffect(() => {
    if (duplicates === null || duplicatesAt === 0) return;
    keep<KeptDuplicates>("duplicates", "cleanup-duplicates", duplicatesAt, {
      drive: duplicatesDrive,
      sets: duplicates,
      summary: duplicateSummary,
    });
  }, [duplicates, duplicateSummary, duplicatesAt, duplicatesDrive]);

  useEffect(() => {
    if (caches === null || cachesAt === 0) return;
    keep<KeptCaches>("caches", "cleanup-caches", cachesAt, { caches });
  }, [caches, cachesAt]);

  // A search that fails empties its lists and leaves its time alone, so the
  // lists being there is part of the answer on screen being the kept one.
  const surveyKept = orphans !== null && keptAt.survey !== undefined && keptAt.survey === foundAt;
  const duplicatesKept =
    duplicates !== null &&
    keptAt.duplicates !== undefined &&
    keptAt.duplicates === duplicatesAt;
  const cachesKept = caches !== null && keptAt.caches !== undefined && keptAt.caches === cachesAt;

  async function find() {
    setError(null);
    setNote(null);
    searched.current.survey = true;
    try {
      await surveyJob.start({ slot: "cleanup-survey", drive });
    } catch (cause) {
      setError(reason(cause));
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
    setError(null);
    try {
      await looseJob.start({ slot: "cleanup-loose", drive });
    } catch (cause) {
      setError(reason(cause));
    }
  }

  async function applyMove(proposal: Proposal) {
    const key = `move:${proposal.from}`;
    if (!claim(key)) return;
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
      release(key);
      onChanged();
    }
  }

  async function undoMove(id: string) {
    const key = `moved:${id}`;
    if (!claim(key)) return;
    setError(null);
    try {
      const record = await api.undoMove(id);
      setNote(`Put ${record.from} back.`);
      await loadMoves();
    } catch (cause) {
      setError(reason(cause));
    } finally {
      release(key);
      onChanged();
    }
  }

  async function findDuplicates() {
    setError(null);
    searched.current.duplicates = true;
    try {
      await duplicatesJob.start({ slot: "cleanup-duplicates", drive });
    } catch (cause) {
      setError(reason(cause));
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
    setError(null);
    searched.current.caches = true;
    try {
      await cachesJob.start({ slot: "cleanup-caches" });
    } catch (cause) {
      setError(reason(cause));
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
      // checked. It is the same measurement as Measure, so it carries on if
      // the page is left. One already going is what will be shown instead.
      searched.current.caches = true;
      afterClear.current = true;
      try {
        await cachesJob.start({ slot: "cleanup-caches" });
      } catch (cause) {
        afterClear.current = false;
        if (!measuringCaches) {
          // The clear happened; the figures from before it are now wrong, so
          // they go rather than stay.
          setCaches(null);
          setError(`Measuring again after the clear failed: ${reason(cause)}`);
        }
      }
    } catch (cause) {
      setError(reason(cause));
    } finally {
      setClearingCache(null);
      onChanged();
    }
  }

  /**
   * Take a copy that has gone out of its set, and settle the set again.
   *
   * The set kept every figure the search had sent. With one of three copies
   * removed it still said "All 3 copies are in folders of yours" and still
   * counted two copies' worth as reclaimable, and the totals above the list
   * and the block on the map, which were the search's own summary, never
   * moved at all.
   *
   * The shell settles the set from the copies that are left, with the code
   * that judged it to begin with, so the arithmetic exists in one place. The
   * set keeps its id, and with it the person's own pick of keeper.
   */
  async function dropCopy(path: string) {
    const set = duplicatesNow.current?.find((group) =>
      group.copies.some((copy) => copy.path === path),
    );
    if (!set) return;

    // Null is an answer: one file is all that is left, which is not a set.
    let settled: DuplicateGroup | null = null;
    try {
      settled = await api.duplicateSetWithout(set, path);
    } catch (cause) {
      // The copy has gone whether or not the set could be settled again. A
      // set that cannot be settled leaves the list with it, because the only
      // figures there are for it describe a copy that is no longer there.
      setCaution(
        `${path} was removed. The set it belonged to could not be worked out ` +
          `again (${reason(cause)}), so it is no longer listed. Find duplicates ` +
          `again to see what is left of it.`,
      );
    }

    const next = settled;
    setDuplicates((current) =>
      current
        ? current.flatMap((group): DupeSet[] => {
            if (group.id !== set.id) return [group];
            return next === null
              ? []
              : [{ ...next, id: group.id, suggestedPath: suggestedPathOf(next) }];
          })
        : current,
    );
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
   *
   * `keep` is the copy that stays. The agent compares the two before it
   * moves anything, because this list may be days old.
   */
  async function holdCopy(path: string, keep: string, bytes: number, chosen: boolean) {
    const key = `copy:${path}`;
    if (!claim(key)) return;
    setError(null);
    try {
      await api.quarantineCopy(
        path,
        keep,
        chosen
          ? "you chose which copy to keep, and this was not it"
          : "a redundant copy of an identical file",
        chosen,
      );
      setNote(
        `Held ${fmt.bytes(bytes)}: ${path}. It is in quarantine below and can be put back for 30 days.`,
      );
      await dropCopy(path);
      await loadQuarantine();
    } catch (cause) {
      setError(reason(cause));
    } finally {
      release(key);
      onChanged();
    }
  }


  /**
   * Send one redundant copy to the Recycle Bin.
   *
   * Same reasoning as `recycleOrphan`: the window does it, so the copy lands in
   * this person's bin rather than SYSTEM's, and no privilege is involved in
   * removing a file they own.
   *
   * It is first compared with the copy that stays, as the agent compares one
   * before quarantining it: this list may be days old.
   */
  async function recycleCopy(path: string, keep: string, bytes: number) {
    const key = `copy:${path}`;
    if (!claim(key)) return;
    setError(null);
    try {
      await api.checkStillTwins(path, keep);
    } catch (cause) {
      setError(reason(cause));
      release(key);
      return;
    }
    try {
      const outcome = await api.recycleItem(path);
      reportRecycle(
        outcome,
        `Sent ${fmt.bytes(bytes)} to the Recycle Bin: ${path}`,
        `${path} was removed but did not reach the Recycle Bin.`,
      );
      await dropCopy(path);
    } catch (cause) {
      setError(
        `${reason(cause)}. If this copy is not yours to delete, hold it instead ` +
          `and it can be put back for 30 days.`,
      );
    } finally {
      release(key);
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
    const key = `held:${id}`;
    if (!claim(key)) return;
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
      release(key);
      onChanged();
    }
  }

  async function emptyAll() {
    const key = "held:all";
    if (!claim(key)) return;
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
      release(key);
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
    const key = `orphan:${orphan.path}`;
    if (!claim(key)) return;
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
      release(key);
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
    const key = `orphan:${orphan.path}`;
    if (!claim(key)) return;
    setError(null);
    try {
      const outcome = await api.recycleItem(orphan.path);
      reportRecycle(
        outcome,
        `Sent ${orphan.name} (${fmt.bytes(orphan.bytes)}) to the Recycle Bin. ` +
          `It is in there until you empty it.`,
        `${orphan.name} was removed but did not reach the Recycle Bin.`,
      );
      setOrphans((current) =>
        current ? current.filter((item) => item.path !== orphan.path) : current,
      );
    } catch (cause) {
      setError(
        `${reason(cause)}. If this folder is not yours to delete, quarantine it ` +
          `instead and it can be put back for 30 days.`,
      );
    } finally {
      release(key);
      onChanged();
    }
  }

  /**
   * Send one large old file to the Recycle Bin, or leave it where it is.
   *
   * The window does it, as everywhere on this page, so the file lands in this
   * person's own bin. Unlike everywhere else on this page it will not let
   * Windows delete the file outright when the bin cannot take it: every row
   * of this list is large, which is when that happens. Such a file stays
   * where it is and the reason is shown beside the list.
   */
  async function recycleOldFile(file: OldFile) {
    const key = `old:${file.path}`;
    if (!claim(key)) return;
    setOldNotice(null);
    try {
      const outcome = await api.recycleOrLeave(file.path);
      setOldNotice(
        outcome.in_bin && !outcome.warning
          ? {
              text:
                `Sent ${file.name} (${fmt.bytes(file.bytes)}) to the Recycle Bin. ` +
                `It is in there until you empty it.`,
              caution: false,
            }
          : {
              text:
                outcome.warning ??
                `${file.name} was removed but did not reach the Recycle Bin.`,
              caution: true,
            },
      );
      setOldFiles((current) =>
        current ? current.filter((item) => item.path !== file.path) : current,
      );
    } catch (cause) {
      // Refused or failed: either way the file has not gone, and the row
      // stays. The reason is the window's own sentence.
      setOldNotice({ text: `${reason(cause)}.`, caution: true });
    } finally {
      release(key);
      onChanged();
    }
  }

  async function restore(id: string) {
    const key = `held:${id}`;
    if (!claim(key)) return;
    setError(null);
    try {
      const manifest = await api.restore(id);
      setNote(`Restored to ${manifest.original_path}.`);
      await loadQuarantine();
    } catch (cause) {
      setError(reason(cause));
    } finally {
      release(key);
      onChanged();
    }
  }

  const active = held.filter((item) => !item.restored);

  /**
   * What the lists on screen come to, now.
   *
   * These were the totals each search sent with its answer, and nothing
   * touched them afterwards. Remove every duplicate copy and the map still
   * drew "Duplicate copies" at full size; quarantine a leftover and "Found"
   * and "Holding" still counted it. A block whose area is a number from
   * before the last press is not a measurement of anything. So they are added
   * up from what is still listed, every time the page draws.
   */
  const leftoversNow = orphans && {
    found: orphans.length,
    total_bytes: orphans.reduce((sum, orphan) => sum + orphan.bytes, 0),
    confident_bytes: orphans
      .filter((orphan) => orphan.confidence === "high")
      .reduce((sum, orphan) => sum + orphan.bytes, 0),
  };
  // Sets the search found and counted but could not fit in its answer. They
  // are not on screen and cannot be acted on, so they stand as they were.
  const unlisted = duplicateSummary?.unlisted ?? {
    groups: 0,
    wasted_bytes: 0,
    reclaimable_bytes: 0,
    actionable: 0,
  };
  const duplicatesStanding = duplicates && {
    groups: duplicates.length + unlisted.groups,
    wasted_bytes:
      duplicates.reduce((sum, group) => sum + group.wasted_bytes, 0) +
      unlisted.wasted_bytes,
    reclaimable_bytes:
      duplicates.reduce((sum, group) => sum + group.reclaimable_bytes, 0) +
      unlisted.reclaimable_bytes,
    actionable:
      duplicates.filter((group) => group.verdict === "choose").length +
      unlisted.actionable,
  };

  /**
   * Everything measured, as one picture with area meaning bytes.
   *
   * Built from whatever has actually been measured rather than from what could
   * be: a category nobody has scanned yet is absent, not drawn as zero. A block
   * of zero area would be invisible anyway, and a *label* with no block behind
   * it would suggest the answer is "nothing" when the answer is "not asked".
   */
  /**
   * What the cache survey measured, as the two things it is.
   *
   * A cache can be cleared. The rest is large, looks as though it could go,
   * and cannot: the hibernation file, what one website stored in a browser,
   * downloaded models. It is measured so that it is accounted for and shown
   * with what it is for, and it has no button. It is kept out of the map and
   * out of every total below, which are of what this page can reclaim.
   */
  const clearable = caches && caches.filter((cache) => cache.safety !== "explained");
  const explained = (caches ?? []).filter((cache) => cache.safety === "explained");

  const reclaim: ReclaimNode[] = [];
  if (orphans && orphans.length > 0) {
    reclaim.push({
      key: "orphans",
      label: "Leftovers",
      bytes: orphans.reduce((sum, orphan) => sum + orphan.bytes, 0),
      // Quarantine is what this page offers first for these, and it is the
      // reversal that always works -- the Recycle Bin is offered beside it only
      // where this account could actually use it.
      reversal: "quarantine",
      detail: `${fmt.count(orphans.length)} ${orphans.length === 1 ? "folder" : "folders"} no installed program accounts for`,
      children: orphans.map((orphan) => ({
        key: orphan.path,
        label: orphan.name,
        bytes: orphan.bytes,
        reversal: "quarantine" as const,
        detail: CONFIDENCE_LABEL[orphan.confidence].toLowerCase(),
        path: orphan.path,
      })),
    });
  }
  if (clearable && clearable.length > 0) {
    reclaim.push({
      key: "caches",
      label: "Caches",
      bytes: clearable.reduce((sum, cache) => sum + cache.bytes, 0),
      // The one category on this page removed outright, which is why it is the
      // one colour that says so.
      reversal: "permanent",
      detail: `${fmt.count(clearable.length)} ${clearable.length === 1 ? "kind" : "kinds"} of scratch space`,
      children: clearable.map((cache) => ({
        key: cache.id,
        label: cache.name,
        bytes: cache.bytes,
        reversal: "permanent" as const,
        detail:
          (cache.cost || "costs nothing to clear") +
          (cache.locations.length > 1
            ? ` (a click opens the first of its ${cache.locations.length} folders)`
            : ""),
        // A cache is an id, not a place; its first folder is the place.
        path: cache.locations[0]?.path,
      })),
    });
  }
  if (duplicatesStanding && duplicatesStanding.reclaimable_bytes > 0) {
    reclaim.push({
      // No single folder holds these, so a click goes to the list of them.
      key: "duplicates",
      label: "Duplicate copies",
      bytes: duplicatesStanding.reclaimable_bytes,
      // The colour is what pressing the button does, so on a drive
      // quarantine cannot hold things from it is the Recycle Bin's.
      reversal: duplicateSummary?.quarantine_only_on ? "recycle" : "quarantine",
      detail: `${fmt.count(duplicatesStanding.actionable)} ${duplicatesStanding.actionable === 1 ? "set" : "sets"} you can choose between`,
    });
  }

  // The drilled-in block as it is now, not as it was when it was clicked. If
  // it has gone -- everything in it removed, or its search failed -- the map
  // goes back to the whole picture rather than drawing what is no longer there.
  const drilled =
    mapIntoKey === null
      ? null
      : (reclaim.find(
          (node) => node.key === mapIntoKey && (node.children?.length ?? 0) > 0,
        ) ?? null);
  const drilledGone = mapIntoKey !== null && drilled === null;
  useEffect(() => {
    if (drilledGone) setMapIntoKey(null);
  }, [drilledGone]);
  const drawn = drilled ? (drilled.children ?? []) : reclaim;

  function openBlock(node: ReclaimNode) {
    if (node.children && node.children.length > 0) {
      setMapIntoKey(node.key);
    } else if (node.path) {
      void reveal(node.path);
    } else if (node.key === "duplicates") {
      duplicatesPanel.current?.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }

  // Asked once per directory rather than once per file, because the probe
  // tests the directory: a hundred leftovers usually sit in three or four.
  const canRecycle = useRecyclable([
    ...(orphans ?? []).map((orphan) => orphan.path),
    ...(duplicates ?? []).flatMap((group) =>
      group.copies.map((copy) => copy.path),
    ),
    ...(oldFiles ?? []).map((file) => file.path),
  ]);

  // The search for loose files is kept by the window's own half and handed
  // over again each time the page opens, so a file moved since it was found
  // is left out here rather than offered to be moved a second time.
  const movedAway = new Set(moves.filter((move) => !move.undone).map((move) => move.from));
  const looseLeft = proposals?.filter((proposal) => !movedAway.has(proposal.from)) ?? null;

  const orderedDownloads = useMemo(
    () => ordered(downloads ?? [], downloadOrder),
    [downloads, downloadOrder],
  );
  const shownDownloads = allDownloads
    ? orderedDownloads
    : orderedDownloads.slice(0, DOWNLOAD_LIMIT);
  const unlistedDownloads = downloadSummary?.unlisted ?? 0;

  // Whether the last-opened date was used to build the list of large old
  // files. Only where Windows is known to be recording opens.
  const opensRecorded = oldSummary?.access_times === "recorded";
  const shownOldFiles = useMemo(
    () => sortedOldFiles(oldFiles ?? [], oldSort),
    [oldFiles, oldSort],
  );
  // The rule as the service applied it, in the page's words.
  const oldAge =
    oldSummary === null
      ? ""
      : oldSummary.older_than_days === 365
        ? "a year"
        : `${fmt.count(oldSummary.older_than_days)} days`;
  // What stands now: the rows still listed, and what was found beyond them.
  const oldStanding = {
    files: (oldFiles?.length ?? 0) + oldRest.files,
    bytes: (oldFiles ?? []).reduce((sum, file) => sum + file.bytes, 0) + oldRest.bytes,
  };

  /** Sort the large old files by a column, or turn that column's order round. */
  function sortOldBy(column: OldColumn) {
    setOldSort((current) =>
      current.by === column
        ? { by: column, ascending: !current.ascending }
        : // Size starts largest first. A date starts oldest first, which is
          // the end of the list a person came here for.
          { by: column, ascending: column !== "bytes" },
    );
  }

  return (
    <>
      <div className="view-head">
        <div>
          <h1>Cleanup</h1>
          <p className="lede">
            Directories left behind by software that is no longer installed,
            and other space worth a look. Quarantine holds what you move where
            this program can put it back, and the Recycle Bin holds it where
            Windows can. Two things here are permanent and say so: clearing a
            cache, and deleting from quarantine.
          </p>
        </div>
      </div>

      {/*
        Ordered by what a person opening this page needs, rather than by
        the order the panels were written in.

        The control comes first because pressing it is what they came to
        do; it used to sit behind a sixty-line explainer that pushed it off
        the first screen. Then what the scan found. Then what is being held
        of theirs, which was last on the page despite being the only thing
        here with a clock on it and the only place an irreversible action
        lives. Then the rest, largest reclaimable space first, ending with
        the one that only tells you something. The explainer is reference
        material and is folded shut.
      */}
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
                  {volume.root} {volume.label ? `(${volume.label})` : ""}
                </option>
              ))}
          </select>
          <button className="primary" onClick={() => void find()} disabled={running}>
            {running ? "Looking…" : "Find leftovers"}
          </button>
          <span className="muted">Needs an agent with administrative rights.</span>
        </div>

        {error && <pre className="error">{error}</pre>}
        {notice && (
          <div className={`notice ${notice.caution ? "notice-warn" : "notice-ok"}`}>
            {notice.text}
          </div>
        )}

        {unreadableKept.survey && orphans === null && !running && (
          <UnreadableNote
            what="The last search for leftovers, downloads and large old files"
            why={unreadableKept.survey}
            again="Press Find leftovers to search again."
          />
        )}
        {notKept.survey && <NotKeptNote why={notKept.survey} />}
        {surveyKept && (
          <KeptNote
            what={`the search of ${surveyDrive} for leftovers, downloads and large old files`}
            at={foundAt}
            again="A file or folder in it may have changed or gone since then. Press Find leftovers to search again."
          />
        )}

        {leftoversNow && (
          <div className="stat-row tight">
            <div className="stat">
              <span className="stat-label">Found</span>
              <span className="stat-value">{fmt.count(leftoversNow.found)}</span>
            </div>
            <div className="stat">
              <span className="stat-label">Holding</span>
              <span className="stat-value">{fmt.bytes(leftoversNow.total_bytes)}</span>
            </div>
            <div className="stat">
              <span className="stat-label">Very likely leftover</span>
              <span className="stat-value">
                {fmt.bytes(leftoversNow.confident_bytes)}
              </span>
            </div>
            <MeasuredAt at={foundAt} />
          </div>
        )}
      </section>

      {reclaim.length > 0 && (
        <section className="panel">
          <div className="panel-head">
            <h2>Where the space is</h2>
            <span className="panel-count">
              {fmt.bytes(reclaim.reduce((sum, node) => sum + node.bytes, 0))}
            </span>
          </div>
          <p className="panel-lede">
            Everything measured so far, drawn to scale: a block's area is its
            size on disk. A list gives a forty-gigabyte item and a
            four-megabyte item the same row and only ever tells you the order,
            never the ratio. And the question on a full drive is not what is on
            it, it is what is worth your time.
          </p>
          <ReclaimMap nodes={drawn} onOpen={openBlock} />
          <GridLegend entries={reclaimLegend(drawn)} />
          {drilled && (
            <button className="link-button" onClick={() => setMapIntoKey(null)}>
              Back to everything
            </button>
          )}
        </section>
      )}

      {orphans && (
        <section className="panel">
          <div className="panel-head">
            <h2>Candidates</h2>
          </div>
          {rootsElsewhere.length > 0 && (
            <div className="notice notice-warn">
              Leftovers are looked for in ProgramData and your two AppData
              folders, on the drive they are really on.{" "}
              {rootsElsewhere.length === 1
                ? "One of those is not on the drive that was searched, so it was not looked in: "
                : `${fmt.count(rootsElsewhere.length)} of those are not on the drive that was searched, so they were not looked in: `}
              {rootsElsewhere.join(", ")}. Choose that drive above and search
              again to look there.
            </div>
          )}
          {orphans.length === 0 ? (
            <p className="empty">
              {/* "A good result" is only that for folders that were looked
                  in, so it is not said when some were not. */}
              {rootsElsewhere.length > 0
                ? "Nothing unaccounted for above 64 MB was found on the drive that was searched."
                : "Nothing unaccounted for above 64 MB. That is a good result."}
            </p>
          ) : (
            <ul className="orphans">
              {orphans.map((orphan) => (
                <OrphanRow
                  key={orphan.path}
                  orphan={orphan}
                  busy={inFlight.has(`orphan:${orphan.path}`)}
                  recyclable={canRecycle(orphan.path)}
                  onQuarantine={(item) => void quarantine(item)}
                  onDelete={(item) => void recycleOrphan(item)}
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
          {active.length > 0 && (
            <button
              className="ghost"
              disabled={anyBusy}
              onClick={() => setEmptying(true)}
            >
              Empty it
            </button>
          )}
        </div>
        <p className="muted">
          Everything here was moved rather than deleted, and goes back where it
          came from with one press for thirty days. After thirty days it is
          deleted for good, and each item says how long it has left. Deleting
          sooner is the other direction and there is no undo for it, so both
          ways of doing that ask first.
        </p>

        {emptying && (
          <div className="confirm">
            <p>
              Delete all {fmt.count(active.length)} held{" "}
              {active.length === 1 ? "item" : "items"}, freeing{" "}
              {fmt.bytes(active.reduce((total, item) => total + item.bytes, 0))}?
              This cannot be undone.
              {held.length > active.length && (
                <>
                  {" "}
                  {/*
                    The request empties the whole store, restored entries
                    included. Those hold no files so the figure above is right,
                    but the count was not -- the dialog quoted the held items
                    and the result reported a larger number, which reads as the
                    software having done more than it asked to.
                  */}
                  It also clears the record of{" "}
                  {fmt.count(held.length - active.length)} already put back,
                  which frees nothing further.
                </>
              )}
            </p>
            <div className="confirm-actions">
              <button onClick={() => void emptyAll()} disabled={anyBusy}>
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
                <span
                  className="held-left"
                  title="Quarantine keeps an item for thirty days, then deletes it for good"
                >
                  {timeLeft(item.quarantined_at)}
                </span>
                {confirming === item.id ? (
                  <>
                    <span className="held-warn">Delete for good?</span>
                    <button
                      disabled={anyBusy}
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
                    <button
                      disabled={anyBusy}
                      onClick={() => void restore(item.id)}
                    >
                      Restore
                    </button>
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

      <section className="panel" ref={duplicatesPanel}>
        <div className="panel-head">
          <h2>Identical copies</h2>
          <button onClick={() => void findDuplicates()} disabled={findingDuplicates}>
            {findingDuplicates ? "Comparing…" : "Find duplicates"}
          </button>
        </div>
        <p className="muted">
          Compared by size, then by their first 64 KB, then in full, so
          "duplicate" means every byte, not a guess. Each set is then judged by
          where its copies live, because identical is not the same as spare:
          Windows keeps several copies of the same library on purpose, every
          installer keeps a second copy of itself so it can repair later, and
          two programs that ship the same runtime each look for it beside
          themselves. Only copies in folders of yours are suggested for
          removal. If you pick which copy to keep, the others can be removed
          wherever they are, except Windows' own files, another account's
          profile and this program's own store.
        </p>

        {findingDuplicates && duplicatesJob.view?.progress && (
          <ProgressBar
            progress={duplicatesJob.view.progress}
            onStop={duplicatesJob.view.stoppable ? duplicatesJob.stop : undefined}
          />
        )}

        {unreadableKept.duplicates && duplicates === null && !findingDuplicates && (
          <UnreadableNote
            what="The last search for identical files"
            why={unreadableKept.duplicates}
            again="Search again to find them."
          />
        )}
        {notKept.duplicates && <NotKeptNote why={notKept.duplicates} />}
        {duplicatesKept && (
          <KeptNote
            what={`the search of ${duplicatesDrive} for identical files`}
            at={duplicatesAt}
            again="A copy may have changed or gone since then, so search again before removing anything from this list."
          />
        )}

        {duplicateSummary && duplicatesStanding && (
          <div className="stat-row tight">
            <div className="stat">
              <span className="stat-label">Sets</span>
              <span className="stat-value">{fmt.count(duplicatesStanding.groups)}</span>
            </div>
            <div className="stat">
              <span className="stat-label">Duplicated</span>
              <span className="stat-value">
                {fmt.bytes(duplicatesStanding.wasted_bytes)}
              </span>
            </div>
            <div className="stat">
              <span className="stat-label">You can reclaim</span>
              <span className="stat-value strong">
                {fmt.bytes(duplicatesStanding.reclaimable_bytes)}
              </span>
            </div>
            <div className="stat">
              <span className="stat-label">Worth a look</span>
              <span className="stat-value">
                {fmt.count(duplicatesStanding.actionable)}{" "}
                {duplicatesStanding.actionable === 1 ? "set" : "sets"}
              </span>
            </div>
            <div className="stat">
              <span className="stat-label">Took</span>
              <span className="stat-value">
                {fmt.duration(duplicateSummary.elapsed_ms)}
              </span>
            </div>
            <MeasuredAt at={duplicatesAt} />
          </div>
        )}

        {/*
          The search has a ceiling on how many bytes it will read in full, and
          when it hits that ceiling it skips whole candidate sets without
          hashing them. The agent has always reported that as `truncated`, the
          type has always carried it, and nothing has ever drawn it -- so a run
          that gave up part-way presented itself as a complete answer, and the
          empty case below said "No identical files over 8 MB" about a disk it
          had not finished looking at.

          Same mistake as an unreadable source reporting as an empty one, which
          is the thing this whole product is built not to do, sitting in the
          interface rather than in the reader.
        */}
        {duplicateSummary?.truncated && (
          <p className="held-warn">
            This stopped before it had finished. There is a ceiling on how much
            it will read in full, and it was reached, so some sets of possible
            copies were never compared, and anything in them is not below.
            Narrowing the search to one drive reads less and gets further.
          </p>
        )}

        {/*
          An answer has a size limit, and a drive with thousands of sets goes
          over it. The search used to finish and then show a pipe error. The
          service now sends as many of the largest as fit and counts the
          rest, and a list that is not all of what was found says so.
        */}
        {duplicates && unlisted.groups > 0 && (
          <p className="held-warn">
            The search found more sets than one answer can carry, so the list
            below holds the ones with the most to reclaim.{" "}
            {fmt.count(unlisted.groups)} more{" "}
            {unlisted.groups === 1 ? "set is" : "sets are"} not listed:{" "}
            {unlisted.groups === 1 ? "it holds" : "they hold"}{" "}
            {fmt.bytes(unlisted.wasted_bytes)} of duplicates,{" "}
            {fmt.bytes(unlisted.reclaimable_bytes)} of it reclaimable, and{" "}
            {unlisted.groups === 1 ? "is" : "are"} counted in the figures
            above. Search again once some of the listed ones have gone and the
            next take their place.
          </p>
        )}

        {duplicates && duplicates.length === 0 && unlisted.groups === 0 && (
          <p className="empty">
            {duplicateSummary?.truncated
              ? "No identical files were confirmed in the part that was compared."
              : "No identical files over 8 MB."}
          </p>
        )}

        {duplicates && duplicates.length > 0 && (
          <>
            {duplicateSummary?.quarantine_only_on && (
              <p className="footnote">
                {/* Said once, here, instead of a button on every copy that
                    could only fail. The store's own refusal is deliberate: it
                    moves by renaming, which works within one drive. */}
                Quarantine holds things on {duplicateSummary.quarantine_only_on}:
                only, so "Remove this one" is not offered for copies on this
                drive. The Recycle Bin works here, where Windows lets this
                account use it.
              </p>
            )}
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
                {/*
                  This said "N of M shown" while the list below drew at most
                  forty, so on a machine with more than forty actionable sets
                  the page stated a number it was not drawing. The cap is real
                  and worth keeping -- forty sets is already more than anybody
                  works through in a sitting -- so the cap is what gets said.
                */}
                {fmt.count(Math.min(shownDuplicates.length, DUPE_LIMIT))} of{" "}
                {fmt.count(duplicates.length + unlisted.groups)} shown
              </span>
            </div>

            {shownDuplicates.length === 0 ? (
              <p className="empty">
                Every set found is one Windows or a program keeps deliberately.
                That is a good answer, not an empty one.
              </p>
            ) : (
              <ul className="dupes">
                {shownDuplicates.slice(0, DUPE_LIMIT).map((group) => (
                  <li key={group.id} className={`dupe dupe-${group.verdict}`}>
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
                      // says otherwise, and then theirs. Both are paths, and
                      // each counts only while that copy is still in the set.
                      const setKey = group.id;
                      const present = (path: string | null | undefined) =>
                        path && group.copies.some((copy) => copy.path === path)
                          ? path
                          : undefined;
                      const picked = present(keeping[setKey]);
                      const keeper = picked ?? present(group.suggestedPath);
                      // Whether the *person* picked the survivor, which is the
                      // only thing that may widen the agent's fence.
                      const theyChose = picked !== undefined;
                      // Windows keeps its own files whatever anybody picks, so
                      // a set made only of those offers no choice at all.
                      const choosable = group.copies.filter(
                        (copy) => copy.owner !== "windows" && copy.owner !== "servicing",
                      );
                      const canChoose = choosable.length > 1;
                      // Quarantine only holds things from its own drive. On
                      // any other, its button could only produce a refusal.
                      const canHold = !duplicateSummary?.quarantine_only_on;

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
                                            disabled={anyBusy}
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
                                              {/* Offered only where the agent
                                                  will take it. Without the
                                                  person's own pick of keeper
                                                  the request goes as our
                                                  suggestion, which only reaches
                                                  a copy in a folder of theirs,
                                                  so the button was shown on
                                                  copies it could only fail on. */}
                                              {canHold && (theyChose || copy.removable) && (
                                                <button
                                                  className="dupe-take"
                                                  disabled={anyBusy}
                                                  title={
                                                    ours
                                                      ? "Moved to quarantine, and restorable for 30 days."
                                                      : "This is not a copy we would have offered. It goes to quarantine and comes back with one press for 30 days."
                                                  }
                                                  onClick={(event) => {
                                                    event.stopPropagation();
                                                    void holdCopy(copy.path, keeper, group.bytes, !ours);
                                                  }}
                                                >
                                                  Remove this one
                                                </button>
                                              )}
                                              {/* Same reasoning as the
                                                  leftovers above: a copy under
                                                  Program Files cannot go to
                                                  this account's bin, and
                                                  offering it there only teaches
                                                  that the button is
                                                  unreliable. */}
                                              {canRecycle(copy.path) && (
                                                <button
                                                  className="ghost"
                                                  disabled={anyBusy}
                                                  title="Send this copy to the Recycle Bin, where Windows can put it back"
                                                  onClick={(event) => {
                                                    event.stopPropagation();
                                                    void recycleCopy(copy.path, keeper, group.bytes);
                                                  }}
                                                >
                                                  Recycle Bin
                                                </button>
                                              )}
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

        {unreadableKept.caches && caches === null && !measuringCaches && (
          <UnreadableNote
            what="The last measurement of caches"
            why={unreadableKept.caches}
            again="Press Measure to measure them again."
          />
        )}
        {notKept.caches && <NotKeptNote why={notKept.caches} />}
        {cachesKept && (
          <KeptNote
            what="the measurement of caches and scratch space"
            at={cachesAt}
            again="Press Measure to measure them again."
          />
        )}

        {clearable && clearable.length === 0 && (
          <p className="empty">Nothing worth clearing. Genuinely.</p>
        )}

        {clearable && clearable.length > 0 && (
          <>
            <div className="stat-row tight">
              <div className="stat">
                <span className="stat-label">Places</span>
                <span className="stat-value">{fmt.count(clearable.length)}</span>
              </div>
              <div className="stat">
                <span className="stat-label">Holding</span>
                <span className="stat-value strong">
                  {fmt.bytes(clearable.reduce((total, cache) => total + cache.bytes, 0))}
                </span>
              </div>
              <div className="stat">
                <span className="stat-label">Costs you nothing</span>
                <span className="stat-value">
                  {fmt.bytes(
                    clearable
                      .filter((cache) => cache.safety === "routine")
                      .reduce((total, cache) => total + cache.bytes, 0),
                  )}
                </span>
              </div>
              <MeasuredAt at={cachesAt} />
            </div>

            <ul className="caches">
              {clearable.map((cache) => (
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
                                {fmt.count(location.files)}{" "}
                                {location.files === 1 ? "file" : "files"}
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
                      {fmt.count(cleared[cache.id].files_removed)}{" "}
                      {cleared[cache.id].files_removed === 1 ? "file" : "files"}.
                      {cleared[cache.id].files_in_use > 0 &&
                        (cleared[cache.id].files_in_use === 1
                          ? " 1 was open in another program and was left alone."
                          : ` ${fmt.count(cleared[cache.id].files_in_use)} were open in another program and were left alone.`)}
                      {cleared[cache.id].refused.length > 0 &&
                        (cleared[cache.id].refused.length === 1
                          ? " 1 place was left alone:"
                          : ` ${fmt.count(cleared[cache.id].refused.length)} places were left alone:`)}
                    </p>
                  )}
                  {/* The service's own reasons, which were only counted. A
                      folder left alone because it turned out to lead
                      somewhere else is something to be told, not a number. */}
                  {cleared[cache.id] && cleared[cache.id].refused.length > 0 && (
                    <ul className="orphan-reasons">
                      {cleared[cache.id].refused.map((why) => (
                        <li key={why}>{why}</li>
                      ))}
                    </ul>
                  )}
                </li>
              ))}
            </ul>
          </>
        )}

        {/*
          Not caches. The largest things on a drive that a person might take
          for one, each with what it is for and what decides its size, and no
          button: the service refuses to clear any of them. Listed apart, and
          kept out of the map and the totals above, so that nothing here reads
          as space this page offers to reclaim.
        */}
        {explained.length > 0 && (
          <>
            <p className="modal-label">Large, and not a cache</p>
            <p className="muted">
              {fmt.bytes(explained.reduce((total, item) => total + item.bytes, 0))}{" "}
              that looks as though it could go and is not cleared from here.
              It is measured so that the space is accounted for, and each says
              what it is for and what decides how large it is.
            </p>
            <ul className="caches">
              {explained.map((item) => (
                <li key={item.id} className="cache">
                  <div className="cache-head">
                    <button
                      className="cache-toggle"
                      onClick={() => setOpenCache(openCache === item.id ? null : item.id)}
                    >
                      <span className="app-caret">
                        {openCache === item.id ? "▾" : "▸"}
                      </span>
                      <span className="cache-name">{item.name}</span>
                      <span className="conf conf-medium">Explained, not cleared</span>
                    </button>
                    <span className="cache-size">{fmt.bytes(item.bytes)}</span>
                  </div>

                  {openCache === item.id && (
                    <div className="cache-detail">
                      <p>{item.what}</p>
                      <p className="cache-cost">
                        <strong>What controls it:</strong> {item.managed_by}
                      </p>
                      <ul className="files">
                        {item.locations.map((location) => (
                          <FileRow
                            key={location.path}
                            path={location.path}
                            bytes={location.bytes}
                            onReveal={(target) => void reveal(target)}
                            note={
                              <span>
                                {fmt.count(location.files)}{" "}
                                {location.files === 1 ? "file" : "files"}
                                {location.partial && " (measured to a ceiling)"}
                              </span>
                            }
                          />
                        ))}
                      </ul>
                    </div>
                  )}
                </li>
              ))}
            </ul>
          </>
        )}
      </section>

      <section className="panel">
        <div className="panel-head">
          <h2>Loose files with a home</h2>
          <button onClick={() => void findProposals()} disabled={organising}>
            {organising ? "Looking…" : "Find loose files"}
          </button>
        </div>
        <p className="muted">
          A destination has to be a folder you already keep that kind of file
          in: this never invents one. Executables are excluded on purpose: a
          downloaded installer may be pointed at by a shortcut or a scheduled
          task, and none of that is visible from here.
        </p>

        {organiseSummary && (
          <p className="muted">
            {fmt.count(organiseSummary.proposals)} of{" "}
            {fmt.count(organiseSummary.examined)} loose files{" "}
            {organiseSummary.proposals === 1 ? "has" : "have"} an obvious home.
            Found by the search at {whenMeasured(looseAt)}.
          </p>
        )}

        {looseLeft && looseLeft.length === 0 && (
          <p className="empty">Nothing loose that matches a folder you already use.</p>
        )}

        {looseLeft && looseLeft.length > 0 && (
          <ul className="proposals">
            {looseLeft.map((proposal) => (
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
                {/* Guarded like every other acting control here. Without
                    it a double-click fired two moves, and the second came back
                    as a refusal from the agent's fence -- which reads as the
                    move having failed. */}
                <button
                  disabled={anyBusy}
                  onClick={() => void applyMove(proposal)}
                >
                  Move
                </button>
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
                    <button
                      disabled={anyBusy}
                      onClick={() => void undoMove(move.id)}
                    >
                      Put back
                    </button>
                  </li>
                ))}
            </ul>
          </>
        )}
      </section>

      {downloads && (
        <section className="panel">
          <div className="panel-head">
            <h2>Downloads you may have forgotten</h2>
            {downloadSummary && (
              <span className="muted">
                {fmt.count(downloadSummary.found)}{" "}
                {downloadSummary.found === 1 ? "file" : "files"} ·{" "}
                {fmt.bytes(downloadSummary.total_bytes)}
              </span>
            )}
          </div>
          <p className="muted">
            Files over 32 MB carrying Windows' own record of having come from
            the internet. Click one to show it in Explorer.
            {downloadSummary && <> {ACCESS_TIMES[downloadSummary.access_times]}</>}
            {downloadSummary &&
              downloadSummary.access_times === "recorded" &&
              downloadSummary.read_as_opened > 0 && (
                <>
                  {" "}
                  {fmt.count(downloadSummary.read_as_opened)} of these could
                  only be read in a way Windows counts as opening{" "}
                  {downloadSummary.read_as_opened === 1 ? "it" : "them"}, so{" "}
                  {downloadSummary.read_as_opened === 1 ? "its" : "their"}{" "}
                  last-opened date now shows this search.
                </>
              )}
          </p>
          {downloads.length > 0 && (
            // The list could only ever be read largest first, twenty-five
            // rows of it. When a file arrived is the other thing a person
            // sorts their downloads by, and the rest of the list was already
            // here, unseen.
            <div className="dupe-filter">
              <label>
                Order
                <select
                  value={downloadOrder}
                  onChange={(event) =>
                    setDownloadOrder(event.target.value as DownloadOrder)
                  }
                >
                  {(Object.keys(DOWNLOAD_ORDER) as DownloadOrder[]).map((order) => (
                    <option key={order} value={order}>
                      {DOWNLOAD_ORDER[order]}
                    </option>
                  ))}
                </select>
              </label>
              {downloads.length > DOWNLOAD_LIMIT && (
                <button
                  className="link-button"
                  onClick={() => setAllDownloads(!allDownloads)}
                >
                  {allDownloads
                    ? `Show ${fmt.count(DOWNLOAD_LIMIT)}`
                    : `Show all ${fmt.count(downloads.length)}`}
                </button>
              )}
            </div>
          )}
          {downloads.length > 0 && (
            <p className="footnote">
              {/* Said rather than silently cut. A list that stops without
                  saying so is a list claiming to be complete. */}
              {shownDownloads.length < downloads.length
                ? DOWNLOADS_SHOWN[downloadOrder](
                    fmt.count(shownDownloads.length),
                    fmt.count(downloads.length),
                  )
                : `Showing all ${fmt.count(downloads.length)}.`}
              {/* What was found can be more than was sent. Those are the
                  smallest, they are not in any order made here, and an order
                  by arrival is of the ones that were sent. */}
              {unlistedDownloads > 0 &&
                (unlistedDownloads === 1
                  ? " 1 more was found and is not in this list, because one answer could not carry it: the smallest, whenever it arrived."
                  : ` ${fmt.count(unlistedDownloads)} more were found and are not in this list, because one answer could not carry them: the smallest, whenever they arrived.`)}
            </p>
          )}
          {downloads.length === 0 ? (
            <p className="empty">
              Nothing over 32 MB carries a download record.
            </p>
          ) : (
            <ul className="files">
              {shownDownloads.map((download) => (
                <FileRow
                  key={download.path}
                  path={download.path}
                  bytes={download.bytes}
                  onReveal={(path) => void reveal(path)}
                  note={
                    <>
                      {fmt.host(download.host_url) ?? "source not recorded"}
                      {download.days_since_arrival !== null ? (
                        <>
                          {" "}
                          · arrived {download.days_since_arrival}{" "}
                          {download.days_since_arrival === 1 ? "day" : "days"} ago
                        </>
                      ) : (
                        // Said now that the list can be put in order of
                        // arrival: this is why such a row sits at the end.
                        <> · when it arrived was not recorded</>
                      )}
                      {/* Only where Windows keeps the date. Elsewhere it is a
                          number nothing maintains, and the paragraph above
                          says so instead. */}
                      {downloadSummary?.access_times === "recorded" && (
                        <>
                          {" "}
                          ·{" "}
                          {download.days_since_access === null
                            ? "no record of when it was last opened"
                            : `last opened ${daysAgo(download.days_since_access)}`}
                        </>
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

      {/*
        Sizes and dates, from the same read as the list above, and wider: any
        large file in the reader's own folders, however it got there. Every
        word here is about what Windows recorded. None of it says a file is
        unused or spare, because a date cannot know that, and this list is
        what somebody will have open while deciding what to remove.
      */}
      {oldFiles && oldSummary && (
        <section className="panel">
          <div className="panel-head">
            <h2>
              {opensRecorded
                ? `Large files last opened more than ${oldAge} ago`
                : `Large files last written more than ${oldAge} ago`}
            </h2>
            <span className="muted">
              {fmt.count(oldStanding.files)}{" "}
              {oldStanding.files === 1 ? "file" : "files"} ·{" "}
              {fmt.bytes(oldStanding.bytes)}
            </span>
          </div>
          <p className="muted">
            {opensRecorded ? (
              <>
                Files of {fmt.bytes(oldSummary.min_bytes)} or more in your own
                folders whose three dates are each more than {oldAge} old: when
                this copy arrived on the drive, when its contents last changed,
                and when anything last opened it. Any program that reads a file
                counts as opening it, antivirus and backup included, so an old
                last-opened date means nothing has read the file since.
              </>
            ) : (
              <>
                Files of {fmt.bytes(oldSummary.min_bytes)} or more in your own
                folders that arrived on the drive more than {oldAge} ago and
                whose contents last changed more than {oldAge} ago.{" "}
                {oldSummary.access_times === "not_recorded"
                  ? "Windows is not recording when files are opened on this PC, so the last-opened date was not used to make this list and its column has nothing to show."
                  : "Whether Windows records when files are opened on this PC could not be read, so the last-opened date was not used to make this list and is not shown."}
              </>
            )}{" "}
            These are sizes and dates and nothing more: a date says when
            something last happened to a file, not whether it is still needed.
            Found by the search at {whenMeasured(foundAt)}.
          </p>
          <p className="muted">
            Your own folders are Desktop, Documents, Downloads, Music, Pictures,
            Videos and Saved Games in your profile, and a OneDrive, Dropbox or
            Google Drive folder there. Everything else on the drive is left
            out: Windows' own files, program folders and program data, the
            Recycle Bin, other accounts' profiles, and anywhere else this
            cannot tell is yours.{" "}
            {oldSummary.left_out.length === 0
              ? "Nothing there met the same size and dates."
              : "Left out there, though as large and with dates as old: " +
                oldSummary.left_out
                  .map(
                    (group) =>
                      `${fmt.count(group.files)} ${group.files === 1 ? "file" : "files"} ` +
                      `(${fmt.bytes(group.bytes)}) ${LEFT_OUT_WHERE[group.owner]}`,
                  )
                  .join("; ") +
                "."}
          </p>
          {oldSummary.undated > 0 && (
            <p className="muted">
              {oldSummary.undated === 1
                ? `1 file of this size in your own folders (${fmt.bytes(oldSummary.undated_bytes)}) has a date Windows did not record. It cannot be said to have every date more than ${oldAge} old, so it is not listed.`
                : `${fmt.count(oldSummary.undated)} files of this size in your own folders (${fmt.bytes(oldSummary.undated_bytes)} together) have a date Windows did not record. They cannot be said to have every date more than ${oldAge} old, so they are not listed.`}
            </p>
          )}
          {oldSummary.unplaced > 0 && (
            <p className="muted">
              {oldSummary.unplaced === 1
                ? "1 file of this size on the drive sits too many folders deep for its path to be worked out, so it could not be placed and is not listed."
                : `${fmt.count(oldSummary.unplaced)} files of this size on the drive sit too many folders deep for their paths to be worked out, so they could not be placed and are not listed.`}
            </p>
          )}

          {oldNotice && (
            <div
              className={`notice ${oldNotice.caution ? "notice-warn" : "notice-ok"}`}
              style={{ overflowWrap: "anywhere", marginTop: 12 }}
              role="status"
            >
              {oldNotice.text}
            </div>
          )}

          {oldFiles.length === 0 && oldRest.files === 0 ? (
            <p className="empty">
              No file of {fmt.bytes(oldSummary.min_bytes)} or more in your own
              folders has every date more than {oldAge} old.
            </p>
          ) : (
            <>
              {oldRest.files > 0 && (
                <p className="footnote">
                  {/* The largest were sent, and the rest are counted, so a
                      list that is not everything says what it is short of. */}
                  {oldFiles.length > 0
                    ? `This list holds the ${fmt.count(oldFiles.length)} largest, in the order you choose.`
                    : "Everything that was listed has gone from the list."}{" "}
                  {fmt.count(oldRest.files)} more{" "}
                  {oldRest.files === 1 ? "was" : "were"} found and{" "}
                  {oldRest.files === 1 ? "holds" : "hold"} {fmt.bytes(oldRest.bytes)}
                  {oldRest.files === 1 ? "" : " together"}. Find leftovers again to list{" "}
                  {oldFiles.length > 0 ? "the next largest as these go." : "them."}
                </p>
              )}
              <div className="datefiles-head">
                <span>File</span>
                {(
                  [
                    ["created", "Arrived here"],
                    ["modified", "Last written"],
                    ["accessed", "Last opened"],
                    ["bytes", "Size"],
                  ] as [OldColumn, string][]
                ).map(([column, label]) => {
                  // Nothing to sort by where the date was not used.
                  const sortable = column !== "accessed" || opensRecorded;
                  const active = oldSort.by === column;
                  return (
                    <button
                      key={column}
                      className={active ? "sorted" : ""}
                      disabled={!sortable}
                      aria-pressed={active}
                      title={
                        !sortable
                          ? "No last-opened dates are shown, so there is nothing to sort by"
                          : active
                            ? `Sorted by ${label.toLowerCase()}, ${
                                column === "bytes"
                                  ? oldSort.ascending
                                    ? "smallest first"
                                    : "largest first"
                                  : oldSort.ascending
                                    ? "oldest first"
                                    : "newest first"
                              }. Press to turn the order round.`
                            : `Sort by ${label.toLowerCase()}`
                      }
                      onClick={() => sortOldBy(column)}
                    >
                      {label}
                      {active ? (oldSort.ascending ? " ▲" : " ▼") : ""}
                    </button>
                  );
                })}
                <span />
              </div>
              <ul className="datefiles">
                {shownOldFiles.map((file) => {
                  const { folder } = fmt.splitPath(file.path);
                  const busy = inFlight.has(`old:${file.path}`);
                  return (
                    <li key={file.path} className="datefiles-row">
                      <button
                        className="filerow-main"
                        title={`Show ${file.path} in Explorer`}
                        onClick={() => void reveal(file.path)}
                      >
                        <span className="filerow-name">{file.name}</span>
                        {folder && <span className="filerow-folder">{folder}</span>}
                      </button>
                      <span className="datefiles-date">{recordedDate(file.created)}</span>
                      <span className="datefiles-date">{recordedDate(file.modified)}</span>
                      <span className="datefiles-date">
                        {opensRecorded
                          ? recordedDate(file.accessed)
                          : oldSummary.access_times === "not_recorded"
                            ? "not recorded"
                            : "not shown"}
                      </span>
                      <span className="datefiles-size">{fmt.bytes(file.bytes)}</span>
                      {canRecycle(file.path) ? (
                        <button
                          className="ghost"
                          disabled={busy}
                          title="Send it to your Recycle Bin, where Windows can put it back. If the bin cannot take it, it is left where it is."
                          onClick={() => void recycleOldFile(file)}
                        >
                          {busy ? "Sending…" : "Recycle Bin"}
                        </button>
                      ) : (
                        <span
                          className="orphan-note"
                          title="Windows will not let this account delete this file, so the Recycle Bin is not offered for it."
                        >
                          Not yours to remove
                        </span>
                      )}
                    </li>
                  );
                })}
              </ul>
            </>
          )}
        </section>
      )}

      {/*
        Reference rather than news. It was the first thing on the page and the
        drive picker was below it, so the control somebody came to press was off
        the first screen. Folded shut: nothing is lost, and it stops charging
        sixty lines of reading for a second visit.
      */}
      <section className="panel">
        <div className="panel-head">
          <h2>What this page does</h2>
          <button className="ghost" onClick={() => setExplaining(!explaining)}>
            {explaining ? "Hide" : "Read it"}
          </button>
        </div>
        {explaining && (
        <ol className="explain">
          <li>
            <strong>Leftovers</strong> are folders under <code>ProgramData</code>{" "}
            and the two <code>AppData</code> roots that no installed application
            accounts for, usually left behind when something was uninstalled
            years ago. Each says why it is listed.
          </li>
          <li>
            <strong>Downloads</strong> are large files Windows recorded as having
            come from the internet, with the site they came from and when they
            arrived. Nothing here is a suggestion to delete; it is a list of
            things you may have forgotten you kept.
          </li>
          <li>
            <strong>Large files by date</strong> are files of 100 MB or more
            in your own folders with no date from the last year: not when the
            copy arrived, not when it was last written, and, where Windows
            records it, not when it was last opened. It is a list of sizes and
            dates. A date says when something last happened to a file, not
            whether you still need it. The Recycle Bin button there leaves a
            file where it is if the bin cannot take it.
          </li>
          <li>
            <strong>Duplicates</strong> are files that are byte-for-byte
            identical. Finding them reads file contents rather than the
            filesystem's index, so it has its own button. Each set is then
            judged by where its copies live: Windows and installers keep
            duplicates deliberately, so only a copy in a folder of yours is
            suggested for removal. Once you pick which copy to keep, the
            others can be removed too, unless they are Windows' own, in
            another account's profile, or in this program's own store.
          </li>
          <li>
            <strong>Caches</strong> are places Windows and a few programs write
            data they can regenerate. Clearing one empties its contents and
            leaves the folder, and each says what it costs you: usually
            nothing, sometimes a slower first launch.
          </li>
          <li>
            <strong>Loose files</strong> are downloads sitting in{" "}
            <code>Downloads</code> or on the Desktop that match a folder you
            already keep that kind of file in. Only documents, images, audio,
            video and archives, never anything that runs.
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
            service's, so it appears where you expect, and this program records
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
        )}
        {explaining && (
        <p className="muted">
          Only those three folders are examined, one level deep, and never a
          directory Windows owns. These are suggestions from names and dates,
          not certainties: an application still using a folder will misbehave
          until you restore it.
        </p>
        )}
      </section>
    </>
  );
}
