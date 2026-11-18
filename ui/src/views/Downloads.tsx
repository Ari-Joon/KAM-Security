import { useCallback, useEffect, useRef, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { api, reason } from "../lib/api";
import * as fmt from "../lib/format";
import { runJob, stopJob, type Progress } from "../lib/jobs";
import ProgressBar from "../components/ProgressBar";
import PathLink from "../components/PathLink";
import type {
  DissectionView,
  DownloadsPage,
  Extraction,
  FileScan,
  LooseFile,
  Member,
  PageRecord,
  Signature,
  ThreatNote,
} from "../lib/types";

/**
 * Active downloads: every file that lands in Downloads, checked by Defender
 * as it arrives.
 *
 * Three rules shape every sentence here. Defender decides what is flagged and
 * the page reports its answer by name, never a score. A check that did not
 * finish, or a file that could not be read, is said out loud and
 * never shown as clean. And nothing is moved or deleted unless somebody presses a button:
 * quarantine is the reversible choice, and extraction writes only what
 * Defender found nothing in.
 */

type Running = {
  what: "check" | "dissect";
  path: string;
  job: string | null;
  progress: Progress | null;
};

type Row =
  | { kind: "record"; at: string; record: PageRecord }
  | { kind: "loose"; at: string; file: LooseFile };

function signatureLabel(signature: Signature | null): string | null {
  if (!signature) return null;
  switch (signature.state) {
    case "valid":
      return `signed by ${signature.signer}`;
    case "invalid":
      return signature.signer
        ? `signed by ${signature.signer}, and Windows does not accept the signature`
        : "carries a signature Windows does not accept";
    case "unsigned":
      return "not signed";
    case "unknown":
      return "who signed it could not be checked";
  }
}

/** Who signed it, as a sentence of its own. */
function signerSentence(signature: Signature | null): string {
  if (!signature) return "";
  switch (signature.state) {
    case "valid":
      return `It is signed by ${signature.signer}.`;
    case "invalid":
      return signature.signer
        ? `It carries a signature in the name of ${signature.signer}, which Windows does not accept.`
        : "It carries a signature Windows does not accept.";
    case "unsigned":
      return "It is not signed.";
    case "unknown":
      return "Who signed it could not be checked.";
  }
}

function originLabel(record: PageRecord): string {
  const host = fmt.host(record.origin?.host_url ?? null);
  if (host) return `from ${host}`;
  if (record.origin) return "came from outside this machine, with no address recorded";
  return "no download address recorded";
}

/** The same, as a clause: "came from github.com". */
function originClause(record: PageRecord): string {
  const host = fmt.host(record.origin?.host_url ?? null);
  if (host) return `came from ${host}`;
  if (record.origin) return "came from outside this machine, with no address recorded";
  return "has no download address recorded";
}

/** Defender's name, with the category it gives in front set apart. */
function ThreatName({ name }: { name: string }) {
  const cut = name.indexOf(":");
  if (cut <= 0) return <strong className="dl-threat">{name}</strong>;
  return (
    <strong className="dl-threat">
      <span className="dl-threat-cat">{name.slice(0, cut + 1)}</span>
      {name.slice(cut + 1)}
    </strong>
  );
}

/** What each name Defender gave means, in the scanner's words. */
function Notes({ notes }: { notes: ThreatNote[] }) {
  if (notes.length === 0) return null;
  return (
    <ul className="dl-notes">
      {notes.map((note) => (
        <li key={note.name}>
          <ThreatName name={note.name} />
          <span className="dl-note-text"> {note.meaning}</span>
        </li>
      ))}
    </ul>
  );
}

/** Defender's answer, as a short line and the caveat when there is one. */
function Answer({ scan }: { scan: FileScan }) {
  if (scan.answer === "nothing_found") {
    return (
      <div className="dl-answer ok">
        Defender found nothing
        {scan.caveat && <p className="small held-warn wrap">{scan.caveat}</p>}
      </div>
    );
  }
  if (scan.answer === "flagged") {
    const names = Array.from(new Set(scan.threats.map((threat) => threat.name)));
    return (
      <div className="dl-answer warn">
        Defender flagged{" "}
        {names.length === 0
          ? "something it did not name"
          : names.map((name, index) => (
              <span key={name}>
                {index > 0 && ", "}
                <ThreatName name={name} />
              </span>
            ))}
        {scan.caveat && <p className="small muted">{scan.caveat}</p>}
      </div>
    );
  }
  return (
    <div className="dl-answer warn">
      Defender could not finish checking it, so this is not a clean result
      {scan.caveat && <p className="small muted">{scan.caveat}</p>}
    </div>
  );
}

export default function Downloads({ launches }: { launches: number }) {
  const [page, setPage] = useState<DownloadsPage | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState<Running | null>(null);
  const [said, setSaid] = useState<Record<string, string>>({});
  const [view, setView] = useState<DissectionView | null>(null);
  const [extraction, setExtraction] = useState<Extraction | null>(null);
  const [extracting, setExtracting] = useState(false);
  const [focus, setFocus] = useState<string | null>(null);
  const [menuError, setMenuError] = useState<string | null>(null);
  /** The open dissection, so leaving the page deletes its private copy. */
  const openToken = useRef<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setPage(await api.downloadsPage());
      setError(null);
    } catch (cause) {
      setError(reason(cause));
    } finally {
      setLoading(false);
    }
  }, []);

  const say = (path: string, text: string) =>
    setSaid((current) => ({ ...current, [path.toLowerCase()]: text }));

  const check = useCallback(
    async (path: string) => {
      setRunning({ what: "check", path, job: null, progress: null });
      try {
        const { result } = await runJob(
          (job) => {
            setRunning((current) => (current ? { ...current, job } : current));
            return api.checkDownload(path, job);
          },
          (progress) => setRunning((current) => (current ? { ...current, progress } : current)),
        );
        say(path, result ? "Checked just now." : "The check was stopped, so it says nothing either way.");
      } catch (cause) {
        say(path, `Not checked: ${reason(cause)}`);
      } finally {
        setRunning(null);
        void load();
      }
    },
    [load],
  );

  const closeDissection = useCallback(async () => {
    const token = openToken.current;
    openToken.current = null;
    setView(null);
    setExtraction(null);
    if (token) {
      try {
        await api.discardDissection(token);
      } catch {
        // The private copy is also cleared the next time the program starts.
      }
    }
  }, []);

  const dissect = useCallback(
    async (path: string) => {
      await closeDissection();
      setRunning({ what: "dissect", path, job: null, progress: null });
      try {
        const { result } = await runJob(
          (job) => {
            setRunning((current) => (current ? { ...current, job } : current));
            return api.dissectArchive(path, job);
          },
          (progress) => setRunning((current) => (current ? { ...current, progress } : current)),
        );
        if (result) {
          openToken.current = result.token;
          setView(result);
        } else {
          say(path, "Taking it apart was stopped, so nothing was changed.");
        }
      } catch (cause) {
        say(path, reason(cause));
      } finally {
        setRunning(null);
        void load();
      }
    },
    [closeDissection, load],
  );

  async function extract() {
    if (!view) return;
    setExtracting(true);
    try {
      const done = await api.extractClean(view.token);
      openToken.current = null;
      setExtraction(done);
    } catch (cause) {
      say(view.dissection.archive, reason(cause));
    } finally {
      setExtracting(false);
      void load();
    }
  }

  async function quarantine(path: string) {
    try {
      await api.quarantineDownload(path);
      say(path, "Quarantined. It can be put back from Cleanup for thirty days.");
    } catch (cause) {
      say(path, `Not quarantined: ${reason(cause)}`);
    } finally {
      void load();
    }
  }

  async function setMenu(enabled: boolean) {
    setMenuError(null);
    try {
      const menu = await api.setContextMenu(enabled);
      setPage((current) => (current ? { ...current, menu } : current));
    } catch (cause) {
      setMenuError(reason(cause));
    }
  }

  useEffect(() => {
    void load();
    const unlisten = listen("downloads://changed", () => void load());
    return () => {
      void unlisten.then((stop) => stop());
      const token = openToken.current;
      if (token) void api.discardDissection(token).catch(() => {});
    };
  }, [load]);

  // A file asked about from Explorer or a notification.
  useEffect(() => {
    api
      .takeLaunch()
      .then((launch) => {
        if (!launch) return;
        setFocus(launch.path.toLowerCase());
        if (launch.action === "check") void check(launch.path);
        if (launch.action === "extract") void dissect(launch.path);
      })
      .catch(() => {});
  }, [launches, check, dissect]);

  const busy = running !== null;
  const rows: Row[] = page
    ? [
        ...page.records.map(
          (record): Row => ({ kind: "record", at: record.arrived_at ?? record.checked_at, record }),
        ),
        ...page.unchecked.map((file): Row => ({ kind: "loose", at: file.arrived_at ?? "", file })),
      ].sort((a, b) => b.at.localeCompare(a.at))
    : [];
  const failures = new Map(
    (page?.failures ?? []).map((failure) => [failure.path.toLowerCase(), failure.message]),
  );

  return (
    <>
      <div className="view-head">
        <div>
          <h1>Active downloads</h1>
          <p className="lede">
            Every file that lands in your Downloads folder is checked by
            Microsoft Defender as it arrives. Defender decides what is flagged;
            this page shows its answer, where the file came from, and what was
            done about it. Nothing is moved or deleted unless you ask.
          </p>
        </div>
        <button onClick={() => void load()} disabled={loading}>
          {loading ? "Reading…" : "Refresh"}
        </button>
      </div>

      {error && (
        <div className="notice notice-down">
          <strong>This page could not be read.</strong>
          <pre className="error">{error}</pre>
        </div>
      )}

      {page && (
        <p className="small muted">
          {page.watch.state === "watching" && <>Watching {page.watch.folder} for new files.</>}
          {page.watch.state === "starting" && <>Starting to watch your Downloads folder.</>}
          {page.watch.state === "not_watching" && (
            <span className="held-warn wrap">
              Not watching for new files: {page.watch.reason}. Files can still be
              checked from here.
            </span>
          )}
        </p>
      )}

      {page?.protection === false && (
        <div className="notice notice-warn">
          Protection is switched off on the Overview, so new downloads are not
          checked as they arrive. They are listed here as not checked yet.
        </div>
      )}
      {page?.notifications && <div className="notice notice-warn">{page.notifications}</div>}
      {page?.folder_error && <div className="notice notice-down">{page.folder_error}</div>}
      {page?.history_error && (
        <div className="notice notice-down">
          The history of checked downloads could not be read, so files below
          may show as not checked yet when they were. ({page.history_error})
        </div>
      )}

      {running && (
        <section className="panel">
          <div className="panel-head">
            <h2>
              {running.what === "check" ? "Checking" : "Taking apart"}{" "}
              {fmt.splitPath(running.path).name}
            </h2>
          </div>
          {running.progress ? (
            <ProgressBar
              progress={running.progress}
              onStop={running.job ? () => void stopJob(running.job ?? "") : undefined}
            />
          ) : (
            <p className="muted">Starting…</p>
          )}
          <p className="small muted">
            Defender does not say how far through a file it is, so while it is
            looking this shows the stage rather than a bar it would have to invent.
          </p>
        </section>
      )}

      {view && (
        <DissectionPanel
          view={view}
          record={page?.records.find(
            (record) => record.path.toLowerCase() === view.dissection.archive.toLowerCase(),
          )}
          extraction={extraction}
          extracting={extracting}
          onExtract={() => void extract()}
          onClose={() => void closeDissection()}
        />
      )}

      <section className="panel">
        <div className="panel-head">
          <h2>Downloads</h2>
          {page && (
            <span className="panel-count">
              {fmt.count(page.records.length)} checked, {fmt.count(page.unchecked.length)} not
              checked yet
            </span>
          )}
        </div>
        {page && rows.length === 0 && (
          <p className="empty">Nothing has arrived in Downloads since this was set up.</p>
        )}
        {page && page.on_record > page.records.length && (
          <p className="small muted">
            Showing {fmt.count(page.records.length)} of the {fmt.count(page.on_record)} checks
            on record: the most recent, and the newest for each file in the folder now. The
            older ones are still on record.
          </p>
        )}
        <ul className="dl-list">
          {rows.map((row) =>
            row.kind === "record" ? (
              <RecordRow
                key={`r-${row.record.path}-${row.record.sha256}`}
                record={row.record}
                said={said[row.record.path.toLowerCase()]}
                focused={focus === row.record.path.toLowerCase()}
                busy={busy}
                onCheck={() => void check(row.record.path)}
                onDissect={() => void dissect(row.record.path)}
                onQuarantine={() => void quarantine(row.record.path)}
              />
            ) : (
              <LooseRow
                key={`l-${row.file.path}`}
                file={row.file}
                failure={failures.get(row.file.path.toLowerCase())}
                said={said[row.file.path.toLowerCase()]}
                focused={focus === row.file.path.toLowerCase()}
                busy={busy}
                onCheck={() => void check(row.file.path)}
                onDissect={() => void dissect(row.file.path)}
              />
            ),
          )}
        </ul>
      </section>

      {page && (
        <section className="panel">
          <div className="panel-head">
            <h2>From Explorer</h2>
          </div>
          <label className="small">
            <input
              type="checkbox"
              checked={page.menu.enabled}
              onChange={(event) => void setMenu(event.target.checked)}
            />{" "}
            Show "Check with KAM Security" on every file, and "Extract with KAM
            Security" on zip files, when you right-click them
          </label>
          <p className="small muted">
            Turned on the first time KAM Security ran. On Windows 11 they are
            under "Show more options". They belong to your account only, and
            unticking this removes them.
          </p>
          {page.menu.points_elsewhere && (
            <p className="small held-warn wrap">
              An entry of this name starts a different copy of KAM Security,
              probably an older one. Ticking the box points it here.
            </p>
          )}
          {menuError && <p className="small held-warn wrap">{menuError}</p>}
          <p className="small muted">
            To deliver its notices, Windows needs KAM Security in your Start
            menu, so it keeps a shortcut there. Notices can be turned off in
            Windows Settings, under Notifications.
          </p>
        </section>
      )}

      <p className="footnote">
        Defender is asked to report, never to act, so a file it flags stays
        where it was until you quarantine it. A check that did not finish, or a
        file that could not be read, is said here and never shown as clean.
      </p>
    </>
  );
}

function RecordRow({
  record,
  said,
  focused,
  busy,
  onCheck,
  onDissect,
  onQuarantine,
}: {
  record: PageRecord;
  said: string | undefined;
  focused: boolean;
  busy: boolean;
  onCheck: () => void;
  onDissect: () => void;
  onQuarantine: () => void;
}) {
  const signer = signatureLabel(record.signature);
  const flaggedProgram =
    record.scan.answer === "flagged" && record.archive === null && record.signature !== null;
  // Defender names a member of an archive after an arrow. A flag on an
  // archive that names none is a flag on the archive itself, and then nothing
  // is known about any one file in it.
  const flaggedWhole =
    record.archive !== null &&
    record.scan.answer === "flagged" &&
    !record.scan.threats.some((threat) => threat.resources.some((text) => text.includes("->")));
  const ref = useRef<HTMLLIElement>(null);
  useEffect(() => {
    if (focused) ref.current?.scrollIntoView({ block: "center" });
  }, [focused]);

  return (
    <li ref={ref} className={`dl-row${focused ? " dl-focused" : ""}`}>
      <div className="dl-head">
        <span className="dl-name">
          {record.present ? (
            <PathLink path={record.path}>{record.name}</PathLink>
          ) : (
            <span title={record.path}>{record.name}</span>
          )}
        </span>
        <span className="dl-size">{fmt.bytes(record.bytes)}</span>
      </div>
      <div className="dl-facts small muted">
        {record.arrived_at ? `arrived ${fmt.timestamp(record.arrived_at)}` : "arrival time not known"}
        {" · "}
        {originLabel(record)}
        {signer && <> · {signer}</>}
        {" · "}checked {fmt.timestamp(record.checked_at)}
        {!record.present && <> · no longer where it was</>}
      </div>

      <Answer scan={record.scan} />
      {record.scan.answer === "flagged" && <Notes notes={record.scan.notes} />}

      {flaggedProgram && (
        <p className="small muted wrap">
          A program Defender flagged cannot be repaired or cleaned here. Quarantine
          it, and if you need it, get a fresh copy from its publisher. This copy{" "}
          {originClause(record)}. {signerSentence(record.signature)}
        </p>
      )}
      {flaggedWhole && (
        <p className="small muted wrap">
          Defender flagged the archive as a whole, not a file inside it, so no
          part of it can be told apart from the rest. This copy {originClause(record)}.
        </p>
      )}
      {record.archive === "other" && (
        <p className="small muted">
          Only zip archives can be taken apart here. Defender was asked about
          this one as a single file.
        </p>
      )}

      {record.dissection && (
        <p className="small muted">
          Taken apart: {fmt.count(record.dissection.totals.files)}{" "}
          {record.dissection.totals.files === 1 ? "file" : "files"},{" "}
          {fmt.count(record.dissection.totals.flagged)} flagged by Defender,{" "}
          {fmt.count(record.dissection.totals.left_out)} left out for another reason,{" "}
          {fmt.count(record.dissection.totals.clean)} Defender found nothing in.
        </p>
      )}

      {record.actions.length > 0 && (
        <ul className="dl-done">
          {record.actions.map((action, index) => (
            <li key={`${action.at}-${index}`} className="small">
              <span className="muted">{fmt.timestamp(action.at)}</span> {action.what}
            </li>
          ))}
        </ul>
      )}

      {said && <p className="small held-warn wrap">{said}</p>}

      {record.present && (
        <div className="dl-actions">
          <button className="ghost" onClick={onCheck} disabled={busy}>
            Check again
          </button>
          {record.archive === "zip" && !flaggedWhole && (
            <button className="ghost" onClick={onDissect} disabled={busy}>
              Extract what Defender did not flag
            </button>
          )}
          <button className="ghost" onClick={onQuarantine} disabled={busy}>
            Quarantine
          </button>
          <PathLink path={record.path} className="link-button">
            Show in Explorer
          </PathLink>
        </div>
      )}
    </li>
  );
}

function LooseRow({
  file,
  failure,
  said,
  focused,
  busy,
  onCheck,
  onDissect,
}: {
  file: LooseFile;
  failure: string | undefined;
  said: string | undefined;
  focused: boolean;
  busy: boolean;
  onCheck: () => void;
  onDissect: () => void;
}) {
  return (
    <li className={`dl-row${focused ? " dl-focused" : ""}`}>
      <div className="dl-head">
        <span className="dl-name">
          <PathLink path={file.path}>{file.name}</PathLink>
        </span>
        <span className="dl-size">{fmt.bytes(file.bytes)}</span>
      </div>
      <div className="dl-facts small muted">
        {file.arrived_at ? `arrived ${fmt.timestamp(file.arrived_at)}` : "arrival time not known"}
      </div>
      <div className="dl-answer pending">
        {file.changed_since_checked
          ? "Changed since it was checked, so not checked as it is now"
          : "Not checked yet"}
        {failure && <p className="small held-warn wrap">{failure}</p>}
      </div>
      {said && <p className="small held-warn wrap">{said}</p>}
      <div className="dl-actions">
        <button className="ghost" onClick={onCheck} disabled={busy}>
          Check now
        </button>
        {file.archive === "zip" && (
          <button className="ghost" onClick={onDissect} disabled={busy}>
            Extract what Defender did not flag
          </button>
        )}
        <PathLink path={file.path} className="link-button">
          Show in Explorer
        </PathLink>
      </div>
    </li>
  );
}

/** Most members drawn at once. The counts above the list cover every one. */
const MEMBERS_SHOWN = 400;

function memberOrder(member: Member): number {
  switch (member.status.state) {
    case "flagged":
      return 0;
    case "left_out":
      return 1;
    case "nothing_found":
      return 2;
    case "folder":
      return 3;
  }
}

function DissectionPanel({
  view,
  record,
  extraction,
  extracting,
  onExtract,
  onClose,
}: {
  view: DissectionView;
  record: PageRecord | undefined;
  extraction: Extraction | null;
  extracting: boolean;
  onExtract: () => void;
  onClose: () => void;
}) {
  const { dissection } = view;
  const totals = dissection.totals;
  const name = fmt.splitPath(dissection.archive).name;
  const members = dissection.members
    .filter((member) => member.status.state !== "folder")
    .sort((a, b) => memberOrder(a) - memberOrder(b));
  const hidden = members.length - MEMBERS_SHOWN;
  const notOut = totals.flagged + totals.left_out;

  return (
    <section className="panel">
      <div className="panel-head">
        <h2>Inside {name}</h2>
        <button className="ghost" onClick={onClose}>
          Close
        </button>
      </div>

      {dissection.original.quarantined && (
        <p className="small muted">
          Defender flagged it, so the original was quarantined before it was taken
          apart. It can be put back from Cleanup for thirty days.
        </p>
      )}
      {dissection.original.refused && (
        <p className="small held-warn wrap">
          The original could not be quarantined, so it is still where it was:{" "}
          {dissection.original.refused}
        </p>
      )}
      {record && (
        <p className="small muted">
          {originLabel(record)}
          {record.signature && <> · {signatureLabel(record.signature)}</>}
        </p>
      )}

      <Answer scan={dissection.scan} />
      {dissection.whole_archive.length > 0 && (
        <p className="small wrap">
          Named on the archive itself:{" "}
          {dissection.whole_archive.map((threat, index) => (
            <span key={threat}>
              {index > 0 && ", "}
              <ThreatName name={threat} />
            </span>
          ))}
        </p>
      )}
      <Notes notes={dissection.scan.notes} />

      <p className="dl-counts">
        {fmt.count(notOut)} of {fmt.count(totals.files)} {totals.files === 1 ? "file" : "files"} left out,{" "}
        {fmt.bytes(totals.flagged_bytes + totals.left_out_bytes)} of {fmt.bytes(totals.bytes)}.
      </p>
      <p className="small muted">
        {fmt.count(totals.flagged)} flagged by Defender ({fmt.bytes(totals.flagged_bytes)}),{" "}
        {fmt.count(totals.left_out)} left out for another reason ({fmt.bytes(totals.left_out_bytes)}),{" "}
        {fmt.count(totals.clean)} Defender found nothing in ({fmt.bytes(totals.clean_bytes)}).
        KAM Security never extracts a file Defender flagged.
      </p>

      {!dissection.offered && dissection.not_offered && (
        <div className="notice notice-warn">{dissection.not_offered}</div>
      )}

      {dissection.offered && !extraction && (
        <div className="dl-actions">
          <button className="primary" onClick={onExtract} disabled={extracting}>
            {extracting
              ? "Extracting…"
              : `Extract the ${fmt.count(totals.clean)} ${totals.clean === 1 ? "file" : "files"} Defender did not flag`}
          </button>
          <span className="small muted">
            Into a new folder beside it in Downloads, named "{name.replace(/\.zip$/i, "")} (checked
            by KAM)".
          </span>
        </div>
      )}

      {extraction && <ExtractionResult extraction={extraction} />}

      <ul className="dl-members">
        {members.slice(0, MEMBERS_SHOWN).map((member, index) => (
          <li key={`${member.name}-${index}`} className={`dl-member ${member.status.state}`}>
            <span className="dl-member-name" title={member.name}>
              {member.name}
            </span>
            <span className="dl-size">{fmt.bytes(member.bytes)}</span>
            <span className="dl-member-status">
              {member.status.state === "nothing_found" && "Defender found nothing"}
              {member.status.state === "flagged" && (
                <>
                  Flagged:{" "}
                  {member.status.threats.map((threat, at) => (
                    <span key={threat}>
                      {at > 0 && ", "}
                      <ThreatName name={threat} />
                    </span>
                  ))}
                </>
              )}
              {member.status.state === "left_out" && member.status.reason}
            </span>
          </li>
        ))}
      </ul>
      {hidden > 0 && (
        <p className="small muted">
          And {fmt.count(hidden)} more, all counted above.
        </p>
      )}
      {dissection.members_omitted > 0 && (
        <p className="small muted">
          {fmt.count(dissection.members_omitted)}{" "}
          {dissection.members_omitted === 1 ? "member is" : "members are"} not
          listed here, and {dissection.members_omitted === 1 ? "is" : "are"}{" "}
          counted above.
        </p>
      )}
      <p className="small muted">
        Defender looks inside an archive only as far as its own limits on size
        and depth, and does not say where it stopped. A password-protected file
        is one it could not look inside, so it is never extracted.
      </p>
    </section>
  );
}

function ExtractionResult({ extraction }: { extraction: Extraction }) {
  return (
    <div className="dl-extracted">
      <p>
        Extracted {fmt.count(extraction.files)} {extraction.files === 1 ? "file" : "files"} (
        {fmt.bytes(extraction.bytes)}) into{" "}
        <PathLink path={extraction.destination}>{extraction.destination}</PathLink>.{" "}
        {fmt.count(extraction.left_out)} left out ({fmt.bytes(extraction.left_out_bytes)}).
      </p>
      {extraction.removed.length > 0 && (
        <>
          <p className="held-warn wrap">
            {fmt.count(extraction.removed.length)}{" "}
            {extraction.removed.length === 1 ? "file was" : "files were"} removed by Defender as{" "}
            {extraction.removed.length === 1 ? "it was" : "they were"} written, so{" "}
            {extraction.removed.length === 1 ? "it is" : "they are"} not counted as extracted:
          </p>
          <ul className="dl-done">
            {extraction.removed.map((removal) => (
              <li key={removal.name} className="small">
                {removal.name}
                {removal.threat ? (
                  <>
                    {" "}
                    (<ThreatName name={removal.threat} />)
                  </>
                ) : (
                  <span className="muted"> (Defender's history does not name it yet)</span>
                )}
              </li>
            ))}
          </ul>
          <Notes
            notes={extraction.removed
              .map((removal) => removal.note)
              .filter((note): note is ThreatNote => note !== null)
              .filter((note, index, all) => all.findIndex((other) => other.name === note.name) === index)}
          />
          <p className="small muted">
            Windows Security's Protection history shows what Defender did with each.
          </p>
        </>
      )}
      {extraction.failed.length > 0 && (
        <>
          <p className="held-warn wrap">
            {fmt.count(extraction.failed.length)} could not be written:
          </p>
          <ul className="dl-done">
            {extraction.failed.map((failure) => (
              <li key={failure} className="small">
                {failure}
              </li>
            ))}
          </ul>
        </>
      )}
      <p className="small muted">The private copy used to take it apart has been deleted.</p>
    </div>
  );
}
