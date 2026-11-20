import { useCallback, useEffect, useState } from "react";
import { api, reason } from "../lib/api";
import type { Reading, WindowsUpdateReport } from "../lib/types";

/**
 * What Windows says about its own updates, beside what the Overview says
 * about protection.
 *
 * Each line is a fact with where it came from, and a source that could not be
 * read is said to be unread. It never says "up to date": from this PC alone
 * nobody can know whether a newer update exists, only what is installed and
 * when. And it reads, nothing more: there is no button here that changes
 * anything about Windows Update.
 */

/** A day as a person says it. A bare `2026-11-11` is that day where they are. */
function day(text: string): string {
  const bare = /^(\d{4})-(\d{2})-(\d{2})$/.exec(text);
  const at = bare
    ? new Date(Number(bare[1]), Number(bare[2]) - 1, Number(bare[3]))
    : new Date(text);
  if (Number.isNaN(at.getTime())) return text;
  return at.toLocaleDateString(undefined, { day: "numeric", month: "long", year: "numeric" });
}

/** Ends a reason that may or may not have its own full stop. */
function stop(text: string): string {
  return /[.!?]$/.test(text) ? text : `${text}.`;
}

function listed(names: string[]): string {
  if (names.length <= 1) return names.join("");
  return `${names.slice(0, -1).join(", ")} and ${names[names.length - 1]}`;
}

/** What the two registry marks for a waiting restart say, in words. */
function marks(restart: WindowsUpdateReport["restart"]): { there: string[]; unread: string[] } {
  const said = { there: [] as string[], unread: [] as string[] };
  const mark = (reading: Reading<boolean>, there: string, name: string) => {
    if (reading.state === "unread") said.unread.push(`${name} could not be read: ${stop(reading.why)}`);
    else if (reading.value) said.there.push(there);
  };
  mark(
    restart.update_marker,
    "Windows Update's mark for a waiting restart is in the registry.",
    "Windows Update's mark for a waiting restart",
  );
  mark(
    restart.servicing_marker,
    "Windows' servicing has marked a restart as pending in the registry.",
    "Windows' servicing mark for a pending restart",
  );
  return said;
}

function restartSentence(restart: WindowsUpdateReport["restart"]): string {
  const asked = restart.windows_update;
  if (asked.state === "read") {
    return asked.value
      ? "A restart is waiting to finish an update, according to Windows Update."
      : "No restart is waiting to finish an update, according to Windows Update.";
  }
  const both = [restart.update_marker, restart.servicing_marker];
  const unasked = `Windows Update could not be asked whether a restart is waiting (${asked.why}).`;
  if (both.some((mark) => mark.state === "read" && mark.value)) {
    return `${unasked} A restart is waiting to finish an update, according to the registry.`;
  }
  if (both.every((mark) => mark.state === "read")) {
    return `${unasked} Neither of the marks Windows leaves in the registry for a waiting restart is there.`;
  }
  return unasked;
}

export default function WindowsUpdate() {
  const [report, setReport] = useState<WindowsUpdateReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [reading, setReading] = useState(false);

  const refresh = useCallback(async () => {
    setReading(true);
    try {
      setReport(await api.windowsUpdate());
      setError(null);
    } catch (cause) {
      setReport(null);
      setError(reason(cause));
    } finally {
      setReading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const build = report?.build;
  const newest = report?.newest;
  const pause = report?.pause;
  const disabled = report?.service_disabled;
  // When Windows Update answered no, a mark in the registry saying otherwise
  // is worth its own line. When it could not be asked, the sentence already
  // stands on the marks, and only a mark that could not be read needs saying.
  const asked = report?.restart.windows_update;
  const extraMarks =
    report === null || asked === undefined
      ? []
      : asked.state === "unread"
        ? marks(report.restart).unread
        : asked.value
          ? []
          : marks(report.restart).there;

  return (
    <section className="panel">
      <div className="panel-head">
        <h2>Windows Update</h2>
        <button onClick={() => void refresh()} disabled={reading}>
          {reading ? "Reading…" : "Read again"}
        </button>
      </div>

      {error && (
        <div className="notice notice-warn">
          <strong>What Windows says about its updates could not be read.</strong> {error}
        </div>
      )}

      {report === null && !error && <p className="muted">Reading what Windows says about its updates.</p>}

      {report && (
        <ul className="entries compact">
          <li className="entry">
            <div className="entry-body">
              <span className="action">
                {build?.state === "read"
                  ? `Windows is on build ${build.value.build}${
                      build.value.revision !== null ? `.${build.value.revision}` : ""
                    }${build.value.version ? `, version ${build.value.version}` : ""}, according to Windows' own record of its version.`
                  : `The build Windows is on could not be read: ${stop(build?.why ?? "")}`}
              </span>
            </div>
          </li>

          <li className="entry">
            <div className="entry-body">
              {newest?.kind === "history" && (
                <span className="action">
                  The update that brought this build, {newest.title}, was installed on{" "}
                  {day(newest.installed_at)}, according to Windows Update's history.
                </span>
              )}
              {newest?.kind === "list" && (
                <>
                  <span className="action">
                    {newest.updates.length === 1
                      ? `The newest entry in Windows' list of installed updates is ${newest.updates[0]}, installed on ${day(newest.installed_on)}.`
                      : `The newest entries in Windows' list of installed updates are ${listed(newest.updates)}, installed on ${day(newest.installed_on)}.`}
                  </span>
                  <span className="detail">
                    {stop(newest.history)} So this is taken from the list of installed updates
                    instead.
                  </span>
                </>
              )}
              {newest?.kind === "unread" && (
                <span className="action">
                  When Windows last installed an update could not be read. {stop(newest.why)}
                </span>
              )}
            </div>
          </li>

          <li className="entry">
            <div className="entry-body">
              <span className="action">{restartSentence(report.restart)}</span>
              {extraMarks.map((line) => (
                <span key={line} className="detail">
                  {line}
                </span>
              ))}
            </div>
          </li>

          <li className="entry">
            <div className="entry-body">
              <span className="action">
                {pause?.state === "unread"
                  ? `Whether updates are paused could not be read: ${stop(pause.why)}`
                  : pause?.value.kind === "until"
                    ? `Updates are paused until ${day(pause.value.at)}, according to the Windows Update settings.`
                    : pause?.value.kind === "ended"
                      ? `Updates are not paused: the pause recorded in the Windows Update settings ended on ${day(pause.value.at)}.`
                      : pause?.value.kind === "unrecognised"
                        ? `The Windows Update settings record a pause until "${pause.value.value}", which KAM cannot read as a date.`
                        : "Updates are not paused, according to the Windows Update settings."}
              </span>
            </div>
          </li>

          {disabled?.state === "read" && disabled.value && (
            <li className="entry">
              <div className="entry-body">
                <span className="action">
                  The Windows Update service is set to Disabled, according to its settings in the
                  registry.
                </span>
              </div>
            </li>
          )}
          {disabled?.state === "unread" && (
            <li className="entry">
              <div className="entry-body">
                <span className="action">
                  Whether the Windows Update service is switched off could not be read:{" "}
                  {stop(disabled.why)}
                </span>
              </div>
            </li>
          )}
        </ul>
      )}

      <p className="footnote">
        This says what is installed and when. Whether a newer update exists cannot be
        known from this PC alone: that takes a search of Microsoft's catalogue, which KAM
        does not make.
      </p>
    </section>
  );
}
