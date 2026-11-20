import { useState } from "react";
import { api, reason } from "../lib/api";
import * as fmt from "../lib/format";
import type { WingetAsked } from "../lib/types";

/**
 * Which installed apps winget says have a newer version.
 *
 * winget is Windows' own package tool. Asking it fetches its catalogue from
 * Microsoft and compares it on this PC, which takes seconds and uses the
 * network, so nothing is asked until the button is pressed and the panel says
 * both before then. It lists; nothing here installs or updates anything.
 *
 * Every line is winget's claim about versions, and says so. Not getting a list
 * is one of three different things (no winget, no answer that could be used,
 * an answer that is not a table KAM recognises), each said in its own words
 * and never drawn as an empty list.
 */
export default function NewerVersions() {
  const [asked, setAsked] = useState<WingetAsked | null>(null);
  const [asking, setAsking] = useState(false);
  const [failure, setFailure] = useState<string | null>(null);

  async function ask() {
    setAsking(true);
    setFailure(null);
    try {
      setAsked(await api.newerVersions());
    } catch (cause) {
      setAsked(null);
      setFailure(reason(cause));
    } finally {
      setAsking(false);
    }
  }

  const answer = asked?.answer ?? null;
  const when = asked
    ? `asked ${fmt.timestamp(asked.asked_at)}, took ${fmt.duration(asked.took_ms)}`
    : "";

  return (
    <section className="panel">
      <div className="panel-head">
        <h2>Newer versions, according to winget</h2>
        <button onClick={() => void ask()} disabled={asking}>
          {asking ? "Asking winget…" : asked ? "Ask again" : "Ask winget"}
        </button>
      </div>
      <p className="lede panel-lede">
        winget is Windows' own package tool. Asked, it fetches its catalogue
        from Microsoft over the internet and compares it with the apps
        installed on this PC, which takes several seconds. Only its community
        catalogue is asked, never the Microsoft Store's, so no agreement is
        accepted for you. KAM lists what winget says and installs nothing.
        Nothing is asked until you press the button.
      </p>

      {failure && (
        <div className="notice notice-warn">
          <strong>winget could not be asked.</strong> {failure}
        </div>
      )}

      {answer?.kind === "not_installed" && (
        <div className="notice notice-warn">
          <strong>winget is not on this PC for your account,</strong> so nothing
          is known here about newer versions of your apps. It comes with App
          Installer, from the Microsoft Store. KAM looked for it at{" "}
          <code>{answer.looked_at}</code>.
        </div>
      )}

      {answer?.kind === "not_answered" && (
        <div className="notice notice-warn">
          <strong>winget gave no answer KAM could use</strong> ({when}), so
          nothing is known from it about newer versions of your apps. What it
          said:
          <pre className="update-notes">{answer.said}</pre>
        </div>
      )}

      {answer?.kind === "not_recognised" && (
        <div className="notice notice-warn">
          <strong>winget answered, but not with a table KAM recognises:</strong>{" "}
          {answer.why}. So nothing is known from it about newer versions of your
          apps ({when}). What it said:
          <pre className="update-notes">{answer.said}</pre>
        </div>
      )}

      {answer?.kind === "listed" && (
        <>
          <p>
            {answer.apps.length === 0 ? (
              <>winget listed no installed app with a newer version ({when}).</>
            ) : (
              <>
                <strong>
                  winget says {fmt.count(answer.apps.length)} installed{" "}
                  {answer.apps.length === 1 ? "app has" : "apps have"} a newer
                  version
                </strong>{" "}
                ({when}).
              </>
            )}{" "}
            {answer.not_compared !== null
              ? `winget could not compare ${fmt.count(answer.not_compared)} more.`
              : "winget did not mention any it could not compare."}
          </p>
          {answer.apps.length > 0 && (
            <ul className="entries compact">
              {answer.apps.map((app) => (
                <li key={`${app.id}\u0000${app.installed}`} className="entry">
                  <div className="entry-body">
                    <span className="setting-label">
                      {app.name}: {app.installed} installed, {app.available}{" "}
                      available, according to winget.
                    </span>
                    <span className="detail">{app.id}</span>
                  </div>
                </li>
              ))}
            </ul>
          )}
          {answer.also_said.length > 0 && (
            <>
              <p className="footnote">winget also said:</p>
              <pre className="update-notes">{answer.also_said.join("\n")}</pre>
            </>
          )}
          <p className="footnote">
            winget matches what is installed to its catalogue by name, so a match
            can be wrong, and an app it has no entry for is not in this list at
            all. An installed version written "&lt; 3.14.7" is winget saying it
            is below 3.14.7, without saying which version it is.
          </p>
        </>
      )}
    </section>
  );
}
