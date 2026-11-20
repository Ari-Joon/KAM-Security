import { whenMeasured } from "./MeasuredAt";
import { serviceWords, type ServiceNotice as Notice } from "../lib/service";

/**
 * What the window found when it last asked KAM Security's service, above
 * whichever page is open.
 *
 * It stays at the top of the page as the page scrolls, because the moment the
 * service stops is not chosen by the reader, and a notice at the top of a
 * long page somebody is halfway down is a notice nobody sees. Nothing is drawn
 * while the service answers.
 */
export default function ServiceNotice({ notice }: { notice: Notice | null }) {
  const words = notice ? serviceWords(notice, whenMeasured) : null;
  if (!words) return null;
  const tone = words.tone === "plain" ? "" : ` notice-${words.tone}`;
  return (
    <div className="service-notice">
      <div
        className={`notice${tone}`}
        role={words.tone === "plain" ? "status" : "alert"}
      >
        <strong>{words.headline}</strong> {words.sentences.join(" ")}
        {words.quoted && <span className="service-why">{words.quoted}</span>}
      </div>
    </div>
  );
}
