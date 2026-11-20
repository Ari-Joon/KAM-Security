import type { SystemStatus } from "./types";

/**
 * What the window says about KAM Security's service, above every page.
 *
 * Worked out by the shell from its questions to the service (`service` in the
 * shell, where each state is tested). Times are milliseconds since 1970.
 */
export type ServiceNotice =
  | { state: "quiet" }
  | {
      state: "not_answering";
      /** The first question in a row that went unanswered. */
      since: number;
      /** The last question it did answer, if it has answered one. */
      last_answered: number | null;
      /** Whether the window was asking all along, so it stopped in between. */
      watched: boolean;
      reason: string;
    }
  | {
      state: "other_version";
      since: number;
      window: number;
      /** Null when what it answered could not be read. */
      service: number | null;
      unreadable: string | null;
    }
  | { state: "refused"; since: number; message: string }
  | { state: "answering_again"; at: number; from: number };

/** What one check tells the window. */
export type ServiceChecked = {
  notice: ServiceNotice;
  /** What the service said about itself, while it is answering. */
  status: SystemStatus | null;
  /** When to ask again. */
  next_in_ms: number;
};

/**
 * A notice in words: how it is drawn, a headline, the sentences after it, and
 * the service's or Windows' own words when there are some.
 */
export type ServiceWords = {
  tone: "down" | "warn" | "plain";
  headline: string;
  sentences: string[];
  quoted: string | null;
};

/**
 * The words for a notice, or null when there is nothing to say.
 *
 * Nothing is said while the service answers: no "connected", "protected" or
 * "all good". The notice being absent is the ordinary state, and a line that
 * always says all is well is one people stop reading.
 *
 * `when` puts a time into words, as the pages do for their own figures.
 */
export function serviceWords(
  notice: ServiceNotice,
  when: (at: number) => string,
): ServiceWords | null {
  switch (notice.state) {
    case "quiet":
      return null;

    case "not_answering": {
      // When it stopped is said only when the window was asking all along.
      // After the window has been closed, or before it has ever had an
      // answer, all that is known is when it was last heard from and when
      // it was first found not answering.
      const stopped =
        notice.watched && notice.last_answered !== null
          ? `It stopped answering at ${when(notice.since)}.`
          : notice.last_answered !== null
            ? `This window last heard from it at ${when(notice.last_answered)}, and it has not answered since ${when(notice.since)}.`
            : `It has not answered since this window first asked, at ${when(notice.since)}.`;
      return {
        tone: "down",
        headline: "KAM Security's service is not answering.",
        sentences: [
          stopped,
          "While it is not answering, the watching and the checks it does are not running: it is not watching what starts itself, and it cannot check new downloads as they arrive.",
          notice.last_answered !== null
            ? "What is on screen was read before it stopped, and anything that needs the service will fail until it answers."
            : "Nothing has been read from it, and anything that needs the service will fail until it answers.",
          "This window keeps asking, and says here when it answers again.",
        ],
        quoted: `Why there was no answer: ${notice.reason.replace(/\.$/, "")}.`,
      };
    }

    case "other_version":
      return {
        tone: "warn",
        headline: "This window and KAM Security's service come from different installs.",
        sentences: [
          notice.service !== null
            ? `They speak different versions of the language they use to talk to each other: the window version ${notice.window}, the service version ${notice.service}.`
            : "The service answered in a form this window cannot read, which is what happens when the two come from different versions.",
          "The service may misread what the window asks, and the window may misread its answers, so do not rely on what these pages show.",
          "Installing KAM Security again puts both on the same version.",
        ],
        quoted:
          notice.unreadable !== null
            ? `What could not be read: ${notice.unreadable.replace(/\.$/, "")}.`
            : null,
      };

    case "refused":
      return {
        tone: "down",
        headline: "KAM Security's service turned this window away.",
        sentences: [
          `It is running, and said: ${notice.message.replace(/\.$/, "")}.`,
          "Until it serves this window, nothing on these pages can be read from it.",
          "This window asks it again in a minute.",
        ],
        quoted: null,
      };

    case "answering_again":
      return {
        tone: "plain",
        headline: "KAM Security's service is answering again.",
        sentences: [
          `It answered as usual at ${when(notice.at)}, after not doing so from ${when(notice.from)}.`,
          "A page that was open in between shows what it read before then: open it again to read it afresh.",
        ],
        quoted: null,
      };
  }
}
