import { whenMeasured } from "./MeasuredAt";

/**
 * Said above a result a page kept from an earlier measurement, for as long
 * as that is what is on screen.
 *
 * "Measured at" beside the figures says when; this says that it is not a
 * measurement taken since the page was opened, so an old result cannot read
 * as the present, and says how to see the present.
 */
export function KeptNote({ what, at, again }: { what: string; at: number; again: string }) {
  return (
    <p className="muted" role="note">
      This is {what}, kept from {whenMeasured(at)}. Nothing has been measured again
      since this page was opened, so anything that changed after that is not in it.{" "}
      {again}
    </p>
  );
}

/**
 * Said where a kept result could not be read back, in place of a page that
 * would otherwise look as though nothing had ever been measured.
 */
export function UnreadableNote({ what, why, again }: { what: string; why: string; again: string }) {
  return (
    <div className="notice notice-warn">
      {what} kept from before could not be read back ({why.replace(/\.$/, "")}). {again}
    </div>
  );
}

/** Said when a result could not be kept for the next time the page opens. */
export function NotKeptNote({ why }: { why: string }) {
  return (
    <p className="muted">
      This result could not be kept for the next time this page is opened:{" "}
      {why.replace(/\.$/, "")}.
    </p>
  );
}
