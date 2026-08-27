import { api } from "../lib/api";

/**
 * A path you can open.
 *
 * Every path this application puts on screen refers to something real on the
 * disk, and the first thing anybody wants when they see one is to go and look
 * at it. A path that cannot be opened is a riddle: it tells you where
 * something is and then makes you copy it into Explorer by hand.
 *
 * So this exists once and is used everywhere a path appears, rather than each
 * view deciding for itself. That is not tidiness — the views that forgot were
 * exactly the ones nobody thought about twice, and a rule kept in one place is
 * the only kind that holds.
 *
 * Opening a folder is not a change to anything, so it needs no confirmation.
 * A path that has since been moved or removed simply fails to open, which is
 * its own answer.
 */
export default function PathLink({
  path,
  children,
  className = "",
  title,
}: {
  path: string;
  /** What to show. Defaults to the path itself. */
  children?: React.ReactNode;
  className?: string;
  title?: string;
}) {
  const shown = children ?? path;

  // Nothing to open: render the text plainly rather than a control that would
  // do nothing when clicked.
  if (!path) {
    return <span className={className}>{shown}</span>;
  }

  return (
    <button
      type="button"
      className={`path-link ${className}`.trim()}
      title={title ?? `Show ${path} in Explorer`}
      onClick={(event) => {
        event.stopPropagation();
        void api.reveal(path);
      }}
    >
      {shown}
    </button>
  );
}
