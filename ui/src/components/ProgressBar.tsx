import type { Progress } from "../lib/jobs";
import { fraction } from "../lib/jobs";

/**
 * What a long job is doing, and a way to stop it.
 *
 * Shows a real bar when the stage knows its total and an indeterminate one
 * when it does not, rather than inventing a total to fill the space. A bar
 * that moves without meaning is worse than no bar: it teaches people that the
 * number is decorative.
 */
export default function ProgressBar({
  progress,
  onStop,
}: {
  progress: Progress;
  onStop?: () => void;
}) {
  const done = fraction(progress);

  return (
    <div className="progress">
      <div className="progress-line">
        <span className="progress-stage">{progress.stage}</span>
        {progress.total !== null && progress.total > 0 ? (
          <span className="progress-count">
            {progress.done.toLocaleString()} of {progress.total.toLocaleString()}
          </span>
        ) : progress.done > 0 ? (
          <span className="progress-count">{progress.done.toLocaleString()}</span>
        ) : null}
        {onStop && (
          <button className="link-button progress-stop" onClick={onStop}>
            Stop
          </button>
        )}
      </div>

      <div className={`progress-track${done === null ? " progress-unknown" : ""}`}>
        <div
          className="progress-fill"
          style={done === null ? undefined : { width: `${done * 100}%` }}
        />
      </div>

      {progress.detail && <span className="progress-detail">{progress.detail}</span>}
    </div>
  );
}
