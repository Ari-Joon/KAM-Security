import { listen } from "@tauri-apps/api/event";
import { api } from "./api";

/**
 * Running a job that reports its progress, and stopping it.
 *
 * A scan behind a disabled button is indistinguishable from one that has hung,
 * and people reasonably assume the second. The agent streams what it is doing;
 * this delivers that to a component and gives back a way to stop.
 */

export type Progress = {
  stage: string;
  done: number;
  total: number | null;
  detail: string | null;
};

/** A fraction to draw a bar from, when the stage knows its total. */
export function fraction(progress: Progress): number | null {
  if (progress.total === null || progress.total <= 0) return null;
  return Math.min(1, Math.max(0, progress.done / progress.total));
}

let counter = 0;

/**
 * A name for one run, unique among those in flight.
 *
 * It only has to be unique within this window's lifetime — the agent forgets a
 * job the moment it ends — so a counter and the clock beat pulling in a UUID
 * library for it.
 */
export function newJobId(): string {
  counter += 1;
  return `${Date.now().toString(36)}-${counter}`;
}

/**
 * Run a job, reporting progress until it finishes.
 *
 * `run` receives the job id and should pass it to the matching command. The
 * listener is attached *before* the command starts, because the first stage is
 * reported immediately and would otherwise be missed.
 *
 * Resolves to `null` when the job was stopped, which is not an error and
 * should not be shown as one.
 */
export async function runJob<T>(
  run: (job: string) => Promise<T | null>,
  onProgress: (progress: Progress) => void,
): Promise<{ job: string; result: T | null }> {
  const job = newJobId();
  const unlisten = await listen<Progress>(`job://${job}`, (event) =>
    onProgress(event.payload),
  );
  try {
    return { job, result: await run(job) };
  } finally {
    unlisten();
  }
}

/** Ask a running job to stop. */
export async function stopJob(job: string): Promise<void> {
  try {
    await api.cancelJob(job);
  } catch {
    // The job may have finished between the click and the request, which is
    // the ordinary case rather than a failure worth reporting.
  }
}
