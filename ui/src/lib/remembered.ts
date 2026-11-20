import { invoke } from "@tauri-apps/api/core";
import { reason } from "./api";

/**
 * The results a page keeps for the next time it is opened, in the person's
 * own Local AppData. See `remembered` in the shell for where and why.
 */
export type RememberedKind =
  | "storage"
  | "applications"
  | "cleanup-survey"
  | "cleanup-duplicates"
  | "cleanup-caches";

/** A kept result, and when it was measured, by this window's clock. */
export type Kept<T> = { measuredAt: number; result: T };

/**
 * Written into every kept result. One kept by a version of the program that
 * wrote it differently is said not to read back, never misread.
 */
const SHAPE = 1;

type Stored<T> = { shape: number; measured_at: number; result: T };

/**
 * The latest result a page kept, or null when it has kept none. Rejects with
 * the reason when one is kept and cannot be read back: that is never the
 * same as nothing having been kept.
 */
export async function recall<T>(kind: RememberedKind): Promise<Kept<T> | null> {
  const text = await invoke<string | null>("remembered_result", { kind });
  if (text === null) return null;
  const stored = JSON.parse(text) as Partial<Stored<T>>;
  if (
    stored.shape !== SHAPE ||
    typeof stored.measured_at !== "number" ||
    stored.result === undefined ||
    stored.result === null
  ) {
    throw "it was kept in a form this version does not read";
  }
  return { measuredAt: stored.measured_at, result: stored.result };
}

/**
 * The write of each kind in progress, so that the next waits for it.
 *
 * Every write of a kind goes through one file beside the kept one, so two at
 * once could trip over each other, and the later of two could land first.
 * Cleanup keeps a search's answer the moment it arrives and again as rows
 * leave it, which can be twice within a moment.
 */
const writing = new Map<RememberedKind, Promise<string | null>>();

/**
 * Keep a page's latest result, in place of the one before. Resolves to the
 * reason it could not be kept, or null when it was.
 */
export function remember<T>(
  kind: RememberedKind,
  measuredAt: number,
  result: T,
): Promise<string | null> {
  const stored: Stored<T> = { shape: SHAPE, measured_at: measuredAt, result };
  let text: string;
  try {
    text = JSON.stringify(stored);
  } catch (cause) {
    return Promise.resolve(reason(cause));
  }
  const written = (writing.get(kind) ?? Promise.resolve(null)).then(async () => {
    try {
      await invoke<void>("remember_result", { kind, result: text });
      return null;
    } catch (cause) {
      return reason(cause);
    }
  });
  writing.set(kind, written);
  return written;
}
