import { useCallback, useEffect, useRef, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { api } from "./api";
import { newer, type Asked, type JobSlot, type PageJob, type PageJobOutcome } from "./jobs";

/**
 * A page's long job, followed from the window's own half (`jobs` in the
 * shell), which runs it and keeps what it came to.
 *
 * The page used to run the job itself and wait for the answer, which went
 * nowhere if the page was left first. Now the page only starts it, and reads
 * it whenever it is drawn: as it runs, how far it has got; once it has ended,
 * what it came to, handed to `onOutcome` once for each run, whether it ended
 * while the page was open or while it was not.
 *
 * `onOutcome` keeps an answer the page keeps (in `remembered`) before it
 * returns. Only then is the shell told the page has it, and the shell lets go
 * of such an answer then and not before: a page left in between finds it
 * again the next time it is opened.
 */
export function usePageJob<T>(
  slot: JobSlot,
  onOutcome: (outcome: PageJobOutcome<T>) => void | Promise<void>,
) {
  const [view, setView] = useState<PageJob | null>(null);
  /** The run whose outcome has been handed to the page in this drawing of it. */
  const handled = useRef<string | null>(null);
  const latest = useRef(onOutcome);
  latest.current = onOutcome;

  const show = useCallback(
    (incoming: PageJob | null) => {
      if (incoming === null) return;
      setView((current) => newer(current, incoming));
      if (incoming.ended === null || handled.current === incoming.job) return;
      handled.current = incoming.job;
      void (async () => {
        const outcome = await api.pageJobOutcome<T>(slot);
        // Gone, or a later run in its place: nothing of this one to hand over.
        if (outcome === null || outcome.view.job !== incoming.job) return;
        await latest.current(outcome);
        await api.pageJobTaken(slot, incoming.job);
      })().catch(() => {
        // Asked again the next time the page is opened.
      });
    },
    [slot],
  );

  useEffect(() => {
    let open = true;
    const unlisten = listen<PageJob>(`jobs://${slot}`, (event) => {
      if (open) show(event.payload);
    });
    // Read only once the listener is in place, so a run that ends in between
    // is still heard about.
    void unlisten
      .then(() => api.pageJob(slot))
      .then((found) => {
        if (open) show(found);
      })
      .catch(() => {});
    return () => {
      open = false;
      void unlisten.then((stop) => stop());
    };
  }, [slot, show]);

  /** Start the job. Rejects with the reason it could not be started. */
  const start = useCallback(
    async (asked: Asked) => {
      show(await api.startPageJob(asked));
    },
    [show],
  );

  const stop = useCallback(() => {
    // It may have ended between the press and the request.
    void api.stopPageJob(slot).catch(() => {});
  }, [slot]);

  return { view, running: view !== null && view.ended === null, start, stop };
}
