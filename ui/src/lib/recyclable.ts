import { useEffect, useState } from "react";
import { api } from "./api";

/**
 * Which paths this account could actually send to the Recycle Bin.
 *
 * # The button that could not work
 *
 * `can_recycle` was written, registered, given an API wrapper, and never
 * called. Its own doc says why it exists: to "offer recycling where it will
 * work and quarantine where it will not, instead of offering both everywhere
 * and failing half the time". Both were offered everywhere. Leftovers live
 * under `ProgramData` and the `AppData` roots and duplicate copies live
 * wherever they were found, including `Program Files` — places an unprivileged
 * account usually cannot delete from — so pressing Recycle Bin there produced a
 * raw COM error from deep inside the shell call.
 *
 * Offering an action that cannot work is worse than not offering it. The person
 * does not learn that the path is protected; they learn that the button is
 * unreliable, which is a much more expensive thing to teach them.
 *
 * # Asked of each item, not of its folder
 *
 * The first version asked once per folder, by writing a probe file there, and
 * that asked the wrong question twice: it passed the folder to a check that
 * then looked at the folder's parent, and adding a file of your own is not the
 * permission to delete one somebody else put there. Each item is now asked
 * about itself, by opening it for delete access, with nothing written. All the
 * items go in one call, and an answer is remembered, so a list that changes
 * only asks about what is new.
 *
 * # What an unanswered check means
 *
 * Optimistic: until the answer comes back, the action is offered. The cost of
 * being wrong in that direction is one clear error message; the cost of being
 * wrong the other way is hiding a button that would have worked, which the
 * person cannot discover or argue with.
 */
export function useRecyclable(paths: string[]): (path: string) => boolean {
  const [known, setKnown] = useState<Record<string, boolean>>({});

  // Joined rather than passed as an array so the effect does not re-run on
  // every render for an array that is rebuilt each time with the same contents.
  const key = paths.join("\0");

  useEffect(() => {
    let live = true;
    const unasked = [...new Set(paths)].filter((path) => !(path in known));
    if (unasked.length === 0) return;

    api
      .canRecycleAll(unasked)
      .then((answers) => {
        if (!live) return;
        setKnown((current) => {
          const next = { ...current };
          unasked.forEach((path, index) => {
            next[path] = answers[index] ?? true;
          });
          return next;
        });
      })
      .catch(() => {
        // Could not ask. Left unknown, which reads as "offer it anyway".
      });

    return () => {
      live = false;
    };
    // `known` is read to skip what is already answered, not to re-run on it.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);

  return (path: string) => known[path] ?? true;
}
