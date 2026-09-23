import { useEffect, useState } from "react";
import { api } from "./api";

/**
 * Which items this account could actually send to the Recycle Bin.
 *
 * # The button that could not work
 *
 * Leftovers live under `ProgramData` and the `AppData` roots, and duplicate
 * copies live wherever they were found, including `Program Files`: places an
 * unprivileged account often cannot delete from. Offering the Recycle Bin
 * there produced a raw error from inside the shell call. An action that cannot
 * work is worse than none: the person does not learn that the item is
 * protected, they learn the button is unreliable.
 *
 * # Asked of each item, not of its folder
 *
 * The first version of this asked once per folder, by writing a probe file
 * there. That asked the wrong question twice over: it passed the folder to a
 * check that then looked at the folder's *parent*, and creating a file of your
 * own is not the same permission as deleting one somebody else put there. It
 * now asks, for each item, whether Windows would let this account delete that
 * item and whether its drive has a Recycle Bin at all. Nothing is written.
 *
 * All the items go in one call, and an answer is remembered, so a list that
 * changes only asks about what is new.
 *
 * # Before the answer arrives
 *
 * Optimistic: the button is offered until the answer says otherwise. Being
 * wrong that way costs one clear message; being wrong the other way hides a
 * button that would have worked, which nobody can discover or argue with.
 */
export function useRecyclable(paths: string[]): (path: string) => boolean {
  const [known, setKnown] = useState<Record<string, boolean>>({});

  // Joined rather than passed as an array, so the effect does not re-run for
  // an array rebuilt with the same contents on every render.
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
