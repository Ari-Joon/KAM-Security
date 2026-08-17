import * as fmt from "../lib/format";

type Props = {
  path: string;
  bytes: number;
  onReveal: (path: string) => void;
  /** Extra line under the folder, for provenance and dates. */
  note?: React.ReactNode;
};

/**
 * One file: its name, then its folder, then its size.
 *
 * A single-line path in a fixed column has to lose one end to an ellipsis, and
 * whichever end goes takes the meaning with it — clipping the front hides the
 * drive and produces the ragged left edge that made this list unreadable, and
 * clipping the back hides the filename. So the name is given its own line at
 * full weight, and the folder is what gives way underneath it.
 */
export default function FileRow({ path, bytes, onReveal, note }: Props) {
  const { folder, name } = fmt.splitPath(path);
  return (
    <li className="filerow">
      <button
        className="filerow-main"
        title={`Show ${path} in Explorer`}
        onClick={() => onReveal(path)}
      >
        <span className="filerow-name">{name}</span>
        {folder && <span className="filerow-folder">{folder}</span>}
        {note && <span className="filerow-note">{note}</span>}
      </button>
      <span className="filerow-size">{fmt.bytes(bytes)}</span>
    </li>
  );
}
