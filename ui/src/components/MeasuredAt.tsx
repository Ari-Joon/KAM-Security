/**
 * When a set of figures was taken.
 *
 * Storage, Applications and Cleanup all show measurements that do not update
 * by themselves, and none of them said how old those were. A Storage result
 * left open put a "Drive" figure refreshed every five seconds beside a
 * "Measured" figure that might be from the morning, with nothing to tell the
 * two apart.
 *
 * The time is the window's own clock at the moment the answer arrived. Today's
 * is shown as a time; anything older carries its date, because "14:02" on a
 * page left open overnight would be read as this afternoon.
 */
export default function MeasuredAt({ at }: { at: number }) {
  const taken = new Date(at);
  const now = new Date();
  const today =
    taken.getFullYear() === now.getFullYear() &&
    taken.getMonth() === now.getMonth() &&
    taken.getDate() === now.getDate();
  const time = taken.toLocaleTimeString(undefined, {
    hour: "2-digit",
    minute: "2-digit",
  });
  const text = today
    ? time
    : `${taken.toLocaleDateString(undefined, { day: "numeric", month: "short" })}, ${time}`;

  return (
    <div
      className="stat"
      title="When these figures were taken. They do not change until you measure again."
    >
      <span className="stat-label">Measured at</span>
      <span className="stat-value small">{text}</span>
    </div>
  );
}
