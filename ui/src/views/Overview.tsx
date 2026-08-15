import * as fmt from "../lib/format";
import type { AuditRecord, SystemStatus, Volume } from "../lib/types";
import EffectBadge from "../components/EffectBadge";

type Props = {
  status: SystemStatus | null;
  volumes: Volume[];
  entries: AuditRecord[];
  onOpenStorage: (root: string) => void;
};

function UsageBar({ used, total }: { used: number; total: number }) {
  const pct = fmt.percent(used, total);
  // Colour is a judgement about headroom, not decoration: red only when the
  // drive is genuinely close to full.
  const tone = pct >= 92 ? "danger" : pct >= 80 ? "warn" : "accent";
  return (
    <div className="usage">
      <div className="usage-track">
        <div className={`usage-fill usage-${tone}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="usage-label">{pct.toFixed(0)}% used</span>
    </div>
  );
}

export default function Overview({ status, volumes, entries, onOpenStorage }: Props) {
  const fixed = volumes.filter((volume) => volume.kind === "fixed");
  const totalCapacity = fixed.reduce((sum, v) => sum + v.total_bytes, 0);
  const totalFree = fixed.reduce((sum, v) => sum + v.free_bytes, 0);

  return (
    <>
      <div className="view-head">
        <div>
          <h1>Overview</h1>
          <p className="lede">
            {status
              ? `Agent ${status.agent_version} on ${status.hostname}, running as ${
                  status.running_as_service ? "a Windows service" : "a console process"
                }.`
              : "The agent is not answering, so nothing below is live."}
          </p>
        </div>
      </div>

      <div className="stat-row">
        <div className="stat">
          <span className="stat-label">Fixed drives</span>
          <span className="stat-value">{fixed.length}</span>
        </div>
        <div className="stat">
          <span className="stat-label">Total capacity</span>
          <span className="stat-value">{fmt.bytes(totalCapacity)}</span>
        </div>
        <div className="stat">
          <span className="stat-label">Free</span>
          <span className="stat-value">{fmt.bytes(totalFree)}</span>
        </div>
        <div className="stat">
          <span className="stat-label">Recorded events</span>
          <span className="stat-value">{fmt.count(entries.length)}</span>
        </div>
      </div>

      <section className="panel">
        <div className="panel-head">
          <h2>Drives</h2>
        </div>
        {volumes.length === 0 ? (
          <p className="empty">No drives reported.</p>
        ) : (
          <div className="drive-grid">
            {volumes.map((volume) => (
              <button
                key={volume.root}
                className="drive"
                onClick={() => onOpenStorage(volume.root)}
              >
                <div className="drive-head">
                  <span className="drive-root">{volume.root}</span>
                  <span className="drive-fs">
                    {volume.filesystem || "unknown"}
                    {volume.supports_mft ? "" : " · walk only"}
                  </span>
                </div>
                <div className="drive-label">{volume.label || "Local disk"}</div>
                <UsageBar
                  used={volume.total_bytes - volume.free_bytes}
                  total={volume.total_bytes}
                />
                <div className="drive-numbers">
                  <span>{fmt.bytes(volume.total_bytes - volume.free_bytes)} used</span>
                  <span className="muted">{fmt.bytes(volume.free_bytes)} free</span>
                </div>
              </button>
            ))}
          </div>
        )}
      </section>

      <section className="panel">
        <div className="panel-head">
          <h2>Recent activity</h2>
        </div>
        {entries.length === 0 ? (
          <p className="empty">Nothing recorded yet.</p>
        ) : (
          <ul className="entries compact">
            {entries.slice(0, 6).map((entry) => (
              <li key={entry.id} className="entry">
                <EffectBadge effect={entry.effect} />
                <div className="entry-body">
                  <span className="action">{entry.action}</span>
                  <span className="detail">{entry.detail}</span>
                </div>
                <time className="at">{fmt.relative(entry.at)}</time>
              </li>
            ))}
          </ul>
        )}
      </section>
    </>
  );
}
