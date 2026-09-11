import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api, reason } from "../lib/api";
import ConnectionMap, {
  ConnectionLegend,
  type MapGroup,
  type MapNode,
  type Tone,
} from "../components/ConnectionMap";
import type {
  Connection,
  ConnectionReport,
  FirewallReport,
  FirewallRule,
  ProfileState,
} from "../lib/types";

/**
 * Windows Defender Firewall, with a usable view over it.
 *
 * Two halves. What the firewall has been told to do — profiles and rules,
 * which `wf.msc` shows badly and only to administrators. And what is actually
 * happening — every open socket joined to the program that owns it and whether
 * that program is signed, which nothing in Windows shows at all.
 *
 * This is the first view in the product with a button that changes the
 * machine, so blocking asks first, says exactly what it will do, and is
 * undoable from the same screen.
 */

function profileLabel(profile: ProfileState["profile"]): string {
  return profile === "domain" ? "Domain" : profile === "private" ? "Private" : "Public";
}

function Profiles({ profiles }: { profiles: ProfileState[] }) {
  return (
    <ul className="settings">
      {profiles.map((profile) => (
        <li
          key={profile.profile}
          className={`setting setting-${profile.enabled ? "on" : "off"}`}
        >
          <span className="setting-dot" />
          <span className="setting-body">
            <span className="setting-label">
              {profileLabel(profile.profile)}
              {profile.active && <span className="chip">in force now</span>}
            </span>
            <span className="setting-explain">
              {profile.profile === "domain"
                ? "Networks joined to a company domain."
                : profile.profile === "private"
                  ? "Home or work networks you have marked as trusted."
                  : "Cafés, airports, and anything else. Windows locks down hardest here."}
              {profile.enabled && (
                <>
                  {" "}
                  Incoming is{" "}
                  {profile.inbound_default === "block" ? "blocked" : "allowed"} by
                  default, outgoing is{" "}
                  {profile.outbound_default === "block" ? "blocked" : "allowed"}.
                </>
              )}
            </span>
          </span>
          <span className="setting-state">{profile.enabled ? "On" : "Off"}</span>
        </li>
      ))}
    </ul>
  );
}

/** What one program is doing on the network, with all of its sockets. */
type Program = {
  /** The image path, or a stand-in key when the owner could not be read. */
  key: string;
  path: string | null;
  /** The best name available: what the file says it is, else its file name. */
  label: string;
  /** The file name, kept when the label came from somewhere else. */
  file: string | null;
  company: string | null;
  signer: string | null;
  unsigned: boolean | null;
  /** True when this is part of KAM Security. */
  ours: boolean;
  connections: Connection[];
  external: number;
  listening: number;
  /**
   * Listening on an address something else on the network can reach.
   *
   * Separate from `listening`, and the distinction is the whole point: a socket
   * bound to `127.0.0.1` can only be reached by this machine, while one bound
   * to `0.0.0.0` can be reached by anything on the network. Windows reports
   * both as "listening" and neither as an outbound connection, so without this
   * a program accepting connections from the whole network looked identical to
   * one talking to itself — and was being coloured as though it were staying
   * put. That was not a presentational nicety, it was the map stating something
   * untrue.
   */
  reachable: number;
};

/** Whether a listening socket can be reached from off this machine. */
function isReachable(connection: Connection): boolean {
  if (connection.state !== "listening") return false;
  const address = connection.local_address;
  // Loopback only. Everything else — the wildcard `0.0.0.0` and `::`, and any
  // real interface address — is reachable by something that is not us.
  return !(
    address === "127.0.0.1" ||
    address === "::1" ||
    address.startsWith("127.")
  );
}

/**
 * Collapse a socket list into a program list.
 *
 * A real machine has dozens of sockets and a handful of programs, and the flat
 * list this replaces showed the program's name once per socket — so reading it
 * meant doing this grouping in your head, over and over, every time the list
 * refreshed. The information is identical; what changes is how much work it
 * takes to get at.
 */
function byProgram(connections: Connection[]): Program[] {
  const groups = new Map<string, Program>();

  for (const connection of connections) {
    // Sockets whose owner could not be read are still worth showing, and are
    // kept apart by process id rather than merged into one meaningless heap.
    const key = connection.image_path ?? `pid:${connection.process_id}`;
    let program = groups.get(key);
    if (!program) {
      program = {
        key,
        path: connection.image_path,
        label:
          connection.description ??
          connection.name ??
          `unidentified program (process ${connection.process_id})`,
        file: connection.name,
        company: connection.company,
        signer: connection.signer,
        unsigned: connection.unsigned,
        ours: connection.ours,
        connections: [],
        external: 0,
        listening: 0,
        reachable: 0,
      };
      groups.set(key, program);
    }
    program.connections.push(connection);
    if (connection.external) program.external += 1;
    if (connection.state === "listening") program.listening += 1;
    if (isReachable(connection)) program.reachable += 1;
  }

  // Same order as before, applied to programs: reaching the internet first,
  // then unsigned, then the busiest.
  return [...groups.values()].sort(
    (a, b) =>
      Number(b.external > 0) - Number(a.external > 0) ||
      Number(b.unsigned === true) - Number(a.unsigned === true) ||
      b.connections.length - a.connections.length ||
      a.label.localeCompare(b.label),
  );
}

/**
 * Which of the five stated states a program is in.
 *
 * Two checked facts, never an opinion: does it carry a valid signature, and is
 * it connected to something outside this machine. See `ConnectionMap` for why
 * the unidentified case is deliberately the dullest colour rather than a
 * warning one.
 */
function toneOf(program: Program): Tone {
  // Said before anything else, because everything else here is about a program
  // the reader has not identified, and this is the one they are looking at.
  if (program.ours) return "ours";
  if (program.unsigned === null) return "unknown";
  // Reaching out, or reachable from outside. Both leave this machine's edge,
  // and a listener on 0.0.0.0 is the one people least expect to be there.
  const exposed = program.external > 0 || program.reachable > 0;
  if (program.unsigned) return exposed ? "look" : "watch";
  return exposed ? "normal" : "quiet";
}

/** How alarming a tone is, only so a publisher can take its worst program's. */
const TONE_RANK: Record<Tone, number> = {
  look: 4,
  watch: 3,
  normal: 2,
  quiet: 1,
  unknown: 0,
  // Never the worst thing in a group, because it is not a thing to be worried
  // about at all — it is the program drawing the picture.
  ours: 0,
};

/**
 * Publishers, with their programs inside.
 *
 * The grouping people actually have in their heads. Steam is `steam.exe` and
 * `steamwebhelper.exe`; grouping by executable splits one program into two
 * rows that sit apart from each other, and this was the specific complaint
 * that prompted the map. Grouping by *signer* puts them back together, because
 * the signature is the only thing that genuinely ties two binaries to the same
 * author.
 *
 * Programs nothing signed cannot be grouped that way and are not lumped into
 * one heap either — a shared "unsigned" block would invent a relationship
 * between unrelated things. They stand alone.
 */
function byPublisher(programs: Program[]): MapGroup[] {
  const groups = new Map<string, MapGroup>();
  // Share is of everything on screen, so the percentages on the map add to a
  // hundred and mean "how much of this picture is that".
  const total = programs.reduce(
    (sum, program) => sum + program.connections.length,
    0,
  );
  const share = (count: number) =>
    total > 0 ? Math.max(1, Math.round((count / total) * 100)) : 0;

  for (const program of programs) {
    const publisher = program.signer;
    const key = publisher ? `signer:${publisher}` : `alone:${program.key}`;
    const notes = attention(program);
    const node: MapNode = {
      key: program.key,
      label: program.label,
      bytes: program.connections.length,
      tone: toneOf(program),
      external: program.external,
      share: share(program.connections.length),
      notes,
      detail: describe(program, share(program.connections.length)),
    };

    let group = groups.get(key);
    if (!group) {
      group = {
        key,
        label: publisher ?? program.label,
        bytes: 0,
        tone: "unknown",
        external: 0,
        share: 0,
        notes: [],
        detail: publisher ? `signed by ${publisher}` : node.detail,
        children: [],
      };
      groups.set(key, group);
    }
    group.children.push(node);
    group.bytes += node.bytes;
    group.external += node.external;
    // The publisher carries every note any of its programs raised, so a single
    // unsigned binary under an otherwise clean name is not averaged out of
    // sight.
    for (const note of notes) {
      if (!group.notes.includes(note)) group.notes.push(note);
    }
    if (TONE_RANK[node.tone] > TONE_RANK[group.tone]) group.tone = node.tone;
  }

  for (const group of groups.values()) {
    group.share = share(group.bytes);
    if (group.children.length > 1) {
      group.detail =
        `${group.bytes} sockets across ${group.children.length} programs, ` +
        `${group.share}% of everything open`;
    }
  }

  return [...groups.values()].sort((a, b) => b.bytes - a.bytes);
}

/**
 * Where a program runs from, when that is worth saying.
 *
 * A real signal and a cheap one. Software installed properly lives under
 * Program Files or in Windows; software that arrived some other way tends to
 * run from a profile folder, and something running from Temp or Downloads got
 * there without an installer at all. None of those is proof of anything —
 * plenty of legitimate applications install per-user into AppData, and this
 * machine has several — which is why it is phrased as a place rather than as a
 * verdict, and why it is only one line among others.
 */
function placeOf(path: string | null): { text: string; notable: boolean } | null {
  if (!path) return null;
  const lower = path.toLowerCase();
  if (lower.includes("\\windows\\") || lower.includes("\\program files")) {
    return { text: "installed in the usual place", notable: false };
  }
  if (lower.includes("\\temp\\") || lower.includes("\\downloads\\")) {
    return { text: "running from a temporary folder", notable: true };
  }
  if (lower.includes("\\appdata\\") || lower.includes("\\users\\")) {
    return { text: "running from your user folder", notable: true };
  }
  return null;
}

/**
 * Everything about a program that is worth a reader's attention, most notable
 * first.
 *
 * # Why a list and not a score
 *
 * The obvious thing to build here is a number — a risk rating, a percentage of
 * danger. It would be invented. Nothing on this machine knows whether a program
 * is dangerous, and turning several checked facts into one number destroys the
 * only thing that made them useful, which is that a person can look at each one
 * and disagree.
 *
 * So this returns the facts, ordered by how much each one warrants a look, and
 * the interface shows the count rather than a rating. "Three things worth
 * noticing" is honest and leads somewhere. "Risk: 73%" is neither.
 */
function attention(program: Program): string[] {
  const notes: string[] = [];

  if (program.ours) {
    // Said in this program's own voice, and said in full. Not being signed is
    // as true of this software as of anything else here, and leaving it out
    // would be the one exemption this whole product exists to refuse.
    notes.push("This is KAM Security itself");
    if (program.unsigned === true) {
      notes.push("It is not signed either, which is worth knowing");
    }
    return notes;
  }

  if (program.unsigned === true) {
    notes.push("Nothing signed it, so there is no publisher to hold to it");
  }
  if (program.external > 0 && program.unsigned === true) {
    notes.push(`Unsigned, and connected out to ${program.external} address${program.external === 1 ? "" : "es"}`);
  }
  if (program.reachable > 0) {
    notes.push(
      `Listening on an address the network can reach, not just this machine`,
    );
  }

  // What the file says about itself against who actually signed it. Both are
  // already read; the disagreement between them is the interesting part and
  // was being thrown away.
  if (
    program.company &&
    program.signer &&
    !program.signer.toLowerCase().includes(program.company.toLowerCase().split(/[ ,.]/)[0]) &&
    !program.company.toLowerCase().includes(program.signer.toLowerCase().split(/[ ,.]/)[0])
  ) {
    notes.push(
      `Says it is from ${program.company}, but ${program.signer} signed it`,
    );
  }

  const place = placeOf(program.path);
  if (place?.notable) {
    notes.push(place.text[0].toUpperCase() + place.text.slice(1));
  }

  if (program.unsigned === null) {
    notes.push("The owning program could not be read, so nothing here is known about it");
  }

  return notes;
}

/** One line of plain fact about a program, for a tooltip. */
function describe(program: Program, share: number): string {
  const parts = [
    `${program.connections.length} ${program.connections.length === 1 ? "socket" : "sockets"}, ${share}% of everything open`,
  ];
  if (program.external > 0) parts.push(`${program.external} reaching the internet`);
  if (program.reachable > 0) {
    parts.push(
      `${program.reachable} listening where the network can reach ${program.reachable === 1 ? "it" : "them"}`,
    );
  } else if (program.listening > 0) {
    parts.push(`${program.listening} listening, on this machine only`);
  }
  parts.push(
    program.signer
      ? `signed by ${program.signer}`
      : program.unsigned === null
        ? "could not be identified"
        : "not signed",
  );
  const place = placeOf(program.path);
  if (place) parts.push(place.text);
  return parts.join(" · ");
}

/** Whether a program matches what someone typed. */
function matches(program: Program, query: string): boolean {
  if (!query) return true;
  const needle = query.toLowerCase();
  const haystack = [
    program.label,
    program.file,
    program.company,
    program.signer,
    program.path,
    ...program.connections.flatMap((connection) => [
      connection.remote_address,
      connection.remote_port === null ? null : String(connection.remote_port),
      String(connection.local_port),
      connection.protocol,
    ]),
  ];
  return haystack.some((part) => part?.toLowerCase().includes(needle));
}

function stateLabel(state: Connection["state"]): string {
  switch (state) {
    case "established":
      return "connected";
    case "listening":
      return "listening";
    case "connectionless":
      return "bound";
    default:
      return "opening";
  }
}

function ProgramGroup({
  program,
  onBlock,
  busy,
  open,
  onToggle,
  nodeRef,
  notes,
}: {
  program: Program;
  onBlock: (path: string, name: string) => void;
  busy: boolean;
  open: boolean;
  onToggle: () => void;
  /** Registers the row so a click on the map can scroll to it. */
  nodeRef: (element: HTMLLIElement | null) => void;
  /** What warrants a look, most notable first. Empty when nothing does. */
  notes: string[];
}) {
  return (
    <li
      ref={nodeRef}
      className={`prog${program.external > 0 ? " prog-external" : ""}`}
    >
      <div className="prog-head">
        <button className="prog-toggle" onClick={onToggle}>
          <span className="app-caret">{open ? "▾" : "▸"}</span>
          <span className="prog-label">{program.label}</span>
          {/*
            The counts are the summary. Someone scanning this list wants to know
            which programs are talking to the internet and how much, without
            opening anything.
          */}
          <span className="prog-counts">
            {program.external > 0 && (
              <span className="prog-badge prog-badge-external">
                {program.external} to the internet
              </span>
            )}
            {program.listening > 0 && (
              <span className="prog-badge">{program.listening} listening</span>
            )}
            <span className="prog-badge prog-badge-quiet">
              {program.connections.length}{" "}
              {program.connections.length === 1 ? "socket" : "sockets"}
            </span>
          </span>
        </button>
        {program.path && (
          <button
            className="link-button conn-block"
            disabled={busy}
            onClick={() => onBlock(program.path ?? "", program.label)}
          >
            Block
          </button>
        )}
      </div>

      {/*
        Signed-by is on the collapsed row because it is the one fact here that
        cannot be forged. The description above it can be typed into a file by
        anybody, so the two must never look like equal evidence.
      */}
      <div className="prog-identity">
        <span
          className={
            program.signer
              ? "prog-signer"
              : program.unsigned === null
                ? "prog-signer prog-signer-unknown"
                : "prog-signer prog-signer-none"
          }
        >
          {program.signer
            ? `signed by ${program.signer}`
            : program.unsigned === null
              ? "could not be identified"
              : "not signed"}
        </span>
        {program.company && program.company !== program.signer && (
          <span className="prog-claim">claims {program.company}</span>
        )}
        {program.file && program.file !== program.label && (
          <span className="prog-file">{program.file}</span>
        )}
      </div>

      {notes.length > 0 && (
        <ul className="prog-notes">
          {notes.map((note) => (
            <li key={note}>{note}</li>
          ))}
        </ul>
      )}

      {open && (
        <div className="prog-detail">
          <ul className="conns">
            {program.connections.map((connection, index) => {
              const peer =
                connection.remote_address === null
                  ? null
                  : `${connection.remote_address}:${connection.remote_port ?? 0}`;
              return (
                <li
                  key={`${connection.local_port}-${index}`}
                  className={`conn${connection.external ? " conn-external" : ""}`}
                >
                  <span className="conn-proto">
                    {connection.protocol} · {stateLabel(connection.state)}
                  </span>
                  <span className="conn-peer">
                    {peer ?? `port ${connection.local_port}`}
                  </span>
                  {peer && (
                    <span className="conn-local">from port {connection.local_port}</span>
                  )}
                </li>
              );
            })}
          </ul>
          {program.path && (
            <button
              className="conn-path"
              title="Open the containing folder"
              onClick={() => void api.reveal(program.path ?? "")}
            >
              {program.path}
            </button>
          )}
        </div>
      )}
    </li>
  );
}

function RuleRow({ rule, onRemove }: { rule: FirewallRule; onRemove: (name: string) => void }) {
  return (
    <li className={`fw-rule${rule.ours ? " fw-rule-ours" : ""}`}>
      <div className="fw-rule-head">
        <span className={`badge ${rule.action === "block" ? "attention-unusual" : "attention-ordinary"}`}>
          {rule.action === "block" ? "block" : "allow"}
        </span>
        <span className="fw-rule-name">{rule.name}</span>
        {rule.ours ? (
          <button className="link-button" onClick={() => onRemove(rule.name)}>
            Remove
          </button>
        ) : (
          !rule.enabled && <span className="fw-rule-off">disabled</span>
        )}
      </div>
      <div className="fw-rule-detail">
        <span>{rule.direction === "in" ? "incoming" : "outgoing"}</span>
        {rule.application && <span className="fw-rule-app">{rule.application}</span>}
        {rule.grouping && !rule.ours && <span>{rule.grouping}</span>}
      </div>
    </li>
  );
}

export default function Firewall() {
  const [report, setReport] = useState<FirewallReport | null>(null);
  const [live, setLive] = useState<ConnectionReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [confirming, setConfirming] = useState<{ path: string; name: string } | null>(null);
  const [showAllRules, setShowAllRules] = useState(false);
  /** Free text, matched against everything on screen and everything under it. */
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<"all" | "external" | "listening" | "unsigned">(
    "all",
  );
  /** One program open at a time, so the list never becomes a wall again. */
  const [expanded, setExpanded] = useState<string | null>(null);
  /**
   * Which publisher the map is inside, if any.
   *
   * The map drills like the storage one rather than nesting, so this is the
   * whole of its navigation state: null is the publisher level, a key is that
   * publisher's programs.
   */
  const [inside, setInside] = useState<string | null>(null);
  /**
   * The list rows, so a selection can be scrolled to.
   *
   * Opening a row several screens below the map is the same as not opening it,
   * which is what "it just highlights it" meant.
   */
  const rows = useRef(new Map<string, HTMLLIElement>());

  /**
   * Programs rather than sockets.
   *
   * `connectionless` sockets are left out here as they were before: a bound UDP
   * socket with no peer is not something a person can act on, and forty of them
   * bury the rows that are.
   */
  const programs = useMemo(
    () =>
      byProgram(
        (live?.connections ?? []).filter(
          (connection) => connection.state !== "connectionless",
        ),
      ),
    [live],
  );

  const shown = useMemo(
    () =>
      programs.filter((program) => {
        if (!matches(program, query)) return false;
        switch (filter) {
          case "external":
            return program.external > 0;
          case "listening":
            return program.listening > 0;
          case "unsigned":
            // Only a real "no signature". Unknown is not a finding, and
            // sweeping it in here would turn a filter into an accusation.
            return program.unsigned === true;
          default:
            return true;
        }
      }),
    [programs, query, filter],
  );

  /** The map's top level: whatever survived the search and filters, by author. */
  const publishers = useMemo(() => byPublisher(shown), [shown]);
  /** The publisher the map is inside, if that publisher is still on screen. */
  const insideGroup = inside
    ? (publishers.find((group) => group.key === inside) ?? null)
    : null;

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setReport(await api.firewall());
      setError(null);
    } catch (cause) {
      setError(reason(cause));
      setReport(null);
    } finally {
      setLoading(false);
    }
    try {
      setLive(await api.connections());
    } catch {
      // The connection table is the secondary half; losing it should not
      // take the rules with it.
      setLive(null);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function block(path: string) {
    setBusy(true);
    setError(null);
    try {
      const rule = await api.blockProgram(path);
      setNote(`Blocked. Added the rule "${rule}", which you can remove below.`);
      await load();
    } catch (cause) {
      setError(reason(cause));
    } finally {
      setConfirming(null);
      setBusy(false);
    }
  }

  async function unblock(rule: string) {
    setBusy(true);
    setError(null);
    try {
      await api.unblockProgram(rule);
      setNote(`Removed "${rule}".`);
      await load();
    } catch (cause) {
      setError(reason(cause));
    } finally {
      setBusy(false);
    }
  }

  const ourRules = report?.rules.filter((rule) => rule.ours) ?? [];
  const otherRules = report?.rules.filter((rule) => !rule.ours) ?? [];
  const shownRules = showAllRules ? otherRules : otherRules.slice(0, 25);

  return (
    <>
      <div className="view-head">
        <div>
          <h1>Firewall</h1>
          <p className="lede">
            Windows Defender Firewall's own state and rules, and every program
            currently holding a network connection. This does not replace the
            firewall — it is the interface it never shipped with.
          </p>
        </div>
        <button onClick={() => void load()} disabled={loading || busy}>
          {loading ? "Reading…" : "Refresh"}
        </button>
      </div>

      {error && (
        <div className="notice notice-down">
          <strong>Something did not work.</strong>
          <pre className="error">{error}</pre>
        </div>
      )}

      {note && (
        <div className="notice notice-ok">
          {note}{" "}
          <button className="link-button" onClick={() => setNote(null)}>
            Dismiss
          </button>
        </div>
      )}

      {confirming && (
        <div className="notice notice-warn">
          <strong>Block {confirming.name}?</strong>
          <p className="confirm-body">
            This adds one Windows Firewall rule stopping{" "}
            <code>{confirming.path}</code> from making outgoing connections, on
            every network. Incoming traffic and every other program are left
            alone. The rule is tagged as ours, so you can remove it from this
            screen — or from Windows Firewall, where it appears under "KAM
            Security".
          </p>
          <div className="confirm-actions">
            <button onClick={() => void block(confirming.path)} disabled={busy}>
              {busy ? "Blocking…" : "Block it"}
            </button>
            <button className="link-button" onClick={() => setConfirming(null)}>
              Cancel
            </button>
          </div>
        </div>
      )}

      {report && (
        <>
          <div
            className={`notice ${report.concerns.length === 0 ? "notice-ok" : "notice-warn"}`}
          >
            {report.concerns.length === 0 ? (
              <>
                <strong>The firewall is on for every profile.</strong> Incoming
                connections nothing asked for are blocked, which is how Windows
                ships and how it should be.
              </>
            ) : (
              <>
                <strong>Worth knowing:</strong>
                <ul className="concerns">
                  {report.concerns.map((concern) => (
                    <li key={concern}>{concern}</li>
                  ))}
                </ul>
              </>
            )}
          </div>

          <section className="panel">
            <div className="panel-head">
              <h2>Profiles</h2>
            </div>
            <Profiles profiles={report.profiles} />
          </section>

          <div className="stat-row">
            <div className="stat">
              <span className="stat-label">Rules</span>
              <span className="stat-value">{report.total_rules.toLocaleString()}</span>
              <span className="stat-sub">{report.enabled_rules.toLocaleString()} enabled</span>
            </div>
            <div className="stat">
              <span className="stat-label">Blocking</span>
              <span className="stat-value">{report.blocking_rules.toLocaleString()}</span>
              <span className="stat-sub">the rest permit traffic</span>
            </div>
            <div className="stat">
              <span className="stat-label">Connected now</span>
              <span className="stat-value">{live?.established.toLocaleString() ?? "—"}</span>
              <span className="stat-sub">
                {live ? `${live.external} reaching the internet` : "not read"}
              </span>
            </div>
            <div className="stat">
              <span className="stat-label">Programs</span>
              <span className="stat-value">{live?.programs.toLocaleString() ?? "—"}</span>
              <span className="stat-sub">holding a connection</span>
            </div>
          </div>
        </>
      )}

      <section className="panel">
        <div className="panel-head">
          <h2>What is connected right now</h2>
          {programs.length > 0 && (
            <span className="panel-count">
              {shown.length === programs.length
                ? `${programs.length} programs`
                : `${shown.length} of ${programs.length} programs`}
            </span>
          )}
        </div>
        <p className="muted">
          Every open socket, grouped by the program that owns it. What a program
          says it is comes from the file itself and can say anything; who signed
          it cannot. Blocking here adds one rule and changes nothing else.
        </p>

        {live !== null && live.connections.length > 0 && (
          <div className="conn-controls">
            <input
              className="conn-search"
              type="search"
              placeholder="Search program, company, address or port"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
            />
            <div className="conn-filters">
              {(
                [
                  ["all", "All"],
                  ["external", "Reaching the internet"],
                  ["listening", "Listening"],
                  ["unsigned", "Not signed"],
                ] as const
              ).map(([value, label]) => (
                <button
                  key={value}
                  className={`chip${filter === value ? " chip-on" : ""}`}
                  onClick={() => setFilter(value)}
                >
                  {label}
                </button>
              ))}
            </div>
          </div>
        )}

        {shown.length > 0 && (
          <>
            <nav className="crumbs connmap-crumbs">
              <button
                className="crumb"
                disabled={inside === null}
                onClick={() => setInside(null)}
              >
                All publishers
              </button>
              {insideGroup && (
                <button className="crumb" disabled>
                  {insideGroup.label}
                </button>
              )}
            </nav>
            <ConnectionMap
              nodes={insideGroup ? insideGroup.children : publishers}
              selected={expanded}
              onActivate={(node) => {
                const group = publishers.find((one) => one.key === node.key);
                if (group && group.children.length > 1 && inside === null) {
                  // A publisher with several programs: go in.
                  setInside(node.key);
                  return;
                }
                // A program: open its row and take the reader to it, because a
                // row opened several screens below the map is a row that did
                // not open.
                const next = expanded === node.key ? null : node.key;
                setExpanded(next);
                if (next) {
                  requestAnimationFrame(() =>
                    rows.current
                      .get(next)
                      ?.scrollIntoView({ behavior: "smooth", block: "center" }),
                  );
                }
              }}
            />
            <ConnectionLegend />
            {live !== null && live.closing > 0 && (
              <p className="muted">
                {live.closing} more {live.closing === 1 ? "socket is" : "sockets are"}{" "}
                left over from connections that have already finished. Windows
                keeps those for a couple of minutes and attributes them to no
                program, so there is nothing to show about them beyond the
                number.
              </p>
            )}
          </>
        )}

        {live === null ? (
          <p className="empty">The connection table could not be read.</p>
        ) : live.connections.length === 0 ? (
          <p className="empty">Nothing has a socket open.</p>
        ) : shown.length === 0 ? (
          <p className="empty">
            Nothing matches. {programs.length}{" "}
            {programs.length === 1 ? "program has" : "programs have"} a socket
            open.
          </p>
        ) : (
          <ul className="progs">
            {shown.map((program) => (
              <ProgramGroup
                key={program.key}
                nodeRef={(element) => {
                  if (element) rows.current.set(program.key, element);
                  else rows.current.delete(program.key);
                }}
                notes={attention(program)}
                program={program}
                busy={busy}
                open={expanded === program.key}
                onToggle={() =>
                  setExpanded(expanded === program.key ? null : program.key)
                }
                onBlock={(path, name) => setConfirming({ path, name })}
              />
            ))}
          </ul>
        )}
      </section>

      {ourRules.length > 0 && (
        <section className="panel">
          <div className="panel-head">
            <h2>Rules this app added</h2>
          </div>
          <p className="muted">
            Everything KAM Security has added to the firewall, and nothing else.
            Rules Windows or your other software created are listed below and are
            not removable here.
          </p>
          <ul className="fw-rules">
            {ourRules.map((rule) => (
              <RuleRow key={rule.name} rule={rule} onRemove={(name) => void unblock(name)} />
            ))}
          </ul>
        </section>
      )}

      {report && (
        <section className="panel">
          <div className="panel-head">
            <h2>Everything else</h2>
          </div>
          <p className="muted">
            The {otherRules.length.toLocaleString()} rules Windows, your
            installers, and you have accumulated. Shown read-only: this product
            does not edit rules it did not create.
          </p>
          <ul className="fw-rules">
            {shownRules.map((rule, index) => (
              <RuleRow
                key={`${rule.name}-${index}`}
                rule={rule}
                onRemove={(name) => void unblock(name)}
              />
            ))}
          </ul>
          {otherRules.length > shownRules.length && (
            <button className="link-button" onClick={() => setShowAllRules(true)}>
              Show all {otherRules.length.toLocaleString()}
            </button>
          )}
        </section>
      )}

      <section className="panel">
        <div className="panel-head">
          <h2>Still to come</h2>
        </div>
        <ul className="planned">
          <li>
            Live connection events rather than a snapshot, from an ETW session
            on the kernel's network provider.
          </li>
          <li>
            Blocking a single address or port rather than a whole program.
          </li>
        </ul>
        <p className="footnote">
          Prompting before a connection opens is not on this list. It needs a
          kernel driver, an EV certificate and Microsoft attestation signing,
          and it is permanently out of scope — observing and then blocking gets
          most of the value with none of that.
        </p>
      </section>
    </>
  );
}
