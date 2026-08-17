# KAM Security — Project Plan

A control plane for Windows' built-in security primitives, plus a storage intelligence
engine that answers questions Windows already knows the answers to but never surfaces.

**Stack:** Rust + Tauri v2 (backend), TypeScript + React (frontend), SQLite (state)
**Target:** Windows 10 1809+ / Windows 11, x64 and arm64
**License:** MIT or Apache-2.0 (no GPL dependencies — see "Licensing constraints")

---

## 1. What this is, and what it is not

### It is
- The good UI that Windows Defender and Defender Firewall never shipped with.
- A **provenance-based** threat detector: who signed this binary, when did it arrive,
  what wrote it, where did it come from, does it persist across reboot.
- A storage intelligence engine that finds orphaned installs, duplicate downloads, and
  the real on-disk footprint of every installed application.
- A replacement for Norton / McAfee / CCleaner-class consumer software.

### It is not
- A new antivirus engine. We orchestrate Microsoft Defender; we do not compete with it.
- A real-time file interceptor. That requires a kernel minifilter driver, an EV
  certificate, Microsoft attestation signing, and Microsoft Virus Initiative membership.
  Out of scope, permanently.
- A registry cleaner. Zero measurable benefit, real breakage risk. Will not be built.
- A replacement for the Windows Filtering Platform. WFP *is* the network stack's filter
  layer. We manage Defender Firewall's ruleset and observe traffic; we do not displace it.

### Non-negotiable product rules
1. **Nothing is ever deleted.** Everything moves to quarantine with a 30-day undo and a
   reversible manifest.
2. **No scareware.** No red badges, no inflated issue counts, no "47 problems found!"
   Findings are ranked by evidence and shown with the reasoning that produced them.
3. **Every privileged action is logged** to an append-only audit log the user can read.
4. **Explain, don't assert.** Every finding shows why: the signature status, the
   provenance trail, the size attribution. No opaque verdicts.

---

## 2. Architecture

```
┌──────────────────────────────────────────────────┐
│  KAM Shell — Tauri window, normal user rights    │
│  React UI · charts · treemap · no privileges     │
└───────────────────────┬──────────────────────────┘
                        │  named pipe, authenticated,
                        │  length-prefixed JSON-RPC
┌───────────────────────▼──────────────────────────┐
│  KAM Agent — Windows Service, runs as SYSTEM     │
│                                                  │
│  ┌────────────┬────────────┬──────────────────┐  │
│  │  scanner   │  firewall  │     storage      │  │
│  ├────────────┼────────────┼──────────────────┤  │
│  │  quarantine · scheduler · auditlog · db    │  │
│  └────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────┘
```

**Why the split:** the UI is a browser engine. A browser engine must never run as SYSTEM.
All privileged work lives in a small, auditable service with a narrow RPC surface.

**Pipe security:** the agent sets a DACL on the pipe restricting it to the interactive
user and Administrators, and verifies the connecting process image path and signature
before accepting commands. Prevents any local process from driving the SYSTEM agent.

### Crate layout (cargo workspace)

```
kam-security/
├── crates/
│   ├── kam-agent/        Windows Service host, RPC server, dispatch
│   ├── kam-ipc/          shared RPC types (serde), pipe transport, DACL setup
│   ├── kam-scanner/      Defender orchestration, YARA, provenance engine
│   ├── kam-firewall/     INetFwPolicy2 rules, connection table, ETW watcher
│   ├── kam-storage/      MFT reader, size attribution, orphan/duplicate detection
│   ├── kam-quarantine/   staging store, manifests, undo journal
│   └── kam-core/         db (SQLite), audit log, config, scheduler, error types
└── ui/                   Tauri v2 app + React frontend
```

### Key dependencies

| Crate | Purpose | Confidence |
|---|---|---|
| `windows` (windows-rs) | All Win32 APIs — Microsoft's official binding | Certain |
| `tauri` v2 | App shell | Certain |
| `serde` / `serde_json` | RPC + manifests | Certain |
| `rusqlite` (bundled) | Local state, scan history, undo journal | Certain |
| `blake3` | Content hashing for duplicate detection | Certain |
| `tracing` + `tracing-subscriber` | Structured logging / audit trail | Certain |
| `wmi` | Defender WMI classes | Verify at Phase 3 |
| `yara` (libyara bindings) | Rule engine | Verify at Phase 3; fallback = bundled `yara.exe` |
| ETW consumer crate | Live network events | Verify at Phase 4; fallback = polling `GetExtendedTcpTable` |

Anything marked "verify" gets a spike before it's committed to. Each has a documented
fallback that does not block the phase.

### Licensing constraints
- **No libclamav.** GPLv2 — linking it makes the entire project GPL.
- YARA is BSD-3-Clause — compatible, fine to link.
- Everything else must be MIT/Apache/BSD. `cargo-deny` runs in CI to enforce this.

---

## 3. Modules

### 3.1 Storage Intelligence — the flagship

The differentiating module. Four features, in build order:

**(a) Full-disk map.** ✅ **Built.**

The original plan said `FSCTL_ENUM_USN_DATA` would give a whole-volume map in
about two seconds. One correction, found while building it: **that call returns
names, parent references and attributes, but no sizes.** A treemap without sizes
is not a treemap, so the shipped reader locates `$MFT` on the raw volume and
parses it directly.

Measured on the development machine, a 1 TB volume with 1.4 million files:

| | Master file table | Directory walk |
|---|---|---|
| First scan after a reboot | 2.4 s | 57.8 s |
| Repeat scan, warm cache | 2.4 s | 15.2 s |
| Against the 1036.3 GB Windows reports | 99.6% | 97.6% |
| Needs elevation | yes | no |

Two traps cost 270 GB before the numbers were checked against Windows rather
than eyeballed:

1. Fragmented files spill their attributes into **extension records**, leaving
   the base record with no `$DATA` at all. A 138 GB game archive read as zero.
2. Where several `$DATA` attributes exist, only the fragment starting at
   **virtual cluster 0** carries the real length. The others hold zero.

The walk remains as the fallback for subdirectories, non-NTFS volumes, and an
agent without administrative rights. It is slower *and* less accurate — it
cannot open every directory, and it counts a hard-linked file once per link,
which on a Windows volume means counting much of `WinSxS` repeatedly.

**(b) True application footprint.**
Control Panel's size column is `EstimatedSize` — a value the installer self-reports.
Often missing, often wrong, and never counts anything outside the install directory.
We compute the real number by attributing every location an app touches:

```
InstallLocation  +  %PROGRAMDATA%\<vendor>  +  %LOCALAPPDATA%\<vendor>
                 +  %APPDATA%\<vendor>      +  registry footprint
                 +  service binaries        +  scheduled task payloads
```

Attribution sources: uninstall registry keys, MSI product database, service image paths,
and executable signer identity to link vendor directories to their owning product.

> Demo line: *"Control Panel says 190 MB. Actual footprint: 4.2 GB across 7 locations."*

**(c) Orphan detection.**
Directories under ProgramData/LocalAppData/AppData whose owning application is no longer
installed. Leftovers from software uninstalled months or years ago. On a development
machine this is routinely 10–40 GB. Ranked by size, last-access time, and confidence
that the owner is truly gone.

**(d) Provenance-aware download intelligence.**
Two Windows features nobody surfaces to users:

- **`Zone.Identifier` alternate data stream** — present on every downloaded file.
  Contains `ZoneId=3` and usually `ReferrerUrl` / `HostUrl`. This is how we know a file
  was downloaded, when, and from where.
- **USN change journal** — tells us when a file appeared and which process created it.

Together these produce findings like: *"This 4.1 GB ISO in `Documents` was downloaded
from example.com on 3 March 2025 and has never been opened."*

Built on this: duplicate detection (blake3 content hash, plus fuzzy matching on names
like `setup(1).exe` / `setup_v2.exe`), and file-organisation proposals.

**File-organisation safety tiers** — this is a hard fence, not a guideline:

| Tier | Rule |
|---|---|
| ✅ May propose a move | Inert user documents (media, docs, archives, installers) outside any install root, AppData, or git working tree |
| ❌ Never propose a move | Executables, libraries, anything under an install root, anything under AppData/ProgramData, anything inside a git repo, anything with an open handle |

Every move is transactional, recorded path-for-path in the undo journal, and reversible
as a single operation. Moves are proposed in batches and always dry-run first.

### 3.2 Scanner

Four layers, each earning its place:

1. **Defender orchestration** — `MSFT_MpScan`, `MSFT_MpThreat`, `MSFT_MpPreference` via
   WMI, plus `MpCmdRun.exe`. Scan control, threat history, real-time-protection status,
   exclusion management. Microsoft's engine and cloud intel, our UI.
2. **YARA rules** — targeted at what Defender deliberately tolerates to avoid false
   positives on commercial software: bundled adware, scareware "optimizers", browser
   hijackers, stalkerware, aggressive telemetry, unwanted persistence.
3. **Provenance & reputation engine** — *the original contribution.* For every executable
   on disk: Authenticode signer and validity, arrival time and writing process (USN),
   download origin (`Zone.Identifier`), persistence footprint (Run keys, services,
   scheduled tasks, startup folders), and location risk. An unsigned binary that appeared
   in `%APPDATA%` three weeks ago via a browser download and installed a Run key is
   suspicious with no signature match required.
4. **VirusTotal** — on-demand, single-file, user supplies their own API key. Free tier is
   rate-limited and non-commercial.

### 3.3 Firewall

- **Rule management** via `INetFwPolicy2` COM — create, edit, group, and explain existing
  Defender Firewall rules. Includes auditing rules other software has silently added.
- **Live connection view** — `GetExtendedTcpTable` joined to process → signer →
  reverse DNS → ASN/geo. Answers "what is this program talking to."
- **One-click block** — turn any observed connection into a scoped outbound rule.
- **ETW watcher** (`Microsoft-Windows-Kernel-Network`) for near-real-time connection
  events. Observe-then-block, milliseconds late.

Explicitly **not** doing outbound connection *prompting* (Little Snitch style) — that
needs a WFP callout driver. Observe-then-block delivers most of the value with no kernel
code.

### 3.4 Quarantine & undo

One store, shared by every module. A quarantined item records: original path, ACLs,
timestamps, hash, reason, and the finding that triggered it. Restore is exact. Retention
30 days, then a purge the user must confirm. Deleting files is never the default path in
any module.

---

## 4. Phases

Each phase ends with something demoable and a tagged release.

### Phase 0 — Foundations
Install Rust toolchain (`rustup`, MSVC target) and Tauri prerequisites. Cargo workspace,
CI (fmt, clippy, test, `cargo-deny`), licence, README stating scope honestly.

### Phase 1 — Skeleton *(chosen starting point)*
The privilege split, end to end, with one trivial feature proving the whole path.

- `kam-agent` installs and runs as a Windows Service
- Named pipe with DACL + client verification
- JSON-RPC request/response, versioned
- SQLite store, append-only audit log
- Tauri shell that connects, calls `get_system_status`, and renders the result
- Service install/uninstall/repair path, and correct behaviour when the agent is absent

**Done when:** UI button → SYSTEM service → real Win32 call → result on screen, with the
call recorded in the audit log.

### Phase 2 — Storage Intelligence ✅ **Complete**
Master file table reader, treemap, application footprints, orphan detection,
download provenance, duplicate detection, and organisation proposals — each with
its reasoning shown and, where it acts, an undo.

One rule in this plan turned out to contradict itself. It listed "installers" as
safe to move and "executables" as never movable; installers are executables. It
is resolved toward caution in `kam_storage::organise`: nothing that runs is ever
proposed for moving, even though downloaded installers are the most common
clutter there is. Being wrong about a PDF confuses someone; being wrong about an
executable silently breaks something.

### Phase 3 — Scanner
Defender orchestration first (immediate value), then the provenance engine (the
differentiator), then YARA, then optional VirusTotal.

Defender orchestration and the provenance engine are built. Two assumptions in
the original plan did not survive contact with Windows.

The plan wanted "which process wrote it" as a provenance signal. Nothing keeps
that. The USN journal records what changed, not who changed it, and there is no
retrospective way to recover the writer of a file that already exists. The
signal was dropped rather than approximated.

Verifying a signature turned out to be two questions, not one. `WinVerifyTrust`
on the file alone reports most of Windows as unsigned, because Windows signs
itself through catalogues — a `.cat` file elsewhere listing the binary's hash.
Checking only embedded signatures would have buried the handful of genuinely
unsigned binaries among several hundred false ones. Both routes are checked, and
a file whose *embedded* signature is broken is never rescued by a catalogue
entry, since that would let a tampered binary pass on the strength of a record
for the version it no longer is.

### Phase 4 — Firewall
Rule management → connection table → one-click block → ETW watcher.

### Phase 5 — Product polish
Scheduler, notifications, first-run experience, MSI/NSIS installer, auto-update,
documentation, screenshots. Decide on code signing here, not before.

---

## 5. Risks

| Risk | Mitigation |
|---|---|
| **Our own app looks like malware** — mass file enumeration, elevated service, firewall edits | Never pack or obfuscate. Publish source. Submit false-positive reports to Microsoft. Keep the binary simple and the behaviour explainable. |
| **SmartScreen blocks the installer** | Accepted for a GitHub release; document the warning in the README. Revisit an EV certificate (~$400/yr, FIPS hardware key required since 2023) only if adoption warrants it. |
| **We destroy user data** | Quarantine-only, undo journal, dry-run, hard file-class fencing on moves, never delete by default. |
| **MFT parsing bugs on unusual volumes** | Handle ReFS/FAT32/network/BitLocker-locked volumes by falling back to directory walking. Fuzz the record parser. |
| **Scope creep into a driver** | Written into the plan as permanently out of scope. |
| **Vendor attribution is heuristic** | Show confidence, never auto-act on low confidence, always let the user inspect the evidence. |

---

## 6. Open decisions

- **YARA integration** — Rust bindings vs. bundling `yara.exe`. Spike in Phase 3.
- **ETW consumer** — crate maturity unverified; polling fallback exists. Spike in Phase 4.
- **Licence** — MIT vs. Apache-2.0. Apache-2.0 gives an explicit patent grant; MIT is
  shorter and more familiar. Either works.
- **Rule distribution** — how YARA rules ship and update (bundled vs. fetched). Phase 3.
