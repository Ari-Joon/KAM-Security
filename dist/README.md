<p align="center">
  <img src="assets/branding/kam-mark.svg" width="104" alt="">
</p>

<h1 align="center">KAM Security</h1>

<p align="center">
  A control plane for Windows' built-in security, and a storage engine that
  answers questions Windows already knows but never surfaces.
</p>

<p align="center">
  <a href="https://github.com/OWNER/kam-security/actions/workflows/ci.yml">
    <img src="https://github.com/OWNER/kam-security/actions/workflows/ci.yml/badge.svg" alt="CI">
  </a>
  <img src="https://img.shields.io/badge/license-Apache--2.0-blue" alt="Apache-2.0">
  <img src="https://img.shields.io/badge/platform-Windows%2010%2F11-0a7bbb" alt="Windows 10/11">
  <img src="https://img.shields.io/badge/rust-1.82%2B-b7410e" alt="Rust 1.82+">
</p>

---

Windows ships an excellent antivirus engine and a capable firewall. What it does
not ship is a usable interface to either, or any way to find out where your disk
space went. Consumer suites fill that gap with subscription nagware.

KAM Security is the alternative: one Rust application that drives Microsoft
Defender, manages Defender Firewall, and adds two things nothing else does.

**Real storage attribution.** Control Panel's size column is `EstimatedSize` — a
number the installer writes about itself. It is routinely wrong and never counts
anything outside the install directory.

**Provenance-based detection.** Rather than asking "does this file match a
signature", ask what an analyst would: who signed it, when did it arrive, which
process wrote it, where was it downloaded from, does it survive a reboot.

## Reading a terabyte in two seconds

Storage is the part that works today. It reads the NTFS master file table
directly instead of walking directories, which is the difference between a
coffee break and an eyeblink.

Measured on a 1 TB system drive holding 1.4 million files:

| | Master file table | Directory walk |
|---|---|---|
| First scan after a reboot | **2.4 s** | 57.8 s |
| Repeat scan, warm cache | **2.4 s** | 15.2 s |
| Agreement with the 1036.3 GB Windows reports | **99.6%** | 97.6% |
| Needs administrator rights | yes | no |

Both figures are given because the walk gains hugely from a warm filesystem
cache while the table barely notices one — it is a single sequential read either
way. Six times faster is the fair claim; twenty-four times is what you see on
the first scan after a reboot.

The walk is slower *and* less accurate: it cannot open every directory, and it
counts a hard-linked file once per link — which on a Windows volume means
counting much of `WinSxS` several times. Both paths produce the same result
type, and the app falls back automatically when it cannot read the table, saying
so rather than quietly taking a minute.

Getting the fast path right needed two things the documentation does not put
front and centre: fragmented files spill their attributes into **extension
records**, and only the `$DATA` fragment starting at **virtual cluster 0** knows
the file's real length. Missing either reports a 138 GB archive as 0 bytes.
Between them they accounted for 270 GB on the test volume.

## What this is not

- **Not a new antivirus engine.** It orchestrates Defender rather than competing
  with it. Two real-time engines make a machine slower and less safe.
- **Not a real-time file interceptor.** That needs a kernel minifilter driver,
  an EV certificate, Microsoft attestation signing and Virus Initiative
  membership. Permanently out of scope.
- **Not a registry cleaner.** No measurable benefit, real breakage risk.
- **Not a WFP replacement.** The Windows Filtering Platform *is* the network
  stack's filter layer. KAM manages its ruleset; it does not displace it.

## Design rules

1. Nothing is deleted. Everything is quarantined with a thirty-day undo.
2. No scareware. No inflated issue counts, no alarming defaults.
3. Every privileged action is written to an audit log the user can read, and the
   database rejects updates and deletes so it cannot be quietly rewritten.
4. Every finding shows the evidence that produced it.

## Architecture

```
┌─ kam-shell — Tauri window, ordinary user rights ─┐
│  React UI · treemap · no privileges              │
└───────────────────────┬──────────────────────────┘
                        │  named pipe, protected DACL,
                        │  length-prefixed JSON
┌───────────────────────▼──────────────────────────┐
│  kam-agent — Windows service, LocalSystem        │
│  scanner · firewall · storage · quarantine       │
└──────────────────────────────────────────────────┘
```

The UI is a browser engine, and a browser engine must never run as SYSTEM. The
pipe carries a protected DACL, rejects remote clients, and the agent resolves
each caller's executable — being allowed to open the pipe is not the same as
being trusted to drive it.

See [PLAN.md](PLAN.md) for the full design and phase breakdown.

## Status

Phases 0 and 1 are complete; phase 2 is in progress. Nothing claims to be
finished software.

| Phase | Scope | State |
|---|---|---|
| 0 | Workspace, CI, tooling | Done |
| 1 | Agent, IPC, audit log, shell | Done |
| 2 | Storage intelligence | Scan, MFT reader and treemap done |
| 3 | Scanner | Not started |
| 4 | Firewall | Not started |
| 5 | Installer, scheduler, polish | Not started |

Still to come in phase 2: true application footprint across every location an
app touches, orphan detection for software uninstalled long ago, and download
provenance from the `Zone.Identifier` stream and the USN journal.

## Running it

Prebuilt binaries are on the [releases page](https://github.com/OWNER/kam-security/releases).
Unzip anywhere and **keep both executables in the same folder** — the agent only
serves clients installed alongside it.

For the fast disk scan, install the agent as a service from an **administrator**
terminal:

```
kam-agent.exe --install
sc start KamSecurityAgent
```

Without it, the app still runs and falls back to walking directories.

To build from source, see [docs/SETUP.md](docs/SETUP.md).

## A note on antivirus warnings

This application enumerates every file on disk, reads raw volumes, runs an
elevated service and edits firewall rules — the same behaviours malware
exhibits. Releases are unsigned, so SmartScreen will warn on first run and some
scanners may flag the binaries.

That is the honest cost of the category. The source is published in full, the
binaries are never packed or obfuscated, and every release ships a SHA-256
checksum. Building it yourself is the strongest guarantee available, and takes
one command.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md), which includes the list of things that
are permanently out of scope — worth reading before writing anything large.

Security issues go through [SECURITY.md](SECURITY.md), privately. Never a public
issue: the agent runs as LocalSystem.

## Licence

[Apache-2.0](LICENSE). Dependencies are held to permissive licences by
`cargo deny`, which is what keeps a copyleft library from quietly making the
whole project GPL.
