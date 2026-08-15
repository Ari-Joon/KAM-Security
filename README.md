<p align="center">
  <img src="assets/branding/kam-mark.svg" width="120" alt="KAM Security">
</p>

<h1 align="center">KAM Security</h1>

<p align="center">
  A control plane for Windows' built-in security primitives, plus a storage
  intelligence engine that answers questions Windows already knows the answers
  to but never surfaces.
</p>

---

## What this is

Windows ships with a first-rate antivirus engine and a capable firewall. What it
does not ship is a usable interface to either, or any way to find out where your
disk space actually went. Consumer security suites fill that gap with
subscription nagware.

KAM Security is the alternative: one Rust application that drives Microsoft
Defender, manages Defender Firewall, and adds two things nothing else does —

**Provenance-based detection.** Instead of asking "does this file match a
signature", ask what a security analyst would ask: who signed it, when did it
arrive, which process wrote it, where was it downloaded from, and does it
survive a reboot. An unsigned binary that appeared in `%APPDATA%` three weeks
ago via a browser download and installed a Run key is worth flagging whether or
not any engine recognises it.

**Real storage attribution.** Control Panel's size column is `EstimatedSize`, a
number the installer writes about itself. It is routinely wrong and never counts
anything outside the install directory. KAM computes actual footprint across
every location an application touches, finds directories orphaned by software
uninstalled months ago, and uses the NTFS `Zone.Identifier` stream and USN
journal to surface downloads you never knew you had.

## What this is not

- **Not a new antivirus engine.** It orchestrates Defender rather than competing
  with it. Running two real-time engines makes a machine slower and less safe.
- **Not a real-time file interceptor.** That needs a kernel minifilter driver,
  an EV certificate, Microsoft attestation signing and Virus Initiative
  membership. Permanently out of scope.
- **Not a registry cleaner.** No measurable benefit, real breakage risk.
- **Not a WFP replacement.** The Windows Filtering Platform is the network
  stack's filter layer. KAM manages its ruleset; it does not displace it.

## Design rules

1. Nothing is deleted. Everything is quarantined with a thirty-day undo.
2. No scareware. No inflated issue counts, no red badges by default.
3. Every privileged action is written to an audit log the user can read.
4. Every finding shows the evidence that produced it.

## Architecture

An unprivileged Tauri shell talks to a small Windows service over an
access-controlled named pipe. The UI is a browser engine, and a browser engine
must never run as SYSTEM.

See [PLAN.md](PLAN.md) for the full design and phase breakdown.

## Status

**Phase 0 — foundations.** Workspace scaffolding and CI are in place. Nothing is
functional yet.

| Phase | Scope | State |
|---|---|---|
| 0 | Workspace, CI, tooling | In progress |
| 1 | Agent, IPC, audit log, shell skeleton | Not started |
| 2 | Storage intelligence | Not started |
| 3 | Scanner | Not started |
| 4 | Firewall | Not started |
| 5 | Installer, scheduler, polish | Not started |

## Building

See [docs/SETUP.md](docs/SETUP.md).

## A note on antivirus warnings

This application enumerates every file on disk, runs an elevated service, and
edits firewall rules — the same behaviours malware exhibits. Releases are
currently unsigned, so SmartScreen will warn on first run. The source is
published in full and the binary is never packed or obfuscated.
