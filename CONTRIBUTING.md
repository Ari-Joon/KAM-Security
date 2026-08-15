# Contributing

Thanks for looking. This is a personal project built in the open; issues and
pull requests are welcome, with a few things worth knowing first.

## Before a large change, open an issue

The scope is deliberately narrow and some things are permanently out of it (see
below). A quick issue saves you writing something that will be declined for
reasons that were never written down where you could find them.

## Setting up

See [docs/SETUP.md](docs/SETUP.md). Short version: Visual Studio Build Tools
with the C++ workload, `rustup`, then `npm install` in `ui/`.

## What CI checks

Run these before pushing; they are exactly what the workflow runs.

```bash
cargo fmt --all -- --check
```

```bash
cargo clippy --workspace --all-targets
```

```bash
cargo test --workspace
```

```bash
cargo deny check
```

Clippy runs with warnings denied. `unwrap`, `expect` and `panic` are lints in
this workspace: in test code add `#[allow(...)]` on the test module, and in
library code handle the error properly. The agent runs as LocalSystem and a
panic there is a service that stops answering.

## House style

- **Comments explain why, never what.** If a line needs a comment saying what it
  does, rename something instead. The comments worth writing are the ones that
  record a decision, a constraint, or a trap — `DisconnectNamedPipe` discarding
  unread data, or only the VCN-0 fragment carrying a file's real size.
- **Full words in names.** `directory`, not `dir`.
- Prefer a hard fence over a heuristic wherever data can be destroyed.
- New privileged operations record an audit entry, including refusals.

## Things that are permanently out of scope

Pull requests for these will be declined regardless of quality:

- **A kernel driver of any kind**, including a filesystem minifilter for
  real-time scanning. It needs an EV certificate, Microsoft attestation signing
  and Virus Initiative membership, and one bug bluescreens a stranger's machine.
- **A competing antivirus engine.** The scanner drives Microsoft Defender. Two
  real-time engines on one machine is worse than one.
- **A registry cleaner.** No measurable benefit and real breakage risk.
- **GPL dependencies**, including libclamav. `cargo deny` enforces this; the
  project ships under Apache-2.0 and is staying permissive.
- **Anything that deletes by default.** Everything destructive goes through
  quarantine with an undo.
- **Scareware patterns** — inflated issue counts, alarming red states by
  default, "your PC is at risk" language.

## Commits

Explain why the change is right, not what the diff shows. If you found something
surprising — a Win32 call that behaves unexpectedly, a number that did not add
up — put it in the commit message. That is the part nobody can reconstruct
later.

## Licence

By contributing you agree your work is licensed under Apache-2.0, matching the
project.
