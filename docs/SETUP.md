# Development setup

Windows 10 1809+ or Windows 11, x64.

## 1. Visual Studio Build Tools

Rust's MSVC toolchain links against the Microsoft linker, so this comes first.
It is a several-gigabyte download.

```bash
winget install --id Microsoft.VisualStudio.2022.BuildTools --override "--quiet --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
```

If you prefer the installer UI, select the **Desktop development with C++**
workload. The Windows SDK is included and is required — this project calls Win32
APIs directly.

## 2. Rust

```bash
winget install --id Rustlang.Rustup
```

Restart your shell, then confirm. `rust-toolchain.toml` pins the channel and
components, so rustup will provision them automatically on first build.

```bash
rustc --version && cargo --version
```

## 3. Node

Already present (v26). The Tauri shell is added in Phase 1.

## 4. First build

```bash
cargo build --workspace
```

The dependency versions in `Cargo.toml` are starting points written before a
toolchain existed on this machine. If resolution fails, let cargo pick current
versions:

```bash
cargo update
```

## 5. Verify the checks CI runs

```bash
cargo fmt --all -- --check && cargo clippy --workspace --all-targets && cargo test --workspace
```

Licence and advisory auditing needs one extra tool. This enforces the rule that
no copyleft dependency enters the tree:

```bash
cargo install cargo-deny && cargo deny check
```

## 6. Run the agent

The agent normally runs as a Windows service under SYSTEM. Developing that way
means reinstalling the service on every code change and debugging in a context
you cannot easily attach to. So it also runs as a plain console process with the
same dispatch path:

```bash
cargo run -p kam-agent -- --console
```

Service hosting arrives in Phase 1 and is exercised only by integration tests
and release builds.

Log level is controlled by `KAM_LOG`, using `tracing-subscriber` filter syntax:

```bash
set KAM_LOG=debug && cargo run -p kam-agent -- --console
```

## Notes

- Some Phase 2 and 3 work needs an elevated shell — reading the MFT requires
  volume-level access. Develop those features in an elevated terminal.
- Test destructive paths in a VM with a snapshot, never on your own profile.
- Defender may flag debug builds during storage work. Add the `target`
  directory as an exclusion rather than disabling real-time protection.
