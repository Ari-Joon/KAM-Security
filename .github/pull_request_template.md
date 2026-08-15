## What this changes, and why

<!-- The why is the part a reader cannot reconstruct from the diff. -->

## How it was verified

<!-- Tests are good. For anything touching Win32, say what you actually ran it
     against: which Windows version, service or console, elevated or not. -->

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --workspace --all-targets`
- [ ] `cargo test --workspace`
- [ ] Ran against a real machine, not only tests

## If it touches privileged code

- [ ] New privileged operations record an audit entry, refusals included
- [ ] Nothing is deleted without going through quarantine
- [ ] No new `unwrap`/`expect`/`panic` in the agent
- [ ] No GPL dependency added (`cargo deny check` passes)
