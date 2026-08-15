# Security policy

KAM Security runs a service as LocalSystem and reads raw disk volumes. A bug
here has more consequences than a bug in most desktop software, so please treat
findings accordingly.

## Reporting a vulnerability

**Do not open a public issue for a security problem.**

Use GitHub's private reporting: the **Security** tab → **Report a vulnerability**.
That opens a private advisory only maintainers can see.

Please include what you would need to reproduce it yourself: Windows version,
how the agent was running (service or `--console`), the steps, and what you
expected instead.

This is a personal project without a funded response team. Expect a first reply
within about a week, and no bug bounty.

## What is in scope

The agent runs as LocalSystem, so anything that lets an unprivileged process
make it act on their behalf is the most serious class of bug here:

- Getting the agent to serve a client that should have failed the caller check
  (`is_trusted_client` in `crates/kam-agent/src/server.rs`).
- Reaching the pipe from a context its DACL should exclude — another user's
  session, a service account, or across the network.
- Crashing the agent, or corrupting its memory, with a malformed request. The
  frame decoder runs inside the SYSTEM process.
- Crashing or corrupting memory in the master file table parser
  (`crates/kam-storage/src/mft.rs`). It parses untrusted on-disk structures, in
  an elevated process, and is the largest attack surface in the codebase.
- Anything that lets a scan or a future cleanup operation touch a file outside
  what the user asked for.
- Escaping the shell's web view into the shell process.

## What is not in scope

- **Needing administrator rights to install the service.** That is by design.
- **Antivirus flagging the binaries.** Expected — see the README. Report false
  positives to the vendor, not here.
- **SmartScreen warning on unsigned releases.** Known; releases are not signed.
- Anything requiring an attacker who is already an administrator on the machine.
  From there they can replace the agent outright, and no pipe DACL helps.
- Denial of service by an authorised client. The agent trusts the shell it was
  installed with; a compromised shell is out of scope for this boundary.

## What this software does not claim

It is not an antivirus engine, and it does not intercept files in real time. It
drives Microsoft Defender and manages Windows Defender Firewall. If you are
comparing it against a commercial suite, the README is explicit about what it
deliberately does not do.
