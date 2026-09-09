# Publishing this repository

Everything here is prepared but not yet done, because it needs a GitHub account
and decisions only you can make.

## 1. Replace the placeholder owner ✅ done

The repository is `Ari-Joon/KAM-Security` and every `OWNER` placeholder has
been replaced. If one ever comes back with a new file, this finds it:

```bash
git grep -l OWNER
```

## 2. Create the repository and push

Create it **empty** — no README, licence or `.gitignore`, since this repo has
all three and GitHub's versions would conflict.

```bash
git remote add origin https://github.com/Ari-Joon/KAM-Security.git
```

```bash
git push -u origin main
```

## 3. Turn on private vulnerability reporting

Settings → Code security → **Private vulnerability reporting** → Enable.

`SECURITY.md` tells people to use it, and the link in the issue template points
at it. Without this enabled that link 404s and someone will file the
vulnerability publicly instead.

## 4. Check the first CI run

The workflow builds the frontend before cargo, because the shell embeds it at
compile time. Watch the first run finish before announcing anything — a red
badge at the top of the README is a bad first impression.

## 5. Repository settings worth setting

- **Description**: "A control plane for Windows' built-in security, and a
  storage engine that reads the NTFS master file table directly."
- **Topics**: `rust`, `windows`, `tauri`, `ntfs`, `mft`, `security`,
  `disk-usage`, `treemap`, `win32`
- **Releases, Packages, Environments**: turn off in the sidebar until there is
  something in them.
- **Branch protection** on `main`: require CI to pass. Worth it even solo — it
  stops a broken push landing on the branch strangers clone.

## 6. Screenshots

The README currently has none, and for a desktop application that is the single
biggest thing missing. Capture at 1280×800 with the window maximised:

1. **Overview** with real drives — the first impression.
2. **Storage** after a scan of `C:\`, treemap filled. This is the screenshot
   that explains the project faster than any paragraph.
3. **Activity** showing a refusal entry, which demonstrates the audit log doing
   something rather than sitting empty.

Save to `docs/screenshots/`, then add near the top of the README:

```markdown
<p align="center">
  <img src="docs/screenshots/storage.png" width="820" alt="Treemap of a scanned drive">
</p>
```

To get a good Activity shot, run the agent, copy `kam-agent.exe` to a temp
folder and run it with `--probe` from there. It will be refused and recorded.

## 7. Before tagging a release

The release workflow triggers on a `v*` tag and drafts a release with a zip and
a checksum.

```bash
git tag v0.1.0 && git push origin v0.1.0
```

Check first:

- The draft's install notes tell people to keep both executables together. If
  they separate them the shell stops working, and the error will read as a bug.
- Version numbers in `Cargo.toml` and `ui/src-tauri/tauri.conf.json` agree with
  the tag.
- The release is **not** signed. That is stated in the notes; leave it there
  rather than letting someone discover it through a SmartScreen block.

## Deliberately not done

- **No code signing certificate.** About $400/yr and, since 2023, a FIPS 140-2
  hardware token. Not worth it before anyone is using this. Revisit if adoption
  makes the SmartScreen warning a real barrier.
- **No `winget` or Chocolatey package.** Both want a signed, stable release.
- **No CODE_OF_CONDUCT.md.** Add one when there is a community to govern;
  adding it to a repository with no contributors is cargo cult.
