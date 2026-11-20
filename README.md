<p align="center">
  <img src="assets/branding/kam-mark.svg" width="104" alt="">
</p>

<h1 align="center">KAM Security</h1>

<p align="center">
  A control plane for Windows' built-in security, and a storage engine that
  answers questions Windows already knows but never surfaces.
</p>

<p align="center">
  <a href="https://github.com/Ari-Joon/KAM-Security/actions/workflows/ci.yml">
    <img src="https://github.com/Ari-Joon/KAM-Security/actions/workflows/ci.yml/badge.svg" alt="CI">
  </a>
  <img src="https://img.shields.io/badge/license-Apache--2.0-blue" alt="Apache-2.0">
  <img src="https://img.shields.io/badge/platform-Windows%2010%2F11-0a7bbb" alt="Windows 10/11">
  <img src="https://img.shields.io/badge/rust-1.95%2B-b7410e" alt="Rust 1.95+">
</p>

---

Windows ships an excellent antivirus engine and a capable firewall. What it does
not ship is a usable interface to either, or any way to find out where your disk
space went. Consumer suites fill that gap with subscription nagware.

KAM Security is the alternative: one Rust application that drives Microsoft
Defender, manages Defender Firewall, and adds two things nothing else does.

**Real storage attribution.** Control Panel's size column is `EstimatedSize`, a
number the installer writes about itself. It is routinely wrong and never counts
anything outside the install directory.

**Provenance-based judgement.** Rather than asking "does this file match a known
threat" (Defender already does that better), ask what an analyst would: who
signed it and does Windows still accept that signature, when did it arrive,
where was it downloaded from, and how does it survive a reboot. None of those
answers means anything alone. Together they sort several hundred executables
into the two or three actually worth reading about, with the reasoning attached.

It is not a detector and does not claim to be. The evidence is circumstantial by
construction, so nothing in that layer deletes, blocks or quarantines anything.
Presenting circumstantial evidence as a verdict is the whole business model of
the software this replaces.

<p align="center">
  <img src="docs/images/overview.png" width="900" alt="The Overview: protection on, starting at sign-in in the notification area, the update check, and the drives it can see">
</p>

<table>
  <tr>
    <td width="50%"><img src="docs/images/storage.png" alt="Storage: 845 GB across 1.67 million files measured from the master file table in 2.9 seconds, drawn as a treemap"></td>
    <td width="50%"><img src="docs/images/applications.png" alt="Applications: 484 GB actually used against the 55.7 GB Control Panel claims, sorted by real size"></td>
  </tr>
  <tr>
    <td><b>Storage:</b> a whole drive read from the master file table in about three seconds, drawn to scale.</td>
    <td><b>Applications:</b> what each program really occupies, against what its installer claimed.</td>
  </tr>
  <tr>
    <td><img src="docs/images/firewall.png" alt="Firewall: 698 rules, 71 open connections, and every connection grouped by the publisher that signed the program, with a colour legend"></td>
    <td><img src="docs/images/scanner.png" alt="Scanner: Defender's own protections read from Defender, with the same quick or full scan as Windows Security started from here"></td>
  </tr>
  <tr>
    <td><b>Firewall:</b> every open socket, grouped by who signed the program holding it.</td>
    <td><b>Scanner:</b> Defender's real state, and the same scan as Windows Security, started from here.</td>
  </tr>
  <tr>
    <td><img src="docs/images/cleanup.png" alt="Cleanup: ten caches holding 76.9 GB, each marked with whether clearing it costs anything"></td>
    <td><img src="docs/images/overview-activity.png" alt="The weekly check registered for Monday at 09:00, and the audit log of recent activity"></td>
  </tr>
  <tr>
    <td><b>Cleanup:</b> caches that say what clearing them costs; removal goes to quarantine or the Recycle Bin.</td>
    <td><b>Weekly check and audit log:</b> state read in seconds, and every action written down.</td>
  </tr>
</table>

## Reading a terabyte in two seconds

The storage view reads the NTFS master file table directly instead of walking
directories, which is the difference between a coffee break and an eyeblink.

Measured on a 1 TB system drive holding 1.4 million files:

| | Master file table | Directory walk |
|---|---|---|
| First scan after a reboot | **2.4 s** | 57.8 s |
| Repeat scan, warm cache | **2.4 s** | 15.2 s |
| Agreement with the 1036.3 GB Windows reports | **99.6%** | 97.6% |
| Needs administrator rights | yes | no |

The table read was later measured properly rather than assumed, on a 1.8 TB
drive whose table holds **1,912,577 records**. Almost none of the time was the
disk:

| | Before | After |
|---|---|---|
| Reading the table | 2356 ms | **1204 ms** |
| Of that, waiting on the disk | 588 ms | 549 ms |
| Of that, interpreting records | 1768 ms | **655 ms** |
| Building the directory tree | 344 ms | 319 ms |
| Measuring every application | 194 ms | 108 ms |
| **Whole survey** | **2937 ms** | **1668 ms** |

Two gigabytes of records came off an NVMe disk in half a second and took nearly
two to interpret, one at a time, while the disk sat idle. The framing stays on
the reading thread, because a data run can end mid-record and deciding where
records begin has to happen in order; the interpreting moved to a pool of
parsers behind a short queue. Identical output either way, down to the record
count.

The window shows what the measurement cost, with the per-stage breakdown behind
the tooltip. "It feels slow" is not something anybody can act on.

Both figures are given because the walk gains hugely from a warm filesystem
cache while the table barely notices one: it is a single sequential read either
way. Six times faster is the fair claim; twenty-four times is what you see on
the first scan after a reboot.

The walk is slower *and* less accurate: it cannot open every directory, and it
counts a hard-linked file once per link, which on a Windows volume means
counting much of `WinSxS` several times. Both paths produce the same result
type, and the app falls back automatically when it cannot read the table, saying
so rather than quietly taking a minute.

Getting the fast path right needed two things the documentation does not put
front and centre: fragmented files spill their attributes into **extension
records**, and only the `$DATA` fragment starting at **virtual cluster 0** knows
the file's real length. Missing either reports a 138 GB archive as 0 bytes.
Between them they accounted for 270 GB on the test volume.

It also has to know when not to answer. A table in more pieces than its first
record lists, or a read that comes back short, used to give part of a drive
presented as all of it. A disk with 4096-byte sectors could not be read at all.
A boot sector whose figures no real volume has was taken at its word. Each is
now either read properly or refused in words, and when it is refused the scan
walks the folders and says why.

### The list arrives before the sizes

What an installer *claims* about itself is a registry read: every name,
publisher, version, install date and claimed size, in about a fifth of a second,
needing no privileges at all. What it *occupies* needs the whole file table.

So the list appears immediately and can be searched, sorted and grouped straight
away; only the size column waits, and it shows a waiting mark rather than a zero,
because a zero in that column is a claim and it would be wrong for every row on
screen.

### Going deeper, and what grew

The map of a drive arrives four folders deep, which on a gaming and development
PC is above most of what anybody is looking for: `AppData\Local` and a Steam
library's `common` folder used to be rectangles that could not be opened. Now a
folder at that floor opens. The service reads the file table again, finds that
one folder and sends its own tree, built by the same function from the same
index as the drive's, so its figure is the rectangle's figure. It opens the same
way below that, as far as the drive goes.

Each scan of a whole drive also leaves a small summary behind: the total, and
every folder holding 100 MB or more. The next scan is compared with it, and the
Storage page says how much more or less the drive holds since then, draws what
grew (area is bytes grown, a real magnitude) and lists what shrank, which cannot
be an area. A folder missing from the older summary is "under 100 MB then", not
new. A table read is never compared with a folder walk, because they count a
file with several names differently, and a different volume serial is a
different drive. The summaries are kept per person and pruned to a dozen and
one a month.

Storage, Applications and Cleanup open on their last result, each saying when it
was measured, so a page left yesterday is not an empty page today. They are
kept in your own profile, not the service's store.

### Large files nothing has opened in a year

The same table read holds three dates for every file, so Cleanup also lists the
large files, 100 MB or more, in your own folders whose created, last written and
last opened dates are all more than a year old, with each date as a sortable
column. It is a list of sizes and dates and says so: a disk image kept for the
day a machine has to be rebuilt looks exactly like one that was forgotten.
Where Windows is not recording opens, the list is built from the other two
dates and says it was. Each row can go to your Recycle Bin, and if Windows would
not put a file there (it is larger than the bin is set to hold, or the bin is
switched off for that drive) the file is left where it is and the page says so,
because otherwise Windows deletes it outright without a word.

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

1. Reversible first. Cleanup moves things to quarantine or to the Recycle Bin.
   Quarantine puts a thing back with one press for thirty days and then deletes
   it for good, and each item says how long it has left. Deleting sooner is a
   separate step you ask for, and clearing a cache that costs something says
   what it costs first.
2. No scareware. No inflated issue counts, no alarming defaults.
3. Every privileged action is written to an audit log the user can read, and the
   database rejects updates and deletes so it cannot be quietly rewritten.
4. Every finding shows the evidence that produced it.
5. The service never makes a change you could not make yourself. Anything that
   affects the whole machine goes through Windows' own permission prompt.

## Architecture

```
┌─ kam-shell: Tauri window, ordinary user rights ──┐
│  React UI · treemap · no privileges              │
└───────────────────────┬──────────────────────────┘
                        │  named pipe, protected DACL,
                        │  length-prefixed JSON
┌───────────────────────▼──────────────────────────┐
│  kam-agent: Windows service, LocalSystem         │
│  scanner · firewall · storage · quarantine       │
└──────────────────────────────────────────────────┘
```

The UI is a browser engine, and a browser engine must never run as SYSTEM. The
pipe carries a protected DACL, rejects remote clients, and the agent resolves
each caller's executable: being allowed to open the pipe is not the same as
being trusted to drive it.

Being trusted to drive it is not the same as being allowed to change the whole
machine, either. Defender's protections, audit policy, firewall rules, the
protection switch, and clearing a cache outside your own profile all need a
caller Windows has elevated, read from the caller's own token before any
handler runs. The window never runs elevated. It asks with the ordinary Windows
permission prompt, and an approved copy makes that one change and exits.

See [PLAN.md](PLAN.md) for the full design and phase breakdown.

### When the service is not answering

While the window is open it asks the service the smallest question there is,
what version it is, five seconds after each answer. The service answers from
memory and does not write it to the Activity log. Only one question is ever
waiting, and one with no answer after five seconds counts as none, so a service
that has stopped, crashed or hung is noticed within about ten seconds without
questions piling up behind it.

What the window found is said once, above whichever page is open, and stays in
view as the page scrolls:

- **Not answering**, since when, and what that means: if the service itself has
  stopped, nothing is watching what starts itself or checking new downloads,
  and what is on screen was read before it stopped answering.
- **From a different install**, when the service answers in a version of the
  pipe's language the window does not speak. The two would misread each other,
  so the pages are not to be relied on until KAM Security is installed again.
- **Turned this window away**, in the service's own words. That is usually a
  copy of the window kept outside the service's folder, and the service writes
  each such caller to the Activity log, so the window then asks once a minute.
- **Answering again**, and when, for fifteen seconds.

While the service answers, nothing is said at all. A line that always says all
is well is one people stop reading. The window never starts, stops or restarts
the service, and the icon in the notification area asks nothing while the
window is closed.

## Status

Phases 0 to 4 are complete and phase 5 is in progress. Nothing claims to be
finished software.

| Phase | Scope | State |
|---|---|---|
| 0 | Workspace, CI, tooling | Done |
| 1 | Agent, IPC, audit log, shell | Done |
| 2 | Storage intelligence | Done |
| 3 | Scanner | Done, plus a behaviour watcher, canary files, a browser extension inventory and a Defender hardening report |
| 4 | Firewall | Rules, connections and one-click block done; ETW watcher deliberately deferred |
| 5 | Installer, scheduler, polish | Setup script, scheduler, cleaning, tray icon and update check done; **no signed installer** |

The honest gap: there is no signed installer. A release is a zip with a setup
script, and SmartScreen warns about it on first run (see
[A note on antivirus warnings](#a-note-on-antivirus-warnings)).

Phase 2 covers: the master file table reader, a zoomable treemap, true
application footprint across every location an app touches, uninstalling from
within the app, orphan detection for software uninstalled long ago, download
provenance from the `Zone.Identifier` stream, byte-for-byte duplicate detection,
and proposals for filing loose downloads into folders you already keep.

Phase 3 so far covers: Defender's real state read from Defender rather than from
the Settings app, and the provenance engine: Authenticode verification against
both embedded signatures and the system catalogues, arrival times, download
origin, and every place a program anchors itself to survive a reboot (Run keys
in both hives and both registry views, services, scheduled tasks and the Startup
folders). Sources it could not read are reported rather than silently omitted.

Scans are Defender's own. A quick or full scan started here is the same scan as
the button in Windows Security, so Defender deals with what it finds the way it
is set up to, usually by quarantining it where Windows Security can restore it.
When the scan ends, KAM lists what Defender recorded, by name, and a history it
could not read is shown as unread rather than as a clean result. Defender's own
switches (cloud protection, blocking of potentially unwanted apps, the attack
surface reduction rules) are read from where Defender keeps them, including
audit mode and settings an organisation's policy controls.

It also matches YARA rules against those same executables. They are aimed not
at malware, which Defender handles, but at the grey band Defender deliberately
tolerates:
bundled adware installers, scareware optimisers, browser hijackers, miners, and
the fetch-and-run patterns that only exist as text. Rules carry their own
plain-English explanation, and you can drop your own `.yar` files into
`%ProgramData%\KAM Security\rules` to have them matched alongside.

Three of those rules exist because of a specific infection, described under
[Watching what starts itself](#watching-what-starts-itself) below: one for
browser credential theft (the exact on-disk names of the password, cookie and
key stores a stealer reads), one for a build tool used as a loader (an MSBuild
project file carrying inline code that reflectively loads a payload), and the
provenance engine learned to judge what a launcher is *told* to run rather than
the launcher itself.

The rule engine runs in the **unprivileged shell**, not in the LocalSystem
agent. `yara-x` compiles rules to WebAssembly and executes them through a JIT,
which does not belong inside the most privileged process in a security product.
That split works because privilege is needed to *find* the interesting
executables (services, scheduled tasks, both registry hives) but not to read
them. The agent finds; the shell matches. A test in the agent fails the build if
the rule engine ever creeps back across that line.

With a free VirusTotal API key you can also ask about an individual file. Only
the file's SHA-256 is sent; the file itself is never uploaded, and there is no
code in the project that could upload it. Every lookup is one deliberate click
on one file. Nothing runs in bulk or in the background, because telling a third
party which files sit on your machine is a decision to make each time rather
than a behaviour to discover. The key is yours, stored encrypted under your
Windows account with DPAPI, and none ships with the product.

Long jobs (the provenance survey and duplicate detection) report what they
are doing as they do it, and can be stopped. A scan behind a disabled button is
indistinguishable from one that has hung, and people reasonably assume the
second. The agent streams named stages and counts down the same pipe that
carries the result, and a second connection carries the request to stop.

They also carry on when you open another page, and the page finds them again.
A Storage scan, Applications' Measure, Cleanup's searches, a Defender scan and
the Scanner's Examine run in the window's own half rather than inside the page,
so coming back shows how far the job has got and its Stop button, or what it
came to and when it finished. A job that failed meanwhile says which job it
was, when it ended and why, and is never shown as nothing found. One of each
runs at a time. The results Storage, Applications and Cleanup already kept on
disk are still kept there and nowhere else; the Defender scan's, Examine's and
the loose files' are kept until the program quits. Closing the window to the
notification area is not a Stop either, and the result is there when the
window is opened again. Only quitting the program loses an answer that has not
arrived yet.

Results are reported as "N of M engines", never as a bare count. A handful of
detections against a large majority is the everyday signature of a false
positive, and the interface says so in as many words rather than colouring it
red.

### What Windows already knows, in one place

Some of the plainest facts about a PC's safety are known to Windows and shown
across several of its screens, or none. KAM gathers four of them, each with
where it came from, and none with a verdict:

- **Windows Update**, on the Overview: the build Windows is on, the newest
  update to the system itself and when it was installed (matched by the running
  build, not by the date of the last thing installed, which counts Defender's
  daily definitions and Store apps), whether a restart is waiting, and whether
  updates are paused and until when. It never says "up to date": from the PC
  alone nobody can know whether a newer update exists.
- **Newer versions, according to winget**, on Applications: one button asks
  winget, Windows' own package tool, which installed programs have a newer
  version. It runs as you, uses the network and takes seconds, so it runs only
  when asked. It lists, and never installs. winget prints a table rather than
  data, so the table is read by column position and checked against winget's
  own count, and an answer that does not add up is said to be one that could
  not be read.
- **This device**, on the Scanner: Secure Boot, the security chip (TPM), whether
  drive C: is encrypted, and whether Remote Desktop is on and anything is
  listening for it. An empty answer is "could not be read", never "none".
- **What Defender has been told to skip.** Windows shows Defender's exclusions
  only to an administrator, on purpose: they tell an attacker where Defender
  does not look. So the panel shows nothing about them, not even how many,
  until you press its button and approve Windows' own permission prompt. The
  list is gone when you leave the page, and the Activity log records that it
  was read and how many entries it held, never the entries.

## Cleaning, and what it refuses to do

There is no registry cleaner and no health score. Both are how this category of
software makes money and neither has ever made a machine faster.

What is here is the real list: temporary files, update downloads and what
Windows keeps while upgrading itself, crash dumps, error reports, logs,
thumbnails, shader caches, browser caches, developer package caches, driver
installers a vendor's app has already used, the caches of chat programs, editors
and game engines, Steam scratch, and a previous Windows that never removed
itself. On the machine this was written on that came to **105 GB**, of which
51.7 GB was one graphics shader cache whose own size limit was plainly not
working. Each entry says what it holds and what clearing it costs, and the ones
that cost something say so rather than being presented as free.

Beside it is a second list, of large things that are not caches: the
hibernation file, the page file, restore points, what websites themselves stored
in a browser, downloaded AI models, the copies Windows Installer keeps. They are
where a person looks next once the caches have gone, and left unexplained they
invite deleting by hand. So each is measured and says what it is for and which
setting decides its size, and none of them has a button. A request to clear one
is refused by name. On the same machine that list came to 87.8 GB.

Prefetch is deliberately absent: clearing it is folklore, and it makes the next
launch of everything slower for a few megabytes. The component store is left
alone too: it looks enormous and is mostly hard links to files in use.

Clearing runs in the agent, so the interface names an **id** from a compiled-in
catalogue and never a path. There is no request shape that carries a directory
to empty, because there is no version of that which is safe in a LocalSystem
process. Only contents go, never the folder; a junction is removed as a link
rather than followed, because a junction inside a cache pointing at your
documents would otherwise mean emptying the cache emptied the documents. The
same holds for a link above a cache. A location is cleared only when the folder
being held open really is the place the catalogue names, which is asked of the
open handle and not of the path, so a folder swapped for a link part-way down
cannot lead the clear somewhere else.

### Duplicates that are not waste

Identical is not the same as spare. Windows keeps several copies of the same
library on purpose, every installer keeps a second copy of itself so it can
repair later, and two programs shipping the same runtime each look for it beside
themselves. A list calling all of that "wasted" is a list that gets somebody to
break their own machine.

So every copy is judged by where it lives, and there are two numbers rather than
one, *duplicated* and *reclaimable*, which are usually very different. Only a
copy in a folder you own is ever offered, anything it cannot attribute is shown
without a recommendation, and removing one goes through quarantine like
everything else. A list of duplicates is true of the moment it was made, and the
page keeps it, so before a copy goes it is compared in full with the copy that
stays. One edited since the search is refused, because it may now hold the only
copy of what it contains.

## The firewall

Windows Defender Firewall works. What it lacks is a way to see what it has been
told to do, and what is happening now. KAM Security shows both: profile state
and all several hundred rules, and every open socket joined to the program that
owns it and to whoever signed that program. `netstat -b` gets closest to the
second and tells you nothing about signing; Resource Monitor shows names without
paths. "chrome.exe is connected to 142.250.x.x" is not useful; "an unsigned
program in your AppData folder is connected to the internet" is.

Blocking a program adds exactly one outbound rule, on every profile, tagged with
a group of our own. That tag is what makes removal safe: this product will only
delete rules carrying it, so a rule Windows or an installer created cannot be
removed here even by mistake, and there is a test asserting it refuses to touch
Windows' own "Core Networking" rules. Existing rules are read and shown, never
edited. Blocking asks first and says exactly what it will do.

Everything else the plan listed for the firewall (prompting *before* a
connection opens) is permanently out of scope. It needs a kernel driver, an EV
certificate and Microsoft attestation signing.

## What changed since last time

Every other view reports what is true now. **Changes** reports what is
different: services, Run keys, Startup items, scheduled tasks and local
administrators, compared against a baseline and charted over twelve weeks.
There is no score, because a score needs an idea of what a correct machine
looks like, and this software does not have one.

<p align="center">
  <img src="docs/images/changes.png" width="900" alt="Changes: fifteen things different since the last look, with a source that could not be read said out loud rather than reported as gone">
</p>

Things disappearing count at least as much as things appearing. An antivirus
service or a backup task quietly removed is reported, and Windows reports that
nowhere else. It also notices when an entry's path stays the same but the file
behind it is now signed by someone else, or by nobody. Changes this program
made itself are labelled rather than hidden, so malware cannot hide by using
its name.

Each comparison's list is kept as it was shown, so opening the page no longer
uses one up: earlier comparisons are offered by date and can be read again.
The weekly check takes a comparison too, so a week in which nobody opened the
page is still looked at, and each list says what took it. Something looked at
for the first time, a whole account's startup places or a kind of thing this
version reads differently, is recorded quietly and said, never announced as
having appeared.

## Downloads

Most of what ends up running on a machine arrived through the Downloads
folder, so **Active downloads** watches it while KAM Security is running.
When a file finishes arriving (its size has held still and nothing is still
writing it), Defender is asked about it straight away, and the answer is
recorded with the file's size, SHA-256, the site it came from and, for a
program, who signed it. Defender decides what is flagged. The page shows its
answer by name and never adds anything up into a score, and nothing is moved
or deleted unless you press a button. The watching waits on Windows to say
something changed, so it costs nothing while nothing arrives. A file that is
gone before it could be checked, which is what Defender's real-time protection
does to one it objects to, is recorded as exactly that, with what Defender's
own history says about it.

The check is report-only, and that turned out to matter. Asked to report
rather than act, Defender records **nothing**: tested with the EICAR test
archive, it named the threat and the file inside the zip on its console and
left no entry in its detection history or its event log. Letting it act so
that it records would mean letting it act on a path in a folder anybody can
write to. So the console is read, under rules that cannot make anything look
better than it is: Defender's exit code decides whether anything was found,
its own counts must match the list that follows, and a check that did not
finish says so and is never shown as Defender having found nothing. A
password-protected archive is the same trap from the other side. Defender
reports no threat in what it could not open, so the page reads the archive's
own list and says how many of its files Defender could not look inside.

The service checks a file only through the one handle your own account was
able to open, and holds it until the check is over. The file it was asked
about and the file it read are then the same file, and nothing can swap one
for the other in between. For the same reason it will not check a file that
another program still has open for writing. The page says so, and the file
can be checked again once that program has finished with it.

A zip can be taken apart. If Defender flagged it, the original goes to
quarantine first, and its row keeps a button that puts it back. A private copy
is made and held open from the moment it is written, Defender is asked about
that copy, and its fingerprint has to be the one the check came back with
before anything is offered. Every file inside is listed with Defender's
answer, and one button extracts the files it did not flag into a new folder in
your Downloads folder, "name (checked by KAM)". Nothing Defender flagged is
ever written, and neither is a password-protected file (Defender could not
look inside it), a link, a name built to land somewhere else, or a file whose
name could be mistaken for the one Defender named. Every extracted file keeps
the mark Windows puts on downloads, so SmartScreen still sees it, and one that
could not be given the mark is listed by name. Defender sometimes flags an
archive as a whole rather than a file in it, and then no part of it can be
told apart from the rest, so nothing is offered. A file Defender removes the
moment it is written is listed as removed, with the detection that took it,
and is not counted as extracted.

Files that were already in Downloads, or arrived while KAM Security was not
running, are listed as not checked yet, and one button checks them all, one
after another, with a Stop. Each goes through exactly the check a single file
gets. A file kept only online by OneDrive is skipped and named, because reading
it would download it, and no notification is raised for any of them: what the
run came to is said once, on the page.

With Windows notifications switched off, a flagged download would otherwise
make no sign anywhere. So the downloads Defender flagged, and the checks that
did not finish, since you last opened the page are counted beside its name in
the menu and in one line on the Overview. Opening the page clears the count,
and the page then says what was new. When you last looked is kept in your own
part of the registry, so each account has its own. A count that could not be
made shows a question mark with the reason, never a zero.

The list can be searched by name, filtered (flagged, not finished, not checked
yet, still here, gone) and put in order. A row can be removed from it, or the
whole list cleared, and both are real deletion of the record, never of the
file. The Activity log keeps its own entry of each check, and of each removal.

Defender's names carry their own category, and the page says what each one
means. `HackTool:` and `PUA:` are Defender saying a program is a dual-use or
unwanted tool rather than malware, which is common for open-source utilities.
Whether to keep one is your decision, made in Windows Security under Protection
history, Allow on device. KAM does not override Defender and has no way to. A
name ending in `!ml` means Defender's machine-learning model flagged it rather
than a known signature, and the page says that as a fact.

The extracting is done by the window, as you, never by the service. Writing
files under names chosen by whoever made an archive is exactly how a hostile
zip writes outside the folder it is unpacked into, and in a LocalSystem
process that would mean anywhere. A test fails if an archive reader ever
reaches the service.

Right-click any file for "Check with KAM Security", or a zip for "Extract with
KAM Security" (on Windows 11, under "Show more options"). Several files chosen
at once are dealt with in turn. Both entries are added for your account the
first time KAM Security runs and can be unticked on the page. New downloads also raise a Windows notification, which needs a KAM
Security shortcut in your Start menu, so the app keeps one there. If Windows
notifications are switched off, the page says so rather than staying quiet.
Other archives (7z, RAR, disc images) are checked as a whole.

## Watching what starts itself

Everything above judges the machine at rest, when someone opens the window and
asks. That is the wrong shape for one kind of threat, and this section exists
because of a real one.

A machine this tool runs on was infected by an infostealer, downloaded inside a
file pretending to be a game update. It ran for about three minutes, copied the
browser's saved passwords and login cookies, and left behind a **hidden
scheduled task** that re-launched itself at every sign-in by handing a project
file to **MSBuild**, a Microsoft-signed build tool that antivirus trusts and
whose project files it does not read. Windows Defender never flagged any of it.
A full offline Defender scan eventually removed one dropped file; the task, the
launcher and the second-stage payload sat untouched until they were taken apart
by hand.

Two things in that story are the point. The malware ran while nobody was
looking, and it survived by wearing a trusted program's face. So the agent now
does one thing without being asked: every couple of minutes it takes the same
cheap snapshot the weekly check does (the Run keys, the Startup folders, the
services, the task store), and anything that has newly appeared in the shape
unwanted software uses to run unseen is written to the audit log and shown in
**Scanner → What has started itself lately**, with the evidence attached. The
shapes it knows are the ones that infection used:

- a launcher (`cmd.exe`, `PowerShell`, `MSBuild`, `rundll32`) told to run a
  script or project from a folder any program can write to
- a scheduled task marked **hidden**, so it never shows in Task Scheduler
- a new sign-in or Startup entry pointing at an unsigned script in AppData or
  Temp
- an unsigned installer run from Temp claiming a hardware vendor whose real
  installers are always signed

It never stops, deletes or blocks anything. Killing a process a second late is
theatre, and acting automatically on circumstantial evidence is the behaviour
this whole product is an alternative to. What it does is make sure a person can
see it within the minute rather than after a day, which is the only thing that
was actually missing the first time.

This is honest about its cost. The rest of the agent makes a point of no
measurable CPU while idle; the watcher spends a little of that on one registry
read a couple of times a minute. That trade is written down here rather than
hidden, and the snapshot is deliberately not a scan.

### The quiet places, and where traffic goes

A few places can start a program without appearing in any list of what starts
itself: the Windows sign-in programs (`Userinit` and `Shell`), a debugger
redirection under Image File Execution Options, a per-account sign-in script,
`AppInit_DLLs`, a WMI event subscription that runs a command, and a per-account
COM class that quietly replaces the one a scheduled task uses. On a normal
machine every one of them is exactly as Windows ships it, so they are compared
against Windows' own values and say nothing until one departs from them. The
watcher and What changed both read them, and the Scanner page names them in one
line when nothing is set.

Three small settings decide where a browser's traffic really goes: the hosts
file, DNS servers set by hand, and a proxy. All three are things people set on
purpose, and all three are what adware changes. The Firewall page shows each
with where it was read from, and What changed notices when one moves. Only DNS
servers set by hand are compared; the ones a network hands out change with every
network joined.

A certificate in the trusted root store lets whoever holds its key show any
website to this PC with a valid padlock. The Scanner page lists every trusted
root by store and names each one that is not on Microsoft's published list, as
Windows last fetched that list, with no request of its own. On the machine this
was written on that is a game launcher's local certificate and two Microsoft
roots that expired in 1999. Not being on the list is a fact, not a verdict.

Browser extensions loaded from a folder rather than a store never appear in the
browser's extension folder, so the browser's own settings file is read for them
as well. Each of these is a kind in What changed with its own quiet first look,
so the first comparison after this was added reported none of them as new.

## Files that exist only to be stolen

Everything above weighs circumstantial evidence, and says so. This does not.

A canary is a file with no legitimate reason to be touched: a fake saved-password
database, a fake wallet, a fake recovery phrase. Nothing on the machine uses
them, no backup job wants them, and nothing but this program knows they exist. So
if something reads one, there is no innocent explanation to weigh against: it is
close to proof that a program is going through your files looking for
credentials. The idea is borrowed from [canarytokens.org](https://canarytokens.org),
which does it with documents that phone home; this does it locally, so nothing
ever leaves the machine.

It works through Windows' own auditing. Each decoy gets a **SACL** asking for an
event whenever anyone reads it, and Windows then records event 4663 in the
Security log naming the file, **the process that read it**, and the account. No
driver, no hooking, no third party, no network. The answer is not "something read
your documents" but "this program, at this time, as this user", which is the
difference between knowing you were robbed and knowing who did it.

Switching on file auditing changes a Windows setting, so this is opt-in twice
over: planting decoys only writes files, and switching on auditing is a
separate, reversible action that says exactly what it does and goes through
Windows' permission prompt. It is narrower than it sounds: the subcategory only
produces events for objects
carrying a SACL, and almost nothing on a normal machine does, so five decoys do
not make a noisy Security log.

### Always on, and one switch to stop it

The agent is a Windows service: automatic start, LocalSystem, and set to restart
itself 5 seconds, 15 seconds and 60 seconds after a crash. Closing the window
does not stop it, and neither does signing out. There is nothing to remember to
launch.

It can be stopped in exactly two places. **Overview → Protection** has a switch,
and turning it off stops the watching within a few seconds. That does *not* stop
the service, on purpose twice over: something has to remain running to switch it
back on, and a security tool that can be silenced through its own interface is
one an attacker silences. Stopping the service itself takes Task Manager or an
administrator, which is a deliberate act by somebody already in charge of the
machine.

Turning the switch off or on raises Windows' own permission prompt, the same
consent Windows Security asks for, so nothing running on the machine can switch
it off without you agreeing.

The same switch is available headlessly. Reading it needs nobody special;
changing it needs an administrator terminal, for the same reason:

```
kam-agent.exe --protection
kam-agent.exe --protection-off
kam-agent.exe --protection-on
```

The setting is remembered across restarts, and a store that has never been
written, or cannot be read, reads as *on*. Failing closed is the wrong default
for a light switch and the right one for this.

The window is separate from all of this. The first time KAM Security runs, it
adds itself to your sign-in items so its icon sits by the clock from then on,
with no window until you open one. It says so on the Overview, beside the
checkbox that turns it off. Closing the window leaves the icon, and the tray's
**Close the icon (protection keeps running)** does exactly what it says: the
service carries on either way.

### The registry gets decoys too

Documents are only half of where a thief looks. Several programs people rely on
keep connection details in the registry under well-known paths: PuTTY stores
every saved session with its hostname and username, WinSCP stores its sessions
with a reversibly-encrypted password beside them, and the Remote Desktop client
records the machines you have connected to and the account you used. All of it is
enumerated by stealers, because it maps out what else of yours is reachable.

So there are decoy sessions there as well, watched the same way. Two details
differ and both are handled: registry auditing is a **separate subcategory** from
file auditing, so switching canaries on switches both (a decoy that produced no
events because only half the policy was set would look like an all-clear), and
Windows names a registry object in the kernel's own namespace
(`\REGISTRY\USER\<sid>\…`) rather than the form anyone types, so the event
matching accounts for that.

A decoy session is a subkey alongside any real ones, never a value inside
somebody's own session, and each is named `KAM-Security-decoy-do-not-use` so that
a person who finds one in their own PuTTY list can tell at a glance it is not
theirs. A stealer enumerates every session under those paths rather than opening
one by name, so a decoy does not need to deceive anybody to be found.

**This half spent ten weeks switched off, and the reason is worth reading.** On
the machine it was built on, the agent created the keys and every check it made
agreed they were there: the create call succeeded, the key reopened, the marker
value read back, and the kernel wrote audit events for successful opens of those
exact paths. Yet `reg.exe`, `Test-Path` and .NET's `OpenSubKey` all reported the
leaf missing, and `OpenSubKey` returned null rather than throwing, so it was
"not found" rather than a permissions problem.

If the account's own tools cannot see a key, an infostealer running as that
account cannot see it either, so the decoy would never be read. A canary that is
never read is not protection. It is a line in the interface claiming protection
that does not exist, which is worse than the feature being absent, because it
stops somebody looking further. So planting was held behind one flag until the
disappearing keys were explained.

The keys had never disappeared. Every tool that reported them missing had been
started from the same terminal, and that terminal belonged to a desktop app
installed as an MSIX package. Windows gives a packaged app, and everything
started from it, a private view of the registry, and in that view those paths
had been marked deleted by this project's own tests, which had been run from the
same terminal. The same query from a process started outside the app showed all
three decoys, and the Decoys panel reported the read a moment later, naming
`reg.exe`. Every observation had been true. The mistake was taking the view
from one place for the state of the machine. Registry decoys are on.

The rules it holds itself to are worth stating, because the decoy paths are
deliberately chosen to look like things people really keep:

- **Nothing is ever overwritten.** A decoy is only created where no file exists.
- **Nothing is planted inside another program's data**, so a canary cannot
  confuse a browser, a wallet, or the tools that read your real `.ssh` folder.
- **Nothing is deleted that this program did not write.** Removal reads a marker
  inside the file first and refuses anything without it.
- **The contents are worthless.** Every decoy says inside what it is, so nobody
  is misled by their own file and an attacker who takes one gains nothing.

## Running it

Prebuilt binaries are on the [releases page](https://github.com/Ari-Joon/KAM-Security/releases).
Unzip anywhere and **keep every file in the same folder**, because the agent only
serves clients installed alongside it. Then right-click `setup.ps1` and choose
**Run with PowerShell**, or from a terminal:

```
powershell -ExecutionPolicy Bypass -File setup.ps1
```

It asks for administrator rights once, locks the folder so only administrators
can change what is in it, registers the service that makes the fast disk scan
possible, and puts a shortcut on your desktop. `setup.ps1 -Remove` undoes those
things. The sign-in entry belongs to the app rather than the script, so untick
**Start KAM Security when I sign in** on the Overview first if you are removing
it for good.

You can skip the script and just run `kam-shell.exe`. The app still works, and
the disk scan falls back to walking directories, which is slower.

To upgrade, run `setup.ps1 -Remove` from the old folder, then set up the new
release the same way. Quarantined items and the audit log are kept.

To build from source, see [docs/SETUP.md](docs/SETUP.md).

### Updates

Once a day, and whenever you press **Check now** on the Overview, KAM Security
asks GitHub's public API for the newest release and compares it with its own
version. If there is a newer one, it shows the version, the date and the notes,
and a button that opens the release page. It sends nothing about the machine,
and the daily check can be switched off.

It never downloads or installs anything itself. The service runs as
LocalSystem, so anything an updater installed would run with the highest
privilege Windows has, and doing that automatically needs signed releases
first. A check that fails says it could not tell. It never says you are up to
date when it does not know.

## A note on antivirus warnings

This application enumerates every file on disk, reads raw volumes, runs an
elevated service and edits firewall rules: the same behaviours malware
exhibits. Releases are unsigned, so SmartScreen will warn on first run and some
scanners may flag the binaries.

That is the honest cost of the category. The source is published in full, the
binaries are never packed or obfuscated, and every release ships a SHA-256
checksum. Building it yourself is the strongest guarantee available, and takes
one command.

Staying unsigned is a decision rather than an oversight, and it is recorded as
one in [PLAN.md](PLAN.md). It has a consequence worth stating: this product's
own weekly check reports **its own agent** as carrying no signature, by name,
alongside anything else on the machine that does. A program that reports on what
starts itself and then quietly omits its own entry would not be worth trusting
about anything else.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md), which includes the list of things that
are permanently out of scope, worth reading before writing anything large.

Security issues go through [SECURITY.md](SECURITY.md), privately. Never a public
issue: the agent runs as LocalSystem.

## Licence

[Apache-2.0](LICENSE). Dependencies are held to permissive licences by
`cargo deny`, which is what keeps a copyleft library from quietly making the
whole project GPL.
