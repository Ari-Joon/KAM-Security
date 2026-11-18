<#
.SYNOPSIS
    Set KAM Security up after unzipping it, or take it back off.

.DESCRIPTION
    A download is two executables in a folder. Without this, somebody has to
    read the README, open an administrator terminal, and know that the fast disk
    scan needs a service, which is three steps too many for the first minute of
    using something.

    This registers the service and puts a shortcut on the desktop. It does not
    add anything to the run keys, and it does not start the window at logon:
    this product reports on what starts itself at boot, and quietly adding
    itself to that list while doing so would be indefensible.

    Everything it does is undone by `-Remove`, which is the same argument in
    reverse rather than a separate script that can drift out of step. The
    sign-in entry is not among them: the app adds that itself the first time
    it runs, so it is switched off from the app's Overview, not from here.

.PARAMETER Remove
    Stop and unregister the service and delete the shortcut. Also removes the
    right-click entries and the Start menu shortcut the app adds for whoever
    runs it, when they point at this folder's kam-shell.exe.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File setup.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File setup.ps1 -Remove
#>
[CmdletBinding()]
param(
    [switch]$Remove
)

$ErrorActionPreference = 'Stop'

# The two executables live beside this script in a release, and one directory up
# from it in the source tree. Both are supported so the same file can be tested
# where it is written and shipped where it is used.
$here = $PSScriptRoot
$agent = Join-Path $here 'kam-agent.exe'
$shell = Join-Path $here 'kam-shell.exe'
if (-not (Test-Path $agent)) {
    $here = Join-Path (Split-Path $here -Parent) 'dist'
    $agent = Join-Path $here 'kam-agent.exe'
    $shell = Join-Path $here 'kam-shell.exe'
}

foreach ($needed in @($agent, $shell)) {
    if (-not (Test-Path $needed)) {
        throw "$(Split-Path $needed -Leaf) is not next to this script. Unzip the whole download into one folder and run it from there."
    }
}

$shortcut = Join-Path ([Environment]::GetFolderPath('Desktop')) 'KAM Security.lnk'

# The identity the app gives itself when it starts (see notice.rs), so the
# window, its taskbar button, its notices and this shortcut are one
# application to Windows. Written onto the shortcut below.
$appId = 'com.kamsecurity.shell'

# What the app adds for the person who runs it, in their own hive and Start
# menu: the right-click entries and the Start menu shortcut notices need. Taken
# away by -Remove when they point at this folder's kam-shell.exe, and left
# alone when they belong to another copy.
function Remove-UserEntries {
    param([string]$Shell)
    $removed = @()
    foreach ($key in @(
            'HKCU:\Software\Classes\*\shell\KAMSecurity.Check',
            'HKCU:\Software\Classes\SystemFileAssociations\.zip\shell\KAMSecurity.Extract')) {
        $command = Get-Item -LiteralPath "$key\command" -ErrorAction SilentlyContinue
        if ($command -and ([string]$command.GetValue('')).ToLowerInvariant().Contains("`"$($Shell.ToLowerInvariant())`"")) {
            Remove-Item -LiteralPath $key -Recurse -Force
            $removed += 'right-click entry'
        }
    }
    $startLink = Join-Path ([Environment]::GetFolderPath('Programs')) 'KAM Security.lnk'
    if (Test-Path -LiteralPath $startLink) {
        $target = (New-Object -ComObject WScript.Shell).CreateShortcut($startLink).TargetPath
        if ($target -and $target -ieq $Shell) {
            Remove-Item -LiteralPath $startLink -Force
            $removed += 'Start menu shortcut'
        }
    }
    foreach ($item in $removed) { Write-Host "  $item removed" -ForegroundColor Gray }
}

# Writes the identity onto a shortcut. WScript.Shell cannot, so this goes
# through the shortcut's property store, as Windows' own installers do.
function Set-ShortcutIdentity {
    param([string]$Link, [string]$Id)
    if (-not ('KamIdentity' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class KamIdentity {
    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    struct PropertyKey { public Guid FormatId; public uint PropertyId; }
    [StructLayout(LayoutKind.Explicit)]
    struct PropVariant {
        [FieldOffset(0)] public ushort Type;
        [FieldOffset(8)] public IntPtr Pointer;
        [FieldOffset(16)] public IntPtr Spare;
    }
    [ComImport, Guid("886D8EEB-8CF2-4446-8D02-CDBA1DBDCF99"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    interface IPropertyStore {
        void GetCount(out uint count);
        void GetAt(uint index, out PropertyKey key);
        void GetValue(ref PropertyKey key, out PropVariant value);
        void SetValue(ref PropertyKey key, ref PropVariant value);
        void Commit();
    }
    [DllImport("shell32.dll", CharSet = CharSet.Unicode, PreserveSig = false)]
    static extern void SHGetPropertyStoreFromParsingName(string path, IntPtr context, int flags, ref Guid iid, [MarshalAs(UnmanagedType.Interface)] out IPropertyStore store);
    [DllImport("ole32.dll")]
    static extern int PropVariantClear(ref PropVariant value);
    public static void Set(string link, string id) {
        Guid iid = new Guid("886D8EEB-8CF2-4446-8D02-CDBA1DBDCF99");
        IPropertyStore store;
        SHGetPropertyStoreFromParsingName(link, IntPtr.Zero, 2, ref iid, out store);
        PropertyKey key = new PropertyKey { FormatId = new Guid("9F4C2855-9F79-4B39-A8D0-E1D42DE1D5F3"), PropertyId = 5 };
        PropVariant value = new PropVariant { Type = 31, Pointer = Marshal.StringToCoTaskMemUni(id) };
        try { store.SetValue(ref key, ref value); store.Commit(); }
        finally { PropVariantClear(ref value); Marshal.ReleaseComObject(store); }
    }
}
'@
    }
    [KamIdentity]::Set($Link, $Id)
}

# --- elevation ------------------------------------------------------------
#
# Registering a service needs it. The script relaunches itself rather than
# telling somebody to go and find an administrator terminal, and quotes its own
# path, because the folder this is unzipped into very often has a space in it.
$identity = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $identity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'Asking for administrator rights (registering a service needs them)...' -ForegroundColor Cyan
    $arguments = @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass',
        '-File', "`"$PSCommandPath`""
    )
    if ($Remove) { $arguments += '-Remove' }

    try {
        $child = Start-Process -FilePath 'powershell.exe' -ArgumentList $arguments -Verb RunAs -PassThru -Wait
    } catch {
        Write-Host 'Administrator rights were not granted, so nothing was changed.' -ForegroundColor Yellow
        exit 1
    }

    # The person's own entries are removed here, in this pass, and not only in
    # the elevated one. When an administrator elevates on behalf of a standard
    # account, the elevated pass runs as the administrator, so its HKCU and
    # Start menu are the administrator's, not this person's. This pass runs as
    # whoever started the script. Only after the elevated half succeeded, so a
    # refused or failed removal leaves everything as it was.
    if ($Remove -and $child.ExitCode -eq 0) {
        Remove-UserEntries -Shell $shell
    }
    exit $child.ExitCode
}

# --- removal --------------------------------------------------------------
if ($Remove) {
    Write-Host 'Removing KAM Security...' -ForegroundColor Cyan

    Get-Process kam-shell -ErrorAction SilentlyContinue | Stop-Process -Force
    & $agent --uninstall
    if ($LASTEXITCODE -ne 0) { Write-Host '  the service could not be unregistered' -ForegroundColor Yellow }
    else { Write-Host '  service unregistered' -ForegroundColor Gray }

    if (Test-Path $shortcut) {
        Remove-Item $shortcut -Force
        Write-Host '  desktop shortcut deleted' -ForegroundColor Gray
    }

    # Started already elevated by the person themselves, this is their hive.
    # Elevated by somebody else, it is that administrator's, and only entries
    # pointing at this folder are touched either way; the unelevated pass
    # above handles the person's own.
    Remove-UserEntries -Shell $shell

    Write-Host ''
    Write-Host 'Done. The folder you unzipped can now be deleted.' -ForegroundColor Green
    Write-Host 'Quarantined items and the audit log are left in' -ForegroundColor Yellow
    Write-Host '  C:\ProgramData\KAM Security' -ForegroundColor Yellow
    Write-Host 'so nothing you moved is lost by uninstalling. Delete it yourself if' -ForegroundColor Yellow
    Write-Host 'you want it gone.' -ForegroundColor Yellow
    exit 0
}

# --- install --------------------------------------------------------------
Write-Host 'Setting KAM Security up...' -ForegroundColor Cyan

# Secure the folder before registering anything to run out of it.
#
# The agent runs as LocalSystem, so whoever can write next to it decides what
# LocalSystem executes. The default outcome of the obvious action gets this
# wrong: a folder unzipped into Downloads, the Desktop or anywhere else in a
# user profile inherits Authenticated Users: Modify, so an ordinary account can
# replace the agent, or drop a `powershell.exe` beside it for the agent to find
# ahead of the real one. Neither needs elevation.
#
# The agent refuses to register from a folder in that state, so without this the
# honest outcome would be setup failing on most machines with a message about
# permissions. Correcting it is better than explaining it: this script already
# holds the administrator rights required.
#
# Well-known SIDs rather than names, because those are localised and this has to
# work on a machine in any language:
#   S-1-5-32-544  Administrators      full
#   S-1-5-18      LocalSystem         full, this is what runs the agent
#   S-1-5-11      Authenticated Users read and execute, never write
& icacls $here /inheritance:r /grant:r `
    '*S-1-5-32-544:(OI)(CI)F' `
    '*S-1-5-18:(OI)(CI)F' `
    '*S-1-5-11:(OI)(CI)RX' | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "the install folder could not be secured (icacls exit $LASTEXITCODE); the agent will not run from a folder anybody can write to"
}

# The list alone is not enough: Windows lets a folder's owner rewrite its list
# whatever the list says, and the owner of an unzipped folder is the ordinary
# account that unzipped it. That account could grant itself write access again
# at any moment and replace the agent, so the folder and everything in it are
# handed to Administrators. The agent refuses to register from a folder an
# ordinary account owns.
& icacls $here /setowner '*S-1-5-32-544' /T /Q | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "the install folder could not be handed to Administrators (icacls exit $LASTEXITCODE); its owner could make it writable again"
}
Write-Host '  install folder secured (administrators only can write, and own it)' -ForegroundColor Gray

# The store, for the same reason and a sharper one.
#
# The audit log is append-only, enforced by database triggers, and the machine's
# baseline lives in the same file. Both are defeated by anybody who can create a
# file in the directory beside it: SQLite keeps its write-ahead log there,
# deletes it on a clean close, and applies it as raw pages underneath SQL, so a
# planted one rewrites rows without a statement ever running.
#
# ProgramData grants ordinary users create-file by inheritance. The agent locks
# this at every start, which makes it self-healing; doing it here closes the one
# window the agent cannot -- between the directory existing and the agent's
# first run.
$store = Join-Path $env:ProgramData 'KAM Security'
if (-not (Test-Path $store)) { New-Item -ItemType Directory -Force -Path $store | Out-Null }
& icacls $store /inheritance:r /grant:r `
    '*S-1-5-32-544:(OI)(CI)F' `
    '*S-1-5-18:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "the store could not be secured (icacls exit $LASTEXITCODE); its audit log and baseline could be rewritten"
}
Write-Host '  store secured (administrators only can write)' -ForegroundColor Gray

& $agent --install
if ($LASTEXITCODE -ne 0) { throw "the service could not be registered (exit $LASTEXITCODE)" }
Write-Host '  service registered and started' -ForegroundColor Gray

# The icon comes from the executable itself rather than a separate .ico. A
# second path is a second thing that can go stale: moving the folder once left a
# shortcut whose target followed and whose icon did not, and it showed up as a
# blank square on the desktop with nothing to explain it.
$wsh = New-Object -ComObject WScript.Shell
$link = $wsh.CreateShortcut($shortcut)
$link.TargetPath = $shell
$link.WorkingDirectory = $here
$link.IconLocation = "$shell,0"
$link.Description = 'KAM Security'
$link.Save()
try {
    Set-ShortcutIdentity -Link $shortcut -Id $appId
} catch {
    Write-Host "  the desktop shortcut could not be given the app's identity: $($_.Exception.Message)" -ForegroundColor Yellow
}
Write-Host "  desktop shortcut created" -ForegroundColor Gray

# Explorer caches the icon it drew last time, so a shortcut replaced in place
# can keep showing the old one until something tells it otherwise.
Add-Type -TypeDefinition 'using System; using System.Runtime.InteropServices; public class KamShell { [DllImport("shell32.dll")] public static extern void SHChangeNotify(int e, uint f, IntPtr a, IntPtr b); }'
[KamShell]::SHChangeNotify(0x08000000, 0x0000, [IntPtr]::Zero, [IntPtr]::Zero)

Write-Host ''
Write-Host 'Ready. Open KAM Security from the desktop.' -ForegroundColor Green
Write-Host ''
Write-Host 'What this changed:' -ForegroundColor White
Write-Host '  - registered the KamSecurityAgent service, which starts with Windows' -ForegroundColor Gray
Write-Host '  - put a shortcut on your desktop' -ForegroundColor Gray
Write-Host ''
Write-Host 'What it did not change:' -ForegroundColor White
Write-Host '  - no browser, firewall or Defender setting was touched' -ForegroundColor Gray
Write-Host ''
Write-Host 'The first time you open it:' -ForegroundColor White
Write-Host '  - KAM Security adds itself to your sign-in items, so its icon sits by the clock' -ForegroundColor Gray
Write-Host '  - untick "Start KAM Security when I sign in" on the Overview to stop that' -ForegroundColor Gray
Write-Host '  - it adds "Check with KAM Security" and "Extract with KAM Security" to the right-click menu' -ForegroundColor Gray
Write-Host '    (untick them on the Active downloads page) and a Start menu shortcut, which' -ForegroundColor Gray
Write-Host '    Windows needs before it will show the app''s notices' -ForegroundColor Gray
Write-Host ''
Write-Host 'Undo what this script did with:  setup.ps1 -Remove  (the sign-in entry is the app''s: untick it first)' -ForegroundColor Gray
