<#
.SYNOPSIS
    Set KAM Security up after unzipping it, or take it back off.

.DESCRIPTION
    A download is two executables in a folder. Without this, somebody has to
    read the README, open an administrator terminal, and know that the fast disk
    scan needs a service — which is three steps too many for the first minute of
    using something.

    This registers the service and puts a shortcut on the desktop. It does not
    add anything to the run keys, and it does not start the window at logon:
    this product reports on what starts itself at boot, and quietly adding
    itself to that list while doing so would be indefensible.

    Everything it does is undone by `-Remove`, which is the same argument in
    reverse rather than a separate script that can drift out of step.

.PARAMETER Remove
    Stop and unregister the service and delete the shortcut.

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
Write-Host '  - nothing was added to the run keys, and the window does not open at logon' -ForegroundColor Gray
Write-Host '  - no browser, firewall or Defender setting was touched' -ForegroundColor Gray
Write-Host ''
Write-Host 'Undo all of it with:  setup.ps1 -Remove' -ForegroundColor Gray
