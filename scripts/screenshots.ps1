<#
.SYNOPSIS
    Take every screenshot the README uses, in one pass.

.DESCRIPTION
    The window is a WebView2 and exposes no accessibility tree unless a screen
    reader is running, so nothing can click through the views on your behalf.
    This asks you to open each one and presses the shutter itself, which is the
    difference between a five-minute chore and a one-minute one.

    Run it, click the view it names, press Enter. Skip any you do not want with
    S. The files land in docs/images and overwrite what is there.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts/screenshots.ps1
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$shots = @(
    @{ Name = 'overview';     View = 'Overview';     Note = 'the drives and the weekly check' }
    @{ Name = 'applications'; View = 'Applications'; Note = 'after pressing Measure, so the real sizes are in' }
    @{ Name = 'storage';      View = 'Storage';      Note = 'the treemap, after a scan' }
    @{ Name = 'cleanup';      View = 'Cleanup';      Note = 'ideally after measuring the caches' }
    @{ Name = 'scanner';      View = 'Scanner';      Note = 'after a provenance survey' }
    @{ Name = 'firewall';     View = 'Firewall';     Note = 'rules and connections' }
)

$single = Join-Path $PSScriptRoot 'screenshot.ps1'
if (-not (Test-Path $single)) { throw "screenshot.ps1 is missing from $PSScriptRoot" }

if (-not (Get-Process kam-shell -ErrorAction SilentlyContinue)) {
    throw 'KAM Security is not running. Start dist\kam-shell.exe first.'
}

Write-Host ''
Write-Host 'Six shots. Open the view, come back here, press Enter. S skips one.' -ForegroundColor Cyan
Write-Host ''

foreach ($shot in $shots) {
    Write-Host ("  {0,-14} {1}" -f $shot.View, $shot.Note) -ForegroundColor White
    $answer = Read-Host '  Enter to capture, S to skip'
    if ($answer -match '^[Ss]') {
        Write-Host '  skipped' -ForegroundColor DarkGray
        continue
    }
    try {
        & $single -Name $shot.Name
    } catch {
        Write-Host "  could not capture: $_" -ForegroundColor Red
    }
}

Write-Host ''
Write-Host 'Done. Check docs\images before committing them: they are pictures of' -ForegroundColor Yellow
Write-Host 'your real machine, so they carry your hostname, your drive sizes and' -ForegroundColor Yellow
Write-Host 'the names of everything you have installed.' -ForegroundColor Yellow
