<#
.SYNOPSIS
    Capture the KAM Security window to docs/images.

.DESCRIPTION
    The README's argument is that this product shows you things nothing else
    does, which is not an argument that survives being made in prose. So it
    needs pictures, and pictures of a live window go stale the moment the
    interface changes.

    This exists so they can be retaken in one command rather than rediscovered
    as a chore. It captures the window itself, not the screen, so nothing of
    the desktop behind it ends up in a public repository.

.PARAMETER Name
    What to call the file, without an extension. It lands in docs/images.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts/screenshot.ps1 overview
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidatePattern('^[a-z0-9-]+$')]
    [string]$Name,

    # Seconds to wait before capturing, so a view can be opened first.
    [int]$Delay = 0
)

$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName System.Drawing
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public class Win {
    [StructLayout(LayoutKind.Sequential)]
    public struct Rect { public int Left, Top, Right, Bottom; }

    [DllImport("user32.dll")]
    public static extern bool SetForegroundWindow(IntPtr handle);

    // The window's visible bounds including its shadow-free frame. GetWindowRect
    // includes the invisible resize border on Windows 10 and later, which shows
    // up as a transparent margin down both sides of every screenshot.
    [DllImport("dwmapi.dll")]
    public static extern int DwmGetWindowAttribute(IntPtr handle, int attribute, out Rect value, int size);

    public const int ExtendedFrameBounds = 9;
}
'@

$process = Get-Process kam-shell -ErrorAction SilentlyContinue |
    Where-Object { $_.MainWindowHandle -ne 0 } |
    Select-Object -First 1

if (-not $process) {
    throw 'KAM Security is not running with a window open. Start dist\kam-shell.exe first.'
}

[void][Win]::SetForegroundWindow($process.MainWindowHandle)
Start-Sleep -Milliseconds 400
if ($Delay -gt 0) {
    Write-Host "Capturing in $Delay seconds - open the view you want." -ForegroundColor Cyan
    Start-Sleep -Seconds $Delay
}

$bounds = New-Object Win+Rect
$result = [Win]::DwmGetWindowAttribute(
    $process.MainWindowHandle,
    [Win]::ExtendedFrameBounds,
    [ref]$bounds,
    [System.Runtime.InteropServices.Marshal]::SizeOf($bounds))
if ($result -ne 0) { throw "could not measure the window (dwm returned $result)" }

$width = $bounds.Right - $bounds.Left
$height = $bounds.Bottom - $bounds.Top
if ($width -le 0 -or $height -le 0) { throw 'the window has no size; is it minimised?' }

$images = Join-Path (Split-Path $PSScriptRoot -Parent) 'docs\images'
if (-not (Test-Path $images)) { New-Item -ItemType Directory -Path $images | Out-Null }
$file = Join-Path $images "$Name.png"

$bitmap = New-Object System.Drawing.Bitmap $width, $height
try {
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    try {
        $graphics.CopyFromScreen($bounds.Left, $bounds.Top, 0, 0, $bitmap.Size)
    } finally {
        $graphics.Dispose()
    }
    $bitmap.Save($file, [System.Drawing.Imaging.ImageFormat]::Png)
} finally {
    $bitmap.Dispose()
}

$size = [math]::Round((Get-Item $file).Length / 1KB)
Write-Host "$file  ${width}x${height}  ${size} KB" -ForegroundColor Green
