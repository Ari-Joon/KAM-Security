<#
.SYNOPSIS
    Run exactly what CI runs, before pushing.

.DESCRIPTION
    CI went red four times in one day, and every one was avoidable. The cause
    was not carelessness about any single check — it was that "what I run" and
    "what CI runs" were different in ways that were invisible from here:

      - CI sets RUSTFLAGS=-D warnings, so a clippy *warning* fails the build
        there and merely prints here. Twice a commit went out with the warning
        visible in my own output, because I was reading it as a warning.
      - CI builds the frontend with `npm ci` from the lockfile, not with
        whatever `node_modules` happens to hold.
      - CI runs `cargo deny check` in a second job, which was never run locally
        at all.

    So this script is the CI workflow, in order, with the same environment. If
    it passes, the push passes. If it cannot run something, it says so rather
    than skipping quietly — a check that silently does nothing is worse than no
    check, because it is trusted.

.PARAMETER SkipFrontend
    Skip the npm install and build. Only for a Rust-only change, and it means
    this is no longer a faithful copy of CI.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\check.ps1
#>
[CmdletBinding()]
param(
    [switch]$SkipFrontend
)

$ErrorActionPreference = 'Continue'
$root = Split-Path $PSScriptRoot -Parent
$failures = @()

# Work from the repository, whatever directory this was started from.
#
# Missed on the first version, which passed for me only because I happened to
# be standing in the repository root when I ran it. Started from anywhere else
# -- an administrator prompt opens in System32, which is exactly where Ari ran
# it -- cargo cannot find Cargo.toml and every Rust step fails for a reason
# that has nothing to do with the code. A check that works from one directory
# and lies from every other is worse than no check.
Push-Location $root

# The single most important line here. Without it clippy warns and this script
# would pass while CI failed, which is the exact hole it exists to close.
$env:RUSTFLAGS = '-D warnings'
$env:CARGO_TERM_COLOR = 'always'

function Step($name, [scriptblock]$work) {
    Write-Host ''
    Write-Host "=== $name ===" -ForegroundColor Cyan
    & $work
    if ($LASTEXITCODE -ne 0) {
        $script:failures += $name
        Write-Host "  FAILED" -ForegroundColor Red
    } else {
        Write-Host "  ok" -ForegroundColor Green
    }
}

# The shell embeds the built frontend at compile time, so this comes first for
# the same reason it does in CI: cargo cannot build until `ui/dist` exists.
if (-not $SkipFrontend) {
    Step 'Build the frontend' {
        Push-Location (Join-Path $root 'ui')
        try {
            & npm ci --ignore-scripts
            if ($LASTEXITCODE -eq 0) { & npm run build }
        } finally { Pop-Location }
        # Back in the repository root, which every cargo step below needs.
    }
} else {
    Write-Host ''
    Write-Host '=== Build the frontend ===' -ForegroundColor Cyan
    Write-Host '  SKIPPED, so this is not what CI will run' -ForegroundColor Yellow
}

Step 'Format' { & cargo fmt --all -- --check }
Step 'Clippy (warnings are errors, as in CI)' { & cargo clippy --workspace --all-targets }
Step 'Test' { & cargo test --workspace }

# The second CI job. Needs a tool that may not be installed; say which rather
# than passing silently.
Write-Host ''
Write-Host '=== Licence and advisory audit ===' -ForegroundColor Cyan
if (Get-Command cargo-deny -ErrorAction SilentlyContinue) {
    & cargo deny check
    if ($LASTEXITCODE -ne 0) {
        $failures += 'Licence and advisory audit'
        Write-Host '  FAILED' -ForegroundColor Red
    } else {
        Write-Host '  ok' -ForegroundColor Green
    }
} else {
    $failures += 'Licence and advisory audit (cargo-deny is not installed here)'
    Write-Host '  NOT CHECKED: cargo-deny is not installed.' -ForegroundColor Yellow
    Write-Host '  CI runs it, so this machine cannot tell you the push will pass.' -ForegroundColor Yellow
    Write-Host '  Install it with:  cargo install --locked cargo-deny' -ForegroundColor Yellow
}

Pop-Location

Write-Host ''
if ($failures.Count -gt 0) {
    Write-Host 'NOT READY TO PUSH:' -ForegroundColor Red
    foreach ($failure in $failures) { Write-Host "  - $failure" -ForegroundColor Red }
    exit 1
}

Write-Host 'Everything CI runs passes here. Safe to push.' -ForegroundColor Green
exit 0
