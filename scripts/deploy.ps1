<#
    Swap the built binaries into dist and restart the service.

    Needed after any change to the agent, and required after a protocol change:
    the shell refuses to talk to an agent reporting a different version, so
    deploying one without the other leaves the application unable to start work.

    Run it from anywhere. If it is not already running as administrator it
    relaunches itself and asks, because stopping a service and writing into a
    privileged directory both need rights an ordinary prompt does not have.

        powershell -ExecutionPolicy Bypass -File scripts\deploy.ps1
#>

$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$service = 'KamSecurityAgent'
$binaries = @('kam-agent.exe', 'kam-shell.exe')

# --- elevate, rather than failing three steps later --------------------------
#
# Without this the stop fails silently, the copy then fails because the file is
# still in use, and the start fails with an access error -- three messages, none
# of which says "you are not an administrator".

$identity = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $identity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'Asking for administrator rights...' -ForegroundColor Yellow
    $log = Join-Path $env:TEMP 'kam-deploy.log'
    if (Test-Path $log) { Remove-Item $log -Force }

    # Every argument is quoted by hand.
    #
    # Start-Process joins ArgumentList with spaces and does NOT quote the
    # parts, so this script's own path -- which lives under "KAM Security" --
    # arrives at PowerShell split in half at the space. It then cannot find the
    # file and exits -196608 before running a line, which is what "Deploy
    # failed (exit -196608)" with no log meant.
    $self = '"' + $MyInvocation.MyCommand.Path + '"'
    $child = Start-Process powershell.exe -Verb RunAs -PassThru -Wait -ArgumentList @(
        '-ExecutionPolicy', 'Bypass',
        '-NoProfile',
        '-File', $self
    )

    if (Test-Path $log) {
        Get-Content $log
    } elseif ($child.ExitCode -ne 0) {
        Write-Host 'The elevated pass wrote no log, so it failed before it began.' -ForegroundColor Red
        Write-Host "Run it directly from an administrator terminal to see why:" -ForegroundColor Yellow
        Write-Host "  powershell -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`"" -ForegroundColor Yellow
    }
    if ($child.ExitCode -ne 0) {
        Write-Host "Deploy failed (exit $($child.ExitCode))." -ForegroundColor Red
    }
    exit $child.ExitCode
}

# The elevated pass writes to a log so the original window can show it.
$log = Join-Path $env:TEMP 'kam-deploy.log'
function Say($text, $colour = 'Gray') {
    Write-Host $text -ForegroundColor $colour
    Add-Content -Path $log -Value $text -Encoding utf8
}

try {
    foreach ($name in $binaries) {
        $built = Join-Path $root "target\release\$name"
        if (-not (Test-Path $built)) {
            throw "$name has not been built. Run: cargo build --release -p kam-agent  and  npm run tauri build -- --no-bundle"
        }
    }

    # --- close the window ----------------------------------------------------
    #
    # kam-shell.exe holds a write lock on itself while it runs, and deploying
    # underneath a running window would leave an old interface talking to a new
    # agent across a protocol that may have changed. Closing it is part of the
    # swap, not a liberty.
    $shells = Get-Process kam-shell -ErrorAction SilentlyContinue
    if ($shells) {
        Say 'Closing the KAM Security window...'
        $shells | Stop-Process -Force
        $waited = 0
        while ((Get-Process kam-shell -ErrorAction SilentlyContinue) -and $waited -lt 100) {
            Start-Sleep -Milliseconds 100
            $waited++
        }
        Say '  closed.'
    }

    # --- stop, and confirm it actually stopped -------------------------------
    $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -ne 'Stopped') {
        Say 'Stopping the service...'
        Stop-Service -Name $service -Force
        $svc.WaitForStatus('Stopped', '00:00:30')

        # The control manager reports Stopped before the process has exited, and
        # a running process keeps a write lock on its own image.
        $waited = 0
        while ((Get-Process kam-agent -ErrorAction SilentlyContinue) -and $waited -lt 100) {
            Start-Sleep -Milliseconds 100
            $waited++
        }
        if (Get-Process kam-agent -ErrorAction SilentlyContinue) {
            throw 'kam-agent.exe is still running after the service stopped; nothing was copied.'
        }
        Say '  stopped.'
    }

    # --- repair the registration --------------------------------------------
    #
    # The service was originally registered as manual-start, which meant a
    # reboot left it stopped and the application reported "Cannot reach the
    # agent". Fixed in the installer, but an existing registration keeps
    # whatever it was created with, so it is corrected here too -- that is the
    # one this machine actually runs.
    $cim = Get-CimInstance Win32_Service -Filter "Name='$service'" -ErrorAction SilentlyContinue
    if ($cim -and $cim.StartMode -ne 'Auto') {
        Say "Start mode is $($cim.StartMode); setting it to Automatic so it survives a reboot..." 'Yellow'
        & sc.exe config $service start= auto | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "could not set the service to start automatically (sc exit $LASTEXITCODE)" }
        & sc.exe failure $service reset= 86400 actions= restart/5000/restart/15000/restart/60000 | Out-Null
        Say '  set to Automatic, with restart-on-failure.' 'Green'
    }

    # --- copy ---------------------------------------------------------------
    New-Item -ItemType Directory -Force -Path (Join-Path $root 'dist') | Out-Null
    foreach ($name in $binaries) {
        $built = Join-Path $root "target\release\$name"
        $live = Join-Path $root "dist\$name"
        Copy-Item $built $live -Force
        $stamp = (Get-Item $live).LastWriteTime.ToString('HH:mm:ss')
        $mb = [math]::Round((Get-Item $live).Length / 1MB, 1)
        Say ("  {0,-16} {1}  {2} MB" -f $name, $stamp, $mb) 'Green'
    }

    # --- start and verify ----------------------------------------------------
    if ($svc) {
        Say 'Starting the service...'
        Start-Service -Name $service
        (Get-Service -Name $service).WaitForStatus('Running', '00:00:30')
        Say '  running.'
    }

    $probe = & (Join-Path $root 'dist\kam-agent.exe') --probe 2>&1 | Out-String
    if ($probe -match '"protocol_version":\s*(\d+)') {
        Say "Deployed. Agent answering on protocol $($Matches[1])." 'Green'
    } else {
        Say "Deployed, but the agent did not answer a probe:" 'Yellow'
        Say $probe 'Yellow'
        exit 1
    }
    exit 0
}
catch {
    Say "FAILED: $($_.Exception.Message)" 'Red'
    # Never leave the machine with the service down because a copy failed.
    if ((Get-Service -Name $service -ErrorAction SilentlyContinue).Status -eq 'Stopped') {
        Say 'Restarting the service so the machine is not left without it...' 'Yellow'
        try { Start-Service -Name $service; Say '  running again.' 'Yellow' } catch { Say '  could not restart it.' 'Red' }
    }
    exit 1
}
