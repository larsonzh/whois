Set-StrictMode -Version Latest

function Invoke-MonitorChainHealthCheck {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Roles,
        [Parameter(Mandatory = $true)]
        [string]$RepoRoot,
        [Parameter(Mandatory = $true)]
        [string]$StartFilePath,
        [string]$LogPrefix = 'health_check'
    )

    $roleMap = @(
        @{ n = 'companion';  p = 'tools/test/open_unattended_ab_companion_window.ps1' }
        @{ n = 'supervisor'; p = 'tools/test/open_unattended_ab_supervisor_window.ps1' }
        @{ n = 'guard';      p = 'tools/test/open_unattended_ab_session_guard_window.ps1' }
        @{ n = 'trigger';    p = 'tools/test/open_unattended_ab_takeover_trigger_window.ps1' }
    )

    foreach ($role in $Roles) {
        $rn = $role.Trim().ToLowerInvariant()
        $entry = $roleMap | Where-Object { $_.n -eq $rn } | Select-Object -First 1
        if ($null -eq $entry) { continue }

        $scriptLeaf = ('unattended_ab_{0}.ps1' -f $rn)
        $found = @(Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -ErrorAction SilentlyContinue | Where-Object {
            $null -ne $_ -and -not [string]::IsNullOrWhiteSpace([string]$_.CommandLine) -and
            ([string]$_.CommandLine).ToLowerInvariant().Contains($scriptLeaf)
        })

        if (@($found).Count -eq 0) {
            $launcherPath = Join-Path $RepoRoot ([string]$entry.p)
            if (Test-Path -LiteralPath $launcherPath) {
                try {
                    Start-Process -FilePath 'powershell' -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$launcherPath`" -StartFile `"$StartFilePath`" -NoRestartIfRunning"
                    Write-Output ("[{0}] role={1} action=restart" -f $LogPrefix, $rn)
                }
                catch {
                    Write-Output ("[{0}] role={1} action=restart_failed detail={2}" -f $LogPrefix, $rn, $_.Exception.Message)
                }
            }
        }
    }
}

function Get-UnattendedExitCodeFromRecord {
    param(
        [string]$Tag,
        [System.Management.Automation.ErrorRecord]$Record,
        [int]$DefaultExitCode = 1
    )

    $exitCode = if ($DefaultExitCode -gt 0) { [int]$DefaultExitCode } else { 1 }
    $detail = ''
    if ($null -ne $Record -and $null -ne $Record.Exception) {
        $detail = [string]$Record.Exception.Message
    }

    $normalized = $detail.Trim().ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($normalized)) {
        return $exitCode
    }

    if ($normalized -match 'path must not be empty|must be an integer within|missing script|not found|cannot find path|because it does not exist|is missing in start file') {
        return 2
    }

    if ($normalized -match 'a_only_guard blocked|precheck gate blocked|launch-ready gate blocked|start gate blocked|task static precheck failed') {
        return 3
    }

    if ($normalized -match 'stage_delegate_failed') {
        return 4
    }

    return $exitCode
}

function Write-UnattendedUnhandledResult {
    param(
        [string]$Tag,
        [System.Management.Automation.ErrorRecord]$Record,
        [int]$ExitCode = 1
    )

    if ([string]::IsNullOrWhiteSpace($Tag)) {
        $Tag = 'UNATTENDED-SCRIPT'
    }

    $detail = if ($null -ne $Record -and $null -ne $Record.Exception) {
        [string]$Record.Exception.Message
    }
    else {
        'unknown-error'
    }

    $detail = ([regex]::Replace($detail, '\s+', ' ')).Trim()
    if ([string]::IsNullOrWhiteSpace($detail)) {
        $detail = 'unknown-error'
    }

    if ($ExitCode -le 0) {
        $ExitCode = 1
    }

    Write-Output ("[AB-UNATTENDED-RESULT] schema=AB_UNATTENDED_SCRIPT_RESULT_V1 script={0} result=FAIL final_result=FAIL exit_code={1} error={2}" -f $Tag, $ExitCode, $detail)
}

function Exit-UnattendedFailure {
    param(
        [string]$Tag,
        [string]$Reason,
        [int]$ExitCode = 1
    )

    if ([string]::IsNullOrWhiteSpace($Tag)) {
        $Tag = 'UNATTENDED-SCRIPT'
    }

    $detail = ([regex]::Replace([string]$Reason, '\s+', ' ')).Trim()
    if ([string]::IsNullOrWhiteSpace($detail)) {
        $detail = 'script-failed'
    }

    if ($ExitCode -le 0) {
        $ExitCode = 1
    }

    Write-Output ("[AB-UNATTENDED-RESULT] schema=AB_UNATTENDED_SCRIPT_RESULT_V1 script={0} result=FAIL final_result=FAIL exit_code={1} error={2}" -f $Tag, $ExitCode, $detail)
    exit $ExitCode
}
