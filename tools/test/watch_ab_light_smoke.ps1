param(
    [string]$OutDirRoot = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'unattended_exit_result.ps1')
$script:UnhandledExitTag = 'WATCH-AB-LIGHT-SMOKE'

function Resolve-RepoRoot {
    return (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
}

function Write-SmokeStartFile {
    param(
        [string]$Path,
        [string]$GuardLog,
        [string]$GuardState
    )

    $notes = 'guard_log={0}; guard_state={1}; live_status={2}' -f $GuardLog, $GuardState, (Join-Path (Split-Path -Parent $GuardLog) 'live_status.json')
    $content = @(
        'SESSION_FINAL_STATUS=RUNNING'
        'A_FINAL_STATUS=RUNNING'
        'B_FINAL_STATUS=RUNNING'
        'SESSION_CLOSED=false'
        ('SESSION_FINAL_NOTES={0}' -f $notes)
    )

    $content | Out-File -LiteralPath $Path -Encoding utf8
}

function Write-SmokeArtifacts {
    param(
        [string]$StartFile,
        [string]$OutDir,
        [string]$TriggerToken,
        [string]$TicketId
    )

    $guardDir = Join-Path $OutDir 'guard'
    New-Item -ItemType Directory -Path $guardDir -Force | Out-Null
    $guardLog = Join-Path $guardDir 'guard.log'
    $guardState = Join-Path $guardDir 'guard_state.json'

    @(
        '[AB-SESSION-GUARD] timestamp=2026-07-06 03:00:00 watch_heartbeat required=true interval_min=10 scopes=artifacts;guard_log;compile-step stage=B row_count=7 file_count=12 latest_path=out\artifacts\dev_verify_multiround\smoke\final_status.json remote_chain_count=1 mode=guard scan_age_sec=0 scan_duration_ms=25'
    ) | Out-File -LiteralPath $guardLog -Encoding utf8
    [ordered]@{ schema = 'AB_SESSION_GUARD_STATE_V1'; stage = 'B' } | ConvertTo-Json -Depth 4 | Out-File -LiteralPath $guardState -Encoding utf8

    Write-SmokeStartFile -Path $StartFile -GuardLog $guardLog -GuardState $guardState

    $queueRoot = Join-Path (Resolve-RepoRoot) 'out\artifacts\ab_agent_queue'
    New-Item -ItemType Directory -Path $queueRoot -Force | Out-Null
    $triggerLog = Join-Path $queueRoot ('takeover_trigger_{0}.log' -f $TriggerToken)
    $triggerState = Join-Path $queueRoot ('takeover_trigger_state_{0}.json' -f $TriggerToken)

    @(
        ('[AB-TAKEOVER-TRIGGER] timestamp=2026-07-06 03:00:01 ticket_dispatch id={0} event=incident-captured brief=out\artifacts\ab_agent_queue\takeover_requests\takeover_{0}.md' -f $TicketId)
        '[AB-TAKEOVER-TRIGGER] timestamp=2026-07-06 03:00:02 fast_poll_window_open ttl_sec=30 reason=event=incident-captured;ticket={0}' -f $TicketId
        ('[AB-TAKEOVER-TRIGGER] timestamp=2026-07-06 03:00:03 external_trigger_route_allowed id={0} expected=incident-auto-resume-code-fix expected_source=brief classification=incident-auto-resume-code-fix action=trigger-code-fix-business-resume-now confidence=0.9 factors=incident_like=true latency_ms=12' -f $TicketId)
    ) | Out-File -LiteralPath $triggerLog -Encoding utf8
    [ordered]@{ schema = 'AB_TAKEOVER_TRIGGER_STATE_V1'; ticket_id = $TicketId } | ConvertTo-Json -Depth 4 | Out-File -LiteralPath $triggerState -Encoding utf8

    return [pscustomobject]@{
        GuardLog = $guardLog
        GuardState = $guardState
        TriggerLog = $triggerLog
        TriggerState = $triggerState
    }
}

function Invoke-WatchOnce {
    param([string]$StartFile)

    $watchScript = Join-Path (Resolve-RepoRoot) 'tools\test\watch_ab_light.ps1'
    return @(& powershell -NoProfile -ExecutionPolicy Bypass -File $watchScript -StartFile $StartFile -Once -NoClear 2>&1 | ForEach-Object { [string]$_ })
}

function Test-WatchOutput {
    param(
        [string[]]$Output,
        [string]$TicketId
    )

    return [ordered]@{
        trigger_log_anchor = (@($Output | Where-Object { $_ -match '^\s*trigger_log:\s+ok@' }).Count -gt 0)
        trigger_state_anchor = (@($Output | Where-Object { $_ -match '^\s*trigger_state:\s+ok@' }).Count -gt 0)
        guard_watch_heartbeat = (@($Output | Where-Object { $_ -match 'watch_heartbeat stage=B rows=7 files=12 chain=1 latest=final_status\.json' }).Count -gt 0)
        trigger_section = (@($Output | Where-Object { $_ -match '^\s*Trigger:' }).Count -gt 0)
        ticket_dispatch = (@($Output | Where-Object { $_ -match ('ticket_dispatch id={0} event=incident-captured' -f [regex]::Escape($TicketId)) }).Count -gt 0)
        route_allowed = (@($Output | Where-Object { $_ -match ('route_allowed id={0} class=incident-auto-resume-code-fix latency_ms=12' -f [regex]::Escape($TicketId)) }).Count -gt 0)
        fast_poll = (@($Output | Where-Object { $_ -match ('fast_poll ttl_sec=30 reason=event=incident-captured;ticket={0}' -f [regex]::Escape($TicketId)) }).Count -gt 0)
    }
}

$repoRoot = Resolve-RepoRoot
if ([string]::IsNullOrWhiteSpace($OutDirRoot)) {
    $OutDirRoot = Join-Path $repoRoot 'out\artifacts\watch_ab_light_smoke'
}

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$outDir = Join-Path $OutDirRoot $stamp
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

$stableStartFile = Join-Path $outDir ('startfile_stable_{0}.md' -f $stamp)
$legacyStartFile = Join-Path $outDir ('startfile_legacy_{0}.md' -f $stamp)
$stableTicketId = 'T-WATCH-STABLE-' + $stamp
$legacyTicketId = 'T-WATCH-LEGACY-' + $stamp

$stableToken = Get-StableStartFileToken -StartFilePath $stableStartFile
$legacyToken = Get-LegacyStartFileToken -StartFilePath $legacyStartFile

$stableArtifacts = Write-SmokeArtifacts -StartFile $stableStartFile -OutDir (Join-Path $outDir 'stable') -TriggerToken $stableToken -TicketId $stableTicketId
$legacyArtifacts = Write-SmokeArtifacts -StartFile $legacyStartFile -OutDir (Join-Path $outDir 'legacy') -TriggerToken $legacyToken -TicketId $legacyTicketId

$stableOutput = Invoke-WatchOnce -StartFile $stableStartFile
$legacyOutput = Invoke-WatchOnce -StartFile $legacyStartFile

$stableOutputPath = Join-Path $outDir 'watch_stable_output.log'
$legacyOutputPath = Join-Path $outDir 'watch_legacy_output.log'
$stableOutput | Out-File -LiteralPath $stableOutputPath -Encoding utf8
$legacyOutput | Out-File -LiteralPath $legacyOutputPath -Encoding utf8

$stableChecks = Test-WatchOutput -Output $stableOutput -TicketId $stableTicketId
$legacyChecks = Test-WatchOutput -Output $legacyOutput -TicketId $legacyTicketId
$stablePass = (-not @($stableChecks.Values | Where-Object { -not [bool]$_ }))
$legacyPass = (-not @($legacyChecks.Values | Where-Object { -not [bool]$_ }))
$pass = ($stablePass -and $legacyPass)

$summary = [ordered]@{
    schema = 'AB_WATCH_LIGHT_SMOKE_V1'
    generated_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    out_dir = $outDir
    stable = [ordered]@{
        start_file = $stableStartFile
        token = $stableToken
        output = $stableOutputPath
        artifacts = $stableArtifacts
        checks = $stableChecks
        pass = $stablePass
    }
    legacy = [ordered]@{
        start_file = $legacyStartFile
        token = $legacyToken
        output = $legacyOutputPath
        artifacts = $legacyArtifacts
        checks = $legacyChecks
        pass = $legacyPass
    }
    pass = $pass
}

$summaryJson = Join-Path $outDir 'summary.json'
$summary | ConvertTo-Json -Depth 8 | Out-File -LiteralPath $summaryJson -Encoding utf8

Write-Output ('[WATCH-AB-LIGHT-SMOKE] out_dir={0}' -f $outDir)
Write-Output ('[WATCH-AB-LIGHT-SMOKE] summary_json={0}' -f $summaryJson)
Write-Output ('[WATCH-AB-LIGHT-SMOKE] stable_pass={0} legacy_pass={1}' -f $stablePass, $legacyPass)

if (-not $pass) {
    Write-Output '[WATCH-AB-LIGHT-SMOKE] result=fail'
    Exit-UnattendedFailure -Tag $script:UnhandledExitTag -Reason 'watch-ab-light-smoke failed' -ExitCode 1
}

Write-Output '[WATCH-AB-LIGHT-SMOKE] result=pass'
exit 0