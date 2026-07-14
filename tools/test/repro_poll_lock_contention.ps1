param(
    [Parameter(Mandatory = $true)][string]$StartFile,
    [int]$Last = 20,
    [int]$TimeoutSec = 45
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'unattended_exit_result.ps1')
$script:UnhandledExitTag = 'POLL-LOCK-CONTENTION-REPRO'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$pollScript = Join-Path $repoRoot 'tools\test\poll_agent_tickets.ps1'
if (-not (Test-Path -LiteralPath $pollScript)) {
    throw "poll script not found: $pollScript"
}

$startFilePath = if ([System.IO.Path]::IsPathRooted($StartFile)) {
    [System.IO.Path]::GetFullPath($StartFile)
}
else {
    [System.IO.Path]::GetFullPath((Join-Path $repoRoot $StartFile))
}

if (-not (Test-Path -LiteralPath $startFilePath)) {
    throw "start file not found: $startFilePath"
}

$outRoot = Join-Path $repoRoot 'out\artifacts\poll_lock_contention'
New-Item -ItemType Directory -Path $outRoot -Force | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss-fff'
$outDir = Join-Path $outRoot $stamp
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

$stdout1 = Join-Path $outDir 'poll1.json'
$stdout2 = Join-Path $outDir 'poll2.json'
$queuePath = Join-Path $outDir 'agent_tickets.jsonl'
$statePath = Join-Path $outDir 'poll_state.json'
$ledgerPath = Join-Path $outDir 'poll_ledger.json'
[System.IO.File]::WriteAllText($queuePath, '', (New-Object System.Text.UTF8Encoding($true)))

$argLine = "-NoProfile -ExecutionPolicy Bypass -File `"$pollScript`" -StartFile `"$startFilePath`" -QueuePath `"$queuePath`" -StatePath `"$statePath`" -LedgerPath `"$ledgerPath`" -Last $Last -AsJson"
$proc1 = Start-Process -FilePath 'powershell.exe' -ArgumentList $argLine -RedirectStandardOutput $stdout1 -NoNewWindow -PassThru
$proc2 = Start-Process -FilePath 'powershell.exe' -ArgumentList $argLine -RedirectStandardOutput $stdout2 -NoNewWindow -PassThru

$null = $proc1.WaitForExit($TimeoutSec * 1000)
$null = $proc2.WaitForExit($TimeoutSec * 1000)

if (-not $proc1.HasExited) {
    try { $proc1.Kill() } catch { Write-Verbose ("Suppress kill failure: {0}" -f $_.Exception.Message) }
    throw "poll1 timeout after ${TimeoutSec}s"
}
if (-not $proc2.HasExited) {
    try { $proc2.Kill() } catch { Write-Verbose ("Suppress kill failure: {0}" -f $_.Exception.Message) }
    throw "poll2 timeout after ${TimeoutSec}s"
}

$raw1 = Get-Content -LiteralPath $stdout1 -Raw -Encoding utf8
$raw2 = Get-Content -LiteralPath $stdout2 -Raw -Encoding utf8

$json1 = $raw1 | ConvertFrom-Json -ErrorAction Stop
$json2 = $raw2 | ConvertFrom-Json -ErrorAction Stop

function Get-PollLockFact {
    param([object]$PollResult)

    if ($PollResult.PSObject.Properties.Name -contains 'lock_busy') {
        return [pscustomobject]@{
            lock_busy = [bool]$PollResult.lock_busy
            lock_name = [string]$PollResult.lock_name
            lock_wait_ms = if ($PollResult.PSObject.Properties.Name -contains 'lock_wait_ms') { [int]$PollResult.lock_wait_ms } else { -1 }
        }
    }

    if ($PollResult.PSObject.Properties.Name -contains 'poll_lock') {
        return [pscustomobject]@{
            lock_busy = [bool]$PollResult.poll_lock.lock_busy
            lock_name = [string]$PollResult.poll_lock.lock_name
            lock_wait_ms = [int]$PollResult.poll_lock.lock_wait_ms
        }
    }

    throw 'poll result does not contain lock facts'
}

$lock1 = Get-PollLockFact -PollResult $json1
$lock2 = Get-PollLockFact -PollResult $json2
$busyFlags = @([bool]$lock1.lock_busy, [bool]$lock2.lock_busy)
$busyCount = @($busyFlags | Where-Object { $_ }).Count
$pass = ($busyCount -eq 1)

$summary = [ordered]@{
    schema = 'AB_POLL_LOCK_CONTENTION_REPRO_V1'
    generated_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    start_file = $startFilePath
    out_dir = $outDir
    pass = $pass
    busy_count = $busyCount
    poll1 = [ordered]@{
        exit_code = [int]$proc1.ExitCode
        lock_busy = [bool]$lock1.lock_busy
        lock_name = [string]$lock1.lock_name
        lock_wait_ms = [int]$lock1.lock_wait_ms
    }
    poll2 = [ordered]@{
        exit_code = [int]$proc2.ExitCode
        lock_busy = [bool]$lock2.lock_busy
        lock_name = [string]$lock2.lock_name
        lock_wait_ms = [int]$lock2.lock_wait_ms
    }
}

$summaryPath = Join-Path $outDir 'summary.json'
$summaryTxt = Join-Path $outDir 'summary.txt'
($summary | ConvertTo-Json -Depth 8) | Out-File -LiteralPath $summaryPath -Encoding utf8
($summary | Format-List | Out-String) | Out-File -LiteralPath $summaryTxt -Encoding utf8

Write-Output ("[POLL-LOCK-REPRO] out_dir={0}" -f $outDir)
Write-Output ("[POLL-LOCK-REPRO] summary_json={0}" -f $summaryPath)
Write-Output ("[POLL-LOCK-REPRO] summary_txt={0}" -f $summaryTxt)
Write-Output ("[POLL-LOCK-REPRO] busy_count={0}" -f $busyCount)

if (-not $pass) {
    Write-Output '[POLL-LOCK-REPRO] result=fail expected_busy_count=1'
    Exit-UnattendedFailure -Tag $script:UnhandledExitTag -Reason 'poll-lock-contention regression failed' -ExitCode 1
}

Write-Output '[POLL-LOCK-REPRO] result=pass'
exit 0
