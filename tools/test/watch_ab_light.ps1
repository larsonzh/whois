<#
Common startup commands:
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/watch_ab_light.ps1 -StartFile testdata/unattended_start/active/unattended_ab_start_20260504-1123.md -Once -NoClear
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/watch_ab_light.ps1 -StartFile testdata/unattended_start/active/unattended_ab_start_20260504-1123.md -IntervalSec 20
#>

param(
    [string]$StartFile = 'testdata\unattended_start\active\unattended_ab_start_20260504-1123.md',
    [ValidateRange(5, 300)][int]$IntervalSec = 20,
    [ValidateRange(1, 200)][int]$TailLines = 8,
    [switch]$NoClear,
    [switch]$Once,
    [switch]$NoAutoStopOnFinal,
    [switch]$ExitShellOnFinal
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:TailLines = $TailLines

. (Join-Path $PSScriptRoot 'unattended_startfile_identity.ps1')

function Invoke-KeyValueFileValueUpdate {
    param(
        [string]$Path,
        [hashtable]$Values
    )

    $mutex = New-Object System.Threading.Mutex($false, (Get-StartFileMutexName -StartFilePath $Path))
    $locked = $false
    $tempPath = ''
    try {
        try {
            $locked = $mutex.WaitOne([TimeSpan]::FromSeconds(30))
        }
        catch [System.Threading.AbandonedMutexException] {
            $locked = $true
        }

        if (-not $locked) {
            throw "Failed to acquire start-file write lock within timeout: $Path"
        }

        $lines = @()
        if (Test-Path -LiteralPath $Path) {
            $lines = @(Get-Content -LiteralPath $Path -Encoding utf8 -ErrorAction Stop)
        }

        $seenKeys = @{}
        $lineNo = 0
        foreach ($line in $lines) {
            $lineNo++
            if ($line -match '^([^=]+)=(.*)$') {
                $key = $Matches[1].Trim()
                if ($seenKeys.ContainsKey($key)) {
                    throw ("Duplicate key '{0}' detected in {1} at line {2} and line {3}." -f $key, $Path, [int]$seenKeys[$key], $lineNo)
                }

                $seenKeys[$key] = $lineNo
            }
        }

        $buffer = New-Object 'System.Collections.Generic.List[string]'
        foreach ($line in $lines) {
            [void]$buffer.Add([string]$line)
        }

        foreach ($key in $Values.Keys) {
            $prefix = "$key="
            $found = $false
            for ($index = 0; $index -lt $buffer.Count; $index++) {
                if ($buffer[$index].StartsWith($prefix, [System.StringComparison]::Ordinal)) {
                    $buffer[$index] = $prefix + [string]$Values[$key]
                    $found = $true
                    break
                }
            }

            if (-not $found) {
                [void]$buffer.Add($prefix + [string]$Values[$key])
            }
        }

        $tempPath = "$Path.tmp.$PID.$([guid]::NewGuid().ToString('N'))"
        $normalizedLines = @($buffer | ForEach-Object { [string]$_ })
        $text = [string]::Join("`n", $normalizedLines)
        if ($normalizedLines.Count -gt 0) {
            $text += "`n"
        }
        [System.IO.File]::WriteAllText($tempPath, $text, [System.Text.UTF8Encoding]::new($true))
        Move-Item -LiteralPath $tempPath -Destination $Path -Force
        $tempPath = ''
    }
    finally {
        if (-not [string]::IsNullOrWhiteSpace($tempPath) -and (Test-Path -LiteralPath $tempPath)) {
            Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue
        }

        if ($locked) {
            try { $mutex.ReleaseMutex() } catch { Write-Verbose ("Suppressed exception: {0}" -f $_.Exception.Message) }
        }
        $mutex.Dispose()
    }
}

function Get-NormalizedPathIdentity {
    param(
        [AllowEmptyString()][string]$Path,
        [string]$RepoRoot
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return ''
    }

    try {
        $resolved = if ([System.IO.Path]::IsPathRooted($Path)) {
            [System.IO.Path]::GetFullPath($Path)
        }
        else {
            [System.IO.Path]::GetFullPath((Join-Path $RepoRoot $Path))
        }

        return $resolved.ToLowerInvariant()
    }
    catch {
        return ''
    }
}

function Get-StartFilePathFromCommandLine {
    param(
        [AllowEmptyString()][string]$CommandLine,
        [string]$RepoRoot
    )

    if ([string]::IsNullOrWhiteSpace($CommandLine)) {
        return ''
    }

    $match = [regex]::Match($CommandLine, '(?i)(?:^|\s)-StartFile\s+("([^"]+)"|''([^'']+)''|([^\s]+))')
    if (-not $match.Success) {
        return ''
    }

    $rawPath = if ($match.Groups[2].Success) {
        $match.Groups[2].Value
    }
    elseif ($match.Groups[3].Success) {
        $match.Groups[3].Value
    }
    else {
        $match.Groups[4].Value
    }

    return Get-NormalizedPathIdentity -Path $rawPath -RepoRoot $RepoRoot
}

function Get-RunningWatchProcessIdList {
    param(
        [string]$StartFileIdentity,
        [string]$RepoRoot,
        [int]$CurrentProcessId
    )

    $ids = @(
        Get-CimInstance Win32_Process |
            Where-Object {
                if ([int]$_.ProcessId -eq $CurrentProcessId) {
                    return $false
                }

                $commandLine = [string]$_.CommandLine
                if ([string]::IsNullOrWhiteSpace($commandLine)) {
                    return $false
                }

                $line = $commandLine.ToLowerInvariant()
                if (-not $line.Contains('watch_ab_light.ps1')) {
                    return $false
                }

                # Keep one-shot queries independent; dedupe only long-running watch loops.
                if ($line -match '(?i)(?:^|\s)-once(?:\s|$)') {
                    return $false
                }

                if ([string]::IsNullOrWhiteSpace($StartFileIdentity)) {
                    return $true
                }

                $processStartFileIdentity = Get-StartFilePathFromCommandLine -CommandLine $commandLine -RepoRoot $RepoRoot
                if ([string]::IsNullOrWhiteSpace($processStartFileIdentity)) {
                    return $false
                }

                return ($processStartFileIdentity -eq $StartFileIdentity)
            } |
            Select-Object -ExpandProperty ProcessId -Unique
    )

    return @($ids)
}

function Invoke-RunningWatchProcessStop {
    param([int[]]$ProcessIds)

    $stopped = New-Object 'System.Collections.Generic.List[int]'
    foreach ($targetPid in @($ProcessIds | Sort-Object -Unique)) {
        if ($targetPid -le 0) {
            continue
        }

        try {
            Stop-Process -Id $targetPid -Force -ErrorAction Stop
            Wait-Process -Id $targetPid -Timeout 20 -ErrorAction SilentlyContinue
            [void]$stopped.Add([int]$targetPid)
        }
        catch { Write-Verbose ("Suppressed exception: {0}" -f $_.Exception.Message) }
    }

    return @($stopped)
}

function Invoke-StartupWatchDedupe {
    param(
        [string]$StartFilePath,
        [switch]$SkipDedupe
    )

    if ($SkipDedupe.IsPresent) {
        return
    }

    $startFileIdentity = Get-NormalizedPathIdentity -Path $StartFilePath -RepoRoot $script:RepoRoot
    $existingPids = @(Get-RunningWatchProcessIdList -StartFileIdentity $startFileIdentity -RepoRoot $script:RepoRoot -CurrentProcessId $PID)
    if ($existingPids.Count -lt 1) {
        return
    }

    Write-Output ("[WATCH-AB-LIGHT] startup_dedupe existing_count={0} existing_pids={1}" -f $existingPids.Count, ($existingPids -join ','))
    $stoppedPids = @(Invoke-RunningWatchProcessStop -ProcessIds $existingPids)
    Write-Output ("[WATCH-AB-LIGHT] startup_dedupe stopped_count={0} stopped_pids={1}" -f $stoppedPids.Count, ($stoppedPids -join ','))
}

function Invoke-WatchLifecycleStateUpdate {
    param(
        [string]$StartFilePath,
        [ValidateSet('startup', 'shutdown')][string]$Phase,
        [int]$WatchPid,
        [int]$ParentPid
    )

    if ([string]::IsNullOrWhiteSpace($StartFilePath) -or -not (Test-Path -LiteralPath $StartFilePath)) {
        return
    }

    $nowText = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    if ($Phase -eq 'startup') {
        Invoke-KeyValueFileValueUpdate -Path $StartFilePath -Values @{
            WATCH_LAUNCH_PID = [string]$WatchPid
            WATCH_PARENT_PID = [string]$ParentPid
            WATCH_LAST_START_AT = $nowText
        }
        return
    }

    $activeWatchPid = 0
    try {
        $settings = Read-KeyValueFile -Path $StartFilePath
        if ($settings.Contains('WATCH_LAUNCH_PID')) {
            [void][int]::TryParse(([string]$settings.WATCH_LAUNCH_PID), [ref]$activeWatchPid)
        }
    }
    catch {
        $activeWatchPid = 0
    }

    if ($activeWatchPid -gt 0 -and $activeWatchPid -ne $WatchPid) {
        Invoke-KeyValueFileValueUpdate -Path $StartFilePath -Values @{
            WATCH_LAST_EXIT_PID = [string]$WatchPid
            WATCH_LAST_EXIT_AT = $nowText
        }

        Write-Output ("[WATCH-AB-LIGHT] lifecycle_skip_clear reason=pid-not-owner active_pid={0} self_pid={1}" -f $activeWatchPid, $WatchPid)
        return
    }

    Invoke-KeyValueFileValueUpdate -Path $StartFilePath -Values @{
        WATCH_LAUNCH_PID = '0'
        WATCH_LAST_EXIT_PID = [string]$WatchPid
        WATCH_LAST_EXIT_AT = $nowText
    }
}

function Get-StatusValue {
    param([AllowEmptyString()][string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return 'NOT_RUN'
    }

    return $Value.Trim().ToUpperInvariant()
}

function Test-IsTerminalFinalStatus {
    param([AllowEmptyString()][string]$Status)

    $normalized = Get-StatusValue -Value $Status
    return $normalized -in @('PASS', 'FAIL', 'BLOCKED', 'STOPPED', 'ERROR', 'ABORTED', 'CANCELLED', 'TIMEOUT')
}

function Test-CurrentHostNoExitMode {
    try {
        $self = Get-CimInstance Win32_Process -Filter ("ProcessId={0}" -f $PID) -ErrorAction Stop
        $commandLine = [string]$self.CommandLine
        if (-not [string]::IsNullOrWhiteSpace($commandLine)) {
            $line = $commandLine.ToLowerInvariant()
            if ($line -match '(?:^|\s)-noexit(?:\s|$)') {
                return $true
            }
        }
    }
    catch { Write-Verbose ("Suppressed exception: {0}" -f $_.Exception.Message) }

    foreach ($arg in @([Environment]::GetCommandLineArgs())) {
        if ([string]::IsNullOrWhiteSpace($arg)) {
            continue
        }

        $normalized = $arg.Trim().ToLowerInvariant()
        if ($normalized -eq '-noexit' -or $normalized -eq '/noexit') {
            return $true
        }
    }

    return $false
}

function Get-LatestAnchorValueFromNoteText {
    param(
        [AllowEmptyString()][string]$Notes,
        [string]$Key
    )

    if ([string]::IsNullOrWhiteSpace($Notes) -or [string]::IsNullOrWhiteSpace($Key)) {
        return ''
    }

    $parts = @($Notes -split ';')
    $partCount = @($parts).Length
    for ($index = $partCount - 1; $index -ge 0; $index--) {
        $segment = [string]$parts[$index]
        if ([string]::IsNullOrWhiteSpace($segment)) {
            continue
        }

        if ($segment -match ('^\s*' + [regex]::Escape($Key) + '=(.+)$')) {
            return $Matches[1].Trim()
        }
    }

    return ''
}

function Get-AnchorMap {
    param([System.Collections.IDictionary]$Settings)

    $notes = if ($Settings.Contains('SESSION_FINAL_NOTES')) {
        [string]$Settings.SESSION_FINAL_NOTES
    }
    else {
        ''
    }

    $anchors = [ordered]@{}
    foreach ($key in @('run_dir', 'supervisor_log', 'companion_log', 'live_status', 'guard_log', 'guard_state', 'trigger_log', 'trigger_state')) {
        $anchors[$key] = Get-LatestAnchorValueFromNoteText -Notes $notes -Key $key
    }

    return $anchors
}

function Get-LatestGuardArtifactSet {
    $guardRoot = Join-Path $script:RepoRoot 'out\artifacts\ab_session_guard'
    if (-not (Test-Path -LiteralPath $guardRoot)) {
        return $null
    }

    $latest = Get-ChildItem -LiteralPath $guardRoot -Directory -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1

    if ($null -eq $latest) {
        return $null
    }

    return [pscustomobject]@{
        Dir = $latest.FullName
        Log = (Join-Path $latest.FullName 'guard.log')
        State = (Join-Path $latest.FullName 'guard_state.json')
    }
}

function Get-TriggerArtifactSet {
    param([string]$StartFilePath)

    $queueRoot = Join-Path $script:RepoRoot 'out\artifacts\ab_agent_queue'
    $stableToken = Get-StableStartFileToken -StartFilePath $StartFilePath
    $legacyToken = Get-LegacyStartFileToken -StartFilePath $StartFilePath

    $logPath = Resolve-PreferredDefaultPath -PreferredPath (Join-Path $queueRoot ("takeover_trigger_{0}.log" -f $stableToken)) -LegacyPath (Join-Path $queueRoot ("takeover_trigger_{0}.log" -f $legacyToken))
    $statePath = Resolve-PreferredDefaultPath -PreferredPath (Join-Path $queueRoot ("takeover_trigger_state_{0}.json" -f $stableToken)) -LegacyPath (Join-Path $queueRoot ("takeover_trigger_state_{0}.json" -f $legacyToken))

    return [pscustomobject]@{
        Log = $logPath
        State = $statePath
    }
}

function Resolve-AnchorPath {
    param([AllowEmptyString()][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return ''
    }

    try {
        return Resolve-RepoPath -Path $Path
    }
    catch {
        return ''
    }
}

function Get-PathStatus {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
		return [pscustomobject]@{
			State = 'missing-anchor'
			Time = ''
		}
    }

    if (-not (Test-Path -LiteralPath $Path)) {
		return [pscustomobject]@{
			State = 'missing-path'
			Time = ''
		}
    }

    $item = Get-Item -LiteralPath $Path
	return [pscustomobject]@{
		State = 'ok'
		Time = $item.LastWriteTime.ToString('HH:mm:ss')
	}
}

function Get-DisplayPath {
    param(
        [string]$Path,
        [ValidateRange(20, 220)][int]$MaxLength = 92
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return '-'
    }

    $display = (Convert-ToRepoRelativePath -Path $Path).Replace('\\', '/')
    if ($display.Length -le $MaxLength) {
        return $display
    }

    return ('...' + $display.Substring($display.Length - ($MaxLength - 3)))
}

function Get-TimestampShort {
    param([string]$Line)

    if ($Line -match 'timestamp=([0-9]{4}-[0-9]{2}-[0-9]{2}\s+([0-9]{2}:[0-9]{2}:[0-9]{2}))') {
        return $Matches[2]
    }

    return '--:--:--'
}

function Get-PathLeafToken {
    param([string]$Token)

    if ([string]::IsNullOrWhiteSpace($Token)) {
        return ''
    }

    $normalized = $Token.Trim().TrimEnd(',', ';').Replace('/', '\\')
    return [System.IO.Path]::GetFileName($normalized)
}

function Format-SupervisorEventLine {
    param([string]$Line)

    $time = Get-TimestampShort -Line $Line

    if ($Line -match 'stage_final\s+stage=([A-Z])\s+result=([A-Za-z]+)\s+exit_code=([0-9-]+)') {
        return ('[{0}] stage_final stage={1} result={2} exit={3}' -f $time, $Matches[1], $Matches[2], $Matches[3])
    }

    if ($Line -match 'heartbeat.*stage=([A-Z]).*row_count=([0-9]+).*file_count=([0-9]+).*latest_path=([^ ]+).*remote_chain_count=([0-9]+)') {
        $leaf = Get-PathLeafToken -Token $Matches[4]
        return ('[{0}] heartbeat stage={1} rows={2} files={3} chain={4} latest={5}' -f $time, $Matches[1], $Matches[2], $Matches[3], $Matches[5], $leaf)
    }

    $compact = [regex]::Replace($Line, '^\[[^\]]+\]\s*', '')
    $compact = [regex]::Replace($compact, '\s+', ' ').Trim()
    if ($compact.Length -gt 135) {
        $compact = $compact.Substring(0, 132) + '...'
    }

    return ('[{0}] {1}' -f $time, $compact)
}

function Format-CompanionEventLine {
    param([string]$Line)

    $time = Get-TimestampShort -Line $Line

    if ($Line -match 'heartbeat.*stage=([A-Z]).*row_count=([0-9]+).*file_count=([0-9]+).*latest_path=([^ ]+).*remote_chain_count=([0-9]+)(?:.*supervisor_quiet=([A-Za-z]+))?') {
        $leaf = Get-PathLeafToken -Token $Matches[4]
        $quiet = if ($Matches[6]) { $Matches[6] } else { '?' }
        return ('[{0}] heartbeat stage={1} rows={2} files={3} chain={4} quiet={5} latest={6}' -f $time, $Matches[1], $Matches[2], $Matches[3], $Matches[5], $quiet, $leaf)
    }

    $compact = [regex]::Replace($Line, '^\[[^\]]+\]\s*', '')
    $compact = [regex]::Replace($compact, '\s+', ' ').Trim()
    if ($compact.Length -gt 135) {
        $compact = $compact.Substring(0, 132) + '...'
    }

    return ('[{0}] {1}' -f $time, $compact)
}

function Format-GuardEventLine {
    param([string]$Line)

    $time = Get-TimestampShort -Line $Line

    if ($Line -match 'incident\s+status=([A-Z]+)\s+a=([A-Z]+)\s+b=([A-Z]+)\s+evidence=([^ ]+)') {
        $incident = Get-PathLeafToken -Token $Matches[4]
        return ('[{0}] incident status={1} a={2} b={3} evidence={4}' -f $time, $Matches[1], $Matches[2], $Matches[3], $incident)
    }

    if ($Line -match 'recovery_triggered\s+stage=([A-Z])\s+attempt=([0-9]+)') {
        return ('[{0}] recovery_triggered stage={1} attempt={2}' -f $time, $Matches[1], $Matches[2])
    }

    if ($Line -match 'heartbeat\s+session=([A-Z]+)\s+a=([A-Z]+)\s+b=([A-Z]+)\s+running=([A-Za-z]+)\s+run_dir=([^ ]+)') {
        $runId = Get-PathLeafToken -Token $Matches[5]
        return ('[{0}] heartbeat session={1} a={2} b={3} running={4} run={5}' -f $time, $Matches[1], $Matches[2], $Matches[3], $Matches[4], $runId)
    }

    if ($Line -match 'watch_heartbeat.*stage=([^ ]+).*row_count=([0-9]+).*file_count=([0-9]+).*latest_path=([^ ]+).*remote_chain_count=([0-9]+)') {
        $leaf = Get-PathLeafToken -Token $Matches[4]
        return ('[{0}] watch_heartbeat stage={1} rows={2} files={3} chain={4} latest={5}' -f $time, $Matches[1], $Matches[2], $Matches[3], $Matches[5], $leaf)
    }

    if ($Line -match 'loop_error\s+detail=(.+)$') {
        return ('[{0}] loop_error {1}' -f $time, $Matches[1])
    }

    $compact = [regex]::Replace($Line, '^\[[^\]]+\]\s*', '')
    $compact = [regex]::Replace($compact, '\s+', ' ').Trim()
    if ($compact.Length -gt 135) {
        $compact = $compact.Substring(0, 132) + '...'
    }

    return ('[{0}] {1}' -f $time, $compact)
}

function Format-TriggerEventLine {
    param([string]$Line)

    $time = Get-TimestampShort -Line $Line

    if ($Line -match 'ticket_dispatch\s+id=([^ ]+)\s+event=([^ ]+)\s+brief=([^ ]+)') {
        return ('[{0}] ticket_dispatch id={1} event={2}' -f $time, $Matches[1], $Matches[2])
    }

    if ($Line -match 'external_trigger_route_allowed\s+id=([^ ]+).*classification=([^ ]+).*latency_ms=([0-9]+)') {
        return ('[{0}] route_allowed id={1} class={2} latency_ms={3}' -f $time, $Matches[1], $Matches[2], $Matches[3])
    }

    if ($Line -match 'status_conflict_deferred\s+owner=guard\s+action=([^ ]+)\s+artifact=([^ ]+)') {
        $artifact = Get-PathLeafToken -Token $Matches[2]
        return ('[{0}] status_conflict_deferred action={1} artifact={2}' -f $time, $Matches[1], $artifact)
    }

    if ($Line -match 'fast_poll_window_open\s+ttl_sec=([0-9]+)\s+reason=(.+)$') {
        return ('[{0}] fast_poll ttl_sec={1} reason={2}' -f $time, $Matches[1], $Matches[2])
    }

    $compact = [regex]::Replace($Line, '^\[[^\]]+\]\s*', '')
    $compact = [regex]::Replace($compact, '\s+', ' ').Trim()
    if ($compact.Length -gt 135) {
        $compact = $compact.Substring(0, 132) + '...'
    }

    return ('[{0}] {1}' -f $time, $compact)
}

function Write-EventSection {
    param(
        [string]$Title,
        [string[]]$Lines,
        [scriptblock]$Formatter
    )

    $lineList = @()
    foreach ($candidate in @($Lines)) {
        if ($null -eq $candidate) {
            continue
        }

        $lineList += [string]$candidate
    }

    if ($lineList.Length -lt 1) {
        return $false
    }

    Write-Host ('  ' + $Title + ':')
    foreach ($line in $lineList) {
        $formatted = & $Formatter $line
        if (-not [string]::IsNullOrWhiteSpace($formatted)) {
            Write-Host ('    - ' + $formatted)
        }
    }

    return $true
}

function Get-LogTailMatch {
    param(
        [string]$Path,
        [string]$Pattern,
        [int]$Lines
    )

    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) {
        return @()
    }

    $scanLines = [Math]::Min(500, [Math]::Max($Lines, $Lines * 8))
    $matchedLines = @(Get-Content -LiteralPath $Path -Tail $scanLines -ErrorAction SilentlyContinue | Where-Object { $_ -match $Pattern })
    if ($matchedLines.Count -le $Lines) {
        return @($matchedLines)
    }

    return @($matchedLines | Select-Object -Last $Lines)
}

function Write-Snapshot {
    param([string]$StartFilePath)

    $settings = Read-KeyValueFile -Path $StartFilePath
    $sessionStatus = Get-StatusValue -Value ([string]$settings.SESSION_FINAL_STATUS)
    $aStatus = Get-StatusValue -Value ([string]$settings.A_FINAL_STATUS)
    $bStatus = Get-StatusValue -Value ([string]$settings.B_FINAL_STATUS)
    $watchExpected = ($sessionStatus -eq 'RUNNING' -or $aStatus -eq 'RUNNING' -or $bStatus -eq 'RUNNING')
    $sessionTerminal = Test-IsTerminalFinalStatus -Status $sessionStatus

    $anchors = Get-AnchorMap -Settings $settings

    $guardArtifacts = Get-LatestGuardArtifactSet
    if ([string]::IsNullOrWhiteSpace([string]$anchors.guard_log) -and $null -ne $guardArtifacts -and (Test-Path -LiteralPath $guardArtifacts.Log)) {
        $anchors.guard_log = $guardArtifacts.Log
    }
    if ([string]::IsNullOrWhiteSpace([string]$anchors.guard_state) -and $null -ne $guardArtifacts -and (Test-Path -LiteralPath $guardArtifacts.State)) {
        $anchors.guard_state = $guardArtifacts.State
    }

    $triggerArtifacts = Get-TriggerArtifactSet -StartFilePath $StartFilePath
    if ([string]::IsNullOrWhiteSpace([string]$anchors.trigger_log) -and $null -ne $triggerArtifacts -and (Test-Path -LiteralPath $triggerArtifacts.Log)) {
        $anchors.trigger_log = $triggerArtifacts.Log
    }
    if ([string]::IsNullOrWhiteSpace([string]$anchors.trigger_state) -and $null -ne $triggerArtifacts -and (Test-Path -LiteralPath $triggerArtifacts.State)) {
        $anchors.trigger_state = $triggerArtifacts.State
    }

    $resolved = [ordered]@{}
    foreach ($key in $anchors.Keys) {
        $resolved[$key] = Resolve-AnchorPath -Path ([string]$anchors[$key])
    }

    $now = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Write-Host ("[{0}] status  A={1}  B={2}  SESSION={3}" -f $now, [string]$settings.A_FINAL_STATUS, [string]$settings.B_FINAL_STATUS, [string]$settings.SESSION_FINAL_STATUS)
    Write-Host ''
    Write-Host 'Anchors'

    foreach ($key in @('run_dir', 'supervisor_log', 'companion_log', 'live_status', 'guard_log', 'guard_state', 'trigger_log', 'trigger_state')) {
        $path = [string]$resolved[$key]
        $status = Get-PathStatus -Path $path
        $statusText = if ($status.State -eq 'ok') { 'ok@' + $status.Time } else { $status.State }
        $pathText = Get-DisplayPath -Path $path
        Write-Host ("  {0,-14} {1,-14} {2}" -f ($key + ':'), $statusText, $pathText)
    }

    $supTail = Get-LogTailMatch -Path ([string]$resolved.supervisor_log) -Pattern 'heartbeat|stage_final|blocked|stop|complete|error|exception' -Lines $script:TailLines

    $compTail = Get-LogTailMatch -Path ([string]$resolved.companion_log) -Pattern 'heartbeat|blocked|unknown-stage-stall|error|exception' -Lines $script:TailLines

    $guardTail = Get-LogTailMatch -Path ([string]$resolved.guard_log) -Pattern 'incident|restart_begin|recovery_triggered|loop_error|manual_action_required|heartbeat' -Lines $script:TailLines

    $triggerTail = Get-LogTailMatch -Path ([string]$resolved.trigger_log) -Pattern 'ticket_dispatch|external_trigger_route_allowed|status_conflict_deferred|fast_poll_window_open|loop_error|shutdown|auto_stop' -Lines $script:TailLines

    Write-Host ''
    Write-Host ('Events (last ' + $script:TailLines + ' matching lines)')
    $printed = $false
    if (Write-EventSection -Title 'Supervisor' -Lines $supTail -Formatter { param($line) Format-SupervisorEventLine -Line $line }) {
        $printed = $true
    }
    if (Write-EventSection -Title 'Companion' -Lines $compTail -Formatter { param($line) Format-CompanionEventLine -Line $line }) {
        $printed = $true
    }
    if (Write-EventSection -Title 'Guard' -Lines $guardTail -Formatter { param($line) Format-GuardEventLine -Line $line }) {
        $printed = $true
    }
    if (Write-EventSection -Title 'Trigger' -Lines $triggerTail -Formatter { param($line) Format-TriggerEventLine -Line $line }) {
        $printed = $true
    }
    if (-not $printed) {
        Write-Host '  (no matching events in current tail window)'
    }

    return [pscustomobject]@{
        watch_expected = [bool]$watchExpected
        session_status = $sessionStatus
        a_status = $aStatus
        b_status = $bStatus
        session_terminal = [bool]$sessionTerminal
    }
}

$script:RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$startFilePath = Resolve-RepoPath -Path $StartFile
Invoke-StartupWatchDedupe -StartFilePath $startFilePath -SkipDedupe:$Once.IsPresent
$startFileRel = Convert-ToRepoRelativePath -Path $startFilePath
$persistLifecycleState = -not $Once.IsPresent
$watchParentPid = 0
try {
    $selfProcess = Get-CimInstance Win32_Process -Filter ("ProcessId={0}" -f $PID) -ErrorAction Stop
    if ($null -ne $selfProcess) {
        $watchParentPid = [int]$selfProcess.ParentProcessId
    }
}
catch {
    $watchParentPid = 0
}
Write-Output ("[WATCH-AB-LIGHT] startup_pid pid={0} parent_pid={1} start_file={2} interval_sec={3} once={4}" -f $PID, $watchParentPid, $startFileRel, $IntervalSec, [bool]$Once.IsPresent)

if ($persistLifecycleState) {
    try {
        Invoke-WatchLifecycleStateUpdate -StartFilePath $startFilePath -Phase 'startup' -WatchPid $PID -ParentPid $watchParentPid
        Write-Output ("[WATCH-AB-LIGHT] lifecycle_write phase=startup watch_pid={0}" -f $PID)
    }
    catch {
        Write-Output ("[WATCH-AB-LIGHT] lifecycle_write_failed phase=startup detail={0}" -f $_.Exception.Message)
    }
}

try {
    do {
        if (-not $NoClear.IsPresent) {
            Clear-Host
        }

        $snapshotState = $null
        try {
            $snapshotState = Write-Snapshot -StartFilePath $startFilePath
        }
        catch {
            Write-Output ("[WATCH-AB-LIGHT] error={0}" -f $_.Exception.Message)
        }

        $autoStopOnFinal = -not $NoAutoStopOnFinal.IsPresent
        if ($autoStopOnFinal -and -not $Once.IsPresent -and $null -ne $snapshotState) {
            if ([bool]$snapshotState.session_terminal -and -not [bool]$snapshotState.watch_expected) {
                Write-Output ("[WATCH-AB-LIGHT] auto_stop reason=session-final session={0} a={1} b={2}" -f [string]$snapshotState.session_status, [string]$snapshotState.a_status, [string]$snapshotState.b_status)
                if ($ExitShellOnFinal.IsPresent -or (Test-CurrentHostNoExitMode)) {
                    [Environment]::Exit(0)
                }

                break
            }
        }

        if ($Once.IsPresent) {
            break
        }

        Start-Sleep -Seconds $IntervalSec
    }
    while ($true)
}
finally {
    if ($persistLifecycleState) {
        try {
            Invoke-WatchLifecycleStateUpdate -StartFilePath $startFilePath -Phase 'shutdown' -WatchPid $PID -ParentPid $watchParentPid
            Write-Output ("[WATCH-AB-LIGHT] lifecycle_write phase=shutdown watch_pid={0}" -f $PID)
        }
        catch {
            Write-Output ("[WATCH-AB-LIGHT] lifecycle_write_failed phase=shutdown detail={0}" -f $_.Exception.Message)
        }
    }

    Write-Output ("[WATCH-AB-LIGHT] shutdown_pid pid={0}" -f $PID)
}
