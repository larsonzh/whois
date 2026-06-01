param(
    [ValidateSet('A', 'B')][string]$Stage,
    [string]$StartFile = 'testdata\unattended_start\active\unattended_ab_start_20260504-1123.md',
    [switch]$StartMonitors,
    [switch]$SkipMonitorRestart,
    [switch]$EnableBMonitorRestart
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$dispatchPolicyModulePath = Join-Path $PSScriptRoot 'chat_dispatch_policy_compiler.ps1'
if (-not (Test-Path -LiteralPath $dispatchPolicyModulePath)) {
    throw "Missing script: $dispatchPolicyModulePath"
}
. $dispatchPolicyModulePath

function Resolve-RepoPath {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw 'Path must not be empty.'
    }

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return (Resolve-Path -LiteralPath $Path).Path
    }

    return (Resolve-Path -LiteralPath (Join-Path $repoRoot $Path)).Path
}

function Resolve-RepoPathAllowMissing {
    param(
        [AllowEmptyString()][string]$Path,
        [string]$RepoRoot
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return ''
    }

    try {
        if ([System.IO.Path]::IsPathRooted($Path)) {
            return [System.IO.Path]::GetFullPath($Path)
        }

        return [System.IO.Path]::GetFullPath((Join-Path $RepoRoot $Path))
    }
    catch {
        return ''
    }
}

function Get-CurrentSourceDiffSet {
    param([string]$RepoRoot)

    $gitWarningPattern = '^\s*(warning:|git(\.exe)?\s*:\s*warning:)'
    $lines = @()
    try {
        $lines = @((& git -C $RepoRoot diff --name-only -- src include 2>&1) | ForEach-Object { [string]$_ })
        $exitCode = if ($null -eq $LASTEXITCODE) { 0 } else { [int]$LASTEXITCODE }
        if ($exitCode -ne 0) {
            $detailLines = @($lines | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
            $detail = if ($detailLines.Count -gt 0) { $detailLines -join ' | ' } else { 'no-output' }
            throw ("git diff --name-only failed exit={0} detail={1}" -f $exitCode, $detail)
        }
    }
    catch {
        throw ("failed to collect current source diff set: {0}" -f $_.Exception.Message)
    }

    $result = New-Object 'System.Collections.Generic.List[string]'
    foreach ($raw in $lines) {
        if ([string]::IsNullOrWhiteSpace($raw)) {
            continue
        }

        $line = ([string]$raw).Trim()
        if ($line -match $gitWarningPattern) {
            continue
        }

        $normalized = $line.Replace('\\', '/').Trim()
        if ([string]::IsNullOrWhiteSpace($normalized)) {
            continue
        }

        [void]$result.Add($normalized)
    }

    return @($result | Sort-Object -Unique)
}

function Test-BNormalModeSourceAlignedWithSnapshot {
    param(
        [string]$RepoRoot,
        [string]$SnapshotDir
    )

    $sourceDir = Join-Path $SnapshotDir 'source'
    if (-not (Test-Path -LiteralPath $sourceDir)) {
        throw "snapshot source directory missing: $sourceDir"
    }

    $sourceFilesPath = Join-Path $SnapshotDir 'source_files.txt'
    $snapshotPaths = New-Object 'System.Collections.Generic.List[string]'

    if (Test-Path -LiteralPath $sourceFilesPath) {
        foreach ($raw in @(Get-Content -LiteralPath $sourceFilesPath -Encoding utf8 -ErrorAction Stop)) {
            if ([string]::IsNullOrWhiteSpace([string]$raw)) {
                continue
            }

            $normalized = ([string]$raw).Trim().Replace('\\', '/').Trim()
            if ([string]::IsNullOrWhiteSpace($normalized)) {
                continue
            }

            [void]$snapshotPaths.Add($normalized)
        }
    }
    else {
        $sourceDirFull = [System.IO.Path]::GetFullPath($sourceDir)
        foreach ($file in @(Get-ChildItem -LiteralPath $sourceDir -File -Recurse -ErrorAction SilentlyContinue)) {
            $relative = $file.FullName.Substring($sourceDirFull.Length).TrimStart('\\').Replace('\\', '/')
            if ([string]::IsNullOrWhiteSpace($relative)) {
                continue
            }

            [void]$snapshotPaths.Add($relative)
        }
    }

    $snapshotList = @($snapshotPaths | Sort-Object -Unique)
    $currentList = @(Get-CurrentSourceDiffSet -RepoRoot $RepoRoot)

    $snapshotSet = @{}
    foreach ($path in $snapshotList) {
        $snapshotSet[[string]$path] = $true
    }

    $currentSet = @{}
    foreach ($path in $currentList) {
        $currentSet[[string]$path] = $true
    }

    $missing = New-Object 'System.Collections.Generic.List[string]'
    foreach ($path in $snapshotList) {
        if (-not $currentSet.ContainsKey([string]$path)) {
            [void]$missing.Add([string]$path)
        }
    }

    $extra = New-Object 'System.Collections.Generic.List[string]'
    foreach ($path in $currentList) {
        if (-not $snapshotSet.ContainsKey([string]$path)) {
            [void]$extra.Add([string]$path)
        }
    }

    $contentMismatches = New-Object 'System.Collections.Generic.List[string]'
    foreach ($path in $snapshotList) {
        if (-not $currentSet.ContainsKey([string]$path)) {
            continue
        }

        $relativeWindows = ([string]$path).Replace('/', '\\')
        $snapshotFile = Join-Path $sourceDir $relativeWindows
        $currentFile = Join-Path $RepoRoot $relativeWindows

        if (-not (Test-Path -LiteralPath $snapshotFile) -or -not (Test-Path -LiteralPath $currentFile)) {
            [void]$contentMismatches.Add([string]$path)
            continue
        }

        $snapshotHash = (Get-FileHash -LiteralPath $snapshotFile -Algorithm SHA256).Hash
        $currentHash = (Get-FileHash -LiteralPath $currentFile -Algorithm SHA256).Hash
        if ($snapshotHash -ne $currentHash) {
            [void]$contentMismatches.Add([string]$path)
        }
    }

    $match = ($missing.Count -eq 0 -and $extra.Count -eq 0 -and $contentMismatches.Count -eq 0)
    return [pscustomobject]@{
        Match = [bool]$match
        SnapshotCount = [int]$snapshotList.Count
        CurrentCount = [int]$currentList.Count
        MissingCount = [int]$missing.Count
        ExtraCount = [int]$extra.Count
        ContentMismatchCount = [int]$contentMismatches.Count
        Missing = @($missing)
        Extra = @($extra)
        ContentMismatches = @($contentMismatches)
    }
}

function Assert-BStartEligibility {
    param(
        [ValidateSet('A', 'B')][string]$Stage,
        [System.Collections.IDictionary]$Settings,
        [string]$StartFilePath,
        [string]$RepoRoot,
        [string]$ScriptTag,
        [bool]$BRestartModeRequested
    )

    if ($Stage -ne 'B') {
        return [pscustomobject]@{
            GateRequired = $false
            EffectiveRestartMode = $false
            SnapshotStatusPath = ''
            SnapshotDir = ''
            Alignment = $null
        }
    }

    $requiresSnapshotGate = if ($Settings.Contains('B_START_REQUIRES_A_PASS_WITH_SNAPSHOT')) {
        Convert-ToBooleanSetting -Value ([string]$Settings.B_START_REQUIRES_A_PASS_WITH_SNAPSHOT) -Default $true
    }
    else {
        $true
    }

    if (-not $requiresSnapshotGate) {
        Write-Host ("[{0}] b_start_gate required=false action=skip" -f $ScriptTag)
        return [pscustomobject]@{
            GateRequired = $false
            EffectiveRestartMode = $false
            SnapshotStatusPath = ''
            SnapshotDir = ''
            Alignment = $null
        }
    }

    $aFinalStatus = if ($Settings.Contains('A_FINAL_STATUS')) {
        ([string]$Settings.A_FINAL_STATUS).Trim().ToUpperInvariant()
    }
    else {
        ''
    }

    if ($aFinalStatus -ne 'PASS') {
        throw ("[{0}] b_start_gate blocked: A_FINAL_STATUS must be PASS (actual={1})" -f $ScriptTag, $aFinalStatus)
    }

    $snapshotStatusRaw = if ($Settings.Contains('A_SUCCESS_SNAPSHOT_FINAL_STATUS')) {
        [string]$Settings.A_SUCCESS_SNAPSHOT_FINAL_STATUS
    }
    else {
        ''
    }

    if ([string]::IsNullOrWhiteSpace($snapshotStatusRaw)) {
        throw ("[{0}] b_start_gate blocked: A_SUCCESS_SNAPSHOT_FINAL_STATUS is empty" -f $ScriptTag)
    }

    $snapshotStatusPath = Resolve-RepoPathAllowMissing -Path $snapshotStatusRaw -RepoRoot $RepoRoot
    if ([string]::IsNullOrWhiteSpace($snapshotStatusPath) -or -not (Test-Path -LiteralPath $snapshotStatusPath)) {
        throw ("[{0}] b_start_gate blocked: snapshot final status not found ({1})" -f $ScriptTag, $snapshotStatusRaw)
    }

    $snapshotDir = Join-Path (Split-Path -Parent $snapshotStatusPath) 'a_success_snapshot'
    if (-not (Test-Path -LiteralPath $snapshotDir)) {
        throw ("[{0}] b_start_gate blocked: snapshot directory missing ({1})" -f $ScriptTag, (Convert-ToAnchorPath -Path $snapshotDir))
    }

    $alignment = Test-BNormalModeSourceAlignedWithSnapshot -RepoRoot $RepoRoot -SnapshotDir $snapshotDir
    $effectiveRestartMode = $false

    if ([bool]$alignment.Match) {
        Write-Host ("[{0}] b_normal_mode_source_guard status=PASS snapshot_files={1} current_files={2}" -f
            $ScriptTag,
            [int]$alignment.SnapshotCount,
            [int]$alignment.CurrentCount)

        if ($BRestartModeRequested) {
            Write-Host ("[{0}] b_restart_mode_request ignored=true reason=auto-mode-selected-normal" -f $ScriptTag)
        }
    }
    else {
        $effectiveRestartMode = $true
        Write-Host ("[{0}] b_mode_auto selected=restart reason=source-mismatch missing={1} extra={2} content_mismatch={3} action=restore-from-a-snapshot" -f
            $ScriptTag,
            [int]$alignment.MissingCount,
            [int]$alignment.ExtraCount,
            [int]$alignment.ContentMismatchCount)

        if ($BRestartModeRequested) {
            Write-Host ("[{0}] b_restart_mode_request requested=true effective=true reason=auto-mode-selected-restart" -f $ScriptTag)
        }
    }

    $modeText = if ($effectiveRestartMode) { 'restart' } else { 'normal' }

    Write-Host ("[{0}] b_start_gate status=PASS a_status={1} snapshot_status={2} snapshot_dir={3} mode={4}" -f
        $ScriptTag,
        $aFinalStatus,
        (Convert-ToAnchorPath -Path $snapshotStatusPath),
        (Convert-ToAnchorPath -Path $snapshotDir),
        $modeText)

    return [pscustomobject]@{
        GateRequired = $true
        EffectiveRestartMode = [bool]$effectiveRestartMode
        SnapshotStatusPath = [string]$snapshotStatusPath
        SnapshotDir = [string]$snapshotDir
        Alignment = $alignment
    }
}

function Resolve-TaskDefinitionRelativePath {
    param(
        [AllowEmptyString()][string]$InputName,
        [string]$SettingKey
    )

    if ([string]::IsNullOrWhiteSpace($InputName)) {
        throw ("{0} is missing in start file." -f $SettingKey)
    }

    $normalized = $InputName.Trim().Replace('\\', '/')
    if ($normalized.StartsWith('./')) {
        $normalized = $normalized.Substring(2)
    }

    if ($normalized -match '^(?:[A-Za-z]:|/|\\\\)') {
        throw ("{0} must be a repository-relative path under testdata/." -f $SettingKey)
    }

    if (-not $normalized.StartsWith('testdata/')) {
        $normalized = 'testdata/' + $normalized
    }

    return $normalized
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

function Get-StartFileMutexName {
    param([string]$StartFilePath)

    $fullPath = [System.IO.Path]::GetFullPath($StartFilePath).ToLowerInvariant()
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($fullPath)
    $sha1 = [System.Security.Cryptography.SHA1]::Create()
    try {
        $hashBytes = $sha1.ComputeHash($bytes)
    }
    finally {
        $sha1.Dispose()
    }

    $hash = [System.BitConverter]::ToString($hashBytes).Replace('-', '')
    return "Local\whois-unattended-startfile-write-$hash"
}

function Read-KeyValueFile {
    param([string]$Path)

    $keyLineMap = @{}
    $map = [ordered]@{}
    $lineNo = 0
    foreach ($line in @(Get-Content -LiteralPath $Path -Encoding utf8 -ErrorAction Stop)) {
        $lineNo++
        if ($line -match '^([^=]+)=(.*)$') {
            $key = $Matches[1].Trim()
            if ($map.Contains($key)) {
                $firstLine = [int]$keyLineMap[$key]
                throw ("Duplicate key '{0}' detected in {1} at line {2} and line {3}." -f $key, $Path, $firstLine, $lineNo)
            }

            $keyLineMap[$key] = $lineNo
            $map[$key] = $Matches[2]
        }
    }

    return $map
}

function Set-KeyValueFileValues {
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
        Set-Content -LiteralPath $tempPath -Value @($buffer) -Encoding utf8 -ErrorAction Stop
        Move-Item -LiteralPath $tempPath -Destination $Path -Force
        $tempPath = ''
    }
    finally {
        if (-not [string]::IsNullOrWhiteSpace($tempPath) -and (Test-Path -LiteralPath $tempPath)) {
            Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue
        }

        if ($locked) {
            try { $mutex.ReleaseMutex() } catch {}
        }
        $mutex.Dispose()
    }
}

function Get-LatestAnchorValueFromNotes {
    param(
        [AllowEmptyString()][string]$Notes,
        [string]$Key
    )

    if ([string]::IsNullOrWhiteSpace($Notes) -or [string]::IsNullOrWhiteSpace($Key)) {
        return ''
    }

    $parts = @($Notes -split ';')
    for ($index = $parts.Count - 1; $index -ge 0; $index--) {
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

function Convert-ToAnchorPath {
    param([AllowEmptyString()][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return ''
    }

    $normalized = $Path.Trim().Replace('/', '\\')
    if (-not [System.IO.Path]::IsPathRooted($normalized)) {
        return $normalized
    }

    $fullPath = [System.IO.Path]::GetFullPath($normalized)
    $repoRootFull = [System.IO.Path]::GetFullPath($repoRoot)
    if ($fullPath.StartsWith($repoRootFull, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $fullPath.Substring($repoRootFull.Length).TrimStart('\\')
    }

    return $fullPath
}

function Update-SessionAnchorsInStartFile {
    param(
        [string]$Path,
        [System.Collections.IDictionary]$Anchors
    )

    $settingsMap = Read-KeyValueFile -Path $Path
    $existingNotes = if ($settingsMap.Contains('SESSION_FINAL_NOTES')) { [string]$settingsMap.SESSION_FINAL_NOTES } else { '' }
    $segments = New-Object 'System.Collections.Generic.List[string]'

    foreach ($part in @($existingNotes -split ';')) {
        $segment = [string]$part
        if ([string]::IsNullOrWhiteSpace($segment)) {
            continue
        }

        $trimmed = $segment.Trim()
        if ($trimmed -match '^(run_dir|supervisor_log|companion_log|live_status|b_runtime_log)=') {
            continue
        }

        [void]$segments.Add($trimmed)
    }

    foreach ($anchorKey in @('run_dir', 'supervisor_log', 'companion_log', 'live_status', 'b_runtime_log')) {
        if (-not $Anchors.ContainsKey($anchorKey)) {
            continue
        }

        $value = [string]$Anchors[$anchorKey]
        if ([string]::IsNullOrWhiteSpace($value)) {
            continue
        }

        [void]$segments.Add("$anchorKey=$value")
    }

    $newNotes = ($segments -join '; ')
    Set-KeyValueFileValues -Path $Path -Values @{ SESSION_FINAL_NOTES = $newNotes }
    return $newNotes
}

function Test-ProcessAlive {
    param([int]$ProcessId)

    if ($ProcessId -le 0) {
        return $false
    }

    return ($null -ne (Get-Process -Id $ProcessId -ErrorAction SilentlyContinue))
}

function Get-ParsedPositiveInt {
    param([AllowEmptyString()][string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return 0
    }

    $parsed = 0
    if ([int]::TryParse($Value.Trim(), [ref]$parsed) -and $parsed -gt 0) {
        return $parsed
    }

    return 0
}

function Test-StageLaunchAllowed {
    param(
        [ValidateSet('A', 'B')][string]$Stage,
        [System.Collections.IDictionary]$Settings,
        [string]$ScriptTag
    )

    $sameStatusKey = if ($Stage -eq 'A') { 'A_FINAL_STATUS' } else { 'B_FINAL_STATUS' }
    $samePidKey = if ($Stage -eq 'A') { 'A_LAUNCH_PID' } else { 'B_LAUNCH_PID' }
    $peerStage = if ($Stage -eq 'A') { 'B' } else { 'A' }
    $peerStatusKey = if ($Stage -eq 'A') { 'B_FINAL_STATUS' } else { 'A_FINAL_STATUS' }
    $peerPidKey = if ($Stage -eq 'A') { 'B_LAUNCH_PID' } else { 'A_LAUNCH_PID' }

    $samePid = if ($Settings.Contains($samePidKey)) {
        Get-ParsedPositiveInt -Value ([string]$Settings[$samePidKey])
    }
    else {
        0
    }
    if ($samePid -gt 0 -and (Test-ProcessAlive -ProcessId $samePid)) {
        $sameStatus = if ($Settings.Contains($sameStatusKey)) { [string]$Settings[$sameStatusKey] } else { '' }
        $sessionStatus = if ($Settings.Contains('SESSION_FINAL_STATUS')) { [string]$Settings.SESSION_FINAL_STATUS } else { '' }
        Write-Output ("[{0}] existing_stage_running stage={1} pid={2} stage_status={3} session_status={4} action=skip_launch" -f $ScriptTag, $Stage, $samePid, $sameStatus, $sessionStatus)
        return $false
    }

    $peerPid = if ($Settings.Contains($peerPidKey)) {
        Get-ParsedPositiveInt -Value ([string]$Settings[$peerPidKey])
    }
    else {
        0
    }
    if ($peerPid -gt 0 -and (Test-ProcessAlive -ProcessId $peerPid)) {
        $peerStatus = if ($Settings.Contains($peerStatusKey)) { [string]$Settings[$peerStatusKey] } else { '' }
        $sessionStatus = if ($Settings.Contains('SESSION_FINAL_STATUS')) { [string]$Settings.SESSION_FINAL_STATUS } else { '' }
        Write-Output ("[{0}] peer_stage_running stage={1} peer_stage={2} peer_pid={3} peer_status={4} session_status={5} action=skip_launch" -f $ScriptTag, $Stage, $peerStage, $peerPid, $peerStatus, $sessionStatus)
        return $false
    }

    return $true
}

function Resolve-CurrentStageRunDir {
    param(
        [datetime]$LaunchTime,
        [System.Collections.IDictionary]$Settings,
        [string]$SessionOutDirRoot,
        [int]$StageProcessId = 0
    )

    $currentRunDir = ''
    for ($attempt = 0; $attempt -lt 24; $attempt++) {
        $candidate = Get-LatestTimestampedDirectory -Root $SessionOutDirRoot -After $LaunchTime
        if ($null -ne $candidate) {
            $currentRunDir = $candidate.FullName
            break
        }

        if ($StageProcessId -gt 0 -and -not (Test-ProcessAlive -ProcessId $StageProcessId)) {
            break
        }

        Start-Sleep -Seconds 5
    }

    if (-not [string]::IsNullOrWhiteSpace($currentRunDir)) {
        return $currentRunDir
    }

    if ($StageProcessId -gt 0 -and -not (Test-ProcessAlive -ProcessId $StageProcessId)) {
        return ''
    }

    if ($null -ne $Settings -and $Settings.Contains('SESSION_FINAL_NOTES')) {
        $hintRunDir = Get-LatestAnchorValueFromNotes -Notes ([string]$Settings.SESSION_FINAL_NOTES) -Key 'run_dir'
        if (-not [string]::IsNullOrWhiteSpace($hintRunDir)) {
            try {
                return (Resolve-RepoPath -Path $hintRunDir)
            }
            catch {
                return ''
            }
        }
    }

    return ''
}

function Convert-ToBooleanSetting {
    param(
        [AllowEmptyString()][string]$Value,
        [bool]$Default = $false
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $Default
    }

    return $Value.Trim().ToLowerInvariant() -in @('1', 'true', 'yes', 'on')
}

function Convert-ToSingleLineText {
    param([AllowEmptyString()][string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return ''
    }

    return ([regex]::Replace($Text.Trim(), '\s+', ' '))
}

function Set-DispatchDeliveryEnabled {
    param(
        [string]$Path,
        [System.Collections.IDictionary]$Settings,
        [string]$ScriptTag
    )

    $defaultTriggerCommand = 'powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/dispatch_takeover_to_chat.ps1 -TicketId "%TICKET_ID%" -TicketEvent "%EVENT%" -StartFile "%START_FILE%" -QueuePath "%QUEUE_PATH%" -BriefPath "%BRIEF_PATH%" -NoOpenEditor -SkipClipboard'
    $policyPlan = Get-ChatDispatchPolicyPlan -Settings $Settings -DefaultTriggerCommand $defaultTriggerCommand
    $updates = if ($null -ne $policyPlan) { [hashtable]$policyPlan.Updates } else { @{} }
    $changes = if ($null -ne $policyPlan) { @($policyPlan.Changes) } else { @() }

    if ($updates.Count -gt 0) {
        Set-KeyValueFileValues -Path $Path -Values $updates
        Write-Host ("[{0}] dispatch_policy_autofix applied={1}" -f $ScriptTag, ($changes -join ','))
        return (Read-KeyValueFile -Path $Path)
    }

    $resolvedPolicy = if ($null -ne $policyPlan) { $policyPlan.ResolvedPolicy } else { $null }
    $policySummary = ''
    if ($null -ne $resolvedPolicy) {
        $policySummary = ('work_mode={0} primary={1} fallback={2} final_stop_gate={3}' -f [string]$resolvedPolicy.work_mode, [string]$resolvedPolicy.delivery_primary, [string]$resolvedPolicy.delivery_fallback, [string]$resolvedPolicy.final_stop_gate)
    }
    Write-Host ("[{0}] dispatch_policy_guard status=PASS {1}" -f $ScriptTag, (Convert-ToSingleLineText -Text $policySummary))
    return $Settings
}

function Clear-MonitorChainShutdownRequest {
    param(
        [string]$Path,
        [System.Collections.IDictionary]$Settings,
        [string]$ScriptTag
    )

    $requested = $false
    if ($null -ne $Settings -and $Settings.Contains('MONITOR_CHAIN_SHUTDOWN_REQUESTED')) {
        $requested = Convert-ToBooleanSetting -Value ([string]$Settings.MONITOR_CHAIN_SHUTDOWN_REQUESTED) -Default $false
    }

    $reason = if ($null -ne $Settings -and $Settings.Contains('MONITOR_CHAIN_SHUTDOWN_REASON')) { [string]$Settings.MONITOR_CHAIN_SHUTDOWN_REASON } else { '' }
    $source = if ($null -ne $Settings -and $Settings.Contains('MONITOR_CHAIN_SHUTDOWN_SOURCE')) { [string]$Settings.MONITOR_CHAIN_SHUTDOWN_SOURCE } else { '' }
    $requestedAt = if ($null -ne $Settings -and $Settings.Contains('MONITOR_CHAIN_SHUTDOWN_AT')) { [string]$Settings.MONITOR_CHAIN_SHUTDOWN_AT } else { '' }
    $detail = if ($null -ne $Settings -and $Settings.Contains('MONITOR_CHAIN_SHUTDOWN_DETAIL')) { [string]$Settings.MONITOR_CHAIN_SHUTDOWN_DETAIL } else { '' }

    if (-not $requested -and [string]::IsNullOrWhiteSpace($reason) -and [string]::IsNullOrWhiteSpace($source) -and [string]::IsNullOrWhiteSpace($requestedAt) -and [string]::IsNullOrWhiteSpace($detail)) {
        Write-Host ("[{0}] monitor_chain_shutdown_reset status=PASS" -f $ScriptTag)
        return $Settings
    }

    Set-KeyValueFileValues -Path $Path -Values @{
        MONITOR_CHAIN_SHUTDOWN_REQUESTED = 'false'
        MONITOR_CHAIN_SHUTDOWN_REASON = ''
        MONITOR_CHAIN_SHUTDOWN_SOURCE = ''
        MONITOR_CHAIN_SHUTDOWN_AT = ''
        MONITOR_CHAIN_SHUTDOWN_DETAIL = ''
    }
    Write-Host ("[{0}] monitor_chain_shutdown_reset applied=true" -f $ScriptTag)
    return (Read-KeyValueFile -Path $Path)
}

function Convert-MsysPathToWindowsPath {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return ''
    }

    if ($Path -match '^/([a-zA-Z])/(.*)$') {
        $drive = $Matches[1].ToUpperInvariant()
        $rest = $Matches[2] -replace '/', '\\'
        return ("{0}:\\{1}" -f $drive, $rest)
    }

    return $Path
}

function Resolve-RemoteKeyPathForNetworkPrecheck {
    param([string]$InputPath)

    if (-not [string]::IsNullOrWhiteSpace($InputPath) -and (Test-Path -LiteralPath $InputPath)) {
        return (Resolve-Path -LiteralPath $InputPath).Path
    }

    $converted = Convert-MsysPathToWindowsPath -Path $InputPath
    if (-not [string]::IsNullOrWhiteSpace($converted) -and (Test-Path -LiteralPath $converted)) {
        return (Resolve-Path -LiteralPath $converted).Path
    }

    throw "Unable to resolve SSH private key for network precheck. input=$InputPath"
}

function Assert-PrecheckGateReady {
    param(
        [System.Collections.IDictionary]$Settings,
        [string]$StartFilePath,
        [string]$ScriptTag
    )

    if ($null -eq $Settings) {
        throw "[$ScriptTag] start file settings map is null"
    }

    $precheckRequired = if ($Settings.Contains('PRECHECK_REQUIRED')) {
        Convert-ToBooleanSetting -Value ([string]$Settings.PRECHECK_REQUIRED) -Default $true
    }
    else {
        $true
    }

    if (-not $precheckRequired) {
        Write-Output ("[{0}] precheck_gate required=false action=skip" -f $ScriptTag)
        return
    }

    $statusRaw = if ($Settings.Contains('PRECHECK_STATUS')) { [string]$Settings.PRECHECK_STATUS } else { '' }
    $startGateRaw = if ($Settings.Contains('PRECHECK_START_GATE')) { [string]$Settings.PRECHECK_START_GATE } else { '' }
    $remoteLockRaw = if ($Settings.Contains('PRECHECK_REMOTE_LOCK')) { [string]$Settings.PRECHECK_REMOTE_LOCK } else { '' }

    $status = $statusRaw.Trim().ToUpperInvariant()
    $startGate = $startGateRaw.Trim().ToUpperInvariant()
    $remoteLock = $remoteLockRaw.Trim().ToUpperInvariant()
    $allowedRemoteLockStates = @('ABSENT', 'HELD-BY-SELF')

    $reasons = New-Object 'System.Collections.Generic.List[string]'
    if ($status -ne 'PASS') {
        [void]$reasons.Add(("PRECHECK_STATUS={0}" -f $statusRaw))
    }
    if ($startGate -ne 'READY') {
        [void]$reasons.Add(("PRECHECK_START_GATE={0}" -f $startGateRaw))
    }
    if (-not ($allowedRemoteLockStates -contains $remoteLock)) {
        [void]$reasons.Add(("PRECHECK_REMOTE_LOCK={0}" -f $remoteLockRaw))
    }

    if ($reasons.Count -gt 0) {
        $reasonText = ($reasons -join '; ')
        Set-KeyValueFileValues -Path $StartFilePath -Values @{
            PRECHECK_START_GATE = 'BLOCKED'
            PRECHECK_START_BLOCKER = $reasonText
            PRECHECK_FAILURE_REASON = $reasonText
        }
        throw ("[{0}] precheck gate blocked: {1}" -f $ScriptTag, $reasonText)
    }

    Write-Output ("[{0}] precheck_gate status=PASS gate=READY remote_lock={1}" -f $ScriptTag, $remoteLockRaw)
}

function Assert-NetworkPrecheckReady {
    param(
        [System.Collections.IDictionary]$Settings,
        [string]$StartFilePath,
        [string]$ScriptTag,
        [string]$RepoRoot
    )

    if ($null -eq $Settings) {
        throw "[$ScriptTag] start file settings map is null for network precheck"
    }

    $networkPrecheckRequired = if ($Settings.Contains('NETWORK_PRECHECK_REQUIRED')) {
        Convert-ToBooleanSetting -Value ([string]$Settings.NETWORK_PRECHECK_REQUIRED) -Default $true
    }
    else {
        $true
    }

    if (-not $networkPrecheckRequired) {
        Write-Output ("[{0}] network_precheck required=false action=skip" -f $ScriptTag)
        return
    }

    $checkLocal = if ($Settings.Contains('NETWORK_PRECHECK_LOCAL_REQUIRED')) {
        Convert-ToBooleanSetting -Value ([string]$Settings.NETWORK_PRECHECK_LOCAL_REQUIRED) -Default $true
    }
    else {
        $true
    }

    $checkRemote = if ($Settings.Contains('NETWORK_PRECHECK_REMOTE_REQUIRED')) {
        Convert-ToBooleanSetting -Value ([string]$Settings.NETWORK_PRECHECK_REMOTE_REQUIRED) -Default $true
    }
    else {
        $true
    }

    $checkIPv4 = if ($Settings.Contains('NETWORK_PRECHECK_CHECK_IPV4')) {
        Convert-ToBooleanSetting -Value ([string]$Settings.NETWORK_PRECHECK_CHECK_IPV4) -Default $true
    }
    else {
        $true
    }

    $checkIPv6 = if ($Settings.Contains('NETWORK_PRECHECK_CHECK_IPV6')) {
        Convert-ToBooleanSetting -Value ([string]$Settings.NETWORK_PRECHECK_CHECK_IPV6) -Default $true
    }
    else {
        $true
    }

    $requireIPv4 = if ($Settings.Contains('NETWORK_PRECHECK_REQUIRE_IPV4')) {
        Convert-ToBooleanSetting -Value ([string]$Settings.NETWORK_PRECHECK_REQUIRE_IPV4) -Default $false
    }
    else {
        $false
    }

    $requireIPv6 = if ($Settings.Contains('NETWORK_PRECHECK_REQUIRE_IPV6')) {
        Convert-ToBooleanSetting -Value ([string]$Settings.NETWORK_PRECHECK_REQUIRE_IPV6) -Default $true
    }
    else {
        $true
    }

    if (-not $checkLocal -and -not $checkRemote) {
        throw "[$ScriptTag] network precheck misconfigured: both local and remote checks are disabled"
    }

    if (-not $checkIPv4 -and -not $checkIPv6) {
        throw "[$ScriptTag] network precheck misconfigured: both IPv4 and IPv6 checks are disabled"
    }

    if ($requireIPv4 -and -not $checkIPv4) {
        $checkIPv4 = $true
    }
    if ($requireIPv6 -and -not $checkIPv6) {
        $checkIPv6 = $true
    }

    $targets = if ($Settings.Contains('NETWORK_PRECHECK_TARGETS') -and -not [string]::IsNullOrWhiteSpace([string]$Settings.NETWORK_PRECHECK_TARGETS)) {
        [string]$Settings.NETWORK_PRECHECK_TARGETS
    }
    else {
        'whois.iana.org;whois.arin.net'
    }

    $timeoutSec = 8
    if ($Settings.Contains('NETWORK_PRECHECK_TIMEOUT_SEC')) {
        $parsedTimeout = 0
        if ([int]::TryParse(([string]$Settings.NETWORK_PRECHECK_TIMEOUT_SEC), [ref]$parsedTimeout)) {
            if ($parsedTimeout -ge 1 -and $parsedTimeout -le 30) {
                $timeoutSec = $parsedTimeout
            }
        }
    }

    $remoteIp = if ($Settings.Contains('REMOTE_IP') -and -not [string]::IsNullOrWhiteSpace([string]$Settings.REMOTE_IP)) {
        [string]$Settings.REMOTE_IP
    }
    else {
        '10.0.0.199'
    }

    $remoteUser = if ($Settings.Contains('REMOTE_USER') -and -not [string]::IsNullOrWhiteSpace([string]$Settings.REMOTE_USER)) {
        [string]$Settings.REMOTE_USER
    }
    else {
        'larson'
    }

    $remoteKeyRaw = if ($Settings.Contains('REMOTE_KEYPATH') -and -not [string]::IsNullOrWhiteSpace([string]$Settings.REMOTE_KEYPATH)) {
        [string]$Settings.REMOTE_KEYPATH
    }
    else {
        "/c/Users/$env:USERNAME/.ssh/id_rsa"
    }

    $precheckScript = Join-Path $RepoRoot 'tools\dev\check_dualstack_whois_connectivity.ps1'
    if (-not (Test-Path -LiteralPath $precheckScript)) {
        throw "[$ScriptTag] network precheck script not found: $precheckScript"
    }

    $resolvedKeyPath = ''
    if ($checkRemote) {
        $resolvedKeyPath = Resolve-RemoteKeyPathForNetworkPrecheck -InputPath $remoteKeyRaw
    }

    $outputLines = @()
    $exitCode = 1
    try {
        $outputLines = @((& $precheckScript `
            -Targets $targets `
            -TimeoutSec $timeoutSec `
            -CheckLocal:$checkLocal `
            -CheckRemote:$checkRemote `
            -CheckIPv4:$checkIPv4 `
            -CheckIPv6:$checkIPv6 `
            -RequireIPv4:$requireIPv4 `
            -RequireIPv6:$requireIPv6 `
            -RemoteIp $remoteIp `
            -RemoteUser $remoteUser `
            -KeyPath $resolvedKeyPath 2>&1) | ForEach-Object { [string]$_ })
        $exitCode = if ($null -eq $LASTEXITCODE) { 0 } else { [int]$LASTEXITCODE }
    }
    catch {
        $exitCode = 1
        $outputLines = @($_.Exception.Message)
    }

    foreach ($line in @($outputLines)) {
        if (-not [string]::IsNullOrWhiteSpace($line)) {
            Write-Output $line
        }
    }

    $nowText = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    if ($exitCode -ne 0) {
        $reason = "NETWORK_PRECHECK_FAIL exit=$exitCode targets=$targets local=$checkLocal remote=$checkRemote check_ipv4=$checkIPv4 check_ipv6=$checkIPv6 require_ipv4=$requireIPv4 require_ipv6=$requireIPv6"
        Set-KeyValueFileValues -Path $StartFilePath -Values @{
            PRECHECK_START_GATE = 'BLOCKED'
            PRECHECK_START_BLOCKER = $reason
            PRECHECK_FAILURE_REASON = $reason
            NETWORK_PRECHECK_LAST_RESULT = 'FAIL'
            NETWORK_PRECHECK_LAST_AT = $nowText
            NETWORK_PRECHECK_LAST_REASON = $reason
        }
        throw ("[{0}] network precheck blocked: {1}" -f $ScriptTag, $reason)
    }

    Set-KeyValueFileValues -Path $StartFilePath -Values @{
        NETWORK_PRECHECK_LAST_RESULT = 'PASS'
        NETWORK_PRECHECK_LAST_AT = $nowText
        NETWORK_PRECHECK_LAST_REASON = ''
    }
    Write-Output ("[{0}] network_precheck status=PASS targets={1} local={2} remote={3} check_ipv4={4} check_ipv6={5} require_ipv4={6} require_ipv6={7}" -f $ScriptTag, $targets, $checkLocal, $checkRemote, $checkIPv4, $checkIPv6, $requireIPv4, $requireIPv6)
}

function Set-EnvFromSetting {
    param(
        [string]$EnvName,
        [System.Collections.IDictionary]$Settings,
        [string]$Key
    )

    if ($null -eq $Settings -or -not $Settings.Contains($Key)) {
        return
    }

    $value = [string]$Settings[$Key]
    if ([string]::IsNullOrWhiteSpace($value)) {
        return
    }

    Set-Item -Path ("Env:{0}" -f $EnvName) -Value $value
}

function Get-LatestTimestampedDirectory {
    param(
        [string]$Root,
        [Nullable[datetime]]$After = $null
    )

    if (-not (Test-Path -LiteralPath $Root)) {
        return $null
    }

    $dirs = Get-ChildItem -LiteralPath $Root -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^[0-9]{8}-[0-9]{6}$' }

    if ($null -ne $After) {
        $dirs = @($dirs | Where-Object { $_.CreationTime -ge $After.AddSeconds(-2) -or $_.LastWriteTime -ge $After.AddSeconds(-2) })
    }

    $candidates = @($dirs | Sort-Object CreationTime, LastWriteTime -Descending | Select-Object -First 1)
    if ($candidates.Count -lt 1) {
        return $null
    }

    return $candidates[0]
}

function Stop-MonitorProcessesForStartFile {
    param([string]$StartFilePath)

    $startFileIdentity = Get-NormalizedPathIdentity -Path $StartFilePath -RepoRoot $repoRoot
    if ([string]::IsNullOrWhiteSpace($startFileIdentity)) {
        return @()
    }

    $targetPids = @(
        Get-CimInstance Win32_Process |
            Where-Object {
                $commandLine = [string]$_.CommandLine
                if ([string]::IsNullOrWhiteSpace($commandLine)) {
                    return $false
                }

                $line = $commandLine.ToLowerInvariant()
                if ($line -notmatch 'unattended_ab_supervisor\.ps1|unattended_ab_companion\.ps1|unattended_ab_session_guard\.ps1|unattended_ab_takeover_trigger\.ps1') {
                    return $false
                }

                $processStartFileIdentity = Get-StartFilePathFromCommandLine -CommandLine $commandLine -RepoRoot $repoRoot
                if ([string]::IsNullOrWhiteSpace($processStartFileIdentity)) {
                    return $false
                }

                return ($processStartFileIdentity -eq $startFileIdentity)
            } |
            Select-Object -ExpandProperty ProcessId -Unique
    )

    foreach ($targetPid in $targetPids) {
        Stop-Process -Id ([int]$targetPid) -Force -ErrorAction SilentlyContinue
    }

    return @($targetPids)
}

function Get-MonitorBindingState {
    param(
        [string]$ScriptLeaf,
        [string]$StartFilePath,
        [string]$RepoRoot
    )

    $scriptNeedle = $ScriptLeaf.Trim().ToLowerInvariant()
    $startFileIdentity = Get-NormalizedPathIdentity -Path $StartFilePath -RepoRoot $RepoRoot
    $matchPids = New-Object 'System.Collections.Generic.List[int]'
    $mismatchPids = New-Object 'System.Collections.Generic.List[int]'
    $unboundPids = New-Object 'System.Collections.Generic.List[int]'

    $candidates = @(
        Get-CimInstance Win32_Process |
            Where-Object {
                $commandLine = [string]$_.CommandLine
                if ([string]::IsNullOrWhiteSpace($commandLine)) {
                    return $false
                }

                return $commandLine.ToLowerInvariant().Contains($scriptNeedle)
            } |
            Select-Object ProcessId, CommandLine
    )

    foreach ($proc in $candidates) {
        $processId = [int]$proc.ProcessId
        $processStartFileIdentity = Get-StartFilePathFromCommandLine -CommandLine ([string]$proc.CommandLine) -RepoRoot $RepoRoot

        if ([string]::IsNullOrWhiteSpace($processStartFileIdentity)) {
            [void]$unboundPids.Add($processId)
            continue
        }

        if ($processStartFileIdentity -eq $startFileIdentity) {
            [void]$matchPids.Add($processId)
        }
        else {
            [void]$mismatchPids.Add($processId)
        }
    }

    return [pscustomobject]@{
        ScriptLeaf = $ScriptLeaf
        RunningForStartFile = ($matchPids.Count -gt 0)
        MatchCount = [int]$matchPids.Count
        MismatchCount = [int]$mismatchPids.Count
        UnboundCount = [int]$unboundPids.Count
        TotalCount = [int]($matchPids.Count + $mismatchPids.Count + $unboundPids.Count)
        MatchPids = @($matchPids)
        MismatchPids = @($mismatchPids)
        UnboundPids = @($unboundPids)
    }
}

function Get-AnchorValueFromSettings {
    param(
        [System.Collections.IDictionary]$Settings,
        [string]$Key
    )

    if ($null -eq $Settings -or [string]::IsNullOrWhiteSpace($Key)) {
        return ''
    }

    if (-not $Settings.Contains('SESSION_FINAL_NOTES')) {
        return ''
    }

    return Get-LatestAnchorValueFromNotes -Notes ([string]$Settings.SESSION_FINAL_NOTES) -Key $Key
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$startFilePath = Resolve-RepoPath -Path $StartFile
$settings = Read-KeyValueFile -Path $startFilePath
$settings = Set-DispatchDeliveryEnabled -Path $startFilePath -Settings $settings -ScriptTag 'OPEN-AB-STAGE'
Assert-PrecheckGateReady -Settings $settings -StartFilePath $startFilePath -ScriptTag 'OPEN-AB-STAGE'
Assert-NetworkPrecheckReady -Settings $settings -StartFilePath $startFilePath -ScriptTag 'OPEN-AB-STAGE' -RepoRoot $repoRoot
$settings = Read-KeyValueFile -Path $startFilePath
$settings = Set-DispatchDeliveryEnabled -Path $startFilePath -Settings $settings -ScriptTag 'OPEN-AB-STAGE'
$settings = Clear-MonitorChainShutdownRequest -Path $startFilePath -Settings $settings -ScriptTag 'OPEN-AB-STAGE'
$bRestartModeRequested = ($Stage -eq 'B' -and $EnableBMonitorRestart.IsPresent)
$bLaunchPlan = Assert-BStartEligibility -Stage $Stage -Settings $settings -StartFilePath $startFilePath -RepoRoot $repoRoot -ScriptTag 'OPEN-AB-STAGE' -BRestartModeRequested $bRestartModeRequested
$bRestartModeForGate = if ($Stage -eq 'B') { [bool]$bLaunchPlan.EffectiveRestartMode } else { $false }

$previousAFinalStatus = if ($settings.Contains('A_FINAL_STATUS')) {
    [string]$settings.A_FINAL_STATUS
}
else {
    ''
}
$previousBFinalStatus = if ($settings.Contains('B_FINAL_STATUS')) {
    [string]$settings.B_FINAL_STATUS
}
else {
    ''
}

if (-not (Test-StageLaunchAllowed -Stage $Stage -Settings $settings -ScriptTag 'OPEN-AB-STAGE')) {
    return
}

$entryScriptKey = if ($Stage -eq 'A') { 'ENTRY_SCRIPT_A' } else { 'ENTRY_SCRIPT_B' }
$taskKey = if ($Stage -eq 'A') { 'A_TASK_DEFINITION' } else { 'B_TASK_DEFINITION' }

$entryScriptPath = Resolve-RepoPath -Path ([string]$settings[$entryScriptKey])
$taskDefinitionRelative = Resolve-TaskDefinitionRelativePath -InputName ([string]$settings[$taskKey]) -SettingKey $taskKey
$null = Resolve-RepoPath -Path $taskDefinitionRelative

$powershellPath = Join-Path $PSHOME 'powershell.exe'
if (-not (Test-Path -LiteralPath $powershellPath)) {
    $powershellPath = 'powershell.exe'
}

Set-EnvFromSetting -EnvName 'AUTO_REMOTE_IP' -Settings $settings -Key 'REMOTE_IP'
Set-EnvFromSetting -EnvName 'AUTO_REMOTE_USER' -Settings $settings -Key 'REMOTE_USER'
Set-EnvFromSetting -EnvName 'AUTO_REMOTE_KEYPATH' -Settings $settings -Key 'REMOTE_KEYPATH'
Set-EnvFromSetting -EnvName 'AUTO_QUERIES' -Settings $settings -Key 'QUERIES'
Set-EnvFromSetting -EnvName 'AUTO_TERMINAL_WATCHDOG_MODE' -Settings $settings -Key 'TERMINAL_WATCHDOG_MODE'
Set-EnvFromSetting -EnvName 'AUTO_TERMINAL_WATCHDOG_INTERVAL_SEC' -Settings $settings -Key 'TERMINAL_WATCHDOG_INTERVAL_SEC'
Set-EnvFromSetting -EnvName 'AUTO_TERMINAL_WATCHDOG_MIN_AGE_SEC' -Settings $settings -Key 'TERMINAL_WATCHDOG_MIN_AGE_SEC'
Set-EnvFromSetting -EnvName 'AUTO_REMOTE_BUILD_LOCK_REQUIRED' -Settings $settings -Key 'REMOTE_BUILD_LOCK_REQUIRED'
Set-EnvFromSetting -EnvName 'AUTO_REMOTE_BUILD_LOCK_SCOPE' -Settings $settings -Key 'REMOTE_BUILD_LOCK_SCOPE'
Set-EnvFromSetting -EnvName 'AUTO_REMOTE_BUILD_LOCK_CONFLICT_ACTION' -Settings $settings -Key 'REMOTE_BUILD_LOCK_CONFLICT_ACTION'
Set-EnvFromSetting -EnvName 'AUTO_NETWORK_PRECHECK_REQUIRED' -Settings $settings -Key 'NETWORK_PRECHECK_REQUIRED'
Set-EnvFromSetting -EnvName 'AUTO_NETWORK_PRECHECK_LOCAL_REQUIRED' -Settings $settings -Key 'NETWORK_PRECHECK_LOCAL_REQUIRED'
Set-EnvFromSetting -EnvName 'AUTO_NETWORK_PRECHECK_REMOTE_REQUIRED' -Settings $settings -Key 'NETWORK_PRECHECK_REMOTE_REQUIRED'
Set-EnvFromSetting -EnvName 'AUTO_NETWORK_PRECHECK_CHECK_IPV4' -Settings $settings -Key 'NETWORK_PRECHECK_CHECK_IPV4'
Set-EnvFromSetting -EnvName 'AUTO_NETWORK_PRECHECK_CHECK_IPV6' -Settings $settings -Key 'NETWORK_PRECHECK_CHECK_IPV6'
Set-EnvFromSetting -EnvName 'AUTO_NETWORK_PRECHECK_REQUIRE_IPV4' -Settings $settings -Key 'NETWORK_PRECHECK_REQUIRE_IPV4'
Set-EnvFromSetting -EnvName 'AUTO_NETWORK_PRECHECK_REQUIRE_IPV6' -Settings $settings -Key 'NETWORK_PRECHECK_REQUIRE_IPV6'
Set-EnvFromSetting -EnvName 'AUTO_NETWORK_PRECHECK_TARGETS' -Settings $settings -Key 'NETWORK_PRECHECK_TARGETS'
Set-EnvFromSetting -EnvName 'AUTO_NETWORK_PRECHECK_TIMEOUT_SEC' -Settings $settings -Key 'NETWORK_PRECHECK_TIMEOUT_SEC'
Set-EnvFromSetting -EnvName 'AUTO_ROUND_RUNTIME_GATE_ENABLED' -Settings $settings -Key 'ROUND_RUNTIME_GATE_ENABLED'
Set-EnvFromSetting -EnvName 'AUTO_ROUND_RUNTIME_GATE_START_ROUND' -Settings $settings -Key 'ROUND_RUNTIME_GATE_START_ROUND'
Set-EnvFromSetting -EnvName 'AUTO_ROUND_RUNTIME_GATE_MAX_ATTEMPTS' -Settings $settings -Key 'ROUND_RUNTIME_GATE_MAX_ATTEMPTS'
Set-EnvFromSetting -EnvName 'AUTO_ROUND_RUNTIME_GATE_RETRY_DELAY_SEC' -Settings $settings -Key 'ROUND_RUNTIME_GATE_RETRY_DELAY_SEC'
Set-EnvFromSetting -EnvName 'AUTO_ROUND_RUNTIME_GATE_MIN_FREE_DISK_MB' -Settings $settings -Key 'ROUND_RUNTIME_GATE_MIN_FREE_DISK_MB'
Set-EnvFromSetting -EnvName 'AUTO_ROUND_RUNTIME_GATE_CHECK_REMOTE_LOCK' -Settings $settings -Key 'ROUND_RUNTIME_GATE_CHECK_REMOTE_LOCK'
Set-EnvFromSetting -EnvName 'AUTO_ROUND_RUNTIME_GATE_CHECK_NETWORK' -Settings $settings -Key 'ROUND_RUNTIME_GATE_CHECK_NETWORK'
Set-EnvFromSetting -EnvName 'AUTO_ROUND_RUNTIME_GATE_CHECK_PROCESS_CONFLICT' -Settings $settings -Key 'ROUND_RUNTIME_GATE_CHECK_PROCESS_CONFLICT'
Set-EnvFromSetting -EnvName 'AUTO_TASK_STATIC_PRECHECK_POLICY' -Settings $settings -Key 'TASK_STATIC_PRECHECK_POLICY'
Remove-Item -Path 'Env:AUTO_KEEP_WINDOW_ON_EXIT' -ErrorAction SilentlyContinue
Set-EnvFromSetting -EnvName 'AUTO_KEEP_WINDOW_ON_EXIT' -Settings $settings -Key 'KEEP_WINDOW_ON_EXIT'

Remove-Item -Path 'Env:AUTO_A_PREVIOUS_FINAL_STATUS' -ErrorAction SilentlyContinue
Remove-Item -Path 'Env:AUTO_B_PREVIOUS_FINAL_STATUS' -ErrorAction SilentlyContinue
Remove-Item -Path 'Env:AUTO_B_RESTORE_FROM_A_SNAPSHOT' -ErrorAction SilentlyContinue
Remove-Item -Path 'Env:AUTO_B_A_SNAPSHOT_DIR' -ErrorAction SilentlyContinue

if ($Stage -eq 'B') {
    Set-Item -Path 'Env:AUTO_A_PREVIOUS_FINAL_STATUS' -Value $previousAFinalStatus
    Set-Item -Path 'Env:AUTO_B_PREVIOUS_FINAL_STATUS' -Value $previousBFinalStatus

    $restoreFromASnapshot = if ($bRestartModeForGate) { 'true' } else { 'false' }
    $restoreDecisionReason = if ($bRestartModeForGate) { 'auto-mode=restart' } else { 'auto-mode=normal' }

    Set-Item -Path 'Env:AUTO_B_RESTORE_FROM_A_SNAPSHOT' -Value $restoreFromASnapshot

    $snapshotDirHint = ''
    if ($null -ne $bLaunchPlan -and $bLaunchPlan.PSObject.Properties.Name -contains 'SnapshotDir') {
        $snapshotDirHint = [string]$bLaunchPlan.SnapshotDir
    }

    if ($settings.Contains('SESSION_FINAL_NOTES')) {
        if ([string]::IsNullOrWhiteSpace($snapshotDirHint)) {
            $snapshotDirHint = Get-LatestAnchorValueFromNotes -Notes ([string]$settings.SESSION_FINAL_NOTES) -Key 'a_snapshot_dir'
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($snapshotDirHint)) {
        Set-Item -Path 'Env:AUTO_B_A_SNAPSHOT_DIR' -Value $snapshotDirHint
    }

    Write-Output ("[OPEN-AB-STAGE] b_restore_decision previous_a={0} previous_b={1} restore={2} reason={3}" -f $previousAFinalStatus, $previousBFinalStatus, $restoreFromASnapshot, $restoreDecisionReason)
}

$stageRuntimeLogPath = ''
if ($Stage -eq 'B') {
    $runtimeLogRoot = Join-Path $repoRoot 'out\artifacts\ab_stage_runtime\B'
    if (-not (Test-Path -LiteralPath $runtimeLogRoot)) {
        New-Item -ItemType Directory -Path $runtimeLogRoot -Force | Out-Null
    }

    $runtimeStamp = (Get-Date).ToString('yyyyMMdd-HHmmss-fff')
    $stageRuntimeLogPath = Join-Path $runtimeLogRoot ("b_runtime_{0}.log" -f $runtimeStamp)
    Set-Item -Path 'Env:AUTO_STAGE_RUNTIME_LOG_PATH' -Value $stageRuntimeLogPath
}
else {
    Remove-Item -Path 'Env:AUTO_STAGE_RUNTIME_LOG_PATH' -ErrorAction SilentlyContinue
}

Set-Item -Path 'Env:AUTO_START_FILE_PATH' -Value $startFilePath

$keepWindowOnExit = if ($settings.Contains('KEEP_WINDOW_ON_EXIT')) {
    Convert-ToBooleanSetting -Value ([string]$settings.KEEP_WINDOW_ON_EXIT) -Default $true
}
else {
    $true
}

$stageLaunchTime = Get-Date
$stageArgumentList = @(
    '-NoProfile',
    '-ExecutionPolicy', 'Bypass',
    '-File', $entryScriptPath,
    $taskDefinitionRelative
)
if ($keepWindowOnExit) {
    $stageArgumentList = @('-NoExit') + $stageArgumentList
}

$processInfo = Start-Process -FilePath $powershellPath -WorkingDirectory $repoRoot -ArgumentList $stageArgumentList -PassThru

Write-Output ("[OPEN-AB-STAGE] stage={0} pid={1} launcher_pid={2} entry={3} task={4}" -f $Stage, $processInfo.Id, $PID, $entryScriptPath, $taskDefinitionRelative)
if ($Stage -eq 'B' -and -not [string]::IsNullOrWhiteSpace($stageRuntimeLogPath)) {
    Write-Output ("[OPEN-AB-STAGE] runtime_log={0}" -f (Convert-ToAnchorPath -Path $stageRuntimeLogPath))
}

$statusUpdates = @{
    SESSION_FINAL_STATUS = 'RUNNING'
    SESSION_CLOSED = 'false'
    SESSION_CLOSED_AT = ''
    SESSION_CLOSED_REASON = ''
}
if ($Stage -eq 'A') {
    $statusUpdates['A_FINAL_STATUS'] = 'RUNNING'
    $statusUpdates['A_LAUNCH_PID'] = [string]$processInfo.Id
}
else {
    $statusUpdates['B_FINAL_STATUS'] = 'RUNNING'
    $statusUpdates['B_LAUNCH_PID'] = [string]$processInfo.Id
    if (-not [string]::IsNullOrWhiteSpace($stageRuntimeLogPath)) {
        $statusUpdates['B_RUNTIME_LOG'] = Convert-ToAnchorPath -Path $stageRuntimeLogPath
    }
}
Set-KeyValueFileValues -Path $startFilePath -Values $statusUpdates
$settings = Read-KeyValueFile -Path $startFilePath
Write-Output ("[OPEN-AB-STAGE] stage_status_update stage={0} session_status=RUNNING" -f $Stage)

$sessionOutDirRoot = Join-Path $repoRoot 'out\artifacts\dev_verify_multiround'
$currentStageRunDir = Resolve-CurrentStageRunDir -LaunchTime $stageLaunchTime -Settings $settings -SessionOutDirRoot $sessionOutDirRoot -StageProcessId ([int]$processInfo.Id)
if (-not [string]::IsNullOrWhiteSpace($currentStageRunDir)) {
    $updatedNotes = Update-SessionAnchorsInStartFile -Path $startFilePath -Anchors @{ run_dir = (Convert-ToAnchorPath -Path $currentStageRunDir) }
    Write-Output ("[OPEN-AB-STAGE] anchor_update run_dir={0}" -f (Convert-ToAnchorPath -Path $currentStageRunDir))
    $settings = Read-KeyValueFile -Path $startFilePath
}
else {
    Write-Output '[OPEN-AB-STAGE] anchor_update run_dir=unknown'

    $stageAlive = Test-ProcessAlive -ProcessId ([int]$processInfo.Id)
    if (-not $stageAlive) {
        $failureDetail = ("stage={0} pid={1} exited_before_run_dir" -f $Stage, $processInfo.Id)
        $failureNotes = "stage_launch_fail $failureDetail"
        $failUpdates = @{
            SESSION_FINAL_STATUS = 'FAIL'
            SESSION_FINAL_NOTES = ''
        }

        if ($Stage -eq 'A') {
            $failUpdates['A_FINAL_STATUS'] = 'FAIL'
            if ($settings.Contains('B_FINAL_STATUS') -and [string]$settings.B_FINAL_STATUS -eq 'NOT_RUN') {
                $failUpdates['B_FINAL_STATUS'] = 'BLOCKED'
            }
            $failUpdates['A_LAUNCH_PID'] = '0'
        }
        else {
            $failUpdates['B_FINAL_STATUS'] = 'FAIL'
            $failUpdates['B_LAUNCH_PID'] = '0'
        }

        if ($settings.Contains('SESSION_FINAL_NOTES') -and -not [string]::IsNullOrWhiteSpace([string]$settings.SESSION_FINAL_NOTES)) {
            $failUpdates['SESSION_FINAL_NOTES'] = ([string]$settings.SESSION_FINAL_NOTES + '; ' + $failureNotes)
        }
        else {
            $failUpdates['SESSION_FINAL_NOTES'] = $failureNotes
        }

        Set-KeyValueFileValues -Path $startFilePath -Values $failUpdates
        Write-Output ("[OPEN-AB-STAGE] stage_launch_fail {0}" -f $failureDetail)
        return
    }
}

$autoStartMonitors = $false
if ($Stage -eq 'A') {
    $autoStartMonitors = if ($StartMonitors.IsPresent) {
        $true
    }
    elseif ($settings.Contains('AUTO_START_MONITORS')) {
        Convert-ToBooleanSetting -Value ([string]$settings.AUTO_START_MONITORS) -Default $false
    }
    else {
        $false
    }
}
elseif ($EnableBMonitorRestart.IsPresent) {
    $autoStartMonitors = $true
}
elseif ($Stage -eq 'B') {
    $autoStartMonitors = if ($settings.Contains('AUTO_START_MONITORS')) {
        Convert-ToBooleanSetting -Value ([string]$settings.AUTO_START_MONITORS) -Default $true
    }
    else {
        $true
    }
}

if (-not $autoStartMonitors) {
    return
}

$bRestartMode = $bRestartModeForGate
if ($bRestartMode) {
    Write-Output '[OPEN-AB-STAGE] b_restart_mode=true policy=force_full_monitor_restart'
}

$skipMonitorRestart = $SkipMonitorRestart.IsPresent
if ($skipMonitorRestart -and $Stage -eq 'B') {
    Write-Output '[OPEN-AB-STAGE] monitor_restart_skip_ignored stage=B reason=monitor-policy-enforced'
    $skipMonitorRestart = $false
}

if ($bRestartMode -and -not $skipMonitorRestart) {
    Write-Output '[OPEN-AB-STAGE] b_monitor_rebind force_restart_all=true targets=supervisor,companion,guard,trigger'
    $stoppedPids = @(Stop-MonitorProcessesForStartFile -StartFilePath $startFilePath)
    Write-Output ("[OPEN-AB-STAGE] monitor_restart stopped_count={0} stopped_pids={1}" -f $stoppedPids.Count, ($stoppedPids -join ','))
}

$supervisorLauncherRelative = if ($settings.Contains('MONITOR_ENTRY_SCRIPT_SUPERVISOR') -and -not [string]::IsNullOrWhiteSpace([string]$settings.MONITOR_ENTRY_SCRIPT_SUPERVISOR)) {
    [string]$settings.MONITOR_ENTRY_SCRIPT_SUPERVISOR
}
else {
    'tools/test/open_unattended_ab_supervisor_window.ps1'
}

$companionLauncherRelative = if ($settings.Contains('MONITOR_ENTRY_SCRIPT_COMPANION') -and -not [string]::IsNullOrWhiteSpace([string]$settings.MONITOR_ENTRY_SCRIPT_COMPANION)) {
    [string]$settings.MONITOR_ENTRY_SCRIPT_COMPANION
}
else {
    'tools/test/open_unattended_ab_companion_window.ps1'
}

$guardLauncherRelative = if ($settings.Contains('MONITOR_ENTRY_SCRIPT_GUARD') -and -not [string]::IsNullOrWhiteSpace([string]$settings.MONITOR_ENTRY_SCRIPT_GUARD)) {
    [string]$settings.MONITOR_ENTRY_SCRIPT_GUARD
}
else {
    'tools/test/open_unattended_ab_session_guard_window.ps1'
}

$triggerLauncherRelative = if ($settings.Contains('MONITOR_ENTRY_SCRIPT_TRIGGER') -and -not [string]::IsNullOrWhiteSpace([string]$settings.MONITOR_ENTRY_SCRIPT_TRIGGER)) {
    [string]$settings.MONITOR_ENTRY_SCRIPT_TRIGGER
}
else {
    'tools/test/open_unattended_ab_takeover_trigger_window.ps1'
}

$supervisorLauncherPath = Resolve-RepoPath -Path $supervisorLauncherRelative
$companionLauncherPath = Resolve-RepoPath -Path $companionLauncherRelative
$guardLauncherPath = Resolve-RepoPath -Path $guardLauncherRelative
$triggerLauncherPath = Resolve-RepoPath -Path $triggerLauncherRelative

$monitorStates = @{}
if (-not $bRestartMode) {
    $monitorStates.supervisor = Get-MonitorBindingState -ScriptLeaf 'unattended_ab_supervisor.ps1' -StartFilePath $startFilePath -RepoRoot $repoRoot
    $monitorStates.companion = Get-MonitorBindingState -ScriptLeaf 'unattended_ab_companion.ps1' -StartFilePath $startFilePath -RepoRoot $repoRoot
    $monitorStates.guard = Get-MonitorBindingState -ScriptLeaf 'unattended_ab_session_guard.ps1' -StartFilePath $startFilePath -RepoRoot $repoRoot
    $monitorStates.trigger = Get-MonitorBindingState -ScriptLeaf 'unattended_ab_takeover_trigger.ps1' -StartFilePath $startFilePath -RepoRoot $repoRoot
}

function Get-RestartReasonFromState {
    param([object]$State)

    if ($null -eq $State) {
        return 'state-unknown'
    }

    if ([int]$State.TotalCount -eq 0) {
        return 'not-running'
    }

    if ([int]$State.MatchCount -eq 0) {
        return 'binding-mismatch'
    }

    return 'healthy'
}

function Test-ShouldRestartMonitorRole {
    param(
        [string]$Role,
        [bool]$RestartMode,
        [bool]$SkipRestart,
        [hashtable]$States
    )

    if ($SkipRestart) {
        return $false
    }

    if ($RestartMode) {
        return $true
    }

    if ($null -eq $States -or -not $States.ContainsKey($Role)) {
        return $true
    }

    return (-not [bool]$States[$Role].RunningForStartFile)
}

$restartSupervisor = Test-ShouldRestartMonitorRole -Role 'supervisor' -RestartMode $bRestartMode -SkipRestart $skipMonitorRestart -States $monitorStates
$supervisorOutput = @()
if ($restartSupervisor) {
    if (-not $bRestartMode -and $monitorStates.ContainsKey('supervisor')) {
        $supervisorState = $monitorStates.supervisor
        Write-Output ("[OPEN-AB-STAGE] monitor_restart_single role=supervisor reason={0} match_count={1} mismatch_count={2} unbound_count={3}" -f
            (Get-RestartReasonFromState -State $supervisorState),
            [int]$supervisorState.MatchCount,
            [int]$supervisorState.MismatchCount,
            [int]$supervisorState.UnboundCount)
    }

    if ($Stage -eq 'A') {
        if ([string]::IsNullOrWhiteSpace($currentStageRunDir)) {
            $supervisorOutput = & $supervisorLauncherPath -StartFile $StartFile -CurrentAStartRound 1
        }
        else {
            $supervisorOutput = & $supervisorLauncherPath -StartFile $StartFile -CurrentAStartRound 1 -CurrentARunDir $currentStageRunDir
        }
    }
    else {
        $currentBRunDir = $currentStageRunDir

        if ([string]::IsNullOrWhiteSpace($currentBRunDir) -and $settings.Contains('SESSION_FINAL_NOTES')) {
            $hintRunDir = Get-LatestAnchorValueFromNotes -Notes ([string]$settings.SESSION_FINAL_NOTES) -Key 'run_dir'
            if (-not [string]::IsNullOrWhiteSpace($hintRunDir)) {
                try {
                    $currentBRunDir = Resolve-RepoPath -Path $hintRunDir
                }
                catch {
                    $currentBRunDir = ''
                }
            }
        }

        if ([string]::IsNullOrWhiteSpace($currentBRunDir)) {
            Write-Output '[OPEN-AB-STAGE] monitor_attach_b run_dir=unknown source=fallback-auto'
            $supervisorOutput = & $supervisorLauncherPath -StartFile $StartFile -StartFromStage B
        }
        else {
            Write-Output ("[OPEN-AB-STAGE] monitor_attach_b run_dir={0}" -f $currentBRunDir)
            $supervisorOutput = & $supervisorLauncherPath -StartFile $StartFile -StartFromStage B -CurrentBRunDir $currentBRunDir
        }
    }

    $supervisorLog = ''
    $liveStatus = ''
    foreach ($line in @($supervisorOutput | ForEach-Object { [string]$_ })) {
        Write-Output $line
        if ($line -match 'supervisor_log=([^\s]+)') {
            $supervisorLog = $Matches[1]
        }
        if ($line -match 'live_status=([^\s]+)') {
            $liveStatus = $Matches[1]
        }
    }
}
else {
    if ($monitorStates.ContainsKey('supervisor')) {
        $supervisorState = $monitorStates.supervisor
        Write-Output ("[OPEN-AB-STAGE] monitor_reuse role=supervisor match_count={0} mismatch_count={1} unbound_count={2} pids={3}" -f
            [int]$supervisorState.MatchCount,
            [int]$supervisorState.MismatchCount,
            [int]$supervisorState.UnboundCount,
            ($supervisorState.MatchPids -join ','))
    }

    $supervisorLog = Get-AnchorValueFromSettings -Settings $settings -Key 'supervisor_log'
    $liveStatus = Get-AnchorValueFromSettings -Settings $settings -Key 'live_status'
}

$restartCompanion = Test-ShouldRestartMonitorRole -Role 'companion' -RestartMode $bRestartMode -SkipRestart $skipMonitorRestart -States $monitorStates
if ($restartCompanion) {
    if (-not $bRestartMode -and $monitorStates.ContainsKey('companion')) {
        $companionState = $monitorStates.companion
        Write-Output ("[OPEN-AB-STAGE] monitor_restart_single role=companion reason={0} match_count={1} mismatch_count={2} unbound_count={3}" -f
            (Get-RestartReasonFromState -State $companionState),
            [int]$companionState.MatchCount,
            [int]$companionState.MismatchCount,
            [int]$companionState.UnboundCount)
    }

    $companionOutput = if ([string]::IsNullOrWhiteSpace($supervisorLog)) {
        & $companionLauncherPath -StartFile $StartFile
    }
    else {
        & $companionLauncherPath -StartFile $StartFile -SupervisorLog $supervisorLog
    }

    $companionLog = ''
    foreach ($line in @($companionOutput | ForEach-Object { [string]$_ })) {
        Write-Output $line
        if ($line -match 'companion_log=([^\s]+)$') {
            $companionLog = $Matches[1]
        }
    }
}
else {
    if ($monitorStates.ContainsKey('companion')) {
        $companionState = $monitorStates.companion
        Write-Output ("[OPEN-AB-STAGE] monitor_reuse role=companion match_count={0} mismatch_count={1} unbound_count={2} pids={3}" -f
            [int]$companionState.MatchCount,
            [int]$companionState.MismatchCount,
            [int]$companionState.UnboundCount,
            ($companionState.MatchPids -join ','))
    }

    $companionLog = Get-AnchorValueFromSettings -Settings $settings -Key 'companion_log'
}

$restartGuard = Test-ShouldRestartMonitorRole -Role 'guard' -RestartMode $bRestartMode -SkipRestart $skipMonitorRestart -States $monitorStates
if ($restartGuard) {
    if (-not $bRestartMode -and $monitorStates.ContainsKey('guard')) {
        $guardStateObj = $monitorStates.guard
        Write-Output ("[OPEN-AB-STAGE] monitor_restart_single role=guard reason={0} match_count={1} mismatch_count={2} unbound_count={3}" -f
            (Get-RestartReasonFromState -State $guardStateObj),
            [int]$guardStateObj.MatchCount,
            [int]$guardStateObj.MismatchCount,
            [int]$guardStateObj.UnboundCount)
    }

    $guardOutput = & $guardLauncherPath -StartFile $StartFile
    $guardLog = ''
    foreach ($line in @($guardOutput | ForEach-Object { [string]$_ })) {
        Write-Output $line
        if ($line -match 'guard_log=([^\s]+)') {
            $guardLog = $Matches[1]
        }
    }
}
else {
    if ($monitorStates.ContainsKey('guard')) {
        $guardStateObj = $monitorStates.guard
        Write-Output ("[OPEN-AB-STAGE] monitor_reuse role=guard match_count={0} mismatch_count={1} unbound_count={2} pids={3}" -f
            [int]$guardStateObj.MatchCount,
            [int]$guardStateObj.MismatchCount,
            [int]$guardStateObj.UnboundCount,
            ($guardStateObj.MatchPids -join ','))
    }

    $guardLog = Get-AnchorValueFromSettings -Settings $settings -Key 'guard_log'
}

$autoStartTakeoverTrigger = if ($settings.Contains('AUTO_START_TAKEOVER_TRIGGER')) {
    Convert-ToBooleanSetting -Value ([string]$settings.AUTO_START_TAKEOVER_TRIGGER) -Default $false
}
elseif ($settings.Contains('EXTERNAL_TRIGGER_EXECUTE')) {
    Convert-ToBooleanSetting -Value ([string]$settings.EXTERNAL_TRIGGER_EXECUTE) -Default $false
}
else {
    $false
}

if ($autoStartTakeoverTrigger) {
    $restartTrigger = Test-ShouldRestartMonitorRole -Role 'trigger' -RestartMode $bRestartMode -SkipRestart $skipMonitorRestart -States $monitorStates
    if ($restartTrigger) {
        if (-not $bRestartMode -and $monitorStates.ContainsKey('trigger')) {
            $triggerStateObj = $monitorStates.trigger
            Write-Output ("[OPEN-AB-STAGE] monitor_restart_single role=trigger reason={0} match_count={1} mismatch_count={2} unbound_count={3}" -f
                (Get-RestartReasonFromState -State $triggerStateObj),
                [int]$triggerStateObj.MatchCount,
                [int]$triggerStateObj.MismatchCount,
                [int]$triggerStateObj.UnboundCount)
        }

        try {
            $triggerOutput = & $triggerLauncherPath -StartFile $StartFile
            foreach ($line in @($triggerOutput | ForEach-Object { [string]$_ })) {
                Write-Output $line
            }
        }
        catch {
            $detail = ([regex]::Replace(([string]$_.Exception.Message), '\s+', ' ')).Trim()
            Write-Output ("[OPEN-AB-STAGE] trigger_autostart_failed stage={0} detail={1}" -f $Stage, $detail)
        }
    }
    else {
        if ($monitorStates.ContainsKey('trigger')) {
            $triggerStateObj = $monitorStates.trigger
            Write-Output ("[OPEN-AB-STAGE] monitor_reuse role=trigger match_count={0} mismatch_count={1} unbound_count={2} pids={3}" -f
                [int]$triggerStateObj.MatchCount,
                [int]$triggerStateObj.MismatchCount,
                [int]$triggerStateObj.UnboundCount,
                ($triggerStateObj.MatchPids -join ','))
        }
    }
}
else {
    Write-Output '[OPEN-AB-STAGE] trigger_autostart_skipped enabled=false'
}

$anchorUpdates = @{}
if (-not [string]::IsNullOrWhiteSpace($currentStageRunDir)) {
    $anchorUpdates.run_dir = Convert-ToAnchorPath -Path $currentStageRunDir
}
if (-not [string]::IsNullOrWhiteSpace($supervisorLog)) {
    $anchorUpdates.supervisor_log = Convert-ToAnchorPath -Path $supervisorLog
}
if (-not [string]::IsNullOrWhiteSpace($companionLog)) {
    $anchorUpdates.companion_log = Convert-ToAnchorPath -Path $companionLog
}
if (-not [string]::IsNullOrWhiteSpace($liveStatus)) {
    $anchorUpdates.live_status = Convert-ToAnchorPath -Path $liveStatus
}
if (-not [string]::IsNullOrWhiteSpace($guardLog)) {
    $anchorUpdates.guard_log = Convert-ToAnchorPath -Path $guardLog
}
if ($Stage -eq 'B' -and -not [string]::IsNullOrWhiteSpace($stageRuntimeLogPath)) {
    $anchorUpdates.b_runtime_log = Convert-ToAnchorPath -Path $stageRuntimeLogPath
}

if ($anchorUpdates.Count -gt 0) {
    $updatedNotes = Update-SessionAnchorsInStartFile -Path $startFilePath -Anchors $anchorUpdates
    Write-Output ("[OPEN-AB-STAGE] anchor_update notes={0}" -f $updatedNotes)
}
