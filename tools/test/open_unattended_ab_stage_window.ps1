param(
    [ValidateSet('A', 'B')][string]$Stage,
    [string]$StartFile = 'testdata\unattended_start\active\unattended_ab_start_20260504-1123.md',
    [switch]$StartMonitors,
    [switch]$SkipMonitorRestart,
    [switch]$EnableBMonitorRestart
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'unattended_exit_result.ps1')
$script:UnhandledExitTag = 'OPEN-AB-STAGE'

trap {
    $exitCode = Get-UnattendedExitCodeFromRecord -Tag $script:UnhandledExitTag -Record $_ -DefaultExitCode 1
    Write-UnattendedUnhandledResult -Tag $script:UnhandledExitTag -Record $_ -ExitCode $exitCode
    exit $exitCode
}

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
    $previousErrorActionPreference = $ErrorActionPreference
    try {
        # Native git stderr warning should not abort stage bootstrap under strict Stop mode.
        $ErrorActionPreference = 'Continue'
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
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
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

                $normalized = ([string]$raw).Trim().TrimStart([char]0xFEFF).Replace('\\', '/').Trim()
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

function Get-NormalizedStatusToken {
    param(
        [AllowEmptyString()][string]$Value,
        [AllowEmptyString()][string]$Default = ''
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $Default
    }

    return $Value.Trim().ToUpperInvariant()
}

function Read-StageFinalStatusEvidence {
    param([AllowEmptyString()][string]$StatusPath)

    $result = [ordered]@{
        Exists = $false
        ParseOk = $false
        Result = ''
        ExitCode = $null
        ExpectedRoundCount = $null
        CompletedRoundCount = $null
        CountsConsistent = $true
        IsPass = $false
        Detail = ''
    }

    if ([string]::IsNullOrWhiteSpace($StatusPath) -or -not (Test-Path -LiteralPath $StatusPath)) {
        return [pscustomobject]$result
    }

    $result.Exists = $true
    $extension = [System.IO.Path]::GetExtension($StatusPath)

    try {
        if ($extension -ieq '.json') {
            $json = Get-Content -LiteralPath $StatusPath -Raw -Encoding utf8 | ConvertFrom-Json -ErrorAction Stop
            $result.ParseOk = $true
            $result.Result = Get-NormalizedStatusToken -Value ([string]$json.Result)

            if ($null -ne $json.PSObject.Properties['ExitCode']) {
                $result.ExitCode = [int]$json.ExitCode
            }

            if ($null -ne $json.PSObject.Properties['ExpectedRoundCount']) {
                $result.ExpectedRoundCount = [int]$json.ExpectedRoundCount
            }

            if ($null -ne $json.PSObject.Properties['CompletedRoundCount']) {
                $result.CompletedRoundCount = [int]$json.CompletedRoundCount
            }
        }
        else {
            $lines = @(Get-Content -LiteralPath $StatusPath -Encoding utf8 -ErrorAction Stop)
            $map = @{}
            foreach ($line in $lines) {
                if ($line -match '^([^=]+)=(.*)$') {
                    $map[$Matches[1].Trim().ToLowerInvariant()] = $Matches[2].Trim()
                }
            }

            $result.ParseOk = ($map.Count -gt 0)
            $result.Result = Get-NormalizedStatusToken -Value ([string]$map['result'])

            if ($map.ContainsKey('exit_code')) {
                $parsedExitCode = 0
                if ([int]::TryParse([string]$map['exit_code'], [ref]$parsedExitCode)) {
                    $result.ExitCode = $parsedExitCode
                }
            }

            if ($map.ContainsKey('expected_round_count')) {
                $parsedExpected = 0
                if ([int]::TryParse([string]$map['expected_round_count'], [ref]$parsedExpected)) {
                    $result.ExpectedRoundCount = $parsedExpected
                }
            }

            if ($map.ContainsKey('completed_round_count')) {
                $parsedCompleted = 0
                if ([int]::TryParse([string]$map['completed_round_count'], [ref]$parsedCompleted)) {
                    $result.CompletedRoundCount = $parsedCompleted
                }
            }
        }
    }
    catch {
        $result.Detail = Convert-ToSingleLineText -Text $_.Exception.Message
        return [pscustomobject]$result
    }

    if ($null -ne $result.ExpectedRoundCount -and $null -ne $result.CompletedRoundCount) {
        $result.CountsConsistent = ($result.ExpectedRoundCount -eq $result.CompletedRoundCount)
    }

    $exitCodePass = ($null -eq $result.ExitCode -or [int]$result.ExitCode -eq 0)
    $result.IsPass = ($result.ParseOk -and $result.Result -eq 'PASS' -and $exitCodePass -and [bool]$result.CountsConsistent)

    $detailParts = New-Object 'System.Collections.Generic.List[string]'
    if (-not [string]::IsNullOrWhiteSpace([string]$result.Result)) {
        [void]$detailParts.Add(('result={0}' -f [string]$result.Result))
    }
    if ($null -ne $result.ExitCode) {
        [void]$detailParts.Add(('exit_code={0}' -f [int]$result.ExitCode))
    }
    if ($null -ne $result.ExpectedRoundCount -and $null -ne $result.CompletedRoundCount) {
        [void]$detailParts.Add(('rounds={0}/{1}' -f [int]$result.CompletedRoundCount, [int]$result.ExpectedRoundCount))
        if (-not [bool]$result.CountsConsistent) {
            [void]$detailParts.Add('counts=mismatch')
        }
    }

    $result.Detail = ($detailParts -join ' ')
    return [pscustomobject]$result
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
            EffectiveAStatus = ''
            UpdatedSettings = $Settings
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
            EffectiveAStatus = ''
            UpdatedSettings = $Settings
        }
    }

    $aFinalStatus = if ($Settings.Contains('A_FINAL_STATUS')) {
        Get-NormalizedStatusToken -Value ([string]$Settings.A_FINAL_STATUS)
    }
    else {
        ''
    }

    $sessionStatus = if ($Settings.Contains('SESSION_FINAL_STATUS')) {
        Get-NormalizedStatusToken -Value ([string]$Settings.SESSION_FINAL_STATUS)
    }
    else {
        ''
    }

    $shutdownRequested = if ($Settings.Contains('MONITOR_CHAIN_SHUTDOWN_REQUESTED')) {
        Convert-ToBooleanSetting -Value ([string]$Settings.MONITOR_CHAIN_SHUTDOWN_REQUESTED) -Default $false
    }
    else {
        $false
    }

    $shutdownReason = if ($Settings.Contains('MONITOR_CHAIN_SHUTDOWN_REASON')) {
        Convert-ToSingleLineText -Text ([string]$Settings.MONITOR_CHAIN_SHUTDOWN_REASON)
    }
    else {
        ''
    }

    $aLaunchPid = if ($Settings.Contains('A_LAUNCH_PID')) {
        Get-ParsedPositiveInt -Value ([string]$Settings.A_LAUNCH_PID)
    }
    else {
        0
    }
    $aLaunchAlive = ($aLaunchPid -gt 0 -and (Test-ProcessAlive -ProcessId $aLaunchPid))

    $snapshotStatusRaw = if ($Settings.Contains('A_SUCCESS_SNAPSHOT_FINAL_STATUS')) {
        [string]$Settings.A_SUCCESS_SNAPSHOT_FINAL_STATUS
    }
    else {
        ''
    }

    $snapshotStatusPath = Resolve-RepoPathAllowMissing -Path $snapshotStatusRaw -RepoRoot $RepoRoot
    $snapshotEvidence = Read-StageFinalStatusEvidence -StatusPath $snapshotStatusPath

    $effectiveAStatus = $aFinalStatus
    $updatedSettings = $Settings
    $aStatusSource = 'config'

    if ($snapshotEvidence.IsPass) {
        $effectiveAStatus = 'PASS'
        if ($aFinalStatus -ne 'PASS') {
            if (-not [string]::IsNullOrWhiteSpace($StartFilePath)) {
                Invoke-KeyValueFileValueUpdate -Path $StartFilePath -Values @{ A_FINAL_STATUS = 'PASS'; A_LAUNCH_PID = '0' }
                $updatedSettings = Read-KeyValueFile -Path $StartFilePath
            }

            $aStatusSource = 'snapshot-reconciled'
            Write-Host ("[{0}] b_start_gate_reconcile applied=true previous_a_status={1} snapshot_status={2} a_launch_pid={3} a_launch_alive={4}" -f
                $ScriptTag,
                $aFinalStatus,
                (Convert-ToSingleLineText -Text $snapshotEvidence.Detail),
                $aLaunchPid,
                [string]$aLaunchAlive)
        }
        else {
            $aStatusSource = 'config+snapshot'
        }
    }

    if ($effectiveAStatus -ne 'PASS') {
        $reasonParts = New-Object 'System.Collections.Generic.List[string]'
        [void]$reasonParts.Add(('a_status={0}' -f $aFinalStatus))
        [void]$reasonParts.Add(('session_status={0}' -f $sessionStatus))
        [void]$reasonParts.Add(('monitor_shutdown_requested={0}' -f ([string]$shutdownRequested).ToLowerInvariant()))
        if (-not [string]::IsNullOrWhiteSpace($shutdownReason)) {
            [void]$reasonParts.Add(('monitor_shutdown_reason={0}' -f $shutdownReason))
        }
        if ($aLaunchPid -gt 0) {
            [void]$reasonParts.Add(('a_launch_pid={0}' -f $aLaunchPid))
            [void]$reasonParts.Add(('a_launch_alive={0}' -f ([string]$aLaunchAlive).ToLowerInvariant()))
        }
        if ([string]::IsNullOrWhiteSpace($snapshotStatusRaw)) {
            [void]$reasonParts.Add('snapshot_status=missing')
        }
        elseif (-not $snapshotEvidence.Exists) {
            [void]$reasonParts.Add(('snapshot_status=missing path={0}' -f $snapshotStatusRaw))
        }
        elseif (-not $snapshotEvidence.ParseOk) {
            [void]$reasonParts.Add(('snapshot_status=parse-failed path={0}' -f (Convert-ToAnchorPath -Path $snapshotStatusPath)))
            if (-not [string]::IsNullOrWhiteSpace([string]$snapshotEvidence.Detail)) {
                [void]$reasonParts.Add(('snapshot_detail={0}' -f [string]$snapshotEvidence.Detail))
            }
        }
        else {
            [void]$reasonParts.Add(('snapshot_status={0}' -f $snapshotEvidence.Detail))
        }

        throw ("[{0}] b_start_gate blocked: A pass snapshot required ({1})" -f $ScriptTag, ($reasonParts -join '; '))
    }

    if ([string]::IsNullOrWhiteSpace($snapshotStatusRaw)) {
        throw ("[{0}] b_start_gate blocked: A_SUCCESS_SNAPSHOT_FINAL_STATUS is empty" -f $ScriptTag)
    }

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
    ('{0} ({1})' -f $effectiveAStatus, $aStatusSource),
    (Convert-ToAnchorPath -Path $snapshotStatusPath),
    (Convert-ToAnchorPath -Path $snapshotDir),
    $modeText)

    return [pscustomobject]@{
        GateRequired = $true
        EffectiveRestartMode = [bool]$effectiveRestartMode
        SnapshotStatusPath = [string]$snapshotStatusPath
        SnapshotDir = [string]$snapshotDir
        Alignment = $alignment
        EffectiveAStatus = [string]$effectiveAStatus
        UpdatedSettings = $updatedSettings
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

    if ([string]::IsNullOrWhiteSpace($StartFilePath)) {
        throw 'Start file path must not be empty when creating write lock.'
    }

    try {
        $fullPath = if (Test-Path -LiteralPath $StartFilePath) {
            (Resolve-Path -LiteralPath $StartFilePath).Path
        }
        else {
            [System.IO.Path]::GetFullPath($StartFilePath)
        }
        $fullPath = $fullPath.ToLowerInvariant()
    }
    catch {
        $sanitized = [regex]::Replace(([string]$StartFilePath), '[\r\n\t]+', ' ')
        throw ("Invalid start file path for write lock: '{0}'" -f $sanitized)
    }

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

function Get-StableStartFileToken {
    param([string]$StartFilePath)

    if ([string]::IsNullOrWhiteSpace($StartFilePath)) {
        return 'sf_unknown'
    }

    $fullPath = [System.IO.Path]::GetFullPath($StartFilePath).ToLowerInvariant()
    $sha1 = [System.Security.Cryptography.SHA1]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($fullPath)
        $hashBytes = $sha1.ComputeHash($bytes)
        $hash = ([System.BitConverter]::ToString($hashBytes)).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sha1.Dispose()
    }

    return ('sf_{0}' -f $hash)
}

function Get-MonitorTimelinePath {
    param(
        [string]$StartFilePath,
        [string]$RepoRoot
    )

    $timelineRoot = Join-Path $RepoRoot 'out\artifacts\ab_monitor_timeline'
    if (-not (Test-Path -LiteralPath $timelineRoot)) {
        New-Item -ItemType Directory -Path $timelineRoot -Force | Out-Null
    }

    $token = Get-StableStartFileToken -StartFilePath $StartFilePath
    return (Join-Path $timelineRoot ("monitor_timeline_{0}.jsonl" -f $token))
}

function Write-MonitorTimelineEvent {
    param(
        [string]$TimelinePath,
        [string]$EventName,
        [hashtable]$Fields
    )

    if ([string]::IsNullOrWhiteSpace($TimelinePath) -or [string]::IsNullOrWhiteSpace($EventName)) {
        return
    }

    try {
        $payload = [ordered]@{
            timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
            event = $EventName
        }

        if ($null -ne $Fields) {
            foreach ($key in $Fields.Keys) {
                $payload[$key] = $Fields[$key]
            }
        }

        $json = ($payload | ConvertTo-Json -Compress -Depth 6)
        Add-Content -LiteralPath $TimelinePath -Encoding utf8 -Value $json
    }
    catch {
        Write-Warning ("[OPEN-AB-STAGE] monitor_timeline_write_failed path={0} detail={1}" -f $TimelinePath, $_.Exception.Message)
    }
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
        Copy-Item -LiteralPath $tempPath -Destination $Path -Force
        Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue
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

function Get-LatestAnchorValueFromNoteText {
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

function Invoke-SessionAnchorUpdateInStartFile {
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
    Invoke-KeyValueFileValueUpdate -Path $Path -Values @{ SESSION_FINAL_NOTES = $newNotes }
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
        $hintRunDir = Get-LatestAnchorValueFromNoteText -Notes ([string]$Settings.SESSION_FINAL_NOTES) -Key 'run_dir'
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

function Convert-ToBoundedSingleLineText {
    param(
        [AllowEmptyString()][string]$Text,
        [ValidateRange(32, 4000)][int]$MaxChars = 800
    )

    $singleLine = Convert-ToSingleLineText -Text $Text
    if ([string]::IsNullOrWhiteSpace($singleLine)) {
        return ''
    }

    if ($singleLine.Length -le $MaxChars) {
        return $singleLine
    }

    return ($singleLine.Substring(0, $MaxChars).TrimEnd() + '...')
}

function Get-AgentTicketQueuePath {
    param([System.Collections.IDictionary]$Settings)

    $rawPath = ''
    if ($null -ne $Settings -and $Settings.Contains('LOCAL_GUARD_AGENT_QUEUE_PATH')) {
        $rawPath = [string]$Settings.LOCAL_GUARD_AGENT_QUEUE_PATH
    }

    if ([string]::IsNullOrWhiteSpace($rawPath)) {
        $rawPath = 'out\artifacts\ab_agent_queue\agent_tickets.jsonl'
    }

    return (Resolve-RepoPathAllowMissing -Path $rawPath -RepoRoot $repoRoot)
}

function Write-JsonLineWithRetry {
    param(
        [string]$Path,
        [string]$Line
    )

    if ([string]::IsNullOrWhiteSpace($Path) -or [string]::IsNullOrWhiteSpace($Line)) {
        return $false
    }

    $parent = Split-Path -Parent $Path
    if (-not [string]::IsNullOrWhiteSpace($parent) -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }

    $maxAttempts = 6
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        try {
            Add-Content -LiteralPath $Path -Value $Line -Encoding utf8 -ErrorAction Stop
            return $true
        }
        catch {
            if ($attempt -eq $maxAttempts) {
                return $false
            }

            $delayMs = switch ($attempt) {
                1 { 30 }
                2 { 60 }
                3 { 120 }
                4 { 200 }
                default { 300 }
            }
            Start-Sleep -Milliseconds $delayMs
        }
    }

    return $false
}

function Add-StageTaskDefinitionFixTicket {
    param(
        [string]$StartFilePath,
        [System.Collections.IDictionary]$Settings,
        [ValidateSet('A', 'B')][string]$Stage,
        [string]$TaskDefinitionRelative,
        [int]$FailCount,
        [int]$MaxFails,
        [int]$PrecheckExitCode
    )

    $queuePath = Get-AgentTicketQueuePath -Settings $Settings
    if ([string]::IsNullOrWhiteSpace($queuePath)) {
        Write-Output '[OPEN-AB-STAGE] task_static_precheck ticket_emit=skip reason=queue-path-empty'
        return
    }

    $sessionStatus = if ($Settings.Contains('SESSION_FINAL_STATUS')) { [string]$Settings.SESSION_FINAL_STATUS } else { '' }
    $aStatus = if ($Settings.Contains('A_FINAL_STATUS')) { [string]$Settings.A_FINAL_STATUS } else { '' }
    $bStatus = if ($Settings.Contains('B_FINAL_STATUS')) { [string]$Settings.B_FINAL_STATUS } else { '' }
    $notes = if ($Settings.Contains('SESSION_FINAL_NOTES')) { [string]$Settings.SESSION_FINAL_NOTES } else { '' }
    $runDirAnchor = Get-LatestAnchorValueFromNoteText -Notes $notes -Key 'run_dir'

    $detail = ('stage={0} category=task-definition-static-precheck fail_count={1} limit={2} exit={3} task_definition={4}' -f $Stage, $FailCount, $MaxFails, $PrecheckExitCode, $TaskDefinitionRelative)
    $recommendedAction = 'Report root cause and remediation path first. Fix the task-definition file under testdata so static precheck passes, rerun task static precheck, then execute business_resume immediately (business_command -> continue_watch_command; continue only when business_command is empty). After completing this ticket cycle, you MUST return handled_at (YYYY-MM-DD HH:mm:ss); session_closed_at is session-level only and MUST be returned only when stop monitoring is requested or both A/B are terminal. After handling, keep read-only monitoring with scheduled status-ticket heartbeat + poll cadence until "stop monitoring".'
    $ticketId = ('T{0}-{1}' -f (Get-Date).ToString('yyyyMMdd-HHmmssfff'), ([System.Guid]::NewGuid().ToString('N').Substring(0, 8)))
    $ticket = [ordered]@{
        schema = 'AB_AGENT_TICKET_V1'
        ticket_id = $ticketId
        created_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        source = 'open_unattended_ab_stage_window'
        event = 'task-definition-fix-required'
        severity = 'high'
        requires_confirmation = $false
        confirmation_key = ''
        start_file = (Convert-ToAnchorPath -Path $StartFilePath)
        guard_log = ''
        guard_state = ''
        queue_path = (Convert-ToAnchorPath -Path $queuePath)
        session_final_status = (Convert-ToSingleLineText -Text $sessionStatus)
        a_final_status = (Convert-ToSingleLineText -Text $aStatus)
        b_final_status = (Convert-ToSingleLineText -Text $bStatus)
        run_dir = (Convert-ToSingleLineText -Text $runDirAnchor)
        incident_dir = ''
        detail = (Convert-ToBoundedSingleLineText -Text $detail -MaxChars 360)
        recommended_action = (Convert-ToBoundedSingleLineText -Text $recommendedAction -MaxChars 280)
        preferred_stage = $Stage
        main_round = ''
        failure_kind = 'task-definition-mismatch'
        failure_category = 'task-definition-static-precheck'
        failure_source = 'tools/test/open_unattended_ab_stage_window.ps1'
        failure_evidence = (Convert-ToBoundedSingleLineText -Text $detail -MaxChars 260)
        self_healable = $true
        non_recoverable_env = $false
        dedup_signature = ('task-definition-static-precheck|{0}|{1}|{2}|{3}' -f $Stage, $TaskDefinitionRelative, $FailCount, $MaxFails)
    }

    $line = $ticket | ConvertTo-Json -Compress -Depth 8
    if (Write-JsonLineWithRetry -Path $queuePath -Line $line) {
        Write-Output ('[OPEN-AB-STAGE] task_static_precheck ticket_emit=queued id={0} queue={1} fail_count={2} limit={3}' -f $ticketId, (Convert-ToAnchorPath -Path $queuePath), $FailCount, $MaxFails)
        return
    }

    Write-Output ('[OPEN-AB-STAGE] task_static_precheck ticket_emit=failed queue={0} fail_count={1} limit={2}' -f (Convert-ToAnchorPath -Path $queuePath), $FailCount, $MaxFails)
}

function Add-StageTaskDefinitionBlockedTicket {
    param(
        [string]$StartFilePath,
        [System.Collections.IDictionary]$Settings,
        [ValidateSet('A', 'B')][string]$Stage,
        [string]$TaskDefinitionRelative,
        [int]$FailCount,
        [int]$MaxFails,
        [int]$PrecheckExitCode,
        [string]$BlockEvent
    )

    $queuePath = Get-AgentTicketQueuePath -Settings $Settings
    if ([string]::IsNullOrWhiteSpace($queuePath)) {
        Write-Output '[OPEN-AB-STAGE] task_static_precheck block_ticket_emit=skip reason=queue-path-empty'
        return
    }

    $sessionStatus = if ($Settings.Contains('SESSION_FINAL_STATUS')) { [string]$Settings.SESSION_FINAL_STATUS } else { '' }
    $aStatus = if ($Settings.Contains('A_FINAL_STATUS')) { [string]$Settings.A_FINAL_STATUS } else { '' }
    $bStatus = if ($Settings.Contains('B_FINAL_STATUS')) { [string]$Settings.B_FINAL_STATUS } else { '' }
    $notes = if ($Settings.Contains('SESSION_FINAL_NOTES')) { [string]$Settings.SESSION_FINAL_NOTES } else { '' }
    $runDirAnchor = Get-LatestAnchorValueFromNoteText -Notes $notes -Key 'run_dir'

    $eventName = 'manual-wait-paused'
    $requiresConfirmation = $true
    $confirmationKey = 'LOCAL_GUARD_RESTART_APPROVED'
    $selfHealable = $false
    $failureCategory = 'task-definition-static-precheck-blocked'
    $detailCategory = 'task-definition-static-precheck-blocked'
    $recommendedAction = 'Report root cause and remediation path first. Task-definition static precheck has exceeded the allowed retry limit, so do not continue automatic stage restarts. Review the task-definition file under testdata, decide whether to repair or reset baseline, rerun task static precheck manually, and only then resume the guarded workflow. After completing this ticket cycle, you MUST return handled_at (YYYY-MM-DD HH:mm:ss); session_closed_at is session-level only and MUST be returned only when stop monitoring is requested or both A/B are terminal. After handling, keep read-only monitoring with scheduled status-ticket heartbeat + poll cadence until "stop monitoring".'

    switch ((Convert-ToSingleLineText -Text $BlockEvent).ToLowerInvariant()) {
        'recovery-await-confirmation' {
            $eventName = 'recovery-await-confirmation'
            $recommendedAction = 'Report root cause and remediation path first. Task-definition static precheck has exceeded the allowed retry limit, so pause automatic retries and require explicit restart approval after evidence review. Repair or reset the task-definition file under testdata, rerun task static precheck manually, and only then resume the guarded workflow. After completing this ticket cycle, you MUST return handled_at (YYYY-MM-DD HH:mm:ss); session_closed_at is session-level only and MUST be returned only when stop monitoring is requested or both A/B are terminal. After handling, keep read-only monitoring with scheduled status-ticket heartbeat + poll cadence until "stop monitoring".'
        }
        'task-definition-fix-required' {
            $eventName = 'task-definition-fix-required'
            $requiresConfirmation = $false
            $confirmationKey = ''
            $selfHealable = $true
            $recommendedAction = 'Report root cause and remediation path first. Task-definition static precheck has exceeded the allowed retry limit, so do not restart automatically; instead repair the task-definition file under testdata until static precheck passes, then resume via the standard business_resume path. After completing this ticket cycle, you MUST return handled_at (YYYY-MM-DD HH:mm:ss); session_closed_at is session-level only and MUST be returned only when stop monitoring is requested or both A/B are terminal. After handling, keep read-only monitoring with scheduled status-ticket heartbeat + poll cadence until "stop monitoring".'
        }
    }

    $detail = ('stage={0} category={1} fail_count={2} limit={3} exit={4} task_definition={5}' -f $Stage, $detailCategory, $FailCount, $MaxFails, $PrecheckExitCode, $TaskDefinitionRelative)
    $ticketId = ('T{0}-{1}' -f (Get-Date).ToString('yyyyMMdd-HHmmssfff'), ([System.Guid]::NewGuid().ToString('N').Substring(0, 8)))
    $ticket = [ordered]@{
        schema = 'AB_AGENT_TICKET_V1'
        ticket_id = $ticketId
        created_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        source = 'open_unattended_ab_stage_window'
        event = $eventName
        severity = 'high'
        requires_confirmation = $requiresConfirmation
        confirmation_key = $confirmationKey
        start_file = (Convert-ToAnchorPath -Path $StartFilePath)
        guard_log = ''
        guard_state = ''
        queue_path = (Convert-ToAnchorPath -Path $queuePath)
        session_final_status = (Convert-ToSingleLineText -Text $sessionStatus)
        a_final_status = (Convert-ToSingleLineText -Text $aStatus)
        b_final_status = (Convert-ToSingleLineText -Text $bStatus)
        run_dir = (Convert-ToSingleLineText -Text $runDirAnchor)
        incident_dir = ''
        detail = (Convert-ToBoundedSingleLineText -Text $detail -MaxChars 360)
        recommended_action = (Convert-ToBoundedSingleLineText -Text $recommendedAction -MaxChars 280)
        preferred_stage = $Stage
        main_round = ''
        failure_kind = 'task-definition-mismatch'
        failure_category = $failureCategory
        failure_source = 'tools/test/open_unattended_ab_stage_window.ps1'
        failure_evidence = (Convert-ToBoundedSingleLineText -Text $detail -MaxChars 260)
        self_healable = $selfHealable
        non_recoverable_env = $false
        dedup_signature = ('task-definition-static-precheck-blocked|{0}|{1}|{2}|{3}|{4}' -f $eventName, $Stage, $TaskDefinitionRelative, $FailCount, $MaxFails)
    }

    $line = $ticket | ConvertTo-Json -Compress -Depth 8
    if (Write-JsonLineWithRetry -Path $queuePath -Line $line) {
        Write-Output ('[OPEN-AB-STAGE] task_static_precheck block_ticket_emit=queued id={0} queue={1} fail_count={2} limit={3}' -f $ticketId, (Convert-ToAnchorPath -Path $queuePath), $FailCount, $MaxFails)
        return
    }

    Write-Output ('[OPEN-AB-STAGE] task_static_precheck block_ticket_emit=failed queue={0} fail_count={1} limit={2}' -f (Convert-ToAnchorPath -Path $queuePath), $FailCount, $MaxFails)
}

function Invoke-DispatchDeliveryToggle {
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
        Invoke-KeyValueFileValueUpdate -Path $Path -Values $updates
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

    Invoke-KeyValueFileValueUpdate -Path $Path -Values @{
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
        Invoke-KeyValueFileValueUpdate -Path $StartFilePath -Values @{
            PRECHECK_START_GATE = 'BLOCKED'
            PRECHECK_START_BLOCKER = $reasonText
            PRECHECK_FAILURE_REASON = $reasonText
        }
        throw ("[{0}] precheck gate blocked: {1}" -f $ScriptTag, $reasonText)
    }

    Write-Output ("[{0}] precheck_gate status=PASS gate=READY remote_lock={1}" -f $ScriptTag, $remoteLockRaw)
}

function Invoke-LaunchReadyGate {
    param(
        [ValidateSet('A', 'B')][string]$Stage,
        [System.Collections.IDictionary]$Settings,
        [string]$StartFilePath,
        [string]$ScriptTag,
        [string]$RepoRoot
    )

    if ($null -eq $Settings) {
        throw "[$ScriptTag] start file settings map is null for launch-ready gate"
    }

    $launchReadyGateEnabled = if ($Settings.Contains('LAUNCH_READY_GATE_ENABLED')) {
        Convert-ToBooleanSetting -Value ([string]$Settings.LAUNCH_READY_GATE_ENABLED) -Default $true
    }
    else {
        $true
    }

    if (-not $launchReadyGateEnabled) {
        Write-Output ("[{0}] launch_ready_gate enabled=false action=skip" -f $ScriptTag)
        return
    }

    $launchReadyScript = Join-Path $RepoRoot 'tools\test\check_unattended_ab_launch_ready.ps1'
    if (-not (Test-Path -LiteralPath $launchReadyScript)) {
        throw "[$ScriptTag] launch-ready gate script not found: $launchReadyScript"
    }

    $launchReadyDetailedOutput = if ($Settings.Contains('LAUNCH_READY_GATE_DETAILED_OUTPUT')) {
        Convert-ToBooleanSetting -Value ([string]$Settings.LAUNCH_READY_GATE_DETAILED_OUTPUT) -Default $false
    }
    else {
        $false
    }

    $powershellPath = Join-Path $PSHOME 'powershell.exe'
    if (-not (Test-Path -LiteralPath $powershellPath)) {
        $powershellPath = 'powershell.exe'
    }

    $launchReadyArgs = @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', $launchReadyScript,
        '-StartFile', $StartFilePath,
        '-Stage', $Stage
    )
    if ($launchReadyDetailedOutput) {
        $launchReadyArgs += '-DetailedOutput'
    }

    Write-Output ("[{0}] launch_ready_gate status=START stage={1} start_file={2} detailed_output={3}" -f $ScriptTag, $Stage, (Convert-ToAnchorPath -Path $StartFilePath), [string]$launchReadyDetailedOutput)

    $outputLines = New-Object 'System.Collections.Generic.List[string]'
    $exitCode = 1
    try {
        & $powershellPath @launchReadyArgs 2>&1 | ForEach-Object {
            $line = [string]$_
            [void]$outputLines.Add($line)
            if (-not [string]::IsNullOrWhiteSpace($line)) {
                Write-Output $line
            }
        }
        $exitCode = if ($null -eq $LASTEXITCODE) { 0 } else { [int]$LASTEXITCODE }
    }
    catch {
        $exitCode = 1
        $fallbackLine = [string]$_.Exception.Message
        [void]$outputLines.Add($fallbackLine)
        if (-not [string]::IsNullOrWhiteSpace($fallbackLine)) {
            Write-Output $fallbackLine
        }
    }

    $outputLines = @($outputLines)

    $resultMarker = @($outputLines | Where-Object {
        $text = (Convert-ToSingleLineText -Text ([string]$_)).Trim()
        $text.StartsWith('AB_LAUNCH_READY_RESULT=', [System.StringComparison]::OrdinalIgnoreCase) -or $text -match '^\[AB-LAUNCH-READY\]\s+result=(pass|fail)$'
    } | Select-Object -Last 1)
    $resultValue = ''
    if ($resultMarker.Count -gt 0) {
        $resultText = (Convert-ToSingleLineText -Text ([string]$resultMarker[0])).Trim()
        if ($resultText.StartsWith('AB_LAUNCH_READY_RESULT=', [System.StringComparison]::OrdinalIgnoreCase)) {
            $resultValue = $resultText.Replace('AB_LAUNCH_READY_RESULT=', '').Trim().ToUpperInvariant()
        }
        elseif ($resultText -match '^\[AB-LAUNCH-READY\]\s+result=(pass|fail)$') {
            $resultValue = ([string]$Matches[1]).Trim().ToUpperInvariant()
        }
    }

    if ($exitCode -ne 0 -or $resultValue -ne 'PASS') {
        $reason = "LAUNCH_READY_GATE_FAIL exit=$exitCode result=$resultValue"
        Invoke-KeyValueFileValueUpdate -Path $StartFilePath -Values @{
            PRECHECK_START_GATE = 'BLOCKED'
            PRECHECK_START_BLOCKER = $reason
            PRECHECK_FAILURE_REASON = $reason
        }
        throw ("[{0}] launch-ready gate blocked: {1}" -f $ScriptTag, $reason)
    }

    Write-Output ("[{0}] launch_ready_gate status=PASS stage={1} result={2}" -f $ScriptTag, $Stage, $resultValue)
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
        Invoke-KeyValueFileValueUpdate -Path $StartFilePath -Values @{
            PRECHECK_START_GATE = 'BLOCKED'
            PRECHECK_START_BLOCKER = $reason
            PRECHECK_FAILURE_REASON = $reason
            NETWORK_PRECHECK_LAST_RESULT = 'FAIL'
            NETWORK_PRECHECK_LAST_AT = $nowText
            NETWORK_PRECHECK_LAST_REASON = $reason
        }
        throw ("[{0}] network precheck blocked: {1}" -f $ScriptTag, $reason)
    }

    Invoke-KeyValueFileValueUpdate -Path $StartFilePath -Values @{
        NETWORK_PRECHECK_LAST_RESULT = 'PASS'
        NETWORK_PRECHECK_LAST_AT = $nowText
        NETWORK_PRECHECK_LAST_REASON = ''
    }
    Write-Output ("[{0}] network_precheck status=PASS targets={1} local={2} remote={3} check_ipv4={4} check_ipv6={5} require_ipv4={6} require_ipv6={7}" -f $ScriptTag, $targets, $checkLocal, $checkRemote, $checkIPv4, $checkIPv6, $requireIPv4, $requireIPv6)
}

function Invoke-EnvFromSetting {
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
        $afterValue = [datetime]$After
        $threshold = if ($afterValue -le [datetime]::MinValue.AddSeconds(2)) {
            [datetime]::MinValue
        }
        else {
            $afterValue.AddSeconds(-2)
        }

        $dirs = @($dirs | Where-Object { $_.CreationTime -ge $threshold -or $_.LastWriteTime -ge $threshold })
    }

    $candidates = @($dirs | Sort-Object CreationTime, LastWriteTime -Descending | Select-Object -First 1)
    if ($candidates.Count -lt 1) {
        return $null
    }

    return $candidates[0]
}

function Invoke-MonitorProcessStopForStartFile {
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

function Invoke-MonitorRoleProcessStopForStartFile {
    param(
        [string]$ScriptLeaf,
        [string]$StartFilePath
    )

    if ([string]::IsNullOrWhiteSpace($ScriptLeaf)) {
        return @()
    }

    $startFileIdentity = Get-NormalizedPathIdentity -Path $StartFilePath -RepoRoot $repoRoot
    if ([string]::IsNullOrWhiteSpace($startFileIdentity)) {
        return @()
    }

    $scriptNeedle = $ScriptLeaf.Trim().ToLowerInvariant()
    $targetPids = @(
        Get-CimInstance Win32_Process |
            Where-Object {
                $commandLine = [string]$_.CommandLine
                if ([string]::IsNullOrWhiteSpace($commandLine)) {
                    return $false
                }

                $line = $commandLine.ToLowerInvariant()
                if (-not $line.Contains($scriptNeedle)) {
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

function Test-MonitorReuseActivity {
    param(
        [System.Collections.IDictionary]$Settings,
        [string]$RepoRoot,
        [int]$MaxStaleMinutes = 5
    )

    $thresholdMinutes = if ($MaxStaleMinutes -gt 0) { $MaxStaleMinutes } else { 5 }
    $now = Get-Date
    $evidence = New-Object 'System.Collections.Generic.List[string]'
    $fresh = $false

    foreach ($anchorKey in @('supervisor_log', 'live_status')) {
        $anchorValue = Get-AnchorValueFromConfig -Settings $Settings -Key $anchorKey
        if ([string]::IsNullOrWhiteSpace($anchorValue)) {
            continue
        }

        $resolvedPath = Resolve-RepoPathAllowMissing -Path $anchorValue -RepoRoot $RepoRoot
        if ([string]::IsNullOrWhiteSpace($resolvedPath) -or -not (Test-Path -LiteralPath $resolvedPath)) {
            [void]$evidence.Add(($anchorKey + ':missing'))
            continue
        }

        $item = Get-Item -LiteralPath $resolvedPath -ErrorAction SilentlyContinue
        if ($null -eq $item) {
            [void]$evidence.Add(($anchorKey + ':missing'))
            continue
        }

        $ageMinutes = [math]::Round((New-TimeSpan -Start $item.LastWriteTime -End $now).TotalMinutes, 2)
        if ($ageMinutes -le $thresholdMinutes) {
            $fresh = $true
        }

        [void]$evidence.Add(($anchorKey + ':age_min=' + $ageMinutes))
    }

    if ($evidence.Count -eq 0) {
        [void]$evidence.Add('no-anchor-evidence')
    }

    return [pscustomobject]@{
        Active = [bool]$fresh
        ThresholdMinutes = [int]$thresholdMinutes
        Evidence = @($evidence)
    }
}

function Test-MonitorReuseProcessPresence {
    param(
        [string]$StartFilePath,
        [string]$RepoRoot
    )

    $startFileIdentity = Get-NormalizedPathIdentity -Path $StartFilePath -RepoRoot $RepoRoot
    if ([string]::IsNullOrWhiteSpace($startFileIdentity)) {
        return [pscustomobject]@{
            Active = $false
            MatchCount = 0
            Evidence = @('start-file-identity-unavailable')
        }
    }

    $roles = @('unattended_ab_supervisor.ps1', 'unattended_ab_companion.ps1', 'unattended_ab_session_guard.ps1', 'unattended_ab_takeover_trigger.ps1')
    $matchCount = 0
    $evidence = New-Object 'System.Collections.Generic.List[string]'
    foreach ($scriptLeaf in $roles) {
        $state = Get-MonitorBindingState -ScriptLeaf $scriptLeaf -StartFilePath $StartFilePath -RepoRoot $RepoRoot
        if ($null -ne $state -and [bool]$state.RunningForStartFile) {
            $matchCount++
            [void]$evidence.Add(('{0}:match={1}' -f $scriptLeaf, [int]$state.MatchCount))
        }
    }

    if ($evidence.Count -eq 0) {
        [void]$evidence.Add('no-live-process-match')
    }

    return [pscustomobject]@{
        Active = [bool]($matchCount -gt 0)
        MatchCount = [int]$matchCount
        Evidence = @($evidence)
    }
}

function Get-MonitorReuseStaleMinutes {
    param([System.Collections.IDictionary]$Settings)

    $threshold = 15
    if ($null -ne $Settings) {
        foreach ($key in @('LOCAL_GUARD_MONITOR_REUSE_STALE_MINUTES', 'MONITOR_REUSE_MAX_STALE_MINUTES')) {
            if ($Settings.Contains($key)) {
                $candidate = Get-ParsedPositiveInt -Value ([string]$Settings[$key])
                if ($candidate -gt 0) {
                    $threshold = $candidate
                    break
                }
            }
        }
    }

    if ($threshold -lt 1) {
        $threshold = 1
    }
    if ($threshold -gt 120) {
        $threshold = 120
    }

    return [int]$threshold
}

function Test-MonitorRoleReuseActivity {
    param(
        [ValidateSet('supervisor', 'companion', 'guard', 'trigger')][string]$Role,
        [System.Collections.IDictionary]$Settings,
        [string]$RepoRoot,
        [string]$StartFilePath,
        [int]$MaxStaleMinutes = 15
    )

    $thresholdMinutes = if ($MaxStaleMinutes -gt 0) { $MaxStaleMinutes } else { 15 }
    $now = Get-Date
    $evidence = New-Object 'System.Collections.Generic.List[string]'
    $fresh = $false

    $anchorKeys = @()
    switch ($Role) {
        'supervisor' { $anchorKeys = @('supervisor_log', 'live_status') }
        'companion' { $anchorKeys = @('companion_log') }
        'guard' { $anchorKeys = @('guard_log') }
        'trigger' { $anchorKeys = @() }
    }

    foreach ($anchorKey in $anchorKeys) {
        $anchorValue = Get-AnchorValueFromConfig -Settings $Settings -Key $anchorKey
        if ([string]::IsNullOrWhiteSpace($anchorValue)) {
            continue
        }

        $resolvedPath = Resolve-RepoPathAllowMissing -Path $anchorValue -RepoRoot $RepoRoot
        if ([string]::IsNullOrWhiteSpace($resolvedPath) -or -not (Test-Path -LiteralPath $resolvedPath)) {
            [void]$evidence.Add(($anchorKey + ':missing'))
            continue
        }

        $item = Get-Item -LiteralPath $resolvedPath -ErrorAction SilentlyContinue
        if ($null -eq $item) {
            [void]$evidence.Add(($anchorKey + ':missing'))
            continue
        }

        $ageMinutes = [math]::Round((New-TimeSpan -Start $item.LastWriteTime -End $now).TotalMinutes, 2)
        if ($ageMinutes -le $thresholdMinutes) {
            $fresh = $true
        }

        [void]$evidence.Add(($anchorKey + ':age_min=' + $ageMinutes))
    }

    if ($Role -eq 'trigger') {
        $queueRoot = Join-Path $RepoRoot 'out\artifacts\ab_agent_queue'
        $token = Get-StableStartFileToken -StartFilePath $StartFilePath
        $triggerLogPath = Join-Path $queueRoot ("takeover_trigger_{0}.log" -f $token)
        $triggerStatePath = Join-Path $queueRoot ("takeover_trigger_state_{0}.json" -f $token)
        foreach ($itemPath in @($triggerLogPath, $triggerStatePath)) {
            $label = [System.IO.Path]::GetFileName($itemPath)
            if (-not (Test-Path -LiteralPath $itemPath)) {
                [void]$evidence.Add(($label + ':missing'))
                continue
            }

            $item = Get-Item -LiteralPath $itemPath -ErrorAction SilentlyContinue
            if ($null -eq $item) {
                [void]$evidence.Add(($label + ':missing'))
                continue
            }

            $ageMinutes = [math]::Round((New-TimeSpan -Start $item.LastWriteTime -End $now).TotalMinutes, 2)
            if ($ageMinutes -le $thresholdMinutes) {
                $fresh = $true
            }

            [void]$evidence.Add(($label + ':age_min=' + $ageMinutes))
        }
    }

    if ($evidence.Count -eq 0) {
        [void]$evidence.Add('no-role-evidence')
    }

    return [pscustomobject]@{
        Role = $Role
        Active = [bool]$fresh
        ThresholdMinutes = [int]$thresholdMinutes
        Evidence = @($evidence)
    }
}

function Get-AnchorValueFromConfig {
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

    return Get-LatestAnchorValueFromNoteText -Notes ([string]$Settings.SESSION_FINAL_NOTES) -Key $Key
}

function Invoke-PreV1EncodingFixGates {
    param(
        [string]$RepoRoot,
        [string]$ScriptTag
    )

    $gateSpecs = @(
        [pscustomobject]@{
            Name = 'changed'
            ScriptPath = Join-Path $RepoRoot 'tools\dev\enforce_utf8_bom_lf_changed.ps1'
            Args = @('-Mode', 'fix', '-Policy', 'enforce', '-IncludeUntracked')
        },
        [pscustomobject]@{
            Name = 'src'
            ScriptPath = Join-Path $RepoRoot 'tools\dev\enforce_utf8_lf_src_changed.ps1'
            Args = @('-Mode', 'fix', '-Policy', 'enforce', '-IncludeUntracked')
        }
    )

    foreach ($gate in $gateSpecs) {
        $gateScriptPath = [string]$gate.ScriptPath
        $resolvedGateScriptPath = ''
        try {
            if (-not [string]::IsNullOrWhiteSpace($gateScriptPath)) {
                $fullGateScriptPath = [System.IO.Path]::GetFullPath($gateScriptPath)
                if ([System.IO.File]::Exists($fullGateScriptPath)) {
                    $resolvedGateScriptPath = $fullGateScriptPath
                }
            }
        }
        catch {
            $resolvedGateScriptPath = ''
        }

        if ([string]::IsNullOrWhiteSpace($resolvedGateScriptPath)) {
            throw ("[{0}] pre-v1 encoding gate script missing: {1}" -f $ScriptTag, $gateScriptPath)
        }

        $lines = @()
        $exitCode = 1
        try {
            # Build named parameter splat for robust invocation (supports switches)
            $paramHash = @{}
            $argList = @($gate.Args | ForEach-Object { [string]$_ })
            for ($i = 0; $i -lt $argList.Count; ) {
                $token = $argList[$i]
                if ($token -like '-*') {
                    $key = $token.TrimStart('-')
                    if ($i + 1 -lt $argList.Count -and ($argList[$i+1] -notlike '-*')) {
                        $paramHash[$key] = $argList[$i+1]
                        $i += 2
                    }
                    else {
                        $paramHash[$key] = $true
                        $i += 1
                    }
                }
                else { $i += 1 }
            }

            $lines = @((& $resolvedGateScriptPath @paramHash 2>&1) | ForEach-Object { [string]$_ })
            $exitCode = 0
            if (Test-Path Variable:LASTEXITCODE) {
                $exitCode = if ($null -eq $LASTEXITCODE) { 0 } else { [int]$LASTEXITCODE }
            }
            else {
                try {
                    $g = Get-Variable -Name LASTEXITCODE -Scope Global -ErrorAction Stop
                    if ($null -ne $g.Value) { $exitCode = [int]$g.Value } else { $exitCode = 0 }
                }
                catch {
                    $exitCode = 0
                }
            }
        }
        catch {
            $errorText = Convert-ToSingleLineText -Text $_.Exception.Message
            if (-not [string]::IsNullOrWhiteSpace($errorText)) {
                $lines = @($errorText)
            }

            try {
                $g = Get-Variable -Name LASTEXITCODE -Scope Global -ErrorAction Stop
                if ($null -ne $g.Value) { $exitCode = [int]$g.Value } else { $exitCode = 1 }
            }
            catch {
                $exitCode = 1
            }
        }

        foreach ($line in @($lines)) {
            if (-not [string]::IsNullOrWhiteSpace($line)) {
                Write-Output $line
            }
        }

        if ($exitCode -ne 0) {
            $detailLines = @($lines | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
            $detail = if ($detailLines.Count -gt 0) {
                Convert-ToSingleLineText -Text ($detailLines -join ' | ')
            }
            else {
                'no-output'
            }

            throw ("[{0}] pre-v1 encoding gate failed gate={1} exit={2} detail={3}" -f $ScriptTag, [string]$gate.Name, $exitCode, $detail)
        }

        Write-Output ("[{0}] pre_v1_encoding_gate={1} status=PASS mode=fix policy=enforce" -f $ScriptTag, [string]$gate.Name)
    }
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$startFilePath = Resolve-RepoPath -Path $StartFile
$settings = Read-KeyValueFile -Path $startFilePath
$monitorTimelinePath = Get-MonitorTimelinePath -StartFilePath $startFilePath -RepoRoot $repoRoot
Invoke-KeyValueFileValueUpdate -Path $startFilePath -Values @{ MONITOR_CHAIN_TIMELINE = (Convert-ToAnchorPath -Path $monitorTimelinePath) }
Write-MonitorTimelineEvent -TimelinePath $monitorTimelinePath -EventName 'stage_window_invoke' -Fields @{
    stage = $Stage
    start_file = (Convert-ToAnchorPath -Path $startFilePath)
    start_monitors = [bool]$StartMonitors.IsPresent
    skip_monitor_restart = [bool]$SkipMonitorRestart.IsPresent
    enable_b_monitor_restart = [bool]$EnableBMonitorRestart.IsPresent
}
$settings = Invoke-DispatchDeliveryToggle -Path $startFilePath -Settings $settings -ScriptTag 'OPEN-AB-STAGE'
Invoke-PreV1EncodingFixGates -RepoRoot $repoRoot -ScriptTag 'OPEN-AB-STAGE'
Invoke-LaunchReadyGate -Stage $Stage -Settings $settings -StartFilePath $startFilePath -ScriptTag 'OPEN-AB-STAGE' -RepoRoot $repoRoot
$settings = Read-KeyValueFile -Path $startFilePath
$settings = Invoke-DispatchDeliveryToggle -Path $startFilePath -Settings $settings -ScriptTag 'OPEN-AB-STAGE'
Assert-PrecheckGateReady -Settings $settings -StartFilePath $startFilePath -ScriptTag 'OPEN-AB-STAGE'
Assert-NetworkPrecheckReady -Settings $settings -StartFilePath $startFilePath -ScriptTag 'OPEN-AB-STAGE' -RepoRoot $repoRoot
$settings = Read-KeyValueFile -Path $startFilePath
$settings = Invoke-DispatchDeliveryToggle -Path $startFilePath -Settings $settings -ScriptTag 'OPEN-AB-STAGE'
$bRestartModeRequested = ($Stage -eq 'B' -and $EnableBMonitorRestart.IsPresent)
$bLaunchPlan = Assert-BStartEligibility -Stage $Stage -Settings $settings -StartFilePath $startFilePath -RepoRoot $repoRoot -ScriptTag 'OPEN-AB-STAGE' -BRestartModeRequested $bRestartModeRequested
if ($null -ne $bLaunchPlan -and $bLaunchPlan.PSObject.Properties.Name -contains 'UpdatedSettings' -and $null -ne $bLaunchPlan.UpdatedSettings) {
    $settings = [System.Collections.IDictionary]$bLaunchPlan.UpdatedSettings
}
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

$settings = Clear-MonitorChainShutdownRequest -Path $startFilePath -Settings $settings -ScriptTag 'OPEN-AB-STAGE'

$entryScriptKey = if ($Stage -eq 'A') { 'ENTRY_SCRIPT_A' } else { 'ENTRY_SCRIPT_B' }
$taskKey = if ($Stage -eq 'A') { 'A_TASK_DEFINITION' } else { 'B_TASK_DEFINITION' }

$entryScriptPath = Resolve-RepoPath -Path ([string]$settings[$entryScriptKey])
$taskDefinitionRelative = Resolve-TaskDefinitionRelativePath -InputName ([string]$settings[$taskKey]) -SettingKey $taskKey
$null = Resolve-RepoPath -Path $taskDefinitionRelative

$powershellPath = Join-Path $PSHOME 'powershell.exe'
if (-not (Test-Path -LiteralPath $powershellPath)) {
    $powershellPath = 'powershell.exe'
}

$taskStaticPrecheckPolicy = 'enforce'
if ($settings.Contains('TASK_STATIC_PRECHECK_POLICY')) {
    $policyCandidate = (Convert-ToSingleLineText -Text ([string]$settings.TASK_STATIC_PRECHECK_POLICY)).ToLowerInvariant()
    if ($policyCandidate -in @('off', 'warn', 'enforce')) {
        $taskStaticPrecheckPolicy = $policyCandidate
    }
}

$taskStaticPrecheckFailOnWarnings = $false
if ($settings.Contains('TASK_STATIC_PRECHECK_FAIL_ON_WARNINGS')) {
    $taskStaticPrecheckFailOnWarnings = Convert-ToBooleanSetting -Value ([string]$settings.TASK_STATIC_PRECHECK_FAIL_ON_WARNINGS) -Default $false
}

$taskStaticPrecheckMaxFails = 3
if ($settings.Contains('TASK_STATIC_PRECHECK_MAX_FAILS')) {
    $parsedMaxFails = Get-ParsedPositiveInt -Value ([string]$settings.TASK_STATIC_PRECHECK_MAX_FAILS)
    if ($parsedMaxFails -gt 0) {
        $taskStaticPrecheckMaxFails = $parsedMaxFails
    }
}

$taskStaticPrecheckBlockEvent = 'manual-wait-paused'
if ($settings.Contains('TASK_STATIC_PRECHECK_BLOCK_EVENT')) {
    $blockEventCandidate = (Convert-ToSingleLineText -Text ([string]$settings.TASK_STATIC_PRECHECK_BLOCK_EVENT)).ToLowerInvariant()
    if ($blockEventCandidate -in @('manual-wait-paused', 'recovery-await-confirmation', 'task-definition-fix-required')) {
        $taskStaticPrecheckBlockEvent = $blockEventCandidate
    }
}

$taskStaticPrecheckFailCount = 0
if ($settings.Contains('TASK_STATIC_PRECHECK_FAIL_COUNT')) {
    $taskStaticPrecheckFailCount = Get-ParsedPositiveInt -Value ([string]$settings.TASK_STATIC_PRECHECK_FAIL_COUNT)
}

$taskStaticPrecheckScript = Join-Path $repoRoot 'tools\test\check_task_definition_static.ps1'
if (-not (Test-Path -LiteralPath $taskStaticPrecheckScript)) {
    throw "[OPEN-AB-STAGE] missing static precheck script: $taskStaticPrecheckScript"
}

$taskStaticPrecheckEnabled = ($Stage -eq 'A')
if ($taskStaticPrecheckEnabled) {
    $precheckScopeRoundTag = 'D1'
    $precheckScopeOperationIndex = 1

    $precheckArgs = @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', $taskStaticPrecheckScript,
        '-TaskDefinitionFile', $taskDefinitionRelative,
        '-Policy', $taskStaticPrecheckPolicy,
        '-RoundTag', $precheckScopeRoundTag,
        '-OperationIndex', [string]$precheckScopeOperationIndex
    )
    if ($taskStaticPrecheckFailOnWarnings) {
        $precheckArgs += '-FailOnWarnings'
    }

    & $powershellPath @precheckArgs
    $precheckExitCode = if ($null -eq $LASTEXITCODE) { 0 } else { [int]$LASTEXITCODE }
    if ($precheckExitCode -ne 0) {
        $taskStaticPrecheckFailCount += 1
        $precheckFailUpdates = @{
            TASK_STATIC_PRECHECK_FAIL_COUNT = [string]$taskStaticPrecheckFailCount
            TASK_STATIC_PRECHECK_LAST_FAIL_STAGE = $Stage
            TASK_STATIC_PRECHECK_LAST_FAIL_AT = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ssK')
        }
        Invoke-KeyValueFileValueUpdate -Path $startFilePath -Values $precheckFailUpdates

        $overLimit = ($taskStaticPrecheckFailCount -gt $taskStaticPrecheckMaxFails)
        if (-not $overLimit) {
            Add-StageTaskDefinitionFixTicket -StartFilePath $startFilePath -Settings $settings -Stage $Stage -TaskDefinitionRelative $taskDefinitionRelative -FailCount $taskStaticPrecheckFailCount -MaxFails $taskStaticPrecheckMaxFails -PrecheckExitCode $precheckExitCode
        }
        if ($overLimit) {
            Add-StageTaskDefinitionBlockedTicket -StartFilePath $startFilePath -Settings $settings -Stage $Stage -TaskDefinitionRelative $taskDefinitionRelative -FailCount $taskStaticPrecheckFailCount -MaxFails $taskStaticPrecheckMaxFails -PrecheckExitCode $precheckExitCode -BlockEvent $taskStaticPrecheckBlockEvent
            throw ("[OPEN-AB-STAGE] task static precheck failed and blocked: fail_count={0} limit={1} exit={2} stage={3} task={4} scope={5}:op{6}" -f $taskStaticPrecheckFailCount, $taskStaticPrecheckMaxFails, $precheckExitCode, $Stage, $taskDefinitionRelative, $precheckScopeRoundTag, $precheckScopeOperationIndex)
        }

        throw ("[OPEN-AB-STAGE] task static precheck failed exit={0} stage={1} task={2} fail_count={3} limit={4} scope={5}:op{6}" -f $precheckExitCode, $Stage, $taskDefinitionRelative, $taskStaticPrecheckFailCount, $taskStaticPrecheckMaxFails, $precheckScopeRoundTag, $precheckScopeOperationIndex)
    }

    if ($taskStaticPrecheckFailCount -gt 0 -or $settings.Contains('TASK_STATIC_PRECHECK_FAIL_COUNT')) {
        Invoke-KeyValueFileValueUpdate -Path $startFilePath -Values @{
            TASK_STATIC_PRECHECK_FAIL_COUNT = '0'
            TASK_STATIC_PRECHECK_LAST_PASS_STAGE = $Stage
            TASK_STATIC_PRECHECK_LAST_PASS_AT = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ssK')
        }
    }
    Write-Output ("[OPEN-AB-STAGE] task_static_precheck status=PASS stage={0} scope={1}:op{2} policy={3} fail_on_warnings={4} fail_count=0 limit={5}" -f $Stage, $precheckScopeRoundTag, $precheckScopeOperationIndex, $taskStaticPrecheckPolicy, [string]$taskStaticPrecheckFailOnWarnings, $taskStaticPrecheckMaxFails)
}
else {
    Write-Output ("[OPEN-AB-STAGE] task_static_precheck status=SKIP stage={0} reason=stage-policy runtime_fail_fast=enabled" -f $Stage)
}

Invoke-EnvFromSetting -EnvName 'AUTO_REMOTE_IP' -Settings $settings -Key 'REMOTE_IP'
Invoke-EnvFromSetting -EnvName 'AUTO_REMOTE_USER' -Settings $settings -Key 'REMOTE_USER'
Invoke-EnvFromSetting -EnvName 'AUTO_REMOTE_KEYPATH' -Settings $settings -Key 'REMOTE_KEYPATH'
Invoke-EnvFromSetting -EnvName 'AUTO_QUERIES' -Settings $settings -Key 'QUERIES'
Invoke-EnvFromSetting -EnvName 'AUTO_TERMINAL_WATCHDOG_MODE' -Settings $settings -Key 'TERMINAL_WATCHDOG_MODE'
Invoke-EnvFromSetting -EnvName 'AUTO_TERMINAL_WATCHDOG_INTERVAL_SEC' -Settings $settings -Key 'TERMINAL_WATCHDOG_INTERVAL_SEC'
Invoke-EnvFromSetting -EnvName 'AUTO_TERMINAL_WATCHDOG_MIN_AGE_SEC' -Settings $settings -Key 'TERMINAL_WATCHDOG_MIN_AGE_SEC'
Invoke-EnvFromSetting -EnvName 'AUTO_REMOTE_BUILD_LOCK_REQUIRED' -Settings $settings -Key 'REMOTE_BUILD_LOCK_REQUIRED'
Invoke-EnvFromSetting -EnvName 'AUTO_REMOTE_BUILD_LOCK_SCOPE' -Settings $settings -Key 'REMOTE_BUILD_LOCK_SCOPE'
Invoke-EnvFromSetting -EnvName 'AUTO_REMOTE_BUILD_LOCK_CONFLICT_ACTION' -Settings $settings -Key 'REMOTE_BUILD_LOCK_CONFLICT_ACTION'
Invoke-EnvFromSetting -EnvName 'AUTO_NETWORK_PRECHECK_REQUIRED' -Settings $settings -Key 'NETWORK_PRECHECK_REQUIRED'
Invoke-EnvFromSetting -EnvName 'AUTO_NETWORK_PRECHECK_LOCAL_REQUIRED' -Settings $settings -Key 'NETWORK_PRECHECK_LOCAL_REQUIRED'
Invoke-EnvFromSetting -EnvName 'AUTO_NETWORK_PRECHECK_REMOTE_REQUIRED' -Settings $settings -Key 'NETWORK_PRECHECK_REMOTE_REQUIRED'
Invoke-EnvFromSetting -EnvName 'AUTO_NETWORK_PRECHECK_CHECK_IPV4' -Settings $settings -Key 'NETWORK_PRECHECK_CHECK_IPV4'
Invoke-EnvFromSetting -EnvName 'AUTO_NETWORK_PRECHECK_CHECK_IPV6' -Settings $settings -Key 'NETWORK_PRECHECK_CHECK_IPV6'
Invoke-EnvFromSetting -EnvName 'AUTO_NETWORK_PRECHECK_REQUIRE_IPV4' -Settings $settings -Key 'NETWORK_PRECHECK_REQUIRE_IPV4'
Invoke-EnvFromSetting -EnvName 'AUTO_NETWORK_PRECHECK_REQUIRE_IPV6' -Settings $settings -Key 'NETWORK_PRECHECK_REQUIRE_IPV6'
Invoke-EnvFromSetting -EnvName 'AUTO_NETWORK_PRECHECK_TARGETS' -Settings $settings -Key 'NETWORK_PRECHECK_TARGETS'
Invoke-EnvFromSetting -EnvName 'AUTO_NETWORK_PRECHECK_TIMEOUT_SEC' -Settings $settings -Key 'NETWORK_PRECHECK_TIMEOUT_SEC'
Invoke-EnvFromSetting -EnvName 'AUTO_ROUND_RUNTIME_GATE_ENABLED' -Settings $settings -Key 'ROUND_RUNTIME_GATE_ENABLED'
Invoke-EnvFromSetting -EnvName 'AUTO_ROUND_RUNTIME_GATE_START_ROUND' -Settings $settings -Key 'ROUND_RUNTIME_GATE_START_ROUND'
Invoke-EnvFromSetting -EnvName 'AUTO_ROUND_RUNTIME_GATE_MAX_ATTEMPTS' -Settings $settings -Key 'ROUND_RUNTIME_GATE_MAX_ATTEMPTS'
Invoke-EnvFromSetting -EnvName 'AUTO_ROUND_RUNTIME_GATE_RETRY_DELAY_SEC' -Settings $settings -Key 'ROUND_RUNTIME_GATE_RETRY_DELAY_SEC'
Invoke-EnvFromSetting -EnvName 'AUTO_ROUND_RUNTIME_GATE_MIN_FREE_DISK_MB' -Settings $settings -Key 'ROUND_RUNTIME_GATE_MIN_FREE_DISK_MB'
Invoke-EnvFromSetting -EnvName 'AUTO_ROUND_RUNTIME_GATE_CHECK_REMOTE_LOCK' -Settings $settings -Key 'ROUND_RUNTIME_GATE_CHECK_REMOTE_LOCK'
Invoke-EnvFromSetting -EnvName 'AUTO_ROUND_RUNTIME_GATE_CHECK_NETWORK' -Settings $settings -Key 'ROUND_RUNTIME_GATE_CHECK_NETWORK'
Invoke-EnvFromSetting -EnvName 'AUTO_ROUND_RUNTIME_GATE_CHECK_PROCESS_CONFLICT' -Settings $settings -Key 'ROUND_RUNTIME_GATE_CHECK_PROCESS_CONFLICT'
Invoke-EnvFromSetting -EnvName 'AUTO_TASK_STATIC_PRECHECK_POLICY' -Settings $settings -Key 'TASK_STATIC_PRECHECK_POLICY'
Invoke-EnvFromSetting -EnvName 'AUTO_TASK_STATIC_PRECHECK_FAIL_ON_WARNINGS' -Settings $settings -Key 'TASK_STATIC_PRECHECK_FAIL_ON_WARNINGS'
if ($Stage -eq 'A') {
    Set-Item -Path 'Env:AUTO_ROUND_TASK_STATIC_GATE_ENABLED' -Value 'true'
    Set-Item -Path 'Env:AUTO_ROUND_TASK_STATIC_GATE_START_ROUND' -Value '1'
    Set-Item -Path 'Env:AUTO_ROUND_TASK_STATIC_GATE_END_ROUND' -Value '4'
    Set-Item -Path 'Env:AUTO_ROUND_TASK_STATIC_GATE_OPERATION_INDEX' -Value '0'
}
else {
    Set-Item -Path 'Env:AUTO_ROUND_TASK_STATIC_GATE_ENABLED' -Value 'true'
    Set-Item -Path 'Env:AUTO_ROUND_TASK_STATIC_GATE_START_ROUND' -Value '1'
    Set-Item -Path 'Env:AUTO_ROUND_TASK_STATIC_GATE_END_ROUND' -Value '8'
    Set-Item -Path 'Env:AUTO_ROUND_TASK_STATIC_GATE_OPERATION_INDEX' -Value '0'
}
Remove-Item -Path 'Env:AUTO_KEEP_WINDOW_ON_EXIT' -ErrorAction SilentlyContinue
Invoke-EnvFromSetting -EnvName 'AUTO_KEEP_WINDOW_ON_EXIT' -Settings $settings -Key 'KEEP_WINDOW_ON_EXIT'

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
            $snapshotDirHint = Get-LatestAnchorValueFromNoteText -Notes ([string]$settings.SESSION_FINAL_NOTES) -Key 'a_snapshot_dir'
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($snapshotDirHint)) {
        Set-Item -Path 'Env:AUTO_B_A_SNAPSHOT_DIR' -Value $snapshotDirHint
    }

    Write-Output ("[OPEN-AB-STAGE] b_restore_decision previous_a={0} previous_b={1} restore={2} reason={3}" -f $previousAFinalStatus, $previousBFinalStatus, $restoreFromASnapshot, $restoreDecisionReason)
}

Write-Output ("[OPEN-AB-STAGE] launch_banner stage={0} start_file={1} start_monitors={2} skip_monitor_restart={3} b_restart_hint={4}" -f
    $Stage,
    $StartFile,
    [string]$StartMonitors.IsPresent,
    [string]$SkipMonitorRestart.IsPresent,
    [string]$EnableBMonitorRestart.IsPresent)

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

$stageLaunchProbeDelayMs = 1200
if ($settings.Contains('STAGE_LAUNCH_PROBE_DELAY_MS')) {
    $parsedProbeDelayMs = 0
    if ([int]::TryParse(([string]$settings.STAGE_LAUNCH_PROBE_DELAY_MS), [ref]$parsedProbeDelayMs)) {
        if ($parsedProbeDelayMs -ge 0 -and $parsedProbeDelayMs -le 10000) {
            $stageLaunchProbeDelayMs = $parsedProbeDelayMs
        }
    }
}

if ($stageLaunchProbeDelayMs -gt 0) {
    Start-Sleep -Milliseconds $stageLaunchProbeDelayMs
}

$stageAliveAfterProbe = Test-ProcessAlive -ProcessId ([int]$processInfo.Id)
if (-not $stageAliveAfterProbe) {
    $failureDetail = ("stage={0} pid={1} exited_during_launch_probe delay_ms={2}" -f $Stage, $processInfo.Id, $stageLaunchProbeDelayMs)
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

    Invoke-KeyValueFileValueUpdate -Path $startFilePath -Values $failUpdates
    Write-Output ("[OPEN-AB-STAGE] stage_launch_fail {0}" -f $failureDetail)
    Write-Output "[OPEN-AB-STAGE] monitor_anchor_preserved reason=launch_probe_failed"
    return
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
Invoke-KeyValueFileValueUpdate -Path $startFilePath -Values $statusUpdates
$settings = Read-KeyValueFile -Path $startFilePath
Write-Output ("[OPEN-AB-STAGE] stage_status_update stage={0} session_status=RUNNING" -f $Stage)

$sessionOutDirRoot = Join-Path $repoRoot 'out\artifacts\dev_verify_multiround'
$currentStageRunDir = Resolve-CurrentStageRunDir -LaunchTime $stageLaunchTime -Settings $settings -SessionOutDirRoot $sessionOutDirRoot -StageProcessId ([int]$processInfo.Id)
if (-not [string]::IsNullOrWhiteSpace($currentStageRunDir)) {
    $updatedNotes = Invoke-SessionAnchorUpdateInStartFile -Path $startFilePath -Anchors @{ run_dir = (Convert-ToAnchorPath -Path $currentStageRunDir) }
    Write-Output ("[OPEN-AB-STAGE] anchor_update run_dir={0}" -f (Convert-ToAnchorPath -Path $currentStageRunDir))
    Write-MonitorTimelineEvent -TimelinePath $monitorTimelinePath -EventName 'run_dir_anchor_update' -Fields @{ stage = $Stage; run_dir = (Convert-ToAnchorPath -Path $currentStageRunDir) }
    $settings = Read-KeyValueFile -Path $startFilePath
}
else {
    Write-Output '[OPEN-AB-STAGE] anchor_update run_dir=unknown'
    Write-MonitorTimelineEvent -TimelinePath $monitorTimelinePath -EventName 'run_dir_anchor_update' -Fields @{ stage = $Stage; run_dir = 'unknown' }
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
$bForceMonitorRestart = ($Stage -eq 'B' -and $EnableBMonitorRestart.IsPresent)
if ($bRestartMode) {
    $monitorRestartPolicy = if ($bForceMonitorRestart) { 'force-full-restart' } else { 'rebind-existing' }
    Write-Output ("[OPEN-AB-STAGE] b_restart_mode=true monitor_restart_policy={0}" -f $monitorRestartPolicy)
    Write-MonitorTimelineEvent -TimelinePath $monitorTimelinePath -EventName 'b_restart_mode' -Fields @{
        stage = $Stage
        monitor_restart_policy = $monitorRestartPolicy
        force_monitor_restart = [bool]$bForceMonitorRestart
    }
}

$skipMonitorRestart = $SkipMonitorRestart.IsPresent
if ($skipMonitorRestart -and $Stage -eq 'B') {
    Write-Output '[OPEN-AB-STAGE] monitor_restart_skip_ignored stage=B reason=monitor-policy-enforced'
    $skipMonitorRestart = $false
    Write-MonitorTimelineEvent -TimelinePath $monitorTimelinePath -EventName 'stage_launch' -Fields @{
        stage = $Stage
        stage_pid = [int]$processInfo.Id
        launcher_pid = [int]$PID
        entry = (Convert-ToAnchorPath -Path $entryScriptPath)
        task = $taskDefinitionRelative
    }
}

$monitorReuseMaxStaleMinutes = Get-MonitorReuseStaleMinutes -Settings $settings
$monitorStates = $null

if (-not $bForceMonitorRestart -and -not $skipMonitorRestart) {
    $monitorPresenceProbe = Test-MonitorReuseProcessPresence -StartFilePath $startFilePath -RepoRoot $repoRoot
    $monitorReuseProbe = Test-MonitorReuseActivity -Settings $settings -RepoRoot $repoRoot -MaxStaleMinutes $monitorReuseMaxStaleMinutes
    if (-not [bool]$monitorPresenceProbe.Active -and -not [bool]$monitorReuseProbe.Active) {
        $staleStoppedPids = @(Invoke-MonitorProcessStopForStartFile -StartFilePath $startFilePath)
        Write-Output ("[OPEN-AB-STAGE] monitor_reuse_guard status=STALE threshold_min={0} evidence={1} action=stop_stale_monitors stopped_count={2} stopped_pids={3}" -f [int]$monitorReuseProbe.ThresholdMinutes, (($monitorReuseProbe.Evidence -join ';')), $staleStoppedPids.Count, ($staleStoppedPids -join ','))
        Write-MonitorTimelineEvent -TimelinePath $monitorTimelinePath -EventName 'monitor_reuse_guard_stale' -Fields @{
            stage = $Stage
            threshold_min = [int]$monitorReuseProbe.ThresholdMinutes
            evidence = @($monitorReuseProbe.Evidence)
            stopped_count = $staleStoppedPids.Count
            stopped_pids = @($staleStoppedPids)
        }

        if (-not $bForceMonitorRestart) {
            $monitorStates = @{}
        }
    }
    elseif ([bool]$monitorPresenceProbe.Active -and -not [bool]$monitorReuseProbe.Active) {
        Write-Output ("[OPEN-AB-STAGE] monitor_reuse_guard status=ACTIVE-UNANCHORED match_count={0} evidence={1} action=keep_live" -f [int]$monitorPresenceProbe.MatchCount, (($monitorPresenceProbe.Evidence -join ';')))
        Write-MonitorTimelineEvent -TimelinePath $monitorTimelinePath -EventName 'monitor_reuse_guard_active_unanchored' -Fields @{
            stage = $Stage
            match_count = [int]$monitorPresenceProbe.MatchCount
            evidence = @($monitorPresenceProbe.Evidence)
        }
    }
    else {
        Write-Output ("[OPEN-AB-STAGE] monitor_reuse_guard status=ACTIVE threshold_min={0} evidence={1}" -f [int]$monitorReuseProbe.ThresholdMinutes, (($monitorReuseProbe.Evidence -join ';')))
        Write-MonitorTimelineEvent -TimelinePath $monitorTimelinePath -EventName 'monitor_reuse_guard_active' -Fields @{
            stage = $Stage
            threshold_min = [int]$monitorReuseProbe.ThresholdMinutes
            evidence = @($monitorReuseProbe.Evidence)
        }
    }
}

if (-not $bForceMonitorRestart -and -not $skipMonitorRestart -and $null -ne $monitorStates) {
    $roleSpec = @(
        [pscustomobject]@{ Role = 'supervisor'; ScriptLeaf = 'unattended_ab_supervisor.ps1' },
        [pscustomobject]@{ Role = 'companion'; ScriptLeaf = 'unattended_ab_companion.ps1' },
        [pscustomobject]@{ Role = 'guard'; ScriptLeaf = 'unattended_ab_session_guard.ps1' },
        [pscustomobject]@{ Role = 'trigger'; ScriptLeaf = 'unattended_ab_takeover_trigger.ps1' }
    )

    foreach ($spec in $roleSpec) {
        $role = [string]$spec.Role
        if (-not $monitorStates.ContainsKey($role)) {
            continue
        }

        $state = $monitorStates[$role]
        if ($null -eq $state -or -not [bool]$state.RunningForStartFile) {
            continue
        }

        $roleProbe = Test-MonitorRoleReuseActivity -Role $role -Settings $settings -RepoRoot $repoRoot -StartFilePath $startFilePath -MaxStaleMinutes $monitorReuseMaxStaleMinutes
        if (-not [bool]$roleProbe.Active) {
            $stoppedRolePids = @(Invoke-MonitorRoleProcessStopForStartFile -ScriptLeaf ([string]$spec.ScriptLeaf) -StartFilePath $startFilePath)
            Write-Output ("[OPEN-AB-STAGE] monitor_reuse_stale_cleanup role={0} threshold_min={1} evidence={2} stopped_count={3} stopped_pids={4}" -f $role, [int]$roleProbe.ThresholdMinutes, (($roleProbe.Evidence -join ';')), $stoppedRolePids.Count, ($stoppedRolePids -join ','))
            Write-MonitorTimelineEvent -TimelinePath $monitorTimelinePath -EventName 'monitor_reuse_stale_cleanup' -Fields @{
                stage = $Stage
                role = $role
                threshold_min = [int]$roleProbe.ThresholdMinutes
                evidence = @($roleProbe.Evidence)
                stopped_count = $stoppedRolePids.Count
                stopped_pids = @($stoppedRolePids)
            }

            $monitorStates[$role] = Get-MonitorBindingState -ScriptLeaf ([string]$spec.ScriptLeaf) -StartFilePath $startFilePath -RepoRoot $repoRoot
        }
    }
}

if ($bForceMonitorRestart -and -not $skipMonitorRestart) {
    Write-Output '[OPEN-AB-STAGE] b_monitor_rebind force_restart_all=true targets=supervisor,companion,guard,trigger'
    $stoppedPids = @(Invoke-MonitorProcessStopForStartFile -StartFilePath $startFilePath)
    Write-Output ("[OPEN-AB-STAGE] monitor_restart stopped_count={0} stopped_pids={1}" -f $stoppedPids.Count, ($stoppedPids -join ','))
    Write-MonitorTimelineEvent -TimelinePath $monitorTimelinePath -EventName 'monitor_restart_all' -Fields @{ stage = $Stage; stopped_count = $stoppedPids.Count; stopped_pids = @($stoppedPids) }
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

$autoStartTakeoverTrigger = if ($settings.Contains('AUTO_START_TAKEOVER_TRIGGER')) {
    Convert-ToBooleanSetting -Value ([string]$settings.AUTO_START_TAKEOVER_TRIGGER) -Default $false
}
elseif ($settings.Contains('EXTERNAL_TRIGGER_EXECUTE')) {
    Convert-ToBooleanSetting -Value ([string]$settings.EXTERNAL_TRIGGER_EXECUTE) -Default $false
}
else {
    $false
}

$monitorStates = @{}
if (-not $bForceMonitorRestart) {
    $monitorStates.supervisor = Get-MonitorBindingState -ScriptLeaf 'unattended_ab_supervisor.ps1' -StartFilePath $startFilePath -RepoRoot $repoRoot
    $monitorStates.companion = Get-MonitorBindingState -ScriptLeaf 'unattended_ab_companion.ps1' -StartFilePath $startFilePath -RepoRoot $repoRoot
    $monitorStates.guard = Get-MonitorBindingState -ScriptLeaf 'unattended_ab_session_guard.ps1' -StartFilePath $startFilePath -RepoRoot $repoRoot
    $monitorStates.trigger = Get-MonitorBindingState -ScriptLeaf 'unattended_ab_takeover_trigger.ps1' -StartFilePath $startFilePath -RepoRoot $repoRoot

    $requiredMonitorRoles = @('supervisor', 'companion', 'guard')
    if ($autoStartTakeoverTrigger) {
        $requiredMonitorRoles += 'trigger'
    }

    $missingMonitorRoles = @()
    foreach ($role in $requiredMonitorRoles) {
        if (-not $monitorStates.ContainsKey($role) -or -not [bool]$monitorStates[$role].RunningForStartFile) {
            $missingMonitorRoles += $role
        }
    }

    if ($missingMonitorRoles.Count -eq 0) {
        Write-Output ("[OPEN-AB-STAGE] monitor_chain_probe status=ALL-REAL-LIVE roles={0} action=reuse" -f ($requiredMonitorRoles -join ','))
        Write-MonitorTimelineEvent -TimelinePath $monitorTimelinePath -EventName 'monitor_chain_probe_all_live' -Fields @{ stage = $Stage; roles = @($requiredMonitorRoles) }
    }
    else {
        Write-Output ("[OPEN-AB-STAGE] monitor_chain_probe status=PARTIAL-OR-MISSING required={0} missing={1} action=launch-missing" -f ($requiredMonitorRoles -join ','), ($missingMonitorRoles -join ','))
        Write-MonitorTimelineEvent -TimelinePath $monitorTimelinePath -EventName 'monitor_chain_probe_partial' -Fields @{ stage = $Stage; required = @($requiredMonitorRoles); missing = @($missingMonitorRoles) }
    }

    # Liveness gate: verify each detected process is truly active by checking anchor freshness.
    # Zombie terminal windows (left from -NoExit in previous runs) may still match by command
    # line even after the actual script has exited. If anchor files are stale, stop the zombie.
    foreach ($checkRole in @('supervisor', 'companion', 'guard', 'trigger')) {
        if (-not $monitorStates.ContainsKey($checkRole) -or -not [bool]$monitorStates[$checkRole].RunningForStartFile) {
            continue
        }

        $roleProbe = Test-MonitorRoleReuseActivity -Role $checkRole -Settings $settings -RepoRoot $repoRoot -StartFilePath $startFilePath -MaxStaleMinutes $monitorReuseMaxStaleMinutes
        if (-not [bool]$roleProbe.Active) {
            $stoppedRolePids = @(Invoke-MonitorRoleProcessStopForStartFile -ScriptLeaf ('unattended_ab_{0}.ps1' -f $checkRole) -StartFilePath $startFilePath)
            Write-Output ("[OPEN-AB-STAGE] monitor_liveness_gate role={0} reason=stale-anchor evidence={1} stopped_pids={2}" -f $checkRole, ($roleProbe.Evidence -join ';'), ($stoppedRolePids -join ','))
            Write-MonitorTimelineEvent -TimelinePath $monitorTimelinePath -EventName 'monitor_liveness_gate' -Fields @{
                stage = $Stage
                role = $checkRole
                reason = 'stale-anchor'
                evidence = @($roleProbe.Evidence)
                stopped_pids = @($stoppedRolePids)
            }
            $monitorStates[$checkRole] = Get-MonitorBindingState -ScriptLeaf ('unattended_ab_{0}.ps1' -f $checkRole) -StartFilePath $startFilePath -RepoRoot $repoRoot
        }
    }
}

exit 0

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
        [bool]$ForceRestart,
        [bool]$SkipRestart,
        [hashtable]$States
    )

    if ($SkipRestart) {
        return $false
    }

    if ($ForceRestart) {
        return $true
    }

    if ($null -eq $States -or -not $States.ContainsKey($Role)) {
        return $true
    }

    return (-not [bool]$States[$Role].RunningForStartFile)
}

$restartSupervisor = Test-ShouldRestartMonitorRole -Role 'supervisor' -ForceRestart $bForceMonitorRestart -SkipRestart $skipMonitorRestart -States $monitorStates
$supervisorOutput = @()
if ($restartSupervisor) {
    if (-not $bForceMonitorRestart -and $monitorStates.ContainsKey('supervisor')) {
        $supervisorState = $monitorStates.supervisor
        Write-Output ("[OPEN-AB-STAGE] monitor_restart_single role=supervisor reason={0} match_count={1} mismatch_count={2} unbound_count={3}" -f
            (Get-RestartReasonFromState -State $supervisorState),
            [int]$supervisorState.MatchCount,
            [int]$supervisorState.MismatchCount,
            [int]$supervisorState.UnboundCount)
        Write-MonitorTimelineEvent -TimelinePath $monitorTimelinePath -EventName 'monitor_restart_single' -Fields @{ stage = $Stage; role = 'supervisor'; reason = (Get-RestartReasonFromState -State $supervisorState); match_count = [int]$supervisorState.MatchCount; mismatch_count = [int]$supervisorState.MismatchCount; unbound_count = [int]$supervisorState.UnboundCount }
    }

    if ($Stage -eq 'A') {
        if ([string]::IsNullOrWhiteSpace($currentStageRunDir)) {
            $supervisorOutput = & $supervisorLauncherPath -StartFile $StartFile -CurrentAStartRound 1 -NoRestartIfRunning
        }
        else {
            $supervisorOutput = & $supervisorLauncherPath -StartFile $StartFile -CurrentAStartRound 1 -CurrentARunDir $currentStageRunDir -NoRestartIfRunning
        }
    }
    else {
        $currentBRunDir = $currentStageRunDir

        if ([string]::IsNullOrWhiteSpace($currentBRunDir) -and $settings.Contains('SESSION_FINAL_NOTES')) {
            $hintRunDir = Get-LatestAnchorValueFromNoteText -Notes ([string]$settings.SESSION_FINAL_NOTES) -Key 'run_dir'
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
            $supervisorOutput = & $supervisorLauncherPath -StartFile $StartFile -StartFromStage B -NoRestartIfRunning
        }
        else {
            Write-Output ("[OPEN-AB-STAGE] monitor_attach_b run_dir={0}" -f $currentBRunDir)
            $supervisorOutput = & $supervisorLauncherPath -StartFile $StartFile -StartFromStage B -CurrentBRunDir $currentBRunDir -NoRestartIfRunning
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
        Write-MonitorTimelineEvent -TimelinePath $monitorTimelinePath -EventName 'monitor_reuse' -Fields @{ stage = $Stage; role = 'supervisor'; match_count = [int]$supervisorState.MatchCount; mismatch_count = [int]$supervisorState.MismatchCount; unbound_count = [int]$supervisorState.UnboundCount; pids = @($supervisorState.MatchPids) }
    }

    if ($Stage -eq 'A') {
        if ([string]::IsNullOrWhiteSpace($currentStageRunDir)) {
            $supervisorOutput = & $supervisorLauncherPath -StartFile $StartFile -CurrentAStartRound 1 -NoRestartIfRunning
        }
        else {
            $supervisorOutput = & $supervisorLauncherPath -StartFile $StartFile -CurrentAStartRound 1 -CurrentARunDir $currentStageRunDir -NoRestartIfRunning
        }
    }
    else {
        if ([string]::IsNullOrWhiteSpace($currentStageRunDir)) {
            $supervisorOutput = & $supervisorLauncherPath -StartFile $StartFile -StartFromStage B -NoRestartIfRunning
        }
        else {
            $supervisorOutput = & $supervisorLauncherPath -StartFile $StartFile -StartFromStage B -CurrentBRunDir $currentStageRunDir -NoRestartIfRunning
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

    if ([string]::IsNullOrWhiteSpace($supervisorLog)) {
        $supervisorLog = Get-AnchorValueFromConfig -Settings $settings -Key 'supervisor_log'
    }
    if ([string]::IsNullOrWhiteSpace($liveStatus)) {
        $liveStatus = Get-AnchorValueFromConfig -Settings $settings -Key 'live_status'
    }

    $supervisorRunDirText = if ([string]::IsNullOrWhiteSpace($currentStageRunDir)) { 'unknown' } else { (Convert-ToAnchorPath -Path $currentStageRunDir) }
    Write-Output ("[OPEN-AB-STAGE] monitor_anchor_rebind role=supervisor run_dir={0}" -f $supervisorRunDirText)
}

$restartCompanion = Test-ShouldRestartMonitorRole -Role 'companion' -ForceRestart $bForceMonitorRestart -SkipRestart $skipMonitorRestart -States $monitorStates
if ($restartCompanion) {
    if (-not $bForceMonitorRestart -and $monitorStates.ContainsKey('companion')) {
        $companionState = $monitorStates.companion
        Write-Output ("[OPEN-AB-STAGE] monitor_restart_single role=companion reason={0} match_count={1} mismatch_count={2} unbound_count={3}" -f
            (Get-RestartReasonFromState -State $companionState),
            [int]$companionState.MatchCount,
            [int]$companionState.MismatchCount,
            [int]$companionState.UnboundCount)
        Write-MonitorTimelineEvent -TimelinePath $monitorTimelinePath -EventName 'monitor_restart_single' -Fields @{ stage = $Stage; role = 'companion'; reason = (Get-RestartReasonFromState -State $companionState); match_count = [int]$companionState.MatchCount; mismatch_count = [int]$companionState.MismatchCount; unbound_count = [int]$companionState.UnboundCount }
    }

    $companionOutput = if ([string]::IsNullOrWhiteSpace($supervisorLog)) {
        & $companionLauncherPath -StartFile $StartFile -NoRestartIfRunning
    }
    else {
        & $companionLauncherPath -StartFile $StartFile -SupervisorLog $supervisorLog -NoRestartIfRunning
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
        Write-MonitorTimelineEvent -TimelinePath $monitorTimelinePath -EventName 'monitor_reuse' -Fields @{ stage = $Stage; role = 'companion'; match_count = [int]$companionState.MatchCount; mismatch_count = [int]$companionState.MismatchCount; unbound_count = [int]$companionState.UnboundCount; pids = @($companionState.MatchPids) }
    }

    $companionOutput = if ([string]::IsNullOrWhiteSpace($supervisorLog)) {
        & $companionLauncherPath -StartFile $StartFile -NoRestartIfRunning
    }
    else {
        & $companionLauncherPath -StartFile $StartFile -SupervisorLog $supervisorLog -NoRestartIfRunning
    }

    $companionLog = ''
    foreach ($line in @($companionOutput | ForEach-Object { [string]$_ })) {
        Write-Output $line
        if ($line -match 'companion_log=([^\s]+)$') {
            $companionLog = $Matches[1]
        }
    }

    if ([string]::IsNullOrWhiteSpace($companionLog)) {
        $companionLog = Get-AnchorValueFromConfig -Settings $settings -Key 'companion_log'
    }

    $companionRunDirText = if ([string]::IsNullOrWhiteSpace($currentStageRunDir)) { 'unknown' } else { (Convert-ToAnchorPath -Path $currentStageRunDir) }
    Write-Output ("[OPEN-AB-STAGE] monitor_anchor_rebind role=companion run_dir={0}" -f $companionRunDirText)
}

$restartGuard = Test-ShouldRestartMonitorRole -Role 'guard' -ForceRestart $bForceMonitorRestart -SkipRestart $skipMonitorRestart -States $monitorStates
if ($restartGuard) {
    if (-not $bForceMonitorRestart -and $monitorStates.ContainsKey('guard')) {
        $guardStateObj = $monitorStates.guard
        Write-Output ("[OPEN-AB-STAGE] monitor_restart_single role=guard reason={0} match_count={1} mismatch_count={2} unbound_count={3}" -f
            (Get-RestartReasonFromState -State $guardStateObj),
            [int]$guardStateObj.MatchCount,
            [int]$guardStateObj.MismatchCount,
            [int]$guardStateObj.UnboundCount)
        Write-MonitorTimelineEvent -TimelinePath $monitorTimelinePath -EventName 'monitor_restart_single' -Fields @{ stage = $Stage; role = 'guard'; reason = (Get-RestartReasonFromState -State $guardStateObj); match_count = [int]$guardStateObj.MatchCount; mismatch_count = [int]$guardStateObj.MismatchCount; unbound_count = [int]$guardStateObj.UnboundCount }
    }

    $guardOutput = & $guardLauncherPath -StartFile $StartFile -NoRestartIfRunning
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
        Write-MonitorTimelineEvent -TimelinePath $monitorTimelinePath -EventName 'monitor_reuse' -Fields @{ stage = $Stage; role = 'guard'; match_count = [int]$guardStateObj.MatchCount; mismatch_count = [int]$guardStateObj.MismatchCount; unbound_count = [int]$guardStateObj.UnboundCount; pids = @($guardStateObj.MatchPids) }
    }

    $guardOutput = & $guardLauncherPath -StartFile $StartFile -NoRestartIfRunning
    $guardLog = ''
    foreach ($line in @($guardOutput | ForEach-Object { [string]$_ })) {
        Write-Output $line
        if ($line -match 'guard_log=([^\s]+)') {
            $guardLog = $Matches[1]
        }
    }

    if ([string]::IsNullOrWhiteSpace($guardLog)) {
        $guardLog = Get-AnchorValueFromConfig -Settings $settings -Key 'guard_log'
    }

    $guardRunDirText = if ([string]::IsNullOrWhiteSpace($currentStageRunDir)) { 'unknown' } else { (Convert-ToAnchorPath -Path $currentStageRunDir) }
    Write-Output ("[OPEN-AB-STAGE] monitor_anchor_rebind role=guard run_dir={0}" -f $guardRunDirText)
}

if ($autoStartTakeoverTrigger) {
    $restartTrigger = Test-ShouldRestartMonitorRole -Role 'trigger' -ForceRestart $bForceMonitorRestart -SkipRestart $skipMonitorRestart -States $monitorStates
    if ($restartTrigger) {
        if (-not $bForceMonitorRestart -and $monitorStates.ContainsKey('trigger')) {
            $triggerStateObj = $monitorStates.trigger
            Write-Output ("[OPEN-AB-STAGE] monitor_restart_single role=trigger reason={0} match_count={1} mismatch_count={2} unbound_count={3}" -f
                (Get-RestartReasonFromState -State $triggerStateObj),
                [int]$triggerStateObj.MatchCount,
                [int]$triggerStateObj.MismatchCount,
                [int]$triggerStateObj.UnboundCount)
            Write-MonitorTimelineEvent -TimelinePath $monitorTimelinePath -EventName 'monitor_restart_single' -Fields @{ stage = $Stage; role = 'trigger'; reason = (Get-RestartReasonFromState -State $triggerStateObj); match_count = [int]$triggerStateObj.MatchCount; mismatch_count = [int]$triggerStateObj.MismatchCount; unbound_count = [int]$triggerStateObj.UnboundCount }
        }

        try {
            $triggerOutput = & $triggerLauncherPath -StartFile $StartFile -NoRestartIfRunning
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
            Write-MonitorTimelineEvent -TimelinePath $monitorTimelinePath -EventName 'monitor_reuse' -Fields @{ stage = $Stage; role = 'trigger'; match_count = [int]$triggerStateObj.MatchCount; mismatch_count = [int]$triggerStateObj.MismatchCount; unbound_count = [int]$triggerStateObj.UnboundCount; pids = @($triggerStateObj.MatchPids) }
        }

        try {
            $triggerOutput = & $triggerLauncherPath -StartFile $StartFile -NoRestartIfRunning
            foreach ($line in @($triggerOutput | ForEach-Object { [string]$_ })) {
                Write-Output $line
            }
        }
        catch {
            $detail = ([regex]::Replace(([string]$_.Exception.Message), '\s+', ' ')).Trim()
            Write-Output ("[OPEN-AB-STAGE] trigger_rebind_probe_failed stage={0} detail={1}" -f $Stage, $detail)
        }

        $triggerRunDirText = if ([string]::IsNullOrWhiteSpace($currentStageRunDir)) { 'unknown' } else { (Convert-ToAnchorPath -Path $currentStageRunDir) }
        Write-Output ("[OPEN-AB-STAGE] monitor_anchor_rebind role=trigger run_dir={0}" -f $triggerRunDirText)
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
    $updatedNotes = Invoke-SessionAnchorUpdateInStartFile -Path $startFilePath -Anchors $anchorUpdates
    Write-Output ("[OPEN-AB-STAGE] anchor_update notes={0}" -f $updatedNotes)
    Write-MonitorTimelineEvent -TimelinePath $monitorTimelinePath -EventName 'anchor_update' -Fields @{ stage = $Stage; anchors = $anchorUpdates; notes = $updatedNotes }
}

