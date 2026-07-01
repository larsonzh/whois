param(
    [Parameter(Mandatory = $true)][string]$StartFile,
    [ValidateRange(5, 300)][int]$PollSec = 30,
    [switch]$Once,
    [switch]$NoAutoStopOnFinal,
    [switch]$ExitShellOnFinal,
    [AllowNull()][string]$QueuePath = '',
    [AllowNull()][string]$TriggerCommand = '',
    [switch]$ExecuteTriggerCommand,
    [ValidateRange(0, 200000)][int]$MaxProcessedIds = 0
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'unattended_exit_result.ps1')
$script:UnhandledExitTag = 'UNATTENDED-AB-TAKEOVER-TRIGGER'

trap {
    # Write terminal marker to trigger state if state path is initialized,
    # so zombie detection can immediately identify this as a dead process.
    if (-not [string]::IsNullOrWhiteSpace($statePath)) {
        try {
            @{ status = 'stopped'; event = 'trap-exit'; error = ("$_" -replace '"', '\"') } | ConvertTo-Json | Out-File -LiteralPath $statePath -Encoding utf8 -Force -ErrorAction SilentlyContinue
        }
        catch { }
    }
    $exitCode = Get-UnattendedExitCodeFromRecord -Tag $script:UnhandledExitTag -Record $_ -DefaultExitCode 1
    Write-UnattendedUnhandledResult -Tag $script:UnhandledExitTag -Record $_ -ExitCode $exitCode
    exit $exitCode
}



function Resolve-RepoPath {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw 'Path must not be empty.'
    }

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return (Resolve-Path -LiteralPath $Path).Path
    }

    return (Resolve-Path -LiteralPath (Join-Path $script:RepoRoot $Path)).Path
}

function Resolve-RepoPathAllowMissing {
    param([AllowNull()][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return ''
    }

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return [System.IO.Path]::GetFullPath($Path)
    }

    return [System.IO.Path]::GetFullPath((Join-Path $script:RepoRoot $Path))
}

function Convert-ToRepoRelativePath {
    param([AllowNull()][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return ''
    }

    try {
        $fullPath = [System.IO.Path]::GetFullPath($Path)
        $repoRootFull = [System.IO.Path]::GetFullPath($script:RepoRoot)
        if ($fullPath.StartsWith($repoRootFull, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $fullPath.Substring($repoRootFull.Length).TrimStart('\\').Replace('\\', '/')
        }

        return $fullPath.Replace('\\', '/')
    }
    catch {
        return $Path.Replace('\\', '/')
    }
}

function Convert-MsysPathToWindowsPath {
    param([AllowNull()][string]$Path)

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

function Convert-ToSingleLineText {
    param([AllowNull()][string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return ''
    }

    $singleLine = (($Text -split "`r?`n") -join ' ')
    return ([regex]::Replace($singleLine, '\s+', ' ')).Trim()
}

function Get-Utf8BomEncoding {
    return [System.Text.UTF8Encoding]::new($true)
}

function Convert-ToFileText {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) {
        return ''
    }

    if ($Value -is [string]) {
        return [string]$Value
    }

    if (-not ($Value -is [string]) -and $Value -is [System.Collections.IEnumerable]) {
        $lines = @($Value | ForEach-Object { [string]$_ })
        return ($lines -join "`r`n")
    }

    return [string]$Value
}

function Write-Utf8BomFile {
    param(
        [string]$Path,
        [AllowNull()][object]$Value
    )

    $parent = Split-Path -Parent $Path
    if (-not [string]::IsNullOrWhiteSpace($parent) -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }

    $text = Convert-ToFileText -Value $Value
    [System.IO.File]::WriteAllText($Path, $text, (Get-Utf8BomEncoding))
}

function Add-Utf8Line {
    param(
        [string]$Path,
        [string]$Line
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        Write-Utf8BomFile -Path $Path -Value $Line
        return
    }

    $appendEncoding = [System.Text.UTF8Encoding]::new($false)
    $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite)
    try {
        $writer = New-Object System.IO.StreamWriter($stream, $appendEncoding)
        try {
            $writer.WriteLine($Line)
            $writer.Flush()
        }
        finally {
            $writer.Dispose()
        }
    }
    finally {
        $stream.Dispose()
    }
}

function Test-TextContainsNonAscii {
    param([AllowNull()][string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return $false
    }

    return ($Text -match '[^\u0000-\u007F]')
}

function Test-FileHasUtf8Bom {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) {
        return $false
    }

    $bytes = [System.IO.File]::ReadAllBytes($Path)
    return ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF)
}

function Assert-Ps51Utf8BomCompatibility {
    param(
        [string]$ScriptPath,
        [string]$ScriptRole
    )

    if ([string]::IsNullOrWhiteSpace($ScriptPath) -or -not (Test-Path -LiteralPath $ScriptPath)) {
        return
    }

    try {
        $raw = Get-Content -LiteralPath $ScriptPath -Raw -Encoding utf8 -ErrorAction Stop
    }
    catch {
        return
    }

    if ((Test-TextContainsNonAscii -Text $raw) -and -not (Test-FileHasUtf8Bom -Path $ScriptPath)) {
        Write-Warning ("[AB-TAKEOVER-TRIGGER] ps51_utf8_bom_recommended role={0} path={1}" -f $ScriptRole, $ScriptPath)
    }
}

function Add-DelimitedNote {
    param(
        [AllowNull()][string]$Existing,
        [AllowNull()][string]$Append
    )

    $appendText = Convert-ToSingleLineText -Text $Append
    if ([string]::IsNullOrWhiteSpace($appendText)) {
        return (Convert-ToSingleLineText -Text $Existing)
    }

    $existingText = Convert-ToSingleLineText -Text $Existing
    if ([string]::IsNullOrWhiteSpace($existingText)) {
        return $appendText
    }

    return ("{0}; {1}" -f $existingText, $appendText)
}

function Get-NormalizedPathKey {
    param([AllowNull()][string]$Path)

    $singleLinePath = Convert-ToSingleLineText -Text $Path
    if ([string]::IsNullOrWhiteSpace($singleLinePath)) {
        return ''
    }

    $candidatePath = Convert-MsysPathToWindowsPath -Path $singleLinePath
    if ([string]::IsNullOrWhiteSpace($candidatePath)) {
        return ''
    }

    try {
        $resolvedPath = Resolve-RepoPathAllowMissing -Path $candidatePath
        if ([string]::IsNullOrWhiteSpace($resolvedPath)) {
            return ''
        }

        return [System.IO.Path]::GetFullPath($resolvedPath).ToLowerInvariant()
    }
    catch {
        return ($candidatePath.Replace('/', '\\')).ToLowerInvariant()
    }
}

function Get-StartFileMutexName {
    param(
        [AllowNull()][string]$Role,
        [string]$StartFilePath
    )

    $roleToken = Convert-ToSingleLineText -Text $Role
    if ([string]::IsNullOrWhiteSpace($roleToken)) {
        $roleToken = 'takeover-trigger'
    }
    $roleToken = ([regex]::Replace($roleToken, '[^A-Za-z0-9._-]', '_')).Trim('_')
    if ([string]::IsNullOrWhiteSpace($roleToken)) {
        $roleToken = 'takeover-trigger'
    }

    $fullPath = [System.IO.Path]::GetFullPath($StartFilePath).ToLowerInvariant()
    $sha1 = [System.Security.Cryptography.SHA1]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($fullPath)
        $hashBytes = $sha1.ComputeHash($bytes)
        $hash = ([System.BitConverter]::ToString($hashBytes)).Replace('-', '').ToLowerInvariant()
    }
    finally {
        if ($null -ne $sha1) {
            $sha1.Dispose()
        }
    }

    return ("Local\wc_ab_{0}_{1}" -f $roleToken, $hash)
}

function Enter-InstanceMutex {
    param(
        [AllowNull()][string]$Role,
        [string]$StartFilePath
    )

    $name = Get-StartFileMutexName -Role $Role -StartFilePath $StartFilePath
    $createdNew = $false
    $mutex = New-Object System.Threading.Mutex($false, $name, [ref]$createdNew)

    $acquired = $false
    try {
        $acquired = $mutex.WaitOne(0, $false)
    }
    catch [System.Threading.AbandonedMutexException] {
        $acquired = $true
    }

    if (-not $acquired) {
        Write-Output ("[AB-TAKEOVER-TRIGGER] single_instance_conflict mutex={0} start_file={1}" -f $name, $StartFilePath)
        $mutex.Dispose()
        return $null
    }

    return $mutex
}

function Get-ObjectPropertyString {
    param(
        [object]$InputObject,
        [string]$Name
    )

    if ($null -eq $InputObject -or [string]::IsNullOrWhiteSpace($Name)) {
        return ''
    }

    if ($InputObject -is [System.Collections.IDictionary]) {
        if ($InputObject.Contains($Name)) {
            return [string]$InputObject[$Name]
        }
        return ''
    }

    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return ''
    }

    return [string]$property.Value
}

function Convert-ToBooleanSetting {
    param(
        [AllowNull()][string]$Value,
        [bool]$Default = $false
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $Default
    }

    return $Value.Trim().ToLowerInvariant() -in @('1', 'true', 'yes', 'on')
}

function Get-DateTimeOrNull {
    param([AllowNull()][string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return $null
    }

    $parsed = [datetimeoffset]::MinValue
    if ([datetimeoffset]::TryParse($Text, [ref]$parsed)) {
        return $parsed.UtcDateTime
    }

    return $null
}

function Get-StatusValue {
    param([AllowNull()][string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return 'NOT_RUN'
    }

    return $Value.Trim().ToUpperInvariant()
}

function Test-IsTerminalFinalStatus {
    param([AllowNull()][string]$Status)

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
    catch {
        $null = $_
    }

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

function Get-IntSetting {
    param(
        [System.Collections.IDictionary]$Settings,
        [string]$Key,
        [int]$Default,
        [int]$Min,
        [int]$Max
    )

    if ($null -eq $Settings -or [string]::IsNullOrWhiteSpace($Key) -or -not $Settings.Contains($Key)) {
        return $Default
    }

    $raw = Convert-ToSingleLineText -Text ([string]$Settings[$Key])
    if ([string]::IsNullOrWhiteSpace($raw)) {
        return $Default
    }

    $parsed = 0
    if (-not [int]::TryParse($raw, [ref]$parsed)) {
        return $Default
    }

    if ($parsed -lt $Min -or $parsed -gt $Max) {
        return $Default
    }

    return $parsed
}

function Get-ChatHeartbeatPath {
    param(
        [System.Collections.IDictionary]$Settings,
        [string]$StartToken,
        [string]$LegacyStartToken
    )

    $pathValue = ''
    if ($null -ne $Settings -and $Settings.Contains('AI_CHAT_HEARTBEAT_PATH')) {
        $pathValue = Convert-ToSingleLineText -Text ([string]$Settings.AI_CHAT_HEARTBEAT_PATH)
    }

    if ([string]::IsNullOrWhiteSpace($pathValue)) {
        $pathValue = Resolve-PreferredDefaultPath -PreferredPath (Resolve-RepoPathAllowMissing -Path (Join-Path 'out\artifacts\ab_agent_queue' ("chat_session_heartbeat_{0}.json" -f $StartToken))) -LegacyPath (Resolve-RepoPathAllowMissing -Path (Join-Path 'out\artifacts\ab_agent_queue' ("chat_session_heartbeat_{0}.json" -f $LegacyStartToken)))
    }

    return Resolve-RepoPathAllowMissing -Path $pathValue
}

function Get-ChatHeartbeatState {
    param(
        [string]$Path,
        [datetime]$NowUtc,
        [int]$TtlMinutes,
        [int]$MissingGraceMinutes,
        [datetime]$ScriptStartUtc
    )

    $pathRel = Convert-ToRepoRelativePath -Path $Path
    $base = [ordered]@{
        path = $pathRel
        exists = $false
        updated_at = ''
        age_seconds = -1
        stale = $false
        reason = 'disabled'
    }

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return [pscustomobject]$base
    }

    if (-not (Test-Path -LiteralPath $Path)) {
        $uptimeMinutes = [Math]::Floor(([timespan]($NowUtc - $ScriptStartUtc)).TotalMinutes)
        if ($uptimeMinutes -lt $MissingGraceMinutes) {
            $base.reason = 'missing-grace'
            return [pscustomobject]$base
        }

        $base.stale = $true
        $base.reason = 'missing'
        return [pscustomobject]$base
    }

    $base.exists = $true
    $raw = Read-JsonFileSafely -Path $Path
    if ($null -eq $raw) {
        $base.stale = $true
        $base.reason = 'invalid-json'
        return [pscustomobject]$base
    }

    $updatedAt = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $raw -Name 'updated_at')
    $base.updated_at = $updatedAt
    if ([string]::IsNullOrWhiteSpace($updatedAt)) {
        $base.stale = $true
        $base.reason = 'missing-updated-at'
        return [pscustomobject]$base
    }

    $updatedUtc = Get-DateTimeOrNull -Text $updatedAt
    if ($null -eq $updatedUtc) {
        $base.stale = $true
        $base.reason = 'invalid-updated-at'
        return [pscustomobject]$base
    }

    $ageSeconds = [int][Math]::Floor(([timespan]($NowUtc - $updatedUtc)).TotalSeconds)
    if ($ageSeconds -lt 0) {
        $ageSeconds = 0
    }

    $base.age_seconds = $ageSeconds
    $ttlSeconds = [int]([Math]::Max(1, $TtlMinutes) * 60)
    if ($ageSeconds -gt $ttlSeconds) {
        $base.stale = $true
        $base.reason = 'heartbeat-timeout'
    }
    else {
        $base.stale = $false
        $base.reason = 'fresh'
    }

    return [pscustomobject]$base
}

function Test-SessionWatchExpected {
    param([System.Collections.IDictionary]$Settings)

    $sessionStatus = 'NOT_RUN'
    if ($null -ne $Settings -and $Settings.Contains('SESSION_FINAL_STATUS')) {
        $sessionStatus = Get-StatusValue -Value ([string]$Settings.SESSION_FINAL_STATUS)
    }

    $aStatus = 'NOT_RUN'
    if ($null -ne $Settings -and $Settings.Contains('A_FINAL_STATUS')) {
        $aStatus = Get-StatusValue -Value ([string]$Settings.A_FINAL_STATUS)
    }

    $bStatus = 'NOT_RUN'
    if ($null -ne $Settings -and $Settings.Contains('B_FINAL_STATUS')) {
        $bStatus = Get-StatusValue -Value ([string]$Settings.B_FINAL_STATUS)
    }

    $watchExpected = ($sessionStatus -eq 'RUNNING' -or $aStatus -eq 'RUNNING' -or $bStatus -eq 'RUNNING')
    return [pscustomobject]@{
        watch_expected = [bool]$watchExpected
        session_status = $sessionStatus
        a_status = $aStatus
        b_status = $bStatus
    }
}

function Get-SessionCloseGateState {
    param([System.Collections.IDictionary]$Settings)

    $sessionStatus = 'NOT_RUN'
    if ($null -ne $Settings -and $Settings.Contains('SESSION_FINAL_STATUS')) {
        $sessionStatus = Get-StatusValue -Value ([string]$Settings.SESSION_FINAL_STATUS)
    }

    $aStatus = 'NOT_RUN'
    if ($null -ne $Settings -and $Settings.Contains('A_FINAL_STATUS')) {
        $aStatus = Get-StatusValue -Value ([string]$Settings.A_FINAL_STATUS)
    }

    $bStatus = 'NOT_RUN'
    if ($null -ne $Settings -and $Settings.Contains('B_FINAL_STATUS')) {
        $bStatus = Get-StatusValue -Value ([string]$Settings.B_FINAL_STATUS)
    }

    $closedByFlagRaw = $false
    if ($null -ne $Settings -and $Settings.Contains('SESSION_CLOSED')) {
        $closedByFlagRaw = Convert-ToBooleanSetting -Value ([string]$Settings.SESSION_CLOSED) -Default $false
    }

    $closedByPassFinal = ($sessionStatus -eq 'PASS') -or ($aStatus -eq 'PASS' -and $bStatus -eq 'PASS')
    $closedByFlag = $closedByFlagRaw -and $closedByPassFinal
    $closed = $closedByFlag -or $closedByPassFinal

    $reason = 'none'
    if ($closedByFlag) {
        $reason = 'session-closed-flag'
    }
    elseif ($closedByPassFinal) {
        $reason = 'pass-final-status'
    }

    return [pscustomobject]@{
        closed = [bool]$closed
        reason = $reason
        closed_by_flag = [bool]$closedByFlag
        closed_by_pass_final = [bool]$closedByPassFinal
        session_status = $sessionStatus
        a_status = $aStatus
        b_status = $bStatus
    }
}

function Resolve-BusinessResumePlan {
    param(
        [string]$StartFileRel,
        [AllowNull()][string]$SessionStatus,
        [AllowNull()][string]$AStatus,
        [AllowNull()][string]$BStatus,
        [AllowNull()][string]$PreferredStage = '',
        [bool]$DisableResume = $false
    )

    $normalizedSession = Get-StatusValue -Value $SessionStatus
    $normalizedA = Get-StatusValue -Value $AStatus
    $normalizedB = Get-StatusValue -Value $BStatus
    $stageHint = (Convert-ToSingleLineText -Text $PreferredStage).ToUpperInvariant()

    if ($DisableResume) {
        return [pscustomobject]@{
            command = ''
            stage = 'none'
            reason = 'resume-disabled'
            session_status = $normalizedSession
            a_status = $normalizedA
            b_status = $normalizedB
        }
    }

    $targetStage = 'A'
    $reason = 'default-a-resume'
    if ($stageHint -eq 'B') {
        $targetStage = 'B'
        $reason = 'ticket-hint-b'
    }
    elseif ($stageHint -eq 'A') {
        $targetStage = 'A'
        $reason = 'ticket-hint-a'
    }
    elseif ($normalizedA -eq 'PASS' -and $normalizedB -in @('FAIL', 'BLOCKED', 'NOT_RUN')) {
        $targetStage = 'B'
        $reason = 'a-pass-b-pending'
    }
    elseif ($normalizedA -in @('FAIL', 'BLOCKED', 'NOT_RUN')) {
        $targetStage = 'A'
        $reason = 'a-needs-recovery'
    }

    $command = 'powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/open_unattended_ab_stage_window.ps1 -Stage {0} -StartFile "{1}" -StartMonitors' -f $targetStage, $StartFileRel

    return [pscustomobject]@{
        command = $command
        stage = $targetStage
        reason = $reason
        session_status = $normalizedSession
        a_status = $normalizedA
        b_status = $normalizedB
    }
}

function Get-BPassFailConflictEvidence {
    param(
        [System.Collections.IDictionary]$Settings,
        [string]$StartFilePath
    )

    $artifactPath = Join-Path $script:RepoRoot 'out\artifacts\ab_stage_exit\latest_b_exit.json'
    $result = [ordered]@{
        conflict = $false
        reason = 'status-not-pass'
        artifact_path = (Convert-ToRepoRelativePath -Path $artifactPath)
        stage = ''
        exit_result = ''
        exit_code = -1
        process_id = 0
        process_id_match = $true
        start_file_match = $true
        generated_at = ''
        fresh = $false
        fail_category = ''
        fail_reason = ''
    }

    $sessionStatus = 'NOT_RUN'
    if ($null -ne $Settings -and $Settings.Contains('SESSION_FINAL_STATUS')) {
        $sessionStatus = Get-StatusValue -Value ([string]$Settings.SESSION_FINAL_STATUS)
    }
    $aStatus = 'NOT_RUN'
    if ($null -ne $Settings -and $Settings.Contains('A_FINAL_STATUS')) {
        $aStatus = Get-StatusValue -Value ([string]$Settings.A_FINAL_STATUS)
    }
    $bStatus = 'NOT_RUN'
    if ($null -ne $Settings -and $Settings.Contains('B_FINAL_STATUS')) {
        $bStatus = Get-StatusValue -Value ([string]$Settings.B_FINAL_STATUS)
    }

    if ($sessionStatus -ne 'PASS' -or $aStatus -ne 'PASS' -or $bStatus -ne 'PASS') {
        return [pscustomobject]$result
    }

    if (-not (Test-Path -LiteralPath $artifactPath)) {
        $result.reason = 'artifact-missing'
        return [pscustomobject]$result
    }

    $payload = Read-JsonFileSafely -Path $artifactPath
    if ($null -eq $payload) {
        $result.reason = 'artifact-parse-failed'
        return [pscustomobject]$result
    }

    $result.stage = (Convert-ToSingleLineText -Text ([string]$payload.stage)).ToUpperInvariant()
    if ([string]$result.stage -ne 'B') {
        $result.reason = 'stage-mismatch'
        return [pscustomobject]$result
    }

    $result.exit_result = (Convert-ToSingleLineText -Text ([string]$payload.result)).ToLowerInvariant()
    if ([string]$result.exit_result -ne 'fail') {
        $result.reason = 'result-not-fail'
        return [pscustomobject]$result
    }

    $exitCodeValue = -1
    if ([int]::TryParse(([string]$payload.exit_code), [ref]$exitCodeValue)) {
        $result.exit_code = [int]$exitCodeValue
    }

    $processIdValue = 0
    if ([int]::TryParse(([string]$payload.process_id), [ref]$processIdValue) -and $processIdValue -gt 0) {
        $result.process_id = [int]$processIdValue
    }

    $startFileArtifact = Convert-ToSingleLineText -Text ([string]$payload.start_file_path)
    if (-not [string]::IsNullOrWhiteSpace($startFileArtifact)) {
        try {
            $expectedStart = [System.IO.Path]::GetFullPath($StartFilePath)
            $artifactStart = [System.IO.Path]::GetFullPath($startFileArtifact)
            $result.start_file_match = $artifactStart.Equals($expectedStart, [System.StringComparison]::OrdinalIgnoreCase)
        }
        catch {
            $result.start_file_match = $false
        }
    }

    if (-not [bool]$result.start_file_match) {
        $result.reason = 'start-file-mismatch'
        return [pscustomobject]$result
    }

    $notes = ''
    if ($null -ne $Settings -and $Settings.Contains('SESSION_FINAL_NOTES')) {
        $notes = [string]$Settings.SESSION_FINAL_NOTES
    }

    $runDirAnchor = Get-LatestAnchorValueFromNoteLog -Notes $notes -Key 'b_run_dir'
    if ([string]::IsNullOrWhiteSpace($runDirAnchor)) {
        $runDirAnchor = Get-LatestAnchorValueFromNoteLog -Notes $notes -Key 'run_dir'
    }
    $runDirResolved = ''
    if (-not [string]::IsNullOrWhiteSpace($runDirAnchor)) {
        try {
            $runDirResolved = Resolve-RepoPath -Path $runDirAnchor
        }
        catch {
            $runDirResolved = ''
        }
    }

    $result.generated_at = Convert-ToSingleLineText -Text ([string]$payload.generated_at)
    $generatedUtc = Get-DateTimeOrNull -Text ([string]$result.generated_at)
    if ($null -eq $generatedUtc) {
        $result.reason = 'generated-at-invalid'
        return [pscustomobject]$result
    }

    if (-not [string]::IsNullOrWhiteSpace($runDirResolved) -and (Test-Path -LiteralPath $runDirResolved)) {
        $runCreatedUtc = (Get-Item -LiteralPath $runDirResolved).CreationTimeUtc
        $result.fresh = ([datetime]$generatedUtc -ge [datetime]$runCreatedUtc.AddMinutes(-2))
    }
    else {
        $ageMinutes = ((Get-Date).ToUniversalTime() - [datetime]$generatedUtc).TotalMinutes
        $result.fresh = ($ageMinutes -ge 0 -and $ageMinutes -le 240)
    }

    if (-not [bool]$result.fresh) {
        $result.reason = 'artifact-not-fresh'
        return [pscustomobject]$result
    }

    $result.fail_category = Convert-ToSingleLineText -Text ([string]$payload.fail_category)
    $result.fail_reason = Convert-ToSingleLineText -Text ([string]$payload.fail_reason)
    $result.conflict = $true
    $result.reason = 'conflict-detected'
    return [pscustomobject]$result
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

function Get-StartFileWriteMutexName {
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

function Set-KeyValueFileValue {
    param(
        [string]$Path,
        [hashtable]$Values
    )

    if ([string]::IsNullOrWhiteSpace($Path) -or $null -eq $Values -or $Values.Count -lt 1) {
        return $false
    }

    $mutex = New-Object System.Threading.Mutex($false, (Get-StartFileWriteMutexName -StartFilePath $Path))
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
        Write-Utf8BomFile -Path $tempPath -Value @($buffer)
        Move-Item -LiteralPath $tempPath -Destination $Path -Force
        $tempPath = ''
        return $true
    }
    finally {
        if (-not [string]::IsNullOrWhiteSpace($tempPath) -and (Test-Path -LiteralPath $tempPath)) {
            Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue
        }

        if ($locked) {
            try { $mutex.ReleaseMutex() } catch { $null = $_ }
        }
        $mutex.Dispose()
    }
}

function Get-LatestAnchorValueFromNoteLog {
    param(
        [AllowNull()][string]$Notes,
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

function Get-SafeToken {
    param([string]$Text)

    $normalized = Convert-ToSingleLineText -Text $Text
    if ([string]::IsNullOrWhiteSpace($normalized)) {
        return 'default'
    }

    return ([regex]::Replace($normalized, '[^A-Za-z0-9._-]', '_')).Trim('_')
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
        if ($null -ne $sha1) {
            $sha1.Dispose()
        }
    }

    return ('sf_{0}' -f $hash)
}

function Get-LegacyStartFileToken {
    param([string]$StartFilePath)

    return Get-SafeToken -Text ([System.IO.Path]::GetFileNameWithoutExtension($StartFilePath).ToLowerInvariant())
}

function Resolve-PreferredDefaultPath {
    param(
        [string]$PreferredPath,
        [string]$LegacyPath
    )

    if (-not [string]::IsNullOrWhiteSpace($LegacyPath) -and -not (Test-Path -LiteralPath $PreferredPath) -and (Test-Path -LiteralPath $LegacyPath)) {
        return $LegacyPath
    }

    return $PreferredPath
}

function Write-TriggerLog {
    param([string]$Message)

    $line = "[AB-TAKEOVER-TRIGGER] timestamp={0} {1}" -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'), (Convert-ToSingleLineText -Text $Message)
    Write-Output $line
    $maxAttempts = 5
    $written = $false
        for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        $stream = $null
        $writer = $null
        try {
            $stream = New-Object System.IO.FileStream($script:TriggerLogPath, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite)
            $writer = New-Object System.IO.StreamWriter($stream, [System.Text.Encoding]::UTF8)
            $writer.WriteLine($line)
            $writer.Flush()
            $written = $true
            break
        }
        catch {
            if ($attempt -lt $maxAttempts) {
                Start-Sleep -Milliseconds (120 * $attempt)
            }
        }
        finally {
            if ($null -ne $writer) {
                $writer.Dispose()
            }
            if ($null -ne $stream) {
                $stream.Dispose()
            }
        }
    }

    if ($written) {
        if ($script:TriggerLogWriteFailureKey -eq $script:TriggerLogPath) {
            $script:TriggerLogWriteFailureKey = ''
            $script:TriggerLogWriteFailureLastAt = [datetime]::MinValue
        }
        return
    }

    $now = Get-Date
    $shouldWarn = $false
    if ($script:TriggerLogWriteFailureKey -ne $script:TriggerLogPath) {
        $shouldWarn = $true
    }
    elseif (($now - $script:TriggerLogWriteFailureLastAt).TotalSeconds -ge 60) {
        $shouldWarn = $true
    }

    if ($shouldWarn) {
        $script:TriggerLogWriteFailureKey = $script:TriggerLogPath
        $script:TriggerLogWriteFailureLastAt = $now
        Write-Warning ("[AB-TAKEOVER-TRIGGER] log_write_failed path={0}" -f $script:TriggerLogPath)
    }
}

function Read-JsonFileSafely {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) {
        return $null
    }

    try {
        $raw = Get-Content -LiteralPath $Path -Raw -Encoding utf8 -ErrorAction Stop
        return ($raw | ConvertFrom-Json -ErrorAction Stop)
    }
    catch {
        return $null
    }
}

function Get-FinalStopGateMode {
    param(
        [System.Collections.IDictionary]$Settings,
        [string]$Default = 'trigger-started'
    )

    if ($null -eq $Settings) {
        return $Default
    }

    $raw = ''
    if ($Settings.Contains('AI_CHAT_POLICY_FINAL_STOP_GATE')) {
        $raw = [string]$Settings.AI_CHAT_POLICY_FINAL_STOP_GATE
    }
    elseif ($Settings.Contains('AI_CHAT_TRIGGER_FINAL_STOP_GATE')) {
        $raw = [string]$Settings.AI_CHAT_TRIGGER_FINAL_STOP_GATE
    }

    $token = (Convert-ToSingleLineText -Text $raw).ToLowerInvariant()
    if ($token -in @('sender-sent', 'sender_sent')) {
        return 'sender-sent'
    }

    if ($token -in @('trigger-started', 'trigger_started')) {
        return 'trigger-started'
    }

    return $Default
}

function Get-LatestDispatchRelayState {
    param(
        [string]$QueueRoot,
        [string]$StartFileToken,
        [string]$LegacyStartFileToken
    )

    $statePath = Resolve-PreferredDefaultPath -PreferredPath (Join-Path $QueueRoot ("chat_dispatch\latest_relay_{0}.json" -f $StartFileToken)) -LegacyPath (Join-Path $QueueRoot ("chat_dispatch\latest_relay_{0}.json" -f $LegacyStartFileToken))
    $state = Read-JsonFileSafely -Path $statePath
    if ($null -eq $state) {
        return [pscustomobject]@{
            loaded = $false
            path = $statePath
            ticket_id = ''
            event = ''
            sender_sent = $false
            sender_mode = ''
            sender_reason = ''
            updated_at = ''
            updated_at_utc = $null
        }
    }

    $eventName = if ($state.PSObject.Properties['event']) { Convert-ToSingleLineText -Text ([string]$state.event) } else { '' }
    $ticketId = if ($state.PSObject.Properties['ticket_id']) { Convert-ToSingleLineText -Text ([string]$state.ticket_id) } else { '' }
    $senderSent = $false
    if ($state.PSObject.Properties['sender_sent']) {
        $senderSent = [bool]$state.sender_sent
    }
    $senderMode = if ($state.PSObject.Properties['sender_mode']) { Convert-ToSingleLineText -Text ([string]$state.sender_mode) } else { '' }
    $senderReason = if ($state.PSObject.Properties['sender_reason']) { Convert-ToSingleLineText -Text ([string]$state.sender_reason) } else { '' }
    $updatedAt = if ($state.PSObject.Properties['updated_at']) { Convert-ToSingleLineText -Text ([string]$state.updated_at) } else { '' }
    $updatedAtUtc = Get-DateTimeOrNull -Text $updatedAt

    return [pscustomobject]@{
        loaded = $true
        path = $statePath
        ticket_id = $ticketId
        event = $eventName
        sender_sent = $senderSent
        sender_mode = $senderMode
        sender_reason = $senderReason
        updated_at = $updatedAt
        updated_at_utc = $updatedAtUtc
    }
}

function Test-FinalDispatchSenderSent {
    param(
        [string]$QueueRoot,
        [string]$StartFileToken,
        [string]$LegacyStartFileToken,
        [AllowNull()][string]$ExpectedTicketId,
        [datetime]$SessionStartUtc
    )

    $state = Get-LatestDispatchRelayState -QueueRoot $QueueRoot -StartFileToken $StartFileToken -LegacyStartFileToken $LegacyStartFileToken
    if (-not [bool]$state.loaded) {
        return [pscustomobject]@{
            confirmed = $false
            reason = 'state-missing'
            state = $state
        }
    }

    $eventToken = (Convert-ToSingleLineText -Text ([string]$state.event)).ToLowerInvariant()
    if ($eventToken -ne 'chat-session-final-status') {
        return [pscustomobject]@{
            confirmed = $false
            reason = 'state-event-mismatch'
            state = $state
        }
    }

    $expected = Convert-ToSingleLineText -Text $ExpectedTicketId
    if (-not [string]::IsNullOrWhiteSpace($expected) -and -not [string]::Equals([string]$state.ticket_id, $expected, [System.StringComparison]::OrdinalIgnoreCase)) {
        return [pscustomobject]@{
            confirmed = $false
            reason = 'state-ticket-mismatch'
            state = $state
        }
    }

    if ([string]::IsNullOrWhiteSpace($expected)) {
        if ($null -eq $state.updated_at_utc) {
            return [pscustomobject]@{
                confirmed = $false
                reason = 'state-updated-at-missing'
                state = $state
            }
        }

        if ($state.updated_at_utc -lt $SessionStartUtc) {
            return [pscustomobject]@{
                confirmed = $false
                reason = 'state-stale-before-session-start'
                state = $state
            }
        }
    }

    if (-not [bool]$state.sender_sent) {
        return [pscustomobject]@{
            confirmed = $false
            reason = 'sender-not-sent'
            state = $state
        }
    }

    return [pscustomobject]@{
        confirmed = $true
        reason = 'ok'
        state = $state
    }
}

function Test-IsRetryableStateWriteError {
    param([System.Exception]$Exception)

    if ($null -eq $Exception) {
        return $false
    }

    if ($Exception -is [System.IO.IOException]) {
        return $true
    }

    $message = Convert-ToSingleLineText -Text $Exception.Message
    if ([string]::IsNullOrWhiteSpace($message)) {
        return $false
    }

    return ($message -match '(?i)(another process|being used by another process|cannot access the file|sharing violation|access.*denied|另一个进程|正在使用|无法访问此文件|访问被拒绝)')
}

function Write-JsonFileSafely {
    param(
        [string]$Path,
        $Value
    )

    $parent = Split-Path -Parent $Path
    if (-not [string]::IsNullOrWhiteSpace($parent) -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }

    $json = $Value | ConvertTo-Json -Depth 10
    $maxAttempts = 4
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        try {
            Write-Utf8BomFile -Path $Path -Value $json
            return $true
        }
        catch {
            $isRetryable = Test-IsRetryableStateWriteError -Exception $_.Exception
            if (-not $isRetryable) {
                throw
            }

            if ($attempt -lt $maxAttempts) {
                Start-Sleep -Milliseconds (75 * $attempt)
                continue
            }

            return $false
        }
    }

    return $false
}

function Test-LogTailContainsFragment {
    param(
        [AllowNull()][string]$Path,
        [AllowNull()][string]$Fragment,
        [ValidateRange(20, 5000)][int]$TailLines = 1200
    )

    if ([string]::IsNullOrWhiteSpace($Path) -or [string]::IsNullOrWhiteSpace($Fragment)) {
        return $false
    }

    if (-not (Test-Path -LiteralPath $Path)) {
        return $false
    }

    try {
        foreach ($line in @(Get-Content -LiteralPath $Path -Tail $TailLines -Encoding utf8 -ErrorAction SilentlyContinue)) {
            if (-not [string]::IsNullOrWhiteSpace($line) -and $line.Contains($Fragment)) {
                return $true
            }
        }
    }
    catch {
        return $false
    }

    return $false
}

function Get-TicketsFromQueue {
    param(
        [string]$Path,
        [ValidateRange(0, [int]::MaxValue)][int]$AfterLineNo = 0
    )

    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) {
        return @()
    }

    $tickets = New-Object 'System.Collections.Generic.List[object]'
    $lineNo = 0
    foreach ($line in @(Get-Content -LiteralPath $Path -Encoding utf8 -ErrorAction SilentlyContinue)) {
        $lineNo++
        if ($lineNo -le $AfterLineNo) {
            continue
        }

        $jsonLine = Convert-ToSingleLineText -Text ([string]$line)
        if ([string]::IsNullOrWhiteSpace($jsonLine)) {
            continue
        }

        try {
            $ticket = $jsonLine | ConvertFrom-Json -ErrorAction Stop
            try {
                Add-Member -InputObject $ticket -NotePropertyName '__queue_line_no' -NotePropertyValue $lineNo -Force
            }
            catch {
                # Keep queue parsing resilient even if metadata annotation fails.
                $null = $_
            }
            [void]$tickets.Add($ticket)
        }
        catch {
            Write-TriggerLog ("queue_parse_skip line={0} detail={1}" -f $lineNo, (Convert-ToSingleLineText -Text $_.Exception.Message))
        }
    }

    return $tickets.ToArray()
}

function Get-QueueLineCount {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) {
        return 0
    }

    $lineCount = 0
    foreach ($line in @(Get-Content -LiteralPath $Path -Encoding utf8 -ErrorAction SilentlyContinue)) {
        $lineCount++
    }

    return $lineCount
}

function Add-TicketToQueue {
    param(
        [object]$Ticket,
        [string]$QueueFilePath
    )

    $targetPath = Resolve-RepoPathAllowMissing -Path $QueueFilePath
    if ([string]::IsNullOrWhiteSpace($targetPath)) {
        return [pscustomobject]@{
            Success = $false
            Reason = 'queue-path-empty'
            Path = ''
        }
    }

    $parent = Split-Path -Parent $targetPath
    if (-not [string]::IsNullOrWhiteSpace($parent) -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }

    try {
        $line = $Ticket | ConvertTo-Json -Compress -Depth 8
        Add-Utf8Line -Path $targetPath -Line $line
        return [pscustomobject]@{
            Success = $true
            Reason = 'queued'
            Path = $targetPath
        }
    }
    catch {
        return [pscustomobject]@{
            Success = $false
            Reason = (Convert-ToSingleLineText -Text $_.Exception.Message)
            Path = $targetPath
        }
    }
}

function Wait-QueueSignalOrTimeout {
    param(
        [AllowNull()][string]$QueueFilePath,
        [ValidateRange(1, 600)][int]$TimeoutSec,
        [bool]$EnableEventDriven = $true
    )

    if ($TimeoutSec -le 0) {
        return 'immediate'
    }

    if (-not $EnableEventDriven) {
        Start-Sleep -Seconds $TimeoutSec
        return 'timer'
    }

    $path = Resolve-RepoPathAllowMissing -Path $QueueFilePath
    if ([string]::IsNullOrWhiteSpace($path)) {
        Start-Sleep -Seconds $TimeoutSec
        return 'timer'
    }

    $parent = Split-Path -Parent $path
    $leaf = Split-Path -Leaf $path
    if ([string]::IsNullOrWhiteSpace($parent) -or [string]::IsNullOrWhiteSpace($leaf) -or -not (Test-Path -LiteralPath $parent)) {
        Start-Sleep -Seconds $TimeoutSec
        return 'timer'
    }

    $watcher = $null
    try {
        $watcher = New-Object System.IO.FileSystemWatcher
        $watcher.Path = $parent
        $watcher.Filter = $leaf
        $watcher.NotifyFilter = [System.IO.NotifyFilters]'FileName,LastWrite,Size,CreationTime'
        $watcher.IncludeSubdirectories = $false
        $watcher.EnableRaisingEvents = $true

        $timeoutMs = [int]([Math]::Min([int]::MaxValue, $TimeoutSec * 1000))
        $change = $watcher.WaitForChanged([System.IO.WatcherChangeTypes]::All, $timeoutMs)
        if ($change.TimedOut) {
            return 'timer'
        }

        $changeType = (Convert-ToSingleLineText -Text ([string]$change.ChangeType)).ToLowerInvariant()
        if ([string]::IsNullOrWhiteSpace($changeType)) {
            return 'event'
        }

        return ('event-{0}' -f $changeType)
    }
    catch {
        Start-Sleep -Seconds $TimeoutSec
        return 'timer'
    }
    finally {
        if ($null -ne $watcher) {
            $watcher.Dispose()
        }
    }
}

function Resolve-ExternalTriggerExecutionPlan {
    param(
        [string]$Template,
        [string]$TicketId,
        [string]$EventName,
        [string]$StartFilePath,
        [string]$QueueFilePath,
        [string]$BriefPath
    )

    if ([string]::IsNullOrWhiteSpace($Template)) {
        return [pscustomobject]@{
            Valid = $false
            Reason = 'command-empty'
            FilePath = ''
            ArgumentList = @()
            Summary = ''
        }
    }

    $normalized = Convert-ToSingleLineText -Text $Template
    $dispatchPattern = '^(?i)powershell(?:\.exe)?\b.*\s-File\s+(["'']?)tools[\\/]test[\\/]dispatch_takeover_to_chat\.ps1\1(?:\s|$)'
    if ($normalized -notmatch $dispatchPattern) {
        return [pscustomobject]@{
            Valid = $false
            Reason = 'unsupported-command-template'
            FilePath = ''
            ArgumentList = @()
            Summary = $normalized
        }
    }

    if ($normalized -match '[`;&|<>]') {
        return [pscustomobject]@{
            Valid = $false
            Reason = 'unsafe-command-template'
            FilePath = ''
            ArgumentList = @()
            Summary = $normalized
        }
    }

    $dispatchScript = Join-Path $script:RepoRoot 'tools\test\dispatch_takeover_to_chat.ps1'
    if (-not (Test-Path -LiteralPath $dispatchScript)) {
        return [pscustomobject]@{
            Valid = $false
            Reason = 'dispatch-script-missing'
            FilePath = ''
            ArgumentList = @()
            Summary = $dispatchScript
        }
    }

    $powershellPath = Join-Path $PSHOME 'powershell.exe'
    if (-not (Test-Path -LiteralPath $powershellPath)) {
        $powershellPath = 'powershell.exe'
    }

    $argumentList = @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', $dispatchScript,
        '-TicketId', $TicketId,
        '-TicketEvent', $EventName,
        '-StartFile', $StartFilePath,
        '-QueuePath', $QueueFilePath,
        '-BriefPath', $BriefPath
    )

    if ($normalized -imatch '(?:^|\s)-NoOpenEditor(?:\s|$)') {
        $argumentList += '-NoOpenEditor'
    }
    if ($normalized -imatch '(?:^|\s)-SkipClipboard(?:\s|$)') {
        $argumentList += '-SkipClipboard'
    }

    return [pscustomobject]@{
        Valid = $true
        Reason = 'ready'
        FilePath = $powershellPath
        ArgumentList = $argumentList
        Summary = $normalized
    }
}

function Invoke-ExternalTriggerCommand {
    param([pscustomobject]$Plan)

    if ($null -eq $Plan -or -not [bool]$Plan.Valid) {
        return [pscustomobject]@{
            Started = $false
            ProcessId = 0
            Reason = if ($null -eq $Plan) { 'plan-empty' } else { [string]$Plan.Reason }
        }
    }

    try {
        $process = Start-Process -FilePath ([string]$Plan.FilePath) -ArgumentList @($Plan.ArgumentList) -WindowStyle Hidden -PassThru
        return [pscustomobject]@{
            Started = $true
            ProcessId = [int]$process.Id
            Reason = 'started'
        }
    }
    catch {
        return [pscustomobject]@{
            Started = $false
            ProcessId = 0
            Reason = (Convert-ToSingleLineText -Text $_.Exception.Message)
        }
    }
}

function Test-ProcessAliveById {
    param([int]$ProcessId)

    if ($ProcessId -le 0) {
        return $false
    }

    try {
        $process = Get-Process -Id $ProcessId -ErrorAction Stop
        if ($null -eq $process) {
            return $false
        }

        return (-not $process.HasExited)
    }
    catch {
        return $false
    }
}

function Invoke-ExternalTriggerCommandWithLivenessGuard {
    param(
        [pscustomobject]$Plan,
        [int]$MaxAttempts = 2,
        [int]$LivenessWaitMs = 1200
    )

    $attemptLimit = [Math]::Max(1, $MaxAttempts)
    $waitMs = [Math]::Max(0, $LivenessWaitMs)
    $lastReason = ''
    $lastProcessId = 0

    for ($attempt = 1; $attempt -le $attemptLimit; $attempt++) {
        $result = Invoke-ExternalTriggerCommand -Plan $Plan
        if (-not [bool]$result.Started) {
            $lastReason = [string]$result.Reason
            continue
        }

        $startedPid = [int]$result.ProcessId
        $lastProcessId = $startedPid
        if ($waitMs -gt 0) {
            Start-Sleep -Milliseconds $waitMs
        }

        if (Test-ProcessAliveById -ProcessId $startedPid) {
            return [pscustomobject]@{
                Started = $true
                ProcessId = $startedPid
                Reason = 'started-and-alive'
                Attempts = [int]$attempt
                LastProcessId = $startedPid
            }
        }

        $lastReason = 'started-exited-early'
    }

    return [pscustomobject]@{
        Started = $false
        ProcessId = 0
        Reason = $lastReason
        Attempts = [int]$attemptLimit
        LastProcessId = [int]$lastProcessId
    }
}

function Invoke-RouteGuardForBrief {
    param(
        [AllowNull()][string]$BriefPath,
        [AllowNull()][string]$QueueFilePath
    )

    $result = [ordered]@{
        Allowed = $false
        Reason = ''
        RouteGuardCommand = ''
        RouteGuardExpected = ''
        RouteGuardExpectedSource = 'fallback'
        Classification = ''
        RecommendedAction = ''
        AllowedActions = @()
        BlockedActions = @()
        DecisionConfidence = 0.0
        DecisionFactors = @()
        Output = ''
        Error = ''
    }

    $briefPathResolved = Resolve-RepoPathAllowMissing -Path $BriefPath
    if ([string]::IsNullOrWhiteSpace($briefPathResolved) -or -not (Test-Path -LiteralPath $briefPathResolved)) {
        $result.Reason = 'route-guard-brief-missing'
        return [pscustomobject]$result
    }

    $briefSettings = $null
    try {
        $briefSettings = Read-KeyValueFile -Path $briefPathResolved
    }
    catch {
        $result.Reason = 'route-guard-brief-read-failed'
        $result.Error = Convert-ToSingleLineText -Text $_.Exception.Message
        return [pscustomobject]$result
    }

    $routeGuardCommand = ''
    $routeGuardExpected = ''
    if ($null -ne $briefSettings) {
        if ($briefSettings.Contains('route_guard_command')) {
            $routeGuardCommand = Convert-ToSingleLineText -Text ([string]$briefSettings.route_guard_command)
        }
        if ($briefSettings.Contains('route_guard_expected')) {
            $routeGuardExpected = (Convert-ToSingleLineText -Text ([string]$briefSettings.route_guard_expected)).ToLowerInvariant()
            if (-not [string]::IsNullOrWhiteSpace($routeGuardExpected)) {
                $result.RouteGuardExpectedSource = 'brief'
            }
        }
    }

    if ([string]::IsNullOrWhiteSpace($routeGuardCommand)) {
        $briefRel = Convert-ToRepoRelativePath -Path $briefPathResolved
        $queueRel = Convert-ToRepoRelativePath -Path $QueueFilePath
        $routeGuardCommand = 'powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/check_takeover_route_guard.ps1 -BriefPath "{0}" -QueuePath "{1}" -AsJson' -f $briefRel, $queueRel
    }

    $result.RouteGuardCommand = $routeGuardCommand
    $result.RouteGuardExpected = $routeGuardExpected

    if ([string]::IsNullOrWhiteSpace($routeGuardCommand)) {
        $result.Reason = 'route-guard-command-empty'
        return [pscustomobject]$result
    }

    try {
        $routeOutput = & powershell -NoProfile -ExecutionPolicy Bypass -Command $routeGuardCommand 2>&1
        $exitCode = if ($null -eq $LASTEXITCODE) { 0 } else { [int]$LASTEXITCODE }
        $result.Output = Convert-ToSingleLineText -Text (($routeOutput | Out-String).Trim())
        if ($exitCode -ne 0) {
            $result.Reason = ('route-guard-exit-code-{0}' -f $exitCode)
            return [pscustomobject]$result
        }

        $payload = (($routeOutput | Out-String) | ConvertFrom-Json -ErrorAction Stop)
        if ($null -eq $payload) {
            $result.Reason = 'route-guard-empty-payload'
            return [pscustomobject]$result
        }

        $route = $payload.route
        if ($null -eq $route) {
            $result.Reason = 'route-guard-missing-route'
            return [pscustomobject]$result
        }

        $classification = (Convert-ToSingleLineText -Text ([string]$route.classification)).ToLowerInvariant()
        $recommendedAction = Convert-ToSingleLineText -Text ([string]$route.recommended_action)
        $allowedActions = @($route.allowed_actions | ForEach-Object { Convert-ToSingleLineText -Text ([string]$_) } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        $blockedActions = @($route.blocked_actions | ForEach-Object { Convert-ToSingleLineText -Text ([string]$_) } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })

        $result.Classification = $classification
        $result.RecommendedAction = $recommendedAction
        $result.AllowedActions = @($allowedActions)
        $result.BlockedActions = @($blockedActions)

        $decisionConfidence = 0.0
        if ($route.PSObject.Properties.Name -contains 'decision_confidence') {
            $parsedDecisionConfidence = 0.0
            if ([double]::TryParse(([string]$route.decision_confidence), [ref]$parsedDecisionConfidence)) {
                $decisionConfidence = $parsedDecisionConfidence
            }
        }
        $result.DecisionConfidence = [double]$decisionConfidence

        if ($route.PSObject.Properties.Name -contains 'decision_factors') {
            $result.DecisionFactors = @($route.decision_factors | ForEach-Object { Convert-ToSingleLineText -Text ([string]$_) } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        }

        if ([string]::IsNullOrWhiteSpace($classification)) {
            $result.Reason = 'route-guard-classification-empty'
            return [pscustomobject]$result
        }

        if (-not [string]::IsNullOrWhiteSpace($routeGuardExpected) -and $classification -ne $routeGuardExpected) {
            $result.Reason = ('route-guard-classification-mismatch expected={0} source={1} actual={2}' -f $routeGuardExpected, [string]$result.RouteGuardExpectedSource, $classification)
            return [pscustomobject]$result
        }

        $result.Allowed = $true
        $result.Reason = 'route-guard-allowed'
        return [pscustomobject]$result
    }
    catch {
        $result.Reason = 'route-guard-exec-failed'
        $result.Error = Convert-ToSingleLineText -Text $_.Exception.Message
        return [pscustomobject]$result
    }
}

function Get-CauseBucket {
    param(
        [AllowNull()][string]$FailureKind,
        [AllowNull()][string]$FailureCategory,
        [AllowNull()][string]$EventName
    )

    $kind = (Convert-ToSingleLineText -Text $FailureKind).ToLowerInvariant()
    $category = (Convert-ToSingleLineText -Text $FailureCategory).ToLowerInvariant()
    $eventNameNormalized = (Convert-ToSingleLineText -Text $EventName).ToLowerInvariant()

    if ($eventNameNormalized -eq 'running-status-report') {
        return 'status'
    }

    if ($category -in @('script-fault')) {
        return 'script'
    }

    if ($category -in @('code-or-unknown') -or $kind -in @('compile-failure', 'compile-warning', 'verify-failure', 'task-definition-mismatch', 'code-edit-failure')) {
        return 'code'
    }

    if ($category -in @('monitor-chain', 'environment', 'infra-transient', 'noncode-transient')) {
        return 'infra'
    }

    if ($eventNameNormalized -in @('manual-wait-paused', 'budget-exhausted-stop', 'known-infra-transient-stop')) {
        return 'notice'
    }

    if ($eventNameNormalized -in @('incident-captured', 'recovery-await-confirmation', 'auto-fix-await-confirmation', 'task-definition-fix-required', 'main-process-exit-review')) {
        return 'incident'
    }

    return 'unknown'
}

function Get-FailureFingerprint {
    param(
        [AllowNull()][string]$FailureKind,
        [AllowNull()][string]$FailureCategory,
        [AllowNull()][string]$FailureSource,
        [AllowNull()][string]$FailureEvidence,
        [AllowNull()][string]$EventName
    )

    function Convert-FailureFingerprintText {
        param([AllowNull()][string]$Text)

        $normalized = Convert-ToSingleLineText -Text $Text
        if ([string]::IsNullOrWhiteSpace($normalized)) {
            return ''
        }

        $normalized = $normalized.ToLowerInvariant()
        $normalized = [regex]::Replace($normalized, '(?i)(^|[\s(])((?:[a-z]:[\\/])?[A-Za-z0-9._-]+(?:[\\/][A-Za-z0-9._-]+)*\.(?:c|h|cc|cpp|cxx|cs|ps1|psm1|psd1|py|json|xml|yml|yaml|md|txt)):\d+(?::\d+)?\s*:?\s*', '$1<source-location> ')
        $normalized = [regex]::Replace($normalized, '(?i)\bline\s+\d+\b', 'line <n>')
        $normalized = [regex]::Replace($normalized, '(?i)\bcolumn\s+\d+\b', 'column <n>')
        $normalized = [regex]::Replace($normalized, '(?i)\bconflicting\s+types\s+for\s+[^\s,;:]+', 'conflicting types')
        $normalized = [regex]::Replace($normalized, '(?i)\bundefined\s+reference\s+to\s+[^\s,;:]+', 'undefined reference')
        $normalized = [regex]::Replace($normalized, '(?i)\bno\s+such\s+file\s+or\s+directory\b', 'missing file')
        $normalized = [regex]::Replace($normalized, '(?i)\berror\s+c\d+\b', 'error c<num>')
        $normalized = [regex]::Replace($normalized, '\s+', ' ')
        return $normalized.Trim()
    }

    $joined = '{0}|{1}|{2}|{3}|{4}' -f 
        (Convert-FailureFingerprintText -Text $FailureKind),
        (Convert-FailureFingerprintText -Text $FailureCategory),
        (Convert-FailureFingerprintText -Text $FailureSource),
        (Convert-FailureFingerprintText -Text $FailureEvidence),
        (Convert-FailureFingerprintText -Text $EventName)

    $sha1 = [System.Security.Cryptography.SHA1]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($joined)
        $hashBytes = $sha1.ComputeHash($bytes)
        $hash = ([System.BitConverter]::ToString($hashBytes)).Replace('-', '').ToLowerInvariant()
        return ('fp_{0}' -f $hash)
    }
    finally {
        if ($null -ne $sha1) {
            $sha1.Dispose()
        }
    }
}

function New-TakeoverBrief {
    param(
        [object]$Ticket,
        [System.Collections.IDictionary]$Settings,
        [string]$OutputRoot,
        [string]$QueueFilePath,
        [string]$StartFilePath
    )

    if (-not (Test-Path -LiteralPath $OutputRoot)) {
        New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null
    }

    $ticketId = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $Ticket -Name 'ticket_id')
    $eventName = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $Ticket -Name 'event')
    $eventNameNormalized = $eventName.ToLowerInvariant()
    $fileName = ('takeover_{0}_{1}.md' -f (Get-SafeToken -Text $ticketId), (Get-Date).ToString('yyyyMMdd-HHmmss'))
    $briefPath = Join-Path $OutputRoot $fileName
    $briefRel = Convert-ToRepoRelativePath -Path $briefPath
    $queueRel = Convert-ToRepoRelativePath -Path $QueueFilePath

    $sessionCloseGate = Get-SessionCloseGateState -Settings $Settings
    $suppressResumeInBrief = [bool]$sessionCloseGate.closed -or $eventNameNormalized -eq 'running-status-report' -or $eventNameNormalized -eq 'chat-session-final-status' -or $eventNameNormalized -eq 'task-definition-fix-required'
    $startFileRel = (Convert-ToRepoRelativePath -Path $StartFilePath)
    $ticketSessionStatus = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $Ticket -Name 'session_final_status')
    if ([string]::IsNullOrWhiteSpace($ticketSessionStatus)) {
        $ticketSessionStatus = [string]$sessionCloseGate.session_status
    }
    $ticketAStatus = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $Ticket -Name 'a_final_status')
    if ([string]::IsNullOrWhiteSpace($ticketAStatus)) {
        $ticketAStatus = [string]$sessionCloseGate.a_status
    }
    $ticketBStatus = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $Ticket -Name 'b_final_status')
    if ([string]::IsNullOrWhiteSpace($ticketBStatus)) {
        $ticketBStatus = [string]$sessionCloseGate.b_status
    }
    $ticketPreferredStage = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $Ticket -Name 'preferred_stage')

    $resumePlan = Resolve-BusinessResumePlan -StartFileRel $startFileRel -SessionStatus $ticketSessionStatus -AStatus $ticketAStatus -BStatus $ticketBStatus -PreferredStage $ticketPreferredStage -DisableResume:$suppressResumeInBrief
    $resumeCommand = [string]$resumePlan.command
    $guardCommand = 'powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/open_unattended_ab_session_guard_window.ps1 -StartFile "{0}" -NoRestartIfRunning' -f (Convert-ToRepoRelativePath -Path $StartFilePath)
    $routeGuardCommand = 'powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/check_takeover_route_guard.ps1 -BriefPath "{0}" -QueuePath "{1}" -AsJson' -f $briefRel, $queueRel
    $launchReadyCommand = 'powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/check_unattended_ab_launch_ready.ps1 -StartFile "{0}"' -f $startFileRel
    $ticketClosureCheckCommand = 'powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/check_unattended_ticket_closure.ps1 -StartFile "{0}" -AsJson' -f $startFileRel
    $eventDedupHealthCheckCommand = 'powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/check_unattended_event_dedup_health.ps1 -StartFile "{0}" -AsJson' -f $startFileRel
    $finalStatusCloseoutCommand = 'powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/check_unattended_final_status_closeout.ps1 -StartFile "{0}" -AsJson' -f $startFileRel
    $finalStatusCloseoutApplyAckCommand = 'powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/check_unattended_final_status_closeout.ps1 -StartFile "{0}" -ApplyAcknowledge -AsJson' -f $startFileRel

    $incidentLikeEvents = @{
        'incident-captured' = $true
        'recovery-await-confirmation' = $true
        'auto-fix-await-confirmation' = $true
        'task-definition-fix-required' = $true
        'main-process-exit-review' = $true
        'manual-wait-paused' = $true
        'budget-exhausted-stop' = $true
        'known-infra-transient-stop' = $true
    }
    $ticketSelfHealable = (Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $Ticket -Name 'self_healable')).ToLowerInvariant() -in @('1', 'true', 'yes', 'on')
    $ticketNonRecoverableEnv = (Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $Ticket -Name 'non_recoverable_env')).ToLowerInvariant() -in @('1', 'true', 'yes', 'on')
    $ticketFailureKind = (Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $Ticket -Name 'failure_kind')).ToLowerInvariant()
    $ticketFailureCategory = (Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $Ticket -Name 'failure_category')).ToLowerInvariant()
    $ticketFailureSource = (Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $Ticket -Name 'failure_source')).ToLowerInvariant()
    $ticketFailureEvidence = (Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $Ticket -Name 'failure_evidence')).ToLowerInvariant()
    $ticketCauseBucket = (Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $Ticket -Name 'cause_bucket')).ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($ticketCauseBucket)) {
        $ticketCauseBucket = Get-CauseBucket -FailureKind $ticketFailureKind -FailureCategory $ticketFailureCategory -EventName $eventName
    }
    $ticketFailureFingerprint = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $Ticket -Name 'failure_fingerprint')
    if ([string]::IsNullOrWhiteSpace($ticketFailureFingerprint)) {
        $ticketFailureFingerprint = Get-FailureFingerprint -FailureKind $ticketFailureKind -FailureCategory $ticketFailureCategory -FailureSource $ticketFailureSource -FailureEvidence $ticketFailureEvidence -EventName $eventName
    }
    $ticketPreferredStageNormalized = (Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $Ticket -Name 'preferred_stage')).ToUpperInvariant()
    $policyWorkMode = ''
    if ($Settings.Contains('AI_CHAT_POLICY_WORK_MODE')) {
        $policyWorkMode = (Convert-ToSingleLineText -Text ([string]$Settings.AI_CHAT_POLICY_WORK_MODE)).ToLowerInvariant()
    }
    if ([string]::IsNullOrWhiteSpace($policyWorkMode)) {
        $policyWorkMode = 'normal'
    }
    $lowDisturbModeEnabled = ($policyWorkMode -eq 'low-disturb')
    $fallbackIncidentAutoResumeEligible = (
        -not $ticketSelfHealable -and
        -not $ticketNonRecoverableEnv -and
        [string]$resumePlan.stage -in @('A', 'B') -and
        ($ticketPreferredStageNormalized -in @('A', 'B') -or [string]::IsNullOrWhiteSpace($ticketPreferredStageNormalized)) -and
        (
            $ticketFailureKind -in @('compile-failure', 'compile-warning', 'verify-failure', 'task-definition-mismatch', 'script-edit-failure', 'code-edit-failure', 'main-process-exit') -or
            $ticketFailureCategory -in @('script-fault', 'code-or-unknown')
        )
    )

    $incidentLane = 'noncode'
    if ($ticketFailureCategory -eq 'script-fault' -and $ticketFailureEvidence -match '(?im)(conflicting\s+types\s+for|undefined\s+reference|compilation\s+terminated|fatal\s+error|error\s+c\d{4}|src[\\/].*\.(c|h):\d+)') {
        $ticketFailureCategory = 'code-or-unknown'
    }
    if ($ticketFailureCategory -eq 'script-fault') {
        $incidentLane = 'script-fix'
    }
    elseif ($ticketFailureCategory -eq 'code-or-unknown') {
        $incidentLane = 'code-fix'
    }
    elseif ($ticketFailureCategory -in @('noncode-transient', 'monitor-chain', 'environment', 'infra-transient')) {
        $incidentLane = 'noncode'
    }
    elseif ($ticketFailureKind -in @('task-definition-mismatch', 'compile-failure', 'compile-warning', 'verify-failure', 'code-edit-failure')) {
        $incidentLane = 'code-fix'
    }
    elseif ($ticketFailureKind -in @('script-failure', 'script-edit-failure', 'main-process-exit')) {
        $incidentLane = 'script-fix'
    }

    $routeGuardExpected = 'event-review'
    if ($eventNameNormalized -eq 'running-status-report') {
        $routeGuardExpected = 'status-health-check-only'
    }
    elseif ($eventNameNormalized -eq 'manual-wait-paused') {
        $routeGuardExpected = 'notice-manual-wait'
    }
    elseif ($eventNameNormalized -eq 'budget-exhausted-stop') {
        $routeGuardExpected = 'notice-budget-exhausted'
    }
    elseif ($eventNameNormalized -eq 'known-infra-transient-stop') {
        $routeGuardExpected = 'notice-known-infra-transient'
    }
    elseif ($incidentLikeEvents.ContainsKey($eventNameNormalized)) {
        if (($ticketSelfHealable -or $fallbackIncidentAutoResumeEligible) -and -not $ticketNonRecoverableEnv -and [string]$resumePlan.stage -ne 'none') {
            $routeGuardExpected = ('incident-auto-resume-{0}' -f $incidentLane)
        }
        else {
            $routeGuardExpected = ('incident-manual-{0}' -f $incidentLane)
        }
    }
    elseif ($lowDisturbModeEnabled) {
        $routeGuardExpected = 'event-review-low-disturb-text-only'
    }

    $selfHealScope = switch ($routeGuardExpected) {
        'incident-auto-resume-script-fix' { 'script-fix: repair guard/trigger/dispatch/poll scripts only'; break }
        'incident-manual-script-fix' { 'script-fix: repair guard/trigger/dispatch/poll scripts only'; break }
        'incident-auto-resume-code-fix' {
            $stageText = if ([string]::IsNullOrWhiteSpace($ticketPreferredStage)) { 'unknown-stage' } else { $ticketPreferredStage.ToUpperInvariant() }
            $roundText = if ([string]::IsNullOrWhiteSpace((Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $Ticket -Name 'main_round')))) { 'unknown-round' } else { (Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $Ticket -Name 'main_round')).ToUpperInvariant() }
            'code-fix: modify task-definition round for {0}/{1} under testdata; do not edit business source directly' -f $stageText, $roundText
            break
        }
        'incident-manual-code-fix' {
            $stageText = if ([string]::IsNullOrWhiteSpace($ticketPreferredStage)) { 'unknown-stage' } else { $ticketPreferredStage.ToUpperInvariant() }
            $roundText = if ([string]::IsNullOrWhiteSpace((Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $Ticket -Name 'main_round')))) { 'unknown-round' } else { (Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $Ticket -Name 'main_round')).ToUpperInvariant() }
            'code-fix: modify task-definition round for {0}/{1} under testdata; do not edit business source directly' -f $stageText, $roundText
            break
        }
        'incident-auto-resume-noncode' { 'noncode: stabilize environment / monitor chain only'; break }
        'incident-manual-noncode' { 'noncode: stabilize environment / monitor chain only'; break }
        'notice-manual-wait' { 'notice: report blocker and handled_at only'; break }
        'notice-budget-exhausted' { 'notice: report budget/cooldown constraint and handled_at only'; break }
        'notice-known-infra-transient' { 'notice: report infra stabilization state and handled_at only'; break }
        'status-health-check-only' { 'status: health-check only'; break }
        default { 'event-review: follow brief classification'; break }
    }

    $includeLaunchReadyBeforeResume = (
        -not [string]::IsNullOrWhiteSpace($resumeCommand) -and
        $eventNameNormalized -ne 'running-status-report' -and
        $eventNameNormalized -ne 'chat-session-final-status' -and
        $routeGuardExpected.StartsWith('incident-', [System.StringComparison]::OrdinalIgnoreCase)
    )

    $launchReadyCommandForBrief = ''
    if ($includeLaunchReadyBeforeResume) {
        $launchReadyCommandForBrief = $launchReadyCommand
    }

    $nextCommands = New-Object 'System.Collections.Generic.List[string]'
    $nextCommandNames = New-Object 'System.Collections.Generic.List[string]'
    $nextCommandPolicy = 'default-route-then-watch'
    if ($routeGuardExpected -eq 'status-health-check-only') {
        $nextCommandPolicy = 'status-healthcheck'
        if (-not [string]::IsNullOrWhiteSpace($routeGuardCommand)) { [void]$nextCommands.Add($routeGuardCommand); [void]$nextCommandNames.Add('route_guard_command') }
        if (-not [string]::IsNullOrWhiteSpace($guardCommand)) { [void]$nextCommands.Add($guardCommand); [void]$nextCommandNames.Add('guard_command') }
    }
    elseif ($routeGuardExpected -like 'notice-*') {
        $nextCommandPolicy = 'notice-stabilize-then-watch'
        if (-not [string]::IsNullOrWhiteSpace($routeGuardCommand)) { [void]$nextCommands.Add($routeGuardCommand); [void]$nextCommandNames.Add('route_guard_command') }
        if (-not [string]::IsNullOrWhiteSpace($guardCommand)) { [void]$nextCommands.Add($guardCommand); [void]$nextCommandNames.Add('guard_command') }
    }
    elseif ($routeGuardExpected -like 'incident-auto-resume-*') {
        $nextCommandPolicy = 'incident-auto-resume'
        if (-not [string]::IsNullOrWhiteSpace($routeGuardCommand)) { [void]$nextCommands.Add($routeGuardCommand); [void]$nextCommandNames.Add('route_guard_command') }
        if (-not [string]::IsNullOrWhiteSpace($launchReadyCommandForBrief)) { [void]$nextCommands.Add($launchReadyCommandForBrief); [void]$nextCommandNames.Add('pre_restart_launch_ready_command') }
        if (-not [string]::IsNullOrWhiteSpace($resumeCommand)) { [void]$nextCommands.Add($resumeCommand); [void]$nextCommandNames.Add('resume_command') }
        if (-not [string]::IsNullOrWhiteSpace($guardCommand)) { [void]$nextCommands.Add($guardCommand); [void]$nextCommandNames.Add('guard_command') }
    }
    elseif ($routeGuardExpected -like 'incident-manual-*') {
        $nextCommandPolicy = 'incident-manual-gated'
        if (-not [string]::IsNullOrWhiteSpace($routeGuardCommand)) { [void]$nextCommands.Add($routeGuardCommand); [void]$nextCommandNames.Add('route_guard_command') }
        if (-not [string]::IsNullOrWhiteSpace($launchReadyCommandForBrief)) { [void]$nextCommands.Add($launchReadyCommandForBrief); [void]$nextCommandNames.Add('pre_restart_launch_ready_command') }
        if (-not [string]::IsNullOrWhiteSpace($guardCommand)) { [void]$nextCommands.Add($guardCommand); [void]$nextCommandNames.Add('guard_command') }
    }
    elseif ($routeGuardExpected -like 'event-review*') {
        $nextCommandPolicy = 'event-review'
        if (-not [string]::IsNullOrWhiteSpace($routeGuardCommand)) { [void]$nextCommands.Add($routeGuardCommand); [void]$nextCommandNames.Add('route_guard_command') }
        if (-not [string]::IsNullOrWhiteSpace($guardCommand)) { [void]$nextCommands.Add($guardCommand); [void]$nextCommandNames.Add('guard_command') }
    }
    else {
        if (-not [string]::IsNullOrWhiteSpace($routeGuardCommand)) { [void]$nextCommands.Add($routeGuardCommand); [void]$nextCommandNames.Add('route_guard_command') }
        if (-not [string]::IsNullOrWhiteSpace($launchReadyCommandForBrief)) { [void]$nextCommands.Add($launchReadyCommandForBrief); [void]$nextCommandNames.Add('pre_restart_launch_ready_command') }
        if (-not [string]::IsNullOrWhiteSpace($resumeCommand)) { [void]$nextCommands.Add($resumeCommand); [void]$nextCommandNames.Add('resume_command') }
        if (-not [string]::IsNullOrWhiteSpace($guardCommand)) { [void]$nextCommands.Add($guardCommand); [void]$nextCommandNames.Add('guard_command') }
    }

    # Integrate diagnostic/closeout helper commands into brief suggestions.
    if ($eventNameNormalized -eq 'chat-session-final-status') {
        if (-not [string]::IsNullOrWhiteSpace($ticketClosureCheckCommand)) { [void]$nextCommands.Add($ticketClosureCheckCommand); [void]$nextCommandNames.Add('ticket_closure_check_command') }
        if (-not [string]::IsNullOrWhiteSpace($eventDedupHealthCheckCommand)) { [void]$nextCommands.Add($eventDedupHealthCheckCommand); [void]$nextCommandNames.Add('event_dedup_health_check_command') }
        if (-not [string]::IsNullOrWhiteSpace($finalStatusCloseoutCommand)) { [void]$nextCommands.Add($finalStatusCloseoutCommand); [void]$nextCommandNames.Add('final_status_closeout_command') }
        if (-not [string]::IsNullOrWhiteSpace($finalStatusCloseoutApplyAckCommand)) { [void]$nextCommands.Add($finalStatusCloseoutApplyAckCommand); [void]$nextCommandNames.Add('final_status_closeout_apply_ack_command') }
    }
    elseif ($routeGuardExpected -eq 'status-health-check-only' -or $routeGuardExpected -like 'notice-*') {
        if (-not [string]::IsNullOrWhiteSpace($ticketClosureCheckCommand)) { [void]$nextCommands.Add($ticketClosureCheckCommand); [void]$nextCommandNames.Add('ticket_closure_check_command') }
        if (-not [string]::IsNullOrWhiteSpace($eventDedupHealthCheckCommand)) { [void]$nextCommands.Add($eventDedupHealthCheckCommand); [void]$nextCommandNames.Add('event_dedup_health_check_command') }
    }
    if ($nextCommands.Count -lt 1) {
        [void]$nextCommands.Add('# no next command')
        [void]$nextCommandNames.Add('no_next_command')
    }

    $expectedNextCommandPolicy = switch -Wildcard ($routeGuardExpected) {
        'status-health-check-only' { 'status-healthcheck'; break }
        'notice-*' { 'notice-stabilize-then-watch'; break }
        'incident-auto-resume-*' { 'incident-auto-resume'; break }
        'incident-manual-*' { 'incident-manual-gated'; break }
        'event-review*' { 'event-review'; break }
        default { 'default-route-then-watch'; break }
    }

    $consistencyIssues = New-Object 'System.Collections.Generic.List[string]'
    if ($nextCommandPolicy -ne $expectedNextCommandPolicy) {
        [void]$consistencyIssues.Add(('policy-mismatch expected={0} actual={1}' -f $expectedNextCommandPolicy, $nextCommandPolicy))
    }

    $firstNextCommandName = if ($nextCommandNames.Count -gt 0) { [string]$nextCommandNames[0] } else { '' }
    if ($firstNextCommandName -ne 'route_guard_command') {
        [void]$consistencyIssues.Add(('route-guard-not-first first={0}' -f $firstNextCommandName))
    }

    $routeNextCommandConsistencyPass = ($consistencyIssues.Count -eq 0)
    $routeNextCommandConsistencyReason = if ($routeNextCommandConsistencyPass) { 'ok' } else { (($consistencyIssues.ToArray()) -join ';') }
    $nextCommandOrderJoined = (($nextCommandNames.ToArray()) -join '|')

    $null = (Write-TriggerLog ('brief_route_command_consistency ticket={0} route={1} expected_policy={2} actual_policy={3} pass={4} order={5} reason={6}' -f $ticketId, $routeGuardExpected, $expectedNextCommandPolicy, $nextCommandPolicy, [bool]$routeNextCommandConsistencyPass, $nextCommandOrderJoined, $routeNextCommandConsistencyReason))

    $notes = if ($Settings.Contains('SESSION_FINAL_NOTES')) { [string]$Settings.SESSION_FINAL_NOTES } else { '' }
    $runDir = Get-LatestAnchorValueFromNoteLog -Notes $notes -Key 'run_dir'
    $supervisorLog = Get-LatestAnchorValueFromNoteLog -Notes $notes -Key 'supervisor_log'
    $companionLog = Get-LatestAnchorValueFromNoteLog -Notes $notes -Key 'companion_log'
    $liveStatus = Get-LatestAnchorValueFromNoteLog -Notes $notes -Key 'live_status'
    $finalStatusCloseoutApplyAckCommandForBrief = ''
    if ($eventNameNormalized -eq 'chat-session-final-status') {
        $finalStatusCloseoutApplyAckCommandForBrief = $finalStatusCloseoutApplyAckCommand
    }

    $lines = @(
        '# AB Takeover Brief',
        '',
        ('generated_at={0}' -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')),
        ('ticket_id={0}' -f $ticketId),
        ('event={0}' -f $eventName),
        ('severity={0}' -f (Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $Ticket -Name 'severity'))),
        ('requires_confirmation={0}' -f (Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $Ticket -Name 'requires_confirmation'))),
        ('start_file={0}' -f (Convert-ToRepoRelativePath -Path $StartFilePath)),
        ('queue_path={0}' -f (Convert-ToRepoRelativePath -Path $QueueFilePath)),
        ('route_guard_command={0}' -f $routeGuardCommand),
        ('route_guard_expected={0}' -f $routeGuardExpected),
        ('status_fault_phase_normal_standard={0}' -f 'route_guard_expected!=status-health-check-only => force-normal-full-receipt'),
        ('event_only_wording_hard_rule={0}' -f 'event-only scheduling must not be interpreted or described as low-disturb execution flow'),
        ('event_queue_idempotent_policy={0}' -f 'process earliest unhandled in-session event tickets by created_at; skip pre-start events; if event missing mark done and continue until drained'),
        ('event_queue_scope_rule={0}' -f 'in-session only: do not consume event tickets created before current execution start baseline'),
        ('mode_restore_policy={0}' -f ('after event queue drained, return to previous work mode: {0}' -f $policyWorkMode)),
        ('guard_state={0}' -f (Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $Ticket -Name 'guard_state'))),
        ('guard_log={0}' -f (Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $Ticket -Name 'guard_log'))),
        ('incident_dir={0}' -f (Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $Ticket -Name 'incident_dir'))),
        ('session_final_status={0}' -f (Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $Ticket -Name 'session_final_status'))),
        ('a_final_status={0}' -f (Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $Ticket -Name 'a_final_status'))),
        ('b_final_status={0}' -f (Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $Ticket -Name 'b_final_status'))),
        ('preferred_stage={0}' -f (Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $Ticket -Name 'preferred_stage'))),
        ('main_round={0}' -f (Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $Ticket -Name 'main_round'))),
        ('failure_kind={0}' -f (Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $Ticket -Name 'failure_kind'))),
        ('failure_category={0}' -f (Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $Ticket -Name 'failure_category'))),
        ('failure_source={0}' -f (Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $Ticket -Name 'failure_source'))),
        ('failure_evidence={0}' -f (Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $Ticket -Name 'failure_evidence'))),
        ('cause_bucket={0}' -f $ticketCauseBucket),
        ('failure_fingerprint={0}' -f $ticketFailureFingerprint),
        ('self_healable={0}' -f (Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $Ticket -Name 'self_healable'))),
        ('non_recoverable_env={0}' -f (Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $Ticket -Name 'non_recoverable_env'))),
        ('business_command_stage={0}' -f [string]$resumePlan.stage),
        ('business_command_reason={0}' -f [string]$resumePlan.reason),
        ('route_next_command_consistency={0}' -f $routeNextCommandConsistencyPass),
        ('route_next_command_consistency_reason={0}' -f $routeNextCommandConsistencyReason),
        ('route_next_command_consistency_expected_policy={0}' -f $expectedNextCommandPolicy),
        ('route_next_command_consistency_actual_policy={0}' -f $nextCommandPolicy),
        ('next_command_policy={0}' -f $nextCommandPolicy),
        ('next_command_order={0}' -f $nextCommandOrderJoined),
        ('run_dir={0}' -f $runDir),
        ('supervisor_log={0}' -f $supervisorLog),
        ('companion_log={0}' -f $companionLog),
        ('live_status={0}' -f $liveStatus),
        ('detail={0}' -f (Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $Ticket -Name 'detail'))),
        ('recommended_action={0}' -f (Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $Ticket -Name 'recommended_action'))),
        ('self_heal_scope={0}' -f $selfHealScope),
        ('self_heal_hint={0}' -f (Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $Ticket -Name 'self_heal_hint'))),
        ('pre_restart_launch_ready_command={0}' -f $launchReadyCommandForBrief),
        ('ticket_closure_check_command={0}' -f $ticketClosureCheckCommand),
        ('event_dedup_health_check_command={0}' -f $eventDedupHealthCheckCommand),
        ('final_status_closeout_command={0}' -f $finalStatusCloseoutCommand),
        ('final_status_closeout_apply_ack_command={0}' -f $finalStatusCloseoutApplyAckCommandForBrief),
        '',
        'next_commands:'
    )
    $lines += @($nextCommands.ToArray())

    Write-Utf8BomFile -Path $briefPath -Value $lines
    return $briefPath
}

$script:RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Assert-Ps51Utf8BomCompatibility -ScriptPath $MyInvocation.MyCommand.Path -ScriptRole 'unattended_ab_takeover_trigger.ps1'
$startFilePath = Resolve-RepoPath -Path $StartFile
$startFileKey = Get-NormalizedPathKey -Path $startFilePath
$startFileToken = Get-StableStartFileToken -StartFilePath $startFilePath
$startFileLegacyToken = Get-LegacyStartFileToken -StartFilePath $startFilePath

try {
    $startFileHash = [System.BitConverter]::ToString(
        [System.Security.Cryptography.SHA1]::Create().ComputeHash(
            [System.Text.Encoding]::UTF8.GetBytes(
                [System.IO.Path]::GetFullPath($startFilePath).ToLowerInvariant()
            )
        )
    ).Replace('-', '').Substring(0, 12).ToLowerInvariant()
    $host.UI.RawUI.WindowTitle = "whois-mon-takeover-trigger-$startFileHash"
}
catch { }

$queueRoot = Resolve-RepoPathAllowMissing -Path 'out\artifacts\ab_agent_queue'
if (-not (Test-Path -LiteralPath $queueRoot)) {
    New-Item -ItemType Directory -Path $queueRoot -Force | Out-Null
}

$script:TriggerLogPath = Resolve-PreferredDefaultPath -PreferredPath (Join-Path $queueRoot ("takeover_trigger_{0}.log" -f $startFileToken)) -LegacyPath (Join-Path $queueRoot ("takeover_trigger_{0}.log" -f $startFileLegacyToken))
$script:TriggerLogWriteFailureKey = ''
$script:TriggerLogWriteFailureLastAt = [datetime]::MinValue
$script:TriggerGraceStartedAt = $null
$statePath = Resolve-PreferredDefaultPath -PreferredPath (Join-Path $queueRoot ("takeover_trigger_state_{0}.json" -f $startFileToken)) -LegacyPath (Join-Path $queueRoot ("takeover_trigger_state_{0}.json" -f $startFileLegacyToken))
$takeoverRoot = Join-Path $queueRoot 'takeover_requests'
$script:InstanceMutex = Enter-InstanceMutex -Role 'takeover-trigger' -StartFilePath $startFilePath
if ($script:InstanceMutex -isnot [System.Threading.Mutex]) {
    exit 0
}

$stateRaw = Read-JsonFileSafely -Path $statePath
$processedIds = New-Object 'System.Collections.Generic.List[string]'
$processedSet = @{}
if ($null -ne $stateRaw -and $stateRaw.PSObject.Properties.Name -contains 'processed_ids') {
    foreach ($id in @($stateRaw.processed_ids)) {
        $ticketId = Convert-ToSingleLineText -Text ([string]$id)
        if ([string]::IsNullOrWhiteSpace($ticketId)) {
            continue
        }

        if (-not $processedSet.Contains($ticketId)) {
            $processedSet[$ticketId] = $true
            [void]$processedIds.Add($ticketId)
        }
    }
}

$queueLastLineRead = -1
$queueStatePathKey = Get-NormalizedPathKey -Path (Get-ObjectPropertyString -InputObject $stateRaw -Name 'queue_path')
$queueLastLineReadRaw = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $stateRaw -Name 'queue_last_line_read')
if (-not [string]::IsNullOrWhiteSpace($queueLastLineReadRaw)) {
    $parsedQueueLastLineRead = 0
    if ([int]::TryParse($queueLastLineReadRaw, [ref]$parsedQueueLastLineRead) -and $parsedQueueLastLineRead -ge 0) {
        $queueLastLineRead = $parsedQueueLastLineRead
    }
}

$scriptStartUtc = (Get-Date).ToUniversalTime()
$chatRecoveryLastTriggerAt = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $stateRaw -Name 'chat_recovery_last_trigger_at')
$chatRecoveryLastSignature = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $stateRaw -Name 'chat_recovery_last_signature')
$chatRecoveryTriggerCount = 0
$chatRecoveryTriggerCountRaw = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $stateRaw -Name 'chat_recovery_trigger_count')
if (-not [string]::IsNullOrWhiteSpace($chatRecoveryTriggerCountRaw)) {
    $parsedCount = 0
    if ([int]::TryParse($chatRecoveryTriggerCountRaw, [ref]$parsedCount) -and $parsedCount -ge 0) {
        $chatRecoveryTriggerCount = $parsedCount
    }
}

$chatRecoveryLastFastRetrySignature = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $stateRaw -Name 'chat_recovery_last_fast_retry_signature')
$chatRecoveryLastFastRetryAt = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $stateRaw -Name 'chat_recovery_last_fast_retry_at')
$chatRecoveryFastRetryCount = 0
$chatRecoveryFastRetryCountRaw = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $stateRaw -Name 'chat_recovery_fast_retry_count')
if (-not [string]::IsNullOrWhiteSpace($chatRecoveryFastRetryCountRaw)) {
    $parsedFastRetryCount = 0
    if ([int]::TryParse($chatRecoveryFastRetryCountRaw, [ref]$parsedFastRetryCount) -and $parsedFastRetryCount -ge 0) {
        $chatRecoveryFastRetryCount = $parsedFastRetryCount
    }
}

Write-TriggerLog ("startup start_file={0} poll_sec={1} once={2} state={3}" -f (Convert-ToRepoRelativePath -Path $startFilePath), $PollSec, [bool]$Once.IsPresent, (Convert-ToRepoRelativePath -Path $statePath))
$fastPollUntilUtc = $null
$fastPollReason = ''
$triggerParentPid = 0
try {
    $triggerSelfProcess = Get-CimInstance Win32_Process -Filter ("ProcessId={0}" -f $PID) -ErrorAction Stop
    if ($null -ne $triggerSelfProcess) {
        $triggerParentPid = [int]$triggerSelfProcess.ParentProcessId
    }
}
catch {
    $triggerParentPid = 0
}
Write-TriggerLog ("startup_pid pid={0} parent_pid={1}" -f $PID, $triggerParentPid)

$waitQueuePath = Resolve-RepoPathAllowMissing -Path 'out\artifacts\ab_agent_queue\agent_tickets.jsonl'
$eventDrivenQueue = $true

while ($true) {
    try {
        if (-not (Test-Path -LiteralPath $startFilePath)) {
            Write-TriggerLog ("stop reason=start-file-missing start_file={0}" -f (Convert-ToRepoRelativePath -Path $startFilePath))
            break
        }

        $settings = Read-KeyValueFile -Path $startFilePath

        # Read stage status before checking shutdown request (needed for guard condition).
        $aFinalStatus = if ($settings.Contains('A_FINAL_STATUS')) { [string]$settings.A_FINAL_STATUS } else { 'NOT_RUN' }
        $bFinalStatus = if ($settings.Contains('B_FINAL_STATUS')) { [string]$settings.B_FINAL_STATUS } else { 'NOT_RUN' }
        $aStageRunning = ($aFinalStatus -eq 'RUNNING')
        $bStageRunning = ($bFinalStatus -eq 'RUNNING')

        $monitorChainShutdownRequested = $false
        if ($settings.Contains('MONITOR_CHAIN_SHUTDOWN_REQUESTED')) {
            $monitorChainShutdownRequested = Convert-ToBooleanSetting -Value ([string]$settings.MONITOR_CHAIN_SHUTDOWN_REQUESTED) -Default $false
        }
        if ($monitorChainShutdownRequested -and -not $aStageRunning -and -not $bStageRunning) {
            $monitorChainShutdownReason = if ($settings.Contains('MONITOR_CHAIN_SHUTDOWN_REASON')) { Convert-ToSingleLineText -Text ([string]$settings.MONITOR_CHAIN_SHUTDOWN_REASON) } else { '' }
            $monitorChainShutdownSource = if ($settings.Contains('MONITOR_CHAIN_SHUTDOWN_SOURCE')) { Convert-ToSingleLineText -Text ([string]$settings.MONITOR_CHAIN_SHUTDOWN_SOURCE) } else { '' }
            $monitorChainShutdownAt = if ($settings.Contains('MONITOR_CHAIN_SHUTDOWN_AT')) { Convert-ToSingleLineText -Text ([string]$settings.MONITOR_CHAIN_SHUTDOWN_AT) } else { '' }
            Write-TriggerLog ('stop reason=monitor-chain-shutdown-request source={0} request_reason={1} request_at={2}' -f $monitorChainShutdownSource, $monitorChainShutdownReason, $monitorChainShutdownAt)
            break
        }

        # Fallback: guard crash safety net. Exit if both stages terminal and no shutdown request after grace period.

        $bothTerminal = ($aFinalStatus -in @('PASS','FAIL','BLOCKED') -or $aFinalStatus -eq 'NOT_RUN') -and
            ($bFinalStatus -in @('PASS','FAIL','BLOCKED') -or $bFinalStatus -eq 'NOT_RUN')
        if ($bothTerminal) {
            if (-not $script:TriggerGraceStartedAt) {
                $script:TriggerGraceStartedAt = Get-Date
            }
            $graceElapsed = ((Get-Date) - $script:TriggerGraceStartedAt).TotalMinutes
            $monitorChainGraceMinutes = 20
            if ($settings.Contains('MONITOR_CHAIN_GRACE_MINUTES')) {
                $parsedGrace = 0
                if ([int]::TryParse(([string]$settings.MONITOR_CHAIN_GRACE_MINUTES), [ref]$parsedGrace)) {
                    if ($parsedGrace -ge 1 -and $parsedGrace -le 120) {
                        $monitorChainGraceMinutes = [int]$parsedGrace
                    }
                }
            }
            if ($graceElapsed -ge $monitorChainGraceMinutes) {
                Write-TriggerLog ('stop reason=grace-expired-no-shutdown-request elapsed_min={0:N1}' -f $graceElapsed)
                break
            }
        }
        else {
            $script:TriggerGraceStartedAt = $null
        }

        $queueEnabled = $true
        if ($settings.Contains('LOCAL_GUARD_AGENT_QUEUE_ENABLED')) {
            $queueEnabled = Convert-ToBooleanSetting -Value ([string]$settings.LOCAL_GUARD_AGENT_QUEUE_ENABLED) -Default $true
        }

        $queuePathValue = $QueuePath
        if ([string]::IsNullOrWhiteSpace($queuePathValue)) {
            if ($settings.Contains('LOCAL_GUARD_AGENT_QUEUE_PATH')) {
                $queuePathValue = [string]$settings.LOCAL_GUARD_AGENT_QUEUE_PATH
            }
        }
        if ([string]::IsNullOrWhiteSpace($queuePathValue)) {
            $queuePathValue = 'out\artifacts\ab_agent_queue\agent_tickets.jsonl'
        }

        $queueFilePath = Resolve-RepoPathAllowMissing -Path $queuePathValue
        $waitQueuePath = $queueFilePath

        $skipExistingQueueOnStart = $true
        if ($settings.Contains('AI_CHAT_TRIGGER_SKIP_EXISTING_QUEUE_ON_START')) {
            $skipExistingQueueOnStart = Convert-ToBooleanSetting -Value ([string]$settings.AI_CHAT_TRIGGER_SKIP_EXISTING_QUEUE_ON_START) -Default $true
        }

        $currentQueuePathKey = Get-NormalizedPathKey -Path $queueFilePath
        if ($queueLastLineRead -lt 0) {
            if ($skipExistingQueueOnStart) {
                $queueLastLineRead = Get-QueueLineCount -Path $queueFilePath
            }
            else {
                $queueLastLineRead = 0
            }
            $queueStatePathKey = $currentQueuePathKey
            Write-TriggerLog ("queue_watermark_initialized line={0} queue={1} skip_existing_on_start={2}" -f $queueLastLineRead, (Convert-ToRepoRelativePath -Path $queueFilePath), [bool]$skipExistingQueueOnStart)
        }
        elseif (-not [string]::IsNullOrWhiteSpace($queueStatePathKey) -and -not [string]::IsNullOrWhiteSpace($currentQueuePathKey) -and $queueStatePathKey -ne $currentQueuePathKey) {
            $queueLastLineRead = Get-QueueLineCount -Path $queueFilePath
            $queueStatePathKey = $currentQueuePathKey
            Write-TriggerLog ("queue_watermark_rebased reason=queue-path-changed line={0} queue={1}" -f $queueLastLineRead, (Convert-ToRepoRelativePath -Path $queueFilePath))
        }
        else {
            $currentQueueLineCount = Get-QueueLineCount -Path $queueFilePath
            if ($currentQueueLineCount -lt $queueLastLineRead) {
                $queueLastLineRead = 0
                Write-TriggerLog ("queue_watermark_reset reason=queue-truncated queue={0}" -f (Convert-ToRepoRelativePath -Path $queueFilePath))
            }
        }

        $bPassFailConflict = Get-BPassFailConflictEvidence -Settings $settings -StartFilePath $startFilePath
        if ([bool]$bPassFailConflict.conflict) {
            Write-TriggerLog (
                'status_conflict_detected reason={0} exit_result={1} exit_code={2} fail_category={3} fail_reason={4} artifact={5}' -f
                [string]$bPassFailConflict.reason,
                [string]$bPassFailConflict.exit_result,
                [int]$bPassFailConflict.exit_code,
                [string]$bPassFailConflict.fail_category,
                [string]$bPassFailConflict.fail_reason,
                [string]$bPassFailConflict.artifact_path)

            $existingNotes = if ($settings.Contains('SESSION_FINAL_NOTES')) { [string]$settings.SESSION_FINAL_NOTES } else { '' }
            $conflictNote = ('trigger_pass_conflict b_exit_fail artifact={0} exit_code={1} fail_category={2}' -f [string]$bPassFailConflict.artifact_path, [int]$bPassFailConflict.exit_code, [string]$bPassFailConflict.fail_category)
            $updatedNotes = Add-DelimitedNote -Existing $existingNotes -Append $conflictNote

            try {
                $applied = Set-KeyValueFileValue -Path $startFilePath -Values @{
                    B_FINAL_STATUS = 'FAIL'
                    B_LAUNCH_PID = '0'
                    SESSION_FINAL_STATUS = 'FAIL'
                    SESSION_CLOSED = 'false'
                    SESSION_CLOSED_AT = ''
                    SESSION_CLOSED_REASON = 'b-exit-fail-conflict'
                    SESSION_FINAL_NOTES = $updatedNotes
                }
                Write-TriggerLog ('status_conflict_reconciled applied={0} artifact={1}' -f [bool]$applied, [string]$bPassFailConflict.artifact_path)
                if ($applied) {
                    $settings = Read-KeyValueFile -Path $startFilePath
                }
            }
            catch {
                Write-TriggerLog ('status_conflict_reconcile_failed detail={0}' -f (Convert-ToSingleLineText -Text $_.Exception.Message))
            }
        }

        $triggerCommandValue = $TriggerCommand
        if ([string]::IsNullOrWhiteSpace($triggerCommandValue) -and $settings.Contains('EXTERNAL_TRIGGER_COMMAND')) {
            $triggerCommandValue = [string]$settings.EXTERNAL_TRIGGER_COMMAND
        }

        $executeCommand = $ExecuteTriggerCommand.IsPresent
        if (-not $executeCommand -and $settings.Contains('EXTERNAL_TRIGGER_EXECUTE')) {
            $executeCommand = Convert-ToBooleanSetting -Value ([string]$settings.EXTERNAL_TRIGGER_EXECUTE) -Default $false
        }

        if (-not $queueEnabled) {
            Write-TriggerLog 'queue_disabled action=skip'
            if ($Once.IsPresent) {
                break
            }

            $effectivePollSec = $PollSec
            if ($null -ne $fastPollUntilUtc -and (Get-Date).ToUniversalTime() -lt $fastPollUntilUtc) {
                $effectivePollSec = [Math]::Min([int]$PollSec, 5)
            }
            $wakeReason = Wait-QueueSignalOrTimeout -QueueFilePath $queueFilePath -TimeoutSec $effectivePollSec -EnableEventDriven $eventDrivenQueue
            if ($wakeReason -ne 'timer') {
                Write-TriggerLog ("wake reason={0} queue={1}" -f $wakeReason, (Convert-ToRepoRelativePath -Path $queueFilePath))
            }
            continue
        }

        $chatHeartbeatEnabled = $true
        if ($settings.Contains('AI_CHAT_HEARTBEAT_ENABLED')) {
            $chatHeartbeatEnabled = Convert-ToBooleanSetting -Value ([string]$settings.AI_CHAT_HEARTBEAT_ENABLED) -Default $true
        }
        $chatAutoRecoverEnabled = $false
        if ($settings.Contains('AI_CHAT_AUTO_RECOVER_ENABLED')) {
            $chatAutoRecoverEnabled = Convert-ToBooleanSetting -Value ([string]$settings.AI_CHAT_AUTO_RECOVER_ENABLED) -Default $false
        }
        $dispatchStatusReports = $false
        if ($settings.Contains('AI_CHAT_TRIGGER_DISPATCH_STATUS_REPORTS')) {
            $dispatchStatusReports = Convert-ToBooleanSetting -Value ([string]$settings.AI_CHAT_TRIGGER_DISPATCH_STATUS_REPORTS) -Default $false
        }
        $eventDrivenQueue = $true
        if ($settings.Contains('AI_CHAT_TRIGGER_EVENT_DRIVEN_QUEUE')) {
            $eventDrivenQueue = Convert-ToBooleanSetting -Value ([string]$settings.AI_CHAT_TRIGGER_EVENT_DRIVEN_QUEUE) -Default $true
        }
        $finalStopGateMode = Get-FinalStopGateMode -Settings $settings -Default 'trigger-started'
        $chatHeartbeatTtlMinutes = Get-IntSetting -Settings $settings -Key 'AI_CHAT_HEARTBEAT_TTL_MINUTES' -Default 12 -Min 2 -Max 180
        $chatHeartbeatMissingGraceMinutes = Get-IntSetting -Settings $settings -Key 'AI_CHAT_HEARTBEAT_MISSING_GRACE_MINUTES' -Default 20 -Min 1 -Max 180
        $chatRecoveryCooldownMinutes = Get-IntSetting -Settings $settings -Key 'AI_CHAT_AUTO_RECOVER_COOLDOWN_MINUTES' -Default 10 -Min 1 -Max 240
        $chatRecoveryFastRetryEnabled = $true
        if ($settings.Contains('AI_CHAT_AUTO_RECOVER_FAST_RETRY_ENABLED')) {
            $chatRecoveryFastRetryEnabled = Convert-ToBooleanSetting -Value ([string]$settings.AI_CHAT_AUTO_RECOVER_FAST_RETRY_ENABLED) -Default $true
        }
        $chatRecoveryFastRetrySeconds = Get-IntSetting -Settings $settings -Key 'AI_CHAT_AUTO_RECOVER_FAST_RETRY_SECONDS' -Default 90 -Min 30 -Max 900
        $finalTriggerVerifyMs = Get-IntSetting -Settings $settings -Key 'AI_CHAT_FINAL_TRIGGER_VERIFY_MS' -Default 1200 -Min 0 -Max 15000
        $finalTriggerMaxAttempts = Get-IntSetting -Settings $settings -Key 'AI_CHAT_FINAL_TRIGGER_MAX_ATTEMPTS' -Default 2 -Min 1 -Max 5
        $chatRecoveryEventRaw = ''
        if ($settings.Contains('AI_CHAT_AUTO_RECOVER_EVENT')) {
            $chatRecoveryEventRaw = [string]$settings.AI_CHAT_AUTO_RECOVER_EVENT
        }
        $chatRecoveryEvent = Convert-ToSingleLineText -Text $chatRecoveryEventRaw
        if ([string]::IsNullOrWhiteSpace($chatRecoveryEvent)) {
            $chatRecoveryEvent = 'chat-session-heartbeat-timeout'
        }

        $watchExpectation = Test-SessionWatchExpected -Settings $settings
        $sessionCloseGate = Get-SessionCloseGateState -Settings $settings
        $autoStopOnFinal = -not $NoAutoStopOnFinal.IsPresent
        $isPassTerminalForFinalSummary =
            ([string]$watchExpectation.session_status -eq 'PASS') -and
            ([string]$watchExpectation.a_status -eq 'PASS') -and
            ([string]$watchExpectation.b_status -eq 'PASS')

        if ($autoStopOnFinal -and $isPassTerminalForFinalSummary -and -not [bool]$watchExpectation.watch_expected) {
            $closeUpdates = @{
                SESSION_CLOSED = 'true'
                SESSION_CLOSED_AT = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
                SESSION_CLOSED_REASON = 'chat-session-final-status-pass'
            }
            try {
                $closeApplied = Set-KeyValueFileValue -Path $startFilePath -Values $closeUpdates
                Write-TriggerLog ('session_closed_set applied={0} reason={1}' -f [bool]$closeApplied, [string]$closeUpdates.SESSION_CLOSED_REASON)
            }
            catch {
                Write-TriggerLog ('session_closed_set_failed detail={0}' -f (Convert-ToSingleLineText -Text $_.Exception.Message))
            }

            $finalEventName = 'chat-session-final-status'
            $finalSignature = ('session={0};a={1};b={2}' -f [string]$watchExpectation.session_status, [string]$watchExpectation.a_status, [string]$watchExpectation.b_status)
            $finalDispatchMarker = ('final_status_trigger_started signature={0}' -f $finalSignature)
            $alreadyFinalDispatched = Test-LogTailContainsFragment -Path $script:TriggerLogPath -Fragment $finalDispatchMarker
            $finalDispatchConfirmed = [bool]$alreadyFinalDispatched
            $finalTicketId = ''

            if (-not $alreadyFinalDispatched) {
                $finalTicketId = ('chat-final-{0}' -f (Get-Date).ToString('yyyyMMdd-HHmmss'))
                $finalDetail = ('session reached terminal status; session={0}; a={1}; b={2}' -f [string]$watchExpectation.session_status, [string]$watchExpectation.a_status, [string]$watchExpectation.b_status)
                $finalTicket = [pscustomobject]@{
                    schema = 'AB_AGENT_TICKET_V1'
                    ticket_id = $finalTicketId
                    created_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
                    source = 'unattended_ab_takeover_trigger'
                    event = $finalEventName
                    severity = 'info'
                    requires_confirmation = $false
                    start_file = (Convert-ToRepoRelativePath -Path $startFilePath)
                    queue_path = (Convert-ToRepoRelativePath -Path $queueFilePath)
                    guard_state = 'session-final'
                    guard_log = ''
                    incident_dir = ''
                    session_final_status = [string]$watchExpectation.session_status
                    a_final_status = [string]$watchExpectation.a_status
                    b_final_status = [string]$watchExpectation.b_status
                    detail = $finalDetail
                    recommended_action = 'summarize unattended execution/completion (timeline, ticket handling, heartbeat, ack, final status), then close monitor windows.'
                }

                $finalQueueAppend = Add-TicketToQueue -Ticket $finalTicket -QueueFilePath $queueFilePath
                if (-not [bool]$finalQueueAppend.Success) {
                    Write-TriggerLog ('final_status_ticket_queue_failed id={0} queue={1} reason={2}' -f $finalTicketId, (Convert-ToRepoRelativePath -Path $finalQueueAppend.Path), [string]$finalQueueAppend.Reason)
                }
                else {
                    Write-TriggerLog ('final_status_ticket_queued id={0} queue={1}' -f $finalTicketId, (Convert-ToRepoRelativePath -Path $finalQueueAppend.Path))
                }

                $finalBriefPath = New-TakeoverBrief -Ticket $finalTicket -Settings $settings -OutputRoot $takeoverRoot -QueueFilePath $queueFilePath -StartFilePath $startFilePath
                $finalBriefRel = Convert-ToRepoRelativePath -Path $finalBriefPath
                Write-TriggerLog ('final_status_dispatch signature={0} id={1} event={2} brief={3}' -f $finalSignature, $finalTicketId, $finalEventName, $finalBriefRel)

                if (-not [bool]$finalQueueAppend.Success) {
                    Write-TriggerLog ('final_status_trigger_blocked id={0} reason=queue-append-failed' -f $finalTicketId)
                    $finalDispatchConfirmed = $false
                }

                if ([bool]$finalQueueAppend.Success -and -not [string]::IsNullOrWhiteSpace($triggerCommandValue) -and $executeCommand) {
                    $finalRouteStartUtc = (Get-Date).ToUniversalTime()
                    $finalRouteDecision = Invoke-RouteGuardForBrief -BriefPath $finalBriefPath -QueueFilePath $queueFilePath
                    if (-not [bool]$finalRouteDecision.Allowed) {
                        Write-TriggerLog ('final_status_trigger_blocked id={0} reason={1} expected={2} expected_source={3} classification={4} action={5}' -f $finalTicketId, [string]$finalRouteDecision.Reason, [string]$finalRouteDecision.RouteGuardExpected, [string]$finalRouteDecision.RouteGuardExpectedSource, [string]$finalRouteDecision.Classification, [string]$finalRouteDecision.RecommendedAction)
                    }
                    else {
                        $finalRouteLatencyMs = [int][Math]::Max(0, [Math]::Round(((Get-Date).ToUniversalTime() - $finalRouteStartUtc).TotalMilliseconds))
                        Write-TriggerLog ('final_status_trigger_route_allowed id={0} expected={1} expected_source={2} classification={3} action={4} latency_ms={5}' -f $finalTicketId, [string]$finalRouteDecision.RouteGuardExpected, [string]$finalRouteDecision.RouteGuardExpectedSource, [string]$finalRouteDecision.Classification, [string]$finalRouteDecision.RecommendedAction, [int]$finalRouteLatencyMs)
                        $finalTriggerStartUtc = (Get-Date).ToUniversalTime()
                        $finalPlan = Resolve-ExternalTriggerExecutionPlan -Template $triggerCommandValue -TicketId $finalTicketId -EventName $finalEventName -StartFilePath $startFilePath -QueueFilePath $queueFilePath -BriefPath $finalBriefPath
                        $finalResult = Invoke-ExternalTriggerCommandWithLivenessGuard -Plan $finalPlan -MaxAttempts $finalTriggerMaxAttempts -LivenessWaitMs $finalTriggerVerifyMs
                        if ([bool]$finalResult.Started) {
                            $finalDispatchConfirmed = $true
                            $finalTriggerLatencyMs = [int][Math]::Max(0, [Math]::Round(((Get-Date).ToUniversalTime() - $finalTriggerStartUtc).TotalMilliseconds))
                            Write-TriggerLog ('final_status_trigger_started signature={0} id={1} pid={2} attempts={3} verify_ms={4} route_class={5} latency_ms={6}' -f $finalSignature, $finalTicketId, [int]$finalResult.ProcessId, [int]$finalResult.Attempts, [int]$finalTriggerVerifyMs, [string]$finalRouteDecision.Classification, [int]$finalTriggerLatencyMs)
                        }
                        else {
                            Write-TriggerLog ('final_status_trigger_failed id={0} detail={1} attempts={2} last_pid={3}' -f $finalTicketId, [string]$finalResult.Reason, [int]$finalResult.Attempts, [int]$finalResult.LastProcessId)
                        }
                    }
                }
                elseif ([bool]$finalQueueAppend.Success -and -not [string]::IsNullOrWhiteSpace($triggerCommandValue)) {
                    $finalDispatchConfirmed = $true
                    Write-TriggerLog ('final_status_trigger_skipped id={0} reason=execution-disabled' -f $finalTicketId)
                }
                elseif ([bool]$finalQueueAppend.Success) {
                    $finalDispatchConfirmed = $true
                    Write-TriggerLog ('final_status_trigger_skipped id={0} reason=command-empty' -f $finalTicketId)
                }
            }
            else {
                Write-TriggerLog ('final_status_skip reason=already-dispatched signature={0}' -f $finalSignature)
            }

            if (-not $finalDispatchConfirmed) {
                Write-TriggerLog ('auto_stop_deferred reason=final-dispatch-not-confirmed signature={0}' -f $finalSignature)
                if ($Once.IsPresent) {
                    break
                }
                $wakeReason = Wait-QueueSignalOrTimeout -QueueFilePath $queueFilePath -TimeoutSec $PollSec -EnableEventDriven $eventDrivenQueue
                if ($wakeReason -ne 'timer') {
                    Write-TriggerLog ("wake reason={0} queue={1}" -f $wakeReason, (Convert-ToRepoRelativePath -Path $queueFilePath))
                }
                continue
            }

            if ([string]::Equals($finalStopGateMode, 'sender-sent', [System.StringComparison]::OrdinalIgnoreCase)) {
                $senderAck = Test-FinalDispatchSenderSent -QueueRoot $queueRoot -StartFileToken $startFileToken -LegacyStartFileToken $startFileLegacyToken -ExpectedTicketId $finalTicketId -SessionStartUtc $scriptStartUtc
                if (-not [bool]$senderAck.confirmed) {
                    $state = $senderAck.state
                    $stateTicketId = if ($null -ne $state) { Convert-ToSingleLineText -Text ([string]$state.ticket_id) } else { '' }
                    $stateEvent = if ($null -ne $state) { Convert-ToSingleLineText -Text ([string]$state.event) } else { '' }
                    $stateSenderSent = if ($null -ne $state) { [bool]$state.sender_sent } else { $false }
                    $stateSenderReason = if ($null -ne $state) { Convert-ToSingleLineText -Text ([string]$state.sender_reason) } else { '' }
                    $stateUpdatedAt = if ($null -ne $state) { Convert-ToSingleLineText -Text ([string]$state.updated_at) } else { '' }
                    Write-TriggerLog ('auto_stop_deferred reason=final-dispatch-sender-not-confirmed gate={0} signature={1} expected_ticket={2} state_ticket={3} state_event={4} state_sender_sent={5} state_sender_reason={6} state_updated_at={7} check_reason={8}' -f $finalStopGateMode, $finalSignature, $finalTicketId, $stateTicketId, $stateEvent, $stateSenderSent, $stateSenderReason, $stateUpdatedAt, [string]$senderAck.reason)
                    if ($Once.IsPresent) {
                        break
                    }
                    $wakeReason = Wait-QueueSignalOrTimeout -QueueFilePath $queueFilePath -TimeoutSec $PollSec -EnableEventDriven $eventDrivenQueue
                    if ($wakeReason -ne 'timer') {
                        Write-TriggerLog ("wake reason={0} queue={1}" -f $wakeReason, (Convert-ToRepoRelativePath -Path $queueFilePath))
                    }
                    continue
                }

                $state = $senderAck.state
                $stateTicketId = if ($null -ne $state) { Convert-ToSingleLineText -Text ([string]$state.ticket_id) } else { '' }
                $stateSenderMode = if ($null -ne $state) { Convert-ToSingleLineText -Text ([string]$state.sender_mode) } else { '' }
                $stateSenderReason = if ($null -ne $state) { Convert-ToSingleLineText -Text ([string]$state.sender_reason) } else { '' }
                Write-TriggerLog ('final_dispatch_sender_confirmed gate={0} expected_ticket={1} state_ticket={2} sender_mode={3} sender_reason={4}' -f $finalStopGateMode, $finalTicketId, $stateTicketId, $stateSenderMode, $stateSenderReason)
            }

            Write-TriggerLog ('auto_stop reason=session-final session={0} a={1} b={2}' -f [string]$watchExpectation.session_status, [string]$watchExpectation.a_status, [string]$watchExpectation.b_status)
            if ($ExitShellOnFinal.IsPresent) {
                [Environment]::Exit(0)
            }

            break
        }

        $nowUtc = (Get-Date).ToUniversalTime()
        $chatHeartbeatPath = ''
        $chatHeartbeatState = [pscustomobject]@{
            path = ''
            exists = $false
            updated_at = ''
            age_seconds = -1
            stale = $false
            reason = 'disabled'
        }
        if ($chatHeartbeatEnabled) {
            $chatHeartbeatPath = Get-ChatHeartbeatPath -Settings $settings -StartToken $startFileToken -LegacyStartToken $startFileLegacyToken
            $chatHeartbeatState = Get-ChatHeartbeatState -Path $chatHeartbeatPath -NowUtc $nowUtc -TtlMinutes $chatHeartbeatTtlMinutes -MissingGraceMinutes $chatHeartbeatMissingGraceMinutes -ScriptStartUtc $scriptStartUtc
        }

        $chatRecoveryRunReason = ''
        if ($chatAutoRecoverEnabled -and $chatHeartbeatEnabled -and [bool]$watchExpectation.watch_expected -and [bool]$chatHeartbeatState.stale) {
            $heartbeatSignature = if (-not [string]::IsNullOrWhiteSpace([string]$chatHeartbeatState.updated_at)) {
                ('updated_at:{0}' -f [string]$chatHeartbeatState.updated_at)
            }
            else {
                ('reason:{0}' -f [string]$chatHeartbeatState.reason)
            }

            $cooldownReady = $true
            $lastTriggerUtc = Get-DateTimeOrNull -Text $chatRecoveryLastTriggerAt
            $elapsedSinceLastTriggerSeconds = -1
            if ($null -ne $lastTriggerUtc) {
                $elapsedMinutes = ([timespan]($nowUtc - $lastTriggerUtc)).TotalMinutes
                $elapsedSinceLastTriggerSeconds = [int][Math]::Floor(([timespan]($nowUtc - $lastTriggerUtc)).TotalSeconds)
                if ($elapsedMinutes -lt $chatRecoveryCooldownMinutes) {
                    $cooldownReady = $false
                }
            }

            $signatureChanged = ([string]$chatRecoveryLastSignature -ne [string]$heartbeatSignature)
            $fastRetryReady = $false
            if ($chatRecoveryFastRetryEnabled -and -not $cooldownReady -and -not $signatureChanged -and $elapsedSinceLastTriggerSeconds -ge 0) {
                $alreadyFastRetriedForSignature = ([string]$chatRecoveryLastFastRetrySignature -eq [string]$heartbeatSignature)
                if (-not $alreadyFastRetriedForSignature -and $elapsedSinceLastTriggerSeconds -ge $chatRecoveryFastRetrySeconds) {
                    $fastRetryReady = $true
                }
            }

            if ($cooldownReady -or $signatureChanged -or $fastRetryReady) {
                $triggerMode = 'regular'
                if ($fastRetryReady) {
                    $triggerMode = 'fast-retry'
                }

                $ticketId = ('chat-recover-{0}' -f (Get-Date).ToString('yyyyMMdd-HHmmss'))
                $detail = ('chat session heartbeat stale; reason={0}; updated_at={1}; age_seconds={2}; ttl_minutes={3}; heartbeat_path={4}' -f
                    [string]$chatHeartbeatState.reason,
                    [string]$chatHeartbeatState.updated_at,
                    [int]$chatHeartbeatState.age_seconds,
                    [int]$chatHeartbeatTtlMinutes,
                    [string]$chatHeartbeatState.path)

                $ticket = [pscustomobject]@{
                    ticket_id = $ticketId
                    event = $chatRecoveryEvent
                    severity = 'high'
                    requires_confirmation = $false
                    start_file = (Convert-ToRepoRelativePath -Path $startFilePath)
                    guard_state = 'chat-session-stale'
                    guard_log = ''
                    incident_dir = ''
                    session_final_status = [string]$watchExpectation.session_status
                    a_final_status = [string]$watchExpectation.a_status
                    b_final_status = [string]$watchExpectation.b_status
                    detail = $detail
                    recommended_action = 'reopen chat channel and continue blocking watch; then execute business and continue_watch commands from latest poll output.'
                }

                $enqueueResult = Add-TicketToQueue -Ticket $ticket -QueueFilePath $queueFilePath
                if ([bool]$enqueueResult.Success) {
                    $chatRecoveryLastTriggerAt = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
                    $chatRecoveryLastSignature = $heartbeatSignature
                    $chatRecoveryTriggerCount = [int]$chatRecoveryTriggerCount + 1
                    if ($fastRetryReady) {
                        $chatRecoveryLastFastRetrySignature = $heartbeatSignature
                        $chatRecoveryLastFastRetryAt = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
                        $chatRecoveryFastRetryCount = [int]$chatRecoveryFastRetryCount + 1
                        $chatRecoveryRunReason = 'ticket-enqueued-fast-retry'
                    }
                    else {
                        $chatRecoveryRunReason = 'ticket-enqueued'
                    }

                    Write-TriggerLog ('chat_recovery_ticket_enqueued id={0} event={1} queue={2} signature={3} mode={4}' -f $ticketId, $chatRecoveryEvent, (Convert-ToRepoRelativePath -Path ([string]$enqueueResult.Path)), $heartbeatSignature, $triggerMode)
                }
                else {
                    $chatRecoveryRunReason = ('ticket-enqueue-failed:{0}' -f [string]$enqueueResult.Reason)
                    Write-TriggerLog ('chat_recovery_ticket_enqueue_failed id={0} detail={1} queue={2} mode={3}' -f $ticketId, [string]$enqueueResult.Reason, (Convert-ToRepoRelativePath -Path ([string]$enqueueResult.Path)), $triggerMode)
                }
            }
            else {
                $chatRecoveryRunReason = ('cooldown-active minutes={0} fast_retry_seconds={1}' -f $chatRecoveryCooldownMinutes, $chatRecoveryFastRetrySeconds)
                Write-TriggerLog ('chat_recovery_skip reason=cooldown signature={0} fast_retry_enabled={1} fast_retry_seconds={2}' -f $heartbeatSignature, $chatRecoveryFastRetryEnabled, $chatRecoveryFastRetrySeconds)
            }
        }

        $tickets = @(Get-TicketsFromQueue -Path $queueFilePath -AfterLineNo $queueLastLineRead)
        $newCount = 0
        $startFileMismatchCount = 0
        $maxObservedQueueLineNo = $queueLastLineRead

        foreach ($ticket in $tickets) {
            $ticketQueueLineNo = 0
            if ($ticket.PSObject.Properties.Name -contains '__queue_line_no') {
                $ticketQueueLineNo = [int]$ticket.__queue_line_no
                if ($ticketQueueLineNo -gt $maxObservedQueueLineNo) {
                    $maxObservedQueueLineNo = $ticketQueueLineNo
                }
            }

            $ticketId = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $ticket -Name 'ticket_id')
            if ([string]::IsNullOrWhiteSpace($ticketId)) {
                continue
            }

            if ($processedSet.Contains($ticketId)) {
                continue
            }

            $ticketStartFileRaw = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $ticket -Name 'start_file')
            $ticketStartFileKey = Get-NormalizedPathKey -Path $ticketStartFileRaw
            $ticketStartFileMatched = $false
            $ticketStartFileReason = 'start-file-missing'

            if (-not [string]::IsNullOrWhiteSpace($ticketStartFileKey) -and -not [string]::IsNullOrWhiteSpace($startFileKey)) {
                if ($ticketStartFileKey -eq $startFileKey) {
                    $ticketStartFileMatched = $true
                }
                else {
                    $ticketStartFileReason = 'start-file-mismatch'
                }
            }
            elseif (-not [string]::IsNullOrWhiteSpace($ticketStartFileKey)) {
                $ticketStartFileReason = 'start-file-normalize-failed'
            }
            else {
                $ticketDetailText = (Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $ticket -Name 'detail')).ToLowerInvariant()
                $startTokenLower = $startFileLegacyToken.ToLowerInvariant()
                if (-not [string]::IsNullOrWhiteSpace($startTokenLower) -and -not [string]::IsNullOrWhiteSpace($ticketDetailText) -and $ticketDetailText.Contains($startTokenLower)) {
                    $ticketStartFileMatched = $true
                    $ticketStartFileReason = 'legacy-detail-match'
                }
            }

            if (-not $ticketStartFileMatched) {
                if ($startFileMismatchCount -lt 3) {
                    Write-TriggerLog ("ticket_skip id={0} reason={1} ticket_start_file={2}" -f $ticketId, $ticketStartFileReason, $ticketStartFileRaw)
                }

                $startFileMismatchCount++
                if (-not $processedSet.Contains($ticketId)) {
                    $processedSet[$ticketId] = $true
                    [void]$processedIds.Add($ticketId)
                }
                $newCount++
                continue
            }

            $eventName = (Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $ticket -Name 'event')).ToLowerInvariant()
            if ([bool]$sessionCloseGate.closed -and $eventName -ne 'chat-session-final-status') {
                Write-TriggerLog ("ticket_skip id={0} event={1} reason=session-closed-lock" -f $ticketId, $eventName)
                if (-not $processedSet.Contains($ticketId)) {
                    $processedSet[$ticketId] = $true
                    [void]$processedIds.Add($ticketId)
                }
                $newCount++
                continue
            }

            if (-not $dispatchStatusReports -and $eventName -eq 'running-status-report') {
                Write-TriggerLog ("ticket_skip id={0} event={1} reason=status-report-dispatch-disabled" -f $ticketId, $eventName)
                if (-not $processedSet.Contains($ticketId)) {
                    $processedSet[$ticketId] = $true
                    [void]$processedIds.Add($ticketId)
                }
                $newCount++
                continue
            }

            $briefPath = New-TakeoverBrief -Ticket $ticket -Settings $settings -OutputRoot $takeoverRoot -QueueFilePath $queueFilePath -StartFilePath $startFilePath
            $briefRel = Convert-ToRepoRelativePath -Path $briefPath
            $eventName = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $ticket -Name 'event')
            $eventNameNormalized = $eventName.ToLowerInvariant()

            Write-TriggerLog ("ticket_dispatch id={0} event={1} brief={2}" -f $ticketId, $eventName, $briefRel)

            if ($eventNameNormalized -in @('incident-captured', 'recovery-await-confirmation', 'auto-fix-await-confirmation', 'task-definition-fix-required', 'main-process-exit-review', 'manual-wait-paused', 'budget-exhausted-stop', 'known-infra-transient-stop')) {
                $fastPollUntilUtc = (Get-Date).ToUniversalTime().AddSeconds(30)
                $fastPollReason = ('event={0};ticket={1}' -f $eventNameNormalized, $ticketId)
                Write-TriggerLog ("fast_poll_window_open ttl_sec=30 reason={0}" -f $fastPollReason)
            }

            if (-not [string]::IsNullOrWhiteSpace($triggerCommandValue)) {
                if ($executeCommand) {
                    $routeStartUtc = (Get-Date).ToUniversalTime()
                    $routeDecision = Invoke-RouteGuardForBrief -BriefPath $briefPath -QueueFilePath $queueFilePath
                    if (-not [bool]$routeDecision.Allowed) {
                        Write-TriggerLog ("external_trigger_blocked id={0} reason={1} expected={2} expected_source={3} classification={4} action={5}" -f $ticketId, [string]$routeDecision.Reason, [string]$routeDecision.RouteGuardExpected, [string]$routeDecision.RouteGuardExpectedSource, [string]$routeDecision.Classification, [string]$routeDecision.RecommendedAction)
                    }
                    else {
                        $routeLatencyMs = [int][Math]::Max(0, [Math]::Round(((Get-Date).ToUniversalTime() - $routeStartUtc).TotalMilliseconds))
                        Write-TriggerLog ("external_trigger_route_allowed id={0} expected={1} expected_source={2} classification={3} action={4} confidence={5} factors={6} latency_ms={7}" -f $ticketId, [string]$routeDecision.RouteGuardExpected, [string]$routeDecision.RouteGuardExpectedSource, [string]$routeDecision.Classification, [string]$routeDecision.RecommendedAction, [double]$routeDecision.DecisionConfidence, (($routeDecision.DecisionFactors -join ';')), [int]$routeLatencyMs)
                        $externalTriggerStartUtc = (Get-Date).ToUniversalTime()
                        $plan = Resolve-ExternalTriggerExecutionPlan -Template $triggerCommandValue -TicketId $ticketId -EventName $eventName -StartFilePath $startFilePath -QueueFilePath $queueFilePath -BriefPath $briefPath
                        $commandResult = Invoke-ExternalTriggerCommand -Plan $plan
                        if ([bool]$commandResult.Started) {
                            $externalTriggerLatencyMs = [int][Math]::Max(0, [Math]::Round(((Get-Date).ToUniversalTime() - $externalTriggerStartUtc).TotalMilliseconds))
                            Write-TriggerLog ("external_trigger_started id={0} pid={1} route_class={2} latency_ms={3}" -f $ticketId, [int]$commandResult.ProcessId, [string]$routeDecision.Classification, [int]$externalTriggerLatencyMs)
                        }
                        else {
                            Write-TriggerLog ("external_trigger_failed id={0} detail={1} template={2}" -f $ticketId, [string]$commandResult.Reason, (Convert-ToSingleLineText -Text ([string]$plan.Summary)))
                        }
                    }
                }
                else {
                    Write-TriggerLog ("external_trigger_skipped id={0} reason=execution-disabled" -f $ticketId)
                }
            }

            $processedSet[$ticketId] = $true
            [void]$processedIds.Add($ticketId)
            $newCount++
        }

        $queueLastLineRead = [Math]::Max($queueLastLineRead, $maxObservedQueueLineNo)

        if ($startFileMismatchCount -gt 0) {
            Write-TriggerLog ("ticket_skip_summary reason=start-file-filter count={0} start_file={1}" -f $startFileMismatchCount, (Convert-ToRepoRelativePath -Path $startFilePath))
        }

        if ($MaxProcessedIds -gt 0) {
            while ($processedIds.Count -gt $MaxProcessedIds) {
                $oldId = [string]$processedIds[0]
                $processedIds.RemoveAt(0)
                if ($processedSet.Contains($oldId)) {
                    $processedSet.Remove($oldId) | Out-Null
                }
            }
        }

        $state = [ordered]@{
            schema = 'AB_TAKEOVER_TRIGGER_STATE_V2'
            updated_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
            start_file = (Convert-ToRepoRelativePath -Path $startFilePath)
            queue_path = (Convert-ToRepoRelativePath -Path $queueFilePath)
            trigger_skip_existing_queue_on_start = [bool]$skipExistingQueueOnStart
            queue_last_line_read = [int]$queueLastLineRead
            processed_ids = @($processedIds)
            chat_recovery_last_trigger_at = $chatRecoveryLastTriggerAt
            chat_recovery_last_signature = $chatRecoveryLastSignature
            chat_recovery_trigger_count = [int]$chatRecoveryTriggerCount
            chat_recovery_last_fast_retry_signature = $chatRecoveryLastFastRetrySignature
            chat_recovery_last_fast_retry_at = $chatRecoveryLastFastRetryAt
            chat_recovery_fast_retry_count = [int]$chatRecoveryFastRetryCount
            chat_recovery_last_run_reason = $chatRecoveryRunReason
            chat_recovery_enabled = [bool]$chatAutoRecoverEnabled
            chat_recovery_fast_retry_enabled = [bool]$chatRecoveryFastRetryEnabled
            chat_recovery_fast_retry_seconds = [int]$chatRecoveryFastRetrySeconds
            chat_recovery_watch_expected = [bool]$watchExpectation.watch_expected
            chat_heartbeat_enabled = [bool]$chatHeartbeatEnabled
            chat_heartbeat_path = (Convert-ToRepoRelativePath -Path $chatHeartbeatPath)
            chat_heartbeat_updated_at = [string]$chatHeartbeatState.updated_at
            chat_heartbeat_age_seconds = [int]$chatHeartbeatState.age_seconds
            chat_heartbeat_stale = [bool]$chatHeartbeatState.stale
            chat_heartbeat_reason = [string]$chatHeartbeatState.reason
            trigger_event_driven_queue = [bool]$eventDrivenQueue
            final_stop_gate = [string]$finalStopGateMode
        }
        $stateWriteOk = Write-JsonFileSafely -Path $statePath -Value $state
        if (-not $stateWriteOk) {
            Write-TriggerLog ("state_write_skip reason=state-file-in-use path={0}" -f (Convert-ToRepoRelativePath -Path $statePath))
        }
        $stateRaw = $state

        if ($Once.IsPresent) {
            break
        }

        $effectivePollSec = $PollSec
        if ($null -ne $fastPollUntilUtc) {
            $nowUtc = (Get-Date).ToUniversalTime()
            if ($nowUtc -lt $fastPollUntilUtc) {
                $effectivePollSec = [Math]::Min([int]$PollSec, 5)
            }
            else {
                Write-TriggerLog ("fast_poll_window_close reason={0}" -f $fastPollReason)
                $fastPollUntilUtc = $null
                $fastPollReason = ''
            }
        }

        $wakeReason = Wait-QueueSignalOrTimeout -QueueFilePath $waitQueuePath -TimeoutSec $effectivePollSec -EnableEventDriven $eventDrivenQueue
        if ($wakeReason -ne 'timer') {
            Write-TriggerLog ("wake reason={0} queue={1}" -f $wakeReason, (Convert-ToRepoRelativePath -Path $waitQueuePath))
        }

        continue
    }
    catch {
        $errorDetail = Convert-ToSingleLineText -Text $_.Exception.Message
        $errorType = if ($null -ne $_.Exception) { [string]$_.Exception.GetType().FullName } else { 'unknown' }
        $errorPos = Convert-ToSingleLineText -Text $_.InvocationInfo.PositionMessage
        Write-TriggerLog ("loop_error type={0} detail={1} pos={2}" -f $errorType, $errorDetail, $errorPos)
        if ($Once.IsPresent) {
            break
        }
    }

    $effectivePollSec = $PollSec
    if ($null -ne $fastPollUntilUtc) {
        $nowUtc = (Get-Date).ToUniversalTime()
        if ($nowUtc -lt $fastPollUntilUtc) {
            $effectivePollSec = [Math]::Min([int]$PollSec, 5)
        }
        else {
            Write-TriggerLog ("fast_poll_window_close reason={0}" -f $fastPollReason)
            $fastPollUntilUtc = $null
            $fastPollReason = ''
        }
    }

    $wakeReason = Wait-QueueSignalOrTimeout -QueueFilePath $waitQueuePath -TimeoutSec $effectivePollSec -EnableEventDriven $eventDrivenQueue
    if ($wakeReason -ne 'timer') {
        Write-TriggerLog ("wake reason={0} queue={1}" -f $wakeReason, (Convert-ToRepoRelativePath -Path $waitQueuePath))
    }
}

Write-TriggerLog 'shutdown'
Write-TriggerLog ("shutdown_pid pid={0}" -f $PID)
if ($script:InstanceMutex -is [System.Threading.Mutex]) {
    try {
        $script:InstanceMutex.ReleaseMutex() | Out-Null
    }
    catch {
        $null = $_
    }
    finally {
        $script:InstanceMutex.Dispose()
    }
}

exit 0

