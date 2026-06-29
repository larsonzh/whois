param(
    [Parameter(Mandatory = $true)][string]$StartFile,
    [ValidateRange(15, 300)][int]$PollSec = 60,
    [ValidateRange(0, 10)][int]$MaxBRecoveryAttempts = 2,
    [ValidateRange(1, 180)][int]$RecoveryCooldownMinutes = 10,
    [bool]$StopOnBudgetExhausted = $true
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'unattended_exit_result.ps1')
$script:UnhandledExitTag = 'UNATTENDED-AB-SESSION-GUARD'

trap {
    $exitCode = Get-UnattendedExitCodeFromRecord -Tag $script:UnhandledExitTag -Record $_ -DefaultExitCode 1
    Write-UnattendedUnhandledResult -Tag $script:UnhandledExitTag -Record $_ -ExitCode $exitCode
    exit $exitCode
}

$pathGuardModulePath = Join-Path $PSScriptRoot 'path_write_guard.ps1'
if (-not (Test-Path -LiteralPath $pathGuardModulePath)) {
    throw "Missing script: $pathGuardModulePath"
}
. $pathGuardModulePath



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
    param([AllowEmptyString()][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return ''
    }

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return [System.IO.Path]::GetFullPath($Path)
    }

    return [System.IO.Path]::GetFullPath((Join-Path $script:RepoRoot $Path))
}

function Convert-ToRepoRelativePath {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return ''
    }

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $repoRootFull = [System.IO.Path]::GetFullPath($script:RepoRoot)
    if ($fullPath.StartsWith($repoRootFull, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $fullPath.Substring($repoRootFull.Length).TrimStart('\\').Replace('\\', '/')
    }

    return $Path.Replace('\\', '/')
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

    $singleLine = (($Text -split "`r?`n") -join ' ')
    return ([regex]::Replace($singleLine, '\s+', ' ')).Trim()
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

function Get-FilteredRuntimeTailLineList {
    param([string[]]$Lines)

    $filtered = New-Object 'System.Collections.Generic.List[string]'
    foreach ($record in @($Lines)) {
        $line = Convert-ToSingleLineText -Text ([string]$record)
        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }

        if ($line -match '^\*{8,}') {
            continue
        }

        if ($line -imatch '^windows powershell transcript (start|end)$' -or
            $line -imatch '^start time:' -or
            $line -imatch '^end time:' -or
            $line -imatch '^username:' -or
            $line -imatch '^runas user:' -or
            $line -imatch '^machine:' -or
            $line -imatch '^host application:' -or
            $line -imatch '^process id:' -or
            $line -imatch '^psversion:' -or
            $line -imatch '^serializationversion:' -or
            $line -imatch '^wsman stack version:') {
            continue
        }

        [void]$filtered.Add($line)
    }

    return @($filtered)
}

function Get-StartFileMutexName {
    param(
        [string]$Role,
        [string]$StartFilePath
    )

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
    return "Local\whois-unattended-{0}-{1}" -f $Role, $hash
}

function Lock-InstanceMutex {
    param(
        [string]$Role,
        [string]$StartFilePath
    )

    $name = Get-StartFileMutexName -Role $Role -StartFilePath $StartFilePath
    $mutex = New-Object System.Threading.Mutex($false, $name)
    $acquired = $false
    try {
        try {
            $acquired = $mutex.WaitOne(0)
        }
        catch [System.Threading.AbandonedMutexException] {
            $acquired = $true
        }

        if (-not $acquired) {
            Write-Output "[AB-SESSION-GUARD] single_instance_conflict mutex=$name start_file=$StartFilePath"
            $mutex.Dispose()
            throw 'Another unattended_ab_session_guard instance is already active for this start file'
        }
    }
    catch {
        if (-not $acquired -and $null -ne $mutex) {
            try { $mutex.Dispose() } catch { Write-Verbose ("Suppressed exception: {0}" -f $_.Exception.Message) }
        }
        throw
    }

    return $mutex
}

function Read-KeyValueFile {
    param([string]$Path)

    $maxAttempts = 8
    $lines = @()
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        try {
            $lines = @(Get-Content -LiteralPath $Path -Encoding utf8 -ErrorAction Stop)
            break
        }
        catch {
            if ($attempt -eq $maxAttempts) {
                throw
            }

            $delayMs = switch ($attempt) {
                1 { 50 }
                2 { 100 }
                3 { 200 }
                4 { 400 }
                default { 800 }
            }
            Start-Sleep -Milliseconds $delayMs
        }
    }

    $keyLineMap = @{}
    $map = [ordered]@{}
    $lineNo = 0
    foreach ($line in $lines) {
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

    $mutex = New-Object System.Threading.Mutex($false, (Get-StartFileMutexName -Role 'startfile-write' -StartFilePath $Path))
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

        $maxAttempts = 8
        $sourceLines = @()
        for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
            try {
                $sourceLines = @(Get-Content -LiteralPath $Path -Encoding utf8 -ErrorAction Stop)
                break
            }
            catch {
                if ($attempt -eq $maxAttempts) {
                    throw
                }

                $delayMs = switch ($attempt) {
                    1 { 50 }
                    2 { 100 }
                    3 { 200 }
                    4 { 400 }
                    default { 800 }
                }
                Start-Sleep -Milliseconds $delayMs
            }
        }

        $seenKeys = @{}
        $lineNo = 0
        foreach ($line in $sourceLines) {
            $lineNo++
            if ($line -match '^([^=]+)=(.*)$') {
                $key = $Matches[1].Trim()
                if ($seenKeys.ContainsKey($key)) {
                    throw ("Duplicate key '{0}' detected in {1} at line {2} and line {3}." -f $key, $Path, [int]$seenKeys[$key], $lineNo)
                }

                $seenKeys[$key] = $lineNo
            }
        }

        $lines = New-Object 'System.Collections.Generic.List[string]'
        foreach ($line in $sourceLines) {
            [void]$lines.Add([string]$line)
        }

        foreach ($key in $Values.Keys) {
            $prefix = "$key="
            $found = $false
            for ($index = 0; $index -lt $lines.Count; $index++) {
                if ($lines[$index].StartsWith($prefix, [System.StringComparison]::Ordinal)) {
                    $lines[$index] = $prefix + [string]$Values[$key]
                    $found = $true
                    break
                }
            }

            if (-not $found) {
                [void]$lines.Add($prefix + [string]$Values[$key])
            }
        }

        for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
            try {
                $tempPath = "$Path.tmp.$PID.$([guid]::NewGuid().ToString('N'))"
                $normalizedLines = @($lines | ForEach-Object { [string]$_ })
                $text = [string]::Join("`n", $normalizedLines)
                if ($normalizedLines.Count -gt 0) {
                    $text += "`n"
                }
                [System.IO.File]::WriteAllText($tempPath, $text, [System.Text.UTF8Encoding]::new($true))
                Move-Item -LiteralPath $tempPath -Destination $Path -Force
                $tempPath = ''
                break
            }
            catch {
                if (-not [string]::IsNullOrWhiteSpace($tempPath) -and (Test-Path -LiteralPath $tempPath)) {
                    Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue
                    $tempPath = ''
                }

                if ($attempt -eq $maxAttempts) {
                    throw
                }

                $delayMs = switch ($attempt) {
                    1 { 50 }
                    2 { 100 }
                    3 { 200 }
                    4 { 400 }
                    default { 800 }
                }
                Start-Sleep -Milliseconds $delayMs
            }
        }
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

function Add-DelimitedNote {
    param(
        [AllowEmptyString()][string]$Existing,
        [AllowEmptyString()][string]$Append
    )

    if ([string]::IsNullOrWhiteSpace($Append)) {
        return $Existing
    }

    if ([string]::IsNullOrWhiteSpace($Existing)) {
        return $Append.Trim()
    }

    return ($Existing.TrimEnd() + '; ' + $Append.Trim())
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

function Resolve-RunDirAnchorFromNotes {
    param([AllowEmptyString()][string]$Notes)

    if ([string]::IsNullOrWhiteSpace($Notes)) {
        return ''
    }

    $runDirAnchor = Get-LatestAnchorValueFromNoteText -Notes $Notes -Key 'b_run_dir'
    if ([string]::IsNullOrWhiteSpace($runDirAnchor)) {
        $runDirAnchor = Get-LatestAnchorValueFromNoteText -Notes $Notes -Key 'run_dir'
    }
    if ([string]::IsNullOrWhiteSpace($runDirAnchor)) {
        $runDirAnchor = Get-LatestAnchorValueFromNoteText -Notes $Notes -Key 'a_run_dir'
    }

    return (Convert-ToSingleLineText -Text $runDirAnchor)
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

function Copy-FileIfPresent {
    param(
        [AllowEmptyString()][string]$Source,
        [string]$Destination
    )

    if ([string]::IsNullOrWhiteSpace($Source)) {
        return
    }

    if (-not (Test-Path -LiteralPath $Source)) {
        return
    }

    $parent = Split-Path -Parent $Destination
    if (-not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }

    Copy-Item -LiteralPath $Source -Destination $Destination -Force
}

function Export-FileTail {
    param(
        [AllowEmptyString()][string]$Source,
        [string]$Destination,
        [ValidateRange(1, 2000)][int]$Tail = 400
    )

    if ([string]::IsNullOrWhiteSpace($Source)) {
        return
    }

    if (-not (Test-Path -LiteralPath $Source)) {
        return
    }

    $parent = Split-Path -Parent $Destination
    if (-not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }

    $tailLines = @((Get-Content -LiteralPath $Source -Tail $Tail -ErrorAction SilentlyContinue) | ForEach-Object { [string]$_ })
    $tailText = [string]::Join("`n", $tailLines)
    if ($tailLines.Count -gt 0) {
        $tailText += "`n"
    }
    [System.IO.File]::WriteAllText($Destination, $tailText, [System.Text.UTF8Encoding]::new($false))
}

function Write-GuardLog {
    param([string]$Message)

    $line = "[AB-SESSION-GUARD] timestamp={0} {1}" -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'), $Message
    Write-Host $line
    try {
        Add-Content -LiteralPath $script:GuardLogPath -Value $line -Encoding utf8
    }
    catch {
        Write-Warning ("[AB-SESSION-GUARD] log_write_failed path={0}" -f $script:GuardLogPath)
    }
}

function Write-GuardRawLine {
    param([string]$Message)

    if ([string]::IsNullOrWhiteSpace($Message)) {
        return
    }

    Write-Host $Message
    try {
        Add-Content -LiteralPath $script:GuardLogPath -Value $Message -Encoding utf8
    }
    catch {
        Write-Warning ("[AB-SESSION-GUARD] log_write_failed path={0}" -f $script:GuardLogPath)
    }
}

function Write-GuardPastedBlock {
    param(
        [string]$Tag,
        [string[]]$Lines,
        [ValidateRange(12, 160)][int]$SeparatorWidth = 72
    )

    if ([string]::IsNullOrWhiteSpace($Tag)) {
        $Tag = 'guard_paste_block'
    }

    $normalized = @(
        @($Lines) |
            ForEach-Object { Convert-ToSingleLineText -Text ([string]$_) } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    )
    if ($normalized.Count -lt 1) {
        return
    }

    $separator = ('-' * $SeparatorWidth)
    Write-GuardLog ("{0}_begin" -f $Tag)
    Write-GuardRawLine -Message $separator
    foreach ($entry in $normalized) {
        Write-GuardLog ("{0} {1}" -f $Tag, $entry)
    }
    Write-GuardRawLine -Message $separator
    Write-GuardLog ("{0}_end" -f $Tag)
}

function Write-GuardState {
    param([hashtable]$Values)

    foreach ($key in $Values.Keys) {
        $script:GuardState[$key] = $Values[$key]
    }
    $script:GuardState.updated_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')

    $json = $script:GuardState | ConvertTo-Json -Depth 8
    $maxAttempts = 8
    $writeSucceeded = $false
    $lastError = ''

    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        try {
            $normalizedJson = [string]$json -replace "`r`n", "`n"
            [System.IO.File]::WriteAllText($script:GuardStatePath, $normalizedJson, [System.Text.UTF8Encoding]::new($false))
            $writeSucceeded = $true
            break
        }
        catch {
            $lastError = Convert-ToSingleLineText -Text $_.Exception.Message
            if ($attempt -lt $maxAttempts) {
                $delayMs = switch ($attempt) {
                    1 { 40 }
                    2 { 80 }
                    3 { 120 }
                    4 { 200 }
                    5 { 300 }
                    default { 500 }
                }
                Start-Sleep -Milliseconds $delayMs
            }
        }
    }

    if ($writeSucceeded) {
        if (($script:GuardStateWriteFailureCount -as [int]) -gt 0) {
            Write-GuardLog ("state_write_recovered path={0} suppressed_failures={1}" -f $script:GuardStatePath, [int]$script:GuardStateWriteFailureCount)
            $script:GuardStateWriteFailureCount = 0
            $script:GuardStateWriteFailureSignature = ''
            $script:GuardStateWriteFailureLastReportAt = [datetime]::MinValue
        }
        return
    }

    $script:GuardStateWriteFailureCount = ([int]$script:GuardStateWriteFailureCount) + 1
    $signature = "{0}|{1}" -f $script:GuardStatePath, $lastError
    $now = Get-Date
    $shouldReport = $false

    if ($signature -ne [string]$script:GuardStateWriteFailureSignature) {
        $shouldReport = $true
    }
    elseif ($script:GuardStateWriteFailureLastReportAt -eq [datetime]::MinValue) {
        $shouldReport = $true
    }
    elseif ((($now - $script:GuardStateWriteFailureLastReportAt).TotalSeconds) -ge 120) {
        $shouldReport = $true
    }

    if ($shouldReport) {
        $script:GuardStateWriteFailureSignature = $signature
        $script:GuardStateWriteFailureLastReportAt = $now
        Write-Warning ("[AB-SESSION-GUARD] state_write_failed path={0} detail={1} failure_count={2}" -f $script:GuardStatePath, $lastError, [int]$script:GuardStateWriteFailureCount)
    }
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

    return (Resolve-RepoPathAllowMissing -Path $rawPath)
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

function Add-AgentTicket {
    param(
        [bool]$Enabled,
        [AllowEmptyString()][string]$QueuePath,
        [string]$EventName,
        [string]$Severity,
        [bool]$RequiresConfirmation,
        [AllowEmptyString()][string]$SessionStatus,
        [AllowEmptyString()][string]$AStatus,
        [AllowEmptyString()][string]$BStatus,
        [AllowEmptyString()][string]$RunDirAnchor,
        [AllowEmptyString()][string]$IncidentDir,
        [AllowEmptyString()][string]$Detail,
        [AllowEmptyString()][string]$DedupSuffix,
        [AllowEmptyString()][string]$RecommendedAction,
        [AllowEmptyString()][string]$PreferredStage = '',
        [AllowEmptyString()][string]$MainRound = '',
        [AllowEmptyString()][string]$FailureKind = '',
        [AllowEmptyString()][string]$FailureCategory = '',
        [AllowEmptyString()][string]$FailureSource = '',
        [AllowEmptyString()][string]$FailureEvidence = '',
        [bool]$SelfHealable = $false,
        [bool]$NonRecoverableEnv = $false
    )

    $result = [ordered]@{
        Queued = $false
        TicketId = ''
        Reason = ''
        QueuePath = ''
    }

    if (-not $Enabled) {
        $result.Reason = 'queue-disabled'
        return [pscustomobject]$result
    }

    $resolvedQueuePath = Resolve-RepoPathAllowMissing -Path $QueuePath
    if ([string]::IsNullOrWhiteSpace($resolvedQueuePath)) {
        $result.Reason = 'queue-path-empty'
        return [pscustomobject]$result
    }

    $detailCompact = Convert-ToBoundedSingleLineText -Text $Detail -MaxChars 360
    $incidentRel = ''
    if (-not [string]::IsNullOrWhiteSpace($IncidentDir)) {
        $incidentRel = Convert-ToRepoRelativePath -Path $IncidentDir
    }
    $eventCompact = Convert-ToSingleLineText -Text $EventName
    $recommendedActionMaxChars = if ($eventCompact.ToLowerInvariant() -eq 'running-status-report') { 2000 } else { 280 }

    $signature = "{0}|{1}|{2}|{3}|{4}|{5}|{6}|{7}" -f
        $eventCompact,
        (Convert-ToSingleLineText -Text $SessionStatus),
        (Convert-ToSingleLineText -Text $AStatus),
        (Convert-ToSingleLineText -Text $BStatus),
        (Convert-ToSingleLineText -Text $RunDirAnchor),
        (Convert-ToSingleLineText -Text $incidentRel),
        (Convert-ToSingleLineText -Text $detailCompact),
        (Convert-ToSingleLineText -Text $DedupSuffix)

    if ($signature -eq [string]$script:AgentTicketLastSignature) {
        $result.Reason = 'duplicate-signature'
        $result.TicketId = [string]$script:AgentTicketLastId
        $result.QueuePath = (Convert-ToRepoRelativePath -Path $resolvedQueuePath)
        return [pscustomobject]$result
    }

    $ticketId = ("T{0}-{1}" -f (Get-Date).ToString('yyyyMMdd-HHmmssfff'), ([System.Guid]::NewGuid().ToString('N').Substring(0, 8)))
    $ticket = [ordered]@{
        schema = 'AB_AGENT_TICKET_V1'
        ticket_id = $ticketId
        created_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        source = 'unattended_ab_session_guard'
        event = $eventCompact
        severity = (Convert-ToSingleLineText -Text $Severity)
        requires_confirmation = [bool]$RequiresConfirmation
        confirmation_key = if ($RequiresConfirmation) { 'LOCAL_GUARD_RESTART_APPROVED' } else { '' }
        start_file = (Convert-ToRepoRelativePath -Path $script:StartFilePath)
        guard_log = (Convert-ToRepoRelativePath -Path $script:GuardLogPath)
        guard_state = (Convert-ToRepoRelativePath -Path $script:GuardStatePath)
        queue_path = (Convert-ToRepoRelativePath -Path $resolvedQueuePath)
        session_final_status = (Convert-ToSingleLineText -Text $SessionStatus)
        a_final_status = (Convert-ToSingleLineText -Text $AStatus)
        b_final_status = (Convert-ToSingleLineText -Text $BStatus)
        run_dir = (Convert-ToSingleLineText -Text $RunDirAnchor)
        incident_dir = (Convert-ToSingleLineText -Text $incidentRel)
        detail = $detailCompact
        recommended_action = (Convert-ToBoundedSingleLineText -Text $RecommendedAction -MaxChars $recommendedActionMaxChars)
        preferred_stage = (Convert-ToSingleLineText -Text $PreferredStage).ToUpperInvariant()
        main_round = (Convert-ToSingleLineText -Text $MainRound).ToUpperInvariant()
        failure_kind = (Convert-ToSingleLineText -Text $FailureKind).ToLowerInvariant()
        failure_category = (Convert-ToSingleLineText -Text $FailureCategory).ToLowerInvariant()
        failure_source = (Convert-ToSingleLineText -Text $FailureSource)
        failure_evidence = (Convert-ToBoundedSingleLineText -Text $FailureEvidence -MaxChars 260)
        self_healable = [bool]$SelfHealable
        non_recoverable_env = [bool]$NonRecoverableEnv
        dedup_signature = $signature
    }

    $line = $ticket | ConvertTo-Json -Compress -Depth 8
    $appendOk = Write-JsonLineWithRetry -Path $resolvedQueuePath -Line $line
    if (-not $appendOk) {
        $result.Reason = 'queue-write-failed'
        $result.QueuePath = (Convert-ToRepoRelativePath -Path $resolvedQueuePath)
        Write-GuardLog ("agent_ticket_write_failed event={0} queue={1}" -f $ticket.event, $result.QueuePath)
        return [pscustomobject]$result
    }

    $script:AgentTicketLastSignature = $signature
    $script:AgentTicketLastId = $ticketId
    $script:AgentTicketLastEvent = [string]$ticket.event

    $result.Queued = $true
    $result.TicketId = $ticketId
    $result.Reason = 'queued'
    $result.QueuePath = (Convert-ToRepoRelativePath -Path $resolvedQueuePath)
    Write-GuardLog ("agent_ticket_queued id={0} event={1} severity={2} queue={3}" -f $ticketId, $ticket.event, $ticket.severity, $result.QueuePath)
    return [pscustomobject]$result
}

function Get-MonitorChainShutdownRequest {
    param([System.Collections.IDictionary]$Settings)

    $requestedRaw = ''
    $reason = ''
    $source = ''
    $requestedAt = ''
    $detail = ''

    if ($null -ne $Settings) {
        if ($Settings.Contains('MONITOR_CHAIN_SHUTDOWN_REQUESTED')) {
            $requestedRaw = [string]$Settings.MONITOR_CHAIN_SHUTDOWN_REQUESTED
        }
        if ($Settings.Contains('MONITOR_CHAIN_SHUTDOWN_REASON')) {
            $reason = Convert-ToSingleLineText -Text ([string]$Settings.MONITOR_CHAIN_SHUTDOWN_REASON)
        }
        if ($Settings.Contains('MONITOR_CHAIN_SHUTDOWN_SOURCE')) {
            $source = Convert-ToSingleLineText -Text ([string]$Settings.MONITOR_CHAIN_SHUTDOWN_SOURCE)
        }
        if ($Settings.Contains('MONITOR_CHAIN_SHUTDOWN_AT')) {
            $requestedAt = Convert-ToSingleLineText -Text ([string]$Settings.MONITOR_CHAIN_SHUTDOWN_AT)
        }
        if ($Settings.Contains('MONITOR_CHAIN_SHUTDOWN_DETAIL')) {
            $detail = Convert-ToBoundedSingleLineText -Text ([string]$Settings.MONITOR_CHAIN_SHUTDOWN_DETAIL) -MaxChars 220
        }
    }

    return [pscustomobject]@{
        Requested = (Convert-ToBooleanSetting -Value $requestedRaw -Default $false)
        Reason = $reason
        Source = $source
        RequestedAt = $requestedAt
        Detail = $detail
    }
}

function Request-MonitorChainShutdown {
    param(
        [System.Collections.IDictionary]$Settings,
        [string]$Reason,
        [string]$Source,
        [AllowEmptyString()][string]$Detail
    )

    $existing = Get-MonitorChainShutdownRequest -Settings $Settings
    if ([bool]$existing.Requested) {
        Write-GuardLog ("monitor_chain_shutdown_request already_set reason={0} source={1} at={2}" -f [string]$existing.Reason, [string]$existing.Source, [string]$existing.RequestedAt)
        return $Settings
    }

    $reasonCompact = Convert-ToSingleLineText -Text $Reason
    if ([string]::IsNullOrWhiteSpace($reasonCompact)) {
        $reasonCompact = 'guard-requested'
    }

    $sourceCompact = Convert-ToSingleLineText -Text $Source
    if ([string]::IsNullOrWhiteSpace($sourceCompact)) {
        $sourceCompact = 'unattended_ab_session_guard'
    }

    $detailCompact = Convert-ToBoundedSingleLineText -Text $Detail -MaxChars 280
    $updates = @{
        MONITOR_CHAIN_SHUTDOWN_REQUESTED = 'true'
        MONITOR_CHAIN_SHUTDOWN_REASON = $reasonCompact
        MONITOR_CHAIN_SHUTDOWN_SOURCE = $sourceCompact
        MONITOR_CHAIN_SHUTDOWN_AT = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        MONITOR_CHAIN_SHUTDOWN_KEEP_WINDOW = 'true'
    }
    if (-not [string]::IsNullOrWhiteSpace($detailCompact)) {
        $updates['MONITOR_CHAIN_SHUTDOWN_DETAIL'] = $detailCompact
    }

    Invoke-KeyValueFileValueUpdate -Path $script:StartFilePath -Values $updates
    Write-GuardLog ("monitor_chain_shutdown_request applied reason={0} source={1} detail={2}" -f $reasonCompact, $sourceCompact, $detailCompact)
    return (Read-KeyValueFile -Path $script:StartFilePath)
}

function Get-StatusValue {
    param([AllowEmptyString()][string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return 'NOT_RUN'
    }

    return $Value.Trim().ToUpperInvariant()
}

function Convert-ToNullablePositiveInt {
    param([AllowEmptyString()][string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $null
    }

    $parsed = 0
    if (-not [int]::TryParse($Value.Trim(), [ref]$parsed)) {
        return $null
    }

    if ($parsed -le 0) {
        return $null
    }

    return [int]$parsed
}

function Test-ProcessAlive {
    param([int]$ProcessId)

    if ($ProcessId -le 0) {
        return $false
    }

    try {
        Get-Process -Id $ProcessId -ErrorAction Stop | Out-Null
        return $true
    }
    catch {
        return $false
    }
}

function Get-AStageProcessCandidateList {
    $startFileLeaf = [string]$script:StartFileLeaf
    $candidates = @(
        Get-CimInstance Win32_Process |
            Where-Object {
                $line = [string]$_.CommandLine
                if ([string]::IsNullOrWhiteSpace($line)) {
                    return $false
                }

                $lineLower = $line.ToLowerInvariant()
                if (-not [string]::IsNullOrWhiteSpace($startFileLeaf) -and -not $lineLower.Contains($startFileLeaf)) {
                    return $false
                }

                if ($lineLower.Contains('unattended_ab_supervisor.ps1') -or
                    $lineLower.Contains('unattended_ab_companion.ps1') -or
                    $lineLower.Contains('unattended_ab_session_guard.ps1') -or
                    $lineLower.Contains('open_unattended_ab_stage_window.ps1')) {
                    return $false
                }

                return ($lineLower -match 'start_dev_verify_fastmode_a\.ps1|start_dev_verify_8round_multiround\.ps1')
            } |
            Select-Object ProcessId, Name, CreationDate, CommandLine |
            Sort-Object CreationDate, ProcessId -Descending
    )

    return @($candidates)
}

function Get-AStageProcessSnapshot {
    param([int]$ExpectedProcessId)

    $expectedAlive = Test-ProcessAlive -ProcessId $ExpectedProcessId
    $candidates = @(Get-AStageProcessCandidateList)
    $candidateIds = @($candidates | Select-Object -ExpandProperty ProcessId -Unique)

    $resolvedProcessId = 0
    $resolvedSource = 'none'

    if ($expectedAlive -and $ExpectedProcessId -gt 0) {
        $resolvedProcessId = [int]$ExpectedProcessId
        $resolvedSource = 'expected'
    }
    elseif ($candidateIds.Count -eq 1) {
        $resolvedProcessId = [int]$candidateIds[0]
        $resolvedSource = 'single-candidate'
    }
    elseif ($candidateIds.Count -gt 1) {
        $resolvedSource = 'ambiguous-candidates'
    }

    $hasAliveProcess = $expectedAlive -or ($candidateIds.Count -gt 0)
    $anchorUpdateRequired = ($resolvedProcessId -gt 0 -and $resolvedProcessId -ne $ExpectedProcessId)

    return [pscustomobject]@{
        ExpectedProcessId = [int]$ExpectedProcessId
        ExpectedAlive = [bool]$expectedAlive
        CandidateCount = [int]$candidateIds.Count
        CandidateIds = @($candidateIds)
        ResolvedProcessId = [int]$resolvedProcessId
        ResolvedSource = [string]$resolvedSource
        HasAliveProcess = [bool]$hasAliveProcess
        AnchorUpdateRequired = [bool]$anchorUpdateRequired
    }
}

function Get-BStageProcessCandidateList {
    $startFileLeaf = [string]$script:StartFileLeaf
    $candidates = @(
        Get-CimInstance Win32_Process |
            Where-Object {
                $line = [string]$_.CommandLine
                if ([string]::IsNullOrWhiteSpace($line)) {
                    return $false
                }

                $lineLower = $line.ToLowerInvariant()
                if (-not [string]::IsNullOrWhiteSpace($startFileLeaf) -and -not $lineLower.Contains($startFileLeaf)) {
                    return $false
                }

                if ($lineLower.Contains('unattended_ab_supervisor.ps1') -or
                    $lineLower.Contains('unattended_ab_companion.ps1') -or
                    $lineLower.Contains('unattended_ab_session_guard.ps1') -or
                    $lineLower.Contains('open_unattended_ab_stage_window.ps1')) {
                    return $false
                }

                return ($lineLower -match 'start_dev_verify_fastmode_b\.ps1|start_dev_verify_8round_multiround\.ps1')
            } |
            Select-Object ProcessId, Name, CreationDate, CommandLine |
            Sort-Object CreationDate, ProcessId -Descending
    )

    return @($candidates)
}

function Get-BStageProcessSnapshot {
    param([int]$ExpectedProcessId)

    $expectedAlive = Test-ProcessAlive -ProcessId $ExpectedProcessId
    $candidates = @(Get-BStageProcessCandidateList)
    $candidateIds = @($candidates | Select-Object -ExpandProperty ProcessId -Unique)

    $resolvedProcessId = 0
    $resolvedSource = 'none'

    if ($expectedAlive -and $ExpectedProcessId -gt 0) {
        $resolvedProcessId = [int]$ExpectedProcessId
        $resolvedSource = 'expected'
    }
    elseif ($candidateIds.Count -eq 1) {
        $resolvedProcessId = [int]$candidateIds[0]
        $resolvedSource = 'single-candidate'
    }
    elseif ($candidateIds.Count -gt 1) {
        $resolvedSource = 'ambiguous-candidates'
    }

    $hasAliveProcess = $expectedAlive -or ($candidateIds.Count -gt 0)
    $anchorUpdateRequired = ($resolvedProcessId -gt 0 -and $resolvedProcessId -ne $ExpectedProcessId)

    return [pscustomobject]@{
        ExpectedProcessId = [int]$ExpectedProcessId
        ExpectedAlive = [bool]$expectedAlive
        CandidateCount = [int]$candidateIds.Count
        CandidateIds = @($candidateIds)
        ResolvedProcessId = [int]$resolvedProcessId
        ResolvedSource = [string]$resolvedSource
        HasAliveProcess = [bool]$hasAliveProcess
        AnchorUpdateRequired = [bool]$anchorUpdateRequired
    }
}

function Get-StageExitReasonArtifactPath {
    param([string]$Stage)

    $stageLower = $Stage.Trim().ToLowerInvariant()
    return (Join-Path $script:RepoRoot (Join-Path 'out\artifacts\ab_stage_exit' ("latest_{0}_exit.json" -f $stageLower)))
}

function Get-BStageExitReasonEvidence {
    param([int]$ExpectedProcessId)

    $artifactPath = Get-StageExitReasonArtifactPath -Stage 'B'
    $result = [ordered]@{
        Available = $false
        ArtifactPath = (Convert-ToRepoRelativePath -Path $artifactPath)
        Stage = 'B'
        ProcessId = 0
        ExitCode = 0
        Result = ''
        FailCategory = ''
        FailReason = ''
        GeneratedAt = ''
        StartFilePath = ''
        RuntimeLogPath = ''
        TaskDefinitionPath = ''
        SourceScript = ''
        StartFileMatch = $false
        ProcessIdMatch = $false
        ParseError = ''
    }

    if (-not (Test-Path -LiteralPath $artifactPath)) {
        return [pscustomobject]$result
    }

    $payload = $null
    try {
        $payloadRaw = Get-Content -LiteralPath $artifactPath -Raw -Encoding utf8 -ErrorAction Stop
        $payload = $payloadRaw | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        $result.ParseError = Convert-ToSingleLineText -Text $_.Exception.Message
        return [pscustomobject]$result
    }

    $result.Available = $true

    if ($payload.PSObject.Properties.Name -contains 'stage') {
        $result.Stage = (Convert-ToSingleLineText -Text ([string]$payload.stage)).ToUpperInvariant()
    }

    if ($payload.PSObject.Properties.Name -contains 'process_id') {
        $parsedPid = Convert-ToNullablePositiveInt -Value ([string]$payload.process_id)
        if ($null -ne $parsedPid) {
            $result.ProcessId = [int]$parsedPid
        }
    }

    if ($payload.PSObject.Properties.Name -contains 'exit_code') {
        $parsedExitCode = 0
        if ([int]::TryParse(([string]$payload.exit_code), [ref]$parsedExitCode)) {
            $result.ExitCode = [int]$parsedExitCode
        }
    }

    if ($payload.PSObject.Properties.Name -contains 'result') {
        $result.Result = (Convert-ToSingleLineText -Text ([string]$payload.result)).ToLowerInvariant()
    }

    if ($payload.PSObject.Properties.Name -contains 'fail_category') {
        $result.FailCategory = Convert-ToSingleLineText -Text ([string]$payload.fail_category)
    }

    if ($payload.PSObject.Properties.Name -contains 'fail_reason') {
        $result.FailReason = Convert-ToSingleLineText -Text ([string]$payload.fail_reason)
    }

    if ($payload.PSObject.Properties.Name -contains 'generated_at') {
        $result.GeneratedAt = Convert-ToSingleLineText -Text ([string]$payload.generated_at)
    }

    $artifactStartFilePath = ''
    if ($payload.PSObject.Properties.Name -contains 'start_file_path') {
        $artifactStartFilePath = Convert-ToSingleLineText -Text ([string]$payload.start_file_path)
        $result.StartFilePath = $artifactStartFilePath
    }

    if ($payload.PSObject.Properties.Name -contains 'runtime_log_path') {
        $result.RuntimeLogPath = Convert-ToSingleLineText -Text ([string]$payload.runtime_log_path)
    }

    if ($payload.PSObject.Properties.Name -contains 'task_definition') {
        $result.TaskDefinitionPath = Convert-ToSingleLineText -Text ([string]$payload.task_definition)
    }

    if ($payload.PSObject.Properties.Name -contains 'source_script') {
        $result.SourceScript = Convert-ToSingleLineText -Text ([string]$payload.source_script)
    }

    if ([string]::IsNullOrWhiteSpace($artifactStartFilePath)) {
        $result.StartFileMatch = $true
    }
    else {
        try {
            $expectedStartFile = [System.IO.Path]::GetFullPath($script:StartFilePath)
            $artifactStartFile = [System.IO.Path]::GetFullPath($artifactStartFilePath)
            $result.StartFileMatch = $artifactStartFile.Equals($expectedStartFile, [System.StringComparison]::OrdinalIgnoreCase)
        }
        catch {
            $result.StartFileMatch = $false
        }
    }

    $result.ProcessIdMatch = ($ExpectedProcessId -gt 0 -and [int]$result.ProcessId -eq $ExpectedProcessId)
    return [pscustomobject]$result
}

function Get-BPassFailConflictEvidence {
    param(
        [System.Collections.IDictionary]$Settings,
        [string]$StartFilePath
    )

    $artifactPath = Get-StageExitReasonArtifactPath -Stage 'B'
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

    $processIdValue = Convert-ToNullablePositiveInt -Value ([string]$payload.process_id)
    if ($null -ne $processIdValue) {
        $result.process_id = [int]$processIdValue
    }

    $expectedProcessId = 0
    if ($null -ne $Settings -and $Settings.Contains('B_LAUNCH_PID')) {
        $parsedExpectedPid = Convert-ToNullablePositiveInt -Value ([string]$Settings.B_LAUNCH_PID)
        if ($null -ne $parsedExpectedPid) {
            $expectedProcessId = [int]$parsedExpectedPid
        }
    }

    if ($expectedProcessId -gt 0) {
        $result.process_id_match = ([int]$result.process_id -eq $expectedProcessId)
    }

    if (-not [bool]$result.process_id_match) {
        $result.reason = 'pid-mismatch'
        return [pscustomobject]$result
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

    $runDirAnchor = Resolve-RunDirAnchorFromNotes -Notes $notes
    $runDirResolved = Resolve-AnchorPath -Path $runDirAnchor

    $result.generated_at = Convert-ToSingleLineText -Text ([string]$payload.generated_at)
    $generatedUtc = [datetime]::MinValue
    $parsedGenerated = [datetime]::TryParse(
        [string]$result.generated_at,
        [System.Globalization.CultureInfo]::InvariantCulture,
        [System.Globalization.DateTimeStyles]::AllowWhiteSpaces -bor [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal,
        [ref]$generatedUtc)
    if (-not $parsedGenerated) {
        $parsedGenerated = [datetime]::TryParse([string]$result.generated_at, [ref]$generatedUtc)
        if ($parsedGenerated) {
            $generatedUtc = $generatedUtc.ToUniversalTime()
        }
    }

    if (-not $parsedGenerated) {
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

function Get-BRuntimeLogHint {
    param(
        [System.Collections.IDictionary]$Settings,
        [AllowEmptyString()][string]$ArtifactRuntimeLogPath
    )

    if (-not [string]::IsNullOrWhiteSpace($ArtifactRuntimeLogPath)) {
        return $ArtifactRuntimeLogPath
    }

    if ($null -ne $Settings -and $Settings.Contains('B_RUNTIME_LOG')) {
        $value = Convert-ToSingleLineText -Text ([string]$Settings.B_RUNTIME_LOG)
        if (-not [string]::IsNullOrWhiteSpace($value)) {
            return $value
        }
    }

    $notes = ''
    if ($null -ne $Settings -and $Settings.Contains('SESSION_FINAL_NOTES')) {
        $notes = [string]$Settings.SESSION_FINAL_NOTES
    }

    $anchor = Get-LatestAnchorValueFromNoteText -Notes $notes -Key 'b_runtime_log'
    if (-not [string]::IsNullOrWhiteSpace($anchor)) {
        return $anchor
    }

    return ''
}

function Get-BRuntimeTailEvidence {
    param(
        [AllowEmptyString()][string]$RuntimeLogPath,
        [ValidateRange(5, 200)][int]$PrimaryTail = 10,
        [ValidateRange(10, 400)][int]$ExpandedTail = 30,
        [ValidateRange(20, 1000)][int]$MaxTail = 80,
        [ValidateRange(1, 50)][int]$MinimumUsefulLines = 6
    )

    $result = [ordered]@{
        Available = $false
        RuntimeLogPath = ''
        UsedTail = 0
        Escalated = $false
        Lines = @()
        Error = ''
    }

    if ([string]::IsNullOrWhiteSpace($RuntimeLogPath)) {
        return [pscustomobject]$result
    }

    $resolvedPath = Resolve-AnchorPath -Path $RuntimeLogPath
    if ([string]::IsNullOrWhiteSpace($resolvedPath)) {
        $result.Error = 'resolve-log-path-failed'
        return [pscustomobject]$result
    }

    $result.RuntimeLogPath = Convert-ToRepoRelativePath -Path $resolvedPath
    if (-not (Test-Path -LiteralPath $resolvedPath)) {
        $result.Error = 'runtime-log-not-found'
        return [pscustomobject]$result
    }

    $tailCandidates = @($PrimaryTail, $ExpandedTail, $MaxTail)
    $bestLines = @()
    $usedTail = $PrimaryTail

    foreach ($tail in $tailCandidates) {
        if ($tail -le 0) {
            continue
        }

        try {
            $rawTail = @(Get-Content -LiteralPath $resolvedPath -Tail $tail -ErrorAction Stop)
            $filteredTail = @(Get-FilteredRuntimeTailLineList -Lines $rawTail)
            if ($filteredTail.Count -eq 0) {
                $filteredTail = @($rawTail | ForEach-Object { Convert-ToSingleLineText -Text ([string]$_) } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
            }

            $bestLines = @($filteredTail)
            $usedTail = $tail

            if ($bestLines.Count -ge $MinimumUsefulLines) {
                break
            }
        }
        catch {
            $result.Error = Convert-ToSingleLineText -Text $_.Exception.Message
            return [pscustomobject]$result
        }
    }

    $result.UsedTail = [int]$usedTail
    $result.Escalated = ([int]$usedTail -gt [int]$PrimaryTail)
    $result.Lines = @($bestLines)
    $result.Available = ($bestLines.Count -gt 0)
    return [pscustomobject]$result
}

function Format-AgeMinutesForLog {
    param([double]$AgeMinutes)

    if ([double]::IsNaN($AgeMinutes) -or [double]::IsInfinity($AgeMinutes) -or $AgeMinutes -lt 0) {
        return 'n/a'
    }

    return ([Math]::Round($AgeMinutes, 1).ToString('0.0'))
}

function Get-PathFreshnessEvidence {
    param(
        [AllowEmptyString()][string]$Path,
        [ValidateRange(1, 180)][int]$WindowMinutes = 6
    )

    $result = [ordered]@{
        Exists = $false
        Fresh = $false
        AgeMinutes = -1.0
        Path = ''
        ResolvedPath = ''
    }

    $resolvedPath = Resolve-AnchorPath -Path $Path
    if ([string]::IsNullOrWhiteSpace($resolvedPath)) {
        return [pscustomobject]$result
    }

    $result.ResolvedPath = $resolvedPath
    $result.Path = Convert-ToRepoRelativePath -Path $resolvedPath

    if (-not (Test-Path -LiteralPath $resolvedPath)) {
        return [pscustomobject]$result
    }

    try {
        $item = Get-Item -LiteralPath $resolvedPath -ErrorAction Stop
        $ageMinutes = ((Get-Date) - $item.LastWriteTime).TotalMinutes
        $result.Exists = $true
        $result.AgeMinutes = [double]$ageMinutes
        $result.Fresh = ($ageMinutes -le $WindowMinutes)
    }
    catch { Write-Verbose ("Suppressed exception: {0}" -f $_.Exception.Message) }

    return [pscustomobject]$result
}

function Get-RunDirFreshnessEvidence {
    param(
        [AllowEmptyString()][string]$RunDirPath,
        [ValidateRange(1, 180)][int]$WindowMinutes = 6
    )

    $result = [ordered]@{
        Exists = $false
        Fresh = $false
        AgeMinutes = -1.0
        Path = ''
        ResolvedPath = ''
    }

    $resolvedPath = Resolve-AnchorPath -Path $RunDirPath
    if ([string]::IsNullOrWhiteSpace($resolvedPath)) {
        return [pscustomobject]$result
    }

    $result.ResolvedPath = $resolvedPath
    $result.Path = Convert-ToRepoRelativePath -Path $resolvedPath

    if (-not (Test-Path -LiteralPath $resolvedPath)) {
        return [pscustomobject]$result
    }

    try {
        $latestWriteTime = (Get-Item -LiteralPath $resolvedPath -ErrorAction Stop).LastWriteTime
        $latestFile = $null
        foreach ($file in @(Get-ChildItem -LiteralPath $resolvedPath -File -Recurse -Force -ErrorAction SilentlyContinue)) {
            if ($null -eq $latestFile -or $file.LastWriteTime -gt $latestFile.LastWriteTime) {
                $latestFile = $file
            }
        }

        if ($null -ne $latestFile -and $latestFile.LastWriteTime -gt $latestWriteTime) {
            $latestWriteTime = $latestFile.LastWriteTime
        }

        $ageMinutes = ((Get-Date) - $latestWriteTime).TotalMinutes
        $result.Exists = $true
        $result.AgeMinutes = [double]$ageMinutes
        $result.Fresh = ($ageMinutes -le $WindowMinutes)
    }
    catch { Write-Verbose ("Suppressed exception: {0}" -f $_.Exception.Message) }

    return [pscustomobject]$result
}

function Get-BudgetExhaustedLivenessEvidence {
    param(
        [System.Collections.IDictionary]$Settings,
        [ValidateRange(2, 180)][int]$WindowMinutes = 6,
        [int]$FallbackProcessId = 0
    )

    $notes = ''
    if ($null -ne $Settings -and $Settings.Contains('SESSION_FINAL_NOTES')) {
        $notes = [string]$Settings.SESSION_FINAL_NOTES
    }

    $bLaunchPid = $FallbackProcessId
    if ($null -ne $Settings -and $Settings.Contains('B_LAUNCH_PID')) {
        $parsedPid = Convert-ToNullablePositiveInt -Value ([string]$Settings.B_LAUNCH_PID)
        if ($null -ne $parsedPid) {
            $bLaunchPid = [int]$parsedPid
        }
    }

    $supervisorLogAnchor = Get-LatestAnchorValueFromNoteText -Notes $notes -Key 'supervisor_log'
    $liveStatusAnchor = Get-LatestAnchorValueFromNoteText -Notes $notes -Key 'live_status'
    $runDirAnchor = Resolve-RunDirAnchorFromNotes -Notes $notes
    $runtimeLogHint = Get-BRuntimeLogHint -Settings $Settings -ArtifactRuntimeLogPath ''

    $pidAlive = Test-ProcessAlive -ProcessId $bLaunchPid
    $supervisorFreshness = Get-PathFreshnessEvidence -Path $supervisorLogAnchor -WindowMinutes $WindowMinutes
    $liveStatusFreshness = Get-PathFreshnessEvidence -Path $liveStatusAnchor -WindowMinutes $WindowMinutes
    $runtimeFreshness = Get-PathFreshnessEvidence -Path $runtimeLogHint -WindowMinutes $WindowMinutes
    $runDirFreshness = Get-RunDirFreshnessEvidence -RunDirPath $runDirAnchor -WindowMinutes $WindowMinutes

    $hostFresh = ([bool]$supervisorFreshness.Fresh -or [bool]$liveStatusFreshness.Fresh)
    $artifactFresh = ([bool]$runtimeFreshness.Fresh -or [bool]$runDirFreshness.Fresh)
    $active = ($pidAlive -or ($hostFresh -and $artifactFresh))

    $detail = ("pid={0} pid_alive={1} window_min={2} supervisor_age_min={3} live_status_age_min={4} runtime_age_min={5} run_dir_age_min={6}" -f
        $bLaunchPid,
        $pidAlive,
        $WindowMinutes,
        (Format-AgeMinutesForLog -AgeMinutes [double]$supervisorFreshness.AgeMinutes),
        (Format-AgeMinutesForLog -AgeMinutes [double]$liveStatusFreshness.AgeMinutes),
        (Format-AgeMinutesForLog -AgeMinutes [double]$runtimeFreshness.AgeMinutes),
        (Format-AgeMinutesForLog -AgeMinutes [double]$runDirFreshness.AgeMinutes))

    return [pscustomobject]@{
        Active = [bool]$active
        BLaunchPid = [int]$bLaunchPid
        ProcessAlive = [bool]$pidAlive
        Detail = $detail
    }
}

function Save-IncidentPackage {
    param(
        [System.Collections.IDictionary]$Settings,
        [string]$SessionStatus,
        [string]$AStatus,
        [string]$BStatus
    )

    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $incidentDir = Join-Path $script:GuardOutDir ("incident_" + $stamp)
    New-Item -ItemType Directory -Path $incidentDir -Force | Out-Null

    $notes = if ($Settings.Contains('SESSION_FINAL_NOTES')) { [string]$Settings.SESSION_FINAL_NOTES } else { '' }
    $runDirAnchor = Resolve-RunDirAnchorFromNotes -Notes $notes
    $supervisorLogAnchor = Get-LatestAnchorValueFromNoteText -Notes $notes -Key 'supervisor_log'
    $companionLogAnchor = Get-LatestAnchorValueFromNoteText -Notes $notes -Key 'companion_log'
    $liveStatusAnchor = Get-LatestAnchorValueFromNoteText -Notes $notes -Key 'live_status'

    $runDir = Resolve-AnchorPath -Path $runDirAnchor
    $supervisorLog = Resolve-AnchorPath -Path $supervisorLogAnchor
    $companionLog = Resolve-AnchorPath -Path $companionLogAnchor
    $liveStatus = Resolve-AnchorPath -Path $liveStatusAnchor

    Copy-FileIfPresent -Source $script:StartFilePath -Destination (Join-Path $incidentDir 'start_file_snapshot.md')
    Copy-FileIfPresent -Source $liveStatus -Destination (Join-Path $incidentDir 'live_status.json')
    Export-FileTail -Source $supervisorLog -Destination (Join-Path $incidentDir 'supervisor_tail.log') -Tail 500
    Export-FileTail -Source $companionLog -Destination (Join-Path $incidentDir 'companion_tail.log') -Tail 500

    if (-not [string]::IsNullOrWhiteSpace($runDir) -and (Test-Path -LiteralPath $runDir)) {
        Copy-FileIfPresent -Source (Join-Path $runDir 'final_status.json') -Destination (Join-Path $incidentDir 'run_final_status.json')
        Copy-FileIfPresent -Source (Join-Path $runDir 'final_status.txt') -Destination (Join-Path $incidentDir 'run_final_status.txt')
        Copy-FileIfPresent -Source (Join-Path $runDir 'summary.csv') -Destination (Join-Path $incidentDir 'summary.csv')
        Copy-FileIfPresent -Source (Join-Path $runDir 'summary_partial.csv') -Destination (Join-Path $incidentDir 'summary_partial.csv')
    }

    $startFileLeaf = [System.IO.Path]::GetFileName($script:StartFilePath).ToLowerInvariant()
    $processSnapshot = @(
        Get-CimInstance Win32_Process |
            Where-Object {
                $line = [string]$_.CommandLine
                if ([string]::IsNullOrWhiteSpace($line)) {
                    return $false
                }

                $lineLower = $line.ToLowerInvariant()
                if (-not [string]::IsNullOrWhiteSpace($startFileLeaf) -and -not $lineLower.Contains($startFileLeaf)) {
                    return $false
                }

                return ($lineLower -match 'unattended_ab_|start_dev_verify_fastmode_|start_dev_verify_8round_multiround')
            } |
            Select-Object ProcessId, Name, CreationDate, CommandLine |
            Sort-Object ProcessId
    )
    $processSnapshotJson = (($processSnapshot | ConvertTo-Json -Depth 6) -replace "`r`n", "`n")
    [System.IO.File]::WriteAllText((Join-Path $incidentDir 'process_snapshot.json'), $processSnapshotJson, [System.Text.UTF8Encoding]::new($false))

    $gitStatus = @((& git -C $script:RepoRoot status --short 2>&1) | ForEach-Object { [string]$_ })
    $gitStatusLines = @($gitStatus | ForEach-Object { [string]$_ })
    $gitStatusText = [string]::Join("`n", $gitStatusLines)
    if ($gitStatusLines.Count -gt 0) {
        $gitStatusText += "`n"
    }
    [System.IO.File]::WriteAllText((Join-Path $incidentDir 'git_status_short.txt'), $gitStatusText, [System.Text.UTF8Encoding]::new($false))

    $summary = @(
        "captured_at=$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))",
        "session_status=$SessionStatus",
        "a_status=$AStatus",
        "b_status=$BStatus",
        "run_dir_anchor=$runDirAnchor",
        "supervisor_log_anchor=$supervisorLogAnchor",
        "companion_log_anchor=$companionLogAnchor",
        "live_status_anchor=$liveStatusAnchor"
    )
    $summaryLines = @($summary | ForEach-Object { [string]$_ })
    $summaryText = [string]::Join("`n", $summaryLines)
    if ($summaryLines.Count -gt 0) {
        $summaryText += "`n"
    }
    [System.IO.File]::WriteAllText((Join-Path $incidentDir 'summary.txt'), $summaryText, [System.Text.UTF8Encoding]::new($false))

    return $incidentDir
}

function Invoke-BStageRestart {
    param([int]$Attempt)

    $stageLauncher = Join-Path $script:RepoRoot 'tools\test\open_unattended_ab_stage_window.ps1'
    $powershellPath = Join-Path $PSHOME 'powershell.exe'
    if (-not (Test-Path -LiteralPath $powershellPath)) {
        $powershellPath = 'powershell.exe'
    }

    Write-GuardLog ("restart_begin stage=B attempt={0} launcher={1}" -f $Attempt, (Convert-ToRepoRelativePath -Path $stageLauncher))
    $output = @(& $powershellPath -NoProfile -ExecutionPolicy Bypass -File $stageLauncher -Stage B -StartFile $script:StartFilePath -EnableBMonitorRestart 2>&1 | ForEach-Object { [string]$_ })
    $exitCode = $LASTEXITCODE

    $outputLines = @(
        @($output) |
            ForEach-Object { Convert-ToSingleLineText -Text ([string]$_) } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    )
    if ($outputLines.Count -gt 0) {
        Write-GuardLog ("restart_output_summary attempt={0} lines={1}" -f $Attempt, $outputLines.Count)
        $outputBlockLines = New-Object 'System.Collections.Generic.List[string]'
        [void]$outputBlockLines.Add(("attempt={0}" -f $Attempt))
        foreach ($line in $outputLines) {
            [void]$outputBlockLines.Add(("line={0}" -f $line))
        }
        Write-GuardPastedBlock -Tag 'restart_output_block' -Lines @($outputBlockLines)
    }

    return [pscustomobject]@{
        ExitCode = [int]$exitCode
        Succeeded = ([int]$exitCode -eq 0)
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

function Import-CsvSafely {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) {
        return @()
    }

    try {
        return @(Import-Csv -LiteralPath $Path -ErrorAction Stop)
    }
    catch {
        return @()
    }
}

function Get-PropertyValueOrEmpty {
    param(
        [AllowNull()]$Object,
        [string]$PropertyName
    )

    if ($null -eq $Object -or [string]::IsNullOrWhiteSpace($PropertyName)) {
        return ''
    }

    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($PropertyName)) {
            return [string]$Object[$PropertyName]
        }
        return ''
    }

    if ($Object.PSObject.Properties.Name -contains $PropertyName) {
        return [string]$Object.$PropertyName
    }

    return ''
}

function Get-RoundFailureCategoryFromLogText {
    param(
        [AllowEmptyString()][string]$RunDir,
        [AllowEmptyString()][string]$RoundTag,
        [AllowEmptyString()][string]$AutopilotOutDir
    )

    $result = [ordered]@{
        Category = 'code-or-unknown'
        Evidence = 'no-script-or-network-marker'
        SourceLog = ''
        HasScriptFault = $false
        HasNetworkTransient = $false
        HasCodeFault = $false
    }

    if ([string]::IsNullOrWhiteSpace($RunDir) -or [string]::IsNullOrWhiteSpace($RoundTag)) {
        return [pscustomobject]$result
    }

    $logCandidates = New-Object 'System.Collections.Generic.List[object]'

    $runLogPath = Join-Path $RunDir ($RoundTag + '.log')
    if (Test-Path -LiteralPath $runLogPath) {
        [void]$logCandidates.Add([pscustomobject]@{ Path = $runLogPath; Label = 'run-round-log' })
    }

    if (-not [string]::IsNullOrWhiteSpace($AutopilotOutDir) -and (Test-Path -LiteralPath $AutopilotOutDir)) {
        $autopilotSummaryPath = Join-Path $AutopilotOutDir 'summary.csv'
        $autopilotRows = @(Import-CsvSafely -Path $autopilotSummaryPath)
        foreach ($row in $autopilotRows) {
            $rowRoundTag = Convert-ToSingleLineText -Text ([string](Get-PropertyValueOrEmpty -Object $row -PropertyName 'RoundTag'))
            if ($rowRoundTag -ne $RoundTag) {
                continue
            }

            $noDeltaStdoutLog = Resolve-AnchorPath -Path (Convert-ToSingleLineText -Text ([string](Get-PropertyValueOrEmpty -Object $row -PropertyName 'NoDeltaStdoutLog')))
            if (-not [string]::IsNullOrWhiteSpace($noDeltaStdoutLog) -and (Test-Path -LiteralPath $noDeltaStdoutLog)) {
                [void]$logCandidates.Add([pscustomobject]@{ Path = $noDeltaStdoutLog; Label = 'no-delta-stdout-log' })
            }

            $noDeltaOutDir = Resolve-AnchorPath -Path (Convert-ToSingleLineText -Text ([string](Get-PropertyValueOrEmpty -Object $row -PropertyName 'NoDeltaOutDir')))
            if (-not [string]::IsNullOrWhiteSpace($noDeltaOutDir) -and (Test-Path -LiteralPath $noDeltaOutDir)) {
                $dryRunLogPath = Join-Path $noDeltaOutDir 'oneclick_dryrun.log'
                if (Test-Path -LiteralPath $dryRunLogPath) {
                    [void]$logCandidates.Add([pscustomobject]@{ Path = $dryRunLogPath; Label = 'no-delta-dryrun-log' })
                }
            }

            break
        }
    }

    $scriptFaultRegex = '(?im)(parsererror|unexpectedtoken|propertynotfoundexception|argumentexception|参数类型不匹配|is not recognized as the name of a cmdlet|cannot find path\s+.*\.ps1|所在位置\s+.*\.ps1:\d+|at\s+.*\.ps1:\d+|line:\s*\d+\s*char:\s*\d+)'
    $networkTransientRegex = '(?im)(connect-timeout|timed_out|connection\s+timed\s+out|temporary\s+failure|name\s+or\s+service\s+not\s+known|network\s+is\s+unreachable|connection\s+refused|connection\s+reset|no\s+route\s+to\s+host|eai_again|lookup\s+timeout|%error:201:\s*access\s+denied|rate\s*limit|too\s+many\s+requests|service\s+unavailable)'
    $codeFaultRegex = '(?im)(\[CODE-STEP\]\s+fatal_error=|code-step\s+fatal\s+error|src[\\/].*\.(c|h):\d+:\d+:\s*error:|error\s+C\d{4}\b|undefined\s+reference\s+to|compilation\s+terminated|was\s+not\s+declared\s+in\s+this\s+scope|conflicting\s+types\s+for|redefinition\s+of|no\s+member\s+named|fatal\s+error:\s+.*)'

    $scriptEvidence = ''
    $networkEvidence = ''
    $codeEvidence = ''
    $scriptSourceLog = ''
    $networkSourceLog = ''
    $codeSourceLog = ''

    foreach ($candidate in $logCandidates) {
        $path = [string]$candidate.Path
        if ([string]::IsNullOrWhiteSpace($path) -or -not (Test-Path -LiteralPath $path)) {
            continue
        }

        $text = ''
        try {
            $text = (@(Get-Content -LiteralPath $path -Tail 600 -ErrorAction Stop) -join "`n")
        }
        catch {
            continue
        }

        $scriptMarker = [regex]::Match($text, $scriptFaultRegex)
        if ($scriptMarker.Success) {
            $result.HasScriptFault = $true
            if ([string]::IsNullOrWhiteSpace($scriptEvidence)) {
                $scriptEvidence = Convert-ToBoundedSingleLineText -Text ([string]$scriptMarker.Value) -MaxChars 120
                $scriptSourceLog = Convert-ToRepoRelativePath -Path $path
            }
        }

        $networkMarker = [regex]::Match($text, $networkTransientRegex)
        if ($networkMarker.Success) {
            $result.HasNetworkTransient = $true
            if ([string]::IsNullOrWhiteSpace($networkEvidence)) {
                $networkEvidence = Convert-ToBoundedSingleLineText -Text ([string]$networkMarker.Value) -MaxChars 120
                $networkSourceLog = Convert-ToRepoRelativePath -Path $path
            }
        }

        $codeMarker = [regex]::Match($text, $codeFaultRegex)
        if ($codeMarker.Success) {
            $result.HasCodeFault = $true
            if ([string]::IsNullOrWhiteSpace($codeEvidence)) {
                $codeEvidence = Convert-ToBoundedSingleLineText -Text ([string]$codeMarker.Value) -MaxChars 120
                $codeSourceLog = Convert-ToRepoRelativePath -Path $path
            }
        }
    }

    if ([bool]$result.HasCodeFault -and [bool]$result.HasScriptFault) {
        # Compile/type/link errors take precedence over wrapper script stack traces.
        # Route to code-fix lane to avoid repeatedly misclassifying known compile failures.
        $result.Category = 'code-or-unknown'
        $result.Evidence = ('code={0};script={1}' -f $codeEvidence, $scriptEvidence)
        $result.SourceLog = if (-not [string]::IsNullOrWhiteSpace($codeSourceLog)) { $codeSourceLog } else { $scriptSourceLog }
        return [pscustomobject]$result
    }

    if ([bool]$result.HasScriptFault) {
        $result.Category = 'script-fault'
        $result.Evidence = ('matched={0}' -f $scriptEvidence)
        $result.SourceLog = $scriptSourceLog
        return [pscustomobject]$result
    }

    if ([bool]$result.HasCodeFault) {
        $result.Category = 'code-or-unknown'
        $result.Evidence = ('code={0}' -f $codeEvidence)
        $result.SourceLog = $codeSourceLog
        return [pscustomobject]$result
    }

    if ([bool]$result.HasNetworkTransient) {
        $result.Category = 'noncode-transient'
        $result.Evidence = ('matched={0}' -f $networkEvidence)
        $result.SourceLog = $networkSourceLog
    }

    # Fallback: if no code/script/network markers found, check whether the
    # no-delta attempt compiled successfully (exit_code=0).  If yes, the
    # round failure is NOT a code/compile issue — it is an infrastructure
    # or consistency-check failure (e.g. Step47 preflight mini-regression).
    # Downgrade from default 'code-or-unknown' to 'noncode-transient' so
    # the ticket routes to resume-only instead of code-fix lane.
    if ([string]$result.Category -eq 'code-or-unknown' -and -not [bool]$result.HasCodeFault -and -not [bool]$result.HasScriptFault) {
        $noDeltaCompilePass = $false
        foreach ($candidate in $logCandidates) {
            if ([string]$candidate.Label -eq 'no-delta-stdout-log' -or [string]$candidate.Label -eq 'no-delta-dryrun-log') {
                $checkPath = [string]$candidate.Path
                if (-not [string]::IsNullOrWhiteSpace($checkPath) -and (Test-Path -LiteralPath $checkPath)) {
                    try {
                        if (Select-String -LiteralPath $checkPath -Pattern 'oneclick_end exit_code=0' -Quiet -ErrorAction Stop) {
                            $noDeltaCompilePass = $true
                            break
                        }
                    }
                    catch { }
                }
            }
        }
        if ($noDeltaCompilePass) {
            $result.Category = 'noncode-transient'
            $result.Evidence = 'no-delta-compile-passed-but-round-failed-consistency-check'
            $result.SourceLog = ''
        }
    }

    return [pscustomobject]$result
}

function Get-VerifyFailureCategoryFromLogText {
    param(
        [AllowEmptyString()][string]$RunDir,
        [AllowEmptyString()][string]$RoundTag,
        [AllowEmptyString()][string]$AutopilotOutDir
    )

    return (Get-RoundFailureCategoryFromLogText -RunDir $RunDir -RoundTag $RoundTag -AutopilotOutDir $AutopilotOutDir)
}

function Get-FailureTicketPolicy {
    param(
        [AllowEmptyString()][string]$RunDirAnchor
    )

    $result = [ordered]@{
        Mode = 'default'
        FailedRoundTag = ''
        IsVerifyRound = $false
        IsDevRound = $false
        RunDir = ''
        AutopilotOutDir = ''
        FailureCategory = 'unknown'
        FailureEvidence = ''
        FailureSourceLog = ''
        FailureHasScriptFault = $false
        FailureHasNetworkTransient = $false
        FailureHasCodeFault = $false
        VerifyFailureCategory = 'unknown'
        VerifyFailureEvidence = ''
        VerifyFailureSourceLog = ''
        DevFailureCategory = 'unknown'
        DevFailureEvidence = ''
        DevFailureSourceLog = ''
    }

    $runDir = Resolve-AnchorPath -Path $RunDirAnchor
    if ([string]::IsNullOrWhiteSpace($runDir) -or -not (Test-Path -LiteralPath $runDir)) {
        return [pscustomobject]$result
    }
    $result.RunDir = Convert-ToRepoRelativePath -Path $runDir

    $summaryPath = Join-Path $runDir 'summary.csv'
    $rows = @(Import-CsvSafely -Path $summaryPath)
    $failedVerifyRow = $null
    $failedRoundRow = $null
    foreach ($row in $rows) {
        $phase = (Convert-ToSingleLineText -Text ([string](Get-PropertyValueOrEmpty -Object $row -PropertyName 'Phase'))).ToUpperInvariant()
        $roundTag = Convert-ToSingleLineText -Text ([string](Get-PropertyValueOrEmpty -Object $row -PropertyName 'RoundTag'))
        $roundPass = (Convert-ToSingleLineText -Text ([string](Get-PropertyValueOrEmpty -Object $row -PropertyName 'RoundPass'))).ToLowerInvariant()
        if ([string]::IsNullOrWhiteSpace($roundTag)) {
            continue
        }

        if ([string]::IsNullOrWhiteSpace([string]$result.FailedRoundTag) -and $roundPass -in @('false', '0')) {
            $result.FailedRoundTag = $roundTag
            $failedRoundRow = $row
        }

        if ($phase -eq 'VERIFY' -and $roundTag -match '^V[0-9]+$' -and $roundPass -in @('false', '0')) {
            $failedVerifyRow = $row
            $failedRoundRow = $row
            $result.FailedRoundTag = $roundTag
            break
        }
    }

    $finalStatusPath = Join-Path $runDir 'final_status.json'
    $finalStatus = Read-JsonFileSafely -Path $finalStatusPath
    if ($null -ne $finalStatus -and ($finalStatus.PSObject.Properties.Name -contains 'FailedRoundTags')) {
        foreach ($tag in @($finalStatus.FailedRoundTags)) {
            $roundTag = Convert-ToSingleLineText -Text ([string]$tag)
            if ([string]::IsNullOrWhiteSpace($roundTag)) {
                continue
            }

            if ([string]::IsNullOrWhiteSpace([string]$result.FailedRoundTag)) {
                $result.FailedRoundTag = $roundTag
            }

            if ($roundTag -match '^V[0-9]+$' -and $null -eq $failedVerifyRow) {
                $result.FailedRoundTag = $roundTag
            }
        }
    }

    if (-not [string]::IsNullOrWhiteSpace([string]$result.FailedRoundTag) -and $null -eq $failedRoundRow) {
        foreach ($row in $rows) {
            $rowRoundTag = Convert-ToSingleLineText -Text ([string](Get-PropertyValueOrEmpty -Object $row -PropertyName 'RoundTag'))
            if ($rowRoundTag -eq [string]$result.FailedRoundTag) {
                $failedRoundRow = $row
                break
            }
        }
    }

    $autopilotOutDir = ''
    if ($null -ne $failedRoundRow) {
        $autopilotOutDir = Resolve-AnchorPath -Path (Convert-ToSingleLineText -Text ([string](Get-PropertyValueOrEmpty -Object $failedRoundRow -PropertyName 'AutopilotOutDir')))
    }
    if (-not [string]::IsNullOrWhiteSpace($autopilotOutDir)) {
        $result.AutopilotOutDir = Convert-ToRepoRelativePath -Path $autopilotOutDir
    }

    if ([string]$result.FailedRoundTag -match '^[VD][0-9]+$') {
        $categoryInfo = Get-RoundFailureCategoryFromLogText -RunDir $runDir -RoundTag ([string]$result.FailedRoundTag) -AutopilotOutDir $autopilotOutDir
        $result.FailureCategory = [string]$categoryInfo.Category
        $result.FailureEvidence = [string]$categoryInfo.Evidence
        $result.FailureSourceLog = [string]$categoryInfo.SourceLog
        $result.FailureHasScriptFault = [bool]$categoryInfo.HasScriptFault
        $result.FailureHasNetworkTransient = [bool]$categoryInfo.HasNetworkTransient
        $result.FailureHasCodeFault = [bool]$categoryInfo.HasCodeFault
    }

    if ([string]$result.FailedRoundTag -match '^V[0-9]+$') {
        $result.Mode = 'verify-diagnose-only'
        $result.IsVerifyRound = $true
        $result.VerifyFailureCategory = [string]$result.FailureCategory
        $result.VerifyFailureEvidence = [string]$result.FailureEvidence
        $result.VerifyFailureSourceLog = [string]$result.FailureSourceLog
    }
    elseif ([string]$result.FailedRoundTag -match '^D[0-9]+$') {
        $result.Mode = 'dev-repair-and-restart'
        $result.IsDevRound = $true
        $result.DevFailureCategory = [string]$result.FailureCategory
        $result.DevFailureEvidence = [string]$result.FailureEvidence
        $result.DevFailureSourceLog = [string]$result.FailureSourceLog
    }

    return [pscustomobject]$result
}

function Test-KnownInfraTransientFailurePolicy {
    param([object]$FailurePolicy)

    if ($null -eq $FailurePolicy) {
        return $false
    }

    $failedRoundTag = Convert-ToSingleLineText -Text ([string]$FailurePolicy.FailedRoundTag)
    if ([string]::IsNullOrWhiteSpace($failedRoundTag) -or $failedRoundTag -notmatch '^D[0-9]+$') {
        return $false
    }

    $category = (Convert-ToSingleLineText -Text ([string]$FailurePolicy.DevFailureCategory)).ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($category)) {
        $category = (Convert-ToSingleLineText -Text ([string]$FailurePolicy.FailureCategory)).ToLowerInvariant()
    }
    if ($category -ne 'noncode-transient') {
        return $false
    }

    $evidence = Convert-ToSingleLineText -Text ([string]$FailurePolicy.DevFailureEvidence)
    if ([string]::IsNullOrWhiteSpace($evidence)) {
        $evidence = Convert-ToSingleLineText -Text ([string]$FailurePolicy.FailureEvidence)
    }
    $sourceLog = Convert-ToSingleLineText -Text ([string]$FailurePolicy.DevFailureSourceLog)
    if ([string]::IsNullOrWhiteSpace($sourceLog)) {
        $sourceLog = Convert-ToSingleLineText -Text ([string]$FailurePolicy.FailureSourceLog)
    }

    $composite = ('{0} {1}' -f $evidence, $sourceLog).Trim()
    if ([string]::IsNullOrWhiteSpace($composite)) {
        return $false
    }

    $knownInfraRegex = '(?im)(network_precheck_error|ssh_command_timed_out_after_[0-9]+_seconds|check_dualstack_whois_connectivity|connect-timeout|timed_out|connection\s+timed\s+out|network\s+is\s+unreachable|no\s+route\s+to\s+host|name\s+or\s+service\s+not\s+known|eai_again|whois\s+connectivity|ipv6|ipv4)'
    return [regex]::IsMatch($composite, $knownInfraRegex)
}

function Get-FailureTicketMeta {
    param(
        [object]$FailurePolicy,
        [bool]$KnownInfraTransient = $false,
        [bool]$AutoRecoverB = $false,
        [bool]$RestartApproved = $true,
        [AllowEmptyString()][string]$AStatus = '',
        [AllowEmptyString()][string]$BStatus = ''
    )

    $result = [ordered]@{
        MainRound = ''
        PreferredStage = ''
        FailureKind = 'unknown-failure'
        FailureCategory = 'unknown'
        FailureSource = ''
        FailureEvidence = ''
        SelfHealable = $false
        NonRecoverableEnv = [bool]$KnownInfraTransient
    }

    $normalizedA = Get-StatusValue -Value $AStatus
    $normalizedB = Get-StatusValue -Value $BStatus
    if ($normalizedA -eq 'PASS' -and $normalizedB -in @('FAIL', 'BLOCKED', 'NOT_RUN')) {
        $result.PreferredStage = 'B'
    }
    elseif ($normalizedA -in @('FAIL', 'BLOCKED', 'NOT_RUN')) {
        $result.PreferredStage = 'A'
    }

    if ($null -eq $FailurePolicy) {
        return [pscustomobject]$result
    }

    $roundTag = Convert-ToSingleLineText -Text ([string]$FailurePolicy.FailedRoundTag)
    $result.MainRound = $roundTag.ToUpperInvariant()

    $failureCategory = (Convert-ToSingleLineText -Text ([string]$FailurePolicy.FailureCategory)).ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($failureCategory)) {
        $failureCategory = 'unknown'
    }

    $failureEvidence = Convert-ToSingleLineText -Text ([string]$FailurePolicy.FailureEvidence)
    $failureSource = Convert-ToSingleLineText -Text ([string]$FailurePolicy.FailureSourceLog)

    $taskDefinitionMismatchRegex = '(?im)(task[- ]definition|regex[- ]patch|expected\s+exactly\s+one\s+match,\s*actual\s*=\s*0|replacement\s+likely\s+double-escaped|double-escaped|failonwarnings|check_task_definition_static|static\s+precheck)'
    $compileErrorRegex = '(?im)(error:|compilation\s+terminated|failed\s+to\s+build|build\s+failed|undefined\s+reference|fatal\s+error)'
    $compileWarningRegex = '(?im)(warning:|\bwarning\b)'

    if ([bool]$FailurePolicy.IsVerifyRound) {
        $failureCategory = (Convert-ToSingleLineText -Text ([string]$FailurePolicy.VerifyFailureCategory)).ToLowerInvariant()
        if ([string]::IsNullOrWhiteSpace($failureCategory)) {
            $failureCategory = 'unknown'
        }
        $failureEvidence = Convert-ToSingleLineText -Text ([string]$FailurePolicy.VerifyFailureEvidence)
        $failureSource = Convert-ToSingleLineText -Text ([string]$FailurePolicy.VerifyFailureSourceLog)
        $verifyComposite = ('{0} {1}' -f $failureEvidence, $failureSource)
        if ([regex]::IsMatch($verifyComposite, $taskDefinitionMismatchRegex)) {
            $result.FailureKind = 'task-definition-mismatch'
        }
        else {
            $result.FailureKind = 'verify-failure'
        }
    }
    elseif ([bool]$FailurePolicy.IsDevRound) {
        $failureCategory = (Convert-ToSingleLineText -Text ([string]$FailurePolicy.DevFailureCategory)).ToLowerInvariant()
        if ([string]::IsNullOrWhiteSpace($failureCategory)) {
            $failureCategory = (Convert-ToSingleLineText -Text ([string]$FailurePolicy.FailureCategory)).ToLowerInvariant()
        }
        if ([string]::IsNullOrWhiteSpace($failureCategory)) {
            $failureCategory = 'unknown'
        }

        $failureEvidence = Convert-ToSingleLineText -Text ([string]$FailurePolicy.DevFailureEvidence)
        if ([string]::IsNullOrWhiteSpace($failureEvidence)) {
            $failureEvidence = Convert-ToSingleLineText -Text ([string]$FailurePolicy.FailureEvidence)
        }
        $failureSource = Convert-ToSingleLineText -Text ([string]$FailurePolicy.DevFailureSourceLog)
        if ([string]::IsNullOrWhiteSpace($failureSource)) {
            $failureSource = Convert-ToSingleLineText -Text ([string]$FailurePolicy.FailureSourceLog)
        }

        if ($failureCategory -eq 'script-fault' -and [bool]$FailurePolicy.FailureHasCodeFault) {
            # Upstream may tag script-fault because of wrapper stack traces,
            # but code markers indicate this belongs to code-fix handling.
            $failureCategory = 'code-or-unknown'
        }

        switch ($failureCategory) {
            'script-fault' {
                $result.FailureKind = 'script-edit-failure'
            }
            'noncode-transient' {
                $result.FailureKind = 'environment-transient'
            }
            default {
                $composite = ('{0} {1}' -f $failureEvidence, $failureSource)
                $hasTaskDefinitionMismatchMarker = [regex]::IsMatch($composite, $taskDefinitionMismatchRegex)
                $hasCompileErrorMarker = [regex]::IsMatch($composite, $compileErrorRegex)
                $hasCompileWarningMarker = [regex]::IsMatch($composite, $compileWarningRegex)
                if ($hasTaskDefinitionMismatchMarker) {
                    $result.FailureKind = 'task-definition-mismatch'
                }
                elseif ($hasCompileErrorMarker -or [bool]$FailurePolicy.FailureHasCodeFault) {
                    $result.FailureKind = 'compile-failure'
                }
                elseif ($hasCompileWarningMarker) {
                    $result.FailureKind = 'compile-warning'
                }
                elseif ($failureCategory -eq 'code-or-unknown') {
                    $result.FailureKind = 'code-edit-failure'
                }
                else {
                    $result.FailureKind = 'unknown-failure'
                }
            }
        }
    }
    elseif ($failureCategory -eq 'script-fault') {
        $result.FailureKind = 'script-edit-failure'
    }
    elseif ($failureCategory -eq 'noncode-transient') {
        $result.FailureKind = 'environment-transient'
    }

    $result.FailureCategory = $failureCategory
    $result.FailureSource = $failureSource
    $result.FailureEvidence = $failureEvidence

    $selfHealable = $false
    if ($result.FailureKind -in @('script-failure', 'script-edit-failure', 'environment-transient', 'compile-failure', 'compile-warning', 'verify-failure', 'task-definition-mismatch', 'code-edit-failure', 'main-process-exit')) {
        $selfHealable = $true
    }
    # Keep B-stage recovery eligibility mode-agnostic: work mode should not
    # downgrade incident self-heal capability just because confirmation gate is pending.
    if ($result.PreferredStage -eq 'B' -and $AutoRecoverB) {
        $selfHealable = $true
    }
    if ([bool]$KnownInfraTransient) {
        $selfHealable = $false
    }
    $result.SelfHealable = [bool]$selfHealable

    return [pscustomobject]$result
}

function Get-TaskDefinitionRepairTicketContext {
    param(
        [object]$FailurePolicy,
        [object]$BExitReasonEvidence,
        [AllowEmptyString()][string]$RunDirAnchor
    )

    $result = [ordered]@{
        ShouldQueue = $false
        Detail = ''
        RecommendedAction = ''
        DedupSuffix = ''
    }

    if ($null -eq $FailurePolicy -or -not [bool]$FailurePolicy.IsDevRound) {
        return [pscustomobject]$result
    }

    $failedRoundTag = Convert-ToSingleLineText -Text ([string]$FailurePolicy.FailedRoundTag)
    if ([string]::IsNullOrWhiteSpace($failedRoundTag) -or $failedRoundTag -notmatch '^D[0-9]+$') {
        return [pscustomobject]$result
    }

    $failReason = ''
    $taskDefinitionPath = ''
    $sourceScript = ''
    if ($null -ne $BExitReasonEvidence -and [bool]$BExitReasonEvidence.Available -and [bool]$BExitReasonEvidence.StartFileMatch) {
        $failReason = Convert-ToSingleLineText -Text ([string]$BExitReasonEvidence.FailReason)
        $taskDefinitionPath = Convert-ToSingleLineText -Text ([string]$BExitReasonEvidence.TaskDefinitionPath)
        $sourceScript = Convert-ToSingleLineText -Text ([string]$BExitReasonEvidence.SourceScript)
    }

    if ([string]::IsNullOrWhiteSpace($failReason)) {
        $failReason = Convert-ToSingleLineText -Text ([string]$FailurePolicy.FailureEvidence)
    }

    $reasonNormalized = $failReason.ToLowerInvariant()
    if ($reasonNormalized -notmatch '\[code-step\].*expected\s+exactly\s+one\s+match,\s*actual\s*=\s*0') {
        return [pscustomobject]$result
    }

    $detail = ('round={0} category=task-definition-mismatch fail_reason={1} task_definition={2} source={3} run_dir={4}' -f
        $failedRoundTag,
        $failReason,
        $taskDefinitionPath,
        $sourceScript,
        (Convert-ToSingleLineText -Text $RunDirAnchor))

    $result.ShouldQueue = $true
    $result.Detail = Convert-ToBoundedSingleLineText -Text $detail -MaxChars 320
    $result.RecommendedAction = 'Report root cause and remediation path first. Inspect latest_b_exit and B runtime evidence, update the failing regex-patch in the matching task-definition round under testdata to match current source shape, and when the failure is in V1-V4 prefer appending the incremental patch after the existing D4 definition instead of rewriting already-validated D1-D4 rounds. Run task static precheck, then execute business_resume immediately (business_command -> continue_watch_command; continue only when business_command is empty). After completing this ticket cycle, you MUST return handled_at (YYYY-MM-DD HH:mm:ss); session_closed_at is session-level only and MUST be returned only when stop monitoring is requested or both A/B are terminal. After handling, keep read-only monitoring with scheduled status-ticket heartbeat + poll cadence until "stop monitoring".'
    $result.DedupSuffix = ('task-definition-fix|{0}|{1}|{2}' -f $failedRoundTag, $taskDefinitionPath, (Convert-ToSingleLineText -Text $RunDirAnchor))
    return [pscustomobject]$result
}

function Get-ACompileFailureContext {
    param(
        [System.Collections.IDictionary]$Settings,
        [AllowEmptyString()][string]$RunDirAnchor
    )

    $result = [ordered]@{
        Eligible = $false
        Reason = ''
        Detail = ''
        RunDir = ''
        RoundTag = ''
        RoundLogPath = ''
        AutopilotOutDir = ''
        D6OutDir = ''
        StrictLogPath = ''
        StrictLogText = ''
        Signatures = @()
        TaskDefinitionPath = ''
        TaskDefinitionHint = ''
    }

    $runDir = Resolve-AnchorPath -Path $RunDirAnchor
    if ([string]::IsNullOrWhiteSpace($runDir) -or -not (Test-Path -LiteralPath $runDir)) {
        $result.Reason = 'run-dir-missing'
        return [pscustomobject]$result
    }
    $result.RunDir = Convert-ToRepoRelativePath -Path $runDir

    $failedRoundCandidates = New-Object 'System.Collections.Generic.List[string]'
    $runFinalStatusPath = Join-Path $runDir 'final_status.json'
    $runFinalStatus = Read-JsonFileSafely -Path $runFinalStatusPath
    if ($null -ne $runFinalStatus -and ($runFinalStatus.PSObject.Properties.Name -contains 'FailedRoundTags')) {
        foreach ($tag in @($runFinalStatus.FailedRoundTags)) {
            $roundTag = Convert-ToSingleLineText -Text ([string]$tag)
            if ($roundTag -match '^D[1-4]$') {
                [void]$failedRoundCandidates.Add($roundTag)
            }
        }
    }

    $runSummaryPath = Join-Path $runDir 'summary.csv'
    $runRows = @(Import-CsvSafely -Path $runSummaryPath)
    if ($runRows.Count -lt 1) {
        $result.Reason = 'run-summary-missing'
        return [pscustomobject]$result
    }

    $failedRoundTag = ''
    if ($failedRoundCandidates.Count -gt 0) {
        $failedRoundTag = [string]$failedRoundCandidates[0]
    }
    else {
        $failedRows = @()
        foreach ($row in $runRows) {
            $phase = Convert-ToSingleLineText -Text ([string]$row.Phase)
            $roundTag = Convert-ToSingleLineText -Text ([string]$row.RoundTag)
            $roundPass = (Convert-ToSingleLineText -Text ([string]$row.RoundPass)).ToLowerInvariant()
            if ($phase -eq 'DEV' -and $roundTag -match '^D[1-4]$' -and $roundPass -in @('false', '0')) {
                $failedRows += $row
            }
        }

        if ($failedRows.Count -gt 0) {
            $failedRoundTag = [string]($failedRows | Sort-Object { [int]($_.Round) } -Descending | Select-Object -First 1).RoundTag
        }
    }

    if ([string]::IsNullOrWhiteSpace($failedRoundTag) -or $failedRoundTag -notmatch '^D[1-4]$') {
        $result.Reason = 'no-failed-d-round'
        return [pscustomobject]$result
    }
    $result.RoundTag = $failedRoundTag

    $failedRunRow = $null
    foreach ($row in $runRows) {
        if ((Convert-ToSingleLineText -Text ([string]$row.RoundTag)) -eq $failedRoundTag) {
            $failedRunRow = $row
        }
    }
    if ($null -eq $failedRunRow) {
        $result.Reason = 'failed-round-row-missing'
        return [pscustomobject]$result
    }

    $roundLogPath = Resolve-AnchorPath -Path (Convert-ToSingleLineText -Text (Get-PropertyValueOrEmpty -Object $failedRunRow -PropertyName 'LogFile'))
    if ([string]::IsNullOrWhiteSpace($roundLogPath) -or -not (Test-Path -LiteralPath $roundLogPath)) {
        $fallbackRoundLog = Join-Path $runDir ($failedRoundTag + '.log')
        if (Test-Path -LiteralPath $fallbackRoundLog) {
            $roundLogPath = $fallbackRoundLog
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($roundLogPath)) {
        $result.RoundLogPath = Convert-ToRepoRelativePath -Path $roundLogPath
    }

    $autopilotOutDir = Resolve-AnchorPath -Path (Convert-ToSingleLineText -Text (Get-PropertyValueOrEmpty -Object $failedRunRow -PropertyName 'AutopilotOutDir'))
    if ([string]::IsNullOrWhiteSpace($autopilotOutDir) -and -not [string]::IsNullOrWhiteSpace($roundLogPath) -and (Test-Path -LiteralPath $roundLogPath)) {
        foreach ($line in @(Get-Content -LiteralPath $roundLogPath -Tail 400 -ErrorAction SilentlyContinue)) {
            if ([string]$line -match '^\[AUTOPILOT-8R\] out_dir=(.+)$') {
                $autopilotOutDir = Resolve-AnchorPath -Path (Convert-ToSingleLineText -Text $Matches[1])
            }
        }
    }

    if ([string]::IsNullOrWhiteSpace($autopilotOutDir) -or -not (Test-Path -LiteralPath $autopilotOutDir)) {
        $result.Reason = 'autopilot-out-dir-missing'
        return [pscustomobject]$result
    }
    $result.AutopilotOutDir = Convert-ToRepoRelativePath -Path $autopilotOutDir

    $autopilotSummaryPath = Join-Path $autopilotOutDir 'summary.csv'
    $autopilotRows = @(Import-CsvSafely -Path $autopilotSummaryPath)
    if ($autopilotRows.Count -lt 1) {
        $result.Reason = 'autopilot-summary-missing'
        return [pscustomobject]$result
    }

    $autopilotRoundRow = $null
    foreach ($row in $autopilotRows) {
        if ((Convert-ToSingleLineText -Text ([string]$row.RoundTag)) -eq $failedRoundTag) {
            $autopilotRoundRow = $row
            break
        }
    }

    if ($null -eq $autopilotRoundRow) {
        $result.Reason = 'autopilot-round-row-missing'
        return [pscustomobject]$result
    }

    $taskDefinitionHint = Convert-ToSingleLineText -Text (Get-PropertyValueOrEmpty -Object $autopilotRoundRow -PropertyName 'TaskDefinitionFile')
    if (-not [string]::IsNullOrWhiteSpace($taskDefinitionHint)) {
        $result.TaskDefinitionHint = $taskDefinitionHint
    }

    $d6OutDir = Resolve-AnchorPath -Path (Convert-ToSingleLineText -Text (Get-PropertyValueOrEmpty -Object $autopilotRoundRow -PropertyName 'D6OutDir'))
    if ([string]::IsNullOrWhiteSpace($d6OutDir)) {
        $d6StdoutLog = Resolve-AnchorPath -Path (Convert-ToSingleLineText -Text (Get-PropertyValueOrEmpty -Object $autopilotRoundRow -PropertyName 'D6StdoutLog'))
        if (-not [string]::IsNullOrWhiteSpace($d6StdoutLog) -and (Test-Path -LiteralPath $d6StdoutLog)) {
            foreach ($line in @(Get-Content -LiteralPath $d6StdoutLog -Tail 240 -ErrorAction SilentlyContinue)) {
                if ([string]$line -match '^\[D6-CONSISTENCY\] out_dir=(.+)$') {
                    $d6OutDir = Resolve-AnchorPath -Path (Convert-ToSingleLineText -Text $Matches[1])
                }
            }
        }
    }

    if ([string]::IsNullOrWhiteSpace($d6OutDir) -or -not (Test-Path -LiteralPath $d6OutDir)) {
        $result.Reason = 'd6-out-dir-missing'
        return [pscustomobject]$result
    }
    $result.D6OutDir = Convert-ToRepoRelativePath -Path $d6OutDir

    $d6SummaryPath = Join-Path $d6OutDir 'summary.csv'
    $d6Rows = @(Import-CsvSafely -Path $d6SummaryPath)
    if ($d6Rows.Count -lt 1) {
        $result.Reason = 'd6-summary-missing'
        return [pscustomobject]$result
    }

    $strictLogPath = ''
    foreach ($row in $d6Rows) {
        $strictExit = 0
        [void][int]::TryParse((Convert-ToSingleLineText -Text (Get-PropertyValueOrEmpty -Object $row -PropertyName 'StrictExit')), [ref]$strictExit)
        $strictLogCandidate = Resolve-AnchorPath -Path (Convert-ToSingleLineText -Text (Get-PropertyValueOrEmpty -Object $row -PropertyName 'StrictLog'))
        if ($strictExit -ne 0 -and -not [string]::IsNullOrWhiteSpace($strictLogCandidate) -and (Test-Path -LiteralPath $strictLogCandidate)) {
            $strictLogPath = $strictLogCandidate
        }
    }

    if ([string]::IsNullOrWhiteSpace($strictLogPath)) {
        foreach ($row in $d6Rows) {
            $strictLogCandidate = Resolve-AnchorPath -Path (Convert-ToSingleLineText -Text (Get-PropertyValueOrEmpty -Object $row -PropertyName 'StrictLog'))
            if (-not [string]::IsNullOrWhiteSpace($strictLogCandidate) -and (Test-Path -LiteralPath $strictLogCandidate)) {
                $strictLogPath = $strictLogCandidate
            }
        }
    }

    if ([string]::IsNullOrWhiteSpace($strictLogPath) -or -not (Test-Path -LiteralPath $strictLogPath)) {
        $result.Reason = 'strict-log-missing'
        $result.Detail = ('round={0} strict_log=missing' -f [string]$failedRoundTag)
        return [pscustomobject]$result
    }
    $result.StrictLogPath = Convert-ToRepoRelativePath -Path $strictLogPath

    $strictLogText = ''
    try {
        $strictLogText = Get-Content -LiteralPath $strictLogPath -Raw -Encoding utf8 -ErrorAction Stop
    }
    catch {
        $result.Reason = 'strict-log-read-failed'
        $result.Detail = ('round={0} strict_log={1} read_failed={2}' -f [string]$failedRoundTag, [string]$result.StrictLogPath, (Convert-ToSingleLineText -Text $_.Exception.Message))
        return [pscustomobject]$result
    }

    $result.StrictLogText = $strictLogText
    if ($strictLogText -notmatch '(?im)src/core/preclass\.c:.*\berror:') {
        $result.Reason = 'not-preclass-compile-error'
        $result.Detail = ('round={0} strict_log={1} detail=strict-log-exists-but-preclass-signature-mismatch' -f [string]$failedRoundTag, [string]$result.StrictLogPath)
        return [pscustomobject]$result
    }

    $signatures = New-Object 'System.Collections.Generic.List[string]'
    if ($strictLogText -match '(?im)wc_preclass_set_special_tuple') {
        [void]$signatures.Add('preclass-special-tuple-forward-decl')
    }
    if ($strictLogText -match '(?im)wc_preclass_reason_unknown_hint_literal|wc_preclass_set_unknown_v6_hint_result') {
        [void]$signatures.Add('preclass-remove-unused-hint-helpers')
    }
    if ($strictLogText -match '(?im)wc_preclass_match_layer_cidr_literal|wc_preclass_match_layer_ip_literal') {
        [void]$signatures.Add('preclass-match-layer-wrapper')
    }

    if ($signatures.Count -lt 1) {
        $result.Reason = 'no-known-signature'
        return [pscustomobject]$result
    }

    $taskDefinitionRaw = ''
    if ($null -ne $Settings -and $Settings.Contains('A_TASK_DEFINITION')) {
        $taskDefinitionRaw = Convert-ToSingleLineText -Text ([string]$Settings.A_TASK_DEFINITION)
    }
    if ([string]::IsNullOrWhiteSpace($taskDefinitionRaw)) {
        $taskDefinitionRaw = $taskDefinitionHint
    }

    $taskDefinitionPath = Resolve-AnchorPath -Path $taskDefinitionRaw
    if ([string]::IsNullOrWhiteSpace($taskDefinitionPath) -or -not (Test-Path -LiteralPath $taskDefinitionPath)) {
        $result.Reason = 'task-definition-missing'
        return [pscustomobject]$result
    }

    $result.TaskDefinitionPath = $taskDefinitionPath
    $result.Signatures = @($signatures)
    $result.Eligible = $true
    return [pscustomobject]$result
}

function Resolve-RegexPatchOperation {
    param(
        [System.Collections.Generic.List[psobject]]$Operations,
        [string]$Pattern,
        [AllowEmptyString()][string]$Replacement
    )

    for ($index = 0; $index -lt $Operations.Count; $index++) {
        if ([string]$Operations[$index].pattern -ne $Pattern) {
            continue
        }

        if ([string]$Operations[$index].replacement -eq $Replacement) {
            return 'present'
        }

        $Operations[$index].replacement = $Replacement
        return 'updated'
    }

    [void]$Operations.Add([pscustomobject]@{
            pattern = $Pattern
            replacement = $Replacement
        })
    return 'added'
}

function Invoke-TaskDefinitionStaticCheck {
    param([string]$TaskDefinitionPath)

    $checkScript = Join-Path $script:RepoRoot 'tools\test\check_task_definition_static.ps1'
    if (-not (Test-Path -LiteralPath $checkScript)) {
        return [pscustomobject]@{
            Passed = $false
            ExitCode = 1
            OutputLines = @('[AB-SESSION-GUARD] task static checker script missing')
        }
    }

    $powershellPath = Join-Path $PSHOME 'powershell.exe'
    if (-not (Test-Path -LiteralPath $powershellPath)) {
        $powershellPath = 'powershell.exe'
    }

    $output = @(& $powershellPath -NoProfile -ExecutionPolicy Bypass -File $checkScript -TaskDefinitionFile $TaskDefinitionPath -Policy enforce 2>&1 | ForEach-Object { [string]$_ })
    $exitCode = if ($null -eq $LASTEXITCODE) { 0 } else { [int]$LASTEXITCODE }
    return [pscustomobject]@{
        Passed = ($exitCode -eq 0)
        ExitCode = $exitCode
        OutputLines = @($output)
    }
}

function Invoke-ApplyKnownPreclassTaskFixSet {
    param(
        [string]$TaskDefinitionPath,
        [string]$RoundTag
    )

    $result = [ordered]@{
        Success = $false
        Changed = $false
        Reason = ''
        BackupPath = ''
        UpdatedOperations = 0
        CheckExitCode = 0
        CheckOutput = @()
    }

    if ([string]::IsNullOrWhiteSpace($TaskDefinitionPath) -or -not (Test-Path -LiteralPath $TaskDefinitionPath)) {
        $result.Reason = 'task-definition-path-invalid'
        return [pscustomobject]$result
    }

    $taskDefinition = Read-JsonFileSafely -Path $TaskDefinitionPath
    if ($null -eq $taskDefinition) {
        $result.Reason = 'task-definition-parse-failed'
        return [pscustomobject]$result
    }

    if (-not ($taskDefinition.PSObject.Properties.Name -contains 'rounds')) {
        $result.Reason = 'task-definition-rounds-missing'
        return [pscustomobject]$result
    }

    $roundProperty = $null
    foreach ($entry in @($taskDefinition.rounds.PSObject.Properties)) {
        if ([string]$entry.Name -eq $RoundTag) {
            $roundProperty = $entry
            break
        }
    }

    if ($null -eq $roundProperty) {
        $result.Reason = 'round-missing'
        return [pscustomobject]$result
    }

    $roundTask = $roundProperty.Value
    $roundType = 'builtin'
    if ($roundTask.PSObject.Properties.Name -contains 'type') {
        $roundType = (Convert-ToSingleLineText -Text ([string]$roundTask.type)).ToLowerInvariant()
    }
    if ($roundType -ne 'regex-patch') {
        $result.Reason = 'round-not-regex-patch'
        return [pscustomobject]$result
    }

    $operationItems = @()
    if ($roundTask.PSObject.Properties.Name -contains 'operations') {
        $operationItems = @($roundTask.operations)
    }

    $operations = New-Object 'System.Collections.Generic.List[psobject]'
    foreach ($operation in $operationItems) {
        [void]$operations.Add([pscustomobject]@{
                pattern = [string]$operation.pattern
                replacement = [string]$operation.replacement
            })
    }
            $TaskDefinitionPath = Assert-GuardTaskDefinitionMutationPath -RepoRoot $script:RepoRoot -Path $TaskDefinitionPath


    $replacementSpecialTuple = @"
static void wc_preclass_set_special_tuple(const char** cls,
        const char** rir,
        const char** reason,
        const char** confidence,
        const char* reason_value);

static void wc_preclass_set_v6_branch_special_result(const char** cls,
        const char** rir,
        const char** reason,
        const char** confidence,
        const char* reason_value)
{
    wc_preclass_set_special_tuple(cls, rir, reason, confidence, reason_value);
}

static int wc_preclass_is_v6_loopback(const struct in6_addr* addr6)
"@

    $replacementMatchLayer = @"
static const char* wc_preclass_match_layer_cidr_literal(void);
static const char* wc_preclass_match_layer_ip_literal(void);

static const char* wc_preclass_match_layer_from_query_kind(int query_is_cidr)
{
    return query_is_cidr ? wc_preclass_match_layer_cidr_literal() : wc_preclass_match_layer_ip_literal();
}
"@

    $changeStates = @()
    $changeStates += (Resolve-RegexPatchOperation -Operations $operations -Pattern 'static int wc_preclass_is_v6_loopback\(const struct in6_addr\* addr6\)' -Replacement $replacementSpecialTuple)
    $changeStates += (Resolve-RegexPatchOperation -Operations $operations -Pattern 'static const char\* wc_preclass_match_layer_from_query_kind\(int query_is_cidr\)\r?\n\{\r?\n\treturn query_is_cidr \? wc_preclass_match_layer_cidr_output_literal\(\) : wc_preclass_match_layer_ip_output_literal\(\);\r?\n\}' -Replacement $replacementMatchLayer)
    $changeStates += (Resolve-RegexPatchOperation -Operations $operations -Pattern 'static const char\* wc_preclass_reason_unknown_hint_literal\(void\)\r?\n\{\r?\n\treturn wc_preclass_reason_unknown_literal\(\);\r?\n\}' -Replacement '')
    $changeStates += (Resolve-RegexPatchOperation -Operations $operations -Pattern 'static void wc_preclass_set_unknown_v6_hint_result\(const char\*\* rir,\r?\n\t\tconst char\*\* reason,\r?\n\t\tconst char\*\* confidence\)\r?\n\{\r?\n\t\*rir = "unknown";\r?\n\t\*reason = "V6_NO_RIR_HINT";\r?\n\t\*confidence = "low";\r?\n\}' -Replacement '')

    $updatedOperations = 0
    foreach ($state in $changeStates) {
        if ($state -in @('added', 'updated')) {
            $updatedOperations++
        }
    }

    if ($updatedOperations -lt 1) {
        $result.Success = $true
        $result.Changed = $false
        $result.Reason = 'already-up-to-date'
        return [pscustomobject]$result
    }

    $backupName = 'taskdef_backup_{0}_{1}.json' -f $RoundTag, (Get-Date -Format 'yyyyMMdd-HHmmss')
    $backupPath = Join-Path $script:GuardOutDir $backupName
    Copy-Item -LiteralPath $TaskDefinitionPath -Destination $backupPath -Force
    $result.BackupPath = Convert-ToRepoRelativePath -Path $backupPath

    if ($roundTask.PSObject.Properties.Name -contains 'operations') {
        $roundTask.operations = @($operations)
    }
    else {
        Add-Member -InputObject $roundTask -MemberType NoteProperty -Name 'operations' -Value @($operations)
    }

    try {
        $json = ($taskDefinition | ConvertTo-Json -Depth 64) -replace "`r`n", "`n"
        [System.IO.File]::WriteAllText($TaskDefinitionPath, $json, [System.Text.UTF8Encoding]::new($true))
    }
    catch {
        Copy-Item -LiteralPath $backupPath -Destination $TaskDefinitionPath -Force
        $result.Reason = 'task-definition-write-failed'
        return [pscustomobject]$result
    }

    $checkResult = Invoke-TaskDefinitionStaticCheck -TaskDefinitionPath $TaskDefinitionPath
    $result.CheckExitCode = [int]$checkResult.ExitCode
    $result.CheckOutput = @($checkResult.OutputLines)
    if (-not [bool]$checkResult.Passed) {
        Copy-Item -LiteralPath $backupPath -Destination $TaskDefinitionPath -Force
        $result.Reason = 'task-definition-static-check-failed'
        return [pscustomobject]$result
    }

    $result.Success = $true
    $result.Changed = $true
    $result.Reason = 'updated'
    $result.UpdatedOperations = $updatedOperations
    return [pscustomobject]$result
}

function Invoke-AStageRestart {
    param(
        [int]$Attempt,
        [string]$RoundTag
    )

    $stageLauncher = Join-Path $script:RepoRoot 'tools\test\open_unattended_ab_stage_window.ps1'
    $powershellPath = Join-Path $PSHOME 'powershell.exe'
    if (-not (Test-Path -LiteralPath $powershellPath)) {
        $powershellPath = 'powershell.exe'
    }

    Write-GuardLog ("restart_begin stage=A round={0} attempt={1} launcher={2}" -f $RoundTag, $Attempt, (Convert-ToRepoRelativePath -Path $stageLauncher))
    $output = @(& $powershellPath -NoProfile -ExecutionPolicy Bypass -File $stageLauncher -Stage A -StartFile $script:StartFilePath -StartMonitors 2>&1 | ForEach-Object { [string]$_ })
    $exitCode = if ($null -eq $LASTEXITCODE) { 0 } else { [int]$LASTEXITCODE }

    $outputLines = @(
        @($output) |
            ForEach-Object { Convert-ToSingleLineText -Text ([string]$_) } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    )

    if ($outputLines.Count -gt 0) {
        Write-GuardLog ("restart_output_summary stage=A round={0} attempt={1} lines={2}" -f $RoundTag, $Attempt, $outputLines.Count)
        $outputBlockLines = New-Object 'System.Collections.Generic.List[string]'
        [void]$outputBlockLines.Add(("stage=A round={0} attempt={1}" -f $RoundTag, $Attempt))
        foreach ($line in $outputLines) {
            [void]$outputBlockLines.Add(("line={0}" -f $line))
        }
        Write-GuardPastedBlock -Tag 'restart_output_block' -Lines @($outputBlockLines)
    }

    return [pscustomobject]@{
        ExitCode = $exitCode
        Succeeded = ($exitCode -eq 0)
    }
}

function Invoke-AVerifyRoundRecovery {
    param(
        [object]$FailurePolicy,
        [bool]$RestartAllowed = $true,
        [ValidateRange(1, 10)][int]$MaxAttemptsPerRound = 2,
        [ValidateRange(0, 180)][int]$CooldownMinutes = 10
    )

    $result = [ordered]@{
        Attempted = $false
        Restarted = $false
        Reason = 'not-eligible'
        RoundTag = ''
        Attempt = 0
        Detail = ''
        Category = ''
        Evidence = ''
        SourceLog = ''
    }

    if ($null -eq $FailurePolicy -or -not [bool]$FailurePolicy.IsVerifyRound) {
        $result.Reason = 'not-verify-round'
        return [pscustomobject]$result
    }

    $roundTag = Convert-ToSingleLineText -Text ([string]$FailurePolicy.FailedRoundTag)
    $category = (Convert-ToSingleLineText -Text ([string]$FailurePolicy.VerifyFailureCategory)).ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($category)) {
        $category = 'code-or-unknown'
    }

    $result.RoundTag = $roundTag
    $result.Category = $category
    $result.Evidence = Convert-ToSingleLineText -Text ([string]$FailurePolicy.VerifyFailureEvidence)
    $result.SourceLog = Convert-ToSingleLineText -Text ([string]$FailurePolicy.VerifyFailureSourceLog)

    if ($category -notin @('script-fault', 'noncode-transient')) {
        $result.Reason = 'code-or-unknown'
        $result.Detail = 'verify_round_requires_manual_code_handling'
        return [pscustomobject]$result
    }

    $ledgerKey = ('{0}|{1}' -f $roundTag, $category)
    if (-not $script:VerifyRecoveryAttemptCounts.ContainsKey($ledgerKey)) {
        $script:VerifyRecoveryAttemptCounts[$ledgerKey] = 0
    }

    $attemptCount = [int]$script:VerifyRecoveryAttemptCounts[$ledgerKey]
    if ($attemptCount -ge $MaxAttemptsPerRound) {
        $result.Reason = 'attempt-budget-exhausted'
        $result.Detail = ('attempts={0} max={1}' -f $attemptCount, $MaxAttemptsPerRound)
        return [pscustomobject]$result
    }

    $now = Get-Date
    if ($CooldownMinutes -gt 0 -and $script:VerifyRecoveryLastAttemptAt.ContainsKey($ledgerKey)) {
        $lastAttemptAt = [datetime]$script:VerifyRecoveryLastAttemptAt[$ledgerKey]
        if ($lastAttemptAt -ne [datetime]::MinValue -and $now -lt $lastAttemptAt.AddMinutes($CooldownMinutes)) {
            $result.Reason = 'cooldown'
            $result.Detail = ('next_at={0}' -f $lastAttemptAt.AddMinutes($CooldownMinutes).ToString('yyyy-MM-dd HH:mm:ss'))
            return [pscustomobject]$result
        }
    }

    $attempt = $attemptCount + 1
    $script:VerifyRecoveryAttemptCounts[$ledgerKey] = $attempt
    $script:VerifyRecoveryLastAttemptAt[$ledgerKey] = $now

    $result.Attempted = $true
    $result.Attempt = $attempt

    if (-not $RestartAllowed) {
        $result.Reason = 'restart-await-confirmation'
        $result.Detail = 'restart_requires_user_confirmation'
        return [pscustomobject]$result
    }

    $restartResult = Invoke-AStageRestart -Attempt $attempt -RoundTag $roundTag
    if ([bool]$restartResult.Succeeded) {
        $result.Restarted = $true
        $result.Reason = 'restart-triggered'
    }
    else {
        $result.Reason = 'restart-failed'
        $result.Detail = ('exit_code={0}' -f [int]$restartResult.ExitCode)
    }

    return [pscustomobject]$result
}

function Invoke-ADevRoundTransientRecovery {
    param(
        [object]$FailurePolicy,
        [bool]$RestartAllowed = $true,
        [ValidateRange(1, 10)][int]$MaxAttemptsPerRound = 2,
        [ValidateRange(0, 180)][int]$CooldownMinutes = 10
    )

    $result = [ordered]@{
        Attempted = $false
        Restarted = $false
        Reason = 'not-eligible'
        RoundTag = ''
        Attempt = 0
        Detail = ''
        Category = ''
        Evidence = ''
        SourceLog = ''
    }

    if ($null -eq $FailurePolicy -or -not [bool]$FailurePolicy.IsDevRound) {
        $result.Reason = 'not-dev-round'
        return [pscustomobject]$result
    }

    $roundTag = Convert-ToSingleLineText -Text ([string]$FailurePolicy.FailedRoundTag)
    $category = (Convert-ToSingleLineText -Text ([string]$FailurePolicy.DevFailureCategory)).ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($category)) {
        $category = (Convert-ToSingleLineText -Text ([string]$FailurePolicy.FailureCategory)).ToLowerInvariant()
    }
    if ([string]::IsNullOrWhiteSpace($category)) {
        $category = 'code-or-unknown'
    }

    $result.RoundTag = $roundTag
    $result.Category = $category
    $result.Evidence = Convert-ToSingleLineText -Text ([string]$FailurePolicy.DevFailureEvidence)
    $result.SourceLog = Convert-ToSingleLineText -Text ([string]$FailurePolicy.DevFailureSourceLog)

    if ($category -ne 'noncode-transient') {
        $result.Reason = 'not-noncode-transient'
        return [pscustomobject]$result
    }

    $ledgerKey = ('{0}|{1}' -f $roundTag, $category)
    if (-not $script:DevRecoveryAttemptCounts.ContainsKey($ledgerKey)) {
        $script:DevRecoveryAttemptCounts[$ledgerKey] = 0
    }

    $attemptCount = [int]$script:DevRecoveryAttemptCounts[$ledgerKey]
    if ($attemptCount -ge $MaxAttemptsPerRound) {
        $result.Reason = 'attempt-budget-exhausted'
        $result.Detail = ('attempts={0} max={1}' -f $attemptCount, $MaxAttemptsPerRound)
        return [pscustomobject]$result
    }

    $now = Get-Date
    if ($CooldownMinutes -gt 0 -and $script:DevRecoveryLastAttemptAt.ContainsKey($ledgerKey)) {
        $lastAttemptAt = [datetime]$script:DevRecoveryLastAttemptAt[$ledgerKey]
        if ($lastAttemptAt -ne [datetime]::MinValue -and $now -lt $lastAttemptAt.AddMinutes($CooldownMinutes)) {
            $result.Reason = 'cooldown'
            $result.Detail = ('next_at={0}' -f $lastAttemptAt.AddMinutes($CooldownMinutes).ToString('yyyy-MM-dd HH:mm:ss'))
            return [pscustomobject]$result
        }
    }

    $attempt = $attemptCount + 1
    $script:DevRecoveryAttemptCounts[$ledgerKey] = $attempt
    $script:DevRecoveryLastAttemptAt[$ledgerKey] = $now

    $result.Attempted = $true
    $result.Attempt = $attempt

    if (-not $RestartAllowed) {
        $result.Reason = 'restart-await-confirmation'
        $result.Detail = 'restart_requires_user_confirmation'
        return [pscustomobject]$result
    }

    $restartResult = Invoke-AStageRestart -Attempt $attempt -RoundTag $roundTag
    if ([bool]$restartResult.Succeeded) {
        $result.Restarted = $true
        $result.Reason = 'restart-triggered'
    }
    else {
        $result.Reason = 'restart-failed'
        $result.Detail = ('exit_code={0}' -f [int]$restartResult.ExitCode)
    }

    return [pscustomobject]$result
}

function Invoke-ACompileAutoFixRecovery {
    param(
        [System.Collections.IDictionary]$Settings,
        [AllowEmptyString()][string]$RunDirAnchor,
        [ValidateRange(1, 8)][int]$MaxAttemptsPerRound = 3,
        [ValidateRange(0, 180)][int]$CooldownMinutes = 1,
        [bool]$RestartAllowed = $true
    )

    $result = [ordered]@{
        Attempted = $false
        Restarted = $false
        Reason = 'not-eligible'
        RoundTag = ''
        Attempt = 0
        Detail = ''
        TaskDefinitionPath = ''
        StrictLogPath = ''
    }

    $context = Get-ACompileFailureContext -Settings $Settings -RunDirAnchor $RunDirAnchor
    if (-not [bool]$context.Eligible) {
        $result.Reason = [string]$context.Reason
        $result.Detail = Convert-ToSingleLineText -Text ([string]$context.Detail)
        return [pscustomobject]$result
    }

    $result.RoundTag = [string]$context.RoundTag
    $result.TaskDefinitionPath = Convert-ToRepoRelativePath -Path ([string]$context.TaskDefinitionPath)
    $result.StrictLogPath = [string]$context.StrictLogPath

    $ledgerKey = ('{0}|{1}' -f [string]$context.RoundTag, ([string]$context.TaskDefinitionPath).ToLowerInvariant())
    if (-not $script:AutoFixAttemptCounts.ContainsKey($ledgerKey)) {
        $script:AutoFixAttemptCounts[$ledgerKey] = 0
    }

    $attemptCount = [int]$script:AutoFixAttemptCounts[$ledgerKey]
    if ($attemptCount -ge $MaxAttemptsPerRound) {
        $result.Reason = 'attempt-budget-exhausted'
        $result.Detail = ('attempts={0} max={1}' -f $attemptCount, $MaxAttemptsPerRound)
        return [pscustomobject]$result
    }

    $now = Get-Date
    if ($CooldownMinutes -gt 0 -and $script:AutoFixLastAttemptAt.ContainsKey($ledgerKey)) {
        $lastAttemptAt = [datetime]$script:AutoFixLastAttemptAt[$ledgerKey]
        if ($lastAttemptAt -ne [datetime]::MinValue -and $now -lt $lastAttemptAt.AddMinutes($CooldownMinutes)) {
            $nextAt = $lastAttemptAt.AddMinutes($CooldownMinutes).ToString('yyyy-MM-dd HH:mm:ss')
            $result.Reason = 'cooldown'
            $result.Detail = ('next_at={0}' -f $nextAt)
            return [pscustomobject]$result
        }
    }

    $attempt = $attemptCount + 1
    $script:AutoFixAttemptCounts[$ledgerKey] = $attempt
    $script:AutoFixLastAttemptAt[$ledgerKey] = $now

    $result.Attempted = $true
    $result.Attempt = $attempt

    $signatureSummary = (@($context.Signatures) -join ',')
    Write-GuardLog ("auto_fix_begin stage=A round={0} attempt={1}/{2} signatures={3} strict_log={4}" -f
        [string]$context.RoundTag,
        $attempt,
        $MaxAttemptsPerRound,
        $signatureSummary,
        [string]$context.StrictLogPath)

    $applyResult = Invoke-ApplyKnownPreclassTaskFixSet -TaskDefinitionPath ([string]$context.TaskDefinitionPath) -RoundTag ([string]$context.RoundTag)
    if (-not [bool]$applyResult.Success) {
        $result.Reason = 'task-definition-fix-failed'
        $result.Detail = [string]$applyResult.Reason
        $checkPreview = Convert-ToBoundedSingleLineText -Text ((@($applyResult.CheckOutput) -join ' | ')) -MaxChars 240
        if (-not [string]::IsNullOrWhiteSpace($checkPreview)) {
            Write-GuardLog ("auto_fix_fail stage=A round={0} attempt={1}/{2} reason={3} check={4}" -f [string]$context.RoundTag, $attempt, $MaxAttemptsPerRound, [string]$applyResult.Reason, $checkPreview)
        }
        else {
            Write-GuardLog ("auto_fix_fail stage=A round={0} attempt={1}/{2} reason={3}" -f [string]$context.RoundTag, $attempt, $MaxAttemptsPerRound, [string]$applyResult.Reason)
        }
        return [pscustomobject]$result
    }

    if ([bool]$applyResult.Changed) {
        Write-GuardLog ("auto_fix_taskdef_updated stage=A round={0} attempt={1}/{2} task={3} updated_ops={4} backup={5}" -f
            [string]$context.RoundTag,
            $attempt,
            $MaxAttemptsPerRound,
            (Convert-ToRepoRelativePath -Path ([string]$context.TaskDefinitionPath)),
            [int]$applyResult.UpdatedOperations,
            [string]$applyResult.BackupPath)
    }
    else {
        Write-GuardLog ("auto_fix_taskdef_nochange stage=A round={0} attempt={1}/{2} task={3}" -f
            [string]$context.RoundTag,
            $attempt,
            $MaxAttemptsPerRound,
            (Convert-ToRepoRelativePath -Path ([string]$context.TaskDefinitionPath)))
    }

    if (-not $RestartAllowed) {
        $result.Reason = 'restart-await-confirmation'
        $result.Detail = 'restart_requires_user_confirmation'
        Write-GuardLog ("auto_fix_restart_blocked stage=A round={0} attempt={1}/{2} reason=await_user_confirmation" -f [string]$context.RoundTag, $attempt, $MaxAttemptsPerRound)
        return [pscustomobject]$result
    }

    $restartResult = Invoke-AStageRestart -Attempt $attempt -RoundTag ([string]$context.RoundTag)
    if ([bool]$restartResult.Succeeded) {
        $result.Restarted = $true
        $result.Reason = 'restart-triggered'
        Write-GuardLog ("auto_fix_restart_triggered stage=A round={0} attempt={1}/{2}" -f [string]$context.RoundTag, $attempt, $MaxAttemptsPerRound)
    }
    else {
        $result.Reason = 'restart-failed'
        $result.Detail = ('exit_code={0}' -f [int]$restartResult.ExitCode)
        Write-GuardLog ("auto_fix_restart_failed stage=A round={0} attempt={1}/{2} exit_code={3}" -f [string]$context.RoundTag, $attempt, $MaxAttemptsPerRound, [int]$restartResult.ExitCode)
    }

    try {
        $currentSettings = Read-KeyValueFile -Path $script:StartFilePath
        $existingNotes = if ($currentSettings.Contains('SESSION_FINAL_NOTES')) { [string]$currentSettings.SESSION_FINAL_NOTES } else { '' }
        $note = ('guard_autofix stage=A round={0} attempt={1}/{2} restarted={3} reason={4} strict_log={5}' -f
            [string]$context.RoundTag,
            $attempt,
            $MaxAttemptsPerRound,
            [bool]$result.Restarted,
            [string]$result.Reason,
            [string]$context.StrictLogPath)
        $newNotes = Add-DelimitedNote -Existing $existingNotes -Append $note
        Invoke-KeyValueFileValueUpdate -Path $script:StartFilePath -Values @{ SESSION_FINAL_NOTES = $newNotes }
    }
    catch {
        Write-GuardLog ("auto_fix_note_update_failed detail={0}" -f (Convert-ToSingleLineText -Text $_.Exception.Message))
    }

    return [pscustomobject]$result
}

$script:RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$script:StartFilePath = Resolve-RepoPath -Path $StartFile
$script:StartFileLeaf = [System.IO.Path]::GetFileName($script:StartFilePath).ToLowerInvariant()

try {
    $startFileHash = [System.BitConverter]::ToString(
        [System.Security.Cryptography.SHA1]::Create().ComputeHash(
            [System.Text.Encoding]::UTF8.GetBytes(
                [System.IO.Path]::GetFullPath($script:StartFilePath).ToLowerInvariant()
            )
        )
    ).Replace('-', '').Substring(0, 12).ToLowerInvariant()
    $host.UI.RawUI.WindowTitle = "whois-mon-session-guard-$startFileHash"
}
catch { }

$script:InstanceMutex = Lock-InstanceMutex -Role 'session-guard' -StartFilePath $script:StartFilePath

$guardStamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$script:GuardOutDir = Join-Path $script:RepoRoot (Join-Path 'out\artifacts\ab_session_guard' $guardStamp)
New-Item -ItemType Directory -Path $script:GuardOutDir -Force | Out-Null
$script:GuardLogPath = Join-Path $script:GuardOutDir 'guard.log'
$script:GuardStatePath = Join-Path $script:GuardOutDir 'guard_state.json'
$script:GuardState = [ordered]@{
    schema = 'AB_SESSION_GUARD_STATE_V1'
    status = 'starting'
    start_file = (Convert-ToRepoRelativePath -Path $script:StartFilePath)
    guard_log = (Convert-ToRepoRelativePath -Path $script:GuardLogPath)
    guard_state = (Convert-ToRepoRelativePath -Path $script:GuardStatePath)
    poll_sec = [int]$PollSec
    max_b_recovery_attempts = [int]$MaxBRecoveryAttempts
    recovery_cooldown_minutes = [int]$RecoveryCooldownMinutes
    stop_on_budget_exhausted = [bool]$StopOnBudgetExhausted
    auto_recover_b = $true
    restart_requires_confirmation = $false
    restart_approved = $true
    suppress_known_infra_tickets = $true
    exit_on_known_infra_transient = $true
    agent_ticket_queue_enabled = $true
    agent_ticket_queue_path = ''
    status_ticket_enabled = $false
    status_ticket_interval_minutes = 30
    last_status_ticket_at = ''
    last_ticket_id = ''
    last_ticket_event = ''
    b_recovery_attempts = 0
    last_recovery_at = ''
}

$script:GuardStateWriteFailureCount = 0
$script:GuardStateWriteFailureSignature = ''
$script:GuardStateWriteFailureLastReportAt = [datetime]::MinValue

$script:AutoFixAttemptCounts = @{}
$script:AutoFixLastAttemptAt = @{}
$script:VerifyRecoveryAttemptCounts = @{}
$script:VerifyRecoveryLastAttemptAt = @{}
$script:DevRecoveryAttemptCounts = @{}
$script:DevRecoveryLastAttemptAt = @{}
$script:AgentTicketLastSignature = ''
$script:AgentTicketLastId = ''
$script:AgentTicketLastEvent = ''

Write-GuardState -Values @{}
Write-GuardLog ("startup start_file={0} poll_sec={1} max_b_recovery_attempts={2} recovery_cooldown_minutes={3} stop_on_budget_exhausted={4} guard_log={5} guard_state={6}" -f (Convert-ToRepoRelativePath -Path $script:StartFilePath), $PollSec, $MaxBRecoveryAttempts, $RecoveryCooldownMinutes, $StopOnBudgetExhausted, (Convert-ToRepoRelativePath -Path $script:GuardLogPath), (Convert-ToRepoRelativePath -Path $script:GuardStatePath))
$guardParentPid = 0
try {
    $guardSelfProcess = Get-CimInstance Win32_Process -Filter ("ProcessId={0}" -f $PID) -ErrorAction Stop
    if ($null -ne $guardSelfProcess) {
        $guardParentPid = [int]$guardSelfProcess.ParentProcessId
    }
}
catch {
    $guardParentPid = 0
}
Write-GuardLog ("startup_pid pid={0} parent_pid={1}" -f $PID, $guardParentPid)

$bRecoveryAttempts = 0
$lastRecoveryAt = [datetime]::MinValue
$lastIncidentSignature = ''
$lastHeartbeatAt = [datetime]::MinValue
$lastBudgetExhaustedSignature = ''
$aRunningNoProcessSince = $null
$lastMissingAProcessReportAt = $null
$bRunningNoProcessSince = $null
$lastMissingBProcessReportAt = $null
$lastBMissingExitReasonEvidence = $null
$lastBMissingRuntimeTailEvidence = $null
$manualPauseActive = $false
$manualPauseSignature = ''
$manualPauseNoticeCount = 0
$manualPauseNoticeRepeat = 2
$manualPauseEnabled = $true
$forceExitOnFinalNoFollowup = $true
$autoFixCompileEnabled = $true
$autoFixMaxPerDRound = 3
$autoFixCooldownMinutes = 1
$lastAutoFixStatusSignature = ''
$restartRequiresConfirmation = $false
$restartApproved = $true
$suppressKnownInfraTickets = $true
$exitOnKnownInfraTransient = $true
$lastRestartApprovalWaitSignature = ''
$taskDefinitionRepairTicketEnabled = $true
$lastTaskDefinitionFixSignature = ''
$statusTicketEnabled = $false
$statusTicketIntervalMinutes = 30
$lastStatusTicketAt = [datetime]::MinValue
$lastMainProcessExitReviewSignature = ''
$lastAPassConclusionSignature = ''
$mainProcessExitGraceStartedAt = $null
$mainProcessExitGraceLastNoticeAt = $null
$mainProcessExitGraceShutdownDetail = ''
$mainProcessExitGraceStage = ''
$monitorChainGraceStartedAt = $null
$monitorChainGraceLastNoticeAt = $null
$monitorChainGraceShutdownDetail = ''
$monitorChainGraceShutdownStage = ''
$monitorChainGraceShutdownReason = ''
$monitorChainGraceShutdownSource = ''
$healthCheckIterationCounter = 0

try {
    while ($true) {
        try {
            if (-not (Test-Path -LiteralPath $script:StartFilePath)) {
                $missingStartFile = Convert-ToRepoRelativePath -Path $script:StartFilePath
                Write-GuardState -Values @{
                    status = 'stopped'
                    event = 'start-file-missing'
                    stop_reason = 'start-file-missing'
                    missing_start_file = $missingStartFile
                }
                Write-GuardLog ("complete reason=start_file_missing start_file={0}" -f $missingStartFile)
                break
            }

            $settings = Read-KeyValueFile -Path $script:StartFilePath

            $sessionStatusRaw = 'NOT_RUN'
            if ($settings.Contains('SESSION_FINAL_STATUS')) {
                $sessionStatusRaw = [string]$settings.SESSION_FINAL_STATUS
            }

            $aStatusRaw = 'NOT_RUN'
            if ($settings.Contains('A_FINAL_STATUS')) {
                $aStatusRaw = [string]$settings.A_FINAL_STATUS
            }

            $bStatusRaw = 'NOT_RUN'
            if ($settings.Contains('B_FINAL_STATUS')) {
                $bStatusRaw = [string]$settings.B_FINAL_STATUS
            }

            $sessionStatus = Get-StatusValue -Value $sessionStatusRaw
            $aStatus = Get-StatusValue -Value $aStatusRaw
            $bStatus = Get-StatusValue -Value $bStatusRaw

            $autoRecoverB = $true
            if ($settings.Contains('LOCAL_GUARD_AUTO_RECOVER_B')) {
                $autoRecoverB = Convert-ToBooleanSetting -Value ([string]$settings.LOCAL_GUARD_AUTO_RECOVER_B) -Default $true
            }

            if ($settings.Contains('LOCAL_GUARD_MAX_B_RECOVERY_ATTEMPTS')) {
                $parsedAttempts = 0
                if ([int]::TryParse(([string]$settings.LOCAL_GUARD_MAX_B_RECOVERY_ATTEMPTS), [ref]$parsedAttempts)) {
                    if ($parsedAttempts -ge 0 -and $parsedAttempts -le 10) {
                        $MaxBRecoveryAttempts = $parsedAttempts
                    }
                }
            }

            if ($settings.Contains('LOCAL_GUARD_RECOVERY_COOLDOWN_MINUTES')) {
                $parsedCooldown = 0
                if ([int]::TryParse(([string]$settings.LOCAL_GUARD_RECOVERY_COOLDOWN_MINUTES), [ref]$parsedCooldown)) {
                    if ($parsedCooldown -ge 1 -and $parsedCooldown -le 180) {
                        $RecoveryCooldownMinutes = $parsedCooldown
                    }
                }
            }

            if ($settings.Contains('LOCAL_GUARD_POLL_SEC')) {
                $parsedPoll = 0
                if ([int]::TryParse(([string]$settings.LOCAL_GUARD_POLL_SEC), [ref]$parsedPoll)) {
                    if ($parsedPoll -ge 15 -and $parsedPoll -le 300) {
                        $PollSec = $parsedPoll
                    }
                }
            }

            if ($settings.Contains('LOCAL_GUARD_STOP_ON_BUDGET_EXHAUSTED')) {
                $StopOnBudgetExhausted = Convert-ToBooleanSetting -Value ([string]$settings.LOCAL_GUARD_STOP_ON_BUDGET_EXHAUSTED) -Default $true
            }

            $manualPauseEnabled = $true
            if ($settings.Contains('LOCAL_GUARD_WAIT_FOR_MANUAL_RESTART')) {
                $manualPauseEnabled = Convert-ToBooleanSetting -Value ([string]$settings.LOCAL_GUARD_WAIT_FOR_MANUAL_RESTART) -Default $true
            }

            $manualPauseNoticeRepeat = 2
            if ($settings.Contains('LOCAL_GUARD_MANUAL_NOTICE_REPEAT')) {
                $parsedManualNoticeRepeat = 0
                if ([int]::TryParse(([string]$settings.LOCAL_GUARD_MANUAL_NOTICE_REPEAT), [ref]$parsedManualNoticeRepeat)) {
                    if ($parsedManualNoticeRepeat -ge 1 -and $parsedManualNoticeRepeat -le 10) {
                        $manualPauseNoticeRepeat = $parsedManualNoticeRepeat
                    }
                }
            }

            $forceExitOnFinalNoFollowup = $true
            if ($settings.Contains('LOCAL_GUARD_FORCE_EXIT_ON_FINAL_NO_FOLLOWUP')) {
                $forceExitOnFinalNoFollowup = Convert-ToBooleanSetting -Value ([string]$settings.LOCAL_GUARD_FORCE_EXIT_ON_FINAL_NO_FOLLOWUP) -Default $true
            }

            $autoFixCompileEnabled = $true
            if ($settings.Contains('LOCAL_GUARD_AUTO_FIX_D_COMPILE')) {
                $autoFixCompileEnabled = Convert-ToBooleanSetting -Value ([string]$settings.LOCAL_GUARD_AUTO_FIX_D_COMPILE) -Default $true
            }

            $autoFixMaxPerDRound = 3
            if ($settings.Contains('LOCAL_GUARD_AUTO_FIX_MAX_PER_D_ROUND')) {
                $parsedAutoFixMaxPerRound = 0
                if ([int]::TryParse(([string]$settings.LOCAL_GUARD_AUTO_FIX_MAX_PER_D_ROUND), [ref]$parsedAutoFixMaxPerRound)) {
                    if ($parsedAutoFixMaxPerRound -ge 1 -and $parsedAutoFixMaxPerRound -le 8) {
                        $autoFixMaxPerDRound = $parsedAutoFixMaxPerRound
                    }
                }
            }

            $autoFixCooldownMinutes = 1
            if ($settings.Contains('LOCAL_GUARD_AUTO_FIX_COOLDOWN_MINUTES')) {
                $parsedAutoFixCooldown = 0
                if ([int]::TryParse(([string]$settings.LOCAL_GUARD_AUTO_FIX_COOLDOWN_MINUTES), [ref]$parsedAutoFixCooldown)) {
                    if ($parsedAutoFixCooldown -ge 0 -and $parsedAutoFixCooldown -le 180) {
                        $autoFixCooldownMinutes = $parsedAutoFixCooldown
                    }
                }
            }

            $restartRequiresConfirmation = $false
            if ($settings.Contains('LOCAL_GUARD_RESTART_REQUIRES_CONFIRM')) {
                $restartRequiresConfirmation = Convert-ToBooleanSetting -Value ([string]$settings.LOCAL_GUARD_RESTART_REQUIRES_CONFIRM) -Default $false
            }

            $restartApproved = (-not $restartRequiresConfirmation)
            if ($restartRequiresConfirmation -and $settings.Contains('LOCAL_GUARD_RESTART_APPROVED')) {
                $restartApproved = Convert-ToBooleanSetting -Value ([string]$settings.LOCAL_GUARD_RESTART_APPROVED) -Default $false
            }

            $suppressKnownInfraTickets = $true
            if ($settings.Contains('LOCAL_GUARD_SUPPRESS_KNOWN_INFRA_TICKETS')) {
                $suppressKnownInfraTickets = Convert-ToBooleanSetting -Value ([string]$settings.LOCAL_GUARD_SUPPRESS_KNOWN_INFRA_TICKETS) -Default $true
            }

            $exitOnKnownInfraTransient = $true
            if ($settings.Contains('LOCAL_GUARD_EXIT_ON_KNOWN_INFRA_TRANSIENT')) {
                $exitOnKnownInfraTransient = Convert-ToBooleanSetting -Value ([string]$settings.LOCAL_GUARD_EXIT_ON_KNOWN_INFRA_TRANSIENT) -Default $true
            }

            $agentQueueEnabled = $true
            if ($settings.Contains('LOCAL_GUARD_AGENT_QUEUE_ENABLED')) {
                $agentQueueEnabled = Convert-ToBooleanSetting -Value ([string]$settings.LOCAL_GUARD_AGENT_QUEUE_ENABLED) -Default $true
            }
            $agentQueuePath = Get-AgentTicketQueuePath -Settings $settings

            $taskDefinitionRepairTicketEnabled = $true
            if ($settings.Contains('LOCAL_GUARD_TASKDEF_REPAIR_TICKET_ENABLED')) {
                $taskDefinitionRepairTicketEnabled = Convert-ToBooleanSetting -Value ([string]$settings.LOCAL_GUARD_TASKDEF_REPAIR_TICKET_ENABLED) -Default $true
            }

            $statusTicketEnabled = $false
            if ($settings.Contains('LOCAL_GUARD_STATUS_TICKET_ENABLED')) {
                $statusTicketEnabled = Convert-ToBooleanSetting -Value ([string]$settings.LOCAL_GUARD_STATUS_TICKET_ENABLED) -Default $false
            }

            $statusTicketIntervalMinutes = 30
            if ($settings.Contains('LOCAL_GUARD_STATUS_TICKET_INTERVAL_MINUTES')) {
                $parsedStatusTicketInterval = 0
                if ([int]::TryParse(([string]$settings.LOCAL_GUARD_STATUS_TICKET_INTERVAL_MINUTES), [ref]$parsedStatusTicketInterval)) {
                    if ($parsedStatusTicketInterval -ge 1 -and $parsedStatusTicketInterval -le 180) {
                        $statusTicketIntervalMinutes = $parsedStatusTicketInterval
                    }
                }
            }

            $mainProcessExitMonitorGraceMinutes = 20
            if ($settings.Contains('LOCAL_GUARD_MAIN_EXIT_MONITOR_GRACE_MINUTES')) {
                $parsedMainExitGrace = 0
                if ([int]::TryParse(([string]$settings.LOCAL_GUARD_MAIN_EXIT_MONITOR_GRACE_MINUTES), [ref]$parsedMainExitGrace)) {
                    if ($parsedMainExitGrace -ge 0 -and $parsedMainExitGrace -le 120) {
                        $mainProcessExitMonitorGraceMinutes = [int]$parsedMainExitGrace
                    }
                }
            }
            if ($settings.Contains('MONITOR_CHAIN_GRACE_MINUTES')) {
                $parsedChainGrace = 0
                if ([int]::TryParse(([string]$settings.MONITOR_CHAIN_GRACE_MINUTES), [ref]$parsedChainGrace)) {
                    if ($parsedChainGrace -ge 0 -and $parsedChainGrace -le 120) {
                        $mainProcessExitMonitorGraceMinutes = [int]$parsedChainGrace
                    }
                }
            }

            $bRunningNoProcessGraceSec = [Math]::Max(([int]$PollSec * 3), 180)
            if ($settings.Contains('LOCAL_GUARD_B_RUNNING_NO_PROCESS_GRACE_SEC')) {
                $parsedGrace = 0
                if ([int]::TryParse(([string]$settings.LOCAL_GUARD_B_RUNNING_NO_PROCESS_GRACE_SEC), [ref]$parsedGrace)) {
                    if ($parsedGrace -ge 30 -and $parsedGrace -le 1800) {
                        $bRunningNoProcessGraceSec = [int]$parsedGrace
                    }
                }
            }

            $aRunningNoProcessGraceSec = $bRunningNoProcessGraceSec
            if ($settings.Contains('LOCAL_GUARD_A_RUNNING_NO_PROCESS_GRACE_SEC')) {
                $parsedAGrace = 0
                if ([int]::TryParse(([string]$settings.LOCAL_GUARD_A_RUNNING_NO_PROCESS_GRACE_SEC), [ref]$parsedAGrace)) {
                    if ($parsedAGrace -ge 30 -and $parsedAGrace -le 1800) {
                        $aRunningNoProcessGraceSec = [int]$parsedAGrace
                    }
                }
            }

            $aLaunchPid = 0
            if ($settings.Contains('A_LAUNCH_PID')) {
                $parsedALaunchPid = Convert-ToNullablePositiveInt -Value ([string]$settings.A_LAUNCH_PID)
                if ($null -ne $parsedALaunchPid) {
                    $aLaunchPid = [int]$parsedALaunchPid
                }
            }

            $bLaunchPid = 0
            if ($settings.Contains('B_LAUNCH_PID')) {
                $parsedLaunchPid = Convert-ToNullablePositiveInt -Value ([string]$settings.B_LAUNCH_PID)
                if ($null -ne $parsedLaunchPid) {
                    $bLaunchPid = [int]$parsedLaunchPid
                }
            }

            $notes = if ($settings.Contains('SESSION_FINAL_NOTES')) { [string]$settings.SESSION_FINAL_NOTES } else { '' }
            $runDirAnchor = Resolve-RunDirAnchorFromNotes -Notes $notes

            if ($null -ne $mainProcessExitGraceStartedAt) {
                $mainExitGraceRecovered = (
                    ($mainProcessExitGraceStage -eq 'A' -and $aStatus -eq 'RUNNING' -and $aLaunchPid -gt 0) -or
                    ($mainProcessExitGraceStage -eq 'B' -and $bStatus -eq 'RUNNING' -and $bLaunchPid -gt 0)
                )
                if ($mainExitGraceRecovered) {
                    $reboundPid = if ($mainProcessExitGraceStage -eq 'A') { $aLaunchPid } else { $bLaunchPid }
                    Write-GuardLog ("main_process_exit_grace_cleared stage={0} rebound_pid={1} session={2} a={3} b={4}" -f $mainProcessExitGraceStage, $reboundPid, $sessionStatus, $aStatus, $bStatus)
                    $mainProcessExitGraceStartedAt = $null
                    $mainProcessExitGraceLastNoticeAt = $null
                    $mainProcessExitGraceShutdownDetail = ''
                    $mainProcessExitGraceStage = ''
                }
            }

            if ($null -ne $monitorChainGraceStartedAt) {
                $monitorChainGraceRecovered = (
                    ($monitorChainGraceShutdownStage -eq 'A' -and $aStatus -eq 'RUNNING' -and $aLaunchPid -gt 0) -or
                    ($monitorChainGraceShutdownStage -eq 'B' -and $bStatus -eq 'RUNNING' -and $bLaunchPid -gt 0) -or
                    ($monitorChainGraceShutdownStage -eq 'SESSION' -and (
                        ($aStatus -eq 'RUNNING' -and $aLaunchPid -gt 0) -or
                        ($bStatus -eq 'RUNNING' -and $bLaunchPid -gt 0)
                    ))
                )
                if ($monitorChainGraceRecovered) {
                    $reboundPid = 0
                    if ($aStatus -eq 'RUNNING' -and $aLaunchPid -gt 0) {
                        $reboundPid = $aLaunchPid
                    }
                    elseif ($bStatus -eq 'RUNNING' -and $bLaunchPid -gt 0) {
                        $reboundPid = $bLaunchPid
                    }

                    Write-GuardLog (
                        "monitor_chain_grace_cleared stage={0} rebound_pid={1} reason={2} session={3} a={4} b={5}" -f
                        $monitorChainGraceShutdownStage,
                        $reboundPid,
                        $monitorChainGraceShutdownReason,
                        $sessionStatus,
                        $aStatus,
                        $bStatus)
                    $monitorChainGraceStartedAt = $null
                    $monitorChainGraceLastNoticeAt = $null
                    $monitorChainGraceShutdownDetail = ''
                    $monitorChainGraceShutdownStage = ''
                    $monitorChainGraceShutdownReason = ''
                    $monitorChainGraceShutdownSource = ''
                    $lastIncidentSignature = ''
                }
            }

            $mainProcessExitNoAutoFixStopRequested = $false
            $monitorChainShutdownRequest = Get-MonitorChainShutdownRequest -Settings $settings
            if ([bool]$monitorChainShutdownRequest.Requested -and $aStatus -ne 'RUNNING' -and $bStatus -ne 'RUNNING') {
                Write-GuardState -Values @{
                    status = 'stopped'
                    event = 'monitor-chain-shutdown-request'
                    stop_reason = 'monitor-chain-shutdown-request'
                    session_final_status = $sessionStatus
                    a_final_status = $aStatus
                    b_final_status = $bStatus
                }
                Write-GuardLog ("complete reason=monitor_chain_shutdown_request status={0} a={1} b={2} source={3} request_reason={4} request_at={5}" -f
                    $sessionStatus,
                    $aStatus,
                    $bStatus,
                    [string]$monitorChainShutdownRequest.Source,
                    [string]$monitorChainShutdownRequest.Reason,
                    [string]$monitorChainShutdownRequest.RequestedAt)
                break
            }

            $aPassConclusionEligible = ($sessionStatus -eq 'RUNNING' -and $aStatus -eq 'PASS' -and $bStatus -eq 'RUNNING')
            if ($aPassConclusionEligible) {
                $bLaunchPidForConclusion = 0
                if ($settings.Contains('B_LAUNCH_PID')) {
                    $parsedBLaunchPidForConclusion = Convert-ToNullablePositiveInt -Value ([string]$settings.B_LAUNCH_PID)
                    if ($null -ne $parsedBLaunchPidForConclusion) {
                        $bLaunchPidForConclusion = [int]$parsedBLaunchPidForConclusion
                    }
                }

                $aSnapshotFinalHint = ''
                if ($settings.Contains('A_SUCCESS_SNAPSHOT_FINAL_STATUS')) {
                    $aSnapshotFinalHint = Convert-ToSingleLineText -Text ([string]$settings.A_SUCCESS_SNAPSHOT_FINAL_STATUS)
                }

                $aPassConclusionDedup = ("{0}|{1}|{2}|{3}|{4}|{5}" -f
                    $sessionStatus,
                    $aStatus,
                    $bStatus,
                    $runDirAnchor,
                    $bLaunchPidForConclusion,
                    $aSnapshotFinalHint)

                if ($aPassConclusionDedup -ne $lastAPassConclusionSignature) {
                    $aPassConclusionDetail = ("A stage PASS confirmed; B stage launch observed (b_status={0}, b_launch_pid={1}); run_dir={2}" -f $bStatus, $bLaunchPidForConclusion, $runDirAnchor)
                    if (-not [string]::IsNullOrWhiteSpace($aSnapshotFinalHint)) {
                        $aPassConclusionDetail = ("{0}; a_snapshot_final={1}" -f $aPassConclusionDetail, $aSnapshotFinalHint)
                    }

                    $aPassConclusionAction = 'Provide an explicit A PASS completion conclusion with a concise A-stage run summary (key checkpoints and final evidence), then report that B-stage has started.'
                    $aPassConclusionTicketResult = Add-AgentTicket -Enabled $agentQueueEnabled -QueuePath $agentQueuePath -EventName 'a-pass-conclusion-b-started' -Severity 'info' -RequiresConfirmation $false -SessionStatus $sessionStatus -AStatus $aStatus -BStatus $bStatus -RunDirAnchor $runDirAnchor -IncidentDir '' -Detail $aPassConclusionDetail -DedupSuffix $aPassConclusionDedup -RecommendedAction $aPassConclusionAction -PreferredStage 'B' -MainRound '' -FailureKind 'stage-transition' -FailureCategory '' -FailureSource '' -FailureEvidence '' -SelfHealable $true -NonRecoverableEnv $false
                    if ([bool]$aPassConclusionTicketResult.Queued -or [string]$aPassConclusionTicketResult.Reason -in @('duplicate-signature', 'queue-disabled')) {
                        $lastAPassConclusionSignature = $aPassConclusionDedup
                    }
                }
            }

            $bPassFailConflict = Get-BPassFailConflictEvidence -Settings $settings -StartFilePath $script:StartFilePath
            if ([bool]$bPassFailConflict.conflict) {
                Write-GuardLog (
                    'status_conflict_detected reason={0} session={1} a={2} b={3} exit_result={4} exit_code={5} fail_category={6} fail_reason={7} artifact={8}' -f
                    [string]$bPassFailConflict.reason,
                    $sessionStatus,
                    $aStatus,
                    $bStatus,
                    [string]$bPassFailConflict.exit_result,
                    [int]$bPassFailConflict.exit_code,
                    [string]$bPassFailConflict.fail_category,
                    [string]$bPassFailConflict.fail_reason,
                    [string]$bPassFailConflict.artifact_path)

                $conflictNote = ('guard_pass_conflict b_exit_fail artifact={0} exit_code={1} fail_category={2}' -f [string]$bPassFailConflict.artifact_path, [int]$bPassFailConflict.exit_code, [string]$bPassFailConflict.fail_category)
                $updatedNotes = Add-DelimitedNote -Existing $notes -Append $conflictNote

                try {
                    Invoke-KeyValueFileValueUpdate -Path $script:StartFilePath -Values @{
                        B_FINAL_STATUS = 'FAIL'
                        B_LAUNCH_PID = '0'
                        SESSION_FINAL_STATUS = 'FAIL'
                        SESSION_CLOSED = 'false'
                        SESSION_CLOSED_AT = ''
                        SESSION_CLOSED_REASON = 'b-exit-fail-conflict'
                        SESSION_FINAL_NOTES = $updatedNotes
                    }
                    Write-GuardLog ('status_conflict_reconciled action=write_fail_status artifact={0}' -f [string]$bPassFailConflict.artifact_path)

                    $settings = Read-KeyValueFile -Path $script:StartFilePath

                    $sessionStatusRaw = 'NOT_RUN'
                    if ($settings.Contains('SESSION_FINAL_STATUS')) {
                        $sessionStatusRaw = [string]$settings.SESSION_FINAL_STATUS
                    }

                    $aStatusRaw = 'NOT_RUN'
                    if ($settings.Contains('A_FINAL_STATUS')) {
                        $aStatusRaw = [string]$settings.A_FINAL_STATUS
                    }

                    $bStatusRaw = 'NOT_RUN'
                    if ($settings.Contains('B_FINAL_STATUS')) {
                        $bStatusRaw = [string]$settings.B_FINAL_STATUS
                    }

                    $sessionStatus = Get-StatusValue -Value $sessionStatusRaw
                    $aStatus = Get-StatusValue -Value $aStatusRaw
                    $bStatus = Get-StatusValue -Value $bStatusRaw
                    $notes = if ($settings.Contains('SESSION_FINAL_NOTES')) { [string]$settings.SESSION_FINAL_NOTES } else { '' }
                    $runDirAnchor = Resolve-RunDirAnchorFromNotes -Notes $notes

                    $bLaunchPid = 0
                    if ($settings.Contains('B_LAUNCH_PID')) {
                        $parsedLaunchPid = Convert-ToNullablePositiveInt -Value ([string]$settings.B_LAUNCH_PID)
                        if ($null -ne $parsedLaunchPid) {
                            $bLaunchPid = [int]$parsedLaunchPid
                        }
                    }
                }
                catch {
                    Write-GuardLog ('status_conflict_reconcile_failed detail={0}' -f (Convert-ToSingleLineText -Text $_.Exception.Message))
                }
            }

            # INIT-DEAD-PROCESS-CHECK: detect when B stage already terminal (FAIL/BLOCKED)
            # but session is still RUNNING — indicates B process exited before the main
            # supervisor loop could detect it. Enter main-process-exit grace to allow
            # time for recovery or clean shutdown.
            if ($null -eq $mainProcessExitGraceStartedAt -and $bStatus -in @('FAIL', 'BLOCKED') -and $sessionStatus -eq 'RUNNING') {
                $deadBLaunchPid = 0
                if ($settings.Contains('B_LAUNCH_PID')) {
                    $parsedDeadBPid = Convert-ToNullablePositiveInt -Value ([string]$settings.B_LAUNCH_PID)
                    if ($null -ne $parsedDeadBPid) {
                        $deadBLaunchPid = [int]$parsedDeadBPid
                    }
                }
                $deadBProcessAlive = ($deadBLaunchPid -gt 0)
                if ($deadBProcessAlive) {
                    try { $null = Get-Process -Id $deadBLaunchPid -ErrorAction Stop } catch { $deadBProcessAlive = $false }
                }
                if (-not $deadBProcessAlive) {
                    $initDeadNote = "guard_init_dead_process stage=B status={0} pid={1}" -f $bStatus, $deadBLaunchPid
                    $updatedNotes = Add-DelimitedNote -Existing $notes -Append $initDeadNote
                    Invoke-KeyValueFileValueUpdate -Path $script:StartFilePath -Values @{
                        B_FINAL_STATUS = 'FAIL'
                        B_LAUNCH_PID = '0'
                        SESSION_FINAL_NOTES = $updatedNotes
                    }
                    $canRecoverBAfterMissing = ($aStatus -eq 'PASS' -and $bStatus -in @('FAIL', 'BLOCKED'))
                    $autoRecoverPossibleAfterMissing = ([bool]$autoRecoverB -and [bool]$canRecoverBAfterMissing)
                    $shutdownDetail = ("init_dead_process stage=B pid={0} session={1} a={2} b={3} run_dir={4}" -f $deadBLaunchPid, $sessionStatus, $aStatus, $bStatus, $runDirAnchor)
                    if ($mainProcessExitMonitorGraceMinutes -gt 0) {
                        $mainProcessExitGraceStartedAt = Get-Date
                        $mainProcessExitGraceLastNoticeAt = $null
                        $mainProcessExitGraceShutdownDetail = $shutdownDetail
                        $mainProcessExitGraceStage = 'B'
                        Write-GuardLog ("init_dead_process_grace_start stage=B grace_min={0} pid={1} session={2} a={3} b={4} auto_recover_b={5} can_recover_b={6} run_dir={7}" -f $mainProcessExitMonitorGraceMinutes, $deadBLaunchPid, $sessionStatus, $aStatus, $bStatus, [bool]$autoRecoverB, [bool]$canRecoverBAfterMissing, $runDirAnchor)
                    }
                    else {
                        $settings = Request-MonitorChainShutdown -Settings $settings -Reason 'init-dead-process' -Source 'session-guard' -Detail $shutdownDetail
                        $mainProcessExitNoAutoFixStopRequested = $true
                    }
                }
            }

            $running = ($aStatus -eq 'RUNNING' -or $bStatus -eq 'RUNNING')
            if ($running) {
                $lastTaskDefinitionFixSignature = ''
            }

            if ($running -and $manualPauseActive) {
                Write-GuardLog ("manual_wait_resume session={0} a={1} b={2} run_dir={3}" -f $sessionStatus, $aStatus, $bStatus, $runDirAnchor)
                $manualPauseActive = $false
                $manualPauseSignature = ''
                $manualPauseNoticeCount = 0
            }

            $aProcessSnapshot = $null
            if ($aStatus -eq 'RUNNING') {
                $aProcessSnapshot = Get-AStageProcessSnapshot -ExpectedProcessId $aLaunchPid

                if ([bool]$aProcessSnapshot.AnchorUpdateRequired) {
                    $newALaunchPid = [int]$aProcessSnapshot.ResolvedProcessId
                    Invoke-KeyValueFileValueUpdate -Path $script:StartFilePath -Values @{
                        A_LAUNCH_PID = [string]$newALaunchPid
                    }
                    Write-GuardLog ("a_anchor_refresh old_pid={0} new_pid={1} source={2} candidate_count={3}" -f $aLaunchPid, $newALaunchPid, $aProcessSnapshot.ResolvedSource, $aProcessSnapshot.CandidateCount)
                    $aLaunchPid = $newALaunchPid
                }

                if ([bool]$aProcessSnapshot.HasAliveProcess) {
                    $aRunningNoProcessSince = $null
                    $lastMissingAProcessReportAt = $null
                }
                else {
                    $nowA = Get-Date
                    if ($null -eq $aRunningNoProcessSince) {
                        $aRunningNoProcessSince = $nowA
                        $lastMissingAProcessReportAt = $nowA
                        Write-GuardLog ("a_process_missing_start expected_pid={0} candidate_count={1} grace_sec={2}" -f $aLaunchPid, $aProcessSnapshot.CandidateCount, $aRunningNoProcessGraceSec)
                    }
                    elseif ($null -eq $lastMissingAProcessReportAt -or (($nowA - $lastMissingAProcessReportAt).TotalMinutes -ge 5)) {
                        $missingASecReport = [Math]::Max(0, [int][Math]::Round(($nowA - $aRunningNoProcessSince).TotalSeconds))
                        Write-GuardLog ("a_process_missing_wait expected_pid={0} elapsed_sec={1} grace_sec={2}" -f $aLaunchPid, $missingASecReport, $aRunningNoProcessGraceSec)
                        $lastMissingAProcessReportAt = $nowA
                    }

                    $missingASec = [Math]::Max(0, [int][Math]::Round(((Get-Date) - $aRunningNoProcessSince).TotalSeconds))
                    if ($missingASec -ge $aRunningNoProcessGraceSec) {
                        $sessionStatusAfterAMissing = if ($bStatus -eq 'RUNNING') { $sessionStatus } else { 'FAIL' }
                        $aFailureNote = ("guard_detected a_process_missing expected_pid={0} elapsed_sec={1} grace_sec={2}" -f $aLaunchPid, $missingASec, $aRunningNoProcessGraceSec)
                        $newANotes = Add-DelimitedNote -Existing $notes -Append $aFailureNote

                        Invoke-KeyValueFileValueUpdate -Path $script:StartFilePath -Values @{
                            A_FINAL_STATUS = 'FAIL'
                            SESSION_FINAL_STATUS = $sessionStatusAfterAMissing
                            A_LAUNCH_PID = '0'
                            SESSION_FINAL_NOTES = $newANotes
                        }
                        Write-GuardLog ("a_process_missing_fail expected_pid={0} elapsed_sec={1} grace_sec={2} session_status={3}" -f $aLaunchPid, $missingASec, $aRunningNoProcessGraceSec, $sessionStatusAfterAMissing)

                        $settings = Read-KeyValueFile -Path $script:StartFilePath
                        $sessionStatusRawAfterA = 'NOT_RUN'
                        if ($settings.Contains('SESSION_FINAL_STATUS')) {
                            $sessionStatusRawAfterA = [string]$settings.SESSION_FINAL_STATUS
                        }
                        $aStatusRawAfterA = 'NOT_RUN'
                        if ($settings.Contains('A_FINAL_STATUS')) {
                            $aStatusRawAfterA = [string]$settings.A_FINAL_STATUS
                        }
                        $bStatusRawAfterA = 'NOT_RUN'
                        if ($settings.Contains('B_FINAL_STATUS')) {
                            $bStatusRawAfterA = [string]$settings.B_FINAL_STATUS
                        }

                        $sessionStatus = Get-StatusValue -Value $sessionStatusRawAfterA
                        $aStatus = Get-StatusValue -Value $aStatusRawAfterA
                        $bStatus = Get-StatusValue -Value $bStatusRawAfterA
                        $running = ($aStatus -eq 'RUNNING' -or $bStatus -eq 'RUNNING')
                        $notes = if ($settings.Contains('SESSION_FINAL_NOTES')) { [string]$settings.SESSION_FINAL_NOTES } else { '' }
                        $runDirAnchor = Resolve-RunDirAnchorFromNotes -Notes $notes

                        $aMainExitDetail = ("main_process=A expected_pid={0} elapsed_sec={1} grace_sec={2}" -f $aLaunchPid, $missingASec, $aRunningNoProcessGraceSec)
                        $aMainExitDedupSuffix = ("{0}|{1}|{2}|{3}|{4}|stage=A" -f $sessionStatus, $aStatus, $bStatus, $runDirAnchor, $aLaunchPid)
                        if ($aMainExitDedupSuffix -ne $lastMainProcessExitReviewSignature) {
                            $aMainExitRecommendedAction = 'Review A-stage main-process exit evidence and root cause, then run script-level self-heal for recoverable faults before deciding the next restart step.'
                            $aMainExitEvidence = Convert-ToBoundedSingleLineText -Text $aMainExitDetail -MaxChars 220
                            $aMainExitTicketResult = Add-AgentTicket -Enabled $agentQueueEnabled -QueuePath $agentQueuePath -EventName 'main-process-exit-review' -Severity 'high' -RequiresConfirmation $false -SessionStatus $sessionStatus -AStatus $aStatus -BStatus $bStatus -RunDirAnchor $runDirAnchor -IncidentDir '' -Detail $aMainExitDetail -DedupSuffix $aMainExitDedupSuffix -RecommendedAction $aMainExitRecommendedAction -PreferredStage 'A' -MainRound '' -FailureKind 'main-process-exit' -FailureCategory 'script-fault' -FailureSource 'tools/test/unattended_ab_session_guard.ps1' -FailureEvidence $aMainExitEvidence -SelfHealable $true -NonRecoverableEnv $false
                            if ([bool]$aMainExitTicketResult.Queued -or [string]$aMainExitTicketResult.Reason -eq 'duplicate-signature') {
                                $lastMainProcessExitReviewSignature = $aMainExitDedupSuffix
                            }
                        }

                        $aLaunchPid = 0
                        $aRunningNoProcessSince = $null
                        $lastMissingAProcessReportAt = $null
                    }
                }
            }
            else {
                $aRunningNoProcessSince = $null
                $lastMissingAProcessReportAt = $null
            }

            $bProcessSnapshot = $null
            if ($bStatus -eq 'RUNNING') {
                $bProcessSnapshot = Get-BStageProcessSnapshot -ExpectedProcessId $bLaunchPid

                # Detect no-exit shell cases: process PID is still alive but stage-exit artifact is already terminal.
                if ([bool]$bProcessSnapshot.HasAliveProcess -and $bLaunchPid -gt 0) {
                    $shellLikeExitEvidence = Get-BStageExitReasonEvidence -ExpectedProcessId $bLaunchPid
                    $shellLikeExitMatched = (
                        $null -ne $shellLikeExitEvidence -and
                        [bool]$shellLikeExitEvidence.Available -and
                        ([string]$shellLikeExitEvidence.Stage -eq 'B') -and
                        [bool]$shellLikeExitEvidence.StartFileMatch -and
                        [bool]$shellLikeExitEvidence.ProcessIdMatch -and
                        ([string]$shellLikeExitEvidence.Result -in @('pass', 'fail'))
                    )

                    if ($shellLikeExitMatched) {
                        Write-GuardLog ("b_shell_alive_after_terminal_exit expected_pid={0} artifact_pid={1} result={2} exit_code={3} category={4} artifact={5}" -f
                            $bLaunchPid,
                            [int]$shellLikeExitEvidence.ProcessId,
                            [string]$shellLikeExitEvidence.Result,
                            [int]$shellLikeExitEvidence.ExitCode,
                            [string]$shellLikeExitEvidence.FailCategory,
                            [string]$shellLikeExitEvidence.ArtifactPath)

                        $bProcessSnapshot = [pscustomobject]@{
                            ExpectedProcessId = [int]$bProcessSnapshot.ExpectedProcessId
                            ExpectedAlive = $false
                            CandidateCount = [int]$bProcessSnapshot.CandidateCount
                            CandidateIds = @($bProcessSnapshot.CandidateIds)
                            ResolvedProcessId = [int]$bProcessSnapshot.ResolvedProcessId
                            ResolvedSource = 'terminal-exit-artifact'
                            HasAliveProcess = $false
                            AnchorUpdateRequired = $false
                        }
                    }
                }

                if ([bool]$bProcessSnapshot.AnchorUpdateRequired) {
                    $newBLaunchPid = [int]$bProcessSnapshot.ResolvedProcessId
                    Invoke-KeyValueFileValueUpdate -Path $script:StartFilePath -Values @{
                        B_LAUNCH_PID = [string]$newBLaunchPid
                    }
                    Write-GuardLog ("b_anchor_refresh old_pid={0} new_pid={1} source={2} candidate_count={3}" -f $bLaunchPid, $newBLaunchPid, $bProcessSnapshot.ResolvedSource, $bProcessSnapshot.CandidateCount)
                    $bLaunchPid = $newBLaunchPid
                }

                if ([bool]$bProcessSnapshot.HasAliveProcess) {
                    $bRunningNoProcessSince = $null
                    $lastMissingBProcessReportAt = $null
                    $lastBMissingExitReasonEvidence = $null
                    $lastBMissingRuntimeTailEvidence = $null
                }
                else {
                    $now = Get-Date
                    if ($null -eq $bRunningNoProcessSince) {
                        $bRunningNoProcessSince = $now
                        $lastMissingBProcessReportAt = $now
                        Write-GuardLog ("b_process_missing_start expected_pid={0} candidate_count={1} grace_sec={2}" -f $bLaunchPid, $bProcessSnapshot.CandidateCount, $bRunningNoProcessGraceSec)

                        $lastBMissingExitReasonEvidence = Get-BStageExitReasonEvidence -ExpectedProcessId $bLaunchPid
                        $reasonMatched = $false
                        if ($null -ne $lastBMissingExitReasonEvidence) {
                            $reasonMatched = (
                                [bool]$lastBMissingExitReasonEvidence.Available -and
                                ([string]$lastBMissingExitReasonEvidence.Stage -eq 'B') -and
                                [bool]$lastBMissingExitReasonEvidence.StartFileMatch -and
                                [bool]$lastBMissingExitReasonEvidence.ProcessIdMatch
                            )

                            if ($reasonMatched) {
                                Write-GuardLog ("b_process_missing_reason expected_pid={0} artifact_pid={1} result={2} exit_code={3} category={4} detail={5} artifact={6}" -f
                                    $bLaunchPid,
                                    [int]$lastBMissingExitReasonEvidence.ProcessId,
                                    [string]$lastBMissingExitReasonEvidence.Result,
                                    [int]$lastBMissingExitReasonEvidence.ExitCode,
                                    [string]$lastBMissingExitReasonEvidence.FailCategory,
                                    [string]$lastBMissingExitReasonEvidence.FailReason,
                                    [string]$lastBMissingExitReasonEvidence.ArtifactPath)
                            }
                            elseif ([bool]$lastBMissingExitReasonEvidence.Available) {
                                Write-GuardLog ("b_process_missing_reason_unmatched expected_pid={0} artifact_pid={1} stage={2} start_file_match={3} pid_match={4} artifact={5}" -f
                                    $bLaunchPid,
                                    [int]$lastBMissingExitReasonEvidence.ProcessId,
                                    [string]$lastBMissingExitReasonEvidence.Stage,
                                    [bool]$lastBMissingExitReasonEvidence.StartFileMatch,
                                    [bool]$lastBMissingExitReasonEvidence.ProcessIdMatch,
                                    [string]$lastBMissingExitReasonEvidence.ArtifactPath)
                            }
                            elseif (-not [string]::IsNullOrWhiteSpace([string]$lastBMissingExitReasonEvidence.ParseError)) {
                                Write-GuardLog ("b_process_missing_reason_parse_error expected_pid={0} artifact={1} detail={2}" -f
                                    $bLaunchPid,
                                    [string]$lastBMissingExitReasonEvidence.ArtifactPath,
                                    [string]$lastBMissingExitReasonEvidence.ParseError)
                            }
                            else {
                                Write-GuardLog ("b_process_missing_reason_unavailable expected_pid={0} artifact={1}" -f
                                    $bLaunchPid,
                                    [string]$lastBMissingExitReasonEvidence.ArtifactPath)
                            }
                        }

                        if (-not $reasonMatched) {
                            $artifactRuntimeLogPath = ''
                            if ($null -ne $lastBMissingExitReasonEvidence) {
                                $artifactRuntimeLogPath = [string]$lastBMissingExitReasonEvidence.RuntimeLogPath
                            }

                            $runtimeLogHint = Get-BRuntimeLogHint -Settings $settings -ArtifactRuntimeLogPath $artifactRuntimeLogPath
                            $lastBMissingRuntimeTailEvidence = Get-BRuntimeTailEvidence -RuntimeLogPath $runtimeLogHint -PrimaryTail 10 -ExpandedTail 30 -MaxTail 80 -MinimumUsefulLines 6
                            if ($null -ne $lastBMissingRuntimeTailEvidence -and [bool]$lastBMissingRuntimeTailEvidence.Available) {
                                $tailLines = @($lastBMissingRuntimeTailEvidence.Lines)
                                $tailPreview = Convert-ToBoundedSingleLineText -Text ($tailLines -join ' || ') -MaxChars 240
                                Write-GuardLog ("b_process_missing_tail expected_pid={0} log={1} used_tail={2} escalated={3} lines={4} detail_preview={5}" -f
                                    $bLaunchPid,
                                    [string]$lastBMissingRuntimeTailEvidence.RuntimeLogPath,
                                    [int]$lastBMissingRuntimeTailEvidence.UsedTail,
                                    [bool]$lastBMissingRuntimeTailEvidence.Escalated,
                                    $tailLines.Count,
                                    $tailPreview)

                                $tailBlockLines = New-Object 'System.Collections.Generic.List[string]'
                                [void]$tailBlockLines.Add(("expected_pid={0} log={1} used_tail={2} escalated={3} lines={4}" -f
                                        $bLaunchPid,
                                        [string]$lastBMissingRuntimeTailEvidence.RuntimeLogPath,
                                        [int]$lastBMissingRuntimeTailEvidence.UsedTail,
                                        [bool]$lastBMissingRuntimeTailEvidence.Escalated,
                                        $tailLines.Count))
                                foreach ($tailLine in $tailLines) {
                                    [void]$tailBlockLines.Add(("line={0}" -f [string]$tailLine))
                                }
                                Write-GuardPastedBlock -Tag 'b_process_missing_tail_block' -Lines @($tailBlockLines)
                            }
                            elseif ($null -ne $lastBMissingRuntimeTailEvidence -and -not [string]::IsNullOrWhiteSpace([string]$lastBMissingRuntimeTailEvidence.Error)) {
                                Write-GuardLog ("b_process_missing_tail_error expected_pid={0} log={1} detail={2}" -f
                                    $bLaunchPid,
                                    [string]$runtimeLogHint,
                                    [string]$lastBMissingRuntimeTailEvidence.Error)
                            }
                            else {
                                Write-GuardLog ("b_process_missing_tail_unavailable expected_pid={0} log={1}" -f
                                    $bLaunchPid,
                                    [string]$runtimeLogHint)
                            }
                        }
                        else {
                            $lastBMissingRuntimeTailEvidence = $null
                        }
                    }
                    elseif ($null -eq $lastMissingBProcessReportAt -or (($now - $lastMissingBProcessReportAt).TotalMinutes -ge 5)) {
                        $missingSecReport = [Math]::Max(0, [int][Math]::Round(($now - $bRunningNoProcessSince).TotalSeconds))
                        Write-GuardLog ("b_process_missing_wait expected_pid={0} elapsed_sec={1} grace_sec={2}" -f $bLaunchPid, $missingSecReport, $bRunningNoProcessGraceSec)
                        $lastMissingBProcessReportAt = $now
                    }

                    $missingSec = [Math]::Max(0, [int][Math]::Round(((Get-Date) - $bRunningNoProcessSince).TotalSeconds))
                    if ($missingSec -ge $bRunningNoProcessGraceSec) {
                        $sessionStatusToWrite = if ($aStatus -eq 'RUNNING') { $sessionStatus } else { 'FAIL' }
                        $failureNote = "guard_detected b_process_missing expected_pid={0} elapsed_sec={1} grace_sec={2}" -f $bLaunchPid, $missingSec, $bRunningNoProcessGraceSec

                        $reasonMatchedForNotes = (
                            $null -ne $lastBMissingExitReasonEvidence -and
                            [bool]$lastBMissingExitReasonEvidence.Available -and
                            ([string]$lastBMissingExitReasonEvidence.Stage -eq 'B') -and
                            [bool]$lastBMissingExitReasonEvidence.StartFileMatch -and
                            [bool]$lastBMissingExitReasonEvidence.ProcessIdMatch
                        )
                        if ($reasonMatchedForNotes) {
                            $failureNote = $failureNote + (" exit_category={0} exit_code={1} exit_reason={2}" -f
                                [string]$lastBMissingExitReasonEvidence.FailCategory,
                                [int]$lastBMissingExitReasonEvidence.ExitCode,
                                [string]$lastBMissingExitReasonEvidence.FailReason)
                        }
                        elseif ($null -ne $lastBMissingRuntimeTailEvidence -and [bool]$lastBMissingRuntimeTailEvidence.Available) {
                            $tailLinesForNote = @($lastBMissingRuntimeTailEvidence.Lines)
                            $tailExcerptForNote = Convert-ToBoundedSingleLineText -Text ($tailLinesForNote -join ' || ') -MaxChars 360
                            if (-not [string]::IsNullOrWhiteSpace($tailExcerptForNote)) {
                                $failureNote = $failureNote + (" tail_log={0} tail_lines={1} tail_used={2} tail_excerpt={3}" -f
                                    [string]$lastBMissingRuntimeTailEvidence.RuntimeLogPath,
                                    $tailLinesForNote.Count,
                                    [int]$lastBMissingRuntimeTailEvidence.UsedTail,
                                    $tailExcerptForNote)
                            }
                        }

                        $newNotes = Add-DelimitedNote -Existing $notes -Append $failureNote
                        Invoke-KeyValueFileValueUpdate -Path $script:StartFilePath -Values @{
                            B_FINAL_STATUS = 'FAIL'
                            SESSION_FINAL_STATUS = $sessionStatusToWrite
                            B_LAUNCH_PID = '0'
                            SESSION_FINAL_NOTES = $newNotes
                        }
                        Write-GuardLog ("b_process_missing_fail expected_pid={0} elapsed_sec={1} grace_sec={2} session_status={3}" -f $bLaunchPid, $missingSec, $bRunningNoProcessGraceSec, $sessionStatusToWrite)

                        $settings = Read-KeyValueFile -Path $script:StartFilePath
                        $sessionStatusRawAfter = 'NOT_RUN'
                        if ($settings.Contains('SESSION_FINAL_STATUS')) {
                            $sessionStatusRawAfter = [string]$settings.SESSION_FINAL_STATUS
                        }
                        $aStatusRawAfter = 'NOT_RUN'
                        if ($settings.Contains('A_FINAL_STATUS')) {
                            $aStatusRawAfter = [string]$settings.A_FINAL_STATUS
                        }
                        $bStatusRawAfter = 'NOT_RUN'
                        if ($settings.Contains('B_FINAL_STATUS')) {
                            $bStatusRawAfter = [string]$settings.B_FINAL_STATUS
                        }
                        $sessionStatus = Get-StatusValue -Value $sessionStatusRawAfter
                        $aStatus = Get-StatusValue -Value $aStatusRawAfter
                        $bStatus = Get-StatusValue -Value $bStatusRawAfter
                        $running = ($aStatus -eq 'RUNNING' -or $bStatus -eq 'RUNNING')
                        $notes = if ($settings.Contains('SESSION_FINAL_NOTES')) { [string]$settings.SESSION_FINAL_NOTES } else { '' }
                        $runDirAnchor = Resolve-RunDirAnchorFromNotes -Notes $notes

                        $canRecoverBAfterMissing = ($aStatus -eq 'PASS' -and $bStatus -in @('FAIL', 'BLOCKED'))
                        $autoRecoverPossibleAfterMissing = ([bool]$autoRecoverB -and [bool]$canRecoverBAfterMissing)
                        $mainExitEvidenceToken = ''
                        $mainExitDetail = ("main_process=B expected_pid={0} elapsed_sec={1} grace_sec={2}" -f $bLaunchPid, $missingSec, $bRunningNoProcessGraceSec)

                        if ($reasonMatchedForNotes) {
                            $mainExitEvidenceToken = ("artifact:{0}|exit:{1}|category:{2}" -f
                                [string]$lastBMissingExitReasonEvidence.ArtifactPath,
                                [int]$lastBMissingExitReasonEvidence.ExitCode,
                                [string]$lastBMissingExitReasonEvidence.FailCategory)
                            $mainExitDetail = ($mainExitDetail + (" artifact={0} exit_result={1} exit_code={2} exit_category={3} exit_reason={4}" -f
                                    [string]$lastBMissingExitReasonEvidence.ArtifactPath,
                                    [string]$lastBMissingExitReasonEvidence.Result,
                                    [int]$lastBMissingExitReasonEvidence.ExitCode,
                                    [string]$lastBMissingExitReasonEvidence.FailCategory,
                                    [string]$lastBMissingExitReasonEvidence.FailReason))
                        }
                        elseif ($null -ne $lastBMissingRuntimeTailEvidence -and [bool]$lastBMissingRuntimeTailEvidence.Available) {
                            $tailLinesForTicket = @($lastBMissingRuntimeTailEvidence.Lines)
                            $tailExcerptForTicket = Convert-ToBoundedSingleLineText -Text ($tailLinesForTicket -join ' || ') -MaxChars 240
                            $mainExitEvidenceToken = ("tail:{0}|used:{1}|lines:{2}" -f [string]$lastBMissingRuntimeTailEvidence.RuntimeLogPath, [int]$lastBMissingRuntimeTailEvidence.UsedTail, $tailLinesForTicket.Count)
                            $mainExitDetail = ($mainExitDetail + (" tail_log={0} tail_used={1} tail_lines={2} tail_excerpt={3}" -f
                                    [string]$lastBMissingRuntimeTailEvidence.RuntimeLogPath,
                                    [int]$lastBMissingRuntimeTailEvidence.UsedTail,
                                    $tailLinesForTicket.Count,
                                    $tailExcerptForTicket))
                        }

                        if ([string]::IsNullOrWhiteSpace($mainExitEvidenceToken)) {
                            $mainExitEvidenceToken = 'evidence-unavailable'
                        }

                        $mainExitDedupSuffix = ("{0}|{1}|{2}|{3}|{4}|{5}|{6}" -f
                            $sessionStatus,
                            $aStatus,
                            $bStatus,
                            $runDirAnchor,
                            $bLaunchPid,
                            [bool]$autoRecoverB,
                            $mainExitEvidenceToken)

                        if ($mainExitDedupSuffix -ne $lastMainProcessExitReviewSignature) {
                            $mainExitRecommendedAction = 'Review main-process exit evidence and provide a clear failure conclusion; then perform post-failure cleanup by letting monitor scripts exit gracefully (keep NoExit terminal windows for forensics) before next restart decision.'
                            $mainExitFailureCategory = ''
                            $mainExitFailureEvidence = ''
                            if ($reasonMatchedForNotes) {
                                $mainExitFailureCategory = Convert-ToSingleLineText -Text ([string]$lastBMissingExitReasonEvidence.FailCategory)
                                $mainExitFailureEvidence = Convert-ToSingleLineText -Text ([string]$lastBMissingExitReasonEvidence.FailReason)
                            }
                            if ([string]::IsNullOrWhiteSpace($mainExitFailureEvidence)) {
                                $mainExitFailureEvidence = Convert-ToBoundedSingleLineText -Text $mainExitDetail -MaxChars 220
                            }

                            $mainExitPreferredStage = ''
                            if ($canRecoverBAfterMissing) {
                                $mainExitPreferredStage = 'B'
                            }
                            elseif ($aStatus -in @('RUNNING', 'FAIL', 'BLOCKED', 'NOT_RUN')) {
                                $mainExitPreferredStage = 'A'
                            }

                            $mainExitTicketResult = Add-AgentTicket -Enabled $agentQueueEnabled -QueuePath $agentQueuePath -EventName 'main-process-exit-review' -Severity 'high' -RequiresConfirmation $false -SessionStatus $sessionStatus -AStatus $aStatus -BStatus $bStatus -RunDirAnchor $runDirAnchor -IncidentDir '' -Detail $mainExitDetail -DedupSuffix $mainExitDedupSuffix -RecommendedAction $mainExitRecommendedAction -PreferredStage $mainExitPreferredStage -MainRound '' -FailureKind 'main-process-exit' -FailureCategory $mainExitFailureCategory -FailureSource 'tools/test/unattended_ab_session_guard.ps1' -FailureEvidence $mainExitFailureEvidence -SelfHealable $true -NonRecoverableEnv $false
                            if ([bool]$mainExitTicketResult.Queued -or [string]$mainExitTicketResult.Reason -eq 'duplicate-signature') {
                                $lastMainProcessExitReviewSignature = $mainExitDedupSuffix
                            }
                        }

                        if (-not $autoRecoverPossibleAfterMissing) {
                            $shutdownDetail = ("main_process_exit expected_pid={0} auto_recover_b={1} can_recover_b={2} run_dir={3}" -f $bLaunchPid, [bool]$autoRecoverB, [bool]$canRecoverBAfterMissing, $runDirAnchor)
                            if ($mainProcessExitMonitorGraceMinutes -gt 0) {
                                $mainProcessExitGraceStartedAt = Get-Date
                                $mainProcessExitGraceLastNoticeAt = $null
                                $mainProcessExitGraceShutdownDetail = $shutdownDetail
                                $mainProcessExitGraceStage = 'B'
                                Write-GuardLog ("main_process_exit_grace_start stage=B grace_min={0} expected_pid={1} session={2} a={3} b={4} auto_recover_b={5} can_recover_b={6} run_dir={7}" -f $mainProcessExitMonitorGraceMinutes, $bLaunchPid, $sessionStatus, $aStatus, $bStatus, [bool]$autoRecoverB, [bool]$canRecoverBAfterMissing, $runDirAnchor)
                            }
                            else {
                                $settings = Request-MonitorChainShutdown -Settings $settings -Reason 'main-process-exit-no-autofix' -Source 'session-guard' -Detail $shutdownDetail
                                $mainProcessExitNoAutoFixStopRequested = $true
                            }
                        }

                        $bLaunchPid = 0
                        $bRunningNoProcessSince = $null
                        $lastMissingBProcessReportAt = $null
                        $lastBMissingExitReasonEvidence = $null
                        $lastBMissingRuntimeTailEvidence = $null
                    }
                }
            }
            else {
                $bRunningNoProcessSince = $null
                $lastMissingBProcessReportAt = $null
                $lastBMissingExitReasonEvidence = $null
                $lastBMissingRuntimeTailEvidence = $null
            }

            $running = ($aStatus -eq 'RUNNING' -or $bStatus -eq 'RUNNING')

            $guardLoopStatus = 'idle'
            if ($manualPauseActive -and -not $running) {
                $guardLoopStatus = 'paused'
            }
            elseif ($running) {
                $guardLoopStatus = 'running'
            }

            $lastRecoveryAtText = ''
            if ($lastRecoveryAt -ne [datetime]::MinValue) {
                $lastRecoveryAtText = $lastRecoveryAt.ToString('yyyy-MM-dd HH:mm:ss')
            }

            $lastStatusTicketAtText = ''
            if ($lastStatusTicketAt -ne [datetime]::MinValue) {
                $lastStatusTicketAtText = $lastStatusTicketAt.ToString('yyyy-MM-dd HH:mm:ss')
            }

            Write-GuardState -Values @{
                status = $guardLoopStatus
                session_final_status = $sessionStatus
                a_final_status = $aStatus
                b_final_status = $bStatus
                run_dir = $runDirAnchor
                a_launch_pid = [int]$aLaunchPid
                a_stage_process_alive = if ($null -ne $aProcessSnapshot) { [bool]$aProcessSnapshot.HasAliveProcess } else { $null }
                a_stage_process_candidates = if ($null -ne $aProcessSnapshot) { [int]$aProcessSnapshot.CandidateCount } else { 0 }
                a_running_no_process_grace_sec = [int]$aRunningNoProcessGraceSec
                b_launch_pid = [int]$bLaunchPid
                b_stage_process_alive = if ($null -ne $bProcessSnapshot) { [bool]$bProcessSnapshot.HasAliveProcess } else { $null }
                b_stage_process_candidates = if ($null -ne $bProcessSnapshot) { [int]$bProcessSnapshot.CandidateCount } else { 0 }
                b_running_no_process_grace_sec = [int]$bRunningNoProcessGraceSec
                poll_sec = [int]$PollSec
                max_b_recovery_attempts = [int]$MaxBRecoveryAttempts
                recovery_cooldown_minutes = [int]$RecoveryCooldownMinutes
                stop_on_budget_exhausted = [bool]$StopOnBudgetExhausted
                auto_recover_b = [bool]$autoRecoverB
                b_recovery_attempts = [int]$bRecoveryAttempts
                last_recovery_at = $lastRecoveryAtText
                manual_wait_for_restart = [bool]$manualPauseEnabled
                manual_wait_paused = [bool]$manualPauseActive
                manual_notice_repeat = [int]$manualPauseNoticeRepeat
                force_exit_on_final_no_followup = [bool]$forceExitOnFinalNoFollowup
                restart_requires_confirmation = [bool]$restartRequiresConfirmation
                restart_approved = [bool]$restartApproved
                suppress_known_infra_tickets = [bool]$suppressKnownInfraTickets
                exit_on_known_infra_transient = [bool]$exitOnKnownInfraTransient
                agent_ticket_queue_enabled = [bool]$agentQueueEnabled
                agent_ticket_queue_path = (Convert-ToRepoRelativePath -Path $agentQueuePath)
                task_definition_repair_ticket_enabled = [bool]$taskDefinitionRepairTicketEnabled
                status_ticket_enabled = [bool]$statusTicketEnabled
                status_ticket_interval_minutes = [int]$statusTicketIntervalMinutes
                last_status_ticket_at = $lastStatusTicketAtText
                last_ticket_id = [string]$script:AgentTicketLastId
                last_ticket_event = [string]$script:AgentTicketLastEvent
                auto_fix_d_compile = [bool]$autoFixCompileEnabled
                auto_fix_max_per_d_round = [int]$autoFixMaxPerDRound
                auto_fix_cooldown_minutes = [int]$autoFixCooldownMinutes
            }

            if ($sessionStatus -eq 'PASS' -and -not $running) {
                Write-GuardLog ("complete session_status=PASS a={0} b={1}" -f $aStatus, $bStatus)
                break
            }

            if (($sessionStatus -in @('FAIL', 'BLOCKED')) -and -not $running) {
                $statusSignature = "{0}|{1}|{2}|{3}" -f $sessionStatus, $aStatus, $bStatus, $runDirAnchor
                $failurePolicy = Get-FailureTicketPolicy -RunDirAnchor $runDirAnchor
                $knownInfraTransient = Test-KnownInfraTransientFailurePolicy -FailurePolicy $failurePolicy
                $knownInfraTicketSuppressed = ([bool]$knownInfraTransient -and [bool]$suppressKnownInfraTickets)
                $incidentRecommendedAction = 'Review incident evidence, report root cause plus remediation path first, then decide restart approval or agent-driven script/code fix workflow.'
                $manualWaitRecommendedAction = 'Open takeover brief, report root cause plus remediation path, then decide script/code fix or manual resume. Fetch via poll_agent_tickets.ps1 from LOCAL_GUARD_AGENT_QUEUE_PATH; execute business_command then continue_watch_command (continue only if business empty); fix LOCAL_GUARD_POLL_* first on strict violation.'
                $failureCategory = (Convert-ToSingleLineText -Text ([string]$failurePolicy.FailureCategory)).ToLowerInvariant()
                if ([string]::IsNullOrWhiteSpace($failureCategory)) {
                    $failureCategory = 'unknown'
                }
                $failureHasScriptFault = [bool]$failurePolicy.FailureHasScriptFault
                $failureHasCodeFault = [bool]$failurePolicy.FailureHasCodeFault
                $failureTicketMeta = Get-FailureTicketMeta -FailurePolicy $failurePolicy -KnownInfraTransient ([bool]$knownInfraTransient) -AutoRecoverB ([bool]$autoRecoverB) -RestartApproved ([bool]$restartApproved) -AStatus $aStatus -BStatus $bStatus
                if ([bool]$failurePolicy.IsVerifyRound) {
                    $verifyCategory = (Convert-ToSingleLineText -Text ([string]$failurePolicy.VerifyFailureCategory)).ToLowerInvariant()
                    switch ($verifyCategory) {
                        'script-fault' {
                            if ($failureHasCodeFault) {
                                $incidentRecommendedAction = ('Verify-round failure detected ({0}) category=script-fault with code-marker. Fix guard/trigger/dispatch scripts and restart only; ignore code-fix actions in V rounds.' -f [string]$failurePolicy.FailedRoundTag)
                                $manualWaitRecommendedAction = ('Verify-round script fault ({0}) source={1}. Code markers are present but must be ignored in V rounds; fix scripts then restart guarded flow.' -f [string]$failurePolicy.FailedRoundTag, [string]$failurePolicy.VerifyFailureSourceLog)
                            }
                            else {
                                $incidentRecommendedAction = ('Verify-round failure detected ({0}) category=script-fault. Fix guard/trigger/dispatch scripts, then allow guarded restart under existing quota/cooldown. Do not issue code-fix instructions in V rounds.' -f [string]$failurePolicy.FailedRoundTag)
                                $manualWaitRecommendedAction = ('Verify-round script fault ({0}) source={1}. Fix scripts and resume guarded restart workflow. Fetch via poll_agent_tickets.ps1 from LOCAL_GUARD_AGENT_QUEUE_PATH; execute business_command then continue_watch_command (continue only if business empty).' -f [string]$failurePolicy.FailedRoundTag, [string]$failurePolicy.VerifyFailureSourceLog)
                            }
                        }
                        'noncode-transient' {
                            $incidentRecommendedAction = ('Verify-round failure detected ({0}) category=noncode-transient. Guard may retry restart under existing quota/cooldown rules after evidence check.' -f [string]$failurePolicy.FailedRoundTag)
                            $manualWaitRecommendedAction = ('Verify-round non-code transient ({0}) evidence={1}. Allow guarded restart retries within quota/cooldown; no code-fix instructions in V rounds.' -f [string]$failurePolicy.FailedRoundTag, [string]$failurePolicy.VerifyFailureEvidence)
                        }
                        default {
                            $incidentRecommendedAction = ('Verify-round failure detected ({0}) category=code-or-unknown. Investigate and report root cause only; do not issue code-fix instructions. Stop and wait for manual code handling.' -f [string]$failurePolicy.FailedRoundTag)
                            $manualWaitRecommendedAction = ('Verify-round code-or-unknown failure ({0}). Keep evidence, stop automated recovery, and wait for manual code handling.' -f [string]$failurePolicy.FailedRoundTag)
                        }
                    }
                }
                elseif ([bool]$failurePolicy.IsDevRound) {
                    $devCategory = (Convert-ToSingleLineText -Text ([string]$failurePolicy.DevFailureCategory)).ToLowerInvariant()
                    if ([string]::IsNullOrWhiteSpace($devCategory)) {
                        $devCategory = $failureCategory
                    }
                    $restartStageHint = if ([string]::IsNullOrWhiteSpace([string]$failureTicketMeta.PreferredStage)) { 'current' } else { ([string]$failureTicketMeta.PreferredStage).ToUpperInvariant() }

                    switch ($devCategory) {
                        'script-fault' {
                            $incidentRecommendedAction = ('Dev-round failure detected ({0}) category=script-fault. Repair unattended script chain only (guard/trigger/dispatch/poll), run D-round script validation, then restart guarded {1}-stage flow under existing quota/cooldown.' -f [string]$failurePolicy.FailedRoundTag, $restartStageHint)
                            $manualWaitRecommendedAction = ('Dev-round script fault ({0}) source={1}. Keep scope in script lane only, provide root-cause evidence, and wait restart decision gates before resuming guarded flow.' -f [string]$failurePolicy.FailedRoundTag, [string]$failurePolicy.DevFailureSourceLog)
                        }
                        'noncode-transient' {
                            $incidentRecommendedAction = ('Dev-round failure detected ({0}) category=noncode-transient. Guard may restart {1}-stage under existing quota/cooldown without code-fix actions.' -f [string]$failurePolicy.FailedRoundTag, $restartStageHint)
                            $manualWaitRecommendedAction = ('Dev-round non-code transient ({0}) evidence={1}. Allow guarded restart retries within quota/cooldown.' -f [string]$failurePolicy.FailedRoundTag, [string]$failurePolicy.DevFailureEvidence)
                        }
                        default {
                            if ($failureHasCodeFault) {
                                $incidentRecommendedAction = ('Dev-round failure detected ({0}) category=code-or-unknown with code-marker. Run code-fix workflow and restart after confirmation; if the fix is a self-heal output mismatch, update the matching task-definition round under testdata (prefer D4 append for V1-V4) rather than rewriting D1-D4 validated content.' -f [string]$failurePolicy.FailedRoundTag)
                                $manualWaitRecommendedAction = ('Dev-round code fault ({0}) evidence={1}. Apply code fixes and restart guarded flow after review; if the fix is a self-heal output mismatch, update the matching task-definition round under testdata (prefer D4 append for V1-V4).' -f [string]$failurePolicy.FailedRoundTag, [string]$failurePolicy.DevFailureEvidence)
                            }
                            else {
                                $incidentRecommendedAction = ('Dev-round failure detected ({0}) category=code-or-unknown. Gather evidence and wait manual decision before restart.' -f [string]$failurePolicy.FailedRoundTag)
                                $manualWaitRecommendedAction = ('Dev-round unknown failure ({0}). Keep incident evidence and decide script/code handling manually.' -f [string]$failurePolicy.FailedRoundTag)
                            }
                        }
                    }
                }
                $eventTicketPolicySuffix = ' If self-healable and not blocked by nonrecoverable env or exhausted budget/cooldown, trigger business_resume immediately. After completing this ticket cycle, you MUST return handled_at (YYYY-MM-DD HH:mm:ss); session_closed_at is session-level only and MUST be returned only when stop monitoring is requested or both A/B are terminal. After handling, keep read-only monitoring with scheduled status-ticket heartbeat + poll cadence until "stop monitoring".'
                $incidentRecommendedAction = Convert-ToBoundedSingleLineText -Text ($incidentRecommendedAction + $eventTicketPolicySuffix) -MaxChars 600
                $manualWaitRecommendedAction = Convert-ToBoundedSingleLineText -Text ($manualWaitRecommendedAction + $eventTicketPolicySuffix) -MaxChars 600

                if ($statusSignature -ne $lastIncidentSignature) {
                    $incidentDir = Save-IncidentPackage -Settings $settings -SessionStatus $sessionStatus -AStatus $aStatus -BStatus $bStatus
                    $incidentRel = Convert-ToRepoRelativePath -Path $incidentDir
                    $lastIncidentSignature = $statusSignature
                    Write-GuardLog ("incident status={0} a={1} b={2} evidence={3}" -f $sessionStatus, $aStatus, $bStatus, $incidentRel)

                    $newNotes = Add-DelimitedNote -Existing $notes -Append ("guard_incident status={0} a={1} b={2} evidence={3}" -f $sessionStatus, $aStatus, $bStatus, $incidentRel)
                    Invoke-KeyValueFileValueUpdate -Path $script:StartFilePath -Values @{
                        SESSION_FINAL_NOTES = $newNotes
                    }

                    $incidentDetail = ("session={0} a={1} b={2} evidence={3}" -f $sessionStatus, $aStatus, $bStatus, $incidentRel)
                    if ([bool]$knownInfraTicketSuppressed) {
                        Write-GuardLog ("agent_ticket_suppressed event=incident-captured reason=known_infra_transient round={0} category={1} evidence={2} source={3}" -f
                            [string]$failurePolicy.FailedRoundTag,
                            [string]$failurePolicy.DevFailureCategory,
                            (Convert-ToBoundedSingleLineText -Text ([string]$failurePolicy.DevFailureEvidence) -MaxChars 180),
                            [string]$failurePolicy.DevFailureSourceLog)
                    }
                    else {
                        # Fallback: if failure ticket meta is unknown, try reading
                        # A_FAIL_CATEGORY / A_FAIL_REASON from start file (written
                        # by supervisor from exit artifact).
                        $startFileFailCategory = ''
                        $startFileFailReason = ''
                        if ($settings.Contains('A_FAIL_CATEGORY')) {
                            $startFileFailCategory = (Convert-ToSingleLineText -Text ([string]$settings.A_FAIL_CATEGORY)).ToLowerInvariant()
                        }
                        if ($settings.Contains('A_FAIL_REASON')) {
                            $startFileFailReason = (Convert-ToSingleLineText -Text ([string]$settings.A_FAIL_REASON))
                        }
                        if (-not [string]::IsNullOrWhiteSpace($startFileFailCategory) -and
                            ([string]$failureTicketMeta.FailureCategory -in @('', 'unknown'))) {
                            $failureTicketMeta.FailureCategory = $startFileFailCategory
                            $failureTicketMeta.FailureEvidence = $startFileFailReason
                            if ($startFileFailCategory -match 'runner-fail|task-definition|code-step') {
                                $failureTicketMeta.FailureKind = 'compile-failure'
                                $failureTicketMeta.SelfHealable = $true
                            }
                        }
                        $null = Add-AgentTicket -Enabled $agentQueueEnabled -QueuePath $agentQueuePath -EventName 'incident-captured' -Severity 'high' -RequiresConfirmation $restartRequiresConfirmation -SessionStatus $sessionStatus -AStatus $aStatus -BStatus $bStatus -RunDirAnchor $runDirAnchor -IncidentDir $incidentDir -Detail $incidentDetail -DedupSuffix $statusSignature -RecommendedAction $incidentRecommendedAction -PreferredStage ([string]$failureTicketMeta.PreferredStage) -MainRound ([string]$failureTicketMeta.MainRound) -FailureKind ([string]$failureTicketMeta.FailureKind) -FailureCategory ([string]$failureTicketMeta.FailureCategory) -FailureSource ([string]$failureTicketMeta.FailureSource) -FailureEvidence ([string]$failureTicketMeta.FailureEvidence) -SelfHealable ([bool]$failureTicketMeta.SelfHealable) -NonRecoverableEnv ([bool]$failureTicketMeta.NonRecoverableEnv)
                    }
                }

                if ([bool]$taskDefinitionRepairTicketEnabled -and $aStatus -eq 'PASS' -and $bStatus -in @('FAIL', 'BLOCKED')) {
                    $bExitReasonEvidence = Get-BStageExitReasonEvidence -ExpectedProcessId $bLaunchPid
                    $taskDefRepairContext = Get-TaskDefinitionRepairTicketContext -FailurePolicy $failurePolicy -BExitReasonEvidence $bExitReasonEvidence -RunDirAnchor $runDirAnchor
                    if ([bool]$taskDefRepairContext.ShouldQueue) {
                        $taskDefFixSignature = Convert-ToSingleLineText -Text ([string]$taskDefRepairContext.DedupSuffix)
                        if ([string]::IsNullOrWhiteSpace($taskDefFixSignature)) {
                            $taskDefFixSignature = $statusSignature
                        }

                        if ($taskDefFixSignature -ne $lastTaskDefinitionFixSignature) {
                            $taskDefTicketResult = Add-AgentTicket -Enabled $agentQueueEnabled -QueuePath $agentQueuePath -EventName 'task-definition-fix-required' -Severity 'high' -RequiresConfirmation $false -SessionStatus $sessionStatus -AStatus $aStatus -BStatus $bStatus -RunDirAnchor $runDirAnchor -IncidentDir '' -Detail ([string]$taskDefRepairContext.Detail) -DedupSuffix $taskDefFixSignature -RecommendedAction ([string]$taskDefRepairContext.RecommendedAction) -PreferredStage 'B' -MainRound ([string]$failureTicketMeta.MainRound) -FailureKind 'task-definition-mismatch' -FailureCategory ([string]$failureTicketMeta.FailureCategory) -FailureSource ([string]$failureTicketMeta.FailureSource) -FailureEvidence ([string]$failureTicketMeta.FailureEvidence) -SelfHealable $true -NonRecoverableEnv $false

                            if ([bool]$taskDefTicketResult.Queued) {
                                Write-GuardLog ('agent_ticket_queued task_definition_fix_required id={0} dedup={1}' -f [string]$taskDefTicketResult.TicketId, $taskDefFixSignature)
                                $lastTaskDefinitionFixSignature = $taskDefFixSignature
                            }
                            elseif ([string]$taskDefTicketResult.Reason -eq 'duplicate-signature') {
                                $lastTaskDefinitionFixSignature = $taskDefFixSignature
                            }
                            else {
                                Write-GuardLog ('agent_ticket_task_definition_fix_skipped reason={0} dedup={1}' -f [string]$taskDefTicketResult.Reason, $taskDefFixSignature)
                            }
                        }
                    }
                }

                $monitorChainGraceStopRequested = $false
                if ($null -ne $monitorChainGraceStartedAt) {
                    $graceElapsedMinutes = ((Get-Date) - $monitorChainGraceStartedAt).TotalMinutes
                    if ($graceElapsedMinutes -ge $mainProcessExitMonitorGraceMinutes) {
                        $shutdownDetail = $monitorChainGraceShutdownDetail
                        if ([string]::IsNullOrWhiteSpace($shutdownDetail)) {
                            $shutdownDetail = ("monitor_chain_grace_expired stage={0} status={1} a={2} b={3} run_dir={4}" -f $monitorChainGraceShutdownStage, $sessionStatus, $aStatus, $bStatus, $runDirAnchor)
                        }
                        $settings = Request-MonitorChainShutdown -Settings $settings -Reason $monitorChainGraceShutdownReason -Source $monitorChainGraceShutdownSource -Detail $shutdownDetail
                        $monitorChainGraceStopRequested = $true
                    }
                    else {
                        $remainingGraceMinutes = [Math]::Max(0.0, ($mainProcessExitMonitorGraceMinutes - $graceElapsedMinutes))
                        if ($null -eq $monitorChainGraceLastNoticeAt -or (((Get-Date) - $monitorChainGraceLastNoticeAt).TotalMinutes -ge 5)) {
                            Write-GuardLog (
                                "monitor_chain_grace_wait stage={0} elapsed_min={1:N1} remaining_min={2:N1} reason={3} session={4} a={5} b={6}" -f
                                $monitorChainGraceShutdownStage,
                                $graceElapsedMinutes,
                                $remainingGraceMinutes,
                                $monitorChainGraceShutdownReason,
                                $sessionStatus,
                                $aStatus,
                                $bStatus)
                            $monitorChainGraceLastNoticeAt = Get-Date
                        }
                        Write-GuardState -Values @{
                            status = 'waiting-monitor-chain-grace'
                            event = 'monitor-chain-grace'
                            stop_reason = ''
                            session_final_status = $sessionStatus
                            a_final_status = $aStatus
                            b_final_status = $bStatus
                            grace_stage = $monitorChainGraceShutdownStage
                            grace_reason = $monitorChainGraceShutdownReason
                            grace_remaining_min = ([Math]::Round($remainingGraceMinutes, 1))
                        }
                        Start-Sleep -Seconds $PollSec
                        continue
                    }
                }

                if ($monitorChainGraceStopRequested) {
                    Write-GuardState -Values @{
                        status = 'stopped'
                        event = 'monitor-chain-grace-stop'
                        stop_reason = [string]$monitorChainGraceShutdownReason
                        session_final_status = $sessionStatus
                        a_final_status = $aStatus
                        b_final_status = $bStatus
                    }
                    Write-GuardLog (
                        "complete reason=monitor_chain_grace_stop shutdown_reason={0} status={1} a={2} b={3}" -f
                        [string]$monitorChainGraceShutdownReason,
                        $sessionStatus,
                        $aStatus,
                        $bStatus)
                    break
                }

                if ([bool]$knownInfraTransient -and [bool]$exitOnKnownInfraTransient) {
                    if ($mainProcessExitMonitorGraceMinutes -gt 0) {
                        if ($null -eq $monitorChainGraceStartedAt) {
                            $monitorChainGraceStartedAt = Get-Date
                            $monitorChainGraceLastNoticeAt = $null
                            $monitorChainGraceShutdownDetail = [string]$failurePolicy.FailedRoundTag
                            $monitorChainGraceShutdownStage = 'SESSION'
                            $monitorChainGraceShutdownReason = 'known-infra-transient-stop'
                            $monitorChainGraceShutdownSource = 'session-guard'
                            Write-GuardLog (
                                "monitor_chain_grace_start stage={0} grace_min={1} reason={2} session={3} a={4} b={5} run_dir={6}" -f
                                $monitorChainGraceShutdownStage,
                                $mainProcessExitMonitorGraceMinutes,
                                $monitorChainGraceShutdownReason,
                                $sessionStatus,
                                $aStatus,
                                $bStatus,
                                $runDirAnchor)
                        }
                        Start-Sleep -Seconds $PollSec
                        continue
                    }

                    $settings = Request-MonitorChainShutdown -Settings $settings -Reason 'known-infra-transient-stop' -Source 'session-guard' -Detail ([string]$failurePolicy.FailedRoundTag)
                    $infraCategory = Convert-ToSingleLineText -Text ([string]$failurePolicy.DevFailureCategory)
                    if ([string]::IsNullOrWhiteSpace($infraCategory)) {
                        $infraCategory = Convert-ToSingleLineText -Text ([string]$failurePolicy.FailureCategory)
                    }
                    $infraEvidence = Convert-ToBoundedSingleLineText -Text ([string]$failurePolicy.DevFailureEvidence) -MaxChars 220
                    if ([string]::IsNullOrWhiteSpace($infraEvidence)) {
                        $infraEvidence = Convert-ToBoundedSingleLineText -Text ([string]$failurePolicy.FailureEvidence) -MaxChars 220
                    }
                    $infraSource = Convert-ToSingleLineText -Text ([string]$failurePolicy.DevFailureSourceLog)
                    if ([string]::IsNullOrWhiteSpace($infraSource)) {
                        $infraSource = Convert-ToSingleLineText -Text ([string]$failurePolicy.FailureSourceLog)
                    }

                    Write-GuardState -Values @{
                        status = 'stopped'
                        event = 'known-infra-transient-stop'
                        stop_reason = 'known-infra-transient-stop'
                        session_final_status = $sessionStatus
                        a_final_status = $aStatus
                        b_final_status = $bStatus
                        failed_round = [string]$failurePolicy.FailedRoundTag
                        failure_category = $infraCategory
                        failure_evidence = $infraEvidence
                        failure_source = $infraSource
                    }
                    Write-GuardLog ("complete reason=known_infra_transient_stop round={0} category={1} evidence={2} source={3} suppress_tickets={4}" -f
                        [string]$failurePolicy.FailedRoundTag,
                        $infraCategory,
                        $infraEvidence,
                        $infraSource,
                        [bool]$knownInfraTicketSuppressed)
                    break
                }

                $canRecoverB = ($aStatus -eq 'PASS' -and $bStatus -in @('FAIL', 'BLOCKED'))

                $autoFixResult = [pscustomobject]@{
                    Attempted = $false
                    Restarted = $false
                    Reason = 'not-run'
                    RoundTag = ''
                    Attempt = 0
                    Detail = ''
                    TaskDefinitionPath = ''
                    StrictLogPath = ''
                }

                $verifyRecoveryResult = [pscustomobject]@{
                    Attempted = $false
                    Restarted = $false
                    Reason = 'not-run'
                    RoundTag = [string]$failurePolicy.FailedRoundTag
                    Attempt = 0
                    Detail = ''
                    Category = [string]$failurePolicy.VerifyFailureCategory
                    Evidence = [string]$failurePolicy.VerifyFailureEvidence
                    SourceLog = [string]$failurePolicy.VerifyFailureSourceLog
                }

                $devTransientRecoveryResult = [pscustomobject]@{
                    Attempted = $false
                    Restarted = $false
                    Reason = 'not-run'
                    RoundTag = [string]$failurePolicy.FailedRoundTag
                    Attempt = 0
                    Detail = ''
                    Category = [string]$failurePolicy.DevFailureCategory
                    Evidence = [string]$failurePolicy.DevFailureEvidence
                    SourceLog = [string]$failurePolicy.DevFailureSourceLog
                }
                $skipAutoFixForDevTransient = $false

                if ($aStatus -eq 'FAIL' -and [bool]$failurePolicy.IsVerifyRound) {
                    $verifyRecoveryResult = Invoke-AVerifyRoundRecovery -FailurePolicy $failurePolicy -RestartAllowed $restartApproved -MaxAttemptsPerRound $MaxBRecoveryAttempts -CooldownMinutes $RecoveryCooldownMinutes
                    Write-GuardLog ("verify_recovery_result round={0} category={1} attempted={2} restarted={3} reason={4} detail={5} evidence={6} source={7}" -f
                        [string]$verifyRecoveryResult.RoundTag,
                        [string]$verifyRecoveryResult.Category,
                        [bool]$verifyRecoveryResult.Attempted,
                        [bool]$verifyRecoveryResult.Restarted,
                        [string]$verifyRecoveryResult.Reason,
                        (Convert-ToBoundedSingleLineText -Text ([string]$verifyRecoveryResult.Detail) -MaxChars 180),
                        (Convert-ToBoundedSingleLineText -Text ([string]$verifyRecoveryResult.Evidence) -MaxChars 140),
                        [string]$verifyRecoveryResult.SourceLog)

                    if ([bool]$verifyRecoveryResult.Attempted -and ([string]$verifyRecoveryResult.Reason -eq 'restart-await-confirmation')) {
                        $verifyWaitDetail = ("stage=A round={0} category={1} attempt={2}/{3} reason={4} detail={5}" -f
                            [string]$verifyRecoveryResult.RoundTag,
                            [string]$verifyRecoveryResult.Category,
                            [int]$verifyRecoveryResult.Attempt,
                            [int]$MaxBRecoveryAttempts,
                            [string]$verifyRecoveryResult.Reason,
                            (Convert-ToBoundedSingleLineText -Text ([string]$verifyRecoveryResult.Detail) -MaxChars 180))
                        $verifyWaitDedup = ("{0}|{1}|{2}|{3}" -f [string]$verifyRecoveryResult.RoundTag, [string]$verifyRecoveryResult.Category, [int]$verifyRecoveryResult.Attempt, $runDirAnchor)
                        $null = Add-AgentTicket -Enabled $agentQueueEnabled -QueuePath $agentQueuePath -EventName 'verify-restart-await-confirmation' -Severity 'high' -RequiresConfirmation $true -SessionStatus $sessionStatus -AStatus $aStatus -BStatus $bStatus -RunDirAnchor $runDirAnchor -IncidentDir '' -Detail $verifyWaitDetail -DedupSuffix $verifyWaitDedup -RecommendedAction 'Set LOCAL_GUARD_RESTART_APPROVED=true after evidence review to allow guarded verify restart.' -PreferredStage 'A' -MainRound ([string]$failureTicketMeta.MainRound) -FailureKind 'verify-failure' -FailureCategory ([string]$verifyRecoveryResult.Category) -FailureSource ([string]$verifyRecoveryResult.SourceLog) -FailureEvidence ([string]$verifyRecoveryResult.Evidence) -SelfHealable $true -NonRecoverableEnv ([bool]$failureTicketMeta.NonRecoverableEnv)
                    }

                    if ([bool]$verifyRecoveryResult.Restarted) {
                        $manualPauseActive = $false
                        $manualPauseSignature = ''
                        $manualPauseNoticeCount = 0
                        $lastIncidentSignature = ''
                        $lastBudgetExhaustedSignature = ''

                        Write-GuardState -Values @{
                            status = 'running'
                            event = 'verify-restart-a'
                            stop_reason = ''
                            verify_restart_round = [string]$verifyRecoveryResult.RoundTag
                            verify_restart_category = [string]$verifyRecoveryResult.Category
                            verify_restart_attempt = [int]$verifyRecoveryResult.Attempt
                        }
                        Start-Sleep -Seconds 5
                        continue
                    }

                    if ([string]$verifyRecoveryResult.Reason -eq 'code-or-unknown') {
                        Write-GuardState -Values @{
                            status = 'stopped'
                            event = 'verify-code-wait-manual'
                            stop_reason = 'verify-code-wait-manual'
                            session_final_status = $sessionStatus
                            a_final_status = $aStatus
                            b_final_status = $bStatus
                        }
                        Write-GuardLog ("complete reason=verify_code_or_unknown_wait_manual round={0} category={1}" -f [string]$verifyRecoveryResult.RoundTag, [string]$verifyRecoveryResult.Category)
                        break
                    }
                }

                if ($aStatus -eq 'FAIL' -and [bool]$failurePolicy.IsDevRound) {
                    $devCategory = (Convert-ToSingleLineText -Text ([string]$failurePolicy.DevFailureCategory)).ToLowerInvariant()
                    if ([string]::IsNullOrWhiteSpace($devCategory)) {
                        $devCategory = (Convert-ToSingleLineText -Text ([string]$failurePolicy.FailureCategory)).ToLowerInvariant()
                    }

                    if ($devCategory -eq 'noncode-transient') {
                        $skipAutoFixForDevTransient = $true
                        $devTransientRecoveryResult = Invoke-ADevRoundTransientRecovery -FailurePolicy $failurePolicy -RestartAllowed $restartApproved -MaxAttemptsPerRound $MaxBRecoveryAttempts -CooldownMinutes $RecoveryCooldownMinutes
                        Write-GuardLog ("dev_transient_recovery_result round={0} category={1} attempted={2} restarted={3} reason={4} detail={5} evidence={6} source={7}" -f
                            [string]$devTransientRecoveryResult.RoundTag,
                            [string]$devTransientRecoveryResult.Category,
                            [bool]$devTransientRecoveryResult.Attempted,
                            [bool]$devTransientRecoveryResult.Restarted,
                            [string]$devTransientRecoveryResult.Reason,
                            (Convert-ToBoundedSingleLineText -Text ([string]$devTransientRecoveryResult.Detail) -MaxChars 180),
                            (Convert-ToBoundedSingleLineText -Text ([string]$devTransientRecoveryResult.Evidence) -MaxChars 140),
                            [string]$devTransientRecoveryResult.SourceLog)

                        if ([bool]$devTransientRecoveryResult.Attempted -and ([string]$devTransientRecoveryResult.Reason -eq 'restart-await-confirmation')) {
                            $devWaitDetail = ("stage=A round={0} category={1} attempt={2}/{3} reason={4} detail={5}" -f
                                [string]$devTransientRecoveryResult.RoundTag,
                                [string]$devTransientRecoveryResult.Category,
                                [int]$devTransientRecoveryResult.Attempt,
                                [int]$MaxBRecoveryAttempts,
                                [string]$devTransientRecoveryResult.Reason,
                                (Convert-ToBoundedSingleLineText -Text ([string]$devTransientRecoveryResult.Detail) -MaxChars 180))
                            $devWaitDedup = ("{0}|{1}|{2}|{3}" -f [string]$devTransientRecoveryResult.RoundTag, [string]$devTransientRecoveryResult.Category, [int]$devTransientRecoveryResult.Attempt, $runDirAnchor)
                            $null = Add-AgentTicket -Enabled $agentQueueEnabled -QueuePath $agentQueuePath -EventName 'dev-restart-await-confirmation' -Severity 'high' -RequiresConfirmation $true -SessionStatus $sessionStatus -AStatus $aStatus -BStatus $bStatus -RunDirAnchor $runDirAnchor -IncidentDir '' -Detail $devWaitDetail -DedupSuffix $devWaitDedup -RecommendedAction 'Set LOCAL_GUARD_RESTART_APPROVED=true after evidence review to allow guarded D-round restart.' -PreferredStage 'A' -MainRound ([string]$failureTicketMeta.MainRound) -FailureKind ([string]$failureTicketMeta.FailureKind) -FailureCategory ([string]$devTransientRecoveryResult.Category) -FailureSource ([string]$devTransientRecoveryResult.SourceLog) -FailureEvidence ([string]$devTransientRecoveryResult.Evidence) -SelfHealable $true -NonRecoverableEnv ([bool]$failureTicketMeta.NonRecoverableEnv)

                            Write-GuardState -Values @{
                                status = 'paused'
                                event = 'dev-restart-await-confirmation'
                                stop_reason = ''
                                session_final_status = $sessionStatus
                                a_final_status = $aStatus
                                b_final_status = $bStatus
                                restart_requires_confirmation = [bool]$restartRequiresConfirmation
                                restart_approved = [bool]$restartApproved
                            }
                            Start-Sleep -Seconds $PollSec
                            continue
                        }

                        if ([bool]$devTransientRecoveryResult.Restarted) {
                            $manualPauseActive = $false
                            $manualPauseSignature = ''
                            $manualPauseNoticeCount = 0
                            $lastIncidentSignature = ''
                            $lastBudgetExhaustedSignature = ''

                            Write-GuardState -Values @{
                                status = 'running'
                                event = 'dev-transient-restart-a'
                                stop_reason = ''
                                dev_restart_round = [string]$devTransientRecoveryResult.RoundTag
                                dev_restart_category = [string]$devTransientRecoveryResult.Category
                                dev_restart_attempt = [int]$devTransientRecoveryResult.Attempt
                            }
                            Start-Sleep -Seconds 5
                            continue
                        }
                    }
                }

                if ($autoFixCompileEnabled -and $aStatus -eq 'FAIL' -and -not [bool]$failurePolicy.IsVerifyRound -and -not $skipAutoFixForDevTransient) {
                    $autoFixResult = Invoke-ACompileAutoFixRecovery -Settings $settings -RunDirAnchor $runDirAnchor -MaxAttemptsPerRound $autoFixMaxPerDRound -CooldownMinutes $autoFixCooldownMinutes -RestartAllowed $restartApproved
                    $autoFixStatusSignature = "{0}|{1}|{2}|{3}" -f [string]$autoFixResult.Reason, [string]$autoFixResult.RoundTag, $runDirAnchor, [int]$autoFixResult.Attempt

                    if ([bool]$autoFixResult.Attempted) {
                        $lastAutoFixStatusSignature = ''
                        Write-GuardLog ("auto_fix_result stage=A round={0} attempt={1}/{2} restarted={3} reason={4} detail={5} task={6} strict_log={7} category={8} script_fault={9} code_fault={10}" -f
                            [string]$autoFixResult.RoundTag,
                            [int]$autoFixResult.Attempt,
                            [int]$autoFixMaxPerDRound,
                            [bool]$autoFixResult.Restarted,
                            [string]$autoFixResult.Reason,
                            (Convert-ToBoundedSingleLineText -Text ([string]$autoFixResult.Detail) -MaxChars 220),
                            [string]$autoFixResult.TaskDefinitionPath,
                            [string]$autoFixResult.StrictLogPath,
                            $failureCategory,
                            $failureHasScriptFault,
                            $failureHasCodeFault)
                    }
                    elseif ($autoFixStatusSignature -ne $lastAutoFixStatusSignature) {
                        $lastAutoFixStatusSignature = $autoFixStatusSignature
                        Write-GuardLog ("auto_fix_skip stage=A reason={0} round={1} detail={2}" -f
                            [string]$autoFixResult.Reason,
                            [string]$autoFixResult.RoundTag,
                            (Convert-ToBoundedSingleLineText -Text ([string]$autoFixResult.Detail) -MaxChars 180))
                    }

                    if ([bool]$autoFixResult.Attempted -and ([string]$autoFixResult.Reason -eq 'restart-await-confirmation')) {
                        $autoFixRecommendedAction = 'Set LOCAL_GUARD_RESTART_APPROVED=true only after evidence review, then resume A-stage restart.'
                        if ([bool]$failurePolicy.IsDevRound -and $failureHasScriptFault -and $failureHasCodeFault) {
                            $autoFixRecommendedAction = 'Code fault markers exist in this D-round failure. Prefer code/task-definition fix workflow first, then set LOCAL_GUARD_RESTART_APPROVED=true only after fix+verify evidence is ready.'
                        }
                        elseif ([bool]$failurePolicy.IsDevRound -and $failureHasScriptFault) {
                            $autoFixRecommendedAction = 'Fix D-round unattended scripts only (guard/trigger/dispatch/poll), complete script validation evidence, then set LOCAL_GUARD_RESTART_APPROVED=true for guarded restart.'
                        }
                        elseif ([bool]$failurePolicy.IsDevRound -and $failureHasCodeFault) {
                            $autoFixRecommendedAction = 'Review D-round code-fix evidence, then set LOCAL_GUARD_RESTART_APPROVED=true to restart guarded A-stage flow; when the fix is a self-heal output mismatch, update the matching task-definition round under testdata, and for V1-V4 prefer appending the incremental patch after the existing D4 definition.'
                        }

                        $autoFixWaitDetail = ("stage=A round={0} attempt={1}/{2} reason={3} detail={4}" -f
                            [string]$autoFixResult.RoundTag,
                            [int]$autoFixResult.Attempt,
                            [int]$autoFixMaxPerDRound,
                            [string]$autoFixResult.Reason,
                            (Convert-ToBoundedSingleLineText -Text ([string]$autoFixResult.Detail) -MaxChars 200))
                        $autoFixDedup = ("{0}|{1}|{2}|{3}" -f [string]$autoFixResult.RoundTag, [int]$autoFixResult.Attempt, [string]$autoFixResult.Reason, $runDirAnchor)
                        $null = Add-AgentTicket -Enabled $agentQueueEnabled -QueuePath $agentQueuePath -EventName 'auto-fix-await-confirmation' -Severity 'high' -RequiresConfirmation $true -SessionStatus $sessionStatus -AStatus $aStatus -BStatus $bStatus -RunDirAnchor $runDirAnchor -IncidentDir '' -Detail $autoFixWaitDetail -DedupSuffix $autoFixDedup -RecommendedAction $autoFixRecommendedAction -PreferredStage 'A' -MainRound ([string]$failureTicketMeta.MainRound) -FailureKind ([string]$failureTicketMeta.FailureKind) -FailureCategory ([string]$failureTicketMeta.FailureCategory) -FailureSource ([string]$failureTicketMeta.FailureSource) -FailureEvidence ([string]$failureTicketMeta.FailureEvidence) -SelfHealable ([bool]$failureTicketMeta.SelfHealable) -NonRecoverableEnv ([bool]$failureTicketMeta.NonRecoverableEnv)
                    }

                    if ([bool]$autoFixResult.Restarted) {
                        $manualPauseActive = $false
                        $manualPauseSignature = ''
                        $manualPauseNoticeCount = 0
                        $lastIncidentSignature = ''
                        $lastBudgetExhaustedSignature = ''

                        Write-GuardState -Values @{
                            status = 'running'
                            event = 'auto-fix-restart-a'
                            stop_reason = ''
                            auto_fix_round = [string]$autoFixResult.RoundTag
                            auto_fix_attempt = [int]$autoFixResult.Attempt
                            auto_fix_max_per_d_round = [int]$autoFixMaxPerDRound
                        }
                        Start-Sleep -Seconds 5
                        continue
                    }
                }

                if ($autoRecoverB -and $canRecoverB) {
                    if (-not $restartApproved) {
                        $approvalWaitSignature = "{0}|{1}|{2}|{3}|{4}" -f $sessionStatus, $aStatus, $bStatus, $runDirAnchor, $bRecoveryAttempts
                        if ($approvalWaitSignature -ne $lastRestartApprovalWaitSignature) {
                            Write-GuardLog ("recovery_waiting_confirmation stage=B attempts={0}/{1} status={2} a={3} b={4}" -f $bRecoveryAttempts, $MaxBRecoveryAttempts, $sessionStatus, $aStatus, $bStatus)
                            $waitDetail = ("stage=B attempts={0}/{1} status={2} a={3} b={4}" -f $bRecoveryAttempts, $MaxBRecoveryAttempts, $sessionStatus, $aStatus, $bStatus)
                            $null = Add-AgentTicket -Enabled $agentQueueEnabled -QueuePath $agentQueuePath -EventName 'recovery-await-confirmation' -Severity 'high' -RequiresConfirmation $true -SessionStatus $sessionStatus -AStatus $aStatus -BStatus $bStatus -RunDirAnchor $runDirAnchor -IncidentDir '' -Detail $waitDetail -DedupSuffix $approvalWaitSignature -RecommendedAction 'Report root cause and remediation path first. After evidence check, set LOCAL_GUARD_RESTART_APPROVED=true and execute business_resume immediately (business_command -> continue_watch_command; continue only when business_command is empty). After completing this ticket cycle, you MUST return handled_at (YYYY-MM-DD HH:mm:ss); session_closed_at is session-level only and MUST be returned only when stop monitoring is requested or both A/B are terminal. After handling, keep read-only monitoring with scheduled status-ticket heartbeat + poll cadence until "stop monitoring".' -PreferredStage 'B' -MainRound ([string]$failureTicketMeta.MainRound) -FailureKind ([string]$failureTicketMeta.FailureKind) -FailureCategory ([string]$failureTicketMeta.FailureCategory) -FailureSource ([string]$failureTicketMeta.FailureSource) -FailureEvidence ([string]$failureTicketMeta.FailureEvidence) -SelfHealable $true -NonRecoverableEnv ([bool]$failureTicketMeta.NonRecoverableEnv)
                            $lastRestartApprovalWaitSignature = $approvalWaitSignature
                        }

                        Write-GuardState -Values @{
                            status = 'paused'
                            event = 'await-restart-confirmation'
                            stop_reason = ''
                            session_final_status = $sessionStatus
                            a_final_status = $aStatus
                            b_final_status = $bStatus
                            auto_recover_b = [bool]$autoRecoverB
                            can_recover_b = [bool]$canRecoverB
                            restart_requires_confirmation = [bool]$restartRequiresConfirmation
                            restart_approved = [bool]$restartApproved
                            b_recovery_attempts = [int]$bRecoveryAttempts
                        }
                        Start-Sleep -Seconds $PollSec
                        continue
                    }

                    $lastRestartApprovalWaitSignature = ''
                    if ($bRecoveryAttempts -ge $MaxBRecoveryAttempts) {
                        $budgetSignature = "{0}|{1}|{2}|{3}" -f $sessionStatus, $aStatus, $bStatus, $runDirAnchor
                        if ($StopOnBudgetExhausted) {
                            $activityWindowMinutes = [Math]::Max(6, [int][Math]::Ceiling(([double]$PollSec * 4.0) / 60.0))
                            $livenessEvidence = Get-BudgetExhaustedLivenessEvidence -Settings $settings -WindowMinutes $activityWindowMinutes -FallbackProcessId $bLaunchPid
                            if ([bool]$livenessEvidence.Active) {
                                $deferSignature = ($budgetSignature + '|active')
                                if ($deferSignature -ne $lastBudgetExhaustedSignature) {
                                    Write-GuardLog ("recovery_skip reason=budget_exhausted_defer_active attempts={0} max={1} detail={2}" -f $bRecoveryAttempts, $MaxBRecoveryAttempts, [string]$livenessEvidence.Detail)
                                    $lastBudgetExhaustedSignature = $deferSignature
                                }

                                Write-GuardState -Values @{
                                    status = 'running'
                                    event = 'budget-exhausted-defer-active'
                                    stop_reason = ''
                                    b_recovery_attempts = [int]$bRecoveryAttempts
                                    b_liveness_detail = [string]$livenessEvidence.Detail
                                }
                                Start-Sleep -Seconds $PollSec
                                continue
                            }

                            if ($budgetSignature -ne $lastBudgetExhaustedSignature) {
                                Write-GuardLog ("recovery_skip reason=budget_exhausted attempts={0} max={1}" -f $bRecoveryAttempts, $MaxBRecoveryAttempts)
                                $lastBudgetExhaustedSignature = $budgetSignature
                            }

                            Write-GuardState -Values @{
                                status = 'stopped'
                                event = 'budget-exhausted'
                                stop_reason = 'budget-exhausted'
                                b_recovery_attempts = [int]$bRecoveryAttempts
                            }
                            if ($mainProcessExitMonitorGraceMinutes -gt 0) {
                                if ($null -eq $monitorChainGraceStartedAt) {
                                    $monitorChainGraceStartedAt = Get-Date
                                    $monitorChainGraceLastNoticeAt = $null
                                    $monitorChainGraceShutdownDetail = ("attempts={0}/{1}" -f $bRecoveryAttempts, $MaxBRecoveryAttempts)
                                    $monitorChainGraceShutdownStage = 'SESSION'
                                    $monitorChainGraceShutdownReason = 'budget-exhausted-stop'
                                    $monitorChainGraceShutdownSource = 'session-guard'
                                    Write-GuardLog (
                                        "monitor_chain_grace_start stage={0} grace_min={1} reason={2} session={3} a={4} b={5} run_dir={6}" -f
                                        $monitorChainGraceShutdownStage,
                                        $mainProcessExitMonitorGraceMinutes,
                                        $monitorChainGraceShutdownReason,
                                        $sessionStatus,
                                        $aStatus,
                                        $bStatus,
                                        $runDirAnchor)
                                }

                                $budgetDetail = ("attempts={0} max={1} stop_on_budget_exhausted={2}" -f $bRecoveryAttempts, $MaxBRecoveryAttempts, $StopOnBudgetExhausted)
                                $null = Add-AgentTicket -Enabled $agentQueueEnabled -QueuePath $agentQueuePath -EventName 'budget-exhausted-stop' -Severity 'high' -RequiresConfirmation $false -SessionStatus $sessionStatus -AStatus $aStatus -BStatus $bStatus -RunDirAnchor $runDirAnchor -IncidentDir '' -Detail $budgetDetail -DedupSuffix $budgetSignature -RecommendedAction 'Use resume workflow and incident evidence to decide rerun scope or scripted fix before next restart.' -PreferredStage 'B' -MainRound ([string]$failureTicketMeta.MainRound) -FailureKind 'budget-exhausted' -FailureCategory ([string]$failureTicketMeta.FailureCategory) -FailureSource ([string]$failureTicketMeta.FailureSource) -FailureEvidence ([string]$failureTicketMeta.FailureEvidence) -SelfHealable $false -NonRecoverableEnv ([bool]$failureTicketMeta.NonRecoverableEnv)
                                Write-GuardLog ("budget_exhausted_grace_started attempts={0} max={1} grace_min={2}" -f $bRecoveryAttempts, $MaxBRecoveryAttempts, $mainProcessExitMonitorGraceMinutes)
                                Start-Sleep -Seconds $PollSec
                                continue
                            }

                            $settings = Request-MonitorChainShutdown -Settings $settings -Reason 'budget-exhausted-stop' -Source 'session-guard' -Detail ("attempts={0}/{1}" -f $bRecoveryAttempts, $MaxBRecoveryAttempts)
                            $budgetDetail = ("attempts={0} max={1} stop_on_budget_exhausted={2}" -f $bRecoveryAttempts, $MaxBRecoveryAttempts, $StopOnBudgetExhausted)
                            $null = Add-AgentTicket -Enabled $agentQueueEnabled -QueuePath $agentQueuePath -EventName 'budget-exhausted-stop' -Severity 'high' -RequiresConfirmation $false -SessionStatus $sessionStatus -AStatus $aStatus -BStatus $bStatus -RunDirAnchor $runDirAnchor -IncidentDir '' -Detail $budgetDetail -DedupSuffix $budgetSignature -RecommendedAction 'Use resume workflow and incident evidence to decide rerun scope or scripted fix before next restart.' -PreferredStage 'B' -MainRound ([string]$failureTicketMeta.MainRound) -FailureKind 'budget-exhausted' -FailureCategory ([string]$failureTicketMeta.FailureCategory) -FailureSource ([string]$failureTicketMeta.FailureSource) -FailureEvidence ([string]$failureTicketMeta.FailureEvidence) -SelfHealable $false -NonRecoverableEnv ([bool]$failureTicketMeta.NonRecoverableEnv)
                            Write-GuardLog ("complete reason=budget_exhausted attempts={0} max={1} stop_on_budget_exhausted={2}" -f $bRecoveryAttempts, $MaxBRecoveryAttempts, $StopOnBudgetExhausted)
                            break
                        }

                        if ($budgetSignature -ne $lastBudgetExhaustedSignature) {
                            Write-GuardLog ("recovery_skip reason=budget_exhausted attempts={0} max={1}" -f $bRecoveryAttempts, $MaxBRecoveryAttempts)
                            $lastBudgetExhaustedSignature = $budgetSignature
                        }
                    }
                    elseif ($lastRecoveryAt -ne [datetime]::MinValue -and ((Get-Date) -lt $lastRecoveryAt.AddMinutes($RecoveryCooldownMinutes))) {
                        $lastBudgetExhaustedSignature = ''
                        $nextAt = $lastRecoveryAt.AddMinutes($RecoveryCooldownMinutes).ToString('yyyy-MM-dd HH:mm:ss')
                        Write-GuardLog ("recovery_skip reason=cooldown next_at={0}" -f $nextAt)
                    }
                    else {
                        $lastBudgetExhaustedSignature = ''
                        $attempt = $bRecoveryAttempts + 1
                        $restartResult = Invoke-BStageRestart -Attempt $attempt
                        if ($restartResult.Succeeded) {
                            $bRecoveryAttempts = $attempt
                            $lastRecoveryAt = Get-Date
                            $lastIncidentSignature = ''
                            $lastBudgetExhaustedSignature = ''
                            Write-GuardState -Values @{
                                status = 'running'
                                last_action = 'restart-triggered'
                                b_recovery_attempts = [int]$bRecoveryAttempts
                                last_recovery_at = $lastRecoveryAt.ToString('yyyy-MM-dd HH:mm:ss')
                            }
                            $restartNote = "guard_recovery action=restart-b attempt={0} at={1}" -f $attempt, $lastRecoveryAt.ToString('yyyy-MM-dd HH:mm:ss')
                            $newNotes = Add-DelimitedNote -Existing ([string](Read-KeyValueFile -Path $script:StartFilePath).SESSION_FINAL_NOTES) -Append $restartNote
                            Invoke-KeyValueFileValueUpdate -Path $script:StartFilePath -Values @{ SESSION_FINAL_NOTES = $newNotes }
                            Write-GuardLog ("recovery_triggered stage=B attempt={0}" -f $attempt)
                            Start-Sleep -Seconds 5
                            continue
                        }

                        Write-GuardLog ("recovery_failed stage=B attempt={0} exit_code={1}" -f $attempt, $restartResult.ExitCode)
                    }
                }
                else {
                    $lastBudgetExhaustedSignature = ''
                    $lastRestartApprovalWaitSignature = ''

                    if ($null -ne $mainProcessExitGraceStartedAt) {
                        $graceElapsedMinutes = ((Get-Date) - $mainProcessExitGraceStartedAt).TotalMinutes
                        if ($graceElapsedMinutes -ge $mainProcessExitMonitorGraceMinutes) {
                            $shutdownDetail = $mainProcessExitGraceShutdownDetail
                            if ([string]::IsNullOrWhiteSpace($shutdownDetail)) {
                                $shutdownDetail = ("main_process_exit grace_expired stage={0} status={1} a={2} b={3} run_dir={4}" -f $mainProcessExitGraceStage, $sessionStatus, $aStatus, $bStatus, $runDirAnchor)
                            }
                            $settings = Request-MonitorChainShutdown -Settings $settings -Reason 'main-process-exit-no-autofix' -Source 'session-guard' -Detail $shutdownDetail
                            $mainProcessExitNoAutoFixStopRequested = $true
                        }
                        else {
                            $remainingGraceMinutes = [Math]::Max(0.0, ($mainProcessExitMonitorGraceMinutes - $graceElapsedMinutes))
                            if ($null -eq $mainProcessExitGraceLastNoticeAt -or (((Get-Date) - $mainProcessExitGraceLastNoticeAt).TotalMinutes -ge 5)) {
                                Write-GuardLog ("main_process_exit_grace_wait stage={0} elapsed_min={1:N1} remaining_min={2:N1} session={3} a={4} b={5}" -f $mainProcessExitGraceStage, $graceElapsedMinutes, $remainingGraceMinutes, $sessionStatus, $aStatus, $bStatus)
                                $mainProcessExitGraceLastNoticeAt = Get-Date
                            }
                            Write-GuardState -Values @{
                                status = 'waiting-main-exit-grace'
                                event = 'main-process-exit-grace'
                                stop_reason = ''
                                session_final_status = $sessionStatus
                                a_final_status = $aStatus
                                b_final_status = $bStatus
                                grace_stage = $mainProcessExitGraceStage
                                grace_remaining_min = ([Math]::Round($remainingGraceMinutes, 1))
                            }
                            Start-Sleep -Seconds $PollSec
                            continue
                        }
                    }

                    if ($mainProcessExitNoAutoFixStopRequested) {
                        Write-GuardState -Values @{
                            status = 'stopped'
                            event = 'main-process-exit-no-autofix-stop'
                            stop_reason = 'main-process-exit-no-autofix-stop'
                            session_final_status = $sessionStatus
                            a_final_status = $aStatus
                            b_final_status = $bStatus
                            auto_recover_b = [bool]$autoRecoverB
                            can_recover_b = [bool]$canRecoverB
                        }
                        Write-GuardLog ("complete reason=main_process_exit_no_autofix_stop status={0} a={1} b={2} auto_recover_b={3} can_recover_b={4}" -f $sessionStatus, $aStatus, $bStatus, $autoRecoverB, $canRecoverB)
                        break
                    }

                    # Before entering final-state-no-followup grace, check if a
                    # new main process is alive despite stale FAIL status from
                    # an earlier A failure.  If so, treat session as RUNNING
                    # and skip the grace entirely.
                    if (-not $canRecoverB -and $mainProcessExitMonitorGraceMinutes -gt 0) {
                        try {
                            $reviveSettings = Read-KeyValueFile -Path $script:StartFilePath
                            if ($null -ne $reviveSettings) {
                                $reviveAPid = 0; $reviveBPid = 0
                                $reviveAPidStr = if ($null -ne $reviveSettings -and $reviveSettings.Contains('A_LAUNCH_PID')) { [string]$reviveSettings.A_LAUNCH_PID } else { '0' }
                                $reviveBPidStr = if ($null -ne $reviveSettings -and $reviveSettings.Contains('B_LAUNCH_PID')) { [string]$reviveSettings.B_LAUNCH_PID } else { '0' }
                                if (-not [string]::IsNullOrWhiteSpace($reviveAPidStr)) { [int]::TryParse($reviveAPidStr, [ref]$reviveAPid) | Out-Null }
                                if (-not [string]::IsNullOrWhiteSpace($reviveBPidStr)) { [int]::TryParse($reviveBPidStr, [ref]$reviveBPid) | Out-Null }
                                $reviveAAlive = ($reviveAPid -gt 0) -and (Get-Process -Id $reviveAPid -ErrorAction SilentlyContinue) -and -not (Get-Process -Id $reviveAPid -ErrorAction SilentlyContinue).HasExited
                                $reviveBAlive = ($reviveBPid -gt 0) -and (Get-Process -Id $reviveBPid -ErrorAction SilentlyContinue) -and -not (Get-Process -Id $reviveBPid -ErrorAction SilentlyContinue).HasExited
                                if ($reviveAAlive) {
                                    Write-GuardLog ("session_revive stage=A pid=$reviveAPid session=$sessionStatus a=$aStatus -> RUNNING")
                                    $sessionStatus = 'RUNNING'; $aStatus = 'RUNNING'
                                    $monitorChainGraceStartedAt = $null
                                }
                                elseif ($reviveBAlive) {
                                    Write-GuardLog ("session_revive stage=B pid=$reviveBPid session=$sessionStatus b=$bStatus -> RUNNING")
                                    $sessionStatus = 'RUNNING'; $bStatus = 'RUNNING'
                                    $monitorChainGraceStartedAt = $null
                                }
                            }
                        }
                        catch {
                            Write-GuardLog ("session_revive_check_failed detail={0}" -f $_.Exception.Message)
                        }
                        # If revived, skip grace and continue monitoring.
                        if ($sessionStatus -eq 'RUNNING') {
                            Start-Sleep -Seconds $PollSec
                            continue
                        }
                    }
                    $manualWaitSignature = "{0}|{1}|{2}|{3}|{4}" -f $sessionStatus, $aStatus, $bStatus, $runDirAnchor, $canRecoverB
                    if (-not $canRecoverB -and $mainProcessExitMonitorGraceMinutes -gt 0) {
                        if ($null -eq $monitorChainGraceStartedAt) {
                            $monitorChainGraceStartedAt = Get-Date
                            $monitorChainGraceLastNoticeAt = $null
                            $monitorChainGraceShutdownDetail = ("status={0} a={1} b={2}" -f $sessionStatus, $aStatus, $bStatus)
                            $monitorChainGraceShutdownStage = 'SESSION'
                            $monitorChainGraceShutdownReason = 'final-state-no-followup'
                            $monitorChainGraceShutdownSource = 'session-guard'
                            Write-GuardLog (
                                "monitor_chain_grace_start stage={0} grace_min={1} reason={2} session={3} a={4} b={5} run_dir={6}" -f
                                $monitorChainGraceShutdownStage,
                                $mainProcessExitMonitorGraceMinutes,
                                $monitorChainGraceShutdownReason,
                                $sessionStatus,
                                $aStatus,
                                $bStatus,
                                $runDirAnchor)
                        }
                        Start-Sleep -Seconds $PollSec
                        continue
                    }

                    if ($manualPauseEnabled -and $forceExitOnFinalNoFollowup -and -not $canRecoverB) {
                        Write-GuardState -Values @{
                            status = 'stopped'
                            event = 'final-state-no-followup'
                            stop_reason = 'final-state-no-followup'
                            session_final_status = $sessionStatus
                            a_final_status = $aStatus
                            b_final_status = $bStatus
                            auto_recover_b = [bool]$autoRecoverB
                            can_recover_b = [bool]$canRecoverB
                        }
                        $settings = Request-MonitorChainShutdown -Settings $settings -Reason 'final-state-no-followup' -Source 'session-guard' -Detail ("status={0} a={1} b={2}" -f $sessionStatus, $aStatus, $bStatus)
                        Write-GuardLog ("complete reason=final_state_no_followup_forced status={0} a={1} b={2} auto_recover_b={3} can_recover_b={4}" -f $sessionStatus, $aStatus, $bStatus, $autoRecoverB, $canRecoverB)
                        break
                    }

                    if ($manualPauseEnabled) {
                        if ($manualWaitSignature -ne $manualPauseSignature) {
                            $manualPauseSignature = $manualWaitSignature
                            $manualPauseNoticeCount = 0
                            $manualPauseActive = $false
                        }

                        if ($manualPauseNoticeCount -lt $manualPauseNoticeRepeat) {
                            $noticeIndex = $manualPauseNoticeCount + 1
                            Write-GuardLog ("manual_action_required status={0} a={1} b={2} auto_recover_b={3} can_recover_b={4} notice={5}/{6}" -f $sessionStatus, $aStatus, $bStatus, $autoRecoverB, $canRecoverB, $noticeIndex, $manualPauseNoticeRepeat)
                            $manualPauseNoticeCount++
                        }

                        if ($manualPauseNoticeCount -ge $manualPauseNoticeRepeat -and -not $manualPauseActive) {
                            $manualPauseActive = $true
                            Write-GuardState -Values @{
                                status = 'paused'
                                event = 'manual-wait-paused'
                                stop_reason = ''
                                session_final_status = $sessionStatus
                                a_final_status = $aStatus
                                b_final_status = $bStatus
                                auto_recover_b = [bool]$autoRecoverB
                                can_recover_b = [bool]$canRecoverB
                                manual_notice_repeat = [int]$manualPauseNoticeRepeat
                            }
                            Write-GuardLog ("manual_wait_paused status={0} a={1} b={2} auto_recover_b={3} can_recover_b={4}" -f $sessionStatus, $aStatus, $bStatus, $autoRecoverB, $canRecoverB)
                            $manualWaitDetail = ("status={0} a={1} b={2} auto_recover_b={3} can_recover_b={4}" -f $sessionStatus, $aStatus, $bStatus, $autoRecoverB, $canRecoverB)
                            $null = Add-AgentTicket -Enabled $agentQueueEnabled -QueuePath $agentQueuePath -EventName 'manual-wait-paused' -Severity 'medium' -RequiresConfirmation $restartRequiresConfirmation -SessionStatus $sessionStatus -AStatus $aStatus -BStatus $bStatus -RunDirAnchor $runDirAnchor -IncidentDir '' -Detail $manualWaitDetail -DedupSuffix $manualWaitSignature -RecommendedAction $manualWaitRecommendedAction -PreferredStage ([string]$failureTicketMeta.PreferredStage) -MainRound ([string]$failureTicketMeta.MainRound) -FailureKind ([string]$failureTicketMeta.FailureKind) -FailureCategory ([string]$failureTicketMeta.FailureCategory) -FailureSource ([string]$failureTicketMeta.FailureSource) -FailureEvidence ([string]$failureTicketMeta.FailureEvidence) -SelfHealable ([bool]$failureTicketMeta.SelfHealable) -NonRecoverableEnv ([bool]$failureTicketMeta.NonRecoverableEnv)
                        }

                        Start-Sleep -Seconds $PollSec
                        continue
                    }

                    if (-not $canRecoverB) {
                        Write-GuardState -Values @{
                            status = 'stopped'
                            event = 'final-state-no-followup'
                            stop_reason = 'final-state-no-followup'
                            session_final_status = $sessionStatus
                            a_final_status = $aStatus
                            b_final_status = $bStatus
                            auto_recover_b = [bool]$autoRecoverB
                            can_recover_b = [bool]$canRecoverB
                        }
                        $settings = Request-MonitorChainShutdown -Settings $settings -Reason 'final-state-no-followup' -Source 'session-guard' -Detail ("status={0} a={1} b={2}" -f $sessionStatus, $aStatus, $bStatus)
                        Write-GuardLog ("complete reason=final_state_no_followup status={0} a={1} b={2} auto_recover_b={3} can_recover_b={4}" -f $sessionStatus, $aStatus, $bStatus, $autoRecoverB, $canRecoverB)
                        break
                    }

                    Write-GuardLog ("manual_action_required status={0} a={1} b={2} auto_recover_b={3} can_recover_b={4}" -f $sessionStatus, $aStatus, $bStatus, $autoRecoverB, $canRecoverB)
                }
            }
            else {
                $lastBudgetExhaustedSignature = ''
                $lastRestartApprovalWaitSignature = ''
                $now = Get-Date
                if ($lastHeartbeatAt -eq [datetime]::MinValue -or (($now - $lastHeartbeatAt).TotalMinutes -ge 5)) {
                    Write-GuardLog ("heartbeat session={0} a={1} b={2} running={3} run_dir={4}" -f $sessionStatus, $aStatus, $bStatus, $running, $runDirAnchor)
                    $lastHeartbeatAt = $now
                }

                if ($statusTicketEnabled) {
                    $statusTicketDue = ($lastStatusTicketAt -eq [datetime]::MinValue -or (($now - $lastStatusTicketAt).TotalMinutes -ge $statusTicketIntervalMinutes))
                    if ($statusTicketDue) {
                        $statusDetail = ("session={0} a={1} b={2} running={3} run_dir={4}" -f $sessionStatus, $aStatus, $bStatus, $running, $runDirAnchor)
                        $statusDedupSuffix = ("interval={0}|slot={1}|status={2}|a={3}|b={4}|run={5}" -f $statusTicketIntervalMinutes, $now.ToString('yyyyMMdd-HHmm'), $sessionStatus, $aStatus, $bStatus, $runDirAnchor)
                        $statusRecommendedAction = 'Report root cause and remediation path first. For running-status-report, execute only the provided status business_command (health check) and then continue_watch_command; do NOT stage-restart A/B from this status ticket unless a separate incident ticket is raised. After completing this ticket cycle, you MUST return handled_at (YYYY-MM-DD HH:mm:ss). For running-status-report, handled_at is mandatory immediately after business/continue_watch and cannot be omitted even when monitoring continues. session_closed_at is session-level only and MUST be returned only when stop monitoring is requested or both A/B are terminal. After handling, switch to read-only monitoring and keep scheduled status-ticket heartbeat + poll cadence until "stop monitoring". Poll hint: include -IncludeStatusReports when consuming running-status-report tickets; continue_watch_command uses -NoRestartIfRunning to avoid unnecessary guard restarts.'
                        $lastStatusTicketAt = $now
                        $statusPreferredStage = if ($aStatus -eq 'PASS' -and $bStatus -ne 'PASS') { 'B' } else { 'A' }
                        $statusTicketResult = Add-AgentTicket -Enabled $agentQueueEnabled -QueuePath $agentQueuePath -EventName 'running-status-report' -Severity 'info' -RequiresConfirmation $false -SessionStatus $sessionStatus -AStatus $aStatus -BStatus $bStatus -RunDirAnchor $runDirAnchor -IncidentDir '' -Detail $statusDetail -DedupSuffix $statusDedupSuffix -RecommendedAction $statusRecommendedAction -PreferredStage $statusPreferredStage -MainRound '' -FailureKind 'running-status' -FailureCategory '' -FailureSource '' -FailureEvidence '' -SelfHealable $false -NonRecoverableEnv $false
                        if (-not [bool]$statusTicketResult.Queued -and [string]$statusTicketResult.Reason -notin @('duplicate-signature', 'queue-disabled')) {
                            Write-GuardLog ("status_ticket_deferred_next_slot reason={0} interval_min={1}" -f [string]$statusTicketResult.Reason, $statusTicketIntervalMinutes)
                        }
                    }
                }
            }
        }
        catch {
            Write-GuardLog ("loop_error detail={0}" -f $_.Exception.Message.Replace("`r", ' ').Replace("`n", ' '))
        }
        finally {
            # Health check runs every ~300s even after continue/break to ensure
            # offline monitors (companion/supervisor/trigger) are restarted.
            $healthCheckIterationCounter++
            $healthCheckIntervalIterations = [Math]::Max(1, [int][Math]::Round(300.0 / [Math]::Max(15, $PollSec)))
            if ($healthCheckIterationCounter -ge $healthCheckIntervalIterations) {
                $healthCheckIterationCounter = 0
                Invoke-MonitorChainHealthCheck -Roles @('companion', 'supervisor', 'trigger') -RepoRoot $script:RepoRoot -StartFilePath $script:StartFilePath -LogPrefix 'GUARD-HC'
            }
        }

        Start-Sleep -Seconds $PollSec
    }
}
finally {
    Write-GuardState -Values @{
        status = 'stopped'
        event = 'shutdown'
    }
    Write-GuardLog ("shutdown_pid pid={0}" -f $PID)
    if ($null -ne $script:InstanceMutex) {
        try {
            $script:InstanceMutex.ReleaseMutex() | Out-Null
        }
        catch { Write-Verbose ("Suppressed exception: {0}" -f $_.Exception.Message) }
        finally {
            $script:InstanceMutex.Dispose()
        }
    }
}

exit 0
