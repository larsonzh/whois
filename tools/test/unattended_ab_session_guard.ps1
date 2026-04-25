param(
    [Parameter(Mandatory = $true)][string]$StartFile,
    [ValidateRange(15, 300)][int]$PollSec = 60,
    [ValidateRange(0, 10)][int]$MaxBRecoveryAttempts = 2,
    [ValidateRange(1, 180)][int]$RecoveryCooldownMinutes = 10,
    [bool]$StopOnBudgetExhausted = $true
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

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

function Get-FilteredRuntimeTailLines {
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

function Acquire-InstanceMutex {
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
            try { $mutex.Dispose() } catch {}
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

    $map = [ordered]@{}
    foreach ($line in $lines) {
        if ($line -match '^([^=]+)=(.*)$') {
            $map[$Matches[1].Trim()] = $Matches[2]
        }
    }

    return $map
}

function Set-KeyValueFileValues {
    param(
        [string]$Path,
        [hashtable]$Values
    )

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
            Set-Content -LiteralPath $Path -Value @($lines) -Encoding utf8 -ErrorAction Stop
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
}

function Append-DelimitedNote {
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

function Copy-FileIfExists {
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

    @(Get-Content -LiteralPath $Source -Tail $Tail -ErrorAction SilentlyContinue) | Set-Content -LiteralPath $Destination -Encoding utf8
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
            $json | Set-Content -LiteralPath $script:GuardStatePath -Encoding utf8 -ErrorAction Stop
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

function Enqueue-AgentTicket {
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
        [AllowEmptyString()][string]$RecommendedAction
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

    $signature = "{0}|{1}|{2}|{3}|{4}|{5}|{6}|{7}" -f
        (Convert-ToSingleLineText -Text $EventName),
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
        event = (Convert-ToSingleLineText -Text $EventName)
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
        recommended_action = (Convert-ToBoundedSingleLineText -Text $RecommendedAction -MaxChars 280)
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

function Get-BStageProcessCandidates {
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
    $candidates = @(Get-BStageProcessCandidates)
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

    $anchor = Get-LatestAnchorValueFromNotes -Notes $notes -Key 'b_runtime_log'
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
            $filteredTail = @(Get-FilteredRuntimeTailLines -Lines $rawTail)
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
    catch {
    }

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
    catch {
    }

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

    $supervisorLogAnchor = Get-LatestAnchorValueFromNotes -Notes $notes -Key 'supervisor_log'
    $liveStatusAnchor = Get-LatestAnchorValueFromNotes -Notes $notes -Key 'live_status'
    $runDirAnchor = Get-LatestAnchorValueFromNotes -Notes $notes -Key 'run_dir'
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

function Capture-IncidentPackage {
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
    $runDirAnchor = Get-LatestAnchorValueFromNotes -Notes $notes -Key 'run_dir'
    $supervisorLogAnchor = Get-LatestAnchorValueFromNotes -Notes $notes -Key 'supervisor_log'
    $companionLogAnchor = Get-LatestAnchorValueFromNotes -Notes $notes -Key 'companion_log'
    $liveStatusAnchor = Get-LatestAnchorValueFromNotes -Notes $notes -Key 'live_status'

    $runDir = Resolve-AnchorPath -Path $runDirAnchor
    $supervisorLog = Resolve-AnchorPath -Path $supervisorLogAnchor
    $companionLog = Resolve-AnchorPath -Path $companionLogAnchor
    $liveStatus = Resolve-AnchorPath -Path $liveStatusAnchor

    Copy-FileIfExists -Source $script:StartFilePath -Destination (Join-Path $incidentDir 'start_file_snapshot.md')
    Copy-FileIfExists -Source $liveStatus -Destination (Join-Path $incidentDir 'live_status.json')
    Export-FileTail -Source $supervisorLog -Destination (Join-Path $incidentDir 'supervisor_tail.log') -Tail 500
    Export-FileTail -Source $companionLog -Destination (Join-Path $incidentDir 'companion_tail.log') -Tail 500

    if (-not [string]::IsNullOrWhiteSpace($runDir) -and (Test-Path -LiteralPath $runDir)) {
        Copy-FileIfExists -Source (Join-Path $runDir 'final_status.json') -Destination (Join-Path $incidentDir 'run_final_status.json')
        Copy-FileIfExists -Source (Join-Path $runDir 'final_status.txt') -Destination (Join-Path $incidentDir 'run_final_status.txt')
        Copy-FileIfExists -Source (Join-Path $runDir 'summary.csv') -Destination (Join-Path $incidentDir 'summary.csv')
        Copy-FileIfExists -Source (Join-Path $runDir 'summary_partial.csv') -Destination (Join-Path $incidentDir 'summary_partial.csv')
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
    $processSnapshot | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $incidentDir 'process_snapshot.json') -Encoding utf8

    $gitStatus = @((& git -C $script:RepoRoot status --short 2>&1) | ForEach-Object { [string]$_ })
    $gitStatus | Set-Content -LiteralPath (Join-Path $incidentDir 'git_status_short.txt') -Encoding utf8

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
    $summary | Set-Content -LiteralPath (Join-Path $incidentDir 'summary.txt') -Encoding utf8

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

function Get-RoundFailureCategoryFromLogs {
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
    $codeFaultRegex = '(?im)(src[\\/].*\.(c|h):\d+:\d+:\s*error:|error\s+C\d{4}\b|undefined\s+reference\s+to|compilation\s+terminated|was\s+not\s+declared\s+in\s+this\s+scope|conflicting\s+types\s+for|redefinition\s+of|no\s+member\s+named|fatal\s+error:\s+.*)'

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

    if ([bool]$result.HasScriptFault) {
        $result.Category = 'script-fault'
        if ([bool]$result.HasCodeFault) {
            $result.Evidence = ('script={0};code={1}' -f $scriptEvidence, $codeEvidence)
            $result.SourceLog = if (-not [string]::IsNullOrWhiteSpace($scriptSourceLog)) { $scriptSourceLog } else { $codeSourceLog }
        }
        else {
            $result.Evidence = ('matched={0}' -f $scriptEvidence)
            $result.SourceLog = $scriptSourceLog
        }
        return [pscustomobject]$result
    }

    if ([bool]$result.HasNetworkTransient) {
        $result.Category = 'noncode-transient'
        $result.Evidence = ('matched={0}' -f $networkEvidence)
        $result.SourceLog = $networkSourceLog
        return [pscustomobject]$result
    }

    if ([bool]$result.HasCodeFault) {
        $result.Category = 'code-or-unknown'
        $result.Evidence = ('code={0}' -f $codeEvidence)
        $result.SourceLog = $codeSourceLog
    }

    return [pscustomobject]$result
}

function Get-VerifyFailureCategoryFromLogs {
    param(
        [AllowEmptyString()][string]$RunDir,
        [AllowEmptyString()][string]$RoundTag,
        [AllowEmptyString()][string]$AutopilotOutDir
    )

    return (Get-RoundFailureCategoryFromLogs -RunDir $RunDir -RoundTag $RoundTag -AutopilotOutDir $AutopilotOutDir)
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
        $categoryInfo = Get-RoundFailureCategoryFromLogs -RunDir $runDir -RoundTag ([string]$result.FailedRoundTag) -AutopilotOutDir $autopilotOutDir
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

function Get-ACompileFailureContext {
    param(
        [System.Collections.IDictionary]$Settings,
        [AllowEmptyString()][string]$RunDirAnchor
    )

    $result = [ordered]@{
        Eligible = $false
        Reason = ''
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
        return [pscustomobject]$result
    }
    $result.StrictLogPath = Convert-ToRepoRelativePath -Path $strictLogPath

    $strictLogText = ''
    try {
        $strictLogText = Get-Content -LiteralPath $strictLogPath -Raw -Encoding utf8 -ErrorAction Stop
    }
    catch {
        $result.Reason = 'strict-log-read-failed'
        return [pscustomobject]$result
    }

    $result.StrictLogText = $strictLogText
    if ($strictLogText -notmatch '(?im)src/core/preclass\.c:.*\berror:') {
        $result.Reason = 'not-preclass-compile-error'
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

function Ensure-RegexPatchOperation {
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

function Invoke-ApplyKnownPreclassTaskFixes {
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
    $changeStates += (Ensure-RegexPatchOperation -Operations $operations -Pattern 'static int wc_preclass_is_v6_loopback\(const struct in6_addr\* addr6\)' -Replacement $replacementSpecialTuple)
    $changeStates += (Ensure-RegexPatchOperation -Operations $operations -Pattern 'static const char\* wc_preclass_match_layer_from_query_kind\(int query_is_cidr\)\r?\n\{\r?\n\treturn query_is_cidr \? wc_preclass_match_layer_cidr_output_literal\(\) : wc_preclass_match_layer_ip_output_literal\(\);\r?\n\}' -Replacement $replacementMatchLayer)
    $changeStates += (Ensure-RegexPatchOperation -Operations $operations -Pattern 'static const char\* wc_preclass_reason_unknown_hint_literal\(void\)\r?\n\{\r?\n\treturn wc_preclass_reason_unknown_literal\(\);\r?\n\}' -Replacement '')
    $changeStates += (Ensure-RegexPatchOperation -Operations $operations -Pattern 'static void wc_preclass_set_unknown_v6_hint_result\(const char\*\* rir,\r?\n\t\tconst char\*\* reason,\r?\n\t\tconst char\*\* confidence\)\r?\n\{\r?\n\t\*rir = "unknown";\r?\n\t\*reason = "V6_NO_RIR_HINT";\r?\n\t\*confidence = "low";\r?\n\}' -Replacement '')

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
        $json = $taskDefinition | ConvertTo-Json -Depth 64
        Set-Content -LiteralPath $TaskDefinitionPath -Value $json -Encoding utf8 -ErrorAction Stop
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

    $applyResult = Invoke-ApplyKnownPreclassTaskFixes -TaskDefinitionPath ([string]$context.TaskDefinitionPath) -RoundTag ([string]$context.RoundTag)
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
        $newNotes = Append-DelimitedNote -Existing $existingNotes -Append $note
        Set-KeyValueFileValues -Path $script:StartFilePath -Values @{ SESSION_FINAL_NOTES = $newNotes }
    }
    catch {
        Write-GuardLog ("auto_fix_note_update_failed detail={0}" -f (Convert-ToSingleLineText -Text $_.Exception.Message))
    }

    return [pscustomobject]$result
}

$script:RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$script:StartFilePath = Resolve-RepoPath -Path $StartFile
$script:StartFileLeaf = [System.IO.Path]::GetFileName($script:StartFilePath).ToLowerInvariant()
$script:InstanceMutex = Acquire-InstanceMutex -Role 'session-guard' -StartFilePath $script:StartFilePath

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

$bRecoveryAttempts = 0
$lastRecoveryAt = [datetime]::MinValue
$lastIncidentSignature = ''
$lastHeartbeatAt = [datetime]::MinValue
$lastBudgetExhaustedSignature = ''
$bRunningNoProcessSince = $null
$lastMissingBProcessReportAt = $null
$lastBMissingExitReasonEvidence = $null
$lastBMissingRuntimeTailEvidence = $null
$manualPauseActive = $false
$manualPauseSignature = ''
$manualPauseNoticeCount = 0
$manualPauseNoticeRepeat = 2
$manualPauseEnabled = $true
$autoFixCompileEnabled = $true
$autoFixMaxPerDRound = 3
$autoFixCooldownMinutes = 1
$lastAutoFixStatusSignature = ''
$restartRequiresConfirmation = $false
$restartApproved = $true
$lastRestartApprovalWaitSignature = ''
$statusTicketEnabled = $false
$statusTicketIntervalMinutes = 30
$lastStatusTicketAt = [datetime]::MinValue

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

            $agentQueueEnabled = $true
            if ($settings.Contains('LOCAL_GUARD_AGENT_QUEUE_ENABLED')) {
                $agentQueueEnabled = Convert-ToBooleanSetting -Value ([string]$settings.LOCAL_GUARD_AGENT_QUEUE_ENABLED) -Default $true
            }
            $agentQueuePath = Get-AgentTicketQueuePath -Settings $settings

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

            $bRunningNoProcessGraceSec = [Math]::Max(([int]$PollSec * 3), 180)
            if ($settings.Contains('LOCAL_GUARD_B_RUNNING_NO_PROCESS_GRACE_SEC')) {
                $parsedGrace = 0
                if ([int]::TryParse(([string]$settings.LOCAL_GUARD_B_RUNNING_NO_PROCESS_GRACE_SEC), [ref]$parsedGrace)) {
                    if ($parsedGrace -ge 30 -and $parsedGrace -le 1800) {
                        $bRunningNoProcessGraceSec = [int]$parsedGrace
                    }
                }
            }

            $bLaunchPid = 0
            if ($settings.Contains('B_LAUNCH_PID')) {
                $parsedLaunchPid = Convert-ToNullablePositiveInt -Value ([string]$settings.B_LAUNCH_PID)
                if ($null -ne $parsedLaunchPid) {
                    $bLaunchPid = [int]$parsedLaunchPid
                }
            }

            $running = ($aStatus -eq 'RUNNING' -or $bStatus -eq 'RUNNING')
            $notes = if ($settings.Contains('SESSION_FINAL_NOTES')) { [string]$settings.SESSION_FINAL_NOTES } else { '' }
            $runDirAnchor = Get-LatestAnchorValueFromNotes -Notes $notes -Key 'run_dir'

            if ($running -and $manualPauseActive) {
                Write-GuardLog ("manual_wait_resume session={0} a={1} b={2} run_dir={3}" -f $sessionStatus, $aStatus, $bStatus, $runDirAnchor)
                $manualPauseActive = $false
                $manualPauseSignature = ''
                $manualPauseNoticeCount = 0
            }

            $bProcessSnapshot = $null
            if ($bStatus -eq 'RUNNING') {
                $bProcessSnapshot = Get-BStageProcessSnapshot -ExpectedProcessId $bLaunchPid
                if ([bool]$bProcessSnapshot.AnchorUpdateRequired) {
                    $newBLaunchPid = [int]$bProcessSnapshot.ResolvedProcessId
                    Set-KeyValueFileValues -Path $script:StartFilePath -Values @{
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

                        $newNotes = Append-DelimitedNote -Existing $notes -Append $failureNote
                        Set-KeyValueFileValues -Path $script:StartFilePath -Values @{
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
                        $runDirAnchor = Get-LatestAnchorValueFromNotes -Notes $notes -Key 'run_dir'
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
                restart_requires_confirmation = [bool]$restartRequiresConfirmation
                restart_approved = [bool]$restartApproved
                agent_ticket_queue_enabled = [bool]$agentQueueEnabled
                agent_ticket_queue_path = (Convert-ToRepoRelativePath -Path $agentQueuePath)
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
                $incidentRecommendedAction = 'Review incident evidence, then decide restart approval or agent-driven script/code fix workflow.'
                $manualWaitRecommendedAction = 'Open takeover brief and decide whether to patch scripts/code or resume stage flow manually.'
                $failureCategory = (Convert-ToSingleLineText -Text ([string]$failurePolicy.FailureCategory)).ToLowerInvariant()
                if ([string]::IsNullOrWhiteSpace($failureCategory)) {
                    $failureCategory = 'unknown'
                }
                $failureHasScriptFault = [bool]$failurePolicy.FailureHasScriptFault
                $failureHasCodeFault = [bool]$failurePolicy.FailureHasCodeFault
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
                                $manualWaitRecommendedAction = ('Verify-round script fault ({0}) source={1}. Fix scripts and resume guarded restart workflow; keep blocking watch active.' -f [string]$failurePolicy.FailedRoundTag, [string]$failurePolicy.VerifyFailureSourceLog)
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

                    switch ($devCategory) {
                        'script-fault' {
                            if ($failureHasCodeFault) {
                                $incidentRecommendedAction = ('Dev-round failure detected ({0}) category=script-fault with code-marker. Repair scripts and code, then restart guarded A-stage flow.' -f [string]$failurePolicy.FailedRoundTag)
                                $manualWaitRecommendedAction = ('Dev-round dual fault ({0}) source={1}. Repair script faults first, then run D-round code auto-fix workflow and restart.' -f [string]$failurePolicy.FailedRoundTag, [string]$failurePolicy.DevFailureSourceLog)
                            }
                            else {
                                $incidentRecommendedAction = ('Dev-round failure detected ({0}) category=script-fault. Repair scripts and run D-round code fix checks before restart.' -f [string]$failurePolicy.FailedRoundTag)
                                $manualWaitRecommendedAction = ('Dev-round script fault ({0}) source={1}. Repair scripts, then run code-fix workflow and restart guarded flow.' -f [string]$failurePolicy.FailedRoundTag, [string]$failurePolicy.DevFailureSourceLog)
                            }
                        }
                        'noncode-transient' {
                            $incidentRecommendedAction = ('Dev-round failure detected ({0}) category=noncode-transient. Guard may restart A-stage under existing quota/cooldown without code-fix actions.' -f [string]$failurePolicy.FailedRoundTag)
                            $manualWaitRecommendedAction = ('Dev-round non-code transient ({0}) evidence={1}. Allow guarded restart retries within quota/cooldown.' -f [string]$failurePolicy.FailedRoundTag, [string]$failurePolicy.DevFailureEvidence)
                        }
                        default {
                            if ($failureHasCodeFault) {
                                $incidentRecommendedAction = ('Dev-round failure detected ({0}) category=code-or-unknown with code-marker. Run code-fix workflow and restart after confirmation.' -f [string]$failurePolicy.FailedRoundTag)
                                $manualWaitRecommendedAction = ('Dev-round code fault ({0}) evidence={1}. Apply code fixes and restart guarded flow after review.' -f [string]$failurePolicy.FailedRoundTag, [string]$failurePolicy.DevFailureEvidence)
                            }
                            else {
                                $incidentRecommendedAction = ('Dev-round failure detected ({0}) category=code-or-unknown. Gather evidence and wait manual decision before restart.' -f [string]$failurePolicy.FailedRoundTag)
                                $manualWaitRecommendedAction = ('Dev-round unknown failure ({0}). Keep incident evidence and decide script/code handling manually.' -f [string]$failurePolicy.FailedRoundTag)
                            }
                        }
                    }
                }
                if ($statusSignature -ne $lastIncidentSignature) {
                    $incidentDir = Capture-IncidentPackage -Settings $settings -SessionStatus $sessionStatus -AStatus $aStatus -BStatus $bStatus
                    $incidentRel = Convert-ToRepoRelativePath -Path $incidentDir
                    $lastIncidentSignature = $statusSignature
                    Write-GuardLog ("incident status={0} a={1} b={2} evidence={3}" -f $sessionStatus, $aStatus, $bStatus, $incidentRel)

                    $newNotes = Append-DelimitedNote -Existing $notes -Append ("guard_incident status={0} a={1} b={2} evidence={3}" -f $sessionStatus, $aStatus, $bStatus, $incidentRel)
                    Set-KeyValueFileValues -Path $script:StartFilePath -Values @{
                        SESSION_FINAL_NOTES = $newNotes
                    }

                    $incidentDetail = ("session={0} a={1} b={2} evidence={3}" -f $sessionStatus, $aStatus, $bStatus, $incidentRel)
                    $null = Enqueue-AgentTicket -Enabled $agentQueueEnabled -QueuePath $agentQueuePath -EventName 'incident-captured' -Severity 'high' -RequiresConfirmation $restartRequiresConfirmation -SessionStatus $sessionStatus -AStatus $aStatus -BStatus $bStatus -RunDirAnchor $runDirAnchor -IncidentDir $incidentDir -Detail $incidentDetail -DedupSuffix $statusSignature -RecommendedAction $incidentRecommendedAction
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
                        $null = Enqueue-AgentTicket -Enabled $agentQueueEnabled -QueuePath $agentQueuePath -EventName 'verify-restart-await-confirmation' -Severity 'high' -RequiresConfirmation $true -SessionStatus $sessionStatus -AStatus $aStatus -BStatus $bStatus -RunDirAnchor $runDirAnchor -IncidentDir '' -Detail $verifyWaitDetail -DedupSuffix $verifyWaitDedup -RecommendedAction 'Set LOCAL_GUARD_RESTART_APPROVED=true after evidence review to allow guarded verify restart.'
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
                            $null = Enqueue-AgentTicket -Enabled $agentQueueEnabled -QueuePath $agentQueuePath -EventName 'dev-restart-await-confirmation' -Severity 'high' -RequiresConfirmation $true -SessionStatus $sessionStatus -AStatus $aStatus -BStatus $bStatus -RunDirAnchor $runDirAnchor -IncidentDir '' -Detail $devWaitDetail -DedupSuffix $devWaitDedup -RecommendedAction 'Set LOCAL_GUARD_RESTART_APPROVED=true after evidence review to allow guarded D-round restart.'

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
                            $autoFixRecommendedAction = 'Fix D-round scripts and code, then set LOCAL_GUARD_RESTART_APPROVED=true to resume guarded A-stage restart.'
                        }
                        elseif ([bool]$failurePolicy.IsDevRound -and $failureHasScriptFault) {
                            $autoFixRecommendedAction = 'Fix D-round scripts first, then set LOCAL_GUARD_RESTART_APPROVED=true to continue code-fix workflow and restart.'
                        }
                        elseif ([bool]$failurePolicy.IsDevRound -and $failureHasCodeFault) {
                            $autoFixRecommendedAction = 'Review D-round code fix evidence, then set LOCAL_GUARD_RESTART_APPROVED=true to restart guarded A-stage flow.'
                        }

                        $autoFixWaitDetail = ("stage=A round={0} attempt={1}/{2} reason={3} detail={4}" -f
                            [string]$autoFixResult.RoundTag,
                            [int]$autoFixResult.Attempt,
                            [int]$autoFixMaxPerDRound,
                            [string]$autoFixResult.Reason,
                            (Convert-ToBoundedSingleLineText -Text ([string]$autoFixResult.Detail) -MaxChars 200))
                        $autoFixDedup = ("{0}|{1}|{2}|{3}" -f [string]$autoFixResult.RoundTag, [int]$autoFixResult.Attempt, [string]$autoFixResult.Reason, $runDirAnchor)
                        $null = Enqueue-AgentTicket -Enabled $agentQueueEnabled -QueuePath $agentQueuePath -EventName 'auto-fix-await-confirmation' -Severity 'high' -RequiresConfirmation $true -SessionStatus $sessionStatus -AStatus $aStatus -BStatus $bStatus -RunDirAnchor $runDirAnchor -IncidentDir '' -Detail $autoFixWaitDetail -DedupSuffix $autoFixDedup -RecommendedAction $autoFixRecommendedAction
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
                            $null = Enqueue-AgentTicket -Enabled $agentQueueEnabled -QueuePath $agentQueuePath -EventName 'recovery-await-confirmation' -Severity 'high' -RequiresConfirmation $true -SessionStatus $sessionStatus -AStatus $aStatus -BStatus $bStatus -RunDirAnchor $runDirAnchor -IncidentDir '' -Detail $waitDetail -DedupSuffix $approvalWaitSignature -RecommendedAction 'Approve guarded B restart by setting LOCAL_GUARD_RESTART_APPROVED=true after evidence check.'
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
                            $budgetDetail = ("attempts={0} max={1} stop_on_budget_exhausted={2}" -f $bRecoveryAttempts, $MaxBRecoveryAttempts, $StopOnBudgetExhausted)
                            $null = Enqueue-AgentTicket -Enabled $agentQueueEnabled -QueuePath $agentQueuePath -EventName 'budget-exhausted-stop' -Severity 'high' -RequiresConfirmation $false -SessionStatus $sessionStatus -AStatus $aStatus -BStatus $bStatus -RunDirAnchor $runDirAnchor -IncidentDir '' -Detail $budgetDetail -DedupSuffix $budgetSignature -RecommendedAction 'Use resume workflow and incident evidence to decide rerun scope or scripted fix before next restart.'
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
                            $newNotes = Append-DelimitedNote -Existing ([string](Read-KeyValueFile -Path $script:StartFilePath).SESSION_FINAL_NOTES) -Append $restartNote
                            Set-KeyValueFileValues -Path $script:StartFilePath -Values @{ SESSION_FINAL_NOTES = $newNotes }
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

                    $manualWaitSignature = "{0}|{1}|{2}|{3}|{4}" -f $sessionStatus, $aStatus, $bStatus, $runDirAnchor, $canRecoverB
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
                            $null = Enqueue-AgentTicket -Enabled $agentQueueEnabled -QueuePath $agentQueuePath -EventName 'manual-wait-paused' -Severity 'medium' -RequiresConfirmation $restartRequiresConfirmation -SessionStatus $sessionStatus -AStatus $aStatus -BStatus $bStatus -RunDirAnchor $runDirAnchor -IncidentDir '' -Detail $manualWaitDetail -DedupSuffix $manualWaitSignature -RecommendedAction $manualWaitRecommendedAction
                        }

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
                        $statusTicketResult = Enqueue-AgentTicket -Enabled $agentQueueEnabled -QueuePath $agentQueuePath -EventName 'running-status-report' -Severity 'info' -RequiresConfirmation $false -SessionStatus $sessionStatus -AStatus $aStatus -BStatus $bStatus -RunDirAnchor $runDirAnchor -IncidentDir '' -Detail $statusDetail -DedupSuffix $statusDedupSuffix -RecommendedAction 'Review relay status and keep blocking watch active. No restart action is required while stages remain running.'
                        if ([bool]$statusTicketResult.Queued -or [string]$statusTicketResult.Reason -eq 'duplicate-signature') {
                            $lastStatusTicketAt = $now
                        }
                    }
                }
            }
        }
        catch {
            Write-GuardLog ("loop_error detail={0}" -f $_.Exception.Message.Replace("`r", ' ').Replace("`n", ' '))
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
        catch {
        }
        finally {
            $script:InstanceMutex.Dispose()
        }
    }
}