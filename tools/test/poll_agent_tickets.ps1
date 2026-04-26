param(
    [Parameter(Mandatory = $true)][string]$StartFile,
    [AllowEmptyString()][string]$QueuePath = '',
    [AllowEmptyString()][string]$StatePath = '',
    [AllowEmptyString()][string]$LedgerPath = '',
    [AllowNull()][object]$EnableLedgerCompaction = $false,
    [ValidateRange(1, 365)][int]$LedgerCompactionDays = 7,
    [ValidateRange(1, 365)][int]$LedgerArchiveRetentionDays = 30,
    [ValidateRange(1, 200)][int]$Last = 20,
    [ValidateRange(0, 200000)][int]$MaxProcessedIds = 200000,
    [switch]$IncludeStatusReports,
    [AllowNull()][object]$MarkProcessed = $false,
    [AllowNull()][object]$EnableFallbackStatus = $true,
    [AllowNull()][object]$EventPolicyStrict = $null,
    [AllowEmptyString()][string]$AcknowledgeTicketIds = '',
    [switch]$AsJson
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:EventSetStatusReport = @{ 'running-status-report' = $true }
$script:EventSetDrainSafe = @{
    'running-status-report' = $true
    'manual-wait-paused' = $true
    'budget-exhausted-stop' = $true
    'known-infra-transient-stop' = $true
}
$script:EventSetBarrier = @{
    'incident-captured' = $true
    'recovery-await-confirmation' = $true
    'auto-fix-await-confirmation' = $true
    'manual-wait-paused' = $true
    'budget-exhausted-stop' = $true
    'known-infra-transient-stop' = $true
}
$script:EventSetRestartSensitive = @{
    'incident-captured' = $true
    'recovery-await-confirmation' = $true
    'auto-fix-await-confirmation' = $true
}

function Normalize-PathLikeValue {
    param([AllowEmptyString()][string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return ''
    }

    $normalized = $Value.Trim()
    if ($normalized.Length -ge 2) {
        if (($normalized.StartsWith('"') -and $normalized.EndsWith('"')) -or
            ($normalized.StartsWith("'") -and $normalized.EndsWith("'"))) {
            $normalized = $normalized.Substring(1, $normalized.Length - 2).Trim()
        }
    }

    return $normalized
}

function Resolve-RepoPath {
    param(
        [string]$Path,
        [bool]$MustExist = $true
    )

    $Path = Normalize-PathLikeValue -Value $Path
    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw 'Path must not be empty.'
    }

        $fullPath = ''
        if ([System.IO.Path]::IsPathRooted($Path)) {
            $fullPath = [System.IO.Path]::GetFullPath($Path)
        }
        else {
            $fullPath = [System.IO.Path]::GetFullPath((Join-Path $script:RepoRoot $Path))
        }

    if ($MustExist -and -not (Test-Path -LiteralPath $fullPath)) {
        throw ("Path not found: {0}" -f $fullPath)
    }

    return $fullPath
}

function Resolve-RepoPathAllowMissing {
    param([AllowEmptyString()][string]$Path)

    $Path = Normalize-PathLikeValue -Value $Path
    if ([string]::IsNullOrWhiteSpace($Path)) {
        return ''
    }

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return [System.IO.Path]::GetFullPath($Path)
    }

    return [System.IO.Path]::GetFullPath((Join-Path $script:RepoRoot $Path))
}

function Convert-ToRepoRelativePath {
    param([AllowEmptyString()][string]$Path)

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

function Convert-ToSingleLineText {
    param([AllowEmptyString()][string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return ''
    }

    $singleLine = (($Text -split "`r?`n") -join ' ')
    return ([regex]::Replace($singleLine, '\s+', ' ')).Trim()
}

function Get-SafeToken {
    param([AllowEmptyString()][string]$Text)

    $normalized = Convert-ToSingleLineText -Text $Text
    if ([string]::IsNullOrWhiteSpace($normalized)) {
        return 'default'
    }

    return ([regex]::Replace($normalized, '[^A-Za-z0-9._-]', '_')).Trim('_')
}

function Convert-ToBooleanValue {
    param(
        [object]$Value,
        [bool]$Default = $false
    )

    if ($null -eq $Value) {
        return $Default
    }

    if ($Value -is [bool]) {
        return [bool]$Value
    }

    $raw = Convert-ToSingleLineText -Text ([string]$Value)
    if ([string]::IsNullOrWhiteSpace($raw)) {
        return $Default
    }

    return $raw.Trim().ToLowerInvariant() -in @('1', 'true', 'yes', 'on')
}

function Get-NormalizedListValues {
    param([AllowEmptyString()][string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return @()
    }

    $items = New-Object 'System.Collections.Generic.List[string]'
    foreach ($token in @($Value -split '[,;\r\n]+')) {
        $normalized = Convert-ToSingleLineText -Text ([string]$token)
        if ([string]::IsNullOrWhiteSpace($normalized)) {
            continue
        }

        [void]$items.Add($normalized)
    }

    return @($items.ToArray())
}

function Get-MarkProcessedCommand {
    param(
        [string]$StartFileRel,
        [string]$TicketId,
        [int]$Last
    )

    $ticket = Convert-ToSingleLineText -Text $TicketId
    if ([string]::IsNullOrWhiteSpace($ticket)) {
        return ''
    }

    return ('powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/poll_agent_tickets.ps1 -StartFile "{0}" -AcknowledgeTicketIds "{1}" -Last {2} -AsJson' -f $StartFileRel, $ticket, $Last)
}

function New-EventNameSet {
    param([string[]]$Values)

    $set = @{}
    foreach ($value in @($Values)) {
        $normalized = (Convert-ToSingleLineText -Text ([string]$value)).ToLowerInvariant()
        if ([string]::IsNullOrWhiteSpace($normalized)) {
            continue
        }

        $set[$normalized] = $true
    }

    return $set
}

function Add-EventSetValues {
    param(
        [hashtable]$TargetSet,
        [string[]]$Values
    )

    if ($null -eq $TargetSet) {
        return
    }

    foreach ($value in @($Values)) {
        $normalized = (Convert-ToSingleLineText -Text ([string]$value)).ToLowerInvariant()
        if ([string]::IsNullOrWhiteSpace($normalized)) {
            continue
        }

        $TargetSet[$normalized] = $true
    }
}

function Get-ConfiguredEventNameList {
    param(
        [System.Collections.IDictionary]$Settings,
        [string]$SettingKey,
        [string[]]$Fallback
    )

    $raw = ''
    if ($null -ne $Settings -and -not [string]::IsNullOrWhiteSpace($SettingKey) -and $Settings.Contains($SettingKey)) {
        $raw = [string]$Settings[$SettingKey]
    }

    if ([string]::IsNullOrWhiteSpace($raw)) {
        return @($Fallback)
    }

    $list = New-Object 'System.Collections.Generic.List[string]'
    foreach ($token in @($raw -split '[,;\r\n]+')) {
        $normalized = (Convert-ToSingleLineText -Text ([string]$token)).ToLowerInvariant()
        if ([string]::IsNullOrWhiteSpace($normalized)) {
            continue
        }

        [void]$list.Add($normalized)
    }

    if ($list.Count -eq 0) {
        return @($Fallback)
    }

    return @($list.ToArray())
}

function Test-EventInSet {
    param(
        [hashtable]$Set,
        [AllowEmptyString()][string]$EventName
    )

    if ($null -eq $Set) {
        return $false
    }

    $normalized = (Convert-ToSingleLineText -Text $EventName).ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($normalized)) {
        return $false
    }

    return $Set.ContainsKey($normalized)
}

function Ensure-EventSetNotEmpty {
    param(
        [hashtable]$TargetSet,
        [string[]]$FallbackValues,
        [System.Collections.Generic.List[string]]$Adjustments,
        [string]$AdjustmentTag
    )

    if ($null -eq $TargetSet) {
        $TargetSet = @{}
    }

    if ($TargetSet.Count -gt 0) {
        return $TargetSet
    }

    Add-EventSetValues -TargetSet $TargetSet -Values $FallbackValues
    if ($null -ne $Adjustments -and -not [string]::IsNullOrWhiteSpace($AdjustmentTag)) {
        [void]$Adjustments.Add($AdjustmentTag)
    }

    return $TargetSet
}

function Ensure-EventSetContainsValues {
    param(
        [hashtable]$TargetSet,
        [string[]]$RequiredValues,
        [System.Collections.Generic.List[string]]$Adjustments,
        [string]$AdjustmentPrefix
    )

    if ($null -eq $TargetSet) {
        return
    }

    foreach ($value in @($RequiredValues)) {
        $normalized = (Convert-ToSingleLineText -Text ([string]$value)).ToLowerInvariant()
        if ([string]::IsNullOrWhiteSpace($normalized)) {
            continue
        }

        if ($TargetSet.ContainsKey($normalized)) {
            continue
        }

        $TargetSet[$normalized] = $true
        if ($null -ne $Adjustments -and -not [string]::IsNullOrWhiteSpace($AdjustmentPrefix)) {
            [void]$Adjustments.Add(('{0}:{1}' -f $AdjustmentPrefix, $normalized))
        }
    }
}

function Test-EventSetIntersects {
    param(
        [hashtable]$TargetSet,
        [string[]]$CandidateValues
    )

    if ($null -eq $TargetSet -or $TargetSet.Count -eq 0) {
        return $false
    }

    foreach ($value in @($CandidateValues)) {
        $normalized = (Convert-ToSingleLineText -Text ([string]$value)).ToLowerInvariant()
        if ([string]::IsNullOrWhiteSpace($normalized)) {
            continue
        }

        if ($TargetSet.ContainsKey($normalized)) {
            return $true
        }
    }

    return $false
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

function Get-ObjectPropertyBoolean {
    param(
        [object]$InputObject,
        [string]$Name,
        [bool]$Default = $false
    )

    if ($null -eq $InputObject -or [string]::IsNullOrWhiteSpace($Name)) {
        return $Default
    }

    if ($InputObject -is [System.Collections.IDictionary]) {
        if ($InputObject.Contains($Name)) {
            return (Convert-ToBooleanValue -Value $InputObject[$Name] -Default $Default)
        }
        return $Default
    }

    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $Default
    }

    return (Convert-ToBooleanValue -Value $property.Value -Default $Default)
}

function Get-StatusValue {
    param([AllowEmptyString()][string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return 'NOT_RUN'
    }

    return $Value.Trim().ToUpperInvariant()
}

function Get-NowText {
    return (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
}

function Get-DateTimeOrNull {
    param([AllowEmptyString()][string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return $null
    }

    $parsed = [datetimeoffset]::MinValue
    if ([datetimeoffset]::TryParse($Text, [ref]$parsed)) {
        return $parsed.UtcDateTime
    }

    return $null
}

function Get-TicketEventProfile {
    param([AllowEmptyString()][string]$EventName)

    $normalized = (Convert-ToSingleLineText -Text $EventName).ToLowerInvariant()
    $isStatusReport = Test-EventInSet -Set $script:EventSetStatusReport -EventName $normalized
    $isDrainSafeFromSet = Test-EventInSet -Set $script:EventSetDrainSafe -EventName $normalized
    $isTerminalNotice = $isDrainSafeFromSet -and (-not $isStatusReport)
    $isBarrierExplicit = Test-EventInSet -Set $script:EventSetBarrier -EventName $normalized
    $isBarrierByPattern = (-not [string]::IsNullOrWhiteSpace($normalized)) -and ($normalized -match '(restart|resume|recovery|blocked|incident)')
    $isBarrier = $isBarrierExplicit -or $isBarrierByPattern
    $isRestartSensitiveFromSet = Test-EventInSet -Set $script:EventSetRestartSensitive -EventName $normalized
    $isRestartSensitive = $isBarrier -or $isRestartSensitiveFromSet
    $isDrainSafe = $isStatusReport -or $isDrainSafeFromSet

    return [pscustomobject]@{
        normalized_event = $normalized
        is_status_report = [bool]$isStatusReport
        is_terminal_notice = [bool]$isTerminalNotice
        is_barrier = [bool]$isBarrier
        is_restart_sensitive = [bool]$isRestartSensitive
        is_drain_safe = [bool]$isDrainSafe
    }
}

function Test-IsStatusReportEvent {
    param([AllowEmptyString()][string]$EventName)

    $profile = Get-TicketEventProfile -EventName $EventName
    return [bool]$profile.is_status_report
}

function Test-IsBarrierEvent {
    param([AllowEmptyString()][string]$EventName)

    $profile = Get-TicketEventProfile -EventName $EventName
    return [bool]$profile.is_barrier
}

function Test-IsDrainSafeEvent {
    param([AllowEmptyString()][string]$EventName)

    $profile = Get-TicketEventProfile -EventName $EventName
    return [bool]$profile.is_drain_safe
}

function Get-DrainMode {
    param(
        [object]$FallbackMonitoring,
        [bool]$RecoveryDrainPending
    )

    if ($RecoveryDrainPending) {
        return [pscustomobject]@{
            mode = 'recovery-drain'
            reason = 'state-recovery-drain-pending'
        }
    }

    if ($null -eq $FallbackMonitoring) {
        return [pscustomobject]@{
            mode = 'none'
            reason = 'fallback-disabled'
        }
    }

    $sessionFinal = (Convert-ToSingleLineText -Text ([string]$FallbackMonitoring.session_final_status)).ToUpperInvariant()
    if ($sessionFinal -in @('PASS', 'FAIL', 'BLOCKED')) {
        return [pscustomobject]@{
            mode = 'drain-pass'
            reason = 'session-final-status'
        }
    }

    $liveState = (Convert-ToSingleLineText -Text ([string]$FallbackMonitoring.live_status_state)).ToLowerInvariant()
    if ($liveState -in @('complete', 'completed', 'shutdown', 'stopped', 'pass', 'fail', 'blocked')) {
        return [pscustomobject]@{
            mode = 'drain-pass'
            reason = 'live-status-state'
        }
    }

    $liveEvent = (Convert-ToSingleLineText -Text ([string]$FallbackMonitoring.live_status_event)).ToLowerInvariant()
    if ($liveEvent -match '(complete|completed|shutdown|terminated|final|stage_complete|session_complete|session_final|known-infra-transient-stop)') {
        return [pscustomobject]@{
            mode = 'drain-pass'
            reason = 'live-status-event'
        }
    }

    return [pscustomobject]@{
        mode = 'none'
        reason = 'not-final'
    }
}

function Test-IsRetryDue {
    param(
        [AllowEmptyString()][string]$NextRetryAt,
        [datetime]$NowUtc = ((Get-Date).ToUniversalTime())
    )

    $retryAtUtc = Get-DateTimeOrNull -Text $NextRetryAt
    if ($null -eq $retryAtUtc) {
        return $true
    }

    return $retryAtUtc -le $NowUtc
}

function Get-NextRetryAtText {
    param(
        [int]$RetryCount,
        [datetime]$NowLocal = (Get-Date)
    )

    $delayMinutes = switch ($RetryCount) {
        { $_ -le 0 } { 5 }
        1 { 5 }
        2 { 15 }
        default { 30 }
    }

    return $NowLocal.AddMinutes($delayMinutes).ToString('yyyy-MM-dd HH:mm:ss')
}

function Get-LedgerTerminalAtUtc {
    param([object]$Record)

    foreach ($candidate in @(
            [string]$Record.done_at,
            [string]$Record.failed_at,
            [string]$Record.last_updated_at,
            [string]$Record.created_at
        )) {
        $dt = Get-DateTimeOrNull -Text $candidate
        if ($null -ne $dt) {
            return $dt
        }
    }

    return $null
}

function Append-JsonLineSafely {
    param(
        [string]$Path,
        $Value
    )

    $parent = Split-Path -Parent $Path
    if (-not [string]::IsNullOrWhiteSpace($parent) -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }

    $jsonLine = $Value | ConvertTo-Json -Depth 12 -Compress
    Add-Content -LiteralPath $Path -Value $jsonLine -Encoding utf8
}

function Invoke-LedgerCompaction {
    param(
        [hashtable]$LedgerRecords,
        [string]$RepoRoot,
        [string]$StartToken,
        [bool]$Enabled,
        [int]$CompactionDays,
        [int]$ArchiveRetentionDays
    )

    $result = [ordered]@{
        enabled = $Enabled
        archived = 0
        removed = 0
        archive_path = ''
        removed_archive_files = 0
    }

    if (-not $Enabled) {
        return [pscustomobject]$result
    }

    $nowUtc = (Get-Date).ToUniversalTime()
    $cutoffUtc = $nowUtc.AddDays(-1 * [double]$CompactionDays)
    $archiveRoot = Join-Path $RepoRoot 'out\artifacts\ab_agent_queue\archive'
    $archivePath = Join-Path $archiveRoot ("ai_ticket_ledger_archive_{0}_{1}.jsonl" -f $StartToken, (Get-Date).ToString('yyyyMMdd'))

    $terminalStatuses = @('done', 'failed', 'stale_by_restart', 'stale_status_superseded')
    foreach ($ticketId in @($LedgerRecords.Keys)) {
        $record = Convert-ToLedgerRecord -InputRecord $LedgerRecords[$ticketId] -FallbackTicketId $ticketId
        $statusName = (Convert-ToSingleLineText -Text ([string]$record.status)).ToLowerInvariant()
        if (-not ($statusName -in $terminalStatuses)) {
            continue
        }

        $terminalAtUtc = Get-LedgerTerminalAtUtc -Record $record
        if ($null -eq $terminalAtUtc -or $terminalAtUtc -gt $cutoffUtc) {
            continue
        }

        Append-JsonLineSafely -Path $archivePath -Value ([ordered]@{
                schema = 'AB_AI_TICKET_LEDGER_ARCHIVE_V1'
                archived_at = Get-NowText
                ticket = $record
            })
        $result.archived = [int]$result.archived + 1

        $LedgerRecords.Remove($ticketId) | Out-Null
        $result.removed = [int]$result.removed + 1
    }

    if ([int]$result.archived -gt 0 -and (Test-Path -LiteralPath $archivePath)) {
        $result.archive_path = Convert-ToRepoRelativePath -Path $archivePath
    }
    else {
        $result.archive_path = ''
    }

    if (Test-Path -LiteralPath $archiveRoot) {
        $archiveCutoffUtc = $nowUtc.AddDays(-1 * [double]$ArchiveRetentionDays)
        $pattern = "ai_ticket_ledger_archive_{0}_*.jsonl" -f $StartToken
        foreach ($file in @(Get-ChildItem -LiteralPath $archiveRoot -Filter $pattern -File -ErrorAction SilentlyContinue)) {
            $fileUtc = [datetime]$file.LastWriteTimeUtc
            if ($fileUtc -lt $archiveCutoffUtc) {
                Remove-Item -LiteralPath $file.FullName -Force -ErrorAction SilentlyContinue
                $result.removed_archive_files = [int]$result.removed_archive_files + 1
            }
        }
    }

    return [pscustomobject]$result
}

function Remove-RowByTicketId {
    param(
        [System.Collections.Generic.List[object]]$Rows,
        [string]$TicketId
    )

    if ([string]::IsNullOrWhiteSpace($TicketId)) {
        return
    }

    for ($index = $Rows.Count - 1; $index -ge 0; $index--) {
        $rowTicketId = Convert-ToSingleLineText -Text ([string]$Rows[$index].ticket_id)
        if ($rowTicketId -eq $TicketId) {
            $Rows.RemoveAt($index)
        }
    }
}

function Get-StaleByBarrierReason {
    param(
        [AllowEmptyString()][string]$EventName,
        [AllowEmptyString()][string]$TicketBatchId,
        [AllowEmptyString()][string]$TicketCreatedAt,
        [AllowEmptyString()][string]$TicketRestartGeneration,
        [AllowEmptyString()][string]$LastBarrierBatchId,
        [AllowEmptyString()][string]$LastBarrierAt,
        [AllowEmptyString()][string]$LastBarrierRestartGeneration
    )

    $profile = Get-TicketEventProfile -EventName $EventName
    if (-not [bool]$profile.is_restart_sensitive) {
        return ''
    }

    $ticketGeneration = (Convert-ToSingleLineText -Text $TicketRestartGeneration).ToLowerInvariant()
    $barrierGeneration = (Convert-ToSingleLineText -Text $LastBarrierRestartGeneration).ToLowerInvariant()
    if ((-not [string]::IsNullOrWhiteSpace($ticketGeneration)) -and
        (-not [string]::IsNullOrWhiteSpace($barrierGeneration)) -and
        ($ticketGeneration -ne $barrierGeneration)) {
        return 'barrier-generation-stale'
    }

    if ([string]::IsNullOrWhiteSpace($TicketBatchId) -or [string]::IsNullOrWhiteSpace($LastBarrierBatchId)) {
        return ''
    }

    if ($TicketBatchId -ne $LastBarrierBatchId) {
        return ''
    }

    $ticketCreatedUtc = Get-DateTimeOrNull -Text $TicketCreatedAt
    $barrierAtUtc = Get-DateTimeOrNull -Text $LastBarrierAt
    if ($null -eq $ticketCreatedUtc -or $null -eq $barrierAtUtc) {
        return ''
    }

    if ($ticketCreatedUtc -le $barrierAtUtc) {
        return 'barrier-context-stale'
    }

    return ''
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
        return Resolve-RepoPath -Path $Path -MustExist $false
    }
    catch {
        return ''
    }
}

function Get-FallbackMonitoringState {
    param(
        [System.Collections.IDictionary]$Settings,
        [string]$StartFileRel
    )

        $sessionStatusRaw = ''
        if ($Settings.Contains('SESSION_FINAL_STATUS')) {
            $sessionStatusRaw = [string]$Settings.SESSION_FINAL_STATUS
        }
        $sessionStatus = Get-StatusValue -Value $sessionStatusRaw

        $aStatusRaw = ''
        if ($Settings.Contains('A_FINAL_STATUS')) {
            $aStatusRaw = [string]$Settings.A_FINAL_STATUS
        }
        $aStatus = Get-StatusValue -Value $aStatusRaw

        $bStatusRaw = ''
        if ($Settings.Contains('B_FINAL_STATUS')) {
            $bStatusRaw = [string]$Settings.B_FINAL_STATUS
        }
        $bStatus = Get-StatusValue -Value $bStatusRaw

    $notes = ''
    if ($Settings.Contains('SESSION_FINAL_NOTES')) {
        $notes = [string]$Settings.SESSION_FINAL_NOTES
    }
    $liveStatusAnchor = Get-LatestAnchorValueFromNotes -Notes $notes -Key 'live_status'
    $supervisorLogAnchor = Get-LatestAnchorValueFromNotes -Notes $notes -Key 'supervisor_log'
    $companionLogAnchor = Get-LatestAnchorValueFromNotes -Notes $notes -Key 'companion_log'
    $guardLogAnchor = Get-LatestAnchorValueFromNotes -Notes $notes -Key 'guard_log'

    $liveStatusPath = Resolve-AnchorPath -Path $liveStatusAnchor
    $supervisorLogPath = Resolve-AnchorPath -Path $supervisorLogAnchor
    $companionLogPath = Resolve-AnchorPath -Path $companionLogAnchor
    $guardLogPath = Resolve-AnchorPath -Path $guardLogAnchor

    $liveStatusRaw = Read-JsonFileSafely -Path $liveStatusPath
    $liveStatusState = ''
    $liveStatusEvent = ''
    $blockedEvidence = ''
    if ($null -ne $liveStatusRaw) {
        $liveStatusState = (Convert-ToSingleLineText -Text ([string](Get-ObjectPropertyString -InputObject $liveStatusRaw -Name 'status'))).ToLowerInvariant()
        $liveStatusEvent = (Convert-ToSingleLineText -Text ([string](Get-ObjectPropertyString -InputObject $liveStatusRaw -Name 'event'))).ToLowerInvariant()
        $blockedEvidence = Convert-ToSingleLineText -Text ([string](Get-ObjectPropertyString -InputObject $liveStatusRaw -Name 'blocked_evidence'))
    }

    $fallbackRequired = $false
    $fallbackReason = 'none'

    if ($sessionStatus -in @('FAIL', 'BLOCKED')) {
        $fallbackRequired = $true
        $fallbackReason = 'session-final-status'
    }

    if (-not $fallbackRequired -and $liveStatusState -in @('fail', 'blocked')) {
        $fallbackRequired = $true
        $fallbackReason = 'live-status-state'
    }

    if (-not $fallbackRequired -and $liveStatusEvent -in @('blocked_package', 'supervisor_error', 'd1_no_progress', 'post_d1_no_progress', 'stage_process_exit_no_final')) {
        $fallbackRequired = $true
        $fallbackReason = 'live-status-event'
    }

    $blockedEvidencePath = Resolve-AnchorPath -Path $blockedEvidence
    $blockedEvidenceRel = Convert-ToRepoRelativePath -Path $blockedEvidencePath

    $watchOnceCommand = 'powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/watch_ab_light.ps1 -StartFile "{0}" -Once -NoClear' -f $StartFileRel
    $resumeCommand = 'powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/open_unattended_ab_resume_window.ps1 -StartFile "{0}" -StartMonitors' -f $StartFileRel
    $continueWatchCommand = 'powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/open_unattended_ab_session_guard_window.ps1 -StartFile "{0}"' -f $StartFileRel

    $inspectEvidenceCommand = ''
    if (-not [string]::IsNullOrWhiteSpace($blockedEvidencePath) -and (Test-Path -LiteralPath $blockedEvidencePath)) {
        $summaryPath = Join-Path $blockedEvidencePath 'summary.txt'
        if (Test-Path -LiteralPath $summaryPath) {
            $summaryRel = Convert-ToRepoRelativePath -Path $summaryPath
            $inspectEvidenceCommand = 'powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-Content -LiteralPath ''{0}''"' -f $summaryRel
        }
    }

    return [pscustomobject]@{
        required = [bool]$fallbackRequired
        reason = $fallbackReason
        session_final_status = $sessionStatus
        a_final_status = $aStatus
        b_final_status = $bStatus
        live_status_state = $liveStatusState
        live_status_event = $liveStatusEvent
        live_status_path = (Convert-ToRepoRelativePath -Path $liveStatusPath)
        supervisor_log = (Convert-ToRepoRelativePath -Path $supervisorLogPath)
        companion_log = (Convert-ToRepoRelativePath -Path $companionLogPath)
        guard_log = (Convert-ToRepoRelativePath -Path $guardLogPath)
        blocked_evidence = $blockedEvidenceRel
        commands = [ordered]@{
            watch_once = $watchOnceCommand
            investigate = $inspectEvidenceCommand
            business_resume = $resumeCommand
            continue_watch = $continueWatchCommand
        }
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
    Set-Content -LiteralPath $Path -Value $json -Encoding utf8
}

function New-LedgerRecord {
    param(
        [string]$TicketId,
        [string]$EventName,
        [string]$Severity,
        [string]$CreatedAt,
        [string]$BatchId,
        [string]$RestartGeneration
    )

    $nowText = Get-NowText
    return [ordered]@{
        ticket_id = $TicketId
        status = 'new'
        event = $EventName
        severity = $Severity
        created_at = $CreatedAt
        claimed_at = ''
        executed_at = ''
        watch_resumed_at = ''
        done_at = ''
        failed_at = ''
        retry_count = 0
        next_retry_at = ''
        failure_reason = ''
        batch_id = $BatchId
        restart_generation = $RestartGeneration
        notes = ''
        status_history = @([ordered]@{ status = 'new'; at = $nowText; note = '' })
        last_updated_at = $nowText
    }
}

function Convert-ToLedgerRecord {
    param(
        [object]$InputRecord,
        [string]$FallbackTicketId
    )

    $ticketId = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $InputRecord -Name 'ticket_id')
    if ([string]::IsNullOrWhiteSpace($ticketId)) {
        $ticketId = $FallbackTicketId
    }

    $status = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $InputRecord -Name 'status')
    if ([string]::IsNullOrWhiteSpace($status)) {
        $status = 'new'
    }

    $retryCount = 0
    $retryRaw = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $InputRecord -Name 'retry_count')
    if (-not [string]::IsNullOrWhiteSpace($retryRaw)) {
        $parsedRetry = 0
        if ([int]::TryParse($retryRaw, [ref]$parsedRetry)) {
            $retryCount = $parsedRetry
        }
    }

    $historyItems = @()
    $rawHistory = $null
    if ($InputRecord -is [System.Collections.IDictionary]) {
        if ($InputRecord.Contains('status_history')) {
            $rawHistory = $InputRecord['status_history']
        }
    }
    elseif ($null -ne $InputRecord -and ($InputRecord.PSObject.Properties.Name -contains 'status_history')) {
        $rawHistory = $InputRecord.status_history
    }
    foreach ($entry in @($rawHistory)) {
        if ($null -eq $entry) {
            continue
        }

        $historyStatus = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $entry -Name 'status')
        if ([string]::IsNullOrWhiteSpace($historyStatus)) {
            continue
        }

        $historyAt = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $entry -Name 'at')
        if ([string]::IsNullOrWhiteSpace($historyAt)) {
            $historyAt = Get-NowText
        }

        $historyNote = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $entry -Name 'note')
        $historyItems += [ordered]@{
            status = $historyStatus
            at = $historyAt
            note = $historyNote
        }
    }

    if ($historyItems.Count -eq 0) {
        $historyItems = @([ordered]@{
                status = $status
                at = Get-NowText
                note = ''
            })
    }

    return [ordered]@{
        ticket_id = $ticketId
        status = $status
        event = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $InputRecord -Name 'event')
        severity = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $InputRecord -Name 'severity')
        created_at = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $InputRecord -Name 'created_at')
        claimed_at = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $InputRecord -Name 'claimed_at')
        executed_at = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $InputRecord -Name 'executed_at')
        watch_resumed_at = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $InputRecord -Name 'watch_resumed_at')
        done_at = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $InputRecord -Name 'done_at')
        failed_at = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $InputRecord -Name 'failed_at')
        retry_count = $retryCount
        next_retry_at = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $InputRecord -Name 'next_retry_at')
        failure_reason = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $InputRecord -Name 'failure_reason')
        batch_id = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $InputRecord -Name 'batch_id')
        restart_generation = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $InputRecord -Name 'restart_generation')
        notes = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $InputRecord -Name 'notes')
        status_history = @($historyItems)
        last_updated_at = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $InputRecord -Name 'last_updated_at')
    }
}

function Ensure-LedgerRecord {
    param(
        [hashtable]$LedgerRecords,
        [string]$TicketId,
        [string]$EventName,
        [string]$Severity,
        [string]$CreatedAt,
        [string]$BatchId,
        [string]$RestartGeneration
    )

    if (-not $LedgerRecords.ContainsKey($TicketId)) {
        $LedgerRecords[$TicketId] = New-LedgerRecord -TicketId $TicketId -EventName $EventName -Severity $Severity -CreatedAt $CreatedAt -BatchId $BatchId -RestartGeneration $RestartGeneration
        return
    }

    $record = Convert-ToLedgerRecord -InputRecord $LedgerRecords[$TicketId] -FallbackTicketId $TicketId
    if ([string]::IsNullOrWhiteSpace([string]$record.event)) {
        $record.event = $EventName
    }
    if ([string]::IsNullOrWhiteSpace([string]$record.severity)) {
        $record.severity = $Severity
    }
    if ([string]::IsNullOrWhiteSpace([string]$record.created_at)) {
        $record.created_at = $CreatedAt
    }
    if ([string]::IsNullOrWhiteSpace([string]$record.batch_id)) {
        $record.batch_id = $BatchId
    }
    if ([string]::IsNullOrWhiteSpace([string]$record.restart_generation)) {
        $record.restart_generation = $RestartGeneration
    }
    if ([string]::IsNullOrWhiteSpace([string]$record.last_updated_at)) {
        $record.last_updated_at = Get-NowText
    }

    $LedgerRecords[$TicketId] = $record
}

function Update-LedgerStatus {
    param(
        [hashtable]$LedgerRecords,
        [string]$TicketId,
        [string]$Status,
        [string]$At,
        [AllowEmptyString()][string]$Note = ''
    )

    if (-not $LedgerRecords.ContainsKey($TicketId)) {
        return
    }

    $record = Convert-ToLedgerRecord -InputRecord $LedgerRecords[$TicketId] -FallbackTicketId $TicketId
    if ([string]::IsNullOrWhiteSpace($At)) {
        $At = Get-NowText
    }

    if ([string]::IsNullOrWhiteSpace([string]$record.status) -or [string]$record.status -ne $Status) {
        $history = @($record.status_history)
        $history += [ordered]@{
            status = $Status
            at = $At
            note = (Convert-ToSingleLineText -Text $Note)
        }
        $record.status_history = $history
    }

    $record.status = $Status
    $record.last_updated_at = $At

    $cleanNote = Convert-ToSingleLineText -Text $Note
    if (-not [string]::IsNullOrWhiteSpace($cleanNote)) {
        if ([string]::IsNullOrWhiteSpace([string]$record.notes)) {
            $record.notes = $cleanNote
        }
        else {
            $record.notes = ([string]$record.notes + '; ' + $cleanNote)
        }
    }

    switch ($Status) {
        'claimed' {
            if ([string]::IsNullOrWhiteSpace([string]$record.claimed_at)) {
                $record.claimed_at = $At
            }
        }
        'executed' {
            if ([string]::IsNullOrWhiteSpace([string]$record.executed_at)) {
                $record.executed_at = $At
            }
        }
        'watch-resumed' {
            if ([string]::IsNullOrWhiteSpace([string]$record.watch_resumed_at)) {
                $record.watch_resumed_at = $At
            }
        }
        'done' {
            if ([string]::IsNullOrWhiteSpace([string]$record.done_at)) {
                $record.done_at = $At
            }
        }
        'failed' {
            if ([string]::IsNullOrWhiteSpace([string]$record.failed_at)) {
                $record.failed_at = $At
            }
        }
    }

    $LedgerRecords[$TicketId] = $record
}

function Set-LedgerDeferred {
    param(
        [hashtable]$LedgerRecords,
        [string]$TicketId,
        [string]$NowAt,
        [AllowEmptyString()][string]$Reason = ''
    )

    if (-not $LedgerRecords.ContainsKey($TicketId)) {
        return
    }

    if ([string]::IsNullOrWhiteSpace($NowAt)) {
        $NowAt = Get-NowText
    }

    Update-LedgerStatus -LedgerRecords $LedgerRecords -TicketId $TicketId -Status 'deferred' -At $NowAt -Note $Reason
    $record = Convert-ToLedgerRecord -InputRecord $LedgerRecords[$TicketId] -FallbackTicketId $TicketId
    $record.retry_count = [int]$record.retry_count + 1
    $record.next_retry_at = Get-NextRetryAtText -RetryCount ([int]$record.retry_count) -NowLocal (Get-Date)
    $LedgerRecords[$TicketId] = $record
}

function Clear-LedgerRetrySchedule {
    param(
        [hashtable]$LedgerRecords,
        [string]$TicketId
    )

    if (-not $LedgerRecords.ContainsKey($TicketId)) {
        return
    }

    $record = Convert-ToLedgerRecord -InputRecord $LedgerRecords[$TicketId] -FallbackTicketId $TicketId
    $record.next_retry_at = ''
    $LedgerRecords[$TicketId] = $record
}

function Get-LedgerStatusCounts {
    param([hashtable]$LedgerRecords)

    $counts = [ordered]@{}
    foreach ($ticketId in $LedgerRecords.Keys) {
        $record = $LedgerRecords[$ticketId]
        $statusName = Convert-ToSingleLineText -Text ([string]$record.status)
        if ([string]::IsNullOrWhiteSpace($statusName)) {
            $statusName = 'unknown'
        }

        if (-not $counts.Contains($statusName)) {
            $counts[$statusName] = 0
        }
        $counts[$statusName] = [int]$counts[$statusName] + 1
    }

    return $counts
}

function Get-TicketsFromQueue {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) {
        return @()
    }

    $tickets = New-Object 'System.Collections.Generic.List[object]'
    foreach ($line in @(Get-Content -LiteralPath $Path -Encoding utf8 -ErrorAction SilentlyContinue)) {
        $jsonLine = Convert-ToSingleLineText -Text ([string]$line)
        if ([string]::IsNullOrWhiteSpace($jsonLine)) {
            continue
        }

        try {
            $ticket = $jsonLine | ConvertFrom-Json -ErrorAction Stop
            [void]$tickets.Add($ticket)
        }
        catch {
            continue
        }
    }

    return $tickets.ToArray()
}

$script:RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$startFilePath = Resolve-RepoPath -Path $StartFile -MustExist $true
$startFileRel = Convert-ToRepoRelativePath -Path $startFilePath
$startToken = Get-SafeToken -Text ([System.IO.Path]::GetFileNameWithoutExtension($startFilePath).ToLowerInvariant())
$settings = Read-KeyValueFile -Path $startFilePath

$defaultStatusReportEvents = @('running-status-report')
$defaultDrainSafeEvents = @('running-status-report', 'manual-wait-paused', 'budget-exhausted-stop', 'known-infra-transient-stop')
$defaultBarrierEvents = @('incident-captured', 'recovery-await-confirmation', 'auto-fix-await-confirmation', 'manual-wait-paused', 'budget-exhausted-stop', 'known-infra-transient-stop')
$defaultRestartSensitiveEvents = @('incident-captured', 'recovery-await-confirmation', 'auto-fix-await-confirmation')
$coreRestartSensitiveEvents = @('incident-captured', 'recovery-await-confirmation', 'auto-fix-await-confirmation')
$eventPolicyAdjustments = New-Object 'System.Collections.Generic.List[string]'
$eventPolicyStrictModeValue = $EventPolicyStrict
if ($null -eq $eventPolicyStrictModeValue -and $settings.Contains('LOCAL_GUARD_POLL_EVENT_POLICY_STRICT')) {
    $eventPolicyStrictModeValue = [string]$settings.LOCAL_GUARD_POLL_EVENT_POLICY_STRICT
}
$eventPolicyStrictModeFlag = Convert-ToBooleanValue -Value $eventPolicyStrictModeValue -Default $false

$script:EventSetStatusReport = New-EventNameSet -Values (Get-ConfiguredEventNameList -Settings $settings -SettingKey 'LOCAL_GUARD_POLL_STATUS_REPORT_EVENTS' -Fallback $defaultStatusReportEvents)
$script:EventSetStatusReport = Ensure-EventSetNotEmpty -TargetSet $script:EventSetStatusReport -FallbackValues $defaultStatusReportEvents -Adjustments $eventPolicyAdjustments -AdjustmentTag 'status-report:fallback-defaults'
Ensure-EventSetContainsValues -TargetSet $script:EventSetStatusReport -RequiredValues @('running-status-report') -Adjustments $eventPolicyAdjustments -AdjustmentPrefix 'status-report:add-required-event'

$script:EventSetDrainSafe = New-EventNameSet -Values (Get-ConfiguredEventNameList -Settings $settings -SettingKey 'LOCAL_GUARD_POLL_DRAIN_SAFE_EVENTS' -Fallback $defaultDrainSafeEvents)
$script:EventSetDrainSafe = Ensure-EventSetNotEmpty -TargetSet $script:EventSetDrainSafe -FallbackValues $defaultDrainSafeEvents -Adjustments $eventPolicyAdjustments -AdjustmentTag 'drain-safe:fallback-defaults'
Ensure-EventSetContainsValues -TargetSet $script:EventSetDrainSafe -RequiredValues @($script:EventSetStatusReport.Keys) -Adjustments $eventPolicyAdjustments -AdjustmentPrefix 'drain-safe:add-status-report-event'

$script:EventSetBarrier = New-EventNameSet -Values (Get-ConfiguredEventNameList -Settings $settings -SettingKey 'LOCAL_GUARD_POLL_BARRIER_EVENTS' -Fallback $defaultBarrierEvents)
$script:EventSetBarrier = Ensure-EventSetNotEmpty -TargetSet $script:EventSetBarrier -FallbackValues $defaultBarrierEvents -Adjustments $eventPolicyAdjustments -AdjustmentTag 'barrier:fallback-defaults'
if (-not (Test-EventSetIntersects -TargetSet $script:EventSetBarrier -CandidateValues $coreRestartSensitiveEvents)) {
    Ensure-EventSetContainsValues -TargetSet $script:EventSetBarrier -RequiredValues $coreRestartSensitiveEvents -Adjustments $eventPolicyAdjustments -AdjustmentPrefix 'barrier:add-core-restart-event'
}

$script:EventSetRestartSensitive = New-EventNameSet -Values (Get-ConfiguredEventNameList -Settings $settings -SettingKey 'LOCAL_GUARD_POLL_RESTART_SENSITIVE_EVENTS' -Fallback $defaultRestartSensitiveEvents)
$script:EventSetRestartSensitive = Ensure-EventSetNotEmpty -TargetSet $script:EventSetRestartSensitive -FallbackValues $defaultRestartSensitiveEvents -Adjustments $eventPolicyAdjustments -AdjustmentTag 'restart-sensitive:fallback-defaults'
if (-not (Test-EventSetIntersects -TargetSet $script:EventSetRestartSensitive -CandidateValues $coreRestartSensitiveEvents)) {
    Ensure-EventSetContainsValues -TargetSet $script:EventSetRestartSensitive -RequiredValues $coreRestartSensitiveEvents -Adjustments $eventPolicyAdjustments -AdjustmentPrefix 'restart-sensitive:add-core-restart-event'
}

if ($eventPolicyStrictModeFlag -and $eventPolicyAdjustments.Count -gt 0) {
    $adjustmentText = ($eventPolicyAdjustments.ToArray() -join ',')
    throw ('Event policy strict mode violation: normalization is required ({0}). Please fix LOCAL_GUARD_POLL_* settings in start file.' -f $adjustmentText)
}

$markProcessedFlag = Convert-ToBooleanValue -Value $MarkProcessed -Default $false
$enableFallbackStatusFlag = Convert-ToBooleanValue -Value $EnableFallbackStatus -Default $true
$enableLedgerCompactionFlag = Convert-ToBooleanValue -Value $EnableLedgerCompaction -Default $false

$fallbackMonitoring = $null
if ($enableFallbackStatusFlag) {
    $fallbackMonitoring = Get-FallbackMonitoringState -Settings $settings -StartFileRel $startFileRel
}

$queuePathValue = $QueuePath
if ([string]::IsNullOrWhiteSpace($queuePathValue) -and $settings.Contains('LOCAL_GUARD_AGENT_QUEUE_PATH')) {
    $queuePathValue = Normalize-PathLikeValue -Value ([string]$settings.LOCAL_GUARD_AGENT_QUEUE_PATH)
}
if ([string]::IsNullOrWhiteSpace($queuePathValue)) {
    $queuePathValue = 'out\artifacts\ab_agent_queue\agent_tickets.jsonl'
}
$queueFilePath = Resolve-RepoPathAllowMissing -Path $queuePathValue

$statePathValue = $StatePath
if ([string]::IsNullOrWhiteSpace($statePathValue)) {
    $statePathValue = Join-Path 'out\artifacts\ab_agent_queue' ("ai_ticket_poll_state_{0}.json" -f $startToken)
}
$stateFilePath = Resolve-RepoPathAllowMissing -Path $statePathValue

$ledgerPathValue = $LedgerPath
if ([string]::IsNullOrWhiteSpace($ledgerPathValue)) {
    $ledgerPathValue = Join-Path 'out\artifacts\ab_agent_queue' ("ai_ticket_ledger_{0}.json" -f $startToken)
}
$ledgerFilePath = Resolve-RepoPathAllowMissing -Path $ledgerPathValue

$stateRaw = Read-JsonFileSafely -Path $stateFilePath
$processedIds = New-Object 'System.Collections.Generic.List[string]'
$processedSet = @{}
$recoveryDrainPending = $false
$lastDrainAt = ''
$lastRecoveryDrainAt = ''
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
if ($null -ne $stateRaw) {
    $recoveryDrainPending = Convert-ToBooleanValue -Value (Get-ObjectPropertyString -InputObject $stateRaw -Name 'recovery_drain_pending') -Default $false
    $lastDrainAt = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $stateRaw -Name 'last_drain_at')
    $lastRecoveryDrainAt = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $stateRaw -Name 'last_recovery_drain_at')
}

$drainModeInfo = Get-DrainMode -FallbackMonitoring $fallbackMonitoring -RecoveryDrainPending $recoveryDrainPending
$drainMode = Convert-ToSingleLineText -Text ([string]$drainModeInfo.mode)
$drainReason = Convert-ToSingleLineText -Text ([string]$drainModeInfo.reason)
$isDrainMode = $drainMode -in @('drain-pass', 'recovery-drain')

$ledgerRaw = Read-JsonFileSafely -Path $ledgerFilePath
$ledgerRecords = @{}
$lastBarrierTicketId = ''
$lastBarrierAt = ''
$lastBarrierBatchId = ''
$lastBarrierRestartGeneration = ''
if ($null -ne $ledgerRaw -and $ledgerRaw.PSObject.Properties.Name -contains 'records') {
    foreach ($entry in @($ledgerRaw.records)) {
        $ticketId = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $entry -Name 'ticket_id')
        if ([string]::IsNullOrWhiteSpace($ticketId)) {
            continue
        }

        $ledgerRecords[$ticketId] = Convert-ToLedgerRecord -InputRecord $entry -FallbackTicketId $ticketId
    }
}
if ($null -ne $ledgerRaw) {
    $lastBarrierTicketId = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $ledgerRaw -Name 'last_barrier_ticket_id')
    $lastBarrierAt = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $ledgerRaw -Name 'last_barrier_at')
    $lastBarrierBatchId = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $ledgerRaw -Name 'last_barrier_batch_id')
    $lastBarrierRestartGeneration = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $ledgerRaw -Name 'last_barrier_restart_generation')
}

$acknowledgeTicketSet = @{}
foreach ($ticketId in @(Get-NormalizedListValues -Value $AcknowledgeTicketIds)) {
    if (-not $acknowledgeTicketSet.Contains($ticketId)) {
        $acknowledgeTicketSet[$ticketId] = $true
    }
}

$acknowledgedThisPoll = 0
if ($acknowledgeTicketSet.Count -gt 0) {
    foreach ($ticketId in @($acknowledgeTicketSet.Keys)) {
        if (-not $ledgerRecords.ContainsKey($ticketId)) {
            continue
        }

        $record = Convert-ToLedgerRecord -InputRecord $ledgerRecords[$ticketId] -FallbackTicketId $ticketId
        $statusName = Convert-ToSingleLineText -Text ([string]$record.status)
        if ($statusName -in @('done', 'failed', 'stale_by_restart', 'stale_status_superseded')) {
            continue
        }

        $ackAt = Get-NowText
        Update-LedgerStatus -LedgerRecords $ledgerRecords -TicketId $ticketId -Status 'executed' -At $ackAt -Note 'acknowledged-by-consumer'
        Update-LedgerStatus -LedgerRecords $ledgerRecords -TicketId $ticketId -Status 'watch-resumed' -At $ackAt -Note 'acknowledged-by-consumer'
        Update-LedgerStatus -LedgerRecords $ledgerRecords -TicketId $ticketId -Status 'done' -At $ackAt -Note 'acknowledged-by-consumer'
        Clear-LedgerRetrySchedule -LedgerRecords $ledgerRecords -TicketId $ticketId

        if (Test-IsBarrierEvent -EventName ([string]$record.event)) {
            $barrierRecord = Convert-ToLedgerRecord -InputRecord $ledgerRecords[$ticketId] -FallbackTicketId $ticketId
            $lastBarrierTicketId = $ticketId
            $lastBarrierAt = $ackAt
            $lastBarrierBatchId = Convert-ToSingleLineText -Text ([string]$barrierRecord.batch_id)
            $lastBarrierRestartGeneration = Convert-ToSingleLineText -Text ([string]$barrierRecord.restart_generation)
        }

        if (-not $processedSet.Contains($ticketId)) {
            $processedSet[$ticketId] = $true
            [void]$processedIds.Add($ticketId)
        }

        $acknowledgedThisPoll++
        $doneThisPoll++
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
}

$businessCommand = 'powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/open_unattended_ab_resume_window.ps1 -StartFile "{0}" -StartMonitors' -f $startFileRel
$continueWatchCommand = 'powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/open_unattended_ab_session_guard_window.ps1 -StartFile "{0}"' -f $startFileRel

$tickets = @(Get-TicketsFromQueue -Path $queueFilePath)
$rows = New-Object 'System.Collections.Generic.List[object]'
$claimedIds = New-Object 'System.Collections.Generic.List[string]'
$skippedStatusReports = 0
$doneThisPoll = 0
$deferredThisPoll = 0
$staleByRestartThisPoll = 0
$statusSupersededThisPoll = 0
$actionBudgetUsed = $false
$selectedActionTicketId = ''
$selectedBarrierTicketId = ''
$selectedBarrierBatchId = ''
$latestStatusTicketId = ''

foreach ($ticket in $tickets) {
    $ticketId = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $ticket -Name 'ticket_id')
    if ([string]::IsNullOrWhiteSpace($ticketId)) {
        continue
    }

    $eventName = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $ticket -Name 'event')
    $createdAt = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $ticket -Name 'created_at')
    $severity = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $ticket -Name 'severity')
    $batchId = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $ticket -Name 'batch_id')
    if ([string]::IsNullOrWhiteSpace($batchId)) {
        $batchId = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $ticket -Name 'dedup_suffix')
    }
    $restartGeneration = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $ticket -Name 'restart_generation')

    $eventProfile = Get-TicketEventProfile -EventName $eventName
    $isStatusReport = [bool]$eventProfile.is_status_report
    $isDrainSafeEvent = [bool]$eventProfile.is_drain_safe

    Ensure-LedgerRecord -LedgerRecords $ledgerRecords -TicketId $ticketId -EventName $eventName -Severity $severity -CreatedAt $createdAt -BatchId $batchId -RestartGeneration $restartGeneration
    $ledgerRecord = $ledgerRecords[$ticketId]
    $currentStatus = Convert-ToSingleLineText -Text ([string]$ledgerRecord.status)

    if ($processedSet.Contains($ticketId)) {
        if ([string]$ledgerRecord.status -ne 'done') {
            Update-LedgerStatus -LedgerRecords $ledgerRecords -TicketId $ticketId -Status 'done' -At (Get-NowText) -Note 'legacy-processed-id-skip'
            Clear-LedgerRetrySchedule -LedgerRecords $ledgerRecords -TicketId $ticketId
        }
        continue
    }

    if ($currentStatus -in @('done', 'failed', 'stale_by_restart', 'stale_status_superseded')) {
        continue
    }

    $staleReason = Get-StaleByBarrierReason -EventName $eventName -TicketBatchId $batchId -TicketCreatedAt $createdAt -TicketRestartGeneration $restartGeneration -LastBarrierBatchId $lastBarrierBatchId -LastBarrierAt $lastBarrierAt -LastBarrierRestartGeneration $lastBarrierRestartGeneration
    if (-not [string]::IsNullOrWhiteSpace($staleReason)) {
        Update-LedgerStatus -LedgerRecords $ledgerRecords -TicketId $ticketId -Status 'stale_by_restart' -At (Get-NowText) -Note $staleReason
        Clear-LedgerRetrySchedule -LedgerRecords $ledgerRecords -TicketId $ticketId
        $staleByRestartThisPoll++
        continue
    }

    if ($currentStatus -eq 'deferred') {
        $nextRetryAt = Convert-ToSingleLineText -Text ([string]$ledgerRecord.next_retry_at)
        if (-not (Test-IsRetryDue -NextRetryAt $nextRetryAt)) {
            continue
        }
    }

    if (-not $IncludeStatusReports.IsPresent -and $isStatusReport) {
        $skippedStatusReports++
        continue
    }

    if ($isDrainMode -and $isDrainSafeEvent -and -not $isStatusReport) {
        $requiresConfirmation = Get-ObjectPropertyBoolean -InputObject $ticket -Name 'requires_confirmation' -Default $false
        $detail = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $ticket -Name 'detail')
        $recommendedAction = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $ticket -Name 'recommended_action')
        $queueRel = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $ticket -Name 'queue_path')

        Update-LedgerStatus -LedgerRecords $ledgerRecords -TicketId $ticketId -Status 'claimed' -At (Get-NowText) -Note 'selected-drain-safe-event'
        Clear-LedgerRetrySchedule -LedgerRecords $ledgerRecords -TicketId $ticketId

        Remove-RowByTicketId -Rows $rows -TicketId $ticketId
        $rows.Add([pscustomobject]@{
                ticket_id = $ticketId
                event = $eventName
                created_at = $createdAt
                severity = $severity
            requires_confirmation = $requiresConfirmation
            detail = $detail
            recommended_action = $recommendedAction
            queue_path = $queueRel
                business_command = ''
                continue_watch_command = $continueWatchCommand
                mark_processed_command = (Get-MarkProcessedCommand -StartFileRel $startFileRel -TicketId $ticketId -Last $Last)
            }) | Out-Null

        if (-not $claimedIds.Contains($ticketId)) {
            [void]$claimedIds.Add($ticketId)
        }
        continue
    }

    if ($isDrainMode -and -not $isDrainSafeEvent) {
        $drainDeferReason = if ($drainMode -eq 'recovery-drain') { 'recovery_drain_guard' } else { 'drain_guard' }
        Set-LedgerDeferred -LedgerRecords $ledgerRecords -TicketId $ticketId -NowAt (Get-NowText) -Reason $drainDeferReason
        $deferredThisPoll++
        continue
    }

    $requiresConfirmation = Get-ObjectPropertyBoolean -InputObject $ticket -Name 'requires_confirmation' -Default $false
    $detail = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $ticket -Name 'detail')
    $recommendedAction = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $ticket -Name 'recommended_action')
    $queueRel = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $ticket -Name 'queue_path')

    if ($isStatusReport) {
        if (-not [string]::IsNullOrWhiteSpace($latestStatusTicketId) -and $latestStatusTicketId -ne $ticketId) {
            Update-LedgerStatus -LedgerRecords $ledgerRecords -TicketId $latestStatusTicketId -Status 'stale_status_superseded' -At (Get-NowText) -Note 'newer-running-status-report'
            Clear-LedgerRetrySchedule -LedgerRecords $ledgerRecords -TicketId $latestStatusTicketId
            Remove-RowByTicketId -Rows $rows -TicketId $latestStatusTicketId
            $statusSupersededThisPoll++
        }

        Update-LedgerStatus -LedgerRecords $ledgerRecords -TicketId $ticketId -Status 'claimed' -At (Get-NowText) -Note 'selected-latest-status-report'
        Clear-LedgerRetrySchedule -LedgerRecords $ledgerRecords -TicketId $ticketId
        $latestStatusTicketId = $ticketId

        Remove-RowByTicketId -Rows $rows -TicketId $ticketId
        $rows.Add([pscustomobject]@{
                ticket_id = $ticketId
                event = $eventName
                created_at = $createdAt
                severity = $severity
                requires_confirmation = $requiresConfirmation
                detail = $detail
                recommended_action = $recommendedAction
                queue_path = $queueRel
                business_command = ''
                continue_watch_command = $continueWatchCommand
            mark_processed_command = (Get-MarkProcessedCommand -StartFileRel $startFileRel -TicketId $ticketId -Last $Last)
            }) | Out-Null

        if (-not $claimedIds.Contains($ticketId)) {
            [void]$claimedIds.Add($ticketId)
        }
        continue
    }

    if ($actionBudgetUsed) {
        $deferReason = 'action_budget'
        if (-not [string]::IsNullOrWhiteSpace($selectedBarrierBatchId) -and -not [string]::IsNullOrWhiteSpace($batchId) -and $batchId -eq $selectedBarrierBatchId) {
            $deferReason = 'restart_barrier'
        }

        Set-LedgerDeferred -LedgerRecords $ledgerRecords -TicketId $ticketId -NowAt (Get-NowText) -Reason $deferReason
        $deferredThisPoll++
        continue
    }

    $actionBudgetUsed = $true
    $selectedActionTicketId = $ticketId
    if (Test-IsBarrierEvent -EventName $eventName) {
        $selectedBarrierTicketId = $ticketId
        $selectedBarrierBatchId = $batchId
    }

    Update-LedgerStatus -LedgerRecords $ledgerRecords -TicketId $ticketId -Status 'claimed' -At (Get-NowText) -Note 'selected-by-poller'
    Clear-LedgerRetrySchedule -LedgerRecords $ledgerRecords -TicketId $ticketId

    Remove-RowByTicketId -Rows $rows -TicketId $ticketId

    $rows.Add([pscustomobject]@{
            ticket_id = $ticketId
            event = $eventName
            created_at = $createdAt
            severity = $severity
            requires_confirmation = $requiresConfirmation
            detail = $detail
            recommended_action = $recommendedAction
            queue_path = $queueRel
            business_command = $businessCommand
            continue_watch_command = $continueWatchCommand
            mark_processed_command = (Get-MarkProcessedCommand -StartFileRel $startFileRel -TicketId $ticketId -Last $Last)
        }) | Out-Null
    if (-not $claimedIds.Contains($ticketId)) {
        [void]$claimedIds.Add($ticketId)
    }
}

if ($markProcessedFlag -and $claimedIds.Count -gt 0) {
    foreach ($ticketId in @($claimedIds)) {
        if ($processedSet.Contains($ticketId)) {
            continue
        }

        $finalizeAt = Get-NowText
        Update-LedgerStatus -LedgerRecords $ledgerRecords -TicketId $ticketId -Status 'executed' -At $finalizeAt -Note 'mark-processed'
        Update-LedgerStatus -LedgerRecords $ledgerRecords -TicketId $ticketId -Status 'watch-resumed' -At $finalizeAt -Note 'mark-processed'
        Update-LedgerStatus -LedgerRecords $ledgerRecords -TicketId $ticketId -Status 'done' -At $finalizeAt -Note 'mark-processed'
        Clear-LedgerRetrySchedule -LedgerRecords $ledgerRecords -TicketId $ticketId

        if ($ticketId -eq $selectedBarrierTicketId) {
            $barrierRecord = Convert-ToLedgerRecord -InputRecord $ledgerRecords[$ticketId] -FallbackTicketId $ticketId
            $lastBarrierTicketId = $ticketId
            $lastBarrierAt = $finalizeAt
            $lastBarrierBatchId = Convert-ToSingleLineText -Text ([string]$barrierRecord.batch_id)
            $lastBarrierRestartGeneration = Convert-ToSingleLineText -Text ([string]$barrierRecord.restart_generation)
        }

        $processedSet[$ticketId] = $true
        [void]$processedIds.Add($ticketId)
        $doneThisPoll++
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

}

$stateRecoveryDrainPending = $recoveryDrainPending
if ($drainMode -eq 'drain-pass') {
    $stateRecoveryDrainPending = $true
    $lastDrainAt = Get-NowText
}
elseif ($drainMode -eq 'recovery-drain') {
    $stateRecoveryDrainPending = $false
    $lastRecoveryDrainAt = Get-NowText
}

$state = [ordered]@{
    schema = 'AB_AI_TICKET_POLL_STATE_V1'
    updated_at = (Get-NowText)
    start_file = $startFileRel
    queue_path = (Convert-ToRepoRelativePath -Path $queueFilePath)
    processed_ids = @($processedIds)
    recovery_drain_pending = [bool]$stateRecoveryDrainPending
    last_drain_at = $lastDrainAt
    last_recovery_drain_at = $lastRecoveryDrainAt
    drain_mode = $drainMode
    drain_reason = $drainReason
}
Write-JsonFileSafely -Path $stateFilePath -Value $state

$compactionResult = Invoke-LedgerCompaction -LedgerRecords $ledgerRecords -RepoRoot $script:RepoRoot -StartToken $startToken -Enabled $enableLedgerCompactionFlag -CompactionDays $LedgerCompactionDays -ArchiveRetentionDays $LedgerArchiveRetentionDays

$ledgerRecordList = New-Object 'System.Collections.Generic.List[object]'
foreach ($ticketId in @($ledgerRecords.Keys | Sort-Object)) {
    [void]$ledgerRecordList.Add($ledgerRecords[$ticketId])
}

$ledgerState = [ordered]@{
    schema = 'AB_AI_TICKET_LEDGER_V2'
    updated_at = (Get-NowText)
    start_file = $startFileRel
    queue_path = (Convert-ToRepoRelativePath -Path $queueFilePath)
    state_path = (Convert-ToRepoRelativePath -Path $stateFilePath)
    last_barrier_ticket_id = $lastBarrierTicketId
    last_barrier_at = $lastBarrierAt
    last_barrier_batch_id = $lastBarrierBatchId
    last_barrier_restart_generation = $lastBarrierRestartGeneration
    records = @($ledgerRecordList.ToArray())
}
Write-JsonFileSafely -Path $ledgerFilePath -Value $ledgerState

$ledgerStatusCounts = Get-LedgerStatusCounts -LedgerRecords $ledgerRecords

$rowsOutput = $rows.ToArray()
$output = [ordered]@{
    schema = 'AB_AGENT_TICKET_POLL_V1'
    generated_at = (Get-NowText)
    start_file = $startFileRel
    queue_path = (Convert-ToRepoRelativePath -Path $queueFilePath)
    state_path = (Convert-ToRepoRelativePath -Path $stateFilePath)
    ledger_path = (Convert-ToRepoRelativePath -Path $ledgerFilePath)
    ledger_schema = 'AB_AI_TICKET_LEDGER_V2'
    mark_processed = [bool]$markProcessedFlag
    drain_mode = $drainMode
    drain_reason = $drainReason
    recovery_drain_pending = [bool]$stateRecoveryDrainPending
    include_status_reports = [bool]$IncludeStatusReports.IsPresent
    skipped_running_status_reports = $skippedStatusReports
    acknowledged_this_poll = $acknowledgedThisPoll
    claimed_this_poll = $claimedIds.Count
    done_this_poll = $doneThisPoll
    deferred_this_poll = $deferredThisPoll
    stale_by_restart_this_poll = $staleByRestartThisPoll
    status_superseded_this_poll = $statusSupersededThisPoll
    selected_action_ticket_id = $selectedActionTicketId
    selected_barrier_ticket_id = $selectedBarrierTicketId
    last_barrier_ticket_id = $lastBarrierTicketId
    last_barrier_at = $lastBarrierAt
    event_policy = [ordered]@{
        strict_mode = [bool]$eventPolicyStrictModeFlag
        status_report_events = @($script:EventSetStatusReport.Keys | Sort-Object)
        drain_safe_events = @($script:EventSetDrainSafe.Keys | Sort-Object)
        barrier_events = @($script:EventSetBarrier.Keys | Sort-Object)
        restart_sensitive_events = @($script:EventSetRestartSensitive.Keys | Sort-Object)
        adjustments = @($eventPolicyAdjustments.ToArray())
    }
    compaction = $compactionResult
    ledger_status_counts = $ledgerStatusCounts
    fallback_monitoring = $fallbackMonitoring
    rows = $rowsOutput
    rescan_commands = [ordered]@{
        every_5m = ('powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/poll_agent_tickets.ps1 -StartFile "{0}" -Last {1} -AsJson' -f $startFileRel, $Last)
        every_10m = ('powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/poll_agent_tickets.ps1 -StartFile "{0}" -Last {1} -AsJson' -f $startFileRel, $Last)
        acknowledge_template = ('powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/poll_agent_tickets.ps1 -StartFile "{0}" -AcknowledgeTicketIds "<ticket-id>" -Last {1} -AsJson' -f $startFileRel, $Last)
    }
}

if ($AsJson.IsPresent) {
    $output | ConvertTo-Json -Depth 8
}
else {
    Write-Output ('[AB-TICKET-POLL] generated_at={0} start_file={1}' -f $output.generated_at, $output.start_file)
    Write-Output ('[AB-TICKET-POLL] queue={0} state={1}' -f $output.queue_path, $output.state_path)
    Write-Output ('[AB-TICKET-POLL] ledger={0} schema={1}' -f $output.ledger_path, $output.ledger_schema)
    Write-Output ('[AB-TICKET-POLL] drain_mode={0} drain_reason={1} recovery_drain_pending={2}' -f [string]$output.drain_mode, [string]$output.drain_reason, [bool]$output.recovery_drain_pending)
    Write-Output ('[AB-TICKET-POLL] rows={0} skipped_running_status_reports={1} mark_processed={2} acknowledged_this_poll={3}' -f $rows.Count, $skippedStatusReports, [bool]$markProcessedFlag, [int]$output.acknowledged_this_poll)
    Write-Output ('[AB-TICKET-POLL] claimed_this_poll={0} done_this_poll={1}' -f [int]$output.claimed_this_poll, [int]$output.done_this_poll)
    Write-Output ('[AB-TICKET-POLL] deferred_this_poll={0} stale_by_restart_this_poll={1} status_superseded_this_poll={2}' -f [int]$output.deferred_this_poll, [int]$output.stale_by_restart_this_poll, [int]$output.status_superseded_this_poll)
    Write-Output ('[AB-TICKET-POLL] selected_action_ticket={0} selected_barrier_ticket={1} last_barrier_ticket={2} last_barrier_at={3}' -f [string]$output.selected_action_ticket_id, [string]$output.selected_barrier_ticket_id, [string]$output.last_barrier_ticket_id, [string]$output.last_barrier_at)
    Write-Output ('[AB-TICKET-POLL] event_policy_strict_mode={0}' -f [bool]$output.event_policy.strict_mode)
    Write-Output ('[AB-TICKET-POLL] event_policy status_report={0} drain_safe={1} barrier={2} restart_sensitive={3}' -f (($output.event_policy.status_report_events -join ',')), (($output.event_policy.drain_safe_events -join ',')), (($output.event_policy.barrier_events -join ',')), (($output.event_policy.restart_sensitive_events -join ',')))
    Write-Output ('[AB-TICKET-POLL] event_policy_adjustments={0}' -f (($output.event_policy.adjustments -join ',')))
    Write-Output ('[AB-TICKET-POLL] compaction_enabled={0} archived={1} removed={2} archive_path={3} removed_archive_files={4}' -f [bool]$output.compaction.enabled, [int]$output.compaction.archived, [int]$output.compaction.removed, [string]$output.compaction.archive_path, [int]$output.compaction.removed_archive_files)
    if ($null -ne $fallbackMonitoring) {
        Write-Output ('[AB-TICKET-POLL] fallback_required={0} reason={1} session={2} a={3} b={4} live_status_state={5} live_status_event={6}' -f
            [bool]$fallbackMonitoring.required,
            [string]$fallbackMonitoring.reason,
            [string]$fallbackMonitoring.session_final_status,
            [string]$fallbackMonitoring.a_final_status,
            [string]$fallbackMonitoring.b_final_status,
            [string]$fallbackMonitoring.live_status_state,
            [string]$fallbackMonitoring.live_status_event)
    }

    if ($rows.Count -eq 0) {
        Write-Output '[AB-TICKET-POLL] no_pending_rows'
        if ($null -ne $fallbackMonitoring -and [bool]$fallbackMonitoring.required) {
            Write-Output '[AB-TICKET-POLL] no_ticket_fallback_actions:'
            Write-Output ('  watch_once_command={0}' -f [string]$fallbackMonitoring.commands.watch_once)
            if (-not [string]::IsNullOrWhiteSpace([string]$fallbackMonitoring.commands.investigate)) {
                Write-Output ('  investigate_command={0}' -f [string]$fallbackMonitoring.commands.investigate)
            }
            Write-Output ('  business_command={0}' -f [string]$fallbackMonitoring.commands.business_resume)
            Write-Output ('  continue_watch_command={0}' -f [string]$fallbackMonitoring.commands.continue_watch)
        }
    }
    else {
        $rows | Select-Object ticket_id, event, severity, requires_confirmation, created_at |
            Format-Table -AutoSize | Out-String | Write-Output

        foreach ($row in $rows) {
            Write-Output ('[AB-TICKET-POLL] ticket={0} event={1}' -f [string]$row.ticket_id, [string]$row.event)
            Write-Output ('  business_command={0}' -f [string]$row.business_command)
            Write-Output ('  continue_watch_command={0}' -f [string]$row.continue_watch_command)
            Write-Output ('  mark_processed_command={0}' -f [string]$row.mark_processed_command)
        }
    }
}
