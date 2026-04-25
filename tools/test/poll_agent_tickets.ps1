param(
    [Parameter(Mandatory = $true)][string]$StartFile,
    [AllowEmptyString()][string]$QueuePath = '',
    [AllowEmptyString()][string]$StatePath = '',
    [ValidateRange(1, 200)][int]$Last = 20,
    [ValidateRange(0, 200000)][int]$MaxProcessedIds = 200000,
    [switch]$IncludeStatusReports,
    [bool]$MarkProcessed = $false,
    [bool]$EnableFallbackStatus = $true,
    [switch]$AsJson
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Resolve-RepoPath {
    param(
        [string]$Path,
        [bool]$MustExist = $true
    )

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

$fallbackMonitoring = $null
if ($EnableFallbackStatus) {
    $fallbackMonitoring = Get-FallbackMonitoringState -Settings $settings -StartFileRel $startFileRel
}

$queuePathValue = $QueuePath
if ([string]::IsNullOrWhiteSpace($queuePathValue) -and $settings.Contains('LOCAL_GUARD_AGENT_QUEUE_PATH')) {
    $queuePathValue = [string]$settings.LOCAL_GUARD_AGENT_QUEUE_PATH
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

$stateRaw = Read-JsonFileSafely -Path $stateFilePath
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

$businessCommand = 'powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/open_unattended_ab_resume_window.ps1 -StartFile "{0}" -StartMonitors' -f $startFileRel
$continueWatchCommand = 'powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/open_unattended_ab_session_guard_window.ps1 -StartFile "{0}"' -f $startFileRel

$tickets = @(Get-TicketsFromQueue -Path $queueFilePath)
$rows = New-Object 'System.Collections.Generic.List[object]'
$claimedIds = New-Object 'System.Collections.Generic.List[string]'
$skippedStatusReports = 0

foreach ($ticket in $tickets) {
    $ticketId = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $ticket -Name 'ticket_id')
    if ([string]::IsNullOrWhiteSpace($ticketId)) {
        continue
    }

    if ($processedSet.Contains($ticketId)) {
        continue
    }

    $eventName = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $ticket -Name 'event')
    if (-not $IncludeStatusReports.IsPresent -and $eventName -eq 'running-status-report') {
        $skippedStatusReports++
        continue
    }

    $createdAt = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $ticket -Name 'created_at')
    $severity = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $ticket -Name 'severity')
    $requiresConfirmation = Get-ObjectPropertyBoolean -InputObject $ticket -Name 'requires_confirmation' -Default $false
    $detail = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $ticket -Name 'detail')
    $recommendedAction = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $ticket -Name 'recommended_action')
    $queueRel = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $ticket -Name 'queue_path')

    $ticketBusinessCommand = ''
    if ($eventName -ne 'running-status-report') {
        $ticketBusinessCommand = $businessCommand
    }

    $rows.Add([pscustomobject]@{
            ticket_id = $ticketId
            event = $eventName
            created_at = $createdAt
            severity = $severity
            requires_confirmation = $requiresConfirmation
            detail = $detail
            recommended_action = $recommendedAction
            queue_path = $queueRel
            business_command = $ticketBusinessCommand
            continue_watch_command = $continueWatchCommand
        }) | Out-Null
    [void]$claimedIds.Add($ticketId)

    if ($rows.Count -ge $Last) {
        break
    }
}

if ($MarkProcessed -and $claimedIds.Count -gt 0) {
    foreach ($ticketId in @($claimedIds)) {
        if ($processedSet.Contains($ticketId)) {
            continue
        }

        $processedSet[$ticketId] = $true
        [void]$processedIds.Add($ticketId)
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
        schema = 'AB_AI_TICKET_POLL_STATE_V1'
        updated_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        start_file = $startFileRel
        queue_path = (Convert-ToRepoRelativePath -Path $queueFilePath)
        processed_ids = @($processedIds)
    }
    Write-JsonFileSafely -Path $stateFilePath -Value $state
}

$rowsOutput = $rows.ToArray()
$output = [ordered]@{
    schema = 'AB_AGENT_TICKET_POLL_V1'
    generated_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    start_file = $startFileRel
    queue_path = (Convert-ToRepoRelativePath -Path $queueFilePath)
    state_path = (Convert-ToRepoRelativePath -Path $stateFilePath)
    mark_processed = [bool]$MarkProcessed
    include_status_reports = [bool]$IncludeStatusReports.IsPresent
    skipped_running_status_reports = $skippedStatusReports
    fallback_monitoring = $fallbackMonitoring
    rows = $rowsOutput
    rescan_commands = [ordered]@{
        every_5m = ('powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/poll_agent_tickets.ps1 -StartFile "{0}" -Last {1} -AsJson' -f $startFileRel, $Last)
        every_10m = ('powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/poll_agent_tickets.ps1 -StartFile "{0}" -Last {1} -AsJson' -f $startFileRel, $Last)
    }
}

if ($AsJson.IsPresent) {
    $output | ConvertTo-Json -Depth 8
}
else {
    Write-Output ('[AB-TICKET-POLL] generated_at={0} start_file={1}' -f $output.generated_at, $output.start_file)
    Write-Output ('[AB-TICKET-POLL] queue={0} state={1}' -f $output.queue_path, $output.state_path)
    Write-Output ('[AB-TICKET-POLL] rows={0} skipped_running_status_reports={1} mark_processed={2}' -f $rows.Count, $skippedStatusReports, [bool]$MarkProcessed)
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
        }
    }
}
