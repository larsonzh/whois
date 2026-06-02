param(
    [Parameter(Mandatory = $true)][string]$StartFile,
    [ValidateRange(1, 200)][int]$Last = 20,
    [switch]$NoIncludeStatusReports,
    [switch]$AsJson
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Convert-ToSingleLineText {
    param([AllowEmptyString()][string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return ''
    }

    return ([regex]::Replace($Text.Trim(), '\s+', ' '))
}

function Convert-ToBooleanValue {
    param(
        [AllowNull()][object]$Value,
        [bool]$Default = $false
    )

    if ($null -eq $Value) {
        return $Default
    }

    if ($Value -is [bool]) {
        return [bool]$Value
    }

    $normalized = (Convert-ToSingleLineText -Text ([string]$Value)).ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($normalized)) {
        return $Default
    }

    return $normalized -in @('1', 'true', 'yes', 'on')
}

function Get-ObjectPropertyString {
    param(
        [AllowNull()][object]$InputObject,
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
        [AllowNull()][object]$InputObject,
        [string]$Name,
        [bool]$Default = $false
    )

    return (Convert-ToBooleanValue -Value (Get-ObjectPropertyString -InputObject $InputObject -Name $Name) -Default $Default)
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$pollScript = Join-Path $repoRoot 'tools\test\poll_agent_tickets.ps1'
if (-not (Test-Path -LiteralPath $pollScript)) {
    throw ('poll script not found: {0}' -f $pollScript)
}

$pollParams = @{
    StartFile = $StartFile
    Last = $Last
    AsJson = $true
}
if (-not $NoIncludeStatusReports.IsPresent) {
    $pollParams.IncludeStatusReports = $true
}

$pollRaw = & $pollScript @pollParams
$pollJson = (($pollRaw | Out-String).Trim())
if ([string]::IsNullOrWhiteSpace($pollJson)) {
    throw 'poll script returned empty output'
}

$poll = $pollJson | ConvertFrom-Json
$rows = @($poll.rows)
$statusRows = @($rows | Where-Object { (Convert-ToSingleLineText -Text ([string]$_.event)).ToLowerInvariant() -eq 'running-status-report' })
$eventRows = @($rows | Where-Object { (Convert-ToSingleLineText -Text ([string]$_.event)).ToLowerInvariant() -ne 'running-status-report' })

$fallbackRequired = Get-ObjectPropertyBoolean -InputObject $poll.fallback_monitoring -Name 'required' -Default $false
$heartbeatWriteOk = Get-ObjectPropertyBoolean -InputObject $poll.chat_session_heartbeat -Name 'write_ok' -Default $false
$heartbeatReason = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $poll.chat_session_heartbeat -Name 'reason')
$eventPolicyStrict = Get-ObjectPropertyBoolean -InputObject $poll.event_policy -Name 'strict_mode' -Default $false
$eventPolicyAdjustments = @($poll.event_policy.adjustments)
$sessionClosed = Get-ObjectPropertyBoolean -InputObject $poll.session_close_gate -Name 'closed' -Default $false
$sessionStatus = (Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $poll.session_close_gate -Name 'session_status')).ToUpperInvariant()
$aStatus = (Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $poll.session_close_gate -Name 'a_status')).ToUpperInvariant()
$bStatus = (Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $poll.session_close_gate -Name 'b_status')).ToUpperInvariant()

$verdict = 'healthy'
$priority = 'low'
$summary = 'No pending ticket and no fallback alert.'

if ($sessionClosed -and $sessionStatus -eq 'PASS' -and $aStatus -eq 'PASS' -and $bStatus -eq 'PASS' -and $rows.Count -eq 0) {
    $verdict = 'terminal-pass'
    $priority = 'low'
    $summary = 'A/B reached PASS terminal and no pending ticket.'
}
elseif ($eventRows.Count -gt 0) {
    $verdict = 'action-required'
    $priority = 'high'
    $summary = ('{0} event-driven ticket(s) pending; prioritize deterministic handling flow.' -f $eventRows.Count)
}
elseif ($fallbackRequired) {
    $verdict = 'action-required'
    $priority = 'high'
    $summary = 'Fallback monitoring indicates unresolved final-state issue.'
}
elseif ($statusRows.Count -gt 0) {
    $verdict = 'status-only'
    $priority = 'medium'
    $summary = ('{0} status ticket(s) pending; execute short routine and return handled_at.' -f $statusRows.Count)
}

if ($eventPolicyStrict -and $eventPolicyAdjustments.Count -gt 0) {
    $verdict = 'action-required'
    $priority = 'high'
    $summary = 'Strict event policy has normalization adjustments; fix start-file policy keys first.'
}

$checks = @(
    [ordered]@{
        name = 'pending_event_tickets'
        ok = ($eventRows.Count -eq 0)
        value = $eventRows.Count
    },
    [ordered]@{
        name = 'pending_status_tickets'
        ok = $true
        value = $statusRows.Count
    },
    [ordered]@{
        name = 'fallback_required'
        ok = (-not $fallbackRequired)
        value = $fallbackRequired
    },
    [ordered]@{
        name = 'heartbeat_write_ok'
        ok = $heartbeatWriteOk
        value = $heartbeatReason
    },
    [ordered]@{
        name = 'event_policy_adjustments'
        ok = (-not ($eventPolicyStrict -and $eventPolicyAdjustments.Count -gt 0))
        value = $eventPolicyAdjustments.Count
    }
)

$firstRow = $null
if ($rows.Count -gt 0) {
    $firstRow = $rows[0]
}

$output = [ordered]@{
    schema = 'AB_ROUTINE_STATUS_CHECK_V1'
    generated_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    start_file = [string]$poll.start_file
    verdict = $verdict
    priority = $priority
    summary = $summary
    counts = [ordered]@{
        total_rows = $rows.Count
        event_rows = $eventRows.Count
        status_rows = $statusRows.Count
    }
    checks = $checks
    session = [ordered]@{
        closed = $sessionClosed
        session_status = $sessionStatus
        a_status = $aStatus
        b_status = $bStatus
    }
    event_policy = [ordered]@{
        strict_mode = $eventPolicyStrict
        adjustments = @($eventPolicyAdjustments)
    }
    heartbeat = [ordered]@{
        enabled = Get-ObjectPropertyBoolean -InputObject $poll.chat_session_heartbeat -Name 'enabled' -Default $false
        write_on_poll = Get-ObjectPropertyBoolean -InputObject $poll.chat_session_heartbeat -Name 'write_on_poll' -Default $false
        write_ok = $heartbeatWriteOk
        reason = $heartbeatReason
        updated_at = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $poll.chat_session_heartbeat -Name 'updated_at')
        path = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $poll.chat_session_heartbeat -Name 'path')
    }
    commands = [ordered]@{
        poll = ('powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/poll_agent_tickets.ps1 -StartFile "{0}" -IncludeStatusReports -Last {1} -AsJson' -f $StartFile, $Last)
        routine_check = ('powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/check_unattended_routine_status.ps1 -StartFile "{0}" -Last {1} -AsJson' -f $StartFile, $Last)
        status_only_autoflow = ('powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/run_unattended_status_only_autoflow.ps1 -StartFile "{0}" -Last {1} -DryRun -AsJson' -f $StartFile, $Last)
        status_only_autoflow_execute_template = ('powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/run_unattended_status_only_autoflow.ps1 -StartFile "{0}" -Last {1} -EnableExecute -AllowedTicketIds "<ticket-id>" -ExecutionToken "<token>" -AsJson' -f $StartFile, $Last)
        heartbeat_ping = (Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $poll.rescan_commands -Name 'heartbeat_ping'))
        selected_ticket = if ($null -ne $firstRow) {
            [ordered]@{
                ticket_id = Convert-ToSingleLineText -Text ([string]$firstRow.ticket_id)
                event = Convert-ToSingleLineText -Text ([string]$firstRow.event)
                business_command = Convert-ToSingleLineText -Text ([string]$firstRow.business_command)
                continue_watch_command = Convert-ToSingleLineText -Text ([string]$firstRow.continue_watch_command)
                handled_receipt_command = Convert-ToSingleLineText -Text ([string]$firstRow.handled_receipt_command)
                mark_processed_command = Convert-ToSingleLineText -Text ([string]$firstRow.mark_processed_command)
                post_check_command = Convert-ToSingleLineText -Text ([string]$firstRow.post_check_command)
            }
        }
        else {
            $null
        }
    }
    raw_poll = $poll
}

if ($AsJson.IsPresent) {
    $output | ConvertTo-Json -Depth 12
}
else {
    Write-Output ('[AB-ROUTINE-CHECK] verdict={0} priority={1} summary={2}' -f [string]$output.verdict, [string]$output.priority, [string]$output.summary)
    Write-Output ('[AB-ROUTINE-CHECK] counts total={0} event={1} status={2}' -f [int]$output.counts.total_rows, [int]$output.counts.event_rows, [int]$output.counts.status_rows)
    Write-Output ('[AB-ROUTINE-CHECK] session closed={0} session={1} a={2} b={3}' -f [bool]$output.session.closed, [string]$output.session.session_status, [string]$output.session.a_status, [string]$output.session.b_status)
    Write-Output ('[AB-ROUTINE-CHECK] heartbeat ok={0} reason={1} updated_at={2}' -f [bool]$output.heartbeat.write_ok, [string]$output.heartbeat.reason, [string]$output.heartbeat.updated_at)

    if ($null -ne $output.commands.selected_ticket) {
        Write-Output ('[AB-ROUTINE-CHECK] selected_ticket={0} event={1}' -f [string]$output.commands.selected_ticket.ticket_id, [string]$output.commands.selected_ticket.event)
        Write-Output ('  business_command={0}' -f [string]$output.commands.selected_ticket.business_command)
        Write-Output ('  continue_watch_command={0}' -f [string]$output.commands.selected_ticket.continue_watch_command)
        Write-Output ('  handled_receipt_command={0}' -f [string]$output.commands.selected_ticket.handled_receipt_command)
        Write-Output ('  mark_processed_command={0}' -f [string]$output.commands.selected_ticket.mark_processed_command)
        Write-Output ('  post_check_command={0}' -f [string]$output.commands.selected_ticket.post_check_command)
    }
}
