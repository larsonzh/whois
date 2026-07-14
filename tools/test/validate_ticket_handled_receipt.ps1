param(
    [Parameter(Mandatory = $true)][string]$StartFile,
    [Parameter(Mandatory = $true)][string]$TicketId,
    [AllowEmptyString()][string]$QueuePath = '',
    [AllowEmptyString()][string]$LedgerPath = '',
    [AllowEmptyString()][string]$ExpectedRetryBudgetUsed = '',
    [AllowNull()][object]$EnqueueReminder = $true,
    [AllowEmptyString()][string]$ReminderEvent = 'handled-receipt-reminder',
    [switch]$AsJson
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'unattended_startfile_identity.ps1')

function Convert-ToSingleLineText {
    param([AllowEmptyString()][string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return ''
    }

    return ([regex]::Replace($Text.Trim(), '\s+', ' '))
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

    $raw = (Convert-ToSingleLineText -Text ([string]$Value)).ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($raw)) {
        return $Default
    }

    return $raw -in @('1', 'true', 'yes', 'on')
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

function Get-SafeToken {
    param([AllowEmptyString()][string]$Text)

    $normalized = Convert-ToSingleLineText -Text $Text
    if ([string]::IsNullOrWhiteSpace($normalized)) {
        return 'default'
    }

    return ([regex]::Replace($normalized, '[^A-Za-z0-9._-]', '_')).Trim('_')
}

function Add-JsonLine {
    param(
        [string]$Path,
        [object]$Value
    )

    $parent = Split-Path -Parent $Path
    if (-not [string]::IsNullOrWhiteSpace($parent) -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }

    $line = ($Value | ConvertTo-Json -Compress -Depth 10)
    $appendEncoding = [System.Text.UTF8Encoding]::new($false)
    $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite)
    try {
        $writer = New-Object System.IO.StreamWriter($stream, $appendEncoding)
        try {
            $writer.WriteLine($line)
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

function Test-HandledAtFormat {
    param([AllowEmptyString()][string]$Value)

    $text = Convert-ToSingleLineText -Text $Value
    if ([string]::IsNullOrWhiteSpace($text)) {
        return $false
    }

    return [regex]::IsMatch($text, '^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$')
}

function Convert-ToRetryBudgetUsedValue {
    param([AllowEmptyString()][string]$Value)

    $text = (Convert-ToSingleLineText -Text $Value).ToLowerInvariant()
    if ($text -in @('yes', 'no')) {
        return $text
    }

    return ''
}

$script:RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path

$startFilePath = Resolve-RepoPathAllowMissing -Path $StartFile
if ([string]::IsNullOrWhiteSpace($startFilePath) -or -not (Test-Path -LiteralPath $startFilePath)) {
    throw ('start file not found: {0}' -f $StartFile)
}

$startFileRel = Convert-ToRepoRelativePath -Path $startFilePath
$startToken = Get-StableStartFileToken -StartFilePath $startFilePath
$legacyStartToken = Get-LegacyStartFileToken -StartFilePath $startFilePath

$settings = Read-KeyValueFile -Path $startFilePath

$queuePathValue = ConvertTo-PathLikeValue -Value $QueuePath
if ([string]::IsNullOrWhiteSpace($queuePathValue) -and $settings.Contains('LOCAL_GUARD_AGENT_QUEUE_PATH')) {
    $queuePathValue = ConvertTo-PathLikeValue -Value ([string]$settings.LOCAL_GUARD_AGENT_QUEUE_PATH)
}
if ([string]::IsNullOrWhiteSpace($queuePathValue)) {
    $queuePathValue = 'out\artifacts\ab_agent_queue\agent_tickets.jsonl'
}
$queueFilePath = Resolve-RepoPathAllowMissing -Path $queuePathValue

$ledgerPathValue = ConvertTo-PathLikeValue -Value $LedgerPath
if ([string]::IsNullOrWhiteSpace($ledgerPathValue)) {
    $preferredLedger = Resolve-RepoPathAllowMissing -Path (Join-Path 'out\artifacts\ab_agent_queue' ("ai_ticket_ledger_{0}.json" -f $startToken))
    $legacyLedger = Resolve-RepoPathAllowMissing -Path (Join-Path 'out\artifacts\ab_agent_queue' ("ai_ticket_ledger_{0}.json" -f $legacyStartToken))
    $ledgerFilePath = Resolve-PreferredDefaultPath -PreferredPath $preferredLedger -LegacyPath $legacyLedger
}
else {
    $ledgerFilePath = Resolve-RepoPathAllowMissing -Path $ledgerPathValue
}

$ticketId = Convert-ToSingleLineText -Text $TicketId
if ([string]::IsNullOrWhiteSpace($ticketId)) {
    throw 'TicketId must not be empty.'
}

$expectedRetryBudgetUsed = Convert-ToRetryBudgetUsedValue -Value $ExpectedRetryBudgetUsed

$enqueueReminder = Convert-ToBooleanValue -Value $EnqueueReminder -Default $true
$reminderEventName = Convert-ToSingleLineText -Text $ReminderEvent
if ([string]::IsNullOrWhiteSpace($reminderEventName)) {
    $reminderEventName = 'handled-receipt-reminder'
}

$ledger = Read-JsonFileSafely -Path $ledgerFilePath
$record = $null
$handledAt = ''
$handledAtValid = $false
$ledgerStatus = ''
$sourceEvent = ''
$sourceSeverity = 'high'
$retryBudgetUsed = ''
$retryBudgetUsedValid = $false

if ($null -ne $ledger -and $ledger.PSObject.Properties.Name -contains 'records') {
    foreach ($entry in @($ledger.records)) {
        $entryTicketId = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $entry -Name 'ticket_id')
        if ([string]::IsNullOrWhiteSpace($entryTicketId)) {
            continue
        }

        if ($entryTicketId.Equals($ticketId, [System.StringComparison]::OrdinalIgnoreCase)) {
            $record = $entry
            break
        }
    }
}

if ($null -ne $record) {
    $handledAt = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $record -Name 'handled_at')
    $handledAtValid = Test-HandledAtFormat -Value $handledAt
    $ledgerStatus = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $record -Name 'status')
    $sourceEvent = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $record -Name 'event')
    $rawSeverity = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $record -Name 'severity')
    if (-not [string]::IsNullOrWhiteSpace($rawSeverity)) {
        $sourceSeverity = $rawSeverity
    }
    $retryBudgetUsed = Convert-ToRetryBudgetUsedValue -Value (Get-ObjectPropertyString -InputObject $record -Name 'retry_budget_used')
    $retryBudgetUsedValid = -not [string]::IsNullOrWhiteSpace($retryBudgetUsed)
}

$retryBudgetMismatch = $false
if (-not [string]::IsNullOrWhiteSpace($expectedRetryBudgetUsed)) {
    $retryBudgetMismatch = ($retryBudgetUsed -ne $expectedRetryBudgetUsed)
}

$missingReceipt = (-not $handledAtValid) -or $retryBudgetMismatch
$reminderEnqueued = $false
$reminderSkippedReason = ''
$reminderTicketId = ''

if ($missingReceipt -and $enqueueReminder) {
    $existingReminder = $false
    $queueLines = @()
    if (-not [string]::IsNullOrWhiteSpace($queueFilePath) -and (Test-Path -LiteralPath $queueFilePath)) {
        $queueLines = @(Get-Content -LiteralPath $queueFilePath -Encoding utf8 -ErrorAction SilentlyContinue)
    }

    foreach ($line in $queueLines) {
        $lineText = Convert-ToSingleLineText -Text ([string]$line)
        if ([string]::IsNullOrWhiteSpace($lineText)) {
            continue
        }

        try {
            $obj = $lineText | ConvertFrom-Json -ErrorAction Stop
            $eventName = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $obj -Name 'event')
            $sourceTicket = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $obj -Name 'source_ticket_id')
            if ($eventName.Equals($reminderEventName, [System.StringComparison]::OrdinalIgnoreCase) -and
                $sourceTicket.Equals($ticketId, [System.StringComparison]::OrdinalIgnoreCase)) {
                $existingReminder = $true
                break
            }
        }
        catch {
            continue
        }
    }

    if ($existingReminder) {
        $reminderSkippedReason = 'existing-reminder'
    }
    else {
        $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
        $ticketSuffix = Get-SafeToken -Text $ticketId
        if ($ticketSuffix.Length -gt 24) {
            $ticketSuffix = $ticketSuffix.Substring(0, 24)
        }
        $reminderTicketId = ('receipt-reminder-{0}-{1}' -f $timestamp, $ticketSuffix)

        $detail = ('Missing mandatory handled_at receipt for ticket {0}. Fail closed and execute the ticket brief atomic_closeout_command; do not run split receipt commands individually.' -f $ticketId)
        $recommended = ('Execute atomic_closeout_command exactly once for ticket {0}; return handled_at only when all machine-fact gates pass.' -f $ticketId)
        if ($retryBudgetMismatch) {
            $detail = ('{0} retry_budget_used expected={1} actual={2}.' -f $detail, $expectedRetryBudgetUsed, (if ([string]::IsNullOrWhiteSpace($retryBudgetUsed)) { 'missing' } else { $retryBudgetUsed }))
            $recommended = ('{0} Also provide retry_budget_used: {1}.' -f $recommended, $expectedRetryBudgetUsed)
        }

        $reminderTicket = [ordered]@{
            ticket_id = $reminderTicketId
            event = $reminderEventName
            severity = $sourceSeverity
            created_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
            requires_confirmation = $false
            detail = $detail
            recommended_action = $recommended
            source_ticket_id = $ticketId
            source_event = $sourceEvent
            queue_path = (Convert-ToRepoRelativePath -Path $queueFilePath)
            start_file = $startFileRel
            receipt_required = $true
            receipt_type = 'handled_at'
            dedup_suffix = ('receipt-missing-{0}' -f (Get-SafeToken -Text $ticketId))
        }

        Add-JsonLine -Path $queueFilePath -Value $reminderTicket
        $reminderEnqueued = $true
    }
}

$success = -not $missingReceipt
$reason = if ($success) {
    'receipt-present'
}
elseif ($reminderEnqueued) {
    'receipt-missing-reminder-enqueued'
}
elseif (-not [string]::IsNullOrWhiteSpace($reminderSkippedReason)) {
    ('receipt-missing-{0}' -f $reminderSkippedReason)
}
else {
    'receipt-missing-reminder-disabled'
}

$output = [ordered]@{
    schema = 'AB_HANDLED_RECEIPT_VALIDATION_V1'
    generated_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    start_file = $startFileRel
    queue_path = (Convert-ToRepoRelativePath -Path $queueFilePath)
    ledger_path = (Convert-ToRepoRelativePath -Path $ledgerFilePath)
    ticket_id = $ticketId
    success = [bool]$success
    reason = $reason
    ledger_status = $ledgerStatus
    handled_at = $handledAt
    handled_at_format_valid = [bool]$handledAtValid
    expected_retry_budget_used = $expectedRetryBudgetUsed
    retry_budget_used = $retryBudgetUsed
    retry_budget_used_format_valid = [bool]$retryBudgetUsedValid
    retry_budget_mismatch = [bool]$retryBudgetMismatch
    missing_receipt = [bool]$missingReceipt
    reminder = [ordered]@{
        enabled = [bool]$enqueueReminder
        event = $reminderEventName
        enqueued = [bool]$reminderEnqueued
        ticket_id = $reminderTicketId
        skipped_reason = $reminderSkippedReason
    }
}

if ($AsJson.IsPresent) {
    $output | ConvertTo-Json -Depth 8
}
else {
    Write-Output ('[AB-HANDLED-RECEIPT] ticket={0} success={1} reason={2} handled_at={3}' -f [string]$output.ticket_id, [bool]$output.success, [string]$output.reason, [string]$output.handled_at)
    Write-Output ('[AB-HANDLED-RECEIPT] ledger_status={0} ledger={1} queue={2}' -f [string]$output.ledger_status, [string]$output.ledger_path, [string]$output.queue_path)
    if ([bool]$output.reminder.enabled) {
        Write-Output ('[AB-HANDLED-RECEIPT] reminder event={0} enqueued={1} ticket={2} skipped_reason={3}' -f [string]$output.reminder.event, [bool]$output.reminder.enqueued, [string]$output.reminder.ticket_id, [string]$output.reminder.skipped_reason)
    }
}

if (-not $success) {
    exit 2
}
