param(
    [Parameter(Mandatory = $true)][string]$StartFile,
    [AllowEmptyString()][string]$OutputRoot = 'out/artifacts/ab_agent_queue/minimal_regression',
    [switch]$AsJson
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'unattended_startfile_identity.ps1')

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location -LiteralPath $repoRoot

$startFilePath = Resolve-RepoPathAllowMissing -Path $StartFile
if ([string]::IsNullOrWhiteSpace($startFilePath) -or -not (Test-Path -LiteralPath $startFilePath)) {
    throw ("start file not found: {0}" -f $StartFile)
}

$startFileRel = Convert-ToRepoRelativePath -Path $startFilePath
$outputRootPath = Resolve-RepoPathAllowMissing -Path $OutputRoot
New-Item -ItemType Directory -Path $outputRootPath -Force | Out-Null

function New-SyntheticTicket {
    param(
        [string]$TicketId,
        [string]$QueuePathRel
    )

    return [ordered]@{
        ticket_id = $TicketId
        event = 'task-definition-fix-required'
        severity = 'high'
        created_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        requires_confirmation = $false
        detail = 'stage=A category=task-definition-static-precheck fingerprint_duplicate=true one_time_retry_only=true round=D4 phase=code-step task_start_at=20260707-120000 fingerprint=fp_demo'
        recommended_action = 'one-time retry only'
        queue_path = $QueuePathRel
        main_round = 'D4'
        failure_kind = 'task-definition-fingerprint-duplicate'
        failure_category = 'task-definition-static-precheck-fingerprint-duplicate'
        failure_source = 'tools/test/open_unattended_ab_stage_window.ps1'
        failure_evidence = 'fingerprint_duplicate=true one_time_retry_only=true'
        self_healable = $true
        non_recoverable_env = $false
        preferred_stage = 'A'
    }
}

function Invoke-Poll {
    param(
        [string]$QueuePath,
        [string]$LedgerPath,
        [string]$StatePath,
        [AllowEmptyString()][string]$TicketId = '',
        [AllowEmptyString()][string]$RetryBudgetUsed = ''
    )

    $pollArgs = @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', 'tools/test/poll_agent_tickets.ps1',
        '-StartFile', $startFileRel,
        '-QueuePath', $QueuePath,
        '-LedgerPath', $LedgerPath,
        '-StatePath', $StatePath,
        '-AsJson'
    )

    if (-not [string]::IsNullOrWhiteSpace($TicketId)) {
        $pollArgs += @('-AcknowledgeTicketIds', $TicketId)
        $normalizedRetry = ([string]$RetryBudgetUsed).Trim().ToLowerInvariant()
        if ($normalizedRetry -in @('yes', 'no')) {
            $pollArgs += @('-AcknowledgeRetryBudgetUsed', $normalizedRetry)
        }
    }

    return (& powershell @pollArgs)
}

function Invoke-RegressionCase {
    param(
        [string]$Name,
        [string]$AckValue,
        [string]$QueuePath,
        [string]$LedgerPath,
        [string]$StatePath
    )

    $ticketId = "T-MIN-" + $Name
    $null = Invoke-Poll -QueuePath $queuePath -LedgerPath $ledgerPath -StatePath $statePath -TicketId $ticketId -RetryBudgetUsed $AckValue

    $ledgerObj = Get-Content -LiteralPath $ledgerPath -Raw -Encoding utf8 | ConvertFrom-Json
    $record = @($ledgerObj.records | Where-Object { $_.ticket_id -eq $ticketId } | Select-Object -First 1)
    if ($record.Count -lt 1) {
        return [ordered]@{
            case = $Name
            ack = $AckValue
            ok = $false
            reason = 'ledger-record-missing'
            ledger_status = 'n/a'
            failure_reason = 'n/a'
        }
    }

    $status = [string]$record[0].status
    $failureReason = [string]$record[0].failure_reason
    $pass = ($Name -eq 'ack_yes' -and $status -eq 'done') -or (($Name -eq 'ack_missing' -or $Name -eq 'ack_no') -and $status -eq 'failed')

    return [ordered]@{
        case = $Name
        ack = $AckValue
        ok = $pass
        ledger_status = $status
        failure_reason = $failureReason
    }
}

$queuePath = Join-Path $outputRootPath 'agent_tickets.jsonl'
$ledgerPath = Join-Path $outputRootPath 'ledger.json'
$statePath = Join-Path $outputRootPath 'state.json'
Remove-Item -LiteralPath $queuePath,$ledgerPath,$statePath -ErrorAction SilentlyContinue

# Seed the session floor once, then exercise the three receipt outcomes through
# the poll script's ack-only fast path without repeating ticket selection.
$null = Invoke-Poll -QueuePath $queuePath -LedgerPath $ledgerPath -StatePath $statePath
$queueRel = Convert-ToRepoRelativePath -Path $queuePath
$caseDefinitions = @(
    [pscustomobject]@{ Name = 'ack_yes'; AckValue = 'yes' }
    [pscustomobject]@{ Name = 'ack_missing'; AckValue = '' }
    [pscustomobject]@{ Name = 'ack_no'; AckValue = 'no' }
)
$ticketLines = @(
    foreach ($caseDefinition in $caseDefinitions) {
        $ticketId = 'T-MIN-' + [string]$caseDefinition.Name
        New-SyntheticTicket -TicketId $ticketId -QueuePathRel $queueRel | ConvertTo-Json -Compress -Depth 8
    }
)
$ticketLines | Out-File -LiteralPath $queuePath -Encoding utf8

$results = @(
    foreach ($caseDefinition in $caseDefinitions) {
        Invoke-RegressionCase -Name ([string]$caseDefinition.Name) -AckValue ([string]$caseDefinition.AckValue) -QueuePath $queuePath -LedgerPath $ledgerPath -StatePath $statePath
    }
)
$failed = @($results | Where-Object { -not $_.ok })
$allPass = ($failed.Count -eq 0)

$output = [ordered]@{
    schema = 'AB_MINIMAL_RETRY_BUDGET_REGRESSION_V1'
    generated_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    start_file = $startFileRel
    output_root = (Convert-ToRepoRelativePath -Path $outputRootPath)
    all_pass = $allPass
    results = @($results)
}

if ($AsJson.IsPresent) {
    $output | ConvertTo-Json -Depth 8
}
else {
    Write-Output ('MIN-REGRESSION all_pass={0}' -f $allPass)
    $results | ConvertTo-Json -Depth 8
}

if (-not $allPass) {
    exit 2
}
