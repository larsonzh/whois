param(
    [string]$StartFile = 'testdata/unattended_start/active/unattended_ab_start_20261031-20261115.md',
    [string]$OutDirRoot = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'unattended_exit_result.ps1')
. (Join-Path $PSScriptRoot 'unattended_startfile_identity.ps1')
$script:UnhandledExitTag = 'EVENT-QUEUE-IDEMPOTENT-REGRESSION'

if ([string]::IsNullOrWhiteSpace($OutDirRoot)) {
    $OutDirRoot = Join-Path $PSScriptRoot '..\..\out\artifacts\event_queue_idempotent_regression'
}

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$outDir = Join-Path $OutDirRoot $stamp
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

function Write-JsonLineFile {
    param(
        [string]$Path,
        [object[]]$Rows
    )

    $lines = New-Object 'System.Collections.Generic.List[string]'
    foreach ($row in @($Rows)) {
        [void]$lines.Add(($row | ConvertTo-Json -Compress -Depth 10))
    }
    [System.IO.File]::WriteAllLines($Path, $lines.ToArray(), [System.Text.UTF8Encoding]::new($false))
}

$pollScript = Resolve-RepoPath -Path 'tools/test/poll_agent_tickets.ps1'
$startFilePath = Resolve-RepoPath -Path $StartFile

$tmpStartFile = Join-Path $outDir 'startfile_probe.md'
Copy-Item -LiteralPath $startFilePath -Destination $tmpStartFile -Force

$startRaw = Get-Content -LiteralPath $tmpStartFile -Raw -Encoding utf8
if ($startRaw -match '(?m)^AI_CHAT_TRIGGER_SKIP_EXISTING_QUEUE_ON_START=') {
    $startRaw = [regex]::Replace($startRaw, '(?m)^AI_CHAT_TRIGGER_SKIP_EXISTING_QUEUE_ON_START=.*$', 'AI_CHAT_TRIGGER_SKIP_EXISTING_QUEUE_ON_START=true')
}
else {
    $startRaw = $startRaw.TrimEnd("`r", "`n") + "`r`nAI_CHAT_TRIGGER_SKIP_EXISTING_QUEUE_ON_START=true`r`n"
}
Set-Content -LiteralPath $tmpStartFile -Value $startRaw -Encoding utf8

$queuePath = Join-Path $outDir 'queue.jsonl'
$statePath = Join-Path $outDir 'state.json'
$ledgerPath = Join-Path $outDir 'ledger.json'
Write-JsonLineFile -Path $queuePath -Rows @()

$poll1 = & $pollScript -StartFile $tmpStartFile -QueuePath $queuePath -StatePath $statePath -LedgerPath $ledgerPath -IncludeStatusReports -Last 20 -AsJson
$poll1Obj = $poll1 | ConvertFrom-Json

$floorAtText = [string]$poll1Obj.event_queue_policy.event_queue_floor_at
if ([string]::IsNullOrWhiteSpace($floorAtText)) {
    throw 'event_queue_floor_at not initialized on first poll.'
}

$floorAt = [datetimeoffset]::Parse($floorAtText)
$ticketBeforeId = ('T-EVT-BEFORE-{0}' -f $stamp)
$ticketAfterId = ('T-EVT-AFTER-{0}' -f $stamp)

$ticketBefore = [ordered]@{
    schema = 'AB_AGENT_TICKET_V1'
    ticket_id = $ticketBeforeId
    created_at = $floorAt.AddMinutes(-1).ToString('yyyy-MM-dd HH:mm:ss')
    source = 'event-queue-idempotent-regression'
    event = 'a-pass-conclusion-b-started'
    severity = 'info'
    requires_confirmation = $false
    start_file = $tmpStartFile
    queue_path = $queuePath
    detail = 'pre-session ticket should be skipped'
    recommended_action = 'skip'
    session_final_status = 'RUNNING'
    a_final_status = 'PASS'
    b_final_status = 'RUNNING'
    preferred_stage = 'B'
    self_healable = $true
    non_recoverable_env = $false
}

$ticketAfter = [ordered]@{
    schema = 'AB_AGENT_TICKET_V1'
    ticket_id = $ticketAfterId
    created_at = $floorAt.AddMinutes(1).ToString('yyyy-MM-dd HH:mm:ss')
    source = 'event-queue-idempotent-regression'
    event = 'a-pass-conclusion-b-started'
    severity = 'info'
    requires_confirmation = $false
    start_file = $tmpStartFile
    queue_path = $queuePath
    detail = 'in-session ticket should be selected'
    recommended_action = 'select'
    session_final_status = 'RUNNING'
    a_final_status = 'PASS'
    b_final_status = 'RUNNING'
    preferred_stage = 'B'
    self_healable = $true
    non_recoverable_env = $false
}

Write-JsonLineFile -Path $queuePath -Rows @($ticketBefore, $ticketAfter)

$poll2 = & $pollScript -StartFile $tmpStartFile -QueuePath $queuePath -StatePath $statePath -LedgerPath $ledgerPath -IncludeStatusReports -Last 20 -AsJson
$poll2Obj = $poll2 | ConvertFrom-Json

$rows = @($poll2Obj.rows)
$selectedIds = @($rows | ForEach-Object { [string]$_.ticket_id })
$hasAfterTicket = $selectedIds -contains $ticketAfterId
$hasBeforeTicket = $selectedIds -contains $ticketBeforeId

$ledgerRaw = Get-Content -LiteralPath $ledgerPath -Raw -Encoding utf8 | ConvertFrom-Json
$ledgerRecords = @($ledgerRaw.records)
$beforeLedger = @($ledgerRecords | Where-Object { [string]$_.ticket_id -eq $ticketBeforeId } | Select-Object -First 1)
$afterLedger = @($ledgerRecords | Where-Object { [string]$_.ticket_id -eq $ticketAfterId } | Select-Object -First 1)

$beforeStatus = if ($beforeLedger.Count -gt 0) { [string]$beforeLedger[0].status } else { '' }
$afterStatus = if ($afterLedger.Count -gt 0) { [string]$afterLedger[0].status } else { '' }
$beforeNote = if ($beforeLedger.Count -gt 0) { [string]$beforeLedger[0].notes } else { '' }
$afterNote = if ($afterLedger.Count -gt 0) { [string]$afterLedger[0].notes } else { '' }

$afterHandledExpected = (
    $afterStatus -eq 'claimed' -or
    ($afterStatus -eq 'done' -and $afterNote -eq 'event_no_longer_present')
)

$floorUnchanged = ([string]$poll2Obj.event_queue_policy.event_queue_floor_at) -eq $floorAtText
$doneThisPoll = [int]$poll2Obj.done_this_poll

$pass = (
    -not $hasBeforeTicket -and
    $beforeStatus -eq 'done' -and
    $beforeNote -eq 'pre_session_event_skipped' -and
    $afterHandledExpected -and
    $doneThisPoll -ge 1 -and
    $floorUnchanged
)

$summary = [ordered]@{
    schema = 'AB_EVENT_QUEUE_IDEMPOTENT_REGRESSION_V1'
    generated_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    out_dir = $outDir
    start_file = $tmpStartFile
    queue_path = $queuePath
    state_path = $statePath
    ledger_path = $ledgerPath
    baseline_floor_at = $floorAtText
    checks = [ordered]@{
        after_ticket_selected = $hasAfterTicket
        before_ticket_not_selected = (-not $hasBeforeTicket)
        before_ticket_ledger_done = ($beforeStatus -eq 'done')
        before_ticket_pre_session_skipped = ($beforeNote -eq 'pre_session_event_skipped')
        after_ticket_handled_expected = $afterHandledExpected
        after_ticket_ledger_status = $afterStatus
        after_ticket_ledger_note = $afterNote
        done_this_poll_ge_1 = ($doneThisPoll -ge 1)
        floor_unchanged = $floorUnchanged
    }
    selected_action_ticket_id = [string]$poll2Obj.selected_action_ticket_id
    rows_count = $rows.Count
    pass = $pass
}

$summaryJsonPath = Join-Path $outDir 'summary.json'
$summaryTxtPath = Join-Path $outDir 'summary.txt'
$summary | ConvertTo-Json -Depth 8 | Out-File -LiteralPath $summaryJsonPath -Encoding utf8
$summary | Format-List | Out-String | Out-File -LiteralPath $summaryTxtPath -Encoding utf8

Write-Output ('[EVENT-QUEUE-IDEMPOTENT-REGRESSION] out_dir={0}' -f $outDir)
Write-Output ('[EVENT-QUEUE-IDEMPOTENT-REGRESSION] summary_json={0}' -f $summaryJsonPath)
Write-Output ('[EVENT-QUEUE-IDEMPOTENT-REGRESSION] checks after_selected={0} before_not_selected={1} before_done={2} before_pre_session={3} after_expected={4} after_status={5} after_note={6} done_this_poll={7} floor_unchanged={8}' -f $hasAfterTicket, (-not $hasBeforeTicket), ($beforeStatus -eq 'done'), ($beforeNote -eq 'pre_session_event_skipped'), $afterHandledExpected, $afterStatus, $afterNote, $doneThisPoll, $floorUnchanged)

if (-not $pass) {
    Write-Output '[EVENT-QUEUE-IDEMPOTENT-REGRESSION] result=fail'
    Exit-UnattendedFailure -Tag $script:UnhandledExitTag -Reason 'event-queue-idempotent-regression failed' -ExitCode 1
}

Write-Output '[EVENT-QUEUE-IDEMPOTENT-REGRESSION] result=pass'
exit 0
