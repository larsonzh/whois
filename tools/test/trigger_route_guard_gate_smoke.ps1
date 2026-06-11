param(
    [string]$StartFile = 'testdata/unattended_start/active/unattended_ab_start_20261031-20261115.md',
    [string]$OutDirRoot = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($OutDirRoot)) {
    $OutDirRoot = Join-Path $PSScriptRoot '..\..\out\artifacts\trigger_route_guard_gate_smoke'
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$outDir = Join-Path $OutDirRoot $stamp
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

$resolvedStartFile = if ([System.IO.Path]::IsPathRooted($StartFile)) {
    [System.IO.Path]::GetFullPath($StartFile)
}
else {
    [System.IO.Path]::GetFullPath((Join-Path $repoRoot $StartFile))
}

if (-not (Test-Path -LiteralPath $resolvedStartFile)) {
    throw ('start file not found: {0}' -f $resolvedStartFile)
}

$triggerScript = Join-Path $repoRoot 'tools\test\unattended_ab_takeover_trigger.ps1'
if (-not (Test-Path -LiteralPath $triggerScript)) {
    throw ('trigger script not found: {0}' -f $triggerScript)
}

$tmpStartFile = Join-Path $outDir 'startfile_probe.md'
Copy-Item -LiteralPath $resolvedStartFile -Destination $tmpStartFile -Force

$startRaw = Get-Content -LiteralPath $tmpStartFile -Raw -Encoding utf8
if ($startRaw -match '(?m)^AI_CHAT_TRIGGER_DISPATCH_STATUS_REPORTS=') {
    $startRaw = [regex]::Replace($startRaw, '(?m)^AI_CHAT_TRIGGER_DISPATCH_STATUS_REPORTS=.*$', 'AI_CHAT_TRIGGER_DISPATCH_STATUS_REPORTS=true')
}
else {
    $startRaw = $startRaw.TrimEnd("`r", "`n") + "`r`nAI_CHAT_TRIGGER_DISPATCH_STATUS_REPORTS=true`r`n"
}
Set-Content -LiteralPath $tmpStartFile -Value $startRaw -Encoding utf8

$tmpQueue = Join-Path $outDir 'queue_probe.jsonl'
$statusTicketId = 'T-SMOKE-STATUS-' + $stamp
$incidentTicketId = 'T-SMOKE-INCIDENT-' + $stamp
$baseCreated = Get-Date

$statusTicket = [ordered]@{
    schema = 'AB_AGENT_TICKET_V1'
    ticket_id = $statusTicketId
    created_at = $baseCreated.ToString('yyyy-MM-dd HH:mm:ss')
    source = 'trigger-route-guard-smoke'
    event = 'running-status-report'
    severity = 'info'
    requires_confirmation = $false
    start_file = $tmpStartFile
    queue_path = $tmpQueue
    session_final_status = 'RUNNING'
    a_final_status = 'RUNNING'
    b_final_status = 'RUNNING'
    run_dir = 'out/artifacts/dev_verify_multiround/20260609-195321'
    detail = 'smoke status ticket'
    recommended_action = 'smoke'
    preferred_stage = 'B'
    self_healable = $false
    non_recoverable_env = $false
}

$incidentTicket = [ordered]@{
    schema = 'AB_AGENT_TICKET_V1'
    ticket_id = $incidentTicketId
    created_at = $baseCreated.AddSeconds(10).ToString('yyyy-MM-dd HH:mm:ss')
    source = 'trigger-route-guard-smoke'
    event = 'incident-captured'
    severity = 'high'
    requires_confirmation = $false
    start_file = $tmpStartFile
    queue_path = $tmpQueue
    session_final_status = 'BLOCKED'
    a_final_status = 'PASS'
    b_final_status = 'FAIL'
    run_dir = 'out/artifacts/dev_verify_multiround/20260609-195321'
    incident_dir = 'out/artifacts/ab_session_guard/20260609-150054/incident_smoke'
    detail = 'smoke incident ticket'
    recommended_action = 'smoke'
    preferred_stage = 'B'
    main_round = 'D4'
    failure_kind = 'unknown-failure'
    failure_category = 'unknown'
    self_healable = $false
    non_recoverable_env = $false
}

Set-Content -LiteralPath $tmpQueue -Encoding utf8 -Value @(($statusTicket | ConvertTo-Json -Compress -Depth 10), ($incidentTicket | ConvertTo-Json -Compress -Depth 10))

$triggerOutput = @(& powershell -NoProfile -ExecutionPolicy Bypass -File $triggerScript -StartFile $tmpStartFile -QueuePath $tmpQueue -TriggerCommand 'cmd /c echo noop' -Once -PollSec 5 2>&1 | ForEach-Object { [string]$_ })

# Trigger initializes watermark on first queue usage and may skip existing lines.
# Append a second probe pair and run once again so the queue has new lines beyond watermark.
$statusTicketId2 = 'T-SMOKE-STATUS2-' + $stamp
$incidentTicketId2 = 'T-SMOKE-INCIDENT2-' + $stamp

$statusTicket2 = [ordered]@{
    schema = 'AB_AGENT_TICKET_V1'
    ticket_id = $statusTicketId2
    created_at = $baseCreated.AddSeconds(20).ToString('yyyy-MM-dd HH:mm:ss')
    source = 'trigger-route-guard-smoke'
    event = 'running-status-report'
    severity = 'info'
    requires_confirmation = $false
    start_file = $tmpStartFile
    queue_path = $tmpQueue
    session_final_status = 'RUNNING'
    a_final_status = 'RUNNING'
    b_final_status = 'RUNNING'
    run_dir = 'out/artifacts/dev_verify_multiround/20260609-195321'
    detail = 'smoke status ticket 2'
    recommended_action = 'smoke'
    preferred_stage = 'B'
    self_healable = $false
    non_recoverable_env = $false
}

$incidentTicket2 = [ordered]@{
    schema = 'AB_AGENT_TICKET_V1'
    ticket_id = $incidentTicketId2
    created_at = $baseCreated.AddSeconds(30).ToString('yyyy-MM-dd HH:mm:ss')
    source = 'trigger-route-guard-smoke'
    event = 'incident-captured'
    severity = 'high'
    requires_confirmation = $false
    start_file = $tmpStartFile
    queue_path = $tmpQueue
    session_final_status = 'BLOCKED'
    a_final_status = 'PASS'
    b_final_status = 'FAIL'
    run_dir = 'out/artifacts/dev_verify_multiround/20260609-195321'
    incident_dir = 'out/artifacts/ab_session_guard/20260609-150054/incident_smoke2'
    detail = 'smoke incident ticket 2'
    recommended_action = 'smoke'
    preferred_stage = 'B'
    main_round = 'D4'
    failure_kind = 'unknown-failure'
    failure_category = 'unknown'
    self_healable = $false
    non_recoverable_env = $false
}

Add-Content -LiteralPath $tmpQueue -Encoding utf8 -Value ($statusTicket2 | ConvertTo-Json -Compress -Depth 10)
Add-Content -LiteralPath $tmpQueue -Encoding utf8 -Value ($incidentTicket2 | ConvertTo-Json -Compress -Depth 10)

$triggerOutput2 = @(& powershell -NoProfile -ExecutionPolicy Bypass -File $triggerScript -StartFile $tmpStartFile -QueuePath $tmpQueue -TriggerCommand 'cmd /c echo noop' -Once -PollSec 5 2>&1 | ForEach-Object { [string]$_ })
$triggerOutput = @($triggerOutput + $triggerOutput2)
$triggerOutputPath = Join-Path $outDir 'trigger_output.log'
$triggerOutput | Out-File -LiteralPath $triggerOutputPath -Encoding utf8

$stateLine = @($triggerOutput | Where-Object { $_ -match 'state=' } | Select-Object -First 1)
if ($stateLine.Count -eq 0) {
    throw 'could not locate state path from trigger output'
}

$statePathRel = ''
if ($stateLine[0] -match 'state=([^\s]+)') {
    $statePathRel = $Matches[1]
}
if ([string]::IsNullOrWhiteSpace($statePathRel)) {
    throw ('could not parse state path from line: {0}' -f $stateLine[0])
}

$statePath = if ([System.IO.Path]::IsPathRooted($statePathRel)) {
    [System.IO.Path]::GetFullPath($statePathRel)
}
else {
    [System.IO.Path]::GetFullPath((Join-Path $repoRoot $statePathRel))
}

$stateFileName = [System.IO.Path]::GetFileName($statePath)
$logFileName = $stateFileName.Replace('takeover_trigger_state_', 'takeover_trigger_').Replace('.json', '.log')
$logPath = Join-Path ([System.IO.Path]::GetDirectoryName($statePath)) $logFileName

if (-not (Test-Path -LiteralPath $logPath)) {
    throw ('trigger log not found: {0}' -f $logPath)
}

$logLines = @(Get-Content -LiteralPath $logPath -Encoding utf8)
$evidence = @($logLines | Where-Object {
        $_ -match [regex]::Escape($statusTicketId) -or
        $_ -match [regex]::Escape($incidentTicketId) -or
        $_ -match 'external_trigger_route_allowed' -or
        $_ -match 'external_trigger_(failed|blocked|started)'
    })
$evidencePath = Join-Path $outDir 'evidence.log'
$evidence | Out-File -LiteralPath $evidencePath -Encoding utf8

$hasStatusAllowed = $false
$hasIncidentAllowed = $false
$hasStatusFailure = $false
$hasIncidentFailure = $false

$statusIds = @($statusTicketId, $statusTicketId2)
$incidentIds = @($incidentTicketId, $incidentTicketId2)

foreach ($line in $evidence) {
    foreach ($sid in $statusIds) {
        if ($line -match [regex]::Escape($sid) -and $line -match 'external_trigger_route_allowed') { $hasStatusAllowed = $true }
        if ($line -match [regex]::Escape($sid) -and $line -match 'external_trigger_failed') { $hasStatusFailure = $true }
    }
    foreach ($iid in $incidentIds) {
        if ($line -match [regex]::Escape($iid) -and $line -match 'external_trigger_route_allowed') { $hasIncidentAllowed = $true }
        if ($line -match [regex]::Escape($iid) -and $line -match 'external_trigger_failed') { $hasIncidentFailure = $true }
    }
}

$pass = ($hasStatusAllowed -and $hasIncidentAllowed -and $hasStatusFailure -and $hasIncidentFailure)

$summary = [ordered]@{
    schema = 'AB_TRIGGER_ROUTE_GUARD_GATE_SMOKE_V1'
    generated_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    source_start_file = $resolvedStartFile
    temp_start_file = $tmpStartFile
    temp_queue = $tmpQueue
    trigger_output = $triggerOutputPath
    trigger_state_path = $statePath
    trigger_log_path = $logPath
    evidence_log = $evidencePath
    status_ticket_ids = @($statusIds)
    incident_ticket_ids = @($incidentIds)
    checks = [ordered]@{
        status_route_allowed = $hasStatusAllowed
        incident_route_allowed = $hasIncidentAllowed
        status_trigger_failed_after_guard = $hasStatusFailure
        incident_trigger_failed_after_guard = $hasIncidentFailure
    }
    pass = $pass
}

$summaryJson = Join-Path $outDir 'summary.json'
$summaryTxt = Join-Path $outDir 'summary.txt'
$summary | ConvertTo-Json -Depth 8 | Out-File -LiteralPath $summaryJson -Encoding utf8
$summary | Format-List | Out-String | Out-File -LiteralPath $summaryTxt -Encoding utf8

Write-Output ('[TRIGGER-ROUTE-GATE-SMOKE] out_dir={0}' -f $outDir)
Write-Output ('[TRIGGER-ROUTE-GATE-SMOKE] summary_json={0}' -f $summaryJson)
Write-Output ('[TRIGGER-ROUTE-GATE-SMOKE] evidence_log={0}' -f $evidencePath)
Write-Output ('[TRIGGER-ROUTE-GATE-SMOKE] checks status_allowed={0} incident_allowed={1} status_failed={2} incident_failed={3}' -f $hasStatusAllowed, $hasIncidentAllowed, $hasStatusFailure, $hasIncidentFailure)

if (-not $pass) {
    Write-Output '[TRIGGER-ROUTE-GATE-SMOKE] result=fail'
    exit 1
}

Write-Output '[TRIGGER-ROUTE-GATE-SMOKE] result=pass'
exit 0
