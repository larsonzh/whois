param(
    [string]$DispatchScript = 'tools/test/dispatch_takeover_to_chat.ps1',
    [string]$MainHealthScript = 'tools/test/check_unattended_main_process_health.ps1',
    [string]$PollScript = 'tools/test/poll_agent_tickets.ps1',
    [string]$PromptDoc = 'docs/UNATTENDED_AB_PROMPTS_CN.md',
    [string]$OutDirRoot = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'unattended_exit_result.ps1')
$script:UnhandledExitTag = 'STATUS-TICKET-MINI-REGRESSION'

if (-not $OutDirRoot -or $OutDirRoot.Trim().Length -eq 0) {
    $OutDirRoot = Join-Path $PSScriptRoot '..\..\out\artifacts\status_ticket_mini_regression'
}

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$outDir = Join-Path $OutDirRoot $stamp
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path

function Resolve-RepoPath {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw 'Path must not be empty.'
    }

    $fullPath = if ([System.IO.Path]::IsPathRooted($Path)) {
        [System.IO.Path]::GetFullPath($Path)
    }
    else {
        [System.IO.Path]::GetFullPath((Join-Path $repoRoot $Path))
    }

    if (-not (Test-Path -LiteralPath $fullPath)) {
        throw ("Path not found: {0}" -f $fullPath)
    }

    return $fullPath
}

function Convert-ToRepoRelativePath {
    param([string]$Path)

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $repoRootFull = [System.IO.Path]::GetFullPath($repoRoot)
    if ($fullPath.StartsWith($repoRootFull, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $fullPath.Substring($repoRootFull.Length).TrimStart('\\').Replace('\\', '/')
    }

    return $fullPath.Replace('\\', '/')
}

function Convert-ToSingleLineText {
    param([AllowEmptyString()][string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return ''
    }

    $singleLine = (($Text -split "`r?`n") -join ' ')
    return ([regex]::Replace($singleLine, '\s+', ' ')).Trim()
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
        $sha1.Dispose()
    }

    return ('sf_{0}' -f $hash)
}

function New-SyntheticDispatchEvidence {
    param(
        [string]$StartFilePath,
        [string]$TicketId,
        [string]$EventName
    )

    if ([string]::IsNullOrWhiteSpace($StartFilePath) -or [string]::IsNullOrWhiteSpace($TicketId)) {
        return
    }

    $token = Get-StableStartFileToken -StartFilePath $StartFilePath
    $queueRoot = Join-Path $repoRoot 'out\artifacts\ab_agent_queue'
    $dispatchRoot = Join-Path $queueRoot 'chat_dispatch'
    New-Item -ItemType Directory -Path $queueRoot -Force | Out-Null
    New-Item -ItemType Directory -Path $dispatchRoot -Force | Out-Null

    $triggerLogPath = Join-Path $queueRoot ("takeover_trigger_{0}.log" -f $token)
    $dispatchLogPath = Join-Path $dispatchRoot ("dispatch_{0}.log" -f $token)
    $relayPath = Join-Path $dispatchRoot ("relay_{0}_{1}.md" -f $TicketId, (Get-Date -Format 'yyyyMMdd-HHmmssfff'))
    $nowText = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')

    Add-Content -LiteralPath $triggerLogPath -Encoding utf8 -Value ("[SYNTHETIC] ticket_dispatch id={0} event={1} at={2}" -f $TicketId, $EventName, $nowText)
    Add-Content -LiteralPath $dispatchLogPath -Encoding utf8 -Value ("[SYNTHETIC] relay_created ticket={0} event={1} at={2}" -f $TicketId, $EventName, $nowText)
    Set-Content -LiteralPath $relayPath -Encoding utf8 -Value (("# synthetic relay`nticket: {0}`nevent: {1}`ncreated_at: {2}" -f $TicketId, $EventName, $nowText))
}

function Get-CaseResult {
    param(
        [string]$Name,
        [bool]$Pass,
        [string]$Reason
    )

    return [pscustomobject]@{
        case = $Name
        pass = [bool]$Pass
        reason = $Reason
    }
}

function Get-FingerprintProbeText {
    param([AllowEmptyString()][string]$Text)

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

$dispatchPath = Resolve-RepoPath -Path $DispatchScript
$mainHealthPath = Resolve-RepoPath -Path $MainHealthScript
$pollPath = Resolve-RepoPath -Path $PollScript
$promptDocPath = Resolve-RepoPath -Path $PromptDoc
$companionPath = Resolve-RepoPath -Path 'tools/test/unattended_ab_companion.ps1'

$dispatchText = Get-Content -LiteralPath $dispatchPath -Raw -Encoding utf8
$mainHealthText = Get-Content -LiteralPath $mainHealthPath -Raw -Encoding utf8
$pollText = Get-Content -LiteralPath $pollPath -Raw -Encoding utf8
$promptDocText = Get-Content -LiteralPath $promptDocPath -Raw -Encoding utf8
$companionText = Get-Content -LiteralPath $companionPath -Raw -Encoding utf8

$results = New-Object 'System.Collections.Generic.List[object]'

# Case 1: healthy status ticket should map to continue-watch-only guidance.
$healthyHasSummary = $mainHealthText.Contains('B main process is alive; treat this status ticket as normal monitoring and do not infer a B restart from stale history.')
$healthyHasAction = $mainHealthText.Contains('$recommendedAction = ''continue-watch-only''')
$healthyPass = ($healthyHasSummary -and $healthyHasAction)
$healthyReason = if ($healthyPass) { 'healthy-status-ticket-guidance-present' } else { 'missing-healthy-status-ticket-guidance' }
[void]$results.Add((Get-CaseResult -Name 'healthy-status-ticket' -Pass $healthyPass -Reason $healthyReason))

# Case 2: stale latest_b_exit must be identified explicitly and surfaced in output verdict.
$staleHasSignal = $mainHealthText.Contains('$staleExitEvidence = ([bool]$bExitEvidence.Available -and (-not [bool]$reasonMatched))')
$staleHasOutput = $mainHealthText.Contains('stale_exit_evidence = [bool]$staleExitEvidence')
$stalePass = ($staleHasSignal -and $staleHasOutput)
$staleReason = if ($stalePass) { 'stale-latest-b-exit-signal-present' } else { 'missing-stale-latest-b-exit-signal' }
[void]$results.Add((Get-CaseResult -Name 'stale-latest-b-exit' -Pass $stalePass -Reason $staleReason))

# Case 3: low-disturb response must enforce two-line healthy reply contract.
$lowDisturbEnTwoLine = $dispatchText.Contains('reply with only two lines: "Running normal" and "handled_at: YYYY-MM-DD HH:mm:ss"')
$lowDisturbHasHandledAtToken = $dispatchText.Contains('handled_at: YYYY-MM-DD HH:mm:ss')
$lowDisturbHasLowDisturbToken = $dispatchText.Contains('[LOW-DISTURB]')
$lowDisturbPass = ($lowDisturbEnTwoLine -and $lowDisturbHasHandledAtToken -and $lowDisturbHasLowDisturbToken)
$lowDisturbReason = if ($lowDisturbPass) { 'low-disturb-two-line-contract-present' } else { 'missing-low-disturb-two-line-contract' }
[void]$results.Add((Get-CaseResult -Name 'low-disturb-two-line-reply' -Pass $lowDisturbPass -Reason $lowDisturbReason))

# Case 4: do-not-create-non-tmp-script guardrail must be present in runtime prompt channels.
$dispatchNoNonTmp = $dispatchText.Contains('do not create new scripts outside tmp')
$promptNoNonTmp = [regex]::IsMatch($promptDocText, 'chat_heartbeat\*\.jsonl.*handled.*tmp', [System.Text.RegularExpressions.RegexOptions]::Singleline)
$noNonTmpPass = ($dispatchNoNonTmp -and $promptNoNonTmp)
$noNonTmpReason = if ($noNonTmpPass) { 'no-non-tmp-script-guardrail-present' } else { 'missing-no-non-tmp-script-guardrail' }
[void]$results.Add((Get-CaseResult -Name 'no-non-tmp-script-creation' -Pass $noNonTmpPass -Reason $noNonTmpReason))

# Case 5: companion stage context must fall back across run_dir anchors.
$companionHasRunDirFallback = $companionText.Contains("Get-LatestAnchorValueFromNoteText -Notes `$sessionNotes -Key 'run_dir'")
$companionHasBRunDirFallback = $companionText.Contains("Get-LatestAnchorValueFromNoteText -Notes `$sessionNotes -Key 'b_run_dir'")
$companionHasCurrentStageRunDirFallback = $companionText.Contains("Get-LatestAnchorValueFromNoteText -Notes `$sessionNotes -Key 'current_stage_run_dir'")
$companionHasStageContextResolver = $companionText.Contains('function Get-CurrentStageContext')
$companionFallbackPass = ($companionHasStageContextResolver -and $companionHasRunDirFallback -and $companionHasBRunDirFallback -and $companionHasCurrentStageRunDirFallback)
$companionFallbackReason = if ($companionFallbackPass) { 'companion-run-dir-fallback-present' } else { 'missing-companion-run-dir-fallback' }
[void]$results.Add((Get-CaseResult -Name 'companion-run-dir-fallback' -Pass $companionFallbackPass -Reason $companionFallbackReason))

# Case 6: poll output must expose triage summary contract for fast diagnosis.
$triageSummaryHasTopCause = $pollText.Contains('top_cause = $triageTopCause')
$triageSummaryHasEvidenceHint = $pollText.Contains('evidence_hint = $triageEvidenceHint')
$triageSummaryHasActionHint = $pollText.Contains('action_hint = $triageActionHint')
$triageSummaryHasConfidence = $pollText.Contains('confidence = [double]$triageConfidence')
$triageLogTopCause = $pollText.Contains("[AB-TICKET-POLL] triage_top_cause={0} triage_confidence={1}")
$triageLogEvidence = $pollText.Contains("[AB-TICKET-POLL] triage_evidence_hint={0}")
$triageLogAction = $pollText.Contains("[AB-TICKET-POLL] triage_action_hint={0}")
$triagePass = ($triageSummaryHasTopCause -and $triageSummaryHasEvidenceHint -and $triageSummaryHasActionHint -and $triageSummaryHasConfidence -and $triageLogTopCause -and $triageLogEvidence -and $triageLogAction)
$triageReason = if ($triagePass) { 'poll-triage-summary-contract-present' } else { 'missing-poll-triage-summary-contract' }
[void]$results.Add((Get-CaseResult -Name 'poll-triage-summary-contract' -Pass $triagePass -Reason $triageReason))

# Case 7: poll runtime JSON must surface triage_summary fields for downstream automation.
$pollRuntimeStartFile = Resolve-RepoPath -Path 'testdata/unattended_start/smoke/unattended_ab_start_status_ticket_smoke.md'
$pollRuntimeArgs = @(
    '-NoProfile',
    '-ExecutionPolicy',
    'Bypass',
    '-File',
    $pollPath,
    '-StartFile',
    $pollRuntimeStartFile,
    '-Last',
    '20',
    '-AsJson'
)
$pollRuntimeRaw = & powershell @pollRuntimeArgs 2>&1 | Out-String
$pollRuntimeJson = $pollRuntimeRaw | ConvertFrom-Json -ErrorAction Stop
$pollRuntimeHasTriagedSummary = ($pollRuntimeJson.PSObject.Properties.Name -contains 'triage_summary')
$pollRuntimeSummary = if ($pollRuntimeHasTriagedSummary) { $pollRuntimeJson.triage_summary } else { $null }
$pollRuntimeHasTopCause = ($null -ne $pollRuntimeSummary -and $pollRuntimeSummary.PSObject.Properties.Name -contains 'top_cause')
$pollRuntimeHasEvidenceHint = ($null -ne $pollRuntimeSummary -and $pollRuntimeSummary.PSObject.Properties.Name -contains 'evidence_hint')
$pollRuntimeHasActionHint = ($null -ne $pollRuntimeSummary -and $pollRuntimeSummary.PSObject.Properties.Name -contains 'action_hint')
$pollRuntimeHasConfidence = ($null -ne $pollRuntimeSummary -and $pollRuntimeSummary.PSObject.Properties.Name -contains 'confidence')
$pollRuntimeConfidenceOk = ($pollRuntimeHasConfidence -and ([double]$pollRuntimeSummary.confidence -ge 0.0) -and ([double]$pollRuntimeSummary.confidence -le 1.0))
$pollRuntimePass = ($pollRuntimeHasTriagedSummary -and $pollRuntimeHasTopCause -and $pollRuntimeHasEvidenceHint -and $pollRuntimeHasActionHint -and $pollRuntimeHasConfidence -and $pollRuntimeConfidenceOk)
$pollRuntimeReason = if ($pollRuntimePass) { 'poll-triage-runtime-json-present' } else { 'missing-poll-triage-runtime-json' }
[void]$results.Add((Get-CaseResult -Name 'poll-triage-runtime-json' -Pass $pollRuntimePass -Reason $pollRuntimeReason))

# Case 8: runtime poll ordering must place route guard first for status-ticket execution.
$pollOrderQueue = Join-Path $outDir 'poll_next_command_order_queue.jsonl'
$pollOrderTicket = [ordered]@{
    schema = 'AB_AGENT_TICKET_V1'
    ticket_id = 'T-MINI-ORDER-' + $stamp
    created_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    source = 'status-ticket-mini-regression'
    event = 'running-status-report'
    severity = 'info'
    requires_confirmation = $false
    start_file = $pollRuntimeStartFile
    queue_path = $pollOrderQueue
    session_final_status = 'RUNNING'
    a_final_status = 'RUNNING'
    b_final_status = 'RUNNING'
    run_dir = 'out/artifacts/dev_verify_multiround/20260609-195321'
    detail = 'status order probe'
    recommended_action = 'probe'
    preferred_stage = 'B'
    self_healable = $false
    non_recoverable_env = $false
}
Set-Content -LiteralPath $pollOrderQueue -Encoding utf8 -Value (($pollOrderTicket | ConvertTo-Json -Compress -Depth 10))

$pollOrderArgs = @(
    '-NoProfile',
    '-ExecutionPolicy',
    'Bypass',
    '-File',
    $pollPath,
    '-StartFile',
    $pollRuntimeStartFile,
    '-QueuePath',
    $pollOrderQueue,
    '-IncludeStatusReports',
    '-Last',
    '20',
    '-AsJson'
)
$pollOrderRaw = & powershell @pollOrderArgs 2>&1 | Out-String
$pollOrderJson = $pollOrderRaw | ConvertFrom-Json -ErrorAction Stop
$pollOrderRows = @($pollOrderJson.rows)
$pollOrderRow = if ($pollOrderRows.Count -gt 0) { $pollOrderRows[0] } else { $null }
$pollOrderHasOrder = ($null -ne $pollOrderRow -and ($pollOrderRow.PSObject.Properties.Name -contains 'next_command_order'))
$pollOrderNames = if ($pollOrderHasOrder) { @($pollOrderRow.next_command_order) } else { @() }
$pollOrderPass = ($pollOrderHasOrder -and $pollOrderNames.Count -ge 2 -and $pollOrderNames[0] -eq 'route_guard_command' -and $pollOrderNames[1] -eq 'business_command')
$pollOrderReason = if ($pollOrderPass) { 'poll-next-command-order-runtime-present' } else { 'missing-poll-next-command-order-runtime' }
[void]$results.Add((Get-CaseResult -Name 'poll-next-command-order-runtime' -Pass $pollOrderPass -Reason $pollOrderReason))

# Case 8: notice/manual events must also expose command order with route guard first.
$pollNoticeQueue = Join-Path $outDir 'poll_notice_command_order_queue.jsonl'
$pollNoticeTicket = [ordered]@{
    schema = 'AB_AGENT_TICKET_V1'
    ticket_id = 'T-MINI-NOTICE-' + $stamp
    created_at = (Get-Date).AddMinutes(10).ToString('yyyy-MM-dd HH:mm:ss')
    source = 'status-ticket-mini-regression'
    event = 'budget-exhausted-stop'
    severity = 'high'
    requires_confirmation = $false
    start_file = $pollRuntimeStartFile
    queue_path = $pollNoticeQueue
    session_final_status = 'BLOCKED'
    a_final_status = 'PASS'
    b_final_status = 'FAIL'
    run_dir = 'out/artifacts/dev_verify_multiround/20260609-195321'
    detail = 'notice order probe'
    recommended_action = 'probe'
    preferred_stage = 'B'
    self_healable = $false
    non_recoverable_env = $false
    budget_exhausted = $true
}
Set-Content -LiteralPath $pollNoticeQueue -Encoding utf8 -Value (($pollNoticeTicket | ConvertTo-Json -Compress -Depth 10))
New-SyntheticDispatchEvidence -StartFilePath $pollRuntimeStartFile -TicketId ([string]$pollNoticeTicket.ticket_id) -EventName ([string]$pollNoticeTicket.event)

$pollNoticeArgs = @(
    '-NoProfile',
    '-ExecutionPolicy',
    'Bypass',
    '-File',
    $pollPath,
    '-StartFile',
    $pollRuntimeStartFile,
    '-QueuePath',
    $pollNoticeQueue,
    '-Last',
    '20',
    '-AsJson'
)
$pollNoticeRaw = & powershell @pollNoticeArgs 2>&1 | Out-String
$pollNoticeJson = $pollNoticeRaw | ConvertFrom-Json -ErrorAction Stop
$pollNoticeRows = @($pollNoticeJson.rows)
$pollNoticeRow = @($pollNoticeRows | Where-Object { [string]$_.event -eq 'budget-exhausted-stop' } | Select-Object -First 1)
$pollNoticeTarget = if ($pollNoticeRow.Count -gt 0) { $pollNoticeRow[0] } else { $null }
$pollNoticeHasOrder = ($null -ne $pollNoticeTarget -and ($pollNoticeTarget.PSObject.Properties.Name -contains 'next_command_order'))
$pollNoticeNames = if ($pollNoticeHasOrder) { @($pollNoticeTarget.next_command_order) } else { @() }
$pollNoticePass = ($pollNoticeHasOrder -and $pollNoticeNames.Count -ge 2 -and $pollNoticeNames[0] -eq 'route_guard_command' -and $pollNoticeNames[1] -eq 'business_command')
$pollNoticeReason = if ($pollNoticePass) { 'poll-notice-command-order-runtime-present' } else { 'missing-poll-notice-command-order-runtime' }
[void]$results.Add((Get-CaseResult -Name 'poll-notice-command-order-runtime' -Pass $pollNoticePass -Reason $pollNoticeReason))

# Case 9: manual-wait notice should map to route guard first and keep continue-watch in order list.
$pollManualQueue = Join-Path $outDir 'poll_manual_command_order_queue.jsonl'
$pollManualTicket = [ordered]@{
    schema = 'AB_AGENT_TICKET_V1'
    ticket_id = 'T-MINI-MANUAL-' + $stamp
    created_at = (Get-Date).AddMinutes(11).ToString('yyyy-MM-dd HH:mm:ss')
    source = 'status-ticket-mini-regression'
    event = 'manual-wait-paused'
    severity = 'high'
    requires_confirmation = $false
    start_file = $pollRuntimeStartFile
    queue_path = $pollManualQueue
    session_final_status = 'BLOCKED'
    a_final_status = 'PASS'
    b_final_status = 'FAIL'
    run_dir = 'out/artifacts/dev_verify_multiround/20260609-195321'
    detail = 'manual wait order probe'
    recommended_action = 'probe'
    preferred_stage = 'B'
    self_healable = $false
    non_recoverable_env = $false
}
Set-Content -LiteralPath $pollManualQueue -Encoding utf8 -Value (($pollManualTicket | ConvertTo-Json -Compress -Depth 10))
New-SyntheticDispatchEvidence -StartFilePath $pollRuntimeStartFile -TicketId ([string]$pollManualTicket.ticket_id) -EventName ([string]$pollManualTicket.event)

$pollManualArgs = @(
    '-NoProfile',
    '-ExecutionPolicy',
    'Bypass',
    '-File',
    $pollPath,
    '-StartFile',
    $pollRuntimeStartFile,
    '-QueuePath',
    $pollManualQueue,
    '-Last',
    '20',
    '-AsJson'
)
$pollManualRaw = & powershell @pollManualArgs 2>&1 | Out-String
$pollManualJson = $pollManualRaw | ConvertFrom-Json -ErrorAction Stop
$pollManualRows = @($pollManualJson.rows)
$pollManualRow = @($pollManualRows | Where-Object { [string]$_.event -eq 'manual-wait-paused' } | Select-Object -First 1)
$pollManualTarget = if ($pollManualRow.Count -gt 0) { $pollManualRow[0] } else { $null }
$pollManualHasOrder = ($null -ne $pollManualTarget -and ($pollManualTarget.PSObject.Properties.Name -contains 'next_command_order'))
$pollManualNames = if ($pollManualHasOrder) { @($pollManualTarget.next_command_order) } else { @() }
$pollManualHasContinueWatch = ($pollManualNames -contains 'continue_watch_command')
$pollManualPass = ($pollManualHasOrder -and $pollManualNames.Count -ge 2 -and $pollManualNames[0] -eq 'route_guard_command' -and $pollManualNames[1] -eq 'business_command' -and $pollManualHasContinueWatch)
$pollManualReason = if ($pollManualPass) { 'poll-manual-command-order-runtime-present' } else { 'missing-poll-manual-command-order-runtime' }
[void]$results.Add((Get-CaseResult -Name 'poll-manual-command-order-runtime' -Pass $pollManualPass -Reason $pollManualReason))

# Case 10: fingerprint normalization must collapse the same issue with different line numbers to one token.
$fingerprintProbeA = 'src/core/net.c:42: conflicting types for wc_retry_connect'
$fingerprintProbeB = 'src/core/net.c:57: conflicting types for wc_retry_connect'
$fingerprintProbeNormalizedA = Get-FingerprintProbeText -Text $fingerprintProbeA
$fingerprintProbeNormalizedB = Get-FingerprintProbeText -Text $fingerprintProbeB
$fingerprintProbePass = ($fingerprintProbeNormalizedA -eq $fingerprintProbeNormalizedB -and $fingerprintProbeNormalizedA -eq '<source-location> conflicting types')
$fingerprintProbeReason = if ($fingerprintProbePass) { 'failure-fingerprint-normalization-present' } else { 'missing-failure-fingerprint-normalization' }
[void]$results.Add((Get-CaseResult -Name 'failure-fingerprint-normalization' -Pass $fingerprintProbePass -Reason $fingerprintProbeReason))

$failedCases = @($results | Where-Object { -not [bool]$_.pass })
$pass = ($failedCases.Count -eq 0)

$summary = [pscustomobject]@{
    schema = 'AB_STATUS_TICKET_MINI_REGRESSION_V1'
    generated_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    pass = [bool]$pass
    total_cases = $results.Count
    failed_cases = $failedCases.Count
    inputs = [pscustomobject]@{
        dispatch_script = (Convert-ToRepoRelativePath -Path $dispatchPath)
        main_health_script = (Convert-ToRepoRelativePath -Path $mainHealthPath)
        poll_script = (Convert-ToRepoRelativePath -Path $pollPath)
        prompt_doc = (Convert-ToRepoRelativePath -Path $promptDocPath)
    }
    cases = @($results.ToArray())
}

$summaryJson = Join-Path $outDir 'summary.json'
$summaryTxt = Join-Path $outDir 'summary.txt'
$summary | ConvertTo-Json -Depth 8 | Out-File -LiteralPath $summaryJson -Encoding utf8
$summary | Format-List | Out-String | Out-File -LiteralPath $summaryTxt -Encoding utf8

Write-Output ('[STATUS-TICKET-MINI] out_dir={0}' -f $outDir)
Write-Output ('[STATUS-TICKET-MINI] summary_json={0}' -f $summaryJson)
Write-Output ('[STATUS-TICKET-MINI] summary_txt={0}' -f $summaryTxt)
foreach ($entry in $results.ToArray()) {
    Write-Output ('[STATUS-TICKET-MINI] case={0} pass={1} reason={2}' -f [string]$entry.case, [bool]$entry.pass, [string]$entry.reason)
}

if (-not $pass) {
    Write-Output '[STATUS-TICKET-MINI] result=fail'
    Exit-UnattendedFailure -Tag $script:UnhandledExitTag -Reason 'status-ticket-mini-regression failed' -ExitCode 1
}

Write-Output '[STATUS-TICKET-MINI] result=pass'
exit 0
