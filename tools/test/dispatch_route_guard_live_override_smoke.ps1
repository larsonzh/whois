param(
    [string]$StartFile = 'testdata/unattended_start/active/unattended_ab_start_20261031-20261115.md',
    [string]$OutDirRoot = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'unattended_exit_result.ps1')
$script:UnhandledExitTag = 'DISPATCH-ROUTE-GUARD-LIVE-OVERRIDE-SMOKE'

function Set-KeyValueLine {
    param(
        [string]$Text,
        [string]$Key,
        [string]$Value
    )

    $pattern = '(?m)^{0}=.*$' -f [regex]::Escape($Key)
    $replacement = '{0}={1}' -f $Key, $Value
    if ($Text -match $pattern) {
        return [regex]::Replace($Text, $pattern, $replacement)
    }

    return $Text.TrimEnd("`r", "`n") + "`n" + $replacement + "`n"
}

function Write-Utf8BomText {
    param(
        [string]$Path,
        [string]$Text
    )

    $encoding = New-Object System.Text.UTF8Encoding($true)
    [System.IO.File]::WriteAllText($Path, $Text, $encoding)
}

function Write-Utf8BomLines {
    param(
        [string]$Path,
        [string[]]$Lines
    )

    $encoding = New-Object System.Text.UTF8Encoding($true)
    [System.IO.File]::WriteAllLines($Path, $Lines, $encoding)
}

if ([string]::IsNullOrWhiteSpace($OutDirRoot)) {
    $OutDirRoot = Join-Path $PSScriptRoot '..\..\out\artifacts\dispatch_route_guard_live_override_smoke'
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

$dispatchScript = Join-Path $repoRoot 'tools\test\dispatch_takeover_to_chat.ps1'
if (-not (Test-Path -LiteralPath $dispatchScript)) {
    throw ('dispatch script not found: {0}' -f $dispatchScript)
}

$tmpStartFile = Join-Path $outDir 'startfile_probe.md'
Copy-Item -LiteralPath $resolvedStartFile -Destination $tmpStartFile -Force

$startRaw = Get-Content -LiteralPath $tmpStartFile -Raw -Encoding utf8
$startRaw = Set-KeyValueLine -Text $startRaw -Key 'AI_CHAT_DISPATCH_OPEN_EDITOR' -Value 'false'
$startRaw = Set-KeyValueLine -Text $startRaw -Key 'AI_CHAT_DISPATCH_USE_CLIPBOARD' -Value 'false'
$startRaw = Set-KeyValueLine -Text $startRaw -Key 'AI_CHAT_DISPATCH_SENDER_PRIMARY' -Value 'none'
$startRaw = Set-KeyValueLine -Text $startRaw -Key 'AI_CHAT_DISPATCH_USE_IPC' -Value 'false'
$startRaw = Set-KeyValueLine -Text $startRaw -Key 'AI_CHAT_DISPATCH_USE_PY_SENDER' -Value 'false'
$startRaw = Set-KeyValueLine -Text $startRaw -Key 'AI_CHAT_DISPATCH_USE_AHK' -Value 'false'
Write-Utf8BomText -Path $tmpStartFile -Text $startRaw

$tmpQueue = Join-Path $outDir 'queue_probe.jsonl'
Write-Utf8BomText -Path $tmpQueue -Text ''

$liveRoutePath = Join-Path $outDir 'live_route.json'
$liveRoutePayload = [ordered]@{
    route = [ordered]@{
        classification = 'incident-auto-resume-code-fix'
    }
}
Write-Utf8BomText -Path $liveRoutePath -Text (($liveRoutePayload | ConvertTo-Json -Depth 5) + "`n")

$liveRouteCommand = 'powershell -NoProfile -Command "Get-Content -LiteralPath ''' + $liveRoutePath.Replace('''', '''''') + ''' -Raw"'

$briefLivePath = Join-Path $outDir 'brief_probe_live.md'
$briefLiveLines = @(
    '# AB Takeover Brief',
    '',
    'ticket_id=T-DISPATCH-LIVE-OVERRIDE-' + $stamp,
    'event=incident-captured',
    'a_final_status=PASS',
    'b_final_status=FAIL',
    'session_final_status=BLOCKED',
    'preferred_stage=B',
    'route_guard_expected=event-review',
    ('route_guard_command={0}' -f $liveRouteCommand)
)
Write-Utf8BomLines -Path $briefLivePath -Lines $briefLiveLines

$ticketIdLive = 'T-DISPATCH-LIVE-OVERRIDE-' + $stamp
$dispatchOutputLive = @(& powershell -NoProfile -ExecutionPolicy Bypass -File $dispatchScript -TicketId $ticketIdLive -TicketEvent 'incident-captured' -StartFile $tmpStartFile -QueuePath $tmpQueue -BriefPath $briefLivePath -NoOpenEditor -SkipClipboard 2>&1 | ForEach-Object { [string]$_ })

$startToken = Get-StableStartFileToken -StartFilePath $tmpStartFile
$dispatchRoot = Join-Path $repoRoot 'out\artifacts\ab_agent_queue\chat_dispatch'
$dispatchLogPath = Join-Path $dispatchRoot ('dispatch_{0}.log' -f $startToken)
$latestStatePath = Join-Path $dispatchRoot ('latest_relay_{0}.json' -f $startToken)

if (-not (Test-Path -LiteralPath $dispatchLogPath)) {
    throw ('dispatch log not found: {0}' -f $dispatchLogPath)
}
if (-not (Test-Path -LiteralPath $latestStatePath)) {
    throw ('latest relay state not found: {0}' -f $latestStatePath)
}

$latestStateLive = Get-Content -LiteralPath $latestStatePath -Raw -Encoding utf8 | ConvertFrom-Json
$relayPathRelLive = [string]$latestStateLive.relay_path
$relayPathLive = if ([System.IO.Path]::IsPathRooted($relayPathRelLive)) {
    [System.IO.Path]::GetFullPath($relayPathRelLive)
}
else {
    [System.IO.Path]::GetFullPath((Join-Path $repoRoot $relayPathRelLive))
}

if (-not (Test-Path -LiteralPath $relayPathLive)) {
    throw ('relay path not found: {0}' -f $relayPathLive)
}

$relayLinesLive = @(Get-Content -LiteralPath $relayPathLive -Encoding utf8)

$badLiveRouteCommand = 'powershell -NoProfile -ExecutionPolicy Bypass -Command "exit 7"'
$briefFallbackPath = Join-Path $outDir 'brief_probe_fallback.md'
$briefFallbackLines = @(
    '# AB Takeover Brief',
    '',
    'ticket_id=T-DISPATCH-LIVE-FALLBACK-' + $stamp,
    'event=incident-captured',
    'a_final_status=PASS',
    'b_final_status=FAIL',
    'session_final_status=BLOCKED',
    'preferred_stage=B',
    'route_guard_expected=event-review',
    ('route_guard_command={0}' -f $badLiveRouteCommand)
)
Write-Utf8BomLines -Path $briefFallbackPath -Lines $briefFallbackLines

$ticketIdFallback = 'T-DISPATCH-LIVE-FALLBACK-' + $stamp
$dispatchOutputFallback = @(& powershell -NoProfile -ExecutionPolicy Bypass -File $dispatchScript -TicketId $ticketIdFallback -TicketEvent 'incident-captured' -StartFile $tmpStartFile -QueuePath $tmpQueue -BriefPath $briefFallbackPath -NoOpenEditor -SkipClipboard 2>&1 | ForEach-Object { [string]$_ })

$dispatchOutputPath = Join-Path $outDir 'dispatch_output.log'
@(
    '## live_override_output',
    @($dispatchOutputLive),
    '',
    '## fallback_output',
    @($dispatchOutputFallback)
) | Out-File -LiteralPath $dispatchOutputPath -Encoding utf8

$latestStateFallback = Get-Content -LiteralPath $latestStatePath -Raw -Encoding utf8 | ConvertFrom-Json
$relayPathRelFallback = [string]$latestStateFallback.relay_path
$relayPathFallback = if ([System.IO.Path]::IsPathRooted($relayPathRelFallback)) {
    [System.IO.Path]::GetFullPath($relayPathRelFallback)
}
else {
    [System.IO.Path]::GetFullPath((Join-Path $repoRoot $relayPathRelFallback))
}

if (-not (Test-Path -LiteralPath $relayPathFallback)) {
    throw ('relay path not found: {0}' -f $relayPathFallback)
}

$dispatchLogLines = @(Get-Content -LiteralPath $dispatchLogPath -Encoding utf8)
$relayLinesFallback = @(Get-Content -LiteralPath $relayPathFallback -Encoding utf8)

$hasOverrideLog = $false
foreach ($line in $dispatchLogLines) {
    if ($line -match [regex]::Escape($ticketIdLive) -and $line -match 'route_guard_expected_overridden' -and $line -match 'brief=event-review' -and $line -match 'live=incident-auto-resume-code-fix') {
        $hasOverrideLog = $true
        break
    }
}

$hasFallbackProbeFailedLog = $false
foreach ($line in $dispatchLogLines) {
    if ($line -match [regex]::Escape($ticketIdFallback) -and $line -match 'route_guard_live_probe_failed') {
        $hasFallbackProbeFailedLog = $true
        break
    }
}

$hasRelaySourceLive = $false
$hasRelayLiveClassification = $false
foreach ($line in $relayLinesLive) {
    if ($line -eq 'route_guard_expected_source=live') {
        $hasRelaySourceLive = $true
    }
    if ($line -eq 'route_guard_live_classification=incident-auto-resume-code-fix') {
        $hasRelayLiveClassification = $true
    }
}

$hasRelaySourceBriefFallback = $false
$hasRelayLiveClassificationFallback = $false
foreach ($line in $relayLinesFallback) {
    if ($line -eq 'route_guard_expected_source=brief') {
        $hasRelaySourceBriefFallback = $true
    }
    if ($line -eq 'route_guard_live_classification=') {
        $hasRelayLiveClassificationFallback = $true
    }
}

$dispatchMessageTextLive = [string]$latestStateLive.dispatch_message
$dispatchMessageLowerLive = $dispatchMessageTextLive.ToLowerInvariant()
$hasCodeFixDispatchTemplate = (
    $dispatchMessageTextLive -match 'CODE-FIX dedicated flow' -or
    $dispatchMessageTextLive -match '代码修复专用流程'
)
$hasEventReviewDispatchTemplate = (
    $dispatchMessageLowerLive -match 'event-review flow' -or
    $dispatchMessageLowerLive -match 'event-review low-disturb' -or
    $dispatchMessageTextLive -match '事件评审流程' -or
    $dispatchMessageTextLive -match '事件评审-低干扰文本回执流程'
)

$dispatchMessageTextFallback = [string]$latestStateFallback.dispatch_message
$dispatchMessageLowerFallback = $dispatchMessageTextFallback.ToLowerInvariant()
$hasFallbackEventReviewDispatchTemplate = (
    $dispatchMessageLowerFallback -match 'event-review flow' -or
    $dispatchMessageLowerFallback -match 'event-review low-disturb' -or
    $dispatchMessageTextFallback -match '事件评审流程' -or
    $dispatchMessageTextFallback -match '事件评审-低干扰文本回执流程'
)
$hasFallbackCodeFixDispatchTemplate = (
    $dispatchMessageTextFallback -match 'CODE-FIX dedicated flow' -or
    $dispatchMessageTextFallback -match '代码修复专用流程'
)

$pass = (
    [string]$latestStateLive.route_guard_expected -eq 'incident-auto-resume-code-fix' -and
    [string]$latestStateLive.route_guard_expected_source -eq 'live' -and
    [string]$latestStateLive.route_guard_live_classification -eq 'incident-auto-resume-code-fix' -and
    [string]$latestStateLive.sender_mode -eq 'none' -and
    $hasOverrideLog -and
    $hasRelaySourceLive -and
    $hasRelayLiveClassification -and
    $hasCodeFixDispatchTemplate -and
    -not $hasEventReviewDispatchTemplate -and
    [string]$latestStateFallback.route_guard_expected -eq 'event-review' -and
    [string]$latestStateFallback.route_guard_expected_source -eq 'brief' -and
    [string]$latestStateFallback.route_guard_live_classification -eq '' -and
    [string]$latestStateFallback.sender_mode -eq 'none' -and
    $hasFallbackProbeFailedLog -and
    $hasRelaySourceBriefFallback -and
    $hasRelayLiveClassificationFallback -and
    $hasFallbackEventReviewDispatchTemplate -and
    -not $hasFallbackCodeFixDispatchTemplate
)

$summary = [ordered]@{
    schema = 'AB_DISPATCH_ROUTE_GUARD_LIVE_OVERRIDE_SMOKE_V1'
    generated_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    source_start_file = $resolvedStartFile
    temp_start_file = $tmpStartFile
    temp_queue = $tmpQueue
    brief_path_live = $briefLivePath
    brief_path_fallback = $briefFallbackPath
    live_route_path = $liveRoutePath
    fallback_route_command = $badLiveRouteCommand
    dispatch_output = $dispatchOutputPath
    dispatch_log_path = $dispatchLogPath
    latest_state_path = $latestStatePath
    relay_path_live = $relayPathLive
    relay_path_fallback = $relayPathFallback
    ticket_id_live = $ticketIdLive
    ticket_id_fallback = $ticketIdFallback
    checks = [ordered]@{
        latest_state_expected_live_override = ([string]$latestStateLive.route_guard_expected -eq 'incident-auto-resume-code-fix')
        latest_state_expected_source_live = ([string]$latestStateLive.route_guard_expected_source -eq 'live')
        latest_state_live_classification = ([string]$latestStateLive.route_guard_live_classification -eq 'incident-auto-resume-code-fix')
        sender_mode_none = ([string]$latestStateLive.sender_mode -eq 'none')
        override_log_written = $hasOverrideLog
        relay_expected_source_live = $hasRelaySourceLive
        relay_live_classification = $hasRelayLiveClassification
        dispatch_message_code_fix_template = $hasCodeFixDispatchTemplate
        dispatch_message_event_review_template = $hasEventReviewDispatchTemplate
        fallback_expected_brief = ([string]$latestStateFallback.route_guard_expected -eq 'event-review')
        fallback_expected_source_brief = ([string]$latestStateFallback.route_guard_expected_source -eq 'brief')
        fallback_live_classification_empty = ([string]$latestStateFallback.route_guard_live_classification -eq '')
        fallback_probe_failed_log_written = $hasFallbackProbeFailedLog
        fallback_relay_expected_source_brief = $hasRelaySourceBriefFallback
        fallback_relay_live_classification_empty = $hasRelayLiveClassificationFallback
        fallback_dispatch_message_event_review_template = $hasFallbackEventReviewDispatchTemplate
        fallback_dispatch_message_code_fix_template = $hasFallbackCodeFixDispatchTemplate
    }
    pass = $pass
}

$summaryJson = Join-Path $outDir 'summary.json'
$summaryTxt = Join-Path $outDir 'summary.txt'
$summary | ConvertTo-Json -Depth 8 | Out-File -LiteralPath $summaryJson -Encoding utf8
$summary | Format-List | Out-String | Out-File -LiteralPath $summaryTxt -Encoding utf8

Write-Output ('[DISPATCH-LIVE-OVERRIDE-SMOKE] out_dir={0}' -f $outDir)
Write-Output ('[DISPATCH-LIVE-OVERRIDE-SMOKE] summary_json={0}' -f $summaryJson)
Write-Output ('[DISPATCH-LIVE-OVERRIDE-SMOKE] dispatch_log={0}' -f $dispatchLogPath)
Write-Output ('[DISPATCH-LIVE-OVERRIDE-SMOKE] checks expected={0} source={1} live={2} sender_none={3} override_log={4} relay_source={5} relay_live={6} code_fix_msg={7} event_review_msg={8} fallback_expected={9} fallback_source={10} fallback_probe_failed={11} fallback_event_review_msg={12}' -f ([string]$latestStateLive.route_guard_expected -eq 'incident-auto-resume-code-fix'), ([string]$latestStateLive.route_guard_expected_source -eq 'live'), ([string]$latestStateLive.route_guard_live_classification -eq 'incident-auto-resume-code-fix'), ([string]$latestStateLive.sender_mode -eq 'none'), $hasOverrideLog, $hasRelaySourceLive, $hasRelayLiveClassification, $hasCodeFixDispatchTemplate, $hasEventReviewDispatchTemplate, ([string]$latestStateFallback.route_guard_expected -eq 'event-review'), ([string]$latestStateFallback.route_guard_expected_source -eq 'brief'), $hasFallbackProbeFailedLog, $hasFallbackEventReviewDispatchTemplate)

if (-not $pass) {
    Write-Output '[DISPATCH-LIVE-OVERRIDE-SMOKE] result=fail'
    Exit-UnattendedFailure -Tag $script:UnhandledExitTag -Reason 'dispatch-route-guard-live-override-smoke failed' -ExitCode 1
}

Write-Output '[DISPATCH-LIVE-OVERRIDE-SMOKE] result=pass'
exit 0