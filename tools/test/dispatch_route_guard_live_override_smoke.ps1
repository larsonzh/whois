param(
    [string]$StartFile = 'testdata/unattended_start/active/unattended_ab_start_20261031-20261115.md',
    [string]$OutDirRoot = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

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

$briefPath = Join-Path $outDir 'brief_probe.md'
$briefLines = @(
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
Write-Utf8BomLines -Path $briefPath -Lines $briefLines

$ticketId = 'T-DISPATCH-LIVE-OVERRIDE-' + $stamp
$dispatchOutput = @(& powershell -NoProfile -ExecutionPolicy Bypass -File $dispatchScript -TicketId $ticketId -TicketEvent 'incident-captured' -StartFile $tmpStartFile -QueuePath $tmpQueue -BriefPath $briefPath -NoOpenEditor -SkipClipboard 2>&1 | ForEach-Object { [string]$_ })
$dispatchOutputPath = Join-Path $outDir 'dispatch_output.log'
$dispatchOutput | Out-File -LiteralPath $dispatchOutputPath -Encoding utf8

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

$latestState = Get-Content -LiteralPath $latestStatePath -Raw -Encoding utf8 | ConvertFrom-Json
$relayPathRel = [string]$latestState.relay_path
$relayPath = if ([System.IO.Path]::IsPathRooted($relayPathRel)) {
    [System.IO.Path]::GetFullPath($relayPathRel)
}
else {
    [System.IO.Path]::GetFullPath((Join-Path $repoRoot $relayPathRel))
}

if (-not (Test-Path -LiteralPath $relayPath)) {
    throw ('relay path not found: {0}' -f $relayPath)
}

$dispatchLogLines = @(Get-Content -LiteralPath $dispatchLogPath -Encoding utf8)
$relayLines = @(Get-Content -LiteralPath $relayPath -Encoding utf8)

$hasOverrideLog = $false
foreach ($line in $dispatchLogLines) {
    if ($line -match [regex]::Escape($ticketId) -and $line -match 'route_guard_expected_overridden' -and $line -match 'brief=event-review' -and $line -match 'live=incident-auto-resume-code-fix') {
        $hasOverrideLog = $true
        break
    }
}

$hasRelaySourceLive = $false
$hasRelayLiveClassification = $false
foreach ($line in $relayLines) {
    if ($line -eq 'route_guard_expected_source=live') {
        $hasRelaySourceLive = $true
    }
    if ($line -eq 'route_guard_live_classification=incident-auto-resume-code-fix') {
        $hasRelayLiveClassification = $true
    }
}

$pass = (
    [string]$latestState.route_guard_expected -eq 'incident-auto-resume-code-fix' -and
    [string]$latestState.route_guard_expected_source -eq 'live' -and
    [string]$latestState.route_guard_live_classification -eq 'incident-auto-resume-code-fix' -and
    [string]$latestState.sender_mode -eq 'none' -and
    $hasOverrideLog -and
    $hasRelaySourceLive -and
    $hasRelayLiveClassification
)

$summary = [ordered]@{
    schema = 'AB_DISPATCH_ROUTE_GUARD_LIVE_OVERRIDE_SMOKE_V1'
    generated_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    source_start_file = $resolvedStartFile
    temp_start_file = $tmpStartFile
    temp_queue = $tmpQueue
    brief_path = $briefPath
    live_route_path = $liveRoutePath
    dispatch_output = $dispatchOutputPath
    dispatch_log_path = $dispatchLogPath
    latest_state_path = $latestStatePath
    relay_path = $relayPath
    ticket_id = $ticketId
    checks = [ordered]@{
        latest_state_expected_live_override = ([string]$latestState.route_guard_expected -eq 'incident-auto-resume-code-fix')
        latest_state_expected_source_live = ([string]$latestState.route_guard_expected_source -eq 'live')
        latest_state_live_classification = ([string]$latestState.route_guard_live_classification -eq 'incident-auto-resume-code-fix')
        sender_mode_none = ([string]$latestState.sender_mode -eq 'none')
        override_log_written = $hasOverrideLog
        relay_expected_source_live = $hasRelaySourceLive
        relay_live_classification = $hasRelayLiveClassification
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
Write-Output ('[DISPATCH-LIVE-OVERRIDE-SMOKE] checks expected={0} source={1} live={2} sender_none={3} override_log={4} relay_source={5} relay_live={6}' -f ([string]$latestState.route_guard_expected -eq 'incident-auto-resume-code-fix'), ([string]$latestState.route_guard_expected_source -eq 'live'), ([string]$latestState.route_guard_live_classification -eq 'incident-auto-resume-code-fix'), ([string]$latestState.sender_mode -eq 'none'), $hasOverrideLog, $hasRelaySourceLive, $hasRelayLiveClassification)

if (-not $pass) {
    Write-Output '[DISPATCH-LIVE-OVERRIDE-SMOKE] result=fail'
    exit 1
}

Write-Output '[DISPATCH-LIVE-OVERRIDE-SMOKE] result=pass'
exit 0