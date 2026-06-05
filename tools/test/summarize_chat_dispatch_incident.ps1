param(
    [AllowEmptyString()][string]$StartFile = 'testdata\unattended_start\active\unattended_ab_start_20260504-1123.md',
    [ValidateRange(1, 200)][int]$Last = 12,
    [AllowEmptyString()][string]$TicketId = '',
    [AllowEmptyString()][string]$DispatchLogPath = '',
    [AllowEmptyString()][string]$TriggerLogPath = '',
    [ValidateRange(200, 200000)][int]$DispatchTailLines = 12000,
    [ValidateRange(200, 200000)][int]$TriggerTailLines = 12000,
    [switch]$AsJson
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

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

function Get-LegacyStartFileToken {
    param([string]$StartFilePath)

    return Get-SafeToken -Text ([System.IO.Path]::GetFileNameWithoutExtension($StartFilePath).ToLowerInvariant())
}

function Resolve-PreferredDefaultPath {
    param(
        [string]$PreferredPath,
        [string]$LegacyPath
    )

    if (-not [string]::IsNullOrWhiteSpace($LegacyPath) -and -not (Test-Path -LiteralPath $PreferredPath) -and (Test-Path -LiteralPath $LegacyPath)) {
        return $LegacyPath
    }

    return $PreferredPath
}

function Read-KeyValueFile {
    param([string]$Path)

    $map = [ordered]@{}
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) {
        return $map
    }

    foreach ($line in @(Get-Content -LiteralPath $Path -Encoding utf8 -ErrorAction SilentlyContinue)) {
        if ($line -match '^([^=]+)=(.*)$') {
            $map[$Matches[1].Trim()] = $Matches[2]
        }
    }

    return $map
}

function Get-MapValue {
    param(
        [System.Collections.IDictionary]$Map,
        [string]$Key
    )

    if ($null -eq $Map -or [string]::IsNullOrWhiteSpace($Key)) {
        return ''
    }

    if ($Map.Contains($Key)) {
        return [string]$Map[$Key]
    }

    return ''
}

function Convert-ToBooleanSetting {
    param(
        [AllowEmptyString()][string]$Value,
        [bool]$Default = $false
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $Default
    }

    return $Value.Trim().ToLowerInvariant() -in @('1', 'true', 'yes', 'on')
}

function ConvertTo-BoolToken {
    param([AllowEmptyString()][string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $null
    }

    $normalized = $Value.Trim().ToLowerInvariant()
    if ($normalized -in @('1', 'true', 'yes', 'on')) {
        return $true
    }
    if ($normalized -in @('0', 'false', 'no', 'off')) {
        return $false
    }

    return $null
}

function ConvertTo-IntToken {
    param([AllowEmptyString()][string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $null
    }

    $parsed = 0
    if ([int]::TryParse($Value.Trim(), [ref]$parsed)) {
        return $parsed
    }

    return $null
}

function Get-LogTailLineList {
    param(
        [string]$Path,
        [ValidateRange(1, 500000)][int]$TailLines
    )

    $items = New-Object 'System.Collections.Generic.List[object]'
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) {
        return $items.ToArray()
    }

    $allLines = @(Get-Content -LiteralPath $Path -Encoding utf8 -ErrorAction SilentlyContinue)
    if ($allLines.Count -eq 0) {
        return $items.ToArray()
    }

    $startIndex = 0
    if ($allLines.Count -gt $TailLines) {
        $startIndex = $allLines.Count - $TailLines
    }

    for ($i = $startIndex; $i -lt $allLines.Count; $i++) {
        $items.Add([pscustomobject]@{
                line_no = $i + 1
                line = [string]$allLines[$i]
            }) | Out-Null
    }

    return $items.ToArray()
}

function ConvertTo-TaggedLogRecord {
    param(
        [string]$Line,
        [int]$LineNo,
        [string]$ExpectedTag
    )

    if ([string]::IsNullOrWhiteSpace($Line)) {
        return $null
    }

    $pattern = '^\[(?<tag>[^\]]+)\]\s+timestamp=(?<ts>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(?<rest>.+)$'
    $m = [regex]::Match($Line, $pattern)
    if (-not $m.Success) {
        return $null
    }

    $tag = Convert-ToSingleLineText -Text ([string]$m.Groups['tag'].Value)
    if (-not [string]::IsNullOrWhiteSpace($ExpectedTag) -and $tag -ne $ExpectedTag) {
        return $null
    }

    $rest = Convert-ToSingleLineText -Text ([string]$m.Groups['rest'].Value)
    if ([string]::IsNullOrWhiteSpace($rest)) {
        return $null
    }

    $parts = @($rest -split '\s+', 2)
    $action = if ($parts.Count -gt 0) { [string]$parts[0] } else { '' }
    $kvText = if ($parts.Count -gt 1) { [string]$parts[1] } else { '' }

    $map = [ordered]@{}
    foreach ($kv in [regex]::Matches($kvText, '(?<key>[A-Za-z0-9_.-]+)=(?<value>[^\s]*)')) {
        $key = [string]$kv.Groups['key'].Value
        $value = [string]$kv.Groups['value'].Value
        $map[$key] = $value
    }

    return [pscustomobject]@{
        tag = $tag
        timestamp = (Convert-ToSingleLineText -Text ([string]$m.Groups['ts'].Value))
        action = $action
        map = $map
        line_no = $LineNo
        raw = $Line
    }
}

function Get-TicketIdListFromRelayRecordSet {
    param(
        [object[]]$RelayRecords,
        [int]$Limit
    )

    $ids = New-Object 'System.Collections.Generic.List[string]'
    $seen = @{}

    foreach ($record in @($RelayRecords | Sort-Object line_no -Descending)) {
        $ticket = Convert-ToSingleLineText -Text (Get-MapValue -Map $record.map -Key 'ticket')
        if ([string]::IsNullOrWhiteSpace($ticket)) {
            continue
        }

        if ($seen.Contains($ticket)) {
            continue
        }

        $seen[$ticket] = $true
        $ids.Add($ticket) | Out-Null
        if ($ids.Count -ge $Limit) {
            break
        }
    }

    return $ids.ToArray()
}

function Get-TriggerSourceInfo {
    param(
        [string]$TicketId,
        [object[]]$TriggerRecords
    )

    $records = @($TriggerRecords | Where-Object {
            $id = Convert-ToSingleLineText -Text (Get-MapValue -Map $_.map -Key 'id')
            -not [string]::IsNullOrWhiteSpace($id) -and $id -eq $TicketId
        })

    if ($records.Count -eq 0) {
        return [pscustomobject]@{
            source = 'direct-dispatch-or-unknown'
            action = ''
            timestamp = ''
            line_no = 0
        }
    }

    $priority = @(
        'chat_recovery_dispatch',
        'final_status_dispatch',
        'ticket_dispatch',
        'final_status_trigger_started',
        'external_trigger_started'
    )

    $picked = $null
    foreach ($name in $priority) {
        $candidate = @($records | Where-Object { [string]$_.action -eq $name } | Sort-Object line_no -Descending | Select-Object -First 1)
        if ($candidate.Count -gt 0) {
            $picked = $candidate[0]
            break
        }
    }

    if ($null -eq $picked) {
        $picked = @($records | Sort-Object line_no -Descending | Select-Object -First 1)[0]
    }

    $source = 'direct-dispatch-or-unknown'
    switch ([string]$picked.action) {
        'chat_recovery_dispatch' { $source = 'chat-recovery-auto' }
        'final_status_dispatch' { $source = 'session-final-auto' }
        'ticket_dispatch' { $source = 'queue-ticket' }
        'final_status_trigger_started' { $source = 'session-final-trigger-started' }
        'external_trigger_started' { $source = 'queue-external-trigger-started' }
        default { $source = ('trigger:{0}' -f [string]$picked.action) }
    }

    return [pscustomobject]@{
        source = $source
        action = [string]$picked.action
        timestamp = [string]$picked.timestamp
        line_no = [int]$picked.line_no
    }
}

function Convert-CountMapToRowList {
    param([System.Collections.IDictionary]$Map)

    $rows = New-Object 'System.Collections.Generic.List[object]'
    foreach ($key in @($Map.Keys | Sort-Object)) {
        $rows.Add([pscustomobject]@{
                key = [string]$key
                count = [int]$Map[$key]
            }) | Out-Null
    }

    return $rows.ToArray()
}

$script:RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path

$startFilePath = Resolve-RepoPathAllowMissing -Path $StartFile
$startToken = Get-StableStartFileToken -StartFilePath $startFilePath
$legacyStartToken = Get-LegacyStartFileToken -StartFilePath $startFilePath
$startSettings = Read-KeyValueFile -Path $startFilePath
$startEscPreflight = $false
if ($startSettings.Contains('AI_CHAT_DISPATCH_ESC_PREFLIGHT')) {
    $startEscPreflight = Convert-ToBooleanSetting -Value ([string]$startSettings.AI_CHAT_DISPATCH_ESC_PREFLIGHT) -Default $false
}

$dispatchLog = $DispatchLogPath
if ([string]::IsNullOrWhiteSpace($dispatchLog)) {
    $dispatchLog = Resolve-PreferredDefaultPath -PreferredPath (Resolve-RepoPathAllowMissing -Path (Join-Path 'out\artifacts\ab_agent_queue\chat_dispatch' ("dispatch_{0}.log" -f $startToken))) -LegacyPath (Resolve-RepoPathAllowMissing -Path (Join-Path 'out\artifacts\ab_agent_queue\chat_dispatch' ("dispatch_{0}.log" -f $legacyStartToken)))
}
$dispatchLogPathResolved = Resolve-RepoPathAllowMissing -Path $dispatchLog

$triggerLog = $TriggerLogPath
if ([string]::IsNullOrWhiteSpace($triggerLog)) {
    $triggerLog = Resolve-PreferredDefaultPath -PreferredPath (Resolve-RepoPathAllowMissing -Path (Join-Path 'out\artifacts\ab_agent_queue' ("takeover_trigger_{0}.log" -f $startToken))) -LegacyPath (Resolve-RepoPathAllowMissing -Path (Join-Path 'out\artifacts\ab_agent_queue' ("takeover_trigger_{0}.log" -f $legacyStartToken)))
}
$triggerLogPathResolved = Resolve-RepoPathAllowMissing -Path $triggerLog

$dispatchLines = Get-LogTailLineList -Path $dispatchLogPathResolved -TailLines $DispatchTailLines
$triggerLines = Get-LogTailLineList -Path $triggerLogPathResolved -TailLines $TriggerTailLines

$dispatchRecords = New-Object 'System.Collections.Generic.List[object]'
foreach ($item in @($dispatchLines)) {
    $record = ConvertTo-TaggedLogRecord -Line ([string]$item.line) -LineNo ([int]$item.line_no) -ExpectedTag 'CHAT-DISPATCH'
    if ($null -ne $record) {
        $dispatchRecords.Add($record) | Out-Null
    }
}

$triggerRecords = New-Object 'System.Collections.Generic.List[object]'
foreach ($item in @($triggerLines)) {
    $record = ConvertTo-TaggedLogRecord -Line ([string]$item.line) -LineNo ([int]$item.line_no) -ExpectedTag 'AB-TAKEOVER-TRIGGER'
    if ($null -ne $record) {
        $triggerRecords.Add($record) | Out-Null
    }
}

$relayRecords = @($dispatchRecords | Where-Object { [string]$_.action -eq 'relay_created' -and -not [string]::IsNullOrWhiteSpace((Get-MapValue -Map $_.map -Key 'ticket')) })
$ahkResultRecords = @($dispatchRecords | Where-Object { [string]$_.action -eq 'ahk_dispatch_result' -and -not [string]::IsNullOrWhiteSpace((Get-MapValue -Map $_.map -Key 'ticket')) })

$targetTicketIds = @()
if (-not [string]::IsNullOrWhiteSpace($TicketId)) {
    $targetTicketIds = @((Convert-ToSingleLineText -Text $TicketId))
}
else {
    $targetTicketIds = Get-TicketIdListFromRelayRecordSet -RelayRecords $relayRecords -Limit $Last
}

$rows = New-Object 'System.Collections.Generic.List[object]'
$sourceCount = @{}
$eventCount = @{}
$sentTrue = 0
$sentFalse = 0
$sentUnknown = 0

foreach ($ticket in @($targetTicketIds)) {
    if ([string]::IsNullOrWhiteSpace($ticket)) {
        continue
    }

    $relay = @($relayRecords | Where-Object { (Get-MapValue -Map $_.map -Key 'ticket') -eq $ticket } | Sort-Object line_no -Descending | Select-Object -First 1)
    $relayRecord = if ($relay.Count -gt 0) { $relay[0] } else { $null }

    $ahk = @($ahkResultRecords | Where-Object { (Get-MapValue -Map $_.map -Key 'ticket') -eq $ticket } | Sort-Object line_no -Descending | Select-Object -First 1)
    $ahkRecord = if ($ahk.Count -gt 0) { $ahk[0] } else { $null }

    $triggerInfo = Get-TriggerSourceInfo -TicketId $ticket -TriggerRecords $triggerRecords

    $eventName = ''
    $dispatchAt = ''
    $dispatchLine = 0
    $relayPath = ''
    $statusReportInteractiveEnabled = ''
    $interactiveSuppressed = ''

    if ($null -ne $relayRecord) {
        $eventName = Convert-ToSingleLineText -Text (Get-MapValue -Map $relayRecord.map -Key 'event')
        $dispatchAt = [string]$relayRecord.timestamp
        $dispatchLine = [int]$relayRecord.line_no
        $relayPath = Convert-ToSingleLineText -Text (Get-MapValue -Map $relayRecord.map -Key 'relay')
        $statusReportInteractiveEnabled = Convert-ToSingleLineText -Text (Get-MapValue -Map $relayRecord.map -Key 'status_report_interactive_enabled')
        $interactiveSuppressed = Convert-ToSingleLineText -Text (Get-MapValue -Map $relayRecord.map -Key 'interactive_suppressed')
    }

    $ahkSent = $null
    $ahkExitCode = $null
    $ahkReason = ''
    $ahkTried = ''

    if ($null -ne $ahkRecord) {
        $ahkSent = ConvertTo-BoolToken -Value (Get-MapValue -Map $ahkRecord.map -Key 'sent')
        $ahkExitCode = ConvertTo-IntToken -Value (Get-MapValue -Map $ahkRecord.map -Key 'exit_code')
        $ahkReason = Convert-ToSingleLineText -Text (Get-MapValue -Map $ahkRecord.map -Key 'reason')
    }
    elseif ($null -ne $relayRecord) {
        $ahkSent = ConvertTo-BoolToken -Value (Get-MapValue -Map $relayRecord.map -Key 'ahk_sent')
        $ahkExitCode = ConvertTo-IntToken -Value (Get-MapValue -Map $relayRecord.map -Key 'ahk_exit_code')
        $ahkReason = Convert-ToSingleLineText -Text (Get-MapValue -Map $relayRecord.map -Key 'ahk_reason')
    }

    if ($null -ne $relayRecord) {
        $ahkTried = Convert-ToSingleLineText -Text (Get-MapValue -Map $relayRecord.map -Key 'ahk_tried')
    }

    $escPreflight = $null
    $escSource = 'start-file-default'
    if ($null -ne $ahkRecord) {
        $escFromAhk = ConvertTo-BoolToken -Value (Get-MapValue -Map $ahkRecord.map -Key 'esc_preflight_enabled')
        if ($null -ne $escFromAhk) {
            $escPreflight = $escFromAhk
            $escSource = 'dispatch-ahk-result'
        }
    }

    if ($null -eq $escPreflight -and $null -ne $relayRecord) {
        $escFromRelay = ConvertTo-BoolToken -Value (Get-MapValue -Map $relayRecord.map -Key 'ahk_esc_preflight_enabled')
        if ($null -ne $escFromRelay) {
            $escPreflight = $escFromRelay
            $escSource = 'dispatch-relay'
        }
    }

    if ($null -eq $escPreflight) {
        $escPreflight = [bool]$startEscPreflight
        $escSource = 'start-file-default'
    }

    if ($null -eq $ahkSent) {
        $sentUnknown++
    }
    elseif ([bool]$ahkSent) {
        $sentTrue++
    }
    else {
        $sentFalse++
    }

    $srcKey = [string]$triggerInfo.source
    if ([string]::IsNullOrWhiteSpace($srcKey)) {
        $srcKey = 'unknown'
    }
    if (-not $sourceCount.Contains($srcKey)) {
        $sourceCount[$srcKey] = 0
    }
    $sourceCount[$srcKey] = [int]$sourceCount[$srcKey] + 1

    $evtKey = if ([string]::IsNullOrWhiteSpace($eventName)) { 'unknown' } else { $eventName }
    if (-not $eventCount.Contains($evtKey)) {
        $eventCount[$evtKey] = 0
    }
    $eventCount[$evtKey] = [int]$eventCount[$evtKey] + 1

    $rows.Add([pscustomobject]@{
            ticket_id = $ticket
            event = $eventName
            trigger_source = [string]$triggerInfo.source
            trigger_action = [string]$triggerInfo.action
            trigger_at = [string]$triggerInfo.timestamp
            trigger_line = [int]$triggerInfo.line_no
            dispatch_at = $dispatchAt
            dispatch_line = $dispatchLine
            relay_path = $relayPath
            ahk_sent = $ahkSent
            ahk_tried = $ahkTried
            ahk_exit_code = $ahkExitCode
            ahk_reason = $ahkReason
            status_report_interactive_enabled = $statusReportInteractiveEnabled
            interactive_suppressed = $interactiveSuppressed
            esc_preflight_enabled = [bool]$escPreflight
            esc_preflight_source = $escSource
        }) | Out-Null
}

$rowsOutput = $rows.ToArray()
$summary = [ordered]@{
    total_rows = $rowsOutput.Count
    sent_true = [int]$sentTrue
    sent_false = [int]$sentFalse
    sent_unknown = [int]$sentUnknown
    by_trigger_source = @(Convert-CountMapToRowList -Map $sourceCount)
    by_event = @(Convert-CountMapToRowList -Map $eventCount)
}

$output = [ordered]@{
    schema = 'AB_CHAT_DISPATCH_INCIDENT_SUMMARY_V1'
    generated_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    start_file = (Convert-ToRepoRelativePath -Path $startFilePath)
    dispatch_log = (Convert-ToRepoRelativePath -Path $dispatchLogPathResolved)
    trigger_log = (Convert-ToRepoRelativePath -Path $triggerLogPathResolved)
    start_file_esc_preflight = [bool]$startEscPreflight
    summary = $summary
    rows = $rowsOutput
}

if ($AsJson.IsPresent) {
    $output | ConvertTo-Json -Depth 10
}
else {
    Write-Output ("[CHAT-INCIDENT-SUMMARY] generated_at={0} start_file={1}" -f $output.generated_at, $output.start_file)
    Write-Output ("[CHAT-INCIDENT-SUMMARY] dispatch_log={0}" -f $output.dispatch_log)
    Write-Output ("[CHAT-INCIDENT-SUMMARY] trigger_log={0}" -f $output.trigger_log)
    Write-Output ("[CHAT-INCIDENT-SUMMARY] start_file_esc_preflight={0}" -f [bool]$output.start_file_esc_preflight)
    Write-Output ("[CHAT-INCIDENT-SUMMARY] totals rows={0} sent_true={1} sent_false={2} sent_unknown={3}" -f
        [int]$output.summary.total_rows,
        [int]$output.summary.sent_true,
        [int]$output.summary.sent_false,
        [int]$output.summary.sent_unknown)

    if ($rowsOutput.Count -eq 0) {
        Write-Output '[CHAT-INCIDENT-SUMMARY] no_rows'
    }
    else {
        foreach ($row in $rowsOutput) {
            Write-Output ("[CHAT-INCIDENT-SUMMARY] row ticket={0} event={1} source={2} sent={3} esc_preflight={4} esc_source={5} status_report_interactive={6} interactive_suppressed={7} dispatch_at={8}" -f
                [string]$row.ticket_id,
                [string]$row.event,
                [string]$row.trigger_source,
                [string]$row.ahk_sent,
                [string]$row.esc_preflight_enabled,
                [string]$row.esc_preflight_source,
                [string]$row.status_report_interactive_enabled,
                [string]$row.interactive_suppressed,
                [string]$row.dispatch_at)
        }
    }
}
