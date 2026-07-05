param(
    [string]$StartFile = 'testdata\unattended_start\smoke\unattended_ab_start_status_ticket_smoke.md',
    [AllowEmptyString()][string]$QueuePath = '',
    [AllowEmptyString()][string]$LedgerPath = '',
    [AllowEmptyString()][string]$TakeoverRoot = '',
    [AllowEmptyString()][string]$OutDirRoot = '',
    [switch]$AsJson
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'unattended_exit_result.ps1')
$script:UnhandledExitTag = 'CHECK-UNATTENDED-TICKET-CLOSURE'

trap {
    $exitCode = Get-UnattendedExitCodeFromRecord -Tag $script:UnhandledExitTag -Record $_ -DefaultExitCode 1
    Write-UnattendedUnhandledResult -Tag $script:UnhandledExitTag -Record $_ -ExitCode $exitCode
    exit $exitCode
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path

function Resolve-RepoPath {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw 'Path must not be empty.'
    }

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return (Resolve-Path -LiteralPath $Path).Path
    }

    return (Resolve-Path -LiteralPath (Join-Path $repoRoot $Path)).Path
}

function Resolve-RepoPathAllowMissing {
    param([AllowEmptyString()][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return ''
    }

    try {
        if ([System.IO.Path]::IsPathRooted($Path)) {
            return [System.IO.Path]::GetFullPath($Path)
        }

        return [System.IO.Path]::GetFullPath((Join-Path $repoRoot $Path))
    }
    catch {
        return ''
    }
}

function Convert-ToRepoRelativePath {
    param([AllowEmptyString()][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return ''
    }

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $repoRootFull = [System.IO.Path]::GetFullPath($repoRoot)
    if ($fullPath.StartsWith($repoRootFull, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $fullPath.Substring($repoRootFull.Length).TrimStart('\').Replace('\', '/')
    }

    return $fullPath.Replace('\', '/')
}

function Convert-ToSingleLineText {
    param([AllowEmptyString()][string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return ''
    }

    $singleLine = (($Text -split "`r?`n") -join ' ')
    return ([regex]::Replace($singleLine, '\s+', ' ')).Trim()
}

function ConvertTo-PathLikeValue {
    param([AllowEmptyString()][string]$Value)

    return (Convert-ToSingleLineText -Text $Value).Replace('/', '\')
}

function Read-KeyValueFile {
    param([string]$Path)

    $map = [ordered]@{}
    foreach ($line in @(Get-Content -LiteralPath $Path -Encoding utf8 -ErrorAction Stop)) {
        if ($line -match '^([^=]+)=(.*)$') {
            $map[$Matches[1].Trim()] = $Matches[2]
        }
    }

    return $map
}

function Resolve-PreferredDefaultPath {
    param(
        [AllowEmptyString()][string]$PreferredPath,
        [AllowEmptyString()][string]$LegacyPath
    )

    if (-not [string]::IsNullOrWhiteSpace($PreferredPath) -and (Test-Path -LiteralPath $PreferredPath)) {
        return $PreferredPath
    }

    if (-not [string]::IsNullOrWhiteSpace($LegacyPath) -and (Test-Path -LiteralPath $LegacyPath)) {
        return $LegacyPath
    }

    if (-not [string]::IsNullOrWhiteSpace($PreferredPath)) {
        return $PreferredPath
    }

    return $LegacyPath
}

function Read-JsonFileSafely {
    param([AllowEmptyString()][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) {
        return $null
    }

    try {
        $raw = Get-Content -LiteralPath $Path -Raw -Encoding utf8 -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($raw)) {
            return $null
        }

        return ($raw | ConvertFrom-Json -ErrorAction Stop)
    }
    catch {
        return $null
    }
}

function Read-JsonLinesSafely {
    param([AllowEmptyString()][string]$Path)

    $items = New-Object 'System.Collections.Generic.List[object]'
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) {
        return @($items.ToArray())
    }

    foreach ($line in @(Get-Content -LiteralPath $Path -Encoding utf8 -ErrorAction SilentlyContinue)) {
        $trimmed = Convert-ToSingleLineText -Text ([string]$line)
        if ([string]::IsNullOrWhiteSpace($trimmed)) {
            continue
        }

        try {
            [void]$items.Add(($trimmed | ConvertFrom-Json -ErrorAction Stop))
        }
        catch {
            continue
        }
    }

    return @($items.ToArray())
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

    if ($InputObject.PSObject.Properties.Name -contains $Name) {
        return [string]$InputObject.$Name
    }

    return ''
}

function New-IssueRecord {
    param(
        [string]$Type,
        [string]$Severity,
        [string]$TicketId,
        [string]$Detail,
        [string]$SuggestedCommand,
        [string]$BriefPath = '',
        [string]$LedgerStatus = ''
    )

    return [ordered]@{
        type = $Type
        severity = $Severity
        ticket_id = $TicketId
        ledger_status = $LedgerStatus
        brief_path = $BriefPath
        detail = $Detail
        suggested_command = $SuggestedCommand
    }
}

$startFilePath = Resolve-RepoPath -Path $StartFile
$settings = Read-KeyValueFile -Path $startFilePath
$startToken = Get-StableStartFileToken -StartFilePath $startFilePath
$legacyStartToken = Get-LegacyStartFileToken -StartFilePath $startFilePath -NoSanitize -EmptyFallback 'startfile'

$queuePathValue = $QueuePath
if ([string]::IsNullOrWhiteSpace($queuePathValue) -and $settings.Contains('LOCAL_GUARD_AGENT_QUEUE_PATH')) {
    $queuePathValue = ConvertTo-PathLikeValue -Value ([string]$settings.LOCAL_GUARD_AGENT_QUEUE_PATH)
}
if ([string]::IsNullOrWhiteSpace($queuePathValue)) {
    $queuePathValue = 'out\artifacts\ab_agent_queue\agent_tickets.jsonl'
}
$queueFilePath = Resolve-RepoPathAllowMissing -Path $queuePathValue

$ledgerPathValue = $LedgerPath
if ([string]::IsNullOrWhiteSpace($ledgerPathValue)) {
    $ledgerPathValue = Resolve-PreferredDefaultPath -PreferredPath (Resolve-RepoPathAllowMissing -Path (Join-Path 'out\artifacts\ab_agent_queue' ("ai_ticket_ledger_{0}.json" -f $startToken))) -LegacyPath (Resolve-RepoPathAllowMissing -Path (Join-Path 'out\artifacts\ab_agent_queue' ("ai_ticket_ledger_{0}.json" -f $legacyStartToken)))
}
$ledgerFilePath = Resolve-RepoPathAllowMissing -Path $ledgerPathValue

$takeoverRootPath = $TakeoverRoot
if ([string]::IsNullOrWhiteSpace($takeoverRootPath)) {
    $takeoverRootPath = 'out\artifacts\ab_agent_queue\takeover_requests'
}
$takeoverRootResolved = Resolve-RepoPathAllowMissing -Path $takeoverRootPath

if (-not $OutDirRoot -or $OutDirRoot.Trim().Length -eq 0) {
    $OutDirRoot = Join-Path $repoRoot 'out\artifacts\ticket_closure_check'
}
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$outDir = Join-Path $OutDirRoot $stamp
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

$queueTickets = @(Read-JsonLinesSafely -Path $queueFilePath)
$ledgerRaw = Read-JsonFileSafely -Path $ledgerFilePath
$ledgerEntries = @()
if ($null -ne $ledgerRaw -and $ledgerRaw.PSObject.Properties.Name -contains 'records') {
    $ledgerEntries = @($ledgerRaw.records)
}

$queueById = @{}
foreach ($ticket in $queueTickets) {
    $ticketId = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $ticket -Name 'ticket_id')
    if ([string]::IsNullOrWhiteSpace($ticketId)) {
        continue
    }
    $queueById[$ticketId] = $ticket
}

$ledgerById = @{}
foreach ($entry in $ledgerEntries) {
    $ticketId = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $entry -Name 'ticket_id')
    if ([string]::IsNullOrWhiteSpace($ticketId)) {
        continue
    }
    $ledgerById[$ticketId] = $entry
}

$issues = New-Object 'System.Collections.Generic.List[object]'
$pollCommand = ('powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/poll_agent_tickets.ps1 -StartFile "{0}" -IncludeStatusReports -Last 20 -AsJson' -f (Convert-ToRepoRelativePath -Path $startFilePath))

foreach ($ticketId in @($queueById.Keys | Sort-Object)) {
    if (-not $ledgerById.ContainsKey($ticketId)) {
        [void]$issues.Add((New-IssueRecord -Type 'queue-without-ledger' -Severity 'high' -TicketId $ticketId -Detail 'ticket exists in queue but has no ledger record' -SuggestedCommand $pollCommand))
        continue
    }

    $ledgerEntry = $ledgerById[$ticketId]
    $ledgerStatus = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $ledgerEntry -Name 'status')
    $handledAt = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $ledgerEntry -Name 'handled_at')
    if ($ledgerStatus -in @('done', 'failed', 'stale_by_restart', 'stale_status_superseded') -and [string]::IsNullOrWhiteSpace($handledAt)) {
        $ackCommand = ('powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/poll_agent_tickets.ps1 -StartFile "{0}" -AcknowledgeTicketIds "{1}" -Last 20 -AsJson' -f (Convert-ToRepoRelativePath -Path $startFilePath), $ticketId)
        [void]$issues.Add((New-IssueRecord -Type 'terminal-ledger-missing-handled-at' -Severity 'high' -TicketId $ticketId -Detail ('ledger terminal status={0} but handled_at is empty' -f $ledgerStatus) -SuggestedCommand $ackCommand -LedgerStatus $ledgerStatus))
    }
}

if (-not [string]::IsNullOrWhiteSpace($takeoverRootResolved) -and (Test-Path -LiteralPath $takeoverRootResolved)) {
    foreach ($briefFile in @(Get-ChildItem -LiteralPath $takeoverRootResolved -Filter '*.md' -File -ErrorAction SilentlyContinue)) {
        $briefMeta = Read-KeyValueFile -Path $briefFile.FullName
        $ticketId = if ($briefMeta.Contains('ticket_id')) { Convert-ToSingleLineText -Text ([string]$briefMeta.ticket_id) } else { '' }
        if ([string]::IsNullOrWhiteSpace($ticketId)) {
            continue
        }

        $briefStartFile = if ($briefMeta.Contains('start_file')) { Resolve-RepoPathAllowMissing -Path ([string]$briefMeta.start_file) } else { '' }
        $briefQueuePath = if ($briefMeta.Contains('queue_path')) { Resolve-RepoPathAllowMissing -Path ([string]$briefMeta.queue_path) } else { '' }

        if (-not [string]::IsNullOrWhiteSpace($briefStartFile) -and $briefStartFile -ne $startFilePath) {
            continue
        }
        if (-not [string]::IsNullOrWhiteSpace($briefQueuePath) -and -not [string]::IsNullOrWhiteSpace($queueFilePath) -and $briefQueuePath -ne $queueFilePath) {
            continue
        }

        if (-not $queueById.ContainsKey($ticketId) -and -not $ledgerById.ContainsKey($ticketId)) {
            [void]$issues.Add((New-IssueRecord -Type 'brief-without-queue-or-ledger' -Severity 'medium' -TicketId $ticketId -Detail 'takeover brief exists but no matching queue ticket or ledger record was found' -SuggestedCommand $pollCommand -BriefPath (Convert-ToRepoRelativePath -Path $briefFile.FullName)))
        }
    }
}

$issuesArray = @($issues.ToArray())
$counts = [ordered]@{
    total = $issuesArray.Count
    queue_without_ledger = @($issuesArray | Where-Object { [string]$_.type -eq 'queue-without-ledger' }).Count
    terminal_ledger_missing_handled_at = @($issuesArray | Where-Object { [string]$_.type -eq 'terminal-ledger-missing-handled-at' }).Count
    brief_without_queue_or_ledger = @($issuesArray | Where-Object { [string]$_.type -eq 'brief-without-queue-or-ledger' }).Count
}

$summary = [ordered]@{
    schema = 'AB_TICKET_CLOSURE_CHECK_V1'
    generated_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    start_file = (Convert-ToRepoRelativePath -Path $startFilePath)
    queue_path = (Convert-ToRepoRelativePath -Path $queueFilePath)
    ledger_path = (Convert-ToRepoRelativePath -Path $ledgerFilePath)
    takeover_root = (Convert-ToRepoRelativePath -Path $takeoverRootResolved)
    counts = $counts
    issues = $issuesArray
    pass = ($issuesArray.Count -eq 0)
}

$resultToken = if ($summary.pass) { 'pass' } else { 'fail' }

$summaryJsonPath = Join-Path $outDir 'summary.json'
$summaryTxtPath = Join-Path $outDir 'summary.txt'
($summary | ConvertTo-Json -Depth 8) | Set-Content -LiteralPath $summaryJsonPath -Encoding utf8

$txtLines = New-Object 'System.Collections.Generic.List[string]'
[void]$txtLines.Add(('[AB-TICKET-CLOSURE-CHECK] start_file={0}' -f $summary.start_file))
[void]$txtLines.Add(('[AB-TICKET-CLOSURE-CHECK] queue_path={0}' -f $summary.queue_path))
[void]$txtLines.Add(('[AB-TICKET-CLOSURE-CHECK] ledger_path={0}' -f $summary.ledger_path))
[void]$txtLines.Add(('[AB-TICKET-CLOSURE-CHECK] takeover_root={0}' -f $summary.takeover_root))
[void]$txtLines.Add(('[AB-TICKET-CLOSURE-CHECK] counts total={0} queue_without_ledger={1} terminal_missing_handled_at={2} brief_without_queue_or_ledger={3}' -f $counts.total, $counts.queue_without_ledger, $counts.terminal_ledger_missing_handled_at, $counts.brief_without_queue_or_ledger))
foreach ($issue in $issuesArray) {
    [void]$txtLines.Add(('[AB-TICKET-CLOSURE-CHECK] issue type={0} severity={1} ticket={2} detail={3} command={4}' -f [string]$issue.type, [string]$issue.severity, [string]$issue.ticket_id, [string]$issue.detail, [string]$issue.suggested_command))
}
[void]$txtLines.Add(('[AB-TICKET-CLOSURE-CHECK] result={0}' -f $resultToken))
$txtLines | Set-Content -LiteralPath $summaryTxtPath -Encoding utf8

Write-Output ('[AB-TICKET-CLOSURE-CHECK] out_dir={0}' -f $outDir)
Write-Output ('[AB-TICKET-CLOSURE-CHECK] summary_json={0}' -f $summaryJsonPath)
Write-Output ('[AB-TICKET-CLOSURE-CHECK] summary_txt={0}' -f $summaryTxtPath)
Write-Output ('[AB-TICKET-CLOSURE-CHECK] counts total={0} queue_without_ledger={1} terminal_missing_handled_at={2} brief_without_queue_or_ledger={3}' -f $counts.total, $counts.queue_without_ledger, $counts.terminal_ledger_missing_handled_at, $counts.brief_without_queue_or_ledger)
Write-Output ('[AB-TICKET-CLOSURE-CHECK] result={0}' -f $resultToken)

if ($AsJson.IsPresent) {
    $summary | ConvertTo-Json -Depth 8
}