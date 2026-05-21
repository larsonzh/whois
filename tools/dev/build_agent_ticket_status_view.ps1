param(
    [Parameter(Mandatory = $true)][string]$StartFile,
    [AllowEmptyString()][string]$QueuePath = 'out\artifacts\ab_agent_queue\agent_tickets.jsonl',
    [AllowEmptyString()][string]$OutputPath = '',
    [ValidateRange(1, 200)][int]$KeepRecentStatus = 5,
    [ValidateRange(1, 720)][int]$KeepStatusHours = 24,
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Resolve-RepoPathAllowMissing {
    param(
        [string]$RepoRoot,
        [string]$Path
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return ''
    }

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return [System.IO.Path]::GetFullPath($Path)
    }

    return [System.IO.Path]::GetFullPath((Join-Path $RepoRoot $Path))
}

function Convert-ToPathKey {
    param([AllowEmptyString()][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return ''
    }

    return ($Path.Replace('\\', '/').Trim().ToLowerInvariant())
}

function Convert-ToRepoRelativePath {
    param(
        [string]$RepoRoot,
        [AllowEmptyString()][string]$Path
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return ''
    }

    try {
        $fullPath = [System.IO.Path]::GetFullPath($Path)
        $repoRootFull = [System.IO.Path]::GetFullPath($RepoRoot)
        if ($fullPath.StartsWith($repoRootFull, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $fullPath.Substring($repoRootFull.Length).TrimStart('\\').Replace('\\', '/')
        }

        return $fullPath.Replace('\\', '/')
    }
    catch {
        return $Path.Replace('\\', '/')
    }
}

function ConvertTo-TicketCreatedAt {
    param([AllowEmptyString()][string]$CreatedAt)

    if ([string]::IsNullOrWhiteSpace($CreatedAt)) {
        return [datetime]::MinValue
    }

    $value = $CreatedAt.Trim()
    $parsed = [datetime]::MinValue

    if ([datetime]::TryParseExact(
            $value,
            'yyyy-MM-dd HH:mm:ss',
            [System.Globalization.CultureInfo]::InvariantCulture,
            [System.Globalization.DateTimeStyles]::AssumeLocal,
            [ref]$parsed
        )) {
        return $parsed
    }

    if ([datetime]::TryParse($value, [ref]$parsed)) {
        return $parsed
    }

    return [datetime]::MinValue
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$queueFilePath = Resolve-RepoPathAllowMissing -RepoRoot $repoRoot -Path $QueuePath
$startFilePath = Resolve-RepoPathAllowMissing -RepoRoot $repoRoot -Path $StartFile

if ([string]::IsNullOrWhiteSpace($queueFilePath) -or -not (Test-Path -LiteralPath $queueFilePath)) {
    throw "Queue file not found: $QueuePath"
}
if ([string]::IsNullOrWhiteSpace($startFilePath) -or -not (Test-Path -LiteralPath $startFilePath)) {
    throw "Start file not found: $StartFile"
}

$startFileKey = Convert-ToPathKey -Path (Convert-ToRepoRelativePath -RepoRoot $repoRoot -Path $startFilePath)
$queueLines = @(Get-Content -LiteralPath $queueFilePath -Encoding utf8)

$allTickets = New-Object 'System.Collections.Generic.List[object]'
for ($i = 0; $i -lt $queueLines.Count; $i++) {
    $lineNo = $i + 1
    $line = [string]$queueLines[$i]
    if ([string]::IsNullOrWhiteSpace($line)) {
        continue
    }

    $ticket = $null
    try {
        $ticket = $line | ConvertFrom-Json
    }
    catch {
        continue
    }

    if ($null -eq $ticket) {
        continue
    }

    $ticketStartFile = ''
    if ($ticket.PSObject.Properties['start_file']) {
        $ticketStartFile = [string]$ticket.start_file
    }

    $ticketStartFileKey = Convert-ToPathKey -Path $ticketStartFile
    if ($ticketStartFileKey -ne $startFileKey) {
        continue
    }

    $eventName = ''
    if ($ticket.PSObject.Properties['event']) {
        $eventName = [string]$ticket.event
    }

    $createdAtRaw = ''
    if ($ticket.PSObject.Properties['created_at']) {
        $createdAtRaw = [string]$ticket.created_at
    }

    $createdAt = ConvertTo-TicketCreatedAt -CreatedAt $createdAtRaw

    $allTickets.Add([pscustomobject]@{
        line_no = $lineNo
        event = $eventName.Trim().ToLowerInvariant()
        created_at_raw = $createdAtRaw
        created_at = $createdAt
        ticket = $ticket
        json_line = $line
    }) | Out-Null
}

$statusTickets = @($allTickets | Where-Object { $_.event -eq 'running-status-report' })
$eventTickets = @($allTickets | Where-Object { $_.event -ne 'running-status-report' })

$cutoff = (Get-Date).AddHours(-1 * $KeepStatusHours)
$statusSorted = @(
    $statusTickets |
        Sort-Object -Property @{ Expression = 'created_at'; Descending = $true }, @{ Expression = 'line_no'; Descending = $true }
)

$keepLineNoSet = @{}
foreach ($item in $eventTickets) {
    $keepLineNoSet[[int]$item.line_no] = $true
}

$keptStatusCount = 0
$prunedStatusCount = 0
for ($idx = 0; $idx -lt $statusSorted.Count; $idx++) {
    $item = $statusSorted[$idx]
    $isRecentByCount = ($idx -lt $KeepRecentStatus)
    $isRecentByTime = ($item.created_at -ne [datetime]::MinValue -and $item.created_at -ge $cutoff)

    if ($isRecentByCount -or $isRecentByTime) {
        $keepLineNoSet[[int]$item.line_no] = $true
        $keptStatusCount++
    }
    else {
        $prunedStatusCount++
    }
}

$viewTickets = @($allTickets | Where-Object { $keepLineNoSet.ContainsKey([int]$_.line_no) } | Sort-Object line_no)

$resolvedOutputPath = $OutputPath
if ([string]::IsNullOrWhiteSpace($resolvedOutputPath)) {
    $startToken = [System.IO.Path]::GetFileNameWithoutExtension($startFilePath)
    $resolvedOutputPath = Join-Path 'out\artifacts\ab_agent_queue' ("agent_tickets_view_{0}.jsonl" -f $startToken)
}
$resolvedOutputPath = Resolve-RepoPathAllowMissing -RepoRoot $repoRoot -Path $resolvedOutputPath

if ((Convert-ToPathKey -Path $resolvedOutputPath) -eq (Convert-ToPathKey -Path $queueFilePath)) {
    throw 'OutputPath must not be the same as QueuePath.'
}

$summary = [ordered]@{
    schema = 'AB_AGENT_TICKET_STATUS_VIEW_SUMMARY_V1'
    generated_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    start_file = (Convert-ToRepoRelativePath -RepoRoot $repoRoot -Path $startFilePath)
    queue_path = (Convert-ToRepoRelativePath -RepoRoot $repoRoot -Path $queueFilePath)
    output_path = (Convert-ToRepoRelativePath -RepoRoot $repoRoot -Path $resolvedOutputPath)
    keep_recent_status = [int]$KeepRecentStatus
    keep_status_hours = [int]$KeepStatusHours
    cutoff_time = $cutoff.ToString('yyyy-MM-dd HH:mm:ss')
    total_for_start = [int]$allTickets.Count
    non_status_kept = [int]$eventTickets.Count
    status_total = [int]$statusTickets.Count
    status_kept = [int]$keptStatusCount
    status_pruned = [int]$prunedStatusCount
    view_total = [int]$viewTickets.Count
}

if ($DryRun.IsPresent) {
    $summary | ConvertTo-Json -Depth 8
    return
}

$outputDir = Split-Path -Parent $resolvedOutputPath
if (-not [string]::IsNullOrWhiteSpace($outputDir) -and -not (Test-Path -LiteralPath $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
}

$viewLines = New-Object 'System.Collections.Generic.List[string]'
foreach ($item in $viewTickets) {
    $viewLines.Add(($item.ticket | ConvertTo-Json -Compress -Depth 12)) | Out-Null
}

Set-Content -LiteralPath $resolvedOutputPath -Value $viewLines -Encoding utf8

$summaryPath = $resolvedOutputPath + '.summary.json'
$summaryJson = $summary | ConvertTo-Json -Depth 8
Set-Content -LiteralPath $summaryPath -Value $summaryJson -Encoding utf8

$summary | ConvertTo-Json -Depth 8
