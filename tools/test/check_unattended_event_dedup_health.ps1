param(
    [string]$StartFile = 'testdata\unattended_start\smoke\unattended_ab_start_status_ticket_smoke.md',
    [AllowEmptyString()][string]$QueuePath = '',
    [AllowEmptyString()][string]$TakeoverRoot = '',
    [ValidateRange(1, 180)][int]$WindowMinutes = 30,
    [AllowEmptyString()][string]$OutDirRoot = '',
    [switch]$AsJson
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'unattended_exit_result.ps1')
. (Join-Path $PSScriptRoot 'unattended_startfile_identity.ps1')
$script:UnhandledExitTag = 'CHECK-UNATTENDED-EVENT-DEDUP-HEALTH'

trap {
    $exitCode = Get-UnattendedExitCodeFromRecord -Tag $script:UnhandledExitTag -Record $_ -DefaultExitCode 1
    Write-UnattendedUnhandledResult -Tag $script:UnhandledExitTag -Record $_ -ExitCode $exitCode
    exit $exitCode
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path

function Convert-ToSingleLineText {
    param([AllowEmptyString()][string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return ''
    }

    $singleLine = (($Text -split "`r?`n") -join ' ')
    return ([regex]::Replace($singleLine, '\s+', ' ')).Trim()
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

function Get-DateTimeOrNull {
    param([AllowEmptyString()][string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return $null
    }

    $parsed = [datetime]::MinValue
    if ([datetime]::TryParse($Text, [ref]$parsed)) {
        return $parsed
    }

    return $null
}

function New-DedupIssue {
    param(
        [string]$Type,
        [string]$Key,
        [object[]]$Rows,
        [string]$SuggestedAction
    )

    $ticketIds = @($Rows | ForEach-Object { [string]$_.ticket_id } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
    $signatures = @($Rows | ForEach-Object { [string]$_.dedup_signature } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
    $fingerprints = @($Rows | ForEach-Object { [string]$_.failure_fingerprint } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)

    return [ordered]@{
        type = $Type
        key = $Key
        count = @($Rows).Count
        ticket_ids = $ticketIds
        dedup_signatures = $signatures
        failure_fingerprints = $fingerprints
        first_seen = ((@($Rows | Sort-Object created_at | Select-Object -First 1)[0]).created_at)
        last_seen = ((@($Rows | Sort-Object created_at -Descending | Select-Object -First 1)[0]).created_at)
        suggested_action = $SuggestedAction
    }
}

$startFilePath = Resolve-RepoPath -Path $StartFile
$settings = Read-KeyValueFile -Path $startFilePath

$queuePathValue = $QueuePath
if ([string]::IsNullOrWhiteSpace($queuePathValue) -and $settings.Contains('LOCAL_GUARD_AGENT_QUEUE_PATH')) {
    $queuePathValue = ConvertTo-PathLikeValue -Value ([string]$settings.LOCAL_GUARD_AGENT_QUEUE_PATH)
}
if ([string]::IsNullOrWhiteSpace($queuePathValue)) {
    $queuePathValue = 'out\artifacts\ab_agent_queue\agent_tickets.jsonl'
}
$queueFilePath = Resolve-RepoPathAllowMissing -Path $queuePathValue

$takeoverRootPath = $TakeoverRoot
if ([string]::IsNullOrWhiteSpace($takeoverRootPath)) {
    $takeoverRootPath = 'out\artifacts\ab_agent_queue\takeover_requests'
}
$takeoverRootResolved = Resolve-RepoPathAllowMissing -Path $takeoverRootPath

if (-not $OutDirRoot -or $OutDirRoot.Trim().Length -eq 0) {
    $OutDirRoot = Join-Path $repoRoot 'out\artifacts\event_dedup_health'
}
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$outDir = Join-Path $OutDirRoot $stamp
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

$windowStart = (Get-Date).AddMinutes(-1 * $WindowMinutes)

$eventRows = New-Object 'System.Collections.Generic.List[object]'
foreach ($ticket in @(Read-JsonLinesSafely -Path $queueFilePath)) {
    $createdAtRaw = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $ticket -Name 'created_at')
    $createdAt = Get-DateTimeOrNull -Text $createdAtRaw
    if ($null -eq $createdAt -or $createdAt -lt $windowStart) {
        continue
    }

    [void]$eventRows.Add([pscustomobject]@{
        source = 'queue'
        ticket_id = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $ticket -Name 'ticket_id')
        event = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $ticket -Name 'event')
        created_at = $createdAtRaw
        dedup_signature = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $ticket -Name 'dedup_signature')
        failure_fingerprint = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $ticket -Name 'failure_fingerprint')
    })
}

if (-not [string]::IsNullOrWhiteSpace($takeoverRootResolved) -and (Test-Path -LiteralPath $takeoverRootResolved)) {
    foreach ($briefFile in @(Get-ChildItem -LiteralPath $takeoverRootResolved -Filter '*.md' -File -ErrorAction SilentlyContinue)) {
        $briefMeta = Read-KeyValueFile -Path $briefFile.FullName
        $createdAtRaw = if ($briefMeta.Contains('generated_at')) { Convert-ToSingleLineText -Text ([string]$briefMeta.generated_at) } else { '' }
        $createdAt = Get-DateTimeOrNull -Text $createdAtRaw
        if ($null -eq $createdAt -or $createdAt -lt $windowStart) {
            continue
        }

        $briefStartFile = if ($briefMeta.Contains('start_file')) { Resolve-RepoPathAllowMissing -Path ([string]$briefMeta.start_file) } else { '' }
        if (-not [string]::IsNullOrWhiteSpace($briefStartFile) -and $briefStartFile -ne $startFilePath) {
            continue
        }

        [void]$eventRows.Add([pscustomobject]@{
            source = 'brief'
            ticket_id = if ($briefMeta.Contains('ticket_id')) { Convert-ToSingleLineText -Text ([string]$briefMeta.ticket_id) } else { '' }
            event = if ($briefMeta.Contains('event')) { Convert-ToSingleLineText -Text ([string]$briefMeta.event) } else { '' }
            created_at = $createdAtRaw
            dedup_signature = if ($briefMeta.Contains('dedup_signature')) { Convert-ToSingleLineText -Text ([string]$briefMeta.dedup_signature) } else { '' }
            failure_fingerprint = if ($briefMeta.Contains('failure_fingerprint')) { Convert-ToSingleLineText -Text ([string]$briefMeta.failure_fingerprint) } else { '' }
        })
    }
}

$issues = New-Object 'System.Collections.Generic.List[object]'

$rowsArray = @($eventRows.ToArray())
foreach ($signatureGroup in @($rowsArray | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_.dedup_signature) } | Group-Object dedup_signature)) {
    $rows = @($signatureGroup.Group)
    $uniqueTicketCount = @($rows | ForEach-Object { [string]$_.ticket_id } | Select-Object -Unique).Count
    if ($uniqueTicketCount -gt 1) {
        [void]$issues.Add((New-DedupIssue -Type 'duplicate-dedup-signature' -Key ([string]$signatureGroup.Name) -Rows $rows -SuggestedAction 'Inspect trigger/session-guard dedup state and compare repeated tickets before re-enqueueing or acknowledging.'))
    }
}

foreach ($fingerprintGroup in @($rowsArray | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_.failure_fingerprint) } | Group-Object failure_fingerprint)) {
    $rows = @($fingerprintGroup.Group)
    $uniqueSignatureCount = @($rows | ForEach-Object { [string]$_.dedup_signature } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique).Count
    if ($rows.Count -gt 1 -and $uniqueSignatureCount -gt 1) {
        [void]$issues.Add((New-DedupIssue -Type 'repeated-fingerprint-divergent-signature' -Key ([string]$fingerprintGroup.Name) -Rows $rows -SuggestedAction 'Compare run_dir/session status fragments inside dedup_signature and verify whether anchor drift or repeated trigger emission is creating duplicate failure tickets.'))
    }
}

$issuesArray = @($issues.ToArray())
$counts = [ordered]@{
    total = $issuesArray.Count
    duplicate_dedup_signature = @($issuesArray | Where-Object { [string]$_.type -eq 'duplicate-dedup-signature' }).Count
    repeated_fingerprint_divergent_signature = @($issuesArray | Where-Object { [string]$_.type -eq 'repeated-fingerprint-divergent-signature' }).Count
}

$summary = [ordered]@{
    schema = 'AB_EVENT_DEDUP_HEALTH_V1'
    generated_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    start_file = (Convert-ToRepoRelativePath -Path $startFilePath)
    queue_path = (Convert-ToRepoRelativePath -Path $queueFilePath)
    takeover_root = (Convert-ToRepoRelativePath -Path $takeoverRootResolved)
    window_minutes = $WindowMinutes
    observed_rows = $rowsArray.Count
    counts = $counts
    issues = $issuesArray
    pass = ($issuesArray.Count -eq 0)
}

$resultToken = if ($summary.pass) { 'pass' } else { 'fail' }
$summaryJsonPath = Join-Path $outDir 'summary.json'
$summaryTxtPath = Join-Path $outDir 'summary.txt'
($summary | ConvertTo-Json -Depth 8) | Set-Content -LiteralPath $summaryJsonPath -Encoding utf8

$txtLines = New-Object 'System.Collections.Generic.List[string]'
[void]$txtLines.Add(('[AB-EVENT-DEDUP-HEALTH] start_file={0}' -f $summary.start_file))
[void]$txtLines.Add(('[AB-EVENT-DEDUP-HEALTH] queue_path={0}' -f $summary.queue_path))
[void]$txtLines.Add(('[AB-EVENT-DEDUP-HEALTH] takeover_root={0}' -f $summary.takeover_root))
[void]$txtLines.Add(('[AB-EVENT-DEDUP-HEALTH] window_minutes={0} observed_rows={1}' -f $WindowMinutes, $rowsArray.Count))
[void]$txtLines.Add(('[AB-EVENT-DEDUP-HEALTH] counts total={0} duplicate_dedup_signature={1} repeated_fingerprint_divergent_signature={2}' -f $counts.total, $counts.duplicate_dedup_signature, $counts.repeated_fingerprint_divergent_signature))
foreach ($issue in $issuesArray) {
    [void]$txtLines.Add(('[AB-EVENT-DEDUP-HEALTH] issue type={0} key={1} count={2} tickets={3} action={4}' -f [string]$issue.type, [string]$issue.key, [int]$issue.count, ((@($issue.ticket_ids) -join ',')), [string]$issue.suggested_action))
}
[void]$txtLines.Add(('[AB-EVENT-DEDUP-HEALTH] result={0}' -f $resultToken))
$txtLines | Set-Content -LiteralPath $summaryTxtPath -Encoding utf8

Write-Output ('[AB-EVENT-DEDUP-HEALTH] out_dir={0}' -f $outDir)
Write-Output ('[AB-EVENT-DEDUP-HEALTH] summary_json={0}' -f $summaryJsonPath)
Write-Output ('[AB-EVENT-DEDUP-HEALTH] summary_txt={0}' -f $summaryTxtPath)
Write-Output ('[AB-EVENT-DEDUP-HEALTH] counts total={0} duplicate_dedup_signature={1} repeated_fingerprint_divergent_signature={2}' -f $counts.total, $counts.duplicate_dedup_signature, $counts.repeated_fingerprint_divergent_signature)
Write-Output ('[AB-EVENT-DEDUP-HEALTH] result={0}' -f $resultToken)

if ($AsJson.IsPresent) {
    $summary | ConvertTo-Json -Depth 8
}