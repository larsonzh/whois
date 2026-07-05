param(
    [string]$StartFile = 'testdata\unattended_start\smoke\unattended_ab_start_status_ticket_smoke.md',
    [switch]$ApplyAcknowledge,
    [AllowEmptyString()][string]$OutDirRoot = '',
    [switch]$AsJson
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'unattended_exit_result.ps1')
. (Join-Path $PSScriptRoot 'unattended_startfile_identity.ps1')
$script:UnhandledExitTag = 'CHECK-UNATTENDED-FINAL-STATUS-CLOSEOUT'

trap {
    $exitCode = Get-UnattendedExitCodeFromRecord -Tag $script:UnhandledExitTag -Record $_ -DefaultExitCode 1
    Write-UnattendedUnhandledResult -Tag $script:UnhandledExitTag -Record $_ -ExitCode $exitCode
    exit $exitCode
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path

function Convert-ToSingleLineText {
    param([AllowEmptyString()][string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return '' }
    $singleLine = (($Text -split "`r?`n") -join ' ')
    return ([regex]::Replace($singleLine, '\s+', ' ')).Trim()
}

function Read-JsonFileSafely {
    param([AllowEmptyString()][string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) { return $null }
    try {
        $raw = Get-Content -LiteralPath $Path -Raw -Encoding utf8 -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
        return ($raw | ConvertFrom-Json -ErrorAction Stop)
    }
    catch { return $null }
}

function Read-JsonLinesSafely {
    param([AllowEmptyString()][string]$Path)
    $items = New-Object 'System.Collections.Generic.List[object]'
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) { return @($items.ToArray()) }
    foreach ($line in @(Get-Content -LiteralPath $Path -Encoding utf8 -ErrorAction SilentlyContinue)) {
        $trimmed = Convert-ToSingleLineText -Text ([string]$line)
        if ([string]::IsNullOrWhiteSpace($trimmed)) { continue }
        try { [void]$items.Add(($trimmed | ConvertFrom-Json -ErrorAction Stop)) } catch { continue }
    }
    return @($items.ToArray())
}

function ConvertFrom-JsonTail {
    param([AllowEmptyString()][string]$Text)

    $normalized = [string]$Text
    if ([string]::IsNullOrWhiteSpace($normalized)) {
        return $null
    }

    $startIndex = $normalized.LastIndexOf('{')
    while ($startIndex -ge 0) {
        $candidate = $normalized.Substring($startIndex).Trim()
        try {
            return ($candidate | ConvertFrom-Json -ErrorAction Stop)
        }
        catch {
            $startIndex = $normalized.LastIndexOf('{', [Math]::Max(0, $startIndex - 1))
        }
    }

    return $null
}

function Get-ObjectPropertyString {
    param([object]$InputObject, [string]$Name)
    if ($null -eq $InputObject -or [string]::IsNullOrWhiteSpace($Name)) { return '' }
    if ($InputObject -is [System.Collections.IDictionary]) {
        if ($InputObject.Contains($Name)) { return [string]$InputObject[$Name] }
        return ''
    }
    if ($InputObject.PSObject.Properties.Name -contains $Name) { return [string]$InputObject.$Name }
    return ''
}

$startFilePath = Resolve-RepoPath -Path $StartFile
$settings = Read-KeyValueFile -Path $startFilePath

$sessionStatus = if ($settings.Contains('SESSION_FINAL_STATUS')) { (Convert-ToSingleLineText -Text ([string]$settings.SESSION_FINAL_STATUS)).ToUpperInvariant() } else { 'NOT_RUN' }
$aStatus = if ($settings.Contains('A_FINAL_STATUS')) { (Convert-ToSingleLineText -Text ([string]$settings.A_FINAL_STATUS)).ToUpperInvariant() } else { 'NOT_RUN' }
$bStatus = if ($settings.Contains('B_FINAL_STATUS')) { (Convert-ToSingleLineText -Text ([string]$settings.B_FINAL_STATUS)).ToUpperInvariant() } else { 'NOT_RUN' }

$queuePathValue = if ($settings.Contains('LOCAL_GUARD_AGENT_QUEUE_PATH')) { ConvertTo-PathLikeValue -Value ([string]$settings.LOCAL_GUARD_AGENT_QUEUE_PATH) } else { '' }
if ([string]::IsNullOrWhiteSpace($queuePathValue)) { $queuePathValue = 'out\artifacts\ab_agent_queue\agent_tickets.jsonl' }
$queueFilePath = Resolve-RepoPathAllowMissing -Path $queuePathValue

$timelinePath = if ($settings.Contains('MONITOR_CHAIN_TIMELINE')) { Resolve-RepoPathAllowMissing -Path ([string]$settings.MONITOR_CHAIN_TIMELINE) } else { '' }

if (-not $OutDirRoot -or $OutDirRoot.Trim().Length -eq 0) {
    $OutDirRoot = Join-Path $repoRoot 'out\artifacts\final_status_closeout'
}
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$outDir = Join-Path $OutDirRoot $stamp
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

$closureScript = Join-Path $repoRoot 'tools\test\check_unattended_ticket_closure.ps1'
$dedupScript = Join-Path $repoRoot 'tools\test\check_unattended_event_dedup_health.ps1'
$pollScript = Join-Path $repoRoot 'tools\test\poll_agent_tickets.ps1'

$closureObj = $null
if (Test-Path -LiteralPath $closureScript) {
    $closureRaw = & powershell -NoProfile -ExecutionPolicy Bypass -File $closureScript -StartFile $startFilePath -AsJson 2>&1 | Out-String
    $closureObj = ConvertFrom-JsonTail -Text $closureRaw
}

$dedupObj = $null
if (Test-Path -LiteralPath $dedupScript) {
    $dedupRaw = & powershell -NoProfile -ExecutionPolicy Bypass -File $dedupScript -StartFile $startFilePath -AsJson 2>&1 | Out-String
    $dedupObj = ConvertFrom-JsonTail -Text $dedupRaw
}

$queueTickets = @(Read-JsonLinesSafely -Path $queueFilePath)
$finalTickets = @($queueTickets | Where-Object { (Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $_ -Name 'event')).ToLowerInvariant() -eq 'chat-session-final-status' })

$pendingFinalTicketIds = New-Object 'System.Collections.Generic.List[string]'
foreach ($ticket in $finalTickets) {
    $ticketId = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $ticket -Name 'ticket_id')
    if ([string]::IsNullOrWhiteSpace($ticketId)) { continue }
    [void]$pendingFinalTicketIds.Add($ticketId)
}

$ackApplied = $false
$ackReceipt = $null
$ackCommand = ''
if ($pendingFinalTicketIds.Count -gt 0) {
    $ackIdCsv = (@($pendingFinalTicketIds.ToArray()) -join ',')
    $ackCommand = ('powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/poll_agent_tickets.ps1 -StartFile "{0}" -AcknowledgeTicketIds "{1}" -Last 20 -AsJson' -f (Convert-ToRepoRelativePath -Path $startFilePath), $ackIdCsv)
    if ($ApplyAcknowledge.IsPresent) {
        $ackRaw = & powershell -NoProfile -ExecutionPolicy Bypass -File $pollScript -StartFile $startFilePath -AcknowledgeTicketIds $ackIdCsv -Last 20 -AsJson 2>&1 | Out-String
        $ackReceipt = ConvertFrom-JsonTail -Text $ackRaw
        $ackApplied = $true
    }
}

$timelineTail = @()
if (-not [string]::IsNullOrWhiteSpace($timelinePath) -and (Test-Path -LiteralPath $timelinePath)) {
    $timelineTail = @(Get-Content -LiteralPath $timelinePath -Encoding utf8 -ErrorAction SilentlyContinue | Select-Object -Last 8)
}

$closurePass = if ($null -ne $closureObj) { [bool]$closureObj.pass } else { $true }
$dedupPass = if ($null -ne $dedupObj) { [bool]$dedupObj.pass } else { $true }

$summary = [ordered]@{
    schema = 'AB_FINAL_STATUS_CLOSEOUT_V1'
    generated_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    start_file = (Convert-ToRepoRelativePath -Path $startFilePath)
    session_final_status = $sessionStatus
    a_final_status = $aStatus
    b_final_status = $bStatus
    queue_path = (Convert-ToRepoRelativePath -Path $queueFilePath)
    monitor_timeline = (Convert-ToRepoRelativePath -Path $timelinePath)
    pending_final_status_ticket_ids = @($pendingFinalTicketIds.ToArray())
    final_status_ack_command = $ackCommand
    acknowledge_applied = $ackApplied
    acknowledge_receipt = $ackReceipt
    closure_check = $closureObj
    dedup_health = $dedupObj
    timeline_tail = $timelineTail
    pass = (
        $sessionStatus -in @('PASS', 'FAIL', 'BLOCKED') -and
        $closurePass -and
        $dedupPass
    )
}

$resultToken = if ($summary.pass) { 'pass' } else { 'fail' }
$summaryJsonPath = Join-Path $outDir 'summary.json'
$summaryTxtPath = Join-Path $outDir 'summary.txt'
($summary | ConvertTo-Json -Depth 10) | Set-Content -LiteralPath $summaryJsonPath -Encoding utf8

$txtLines = New-Object 'System.Collections.Generic.List[string]'
[void]$txtLines.Add(('[AB-FINAL-STATUS-CLOSEOUT] start_file={0}' -f $summary.start_file))
[void]$txtLines.Add(('[AB-FINAL-STATUS-CLOSEOUT] session={0} a={1} b={2}' -f $sessionStatus, $aStatus, $bStatus))
[void]$txtLines.Add(('[AB-FINAL-STATUS-CLOSEOUT] queue_path={0}' -f $summary.queue_path))
[void]$txtLines.Add(('[AB-FINAL-STATUS-CLOSEOUT] monitor_timeline={0}' -f $summary.monitor_timeline))
[void]$txtLines.Add(('[AB-FINAL-STATUS-CLOSEOUT] pending_final_status_tickets={0}' -f ((@($summary.pending_final_status_ticket_ids) -join ','))))
[void]$txtLines.Add(('[AB-FINAL-STATUS-CLOSEOUT] closure_pass={0} dedup_pass={1}' -f $closurePass, $dedupPass))
if (-not [string]::IsNullOrWhiteSpace($ackCommand)) { [void]$txtLines.Add(('[AB-FINAL-STATUS-CLOSEOUT] final_status_ack_command={0}' -f $ackCommand)) }
[void]$txtLines.Add(('[AB-FINAL-STATUS-CLOSEOUT] result={0}' -f $resultToken))
$txtLines | Set-Content -LiteralPath $summaryTxtPath -Encoding utf8

Write-Output ('[AB-FINAL-STATUS-CLOSEOUT] out_dir={0}' -f $outDir)
Write-Output ('[AB-FINAL-STATUS-CLOSEOUT] summary_json={0}' -f $summaryJsonPath)
Write-Output ('[AB-FINAL-STATUS-CLOSEOUT] summary_txt={0}' -f $summaryTxtPath)
Write-Output ('[AB-FINAL-STATUS-CLOSEOUT] session={0} a={1} b={2}' -f $sessionStatus, $aStatus, $bStatus)
Write-Output ('[AB-FINAL-STATUS-CLOSEOUT] pending_final_status_tickets={0}' -f ((@($summary.pending_final_status_ticket_ids) -join ',')))
Write-Output ('[AB-FINAL-STATUS-CLOSEOUT] result={0}' -f $resultToken)

if ($AsJson.IsPresent) {
    $summary | ConvertTo-Json -Depth 10
}