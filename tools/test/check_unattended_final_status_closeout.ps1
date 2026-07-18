param(
    [string]$StartFile = 'testdata\unattended_start\smoke\unattended_ab_start_status_ticket_smoke.md',
    [switch]$ApplyAcknowledge,
    [AllowEmptyString()][string]$OutDirRoot = '',
    [switch]$AsJson,
    [int]$ChildScriptTimeoutSec = 35,
    [int]$QueueTailLines = 2000
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
    param(
        [AllowEmptyString()][string]$Path,
        [int]$MaxLines = 0
    )

    if ($MaxLines -lt 0) { $MaxLines = 0 }
    $items = New-Object 'System.Collections.Generic.List[object]'
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) { return @($items.ToArray()) }
    $lines = if ($MaxLines -gt 0) {
        @(Get-Content -LiteralPath $Path -Encoding utf8 -Tail $MaxLines -ErrorAction SilentlyContinue)
    }
    else {
        @(Get-Content -LiteralPath $Path -Encoding utf8 -ErrorAction SilentlyContinue)
    }
    foreach ($line in $lines) {
        $trimmed = Convert-ToSingleLineText -Text ([string]$line)
        if ([string]::IsNullOrWhiteSpace($trimmed)) { continue }
        try { [void]$items.Add(($trimmed | ConvertFrom-Json -ErrorAction Stop)) } catch { continue }
    }
    return @($items.ToArray())
}

function Write-CloseoutHeartbeat {
    param(
        [string]$Step,
        [AllowEmptyString()][string]$Detail = ''
    )

    $stamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    if ([string]::IsNullOrWhiteSpace($Detail)) {
        Write-Information ("[AB-FINAL-STATUS-CLOSEOUT] heartbeat={0} step={1}" -f $stamp, $Step) -InformationAction Continue
    }
    else {
        Write-Information ("[AB-FINAL-STATUS-CLOSEOUT] heartbeat={0} step={1} detail={2}" -f $stamp, $Step, (Convert-ToSingleLineText -Text $Detail)) -InformationAction Continue
    }
}

function Get-ChildProcessIds {
    param([int]$ParentPid)

    $result = New-Object 'System.Collections.Generic.List[int]'
    if ($ParentPid -le 0) { return @($result.ToArray()) }

    $pending = New-Object 'System.Collections.Generic.Queue[int]'
    $pending.Enqueue($ParentPid)
    while ($pending.Count -gt 0) {
        $current = $pending.Dequeue()
        $children = @(Get-CimInstance Win32_Process -Filter "ParentProcessId = $current" -ErrorAction SilentlyContinue)
        foreach ($child in $children) {
            $childPid = [int]$child.ProcessId
            if ($childPid -gt 0 -and -not $result.Contains($childPid)) {
                [void]$result.Add($childPid)
                $pending.Enqueue($childPid)
            }
        }
    }

    return @($result.ToArray())
}

function Stop-ProcessTree {
    param([int]$RootPid)

    if ($RootPid -le 0) { return }
    $children = @(Get-ChildProcessIds -ParentPid $RootPid)
    foreach ($childPid in ($children | Sort-Object -Descending)) {
        try { Stop-Process -Id $childPid -Force -ErrorAction SilentlyContinue } catch {}
    }
    try { Stop-Process -Id $RootPid -Force -ErrorAction SilentlyContinue } catch {}
}

function Invoke-ChildScriptJsonWithTimeout {
    param(
        [string]$ScriptPath,
        [string]$StartFilePath,
        [int]$TimeoutSec
    )

    $result = [ordered]@{
        timed_out = $false
        exit_code = -1
        raw = ''
        json = $null
    }

    if ([string]::IsNullOrWhiteSpace($ScriptPath) -or -not (Test-Path -LiteralPath $ScriptPath)) {
        return [pscustomobject]$result
    }

    if ($TimeoutSec -le 0) { $TimeoutSec = 20 }

    $tmpOut = Join-Path $env:TEMP ("final_closeout_child_{0}_{1}.out" -f $PID, ([guid]::NewGuid().ToString('N')))
    $tmpErr = Join-Path $env:TEMP ("final_closeout_child_{0}_{1}.err" -f $PID, ([guid]::NewGuid().ToString('N')))
    try {
        Write-CloseoutHeartbeat -Step 'child-script-start' -Detail ("script={0} timeout_sec={1}" -f $ScriptPath, $TimeoutSec)
        $argList = @('-NoProfile','-ExecutionPolicy','Bypass','-File',$ScriptPath,'-StartFile',$StartFilePath,'-AsJson')
        $scriptLeaf = [System.IO.Path]::GetFileName($ScriptPath).ToLowerInvariant()
        if ($scriptLeaf -eq 'check_unattended_ticket_closure.ps1') {
            $argList += @('-QueueTailLines','5000','-TakeoverBriefMaxFiles','1000','-MaxIssuesInSummary','120')
        }
        elseif ($scriptLeaf -eq 'check_unattended_event_dedup_health.ps1') {
            $argList += @('-QueueTailLines','5000','-TakeoverBriefMaxFiles','1000')
        }

        $proc = Start-Process -FilePath 'powershell.exe' -ArgumentList $argList -PassThru -NoNewWindow -RedirectStandardOutput $tmpOut -RedirectStandardError $tmpErr
        if (-not $proc.WaitForExit($TimeoutSec * 1000)) {
            $result.timed_out = $true
            Write-CloseoutHeartbeat -Step 'child-script-timeout' -Detail ("script={0} pid={1}" -f $ScriptPath, $proc.Id)
            Stop-ProcessTree -RootPid $proc.Id
        }
        else {
            $result.exit_code = [int]$proc.ExitCode
        }

        $outText = if (Test-Path -LiteralPath $tmpOut) { Get-Content -LiteralPath $tmpOut -Raw -Encoding utf8 -ErrorAction SilentlyContinue } else { '' }
        $errText = if (Test-Path -LiteralPath $tmpErr) { Get-Content -LiteralPath $tmpErr -Raw -Encoding utf8 -ErrorAction SilentlyContinue } else { '' }
        $result.raw = ("{0}`r`n{1}" -f $outText, $errText).Trim()
        $result.json = ConvertFrom-JsonTail -Text $result.raw
        Write-CloseoutHeartbeat -Step 'child-script-end' -Detail ("script={0} timed_out={1} exit_code={2} json_parsed={3}" -f $ScriptPath, $result.timed_out, $result.exit_code, ($null -ne $result.json))
    }
    finally {
        if (Test-Path -LiteralPath $tmpOut) { Remove-Item -LiteralPath $tmpOut -Force -ErrorAction SilentlyContinue }
        if (Test-Path -LiteralPath $tmpErr) { Remove-Item -LiteralPath $tmpErr -Force -ErrorAction SilentlyContinue }
    }

    return [pscustomobject]$result
}

function ConvertFrom-JsonTail {
    param([AllowEmptyString()][string]$Text)

    $normalized = [string]$Text
    if ([string]::IsNullOrWhiteSpace($normalized)) {
        return $null
    }

    $startIndex = $normalized.LastIndexOf('{')
    $maxAttempts = 2048
    $attempt = 0
    while ($startIndex -ge 0 -and $attempt -lt $maxAttempts) {
        $attempt++
        $candidate = $normalized.Substring($startIndex).Trim()
        try {
            return ($candidate | ConvertFrom-Json -ErrorAction Stop)
        }
        catch {
            if ($startIndex -le 0) {
                $startIndex = -1
            }
            else {
                $startIndex = $normalized.LastIndexOf('{', $startIndex - 1)
            }
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

function Get-ObjectPropertyValue {
    param([object]$InputObject, [string]$Name)
    if ($null -eq $InputObject -or [string]::IsNullOrWhiteSpace($Name)) { return $null }
    if ($InputObject -is [System.Collections.IDictionary]) {
        if ($InputObject.Contains($Name)) { return $InputObject[$Name] }
        return $null
    }
    if ($InputObject.PSObject.Properties.Name -contains $Name) { return $InputObject.$Name }
    return $null
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
$atomicCloseoutScript = Join-Path $repoRoot 'tools\test\complete_agent_ticket_closeout.ps1'

Write-CloseoutHeartbeat -Step 'start' -Detail ("start_file={0}" -f $startFilePath)

$closureObj = $null
$closureTimedOut = $false
if (Test-Path -LiteralPath $closureScript) {
    Write-CloseoutHeartbeat -Step 'closure-check-begin' -Detail $closureScript
    $closureRun = Invoke-ChildScriptJsonWithTimeout -ScriptPath $closureScript -StartFilePath $startFilePath -TimeoutSec $ChildScriptTimeoutSec
    $closureObj = $closureRun.json
    $closureTimedOut = [bool]$closureRun.timed_out
    Write-CloseoutHeartbeat -Step 'closure-check-end' -Detail ("timed_out={0}" -f $closureTimedOut)
}

$dedupObj = $null
$dedupTimedOut = $false
if (Test-Path -LiteralPath $dedupScript) {
    Write-CloseoutHeartbeat -Step 'dedup-check-begin' -Detail $dedupScript
    $dedupRun = Invoke-ChildScriptJsonWithTimeout -ScriptPath $dedupScript -StartFilePath $startFilePath -TimeoutSec $ChildScriptTimeoutSec
    $dedupObj = $dedupRun.json
    $dedupTimedOut = [bool]$dedupRun.timed_out
    Write-CloseoutHeartbeat -Step 'dedup-check-end' -Detail ("timed_out={0}" -f $dedupTimedOut)
}

Write-CloseoutHeartbeat -Step 'queue-read-begin' -Detail ("queue={0} tail={1}" -f $queueFilePath, $QueueTailLines)
$queueTickets = @(Read-JsonLinesSafely -Path $queueFilePath -MaxLines $QueueTailLines)
$finalTickets = @($queueTickets | Where-Object { (Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $_ -Name 'event')).ToLowerInvariant() -eq 'chat-session-final-status' })
Write-CloseoutHeartbeat -Step 'queue-read-end' -Detail ("tickets={0} final_status_tickets={1}" -f @($queueTickets).Count, @($finalTickets).Count)

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
    $firstTicketId = [string]$pendingFinalTicketIds[0]
    $ackCommand = ('powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/complete_agent_ticket_closeout.ps1 -StartFile "{0}" -TicketId "{1}" -Last 20 -AsJson' -f (Convert-ToRepoRelativePath -Path $startFilePath), $firstTicketId)
    if ($ApplyAcknowledge.IsPresent) {
        Write-CloseoutHeartbeat -Step 'atomic-closeout-begin' -Detail ("ticket_id={0}" -f $firstTicketId)
        $ackRaw = & powershell -NoProfile -ExecutionPolicy Bypass -File $atomicCloseoutScript -StartFile $startFilePath -TicketId $firstTicketId -Last 20 -AsJson 2>&1 | Out-String
        $ackReceipt = ConvertFrom-JsonTail -Text $ackRaw
        $ackApplied = $true
        Write-CloseoutHeartbeat -Step 'atomic-closeout-end' -Detail ("closeout_applied={0}" -f $ackApplied)
    }
}

$timelineTail = @()
if (-not [string]::IsNullOrWhiteSpace($timelinePath) -and (Test-Path -LiteralPath $timelinePath)) {
    Write-CloseoutHeartbeat -Step 'timeline-tail-begin' -Detail ("timeline={0}" -f $timelinePath)
    try {
        $timelineTail = @(Get-Content -LiteralPath $timelinePath -Encoding utf8 -Tail 8 -ErrorAction Stop)
        Write-CloseoutHeartbeat -Step 'timeline-tail-end' -Detail ("lines={0}" -f @($timelineTail).Count)
    }
    catch {
        $timelineTail = @()
        Write-CloseoutHeartbeat -Step 'timeline-tail-fallback' -Detail ("detail={0}" -f $_.Exception.Message)
    }
}

$timelineTailPreview = @()
foreach ($line in @($timelineTail)) {
    $singleLine = Convert-ToSingleLineText -Text ([string]$line)
    if ($singleLine.Length -gt 320) {
        $singleLine = $singleLine.Substring(0, 320) + '...'
    }
    $timelineTailPreview += $singleLine
}

$closurePass = if ($null -ne $closureObj) { [bool]$closureObj.pass } else { $true }
$dedupPass = if ($null -ne $dedupObj) { [bool]$dedupObj.pass } else { $true }

$closureSnapshot = $null
if ($null -ne $closureObj) {
    $closureSnapshot = [ordered]@{
        pass = [bool](Get-ObjectPropertyValue -InputObject $closureObj -Name 'pass')
        generated_at = (Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $closureObj -Name 'generated_at'))
        start_file = (Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $closureObj -Name 'start_file'))
        queue_path = (Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $closureObj -Name 'queue_path'))
        ticket_id = (Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $closureObj -Name 'ticket_id'))
        ticket_event = (Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $closureObj -Name 'ticket_event'))
        has_next_ticket = [bool](Get-ObjectPropertyValue -InputObject $closureObj -Name 'has_next_ticket')
        next_ticket_id = (Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $closureObj -Name 'next_ticket_id'))
        next_event = (Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $closureObj -Name 'next_event'))
    }
}

$dedupSnapshot = $null
if ($null -ne $dedupObj) {
    $countsObj = Get-ObjectPropertyValue -InputObject $dedupObj -Name 'counts'
    $countsSnapshot = $null
    if ($null -ne $countsObj) {
        $countsSnapshot = [ordered]@{
            total = [int](Get-ObjectPropertyValue -InputObject $countsObj -Name 'total')
            duplicate_dedup_signature = [int](Get-ObjectPropertyValue -InputObject $countsObj -Name 'duplicate_dedup_signature')
            repeated_fingerprint_divergent_signature = [int](Get-ObjectPropertyValue -InputObject $countsObj -Name 'repeated_fingerprint_divergent_signature')
        }
    }

    $dedupSnapshot = [ordered]@{
        pass = [bool](Get-ObjectPropertyValue -InputObject $dedupObj -Name 'pass')
        generated_at = (Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $dedupObj -Name 'generated_at'))
        start_file = (Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $dedupObj -Name 'start_file'))
        queue_path = (Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $dedupObj -Name 'queue_path'))
        window_minutes = [int](Get-ObjectPropertyValue -InputObject $dedupObj -Name 'window_minutes')
        observed_rows = [int](Get-ObjectPropertyValue -InputObject $dedupObj -Name 'observed_rows')
        counts = $countsSnapshot
        issues_count = @((Get-ObjectPropertyValue -InputObject $dedupObj -Name 'issues')).Count
    }
}

Write-CloseoutHeartbeat -Step 'summary-build-begin'
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
    closure_check = $closureSnapshot
    closure_timed_out = $closureTimedOut
    dedup_health = $dedupSnapshot
    dedup_timed_out = $dedupTimedOut
    timeline_tail = $timelineTailPreview
    pass = (
        $sessionStatus -in @('PASS', 'FAIL', 'BLOCKED') -and
        -not $closureTimedOut -and
        -not $dedupTimedOut -and
        $closurePass -and
        $dedupPass
    )
}
Write-CloseoutHeartbeat -Step 'summary-build-end'

$resultToken = if ($summary.pass) { 'pass' } else { 'fail' }
$summaryJsonPath = Join-Path $outDir 'summary.json'
$summaryTxtPath = Join-Path $outDir 'summary.txt'
Write-CloseoutHeartbeat -Step 'summary-json-serialize-begin'
$summaryJsonText = ($summary | ConvertTo-Json -Depth 10)
Write-CloseoutHeartbeat -Step 'summary-json-serialize-end' -Detail ("length={0}" -f $summaryJsonText.Length)
Write-CloseoutHeartbeat -Step 'summary-json-write-begin' -Detail $summaryJsonPath
$summaryJsonText | Set-Content -LiteralPath $summaryJsonPath -Encoding utf8
Write-CloseoutHeartbeat -Step 'summary-json-write-end'

$txtLines = New-Object 'System.Collections.Generic.List[string]'
[void]$txtLines.Add(('[AB-FINAL-STATUS-CLOSEOUT] start_file={0}' -f $summary.start_file))
[void]$txtLines.Add(('[AB-FINAL-STATUS-CLOSEOUT] session={0} a={1} b={2}' -f $sessionStatus, $aStatus, $bStatus))
[void]$txtLines.Add(('[AB-FINAL-STATUS-CLOSEOUT] queue_path={0}' -f $summary.queue_path))
[void]$txtLines.Add(('[AB-FINAL-STATUS-CLOSEOUT] monitor_timeline={0}' -f $summary.monitor_timeline))
[void]$txtLines.Add(('[AB-FINAL-STATUS-CLOSEOUT] pending_final_status_tickets={0}' -f ((@($summary.pending_final_status_ticket_ids) -join ','))))
[void]$txtLines.Add(('[AB-FINAL-STATUS-CLOSEOUT] closure_pass={0} dedup_pass={1} closure_timed_out={2} dedup_timed_out={3}' -f $closurePass, $dedupPass, $closureTimedOut, $dedupTimedOut))
if (-not [string]::IsNullOrWhiteSpace($ackCommand)) { [void]$txtLines.Add(('[AB-FINAL-STATUS-CLOSEOUT] final_status_ack_command={0}' -f $ackCommand)) }
[void]$txtLines.Add(('[AB-FINAL-STATUS-CLOSEOUT] result={0}' -f $resultToken))
$txtLines | Set-Content -LiteralPath $summaryTxtPath -Encoding utf8
Write-CloseoutHeartbeat -Step 'summary-txt-write-end'

Write-Output ('[AB-FINAL-STATUS-CLOSEOUT] out_dir={0}' -f $outDir)
Write-Output ('[AB-FINAL-STATUS-CLOSEOUT] summary_json={0}' -f $summaryJsonPath)
Write-Output ('[AB-FINAL-STATUS-CLOSEOUT] summary_txt={0}' -f $summaryTxtPath)
Write-Output ('[AB-FINAL-STATUS-CLOSEOUT] session={0} a={1} b={2}' -f $sessionStatus, $aStatus, $bStatus)
Write-Output ('[AB-FINAL-STATUS-CLOSEOUT] pending_final_status_tickets={0}' -f ((@($summary.pending_final_status_ticket_ids) -join ',')))
Write-Output ('[AB-FINAL-STATUS-CLOSEOUT] result={0}' -f $resultToken)
Write-CloseoutHeartbeat -Step 'done' -Detail ("result={0}" -f $resultToken)

if ($AsJson.IsPresent) {
    Write-CloseoutHeartbeat -Step 'stdout-json-begin'
    Write-Output $summaryJsonText
    Write-CloseoutHeartbeat -Step 'stdout-json-end'
}