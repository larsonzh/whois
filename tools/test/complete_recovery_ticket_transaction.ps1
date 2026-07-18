param(
    [Parameter(Mandatory = $true)][string]$StartFile,
    [Parameter(Mandatory = $true)][string]$TicketId,
    [AllowEmptyString()][string]$QueuePath = '',
    [ValidateRange(1, 200)][int]$Last = 20,
    [ValidateRange(30, 900)][int]$BusinessCommandVerifyTimeoutSec = 240,
    [switch]$ShowBusinessCommandWindow,
    [switch]$AsJson
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Convert-ToSingleLineText {
    param([AllowEmptyString()][string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return ''
    }

    $singleLine = (($Text -split "`r?`n") -join ' ')
    return ([regex]::Replace($singleLine, '\s+', ' ')).Trim()
}

function Get-ObjectPropertyString {
    param(
        [AllowNull()][object]$InputObject,
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

    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return ''
    }

    return [string]$property.Value
}

function Test-ListContainsToken {
    param(
        [AllowNull()][object]$Values,
        [AllowEmptyString()][string]$Token
    )

    $needle = (Convert-ToSingleLineText -Text $Token).ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($needle)) {
        return $false
    }

    foreach ($value in @($Values)) {
        $candidate = (Convert-ToSingleLineText -Text ([string]$value)).ToLowerInvariant()
        if ($candidate -eq $needle) {
            return $true
        }
    }

    return $false
}

function Convert-CommandOutputToJson {
    param(
        [object[]]$Output,
        [string]$Step
    )

    $text = [string]::Join("`n", @($Output | ForEach-Object { [string]$_ }))
    $jsonStart = $text.IndexOf('{')
    if ($jsonStart -lt 0) {
        throw ("{0} did not return JSON" -f $Step)
    }

    try {
        return ($text.Substring($jsonStart) | ConvertFrom-Json -ErrorAction Stop)
    }
    catch {
        throw ("{0} returned invalid JSON: {1}" -f $Step, $_.Exception.Message)
    }
}

function Read-KeyValueFile {
    param([string]$Path)

    $values = @{}
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) {
        return $values
    }

    foreach ($line in @(Get-Content -LiteralPath $Path -Encoding utf8)) {
        $text = [string]$line
        $index = $text.IndexOf('=')
        if ($index -le 0) {
            continue
        }

        $key = (Convert-ToSingleLineText -Text $text.Substring(0, $index))
        if ([string]::IsNullOrWhiteSpace($key)) {
            continue
        }

        $values[$key] = $text.Substring($index + 1).Trim()
    }

    return $values
}

function Resolve-RepoPath {
    param(
        [string]$RepoRoot,
        [AllowEmptyString()][string]$Path
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return ''
    }

    try {
        if ([System.IO.Path]::IsPathRooted($Path)) {
            return [System.IO.Path]::GetFullPath($Path)
        }

        return [System.IO.Path]::GetFullPath((Join-Path $RepoRoot $Path))
    }
    catch {
        return ''
    }
}

function Read-StageExitEvidence {
    param(
        [AllowEmptyString()][string]$Stage,
        [AllowEmptyString()][string]$StartFilePath
    )

    $stageToken = (Convert-ToSingleLineText -Text $Stage).ToUpperInvariant()
    $result = [ordered]@{
        Available = $false
        Stage = $stageToken
        ProcessId = 0
        Result = ''
        GeneratedAt = ''
        StartFileMatch = $false
        ArtifactPath = ''
    }

    if ($stageToken -notin @('A', 'B')) {
        return [pscustomobject]$result
    }

    $artifactPath = Join-Path $repoRoot (Join-Path 'out\artifacts\ab_stage_exit' ('latest_{0}_exit.json' -f $stageToken.ToLowerInvariant()))
    $result.ArtifactPath = $artifactPath
    if (-not (Test-Path -LiteralPath $artifactPath)) {
        return [pscustomobject]$result
    }

    try {
        $payload = Get-Content -LiteralPath $artifactPath -Raw -Encoding utf8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        $result.Available = $true
        $result.Stage = (Convert-ToSingleLineText -Text ([string]$payload.stage)).ToUpperInvariant()
        $parsedPid = 0
        if ([int]::TryParse(([string]$payload.process_id), [ref]$parsedPid)) {
            $result.ProcessId = [int]$parsedPid
        }
        $result.Result = (Convert-ToSingleLineText -Text ([string]$payload.result)).ToLowerInvariant()
        $result.GeneratedAt = Convert-ToSingleLineText -Text ([string]$payload.generated_at)

        $artifactStartFile = Convert-ToSingleLineText -Text ([string]$payload.start_file_path)
        if ([string]::IsNullOrWhiteSpace($artifactStartFile) -or [string]::IsNullOrWhiteSpace($StartFilePath)) {
            $result.StartFileMatch = [string]::IsNullOrWhiteSpace($artifactStartFile)
        }
        else {
            $expectedStartFile = [System.IO.Path]::GetFullPath($StartFilePath)
            $actualStartFile = [System.IO.Path]::GetFullPath($artifactStartFile)
            $result.StartFileMatch = $actualStartFile.Equals($expectedStartFile, [System.StringComparison]::OrdinalIgnoreCase)
        }
    }
    catch {
        $result.Available = $false
    }

    return [pscustomobject]$result
}

function Test-ProcessFilteredByTerminalExitArtifact {
    param(
        [AllowNull()][object]$Process,
        [AllowNull()][object]$ExitEvidence
    )

    if ($null -eq $Process -or $null -eq $ExitEvidence) {
        return $false
    }

    if (-not ([bool]$ExitEvidence.Available -and [bool]$ExitEvidence.StartFileMatch)) {
        return $false
    }

    if ([string]$ExitEvidence.Result -notin @('pass', 'fail')) {
        return $false
    }

    if ([int]$ExitEvidence.ProcessId -le 0 -or [int]$Process.ProcessId -ne [int]$ExitEvidence.ProcessId) {
        return $false
    }

    $artifactGeneratedAt = [datetime]::MinValue
    if (-not [datetime]::TryParse(([string]$ExitEvidence.GeneratedAt), [ref]$artifactGeneratedAt)) {
        return $true
    }

    try {
        $processCreatedAt = [datetime]::MinValue
        if ($Process.CreationDate -is [datetime]) {
            $processCreatedAt = [datetime]$Process.CreationDate
        }
        elseif (-not [datetime]::TryParse(([string]$Process.CreationDate), [ref]$processCreatedAt)) {
            $processCreatedAt = [System.Management.ManagementDateTimeConverter]::ToDateTime([string]$Process.CreationDate)
        }
        return ($artifactGeneratedAt -ge $processCreatedAt.AddSeconds(-5))
    }
    catch {
        return $true
    }
}

function Find-TakeoverBriefPath {
    param([string]$TicketId)

    if ([string]::IsNullOrWhiteSpace($TicketId)) {
        return ''
    }

    $takeoverRoot = Join-Path $repoRoot 'out\artifacts\ab_agent_queue\takeover_requests'
    if (-not (Test-Path -LiteralPath $takeoverRoot)) {
        return ''
    }

    $safePattern = ('takeover_{0}_*.md' -f $TicketId)
    $match = @(Get-ChildItem -LiteralPath $takeoverRoot -Filter $safePattern -File | Sort-Object LastWriteTime -Descending | Select-Object -First 1)
    if ($match.Count -eq 0) {
        return ''
    }

    return [string]$match[0].FullName
}

function Get-TransactionRowFromBrief {
    param(
        [string]$TicketId,
        [string]$StartFileRel,
        [AllowEmptyString()][string]$QueuePathRel,
        [int]$Last
    )

    $briefPath = Find-TakeoverBriefPath -TicketId $TicketId
    if ([string]::IsNullOrWhiteSpace($briefPath)) {
        throw ("ticket {0} was not returned by poll_agent_tickets.ps1 and takeover brief was not found" -f $TicketId)
    }

    $brief = Read-KeyValueFile -Path $briefPath
    $briefTicket = Convert-ToSingleLineText -Text ([string]$brief['ticket_id'])
    if ($briefTicket -ne $TicketId) {
        throw ("takeover brief ticket mismatch: expected {0}, got {1}" -f $TicketId, $briefTicket)
    }

    $stage = (Convert-ToSingleLineText -Text ([string]$brief['business_command_stage'])).ToUpperInvariant()
    if ($stage -notin @('A', 'B')) {
        $stage = (Convert-ToSingleLineText -Text ([string]$brief['preferred_stage'])).ToUpperInvariant()
    }
    if ($stage -notin @('A', 'B')) {
        $stage = 'A'
    }

    $queueForCommand = Convert-ToSingleLineText -Text $QueuePathRel
    if ([string]::IsNullOrWhiteSpace($queueForCommand)) {
        $queueForCommand = 'out\artifacts\ab_agent_queue\agent_tickets.jsonl'
    }

    return [pscustomobject]@{
        ticket_id = $TicketId
        event = [string]$brief['event']
        route_guard_command = [string]$brief['route_guard_command']
        business_command = ('powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/open_unattended_ab_stage_window.ps1 -Stage {0} -StartFile "{1}" -StartMonitors' -f $stage, $StartFileRel)
        continue_watch_command = ''
        atomic_closeout_command = [string]$brief['atomic_closeout_command']
        handled_receipt_command = [string]$brief['handled_receipt_command']
        validate_receipt_command = [string]$brief['validate_receipt_command']
        ticket_closure_check_command = [string]$brief['ticket_closure_check_command']
        event_dedup_health_check_command = [string]$brief['event_dedup_health_check_command']
        final_status_closeout_command = [string]$brief['final_status_closeout_command']
        final_status_closeout_apply_ack_command = [string]$brief['final_status_closeout_apply_ack_command']
        source = 'takeover-brief-fallback'
        queue_path = $queueForCommand
        last = $Last
    }
}

function Get-BusinessCommandStage {
    param([AllowEmptyString()][string]$CommandLine)

    $text = Convert-ToSingleLineText -Text $CommandLine
    if ($text -match '(?i)(?:^|\s)-Stage\s+([AB])(?:\s|$)') {
        return $matches[1].ToUpperInvariant()
    }

    return ''
}

function Test-StageMainProcessRunning {
    param([AllowEmptyString()][string]$Stage)

    $processes = @(Get-StageMainProcesses -Stage $Stage)
    return ($processes.Count -gt 0)
}

function Get-StageMainProcesses {
    param([AllowEmptyString()][string]$Stage)

    $stageToken = (Convert-ToSingleLineText -Text $Stage).ToUpperInvariant()
    if ($stageToken -notin @('A', 'B')) {
        return @()
    }

    $pattern = 'start_dev_verify_fastmode_{0}\.ps1' -f $stageToken
    $startFilePath = Resolve-RepoPath -RepoRoot $repoRoot -Path $StartFile
    $exitEvidence = Read-StageExitEvidence -Stage $stageToken -StartFilePath $startFilePath
    $processes = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { [string]$_.CommandLine -match $pattern })
    return @($processes | Where-Object { -not (Test-ProcessFilteredByTerminalExitArtifact -Process $_ -ExitEvidence $exitEvidence) })
}

function Get-StageMainProcessIdText {
    param([AllowEmptyString()][string]$Stage)

    $processes = @(Get-StageMainProcesses -Stage $Stage)
    if ($processes.Count -eq 0) {
        return ''
    }

    return ([string]::Join(',', @($processes | ForEach-Object { [string]$_.ProcessId })))
}

function Invoke-TransactionCommand {
    param(
        [string]$Name,
        [AllowEmptyString()][string]$CommandLine,
        [AllowNull()][object]$AllowedActions,
        [AllowNull()][object]$BlockedActions,
        [string[]]$AllowedTokens,
        [string[]]$BlockedTokens
    )

    $step = [ordered]@{
        name = $Name
        command = $CommandLine
        skipped = $false
        skip_reason = ''
        exit_code = $null
        elapsed_ms = 0
        output = @()
        output_tail = @()
    }

    if ([string]::IsNullOrWhiteSpace($CommandLine)) {
        $step.skipped = $true
        $step.skip_reason = 'empty-command'
        return [pscustomobject]$step
    }

    foreach ($blocked in @($BlockedTokens)) {
        if (Test-ListContainsToken -Values $BlockedActions -Token $blocked) {
            throw ("{0} is blocked by route guard action {1}" -f $Name, $blocked)
        }
    }

    $allowed = $false
    foreach ($allowedToken in @($AllowedTokens)) {
        if (Test-ListContainsToken -Values $AllowedActions -Token $allowedToken) {
            $allowed = $true
            break
        }
    }
    if (-not $allowed) {
        throw ("{0} is not authorized by route guard allowed_actions" -f $Name)
    }

    if ($Name -eq 'business_command') {
        $stage = Get-BusinessCommandStage -CommandLine $CommandLine
        if (Test-StageMainProcessRunning -Stage $stage) {
            $pidText = Get-StageMainProcessIdText -Stage $stage
            $step.skipped = $true
            $step.skip_reason = ('stage-{0}-already-running' -f $stage)
            $step.exit_code = 0
            $step.output = @($step.skip_reason, ('stage_main_pids={0}' -f $pidText))
            $step.output_tail = @($step.skip_reason, ('stage_main_pids={0}' -f $pidText))
            return [pscustomobject]$step
        }

        $watch = [System.Diagnostics.Stopwatch]::StartNew()
        $launcherWindowStyle = if ($ShowBusinessCommandWindow.IsPresent) { 'Normal' } else { 'Hidden' }
        $launcher = Start-Process -FilePath 'powershell.exe' -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', $CommandLine) -WindowStyle $launcherWindowStyle -PassThru
        $verifyTimeoutMs = $BusinessCommandVerifyTimeoutSec * 1000
        $verifiedPidText = ''
        while ($watch.ElapsedMilliseconds -lt $verifyTimeoutMs) {
            if (Test-StageMainProcessRunning -Stage $stage) {
                $verifiedPidText = Get-StageMainProcessIdText -Stage $stage
                break
            }

            [System.Threading.Thread]::Sleep(500)
        }
        $watch.Stop()

        if ([string]::IsNullOrWhiteSpace($verifiedPidText)) {
            throw ('business_command did not start stage-{0} main process within {1}ms' -f $stage, $verifyTimeoutMs)
        }

        $step.exit_code = 0
        $step.elapsed_ms = [int][Math]::Min([int]::MaxValue, $watch.ElapsedMilliseconds)
        $step.output = @('business_command_started_detached', ('launcher_pid={0}' -f $launcher.Id), ('business_command_window_style={0}' -f $launcherWindowStyle), ('business_command_verify_timeout_ms={0}' -f $verifyTimeoutMs), ('stage_main_pids={0}' -f $verifiedPidText), 'stage_main_process_verified')
        $step.output_tail = @('business_command_started_detached', ('launcher_pid={0}' -f $launcher.Id), ('business_command_window_style={0}' -f $launcherWindowStyle), ('business_command_verify_timeout_ms={0}' -f $verifyTimeoutMs), ('stage_main_pids={0}' -f $verifiedPidText), 'stage_main_process_verified')
        return [pscustomobject]$step
    }

    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    $output = @(& powershell -NoProfile -ExecutionPolicy Bypass -Command $CommandLine 2>&1)
    $exitCode = if ($null -eq $LASTEXITCODE) { 0 } else { [int]$LASTEXITCODE }
    $watch.Stop()

    $step.exit_code = $exitCode
    $step.elapsed_ms = [int][Math]::Min([int]::MaxValue, $watch.ElapsedMilliseconds)
    $step.output = @($output | ForEach-Object { [string]$_ })
    $step.output_tail = @($output | Select-Object -Last 12 | ForEach-Object { [string]$_ })

    if ($exitCode -ne 0) {
        throw ("{0} exited with code {1}" -f $Name, $exitCode)
    }

    return [pscustomobject]$step
}

function Write-TransactionResult {
    param(
        [System.Collections.IDictionary]$Result,
        [switch]$Json
    )

    if ($Json.IsPresent) {
        $Result | ConvertTo-Json -Depth 10
        return
    }

    Write-Output ('[AB-RECOVERY-TRANSACTION] ticket={0} success={1} reason={2} handled_at={3}' -f $Result.ticket_id, $Result.success, $Result.reason, $Result.handled_at)
    Write-Output ('[AB-RECOVERY-TRANSACTION] route={0} event={1} elapsed_ms={2}' -f $Result.route_classification, $Result.event, $Result.elapsed_ms)
}

$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$ticket = (Convert-ToSingleLineText -Text $TicketId)
$result = [ordered]@{
    schema = 'AB_RECOVERY_TICKET_TRANSACTION_V1'
    generated_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    success = $false
    reason = 'not-started'
    ticket_id = $ticket
    event = ''
    route_classification = ''
    handled_at = ''
    elapsed_ms = 0
    steps = @()
    closeout = $null
}

$totalWatch = [System.Diagnostics.Stopwatch]::StartNew()
try {
    if ([string]::IsNullOrWhiteSpace($ticket)) {
        throw 'TicketId must not be empty'
    }

    Push-Location $repoRoot
    try {
        $row = $null
        try {
            $queueForBrief = $QueuePath
            if ([string]::IsNullOrWhiteSpace($queueForBrief)) {
                $queueForBrief = 'out\artifacts\ab_agent_queue\agent_tickets.jsonl'
            }
            $row = Get-TransactionRowFromBrief -TicketId $ticket -StartFileRel $StartFile -QueuePathRel $queueForBrief -Last $Last
        }
        catch {
            $row = $null
        }

        if ($null -eq $row) {
            $pollArgs = @(
            '-NoProfile', '-ExecutionPolicy', 'Bypass',
            '-File', (Join-Path $PSScriptRoot 'poll_agent_tickets.ps1'),
            '-StartFile', $StartFile,
            '-IncludeStatusReports',
            '-EnableFallbackStatus', 'false',
            '-SelectTicketId', $ticket,
            '-AllowSelectedProcessedTicket',
            '-Last', [string]$Last,
            '-AsJson'
            )
            if (-not [string]::IsNullOrWhiteSpace($QueuePath)) { $pollArgs += @('-QueuePath', $QueuePath) }
            $pollOutput = @(& powershell @pollArgs 2>&1)
            $pollExitCode = if ($null -eq $LASTEXITCODE) { 0 } else { [int]$LASTEXITCODE }
            if ($pollExitCode -ne 0) {
                throw ("poll exited with code {0}" -f $pollExitCode)
            }

            $poll = Convert-CommandOutputToJson -Output $pollOutput -Step 'poll'
            foreach ($candidate in @($poll.rows)) {
                $candidateId = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $candidate -Name 'ticket_id')
                if ($candidateId -eq $ticket) {
                    $row = $candidate
                    break
                }
            }

            if ($null -eq $row) {
                $queueForFallback = $QueuePath
                if ([string]::IsNullOrWhiteSpace($queueForFallback)) {
                    $queueForFallback = 'out\artifacts\ab_agent_queue\agent_tickets.jsonl'
                }
                $row = Get-TransactionRowFromBrief -TicketId $ticket -StartFileRel $StartFile -QueuePathRel $queueForFallback -Last $Last
            }
        }

        $result.event = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $row -Name 'event')

        $routeCommand = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $row -Name 'route_guard_command')
        if ([string]::IsNullOrWhiteSpace($routeCommand)) {
            throw 'route_guard_command is empty'
        }

        $routeOutput = @(& powershell -NoProfile -ExecutionPolicy Bypass -Command $routeCommand 2>&1)
        $routeExitCode = if ($null -eq $LASTEXITCODE) { 0 } else { [int]$LASTEXITCODE }
        if ($routeExitCode -ne 0) {
            throw ("route guard exited with code {0}" -f $routeExitCode)
        }
        $route = Convert-CommandOutputToJson -Output $routeOutput -Step 'route-guard'
        $allowedActions = @($route.route.allowed_actions)
        $blockedActions = @($route.route.blocked_actions)
        $result.route_classification = Convert-ToSingleLineText -Text ([string]$route.route.classification)

        $businessCommand = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $row -Name 'business_command')
        $continueWatchCommand = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $row -Name 'continue_watch_command')
        $atomicCloseoutCommand = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $row -Name 'atomic_closeout_command')
        $handledReceiptCommand = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $row -Name 'handled_receipt_command')
        $validateReceiptCommand = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $row -Name 'validate_receipt_command')
        $ticketClosureCheckCommand = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $row -Name 'ticket_closure_check_command')
        $eventDedupHealthCheckCommand = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $row -Name 'event_dedup_health_check_command')
        $finalStatusCloseoutCommand = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $row -Name 'final_status_closeout_command')
        $finalStatusCloseoutApplyAckCommand = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $row -Name 'final_status_closeout_apply_ack_command')

        $steps = New-Object 'System.Collections.Generic.List[object]'
        [void]$steps.Add((Invoke-TransactionCommand -Name 'business_command' -CommandLine $businessCommand -AllowedActions $allowedActions -BlockedActions $blockedActions -AllowedTokens @('business_command', 'business_resume') -BlockedTokens @('business_command', 'business_resume', 'stage_restart')))
        [void]$steps.Add((Invoke-TransactionCommand -Name 'continue_watch_command' -CommandLine $continueWatchCommand -AllowedActions $allowedActions -BlockedActions $blockedActions -AllowedTokens @('continue_watch_command') -BlockedTokens @('continue_watch_command', 'guard_restart')))

        if (-not [string]::IsNullOrWhiteSpace($atomicCloseoutCommand)) {
            [void]$steps.Add((Invoke-TransactionCommand -Name 'atomic_closeout_command' -CommandLine $atomicCloseoutCommand -AllowedActions $allowedActions -BlockedActions $blockedActions -AllowedTokens @('handled_at') -BlockedTokens @('handled_at')))
            $closeoutOutput = @($steps[$steps.Count - 1].output)
            $closeoutText = [string]::Join("`n", $closeoutOutput)
            if ($closeoutText.Contains('{')) {
                $closeout = Convert-CommandOutputToJson -Output $closeoutOutput -Step 'atomic-closeout'
                $result.closeout = $closeout
                $result.handled_at = Convert-ToSingleLineText -Text ([string]$closeout.handled_at)
                if (-not ([bool]$closeout.success -and [bool]$closeout.processed -and [bool]$closeout.receipt_valid -and [bool]$closeout.closure_pass -and [string]$closeout.ledger_status -eq 'done' -and -not [string]::IsNullOrWhiteSpace($result.handled_at))) {
                    throw 'atomic closeout machine-fact gate failed'
                }
            }
        }
        else {
            [void]$steps.Add((Invoke-TransactionCommand -Name 'handled_receipt_command' -CommandLine $handledReceiptCommand -AllowedActions $allowedActions -BlockedActions $blockedActions -AllowedTokens @('handled_at') -BlockedTokens @('handled_at')))
            [void]$steps.Add((Invoke-TransactionCommand -Name 'validate_receipt_command' -CommandLine $validateReceiptCommand -AllowedActions $allowedActions -BlockedActions $blockedActions -AllowedTokens @('handled_at') -BlockedTokens @('handled_at')))
        }

        [void]$steps.Add((Invoke-TransactionCommand -Name 'ticket_closure_check_command' -CommandLine $ticketClosureCheckCommand -AllowedActions $allowedActions -BlockedActions $blockedActions -AllowedTokens @('handled_at') -BlockedTokens @('handled_at')))
        [void]$steps.Add((Invoke-TransactionCommand -Name 'event_dedup_health_check_command' -CommandLine $eventDedupHealthCheckCommand -AllowedActions $allowedActions -BlockedActions $blockedActions -AllowedTokens @('handled_at') -BlockedTokens @('handled_at')))
        [void]$steps.Add((Invoke-TransactionCommand -Name 'final_status_closeout_command' -CommandLine $finalStatusCloseoutCommand -AllowedActions $allowedActions -BlockedActions $blockedActions -AllowedTokens @('handled_at') -BlockedTokens @('handled_at')))
        [void]$steps.Add((Invoke-TransactionCommand -Name 'final_status_closeout_apply_ack_command' -CommandLine $finalStatusCloseoutApplyAckCommand -AllowedActions $allowedActions -BlockedActions $blockedActions -AllowedTokens @('handled_at') -BlockedTokens @('handled_at')))

        $result.steps = @($steps.ToArray())
        $result.success = $true
        $result.reason = 'transaction-complete'
    }
    finally {
        Pop-Location
    }
}
catch {
    $result.reason = $_.Exception.Message
}
finally {
    $totalWatch.Stop()
    $result.elapsed_ms = [int][Math]::Min([int]::MaxValue, $totalWatch.ElapsedMilliseconds)
}

Write-TransactionResult -Result $result -Json:$AsJson
if (-not $result.success) {
    exit 2
}
