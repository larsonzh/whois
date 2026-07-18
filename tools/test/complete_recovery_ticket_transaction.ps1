param(
    [Parameter(Mandatory = $true)][string]$StartFile,
    [Parameter(Mandatory = $true)][string]$TicketId,
    [AllowEmptyString()][string]$QueuePath = '',
    [ValidateRange(1, 200)][int]$Last = 20,
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
        $pollArgs = @(
            '-NoProfile', '-ExecutionPolicy', 'Bypass',
            '-File', (Join-Path $PSScriptRoot 'poll_agent_tickets.ps1'),
            '-StartFile', $StartFile,
            '-IncludeStatusReports',
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
        $row = $null
        foreach ($candidate in @($poll.rows)) {
            $candidateId = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $candidate -Name 'ticket_id')
            if ($candidateId -eq $ticket) {
                $row = $candidate
                break
            }
        }
        if ($null -eq $row) {
            throw ("ticket {0} was not returned by poll_agent_tickets.ps1" -f $ticket)
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
