param(
    [Parameter(Mandatory = $true)][string]$StartFile,
    [ValidateRange(1, 200)][int]$Last = 20,
    [switch]$NoIncludeStatusReports,
    [switch]$EnableExecute,
    [AllowEmptyString()][string]$AllowedTicketIds = '',
    [AllowEmptyString()][string]$ExecutionToken = '',
    [AllowEmptyString()][string]$ExecutionTokenSettingKey = 'LOCAL_GUARD_STATUS_ONLY_AUTOFLOW_EXEC_TOKEN',
    [switch]$AllowNonStatusEvent,
    [switch]$ContinueOnCommandFailure,
    [switch]$DryRun,
    [switch]$AsJson
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'unattended_exit_result.ps1')
$script:UnhandledExitTag = 'RUN-UNATTENDED-STATUS-ONLY-AUTOFLOW'

trap {
    Write-UnattendedUnhandledResult -Tag $script:UnhandledExitTag -Record $_
    exit 1
}

function Convert-ToSingleLineText {
    param([AllowEmptyString()][string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return ''
    }

    return ([regex]::Replace($Text.Trim(), '\s+', ' '))
}

function Get-NormalizedListValueSet {
    param([AllowEmptyString()][string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return @()
    }

    $items = New-Object 'System.Collections.Generic.List[string]'
    foreach ($token in @($Value -split '[,;\r\n]+')) {
        $normalized = Convert-ToSingleLineText -Text ([string]$token)
        if ([string]::IsNullOrWhiteSpace($normalized)) {
            continue
        }

        [void]$items.Add($normalized)
    }

    return @($items.ToArray())
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

function Get-ObjectPropertyBoolean {
    param(
        [AllowNull()][object]$InputObject,
        [string]$Name,
        [bool]$Default = $false
    )

    $raw = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $InputObject -Name $Name)
    if ([string]::IsNullOrWhiteSpace($raw)) {
        return $Default
    }

    return $raw.ToLowerInvariant() -in @('1', 'true', 'yes', 'on')
}

function Get-NormalizedStringList {
    param([AllowNull()][object]$Values)

    $list = New-Object 'System.Collections.Generic.List[string]'
    foreach ($item in @($Values)) {
        $normalized = (Convert-ToSingleLineText -Text ([string]$item)).ToLowerInvariant()
        if ([string]::IsNullOrWhiteSpace($normalized)) {
            continue
        }

        [void]$list.Add($normalized)
    }

    return @($list.ToArray())
}

function Get-RequiredRouteActionsForStep {
    param([string]$StepName)

    switch ((Convert-ToSingleLineText -Text $StepName).ToLowerInvariant()) {
        'business_command' { return @('business_command', 'business_resume') }
        'continue_watch_command' { return @('continue_watch_command', 'read-only-watch') }
        'handled_receipt_command' { return @('handled_at', 'mark-handled') }
        'validate_receipt_command' { return @('handled_at', 'mark-handled') }
        'mark_processed_command' { return @('handled_at', 'mark-handled') }
        'post_check_command' { return @('read-only-watch', 'manual-review', 'handled_at', 'mark-handled') }
        default { return @() }
    }
}

function Test-AnyRequiredRouteActionAllowed {
    param(
        [string[]]$AllowedActions,
        [string[]]$RequiredActions
    )

    if ($null -eq $RequiredActions -or $RequiredActions.Count -eq 0) {
        return $true
    }

    $allowSet = @{}
    foreach ($action in @($AllowedActions)) {
        $normalized = (Convert-ToSingleLineText -Text ([string]$action)).ToLowerInvariant()
        if ([string]::IsNullOrWhiteSpace($normalized)) {
            continue
        }

        $allowSet[$normalized] = $true
    }

    foreach ($required in @($RequiredActions)) {
        $normalizedRequired = (Convert-ToSingleLineText -Text ([string]$required)).ToLowerInvariant()
        if ([string]::IsNullOrWhiteSpace($normalizedRequired)) {
            continue
        }

        if ($allowSet.Contains($normalizedRequired)) {
            return $true
        }
    }

    return $false
}

function Invoke-RouteGuardStep {
    param([AllowEmptyString()][string]$Command)

    $normalized = Convert-ToSingleLineText -Text $Command
    $result = [ordered]@{
        step = 'route_guard_command'
        command = $normalized
        dry_run = $false
        attempted = $false
        succeeded = $false
        exit_code = -1
        output = ''
        error = ''
        classification = ''
        recommended_action = ''
        allowed_actions = @()
        blocked_actions = @()
        must_trigger_business_resume = $false
    }

    if ([string]::IsNullOrWhiteSpace($normalized)) {
        $result.error = 'route-guard-command-empty'
        return [pscustomobject]$result
    }

    $result.attempted = $true

    try {
        $output = & powershell -NoProfile -ExecutionPolicy Bypass -Command $normalized 2>&1
        $exitCode = $LASTEXITCODE
        if ($null -eq $exitCode) {
            $exitCode = 0
        }

        $result.exit_code = [int]$exitCode
        $result.output = (($output | Out-String).Trim())
        if ([int]$exitCode -ne 0) {
            $result.error = ('exit-code-{0}' -f [int]$exitCode)
            return [pscustomobject]$result
        }

        $jsonText = [string]$result.output
        if ([string]::IsNullOrWhiteSpace($jsonText)) {
            $result.error = 'route-guard-empty-output'
            return [pscustomobject]$result
        }

        $guard = $jsonText | ConvertFrom-Json -ErrorAction Stop
        if ($null -eq $guard -or $null -eq $guard.route) {
            $result.error = 'route-guard-invalid-json'
            return [pscustomobject]$result
        }

        $result.classification = Convert-ToSingleLineText -Text ([string](Get-ObjectPropertyString -InputObject $guard.route -Name 'classification'))
        $result.recommended_action = Convert-ToSingleLineText -Text ([string](Get-ObjectPropertyString -InputObject $guard.route -Name 'recommended_action'))
        $result.must_trigger_business_resume = Get-ObjectPropertyBoolean -InputObject $guard.route -Name 'must_trigger_business_resume' -Default $false
        $result.allowed_actions = @(Get-NormalizedStringList -Values $guard.route.allowed_actions)
        $result.blocked_actions = @(Get-NormalizedStringList -Values $guard.route.blocked_actions)

        if ([string]::IsNullOrWhiteSpace([string]$result.classification)) {
            $result.error = 'route-guard-missing-classification'
            return [pscustomobject]$result
        }

        $result.succeeded = $true
        $result.output = Convert-ToSingleLineText -Text ([string]$result.output)
    }
    catch {
        $result.exit_code = 1
        $result.succeeded = $false
        $result.error = Convert-ToSingleLineText -Text $_.Exception.Message
    }

    return [pscustomobject]$result
}

function Get-StepResult {
    param(
        [string]$Name,
        [string]$Command,
        [bool]$DryRunMode
    )

    return [ordered]@{
        step = $Name
        command = $Command
        dry_run = $DryRunMode
        attempted = $false
        succeeded = $false
        exit_code = -1
        output = ''
        error = ''
    }
}

function Invoke-CommandStep {
    param(
        [string]$Name,
        [AllowEmptyString()][string]$Command,
        [bool]$DryRunMode
    )

    $normalized = Convert-ToSingleLineText -Text $Command
    $result = Get-StepResult -Name $Name -Command $normalized -DryRunMode $DryRunMode

    if ([string]::IsNullOrWhiteSpace($normalized)) {
        $result.error = 'command-empty'
        return [pscustomobject]$result
    }

    if ($DryRunMode) {
        $result.attempted = $true
        $result.succeeded = $true
        $result.exit_code = 0
        $result.output = 'dry-run skipped execution'
        return [pscustomobject]$result
    }

    $result.attempted = $true

    try {
        $output = & powershell -NoProfile -ExecutionPolicy Bypass -Command $normalized 2>&1
        $exitCode = $LASTEXITCODE
        if ($null -eq $exitCode) {
            $exitCode = 0
        }

        $result.exit_code = [int]$exitCode
        $result.output = Convert-ToSingleLineText -Text (($output | Out-String).Trim())
        $result.succeeded = ([int]$exitCode -eq 0)
        if (-not $result.succeeded) {
            $result.error = ('exit-code-{0}' -f [int]$exitCode)
        }
    }
    catch {
        $result.exit_code = 1
        $result.succeeded = $false
        $result.error = Convert-ToSingleLineText -Text $_.Exception.Message
    }

    return [pscustomobject]$result
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$routineScript = Join-Path $repoRoot 'tools\test\check_unattended_routine_status.ps1'
if (-not (Test-Path -LiteralPath $routineScript)) {
    throw ('routine script not found: {0}' -f $routineScript)
}

$startFilePath = if ([System.IO.Path]::IsPathRooted($StartFile)) {
    [System.IO.Path]::GetFullPath($StartFile)
}
else {
    [System.IO.Path]::GetFullPath((Join-Path $repoRoot $StartFile))
}
if (-not (Test-Path -LiteralPath $startFilePath)) {
    throw ('start file not found: {0}' -f $startFilePath)
}

$startSettings = Read-KeyValueFile -Path $startFilePath
$tokenSettingKey = Convert-ToSingleLineText -Text $ExecutionTokenSettingKey
if ([string]::IsNullOrWhiteSpace($tokenSettingKey)) {
    $tokenSettingKey = 'LOCAL_GUARD_STATUS_ONLY_AUTOFLOW_EXEC_TOKEN'
}
$requiredExecutionToken = ''
if ($startSettings.Contains($tokenSettingKey)) {
    $requiredExecutionToken = Convert-ToSingleLineText -Text ([string]$startSettings[$tokenSettingKey])
}
$providedExecutionToken = Convert-ToSingleLineText -Text $ExecutionToken
$tokenConfigured = -not [string]::IsNullOrWhiteSpace($requiredExecutionToken)
$tokenProvided = -not [string]::IsNullOrWhiteSpace($providedExecutionToken)
$tokenMatched = $tokenConfigured -and $tokenProvided -and ($requiredExecutionToken -eq $providedExecutionToken)

$routineParams = @{
    StartFile = $StartFile
    Last = $Last
    AsJson = $true
}
if ($NoIncludeStatusReports.IsPresent) {
    $routineParams.NoIncludeStatusReports = $true
}

$routineRaw = & $routineScript @routineParams
$routineJson = (($routineRaw | Out-String).Trim())
if ([string]::IsNullOrWhiteSpace($routineJson)) {
    throw 'routine check returned empty output'
}

$routine = $routineJson | ConvertFrom-Json
$verdict = (Convert-ToSingleLineText -Text ([string]$routine.verdict)).ToLowerInvariant()
$selectedTicket = $routine.commands.selected_ticket
$selectedTicketId = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $selectedTicket -Name 'ticket_id')
$selectedEvent = (Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $selectedTicket -Name 'event')).ToLowerInvariant()
$routeGuardCommand = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $selectedTicket -Name 'route_guard_command')
$hasRouteGuardCommand = -not [string]::IsNullOrWhiteSpace($routeGuardCommand)

$allowExecuteMode = [bool]$DryRun.IsPresent -or [bool]$EnableExecute.IsPresent
$executeTokenAllowed = $tokenConfigured -and $tokenMatched
$allowedTicketSet = @{}
foreach ($ticketId in @(Get-NormalizedListValueSet -Value $AllowedTicketIds)) {
    if (-not $allowedTicketSet.Contains($ticketId)) {
        $allowedTicketSet[$ticketId] = $true
    }
}
$hasTicketWhitelist = ($allowedTicketSet.Count -gt 0)
$ticketAllowed = (-not $hasTicketWhitelist) -or $allowedTicketSet.Contains($selectedTicketId)

$statusOnly = ($verdict -eq 'status-only')
$eventAllowed = ($selectedEvent -eq 'running-status-report') -or $AllowNonStatusEvent.IsPresent
$canExecute = $statusOnly -and ($null -ne $selectedTicket) -and $eventAllowed -and $allowExecuteMode -and $ticketAllowed -and $executeTokenAllowed -and $hasRouteGuardCommand

$results = New-Object 'System.Collections.Generic.List[object]'
$reason = 'ready'
$routeGuardStepResult = $null
$routeGuardClassification = ''
$routeGuardRecommendedAction = ''
$routeGuardAllowedActions = @()
$routeGuardBlockedActions = @()
$routeGuardMustTriggerBusinessResume = $false

if (-not $statusOnly) {
    $reason = ('skip-verdict-{0}' -f $verdict)
}
elseif ($null -eq $selectedTicket) {
    $reason = 'skip-no-selected-ticket'
}
elseif (-not $eventAllowed) {
    $reason = ('skip-event-{0}' -f $selectedEvent)
}
elseif (-not $allowExecuteMode) {
    $reason = 'skip-execute-disabled-use-enableexecute-or-dryrun'
}
elseif (-not $tokenConfigured) {
    $reason = ('skip-execution-token-not-configured-key-{0}' -f $tokenSettingKey)
}
elseif (-not $tokenProvided) {
    $reason = 'skip-execution-token-missing'
}
elseif (-not $tokenMatched) {
    $reason = 'skip-execution-token-mismatch'
}
elseif (-not $ticketAllowed) {
    $reason = ('skip-ticket-not-whitelisted-{0}' -f $selectedTicketId)
}
elseif (-not $hasRouteGuardCommand) {
    $reason = 'skip-route-guard-command-missing'
}

if ($canExecute) {
    $routeGuardStepResult = Invoke-RouteGuardStep -Command $routeGuardCommand
    [void]$results.Add($routeGuardStepResult)

    if (-not [bool]$routeGuardStepResult.succeeded) {
        $reason = 'failed-step-route_guard_command'
    }
    else {
        $routeGuardClassification = Convert-ToSingleLineText -Text ([string]$routeGuardStepResult.classification)
        $routeGuardRecommendedAction = Convert-ToSingleLineText -Text ([string]$routeGuardStepResult.recommended_action)
        $routeGuardAllowedActions = @(Get-NormalizedStringList -Values $routeGuardStepResult.allowed_actions)
        $routeGuardBlockedActions = @(Get-NormalizedStringList -Values $routeGuardStepResult.blocked_actions)
        $routeGuardMustTriggerBusinessResume = [bool]$routeGuardStepResult.must_trigger_business_resume
    }

    if ([string]$reason -ne 'ready' -and -not $ContinueOnCommandFailure.IsPresent) {
        $canExecute = $false
    }
}

if ($canExecute) {
    $steps = @(
        [ordered]@{ name = 'business_command'; value = (Get-ObjectPropertyString -InputObject $selectedTicket -Name 'business_command') },
        [ordered]@{ name = 'continue_watch_command'; value = (Get-ObjectPropertyString -InputObject $selectedTicket -Name 'continue_watch_command') },
        [ordered]@{ name = 'handled_receipt_command'; value = (Get-ObjectPropertyString -InputObject $selectedTicket -Name 'handled_receipt_command') },
        [ordered]@{ name = 'validate_receipt_command'; value = (Get-ObjectPropertyString -InputObject $selectedTicket -Name 'validate_receipt_command') },
        [ordered]@{ name = 'mark_processed_command'; value = (Get-ObjectPropertyString -InputObject $selectedTicket -Name 'mark_processed_command') },
        [ordered]@{ name = 'post_check_command'; value = (Get-ObjectPropertyString -InputObject $selectedTicket -Name 'post_check_command') }
    )

    $receiptExecuted = $false

    foreach ($step in $steps) {
        $stepName = [string]$step.name
        $requiredActions = @(Get-RequiredRouteActionsForStep -StepName $stepName)
        $stepAllowedByRoute = Test-AnyRequiredRouteActionAllowed -AllowedActions $routeGuardAllowedActions -RequiredActions $requiredActions

        if (-not $stepAllowedByRoute) {
            $blockedReason = ('route-guard-blocked-step-{0}-requires-{1}-allowed-{2}' -f $stepName, (($requiredActions -join '+')), (($routeGuardAllowedActions -join '+')))
            $blockedStepResult = [ordered]@{
                step = $stepName
                command = Convert-ToSingleLineText -Text ([string]$step.value)
                dry_run = [bool]$DryRun.IsPresent
                attempted = $false
                succeeded = $false
                exit_code = 1
                output = ''
                error = $blockedReason
                required_actions = @($requiredActions)
                allowed_actions = @($routeGuardAllowedActions)
                route_guard_classification = $routeGuardClassification
            }
            [void]$results.Add([pscustomobject]$blockedStepResult)

            if ([string]$reason -eq 'ready') {
                $reason = ('failed-step-{0}' -f $stepName)
            }

            if (-not $ContinueOnCommandFailure.IsPresent) {
                break
            }

            continue
        }

        if ($stepName -eq 'mark_processed_command' -and $receiptExecuted) {
            continue
        }

        $stepResult = Invoke-CommandStep -Name $stepName -Command ([string]$step.value) -DryRunMode:$DryRun.IsPresent
        [void]$results.Add($stepResult)

        if ($stepName -eq 'handled_receipt_command' -and [bool]$stepResult.succeeded) {
            $receiptExecuted = $true
        }

        if (-not [bool]$stepResult.succeeded -and -not $ContinueOnCommandFailure.IsPresent) {
            $reason = ('failed-step-{0}' -f $stepName)
            break
        }
    }

    if ($results.Count -gt 0 -and [string]$reason -eq 'ready') {
        $lastStep = $results[$results.Count - 1]
        if (-not [bool]$lastStep.succeeded) {
            $reason = ('failed-step-{0}' -f [string]$lastStep.step)
        }
        else {
            $reason = 'completed'
        }
    }
}

$allSucceeded = $true
foreach ($item in @($results.ToArray())) {
    if (-not [bool]$item.succeeded) {
        $allSucceeded = $false
        break
    }
}
if ($results.Count -eq 0) {
    $allSucceeded = $false
}

$output = [ordered]@{
    schema = 'AB_STATUS_ONLY_AUTOFLOW_V1'
    generated_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    start_file = $StartFile
    dry_run = [bool]$DryRun.IsPresent
    can_execute = [bool]$canExecute
    enable_execute = [bool]$EnableExecute.IsPresent
    verdict = $verdict
    reason = $reason
    execution_token = [ordered]@{
        setting_key = $tokenSettingKey
        configured = [bool]$tokenConfigured
        provided = [bool]$tokenProvided
        matched = [bool]$tokenMatched
    }
    allowed_ticket_ids = @($allowedTicketSet.Keys)
    has_ticket_whitelist = [bool]$hasTicketWhitelist
    selected_ticket_allowed = [bool]$ticketAllowed
    continue_on_failure = [bool]$ContinueOnCommandFailure.IsPresent
    selected_ticket = if ($null -eq $selectedTicket) { $null } else {
        [ordered]@{
            ticket_id = $selectedTicketId
            event = Get-ObjectPropertyString -InputObject $selectedTicket -Name 'event'
            route_guard_command = $routeGuardCommand
        }
    }
    route_guard = [ordered]@{
        required = $true
        command = $routeGuardCommand
        executed = ($null -ne $routeGuardStepResult)
        classification = $routeGuardClassification
        recommended_action = $routeGuardRecommendedAction
        must_trigger_business_resume = [bool]$routeGuardMustTriggerBusinessResume
        allowed_actions = @($routeGuardAllowedActions)
        blocked_actions = @($routeGuardBlockedActions)
    }
    steps = @($results.ToArray())
    success = [bool]$allSucceeded
    routine_summary = [ordered]@{
        summary = Convert-ToSingleLineText -Text ([string]$routine.summary)
        priority = Convert-ToSingleLineText -Text ([string]$routine.priority)
        counts = $routine.counts
    }
}

if ($AsJson.IsPresent) {
    $output | ConvertTo-Json -Depth 10
}
else {
    Write-Output ('[AB-STATUS-AUTOFLOW] verdict={0} can_execute={1} dry_run={2} reason={3}' -f [string]$output.verdict, [bool]$output.can_execute, [bool]$output.dry_run, [string]$output.reason)
    if ($null -ne $output.selected_ticket) {
        Write-Output ('[AB-STATUS-AUTOFLOW] ticket={0} event={1}' -f [string]$output.selected_ticket.ticket_id, [string]$output.selected_ticket.event)
    }

    foreach ($step in @($output.steps)) {
        Write-Output ('[AB-STATUS-AUTOFLOW] step={0} ok={1} exit={2}' -f [string]$step.step, [bool]$step.succeeded, [int]$step.exit_code)
        if (-not [string]::IsNullOrWhiteSpace([string]$step.error)) {
            Write-Output ('  error={0}' -f [string]$step.error)
        }
    }
}
