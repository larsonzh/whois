param(
    [Parameter(Mandatory = $true)][string]$BriefPath,
    [AllowEmptyString()][string]$QueuePath = '',
    [switch]$AsJson
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'unattended_startfile_identity.ps1')

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

function Read-JsonLinesSafely {
    param([string]$Path)

    $items = New-Object 'System.Collections.Generic.List[object]'
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) {
        return @($items.ToArray())
    }

    foreach ($line in @(Get-Content -LiteralPath $Path -Encoding utf8 -ErrorAction SilentlyContinue)) {
        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }

        try {
            $obj = $line | ConvertFrom-Json -ErrorAction Stop
            if ($null -ne $obj) {
                [void]$items.Add($obj)
            }
        }
        catch {
            continue
        }
    }

    return @($items.ToArray())
}

function Get-TicketTimeValue {
    param([AllowEmptyString()][string]$Value)

    $text = Convert-ToSingleLineText -Text $Value
    if ([string]::IsNullOrWhiteSpace($text)) {
        return $null
    }

    $parsed = [datetime]::MinValue
    $ok = [datetime]::TryParseExact($text, 'yyyy-MM-dd HH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeLocal, [ref]$parsed)
    if ($ok) {
        return $parsed
    }

    if ([datetime]::TryParse($text, [ref]$parsed)) {
        return $parsed
    }

    return $null
}

function Test-EventInSet {
    param(
        [hashtable]$Set,
        [AllowEmptyString()][string]$EventName
    )

    $normalized = (Convert-ToSingleLineText -Text $EventName).ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($normalized)) {
        return $false
    }

    return $Set.ContainsKey($normalized)
}

$script:RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path

$briefFilePath = Resolve-RepoPathAllowMissing -Path $BriefPath
if ([string]::IsNullOrWhiteSpace($briefFilePath) -or -not (Test-Path -LiteralPath $briefFilePath)) {
    throw ('takeover brief not found: {0}' -f $BriefPath)
}

$brief = Read-KeyValueFile -Path $briefFilePath
$ticketId = Convert-ToSingleLineText -Text ([string]$brief.ticket_id)
$eventName = (Convert-ToSingleLineText -Text ([string]$brief.event)).ToLowerInvariant()
$startFileRel = Convert-ToSingleLineText -Text ([string]$brief.start_file)
$runDirRel = Convert-ToSingleLineText -Text ([string]$brief.run_dir)
$businessStage = (Convert-ToSingleLineText -Text ([string]$brief.business_command_stage)).ToLowerInvariant()
$selfHealable = (Convert-ToSingleLineText -Text ([string]$brief.self_healable)).ToLowerInvariant() -in @('1', 'true', 'yes', 'on')
$nonRecoverableEnv = (Convert-ToSingleLineText -Text ([string]$brief.non_recoverable_env)).ToLowerInvariant() -in @('1', 'true', 'yes', 'on')
$failureKind = (Convert-ToSingleLineText -Text ([string]$brief.failure_kind)).ToLowerInvariant()
$failureCategory = (Convert-ToSingleLineText -Text ([string]$brief.failure_category)).ToLowerInvariant()
$failurePhase = ''
if ($brief.Contains('failure_phase')) {
    $failurePhase = (Convert-ToSingleLineText -Text ([string]$brief.failure_phase)).ToLowerInvariant()
}
$failureEvidence = (Convert-ToSingleLineText -Text ([string]$brief.failure_evidence)).ToLowerInvariant()
$preferredStage = (Convert-ToSingleLineText -Text ([string]$brief.preferred_stage)).ToUpperInvariant()
$briefRecommendedAction = Convert-ToSingleLineText -Text ([string]$brief.recommended_action)

$policyWorkMode = ''
$isLowDisturbMode = $false
$scriptSelfHealEnabled = $false
if (-not [string]::IsNullOrWhiteSpace($startFileRel)) {
    $startFilePath = Resolve-RepoPathAllowMissing -Path $startFileRel
    if (-not [string]::IsNullOrWhiteSpace($startFilePath) -and (Test-Path -LiteralPath $startFilePath)) {
        try {
            $startSettings = Read-KeyValueFile -Path $startFilePath
            if ($startSettings.Contains('AI_CHAT_POLICY_WORK_MODE')) {
                $policyWorkMode = (Convert-ToSingleLineText -Text ([string]$startSettings.AI_CHAT_POLICY_WORK_MODE)).ToLowerInvariant()
            }
            if ($startSettings.Contains('LOCAL_GUARD_SCRIPT_SELF_HEAL_ENABLED')) {
                $scriptSelfHealEnabled = (Convert-ToSingleLineText -Text ([string]$startSettings.LOCAL_GUARD_SCRIPT_SELF_HEAL_ENABLED)).ToLowerInvariant() -in @('1', 'true', 'yes', 'on')
            }
        }
        catch {
            $policyWorkMode = ''
        }
    }
}
if ($policyWorkMode -eq 'low-disturb') {
    $isLowDisturbMode = $true
}

$sessionInitialLaunchAt = ''
if (-not [string]::IsNullOrWhiteSpace($startFileRel)) {
    $candidatePath = Resolve-RepoPathAllowMissing -Path $startFileRel
    if (-not [string]::IsNullOrWhiteSpace($candidatePath) -and (Test-Path -LiteralPath $candidatePath)) {
        try {
            $settingsForSession = Read-KeyValueFile -Path $candidatePath
            if ($settingsForSession.Contains('SESSION_INITIAL_LAUNCH_AT')) {
                $sessionInitialLaunchAt = (Convert-ToSingleLineText -Text ([string]$settingsForSession.SESSION_INITIAL_LAUNCH_AT))
            }
        }
        catch { $null = $_ }
    }
}

$queuePathValue = ConvertTo-PathLikeValue -Value $QueuePath
if ([string]::IsNullOrWhiteSpace($queuePathValue)) {
    $queuePathValue = Convert-ToSingleLineText -Text ([string]$brief.queue_path)
}
if ([string]::IsNullOrWhiteSpace($queuePathValue)) {
    $queuePathValue = 'out/artifacts/ab_agent_queue/agent_tickets.jsonl'
}
$queueFilePath = Resolve-RepoPathAllowMissing -Path $queuePathValue

$tickets = Read-JsonLinesSafely -Path $queueFilePath
$currentTicket = $null
if (-not [string]::IsNullOrWhiteSpace($ticketId)) {
    $currentTicket = @($tickets | Where-Object { (Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $_ -Name 'ticket_id')) -eq $ticketId } | Select-Object -Last 1)
    if ($currentTicket.Count -gt 0) {
        $currentTicket = $currentTicket[0]
    }
    else {
        $currentTicket = $null
    }
}

$ticketCreatedAt = $null
if ($null -ne $currentTicket) {
    $ticketCreatedAt = Get-TicketTimeValue -Value (Get-ObjectPropertyString -InputObject $currentTicket -Name 'created_at')
}
if ($null -eq $ticketCreatedAt) {
    $ticketCreatedAt = Get-TicketTimeValue -Value ([string]$brief.generated_at)
}

$ticketRecommendedAction = ''
if ($null -ne $currentTicket) {
    $ticketRecommendedAction = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $currentTicket -Name 'recommended_action')
}

$eventReviewRecommendedAction = $ticketRecommendedAction
if ([string]::IsNullOrWhiteSpace($eventReviewRecommendedAction)) {
    $eventReviewRecommendedAction = $briefRecommendedAction
}
if ([string]::IsNullOrWhiteSpace($eventReviewRecommendedAction)) {
    $eventReviewRecommendedAction = 'review-ticket-contract'
}

$barrierEvents = @{
    'incident-captured' = $true
    'recovery-await-confirmation' = $true
    'auto-fix-await-confirmation' = $true
    'task-definition-fix-required' = $true
    'main-process-exit-review' = $true
    'manual-wait-paused' = $true
    'budget-exhausted-stop' = $true
    'known-infra-transient-stop' = $true
}

$newerBarrier = New-Object 'System.Collections.Generic.List[object]'
foreach ($ticket in @($tickets)) {
    $candidateEvent = (Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $ticket -Name 'event')).ToLowerInvariant()
    if (-not (Test-EventInSet -Set $barrierEvents -EventName $candidateEvent)) {
        continue
    }

    $candidateAt = Get-TicketTimeValue -Value (Get-ObjectPropertyString -InputObject $ticket -Name 'created_at')
    if ($null -eq $candidateAt -or $null -eq $ticketCreatedAt -or $candidateAt -le $ticketCreatedAt) {
        continue
    }

    $candidateStart = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $ticket -Name 'start_file')
    if (-not [string]::IsNullOrWhiteSpace($startFileRel) -and -not [string]::IsNullOrWhiteSpace($candidateStart)) {
        if (-not $candidateStart.Equals($startFileRel, [System.StringComparison]::OrdinalIgnoreCase)) {
            continue
        }
    }

    $candidateRun = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $ticket -Name 'run_dir')
    if (-not [string]::IsNullOrWhiteSpace($runDirRel) -and -not [string]::IsNullOrWhiteSpace($candidateRun)) {
        if (-not $candidateRun.Equals($runDirRel, [System.StringComparison]::OrdinalIgnoreCase)) {
            continue
        }
    }

    [void]$newerBarrier.Add([pscustomobject]@{
        ticket_id = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $ticket -Name 'ticket_id')
        event = $candidateEvent
        created_at = (Get-ObjectPropertyString -InputObject $ticket -Name 'created_at')
    })
}

$newerBarrierTickets = @($newerBarrier.ToArray() | Sort-Object created_at -Descending)
$hasNewerBarrier = ($newerBarrierTickets.Count -gt 0)

$budgetExhausted = $false
$cooldownExhausted = $false
if ($null -ne $currentTicket) {
    $budgetExhausted = (
        (Get-ObjectPropertyBoolean -InputObject $currentTicket -Name 'budget_exhausted' -Default $false) -or
        (Get-ObjectPropertyBoolean -InputObject $currentTicket -Name 'budget_exceeded' -Default $false) -or
        (Get-ObjectPropertyBoolean -InputObject $currentTicket -Name 'retry_budget_exhausted' -Default $false)
    )

    $cooldownExhausted = (
        (Get-ObjectPropertyBoolean -InputObject $currentTicket -Name 'cooldown_exhausted' -Default $false) -or
        (Get-ObjectPropertyBoolean -InputObject $currentTicket -Name 'cooldown_blocked' -Default $false)
    )
}

$classification = 'unclassified'
$recommendedAction = 'manual-review'
$mustTriggerBusinessResume = $false
$mustAvoidStageRestart = $false
$supersededByNewerIncident = $false
$allowedActions = @('manual-review')
$blockedActions = @()
$reason = ''
$lowDisturbEventReviewDowngraded = $false
$decisionFactors = New-Object 'System.Collections.Generic.List[string]'
$decisionConfidence = 0.50

$isStatusTicket = ($eventName -eq 'running-status-report')
$isIncidentLike = Test-EventInSet -Set $barrierEvents -EventName $eventName
$isNoticeEvent = ($eventName -in @('manual-wait-paused', 'budget-exhausted-stop', 'known-infra-transient-stop'))
$fallbackAutoResumeEligible = (
    $isIncidentLike -and
    -not $selfHealable -and
    -not $nonRecoverableEnv -and
    -not $budgetExhausted -and
    -not $cooldownExhausted -and
    $businessStage -in @('a', 'b') -and
    ($preferredStage -in @('A', 'B') -or [string]::IsNullOrWhiteSpace($preferredStage)) -and
    (
        $failureKind -in @('compile-failure', 'compile-warning', 'verify-failure', 'task-definition-mismatch', 'script-edit-failure', 'code-edit-failure', 'main-process-exit') -or
        $failureCategory -in @('script-fault', 'code-or-unknown') -or
        $failureCategory -match '^task-definition(?:-|$)'
    )
)
$canAutoResume = (($selfHealable -or $fallbackAutoResumeEligible) -and -not $nonRecoverableEnv -and -not $budgetExhausted -and -not $cooldownExhausted -and -not [string]::IsNullOrWhiteSpace($businessStage) -and $businessStage -ne 'none')

$incidentLane = 'noncode'
if ($failurePhase -eq 'code-step') {
    $failureKind = 'environment-transient'
    $failureCategory = 'noncode-transient'
}
elseif ($failureKind -eq 'code-edit-failure') {
    $failureKind = 'environment-transient'
    $failureCategory = 'noncode-transient'
}
elseif ($failurePhase -eq 'task-static') {
    $failureKind = 'task-definition-mismatch'
    $failureCategory = 'task-definition-mismatch'
}
elseif ($failureCategory -eq 'script-fault' -and $failureEvidence -match '(?im)(conflicting\s+types\s+for|undefined\s+reference|compilation\s+terminated|fatal\s+error|error\s+c\d{4}|src[\\/].*\.(c|h):\d+)') {
    # Defensive correction for known compile-failure incidents mis-tagged as script-fault.
    $failureCategory = 'code-or-unknown'
}
if ($failurePhase -eq 'code-step') {
    $incidentLane = 'noncode'
}
elseif ($failurePhase -eq 'task-static') {
    $incidentLane = 'code-fix'
}
elseif ($failureCategory -eq 'script-fault') {
    $incidentLane = 'script-fix'
}
elseif ($failureCategory -eq 'code-or-unknown') {
    $incidentLane = 'code-fix'
}
elseif ($failureCategory -in @('noncode-transient', 'monitor-chain', 'environment', 'infra-transient')) {
    $incidentLane = 'noncode'
}
elseif ($failureCategory -match '^task-definition(?:-|$)' -or $failureKind -eq 'task-definition-mismatch') {
    $incidentLane = 'code-fix'
}
elseif ($failureKind -in @('script-failure', 'script-edit-failure', 'main-process-exit')) {
    $incidentLane = 'script-fix'
}
$scriptDiagnoseOnly = ($isIncidentLike -and $incidentLane -eq 'script-fix' -and -not $scriptSelfHealEnabled)
$canAutoResume = ($canAutoResume -and -not $scriptDiagnoseOnly)

# Skip tickets created before the session's initial launch (pre-start events)
$isPreStart = $false
if (-not [string]::IsNullOrWhiteSpace($sessionInitialLaunchAt) -and $null -ne $ticketCreatedAt) {
    try {
        $sessionStartDt = [datetime]::ParseExact($sessionInitialLaunchAt, 'yyyy-MM-dd HH:mm:ss', $null)
        if ($ticketCreatedAt -lt $sessionStartDt) {
            $isPreStart = $true
        }
    }
    catch { $null = $_ }
}
if ($isPreStart) {
    $classification = 'pre-start-skip'
    $recommendedAction = 'mark-handled-and-continue'
    $allowedActions = @('handled_at')
    $blockedActions = @('business_resume', 'stage_restart', 'source_edit', 'code-fix-workflow', 'business_command', 'continue_watch_command')
    $reason = 'Ticket created before the current session initial launch time; skip as pre-start event.'
    [void]$decisionFactors.Add('pre_start_ticket=true')
    [void]$decisionFactors.Add(('session_initial_launch_at={0}' -f $sessionInitialLaunchAt))
    $decisionConfidence = 0.98
    $mustTriggerBusinessResume = $false
    $mustAvoidStageRestart = $true
}
elseif ($isStatusTicket -and $hasNewerBarrier) {
    $classification = 'superseded-status-ticket'
    $recommendedAction = 'switch-to-newer-incident-ticket'
    $supersededByNewerIncident = $true
    $mustAvoidStageRestart = $true
    $allowedActions = @('mark-handled', 'read-only-watch')
    $blockedActions = @('business_resume', 'stage_restart', 'source_edit', 'new_non_tmp_script')
    $reason = 'A newer barrier/incident ticket exists after this status ticket; do not execute recovery from this status ticket.'
    [void]$decisionFactors.Add('status_ticket=true')
    [void]$decisionFactors.Add('has_newer_barrier=true')
    [void]$decisionFactors.Add('safety_preemption=true')
    $decisionConfidence = 0.98
}
elseif ($isStatusTicket) {
    $classification = 'status-health-check-only'
    $recommendedAction = 'report-observed-runtime-status-only'
    $mustAvoidStageRestart = $true
    $allowedActions = @('read-only-status-check', 'status-report', 'handled_at')
    $blockedActions = @('self_heal', 'fault_handling', 'business_resume', 'stage_restart', 'guard_restart', 'source_edit', 'script_edit', 'new_non_tmp_script', 'business_command', 'continue_watch_command')
    $reason = 'Scheduled running-status tickets are observation-only and must not initiate repair, fault handling, process control, or recovery.'
    [void]$decisionFactors.Add('status_ticket=true')
    [void]$decisionFactors.Add('report_only=true')
    $decisionConfidence = 0.99
}
elseif ($isNoticeEvent) {
    switch ($eventName) {
        'manual-wait-paused' {
            $classification = 'notice-manual-wait'
            $recommendedAction = 'manual-recovery-gated-decision'
            $allowedActions = @('root-cause-report', 'manual-recovery-decision', 'handled_at')
            $blockedActions = @('business_resume', 'continue_watch_command', 'stage_restart', 'source_edit', 'script_edit', 'task_definition_edit', 'environment_mutation', 'new_non_tmp_script')
            $reason = 'Manual-wait notice authorizes reporting and a recovery decision only; any recovery action requires a separate authorized incident ticket or explicit user authorization.'
            [void]$decisionFactors.Add('notice_event=manual-wait-paused')
            [void]$decisionFactors.Add('decision_gate=manual')
            $decisionConfidence = 0.94
            break
        }
        'budget-exhausted-stop' {
            $classification = 'notice-budget-exhausted'
            $recommendedAction = 'budget-aware-rerun-scope-decision'
            $allowedActions = @('root-cause-report', 'rerun-scope-decision', 'handled_at')
            $blockedActions = @('business_resume', 'continue_watch_command', 'unbounded-retry', 'stage_restart', 'source_edit', 'script_edit', 'task_definition_edit', 'environment_mutation')
            $reason = 'Budget notice authorizes reporting and rerun-scope decision only. An already-authorized pending repair ticket keeps its own priority and permissions; this notice grants no new repair or restart authority.'
            [void]$decisionFactors.Add('notice_event=budget-exhausted-stop')
            [void]$decisionFactors.Add('decision_gate=budget')
            $decisionConfidence = 0.95
            break
        }
        'known-infra-transient-stop' {
            $classification = 'notice-known-infra-transient'
            $recommendedAction = 'environment-stabilization-first'
            $allowedActions = @('root-cause-report', 'environment-stabilization-decision', 'handled_at')
            $blockedActions = @('business_resume', 'continue_watch_command', 'stage_restart', 'source_edit', 'script_edit', 'task_definition_edit', 'environment_mutation')
            $reason = 'Infrastructure notice authorizes reporting and a stabilization decision only; environment changes and recovery require a separate authorized noncode incident ticket or explicit user authorization.'
            [void]$decisionFactors.Add('notice_event=known-infra-transient-stop')
            [void]$decisionFactors.Add('decision_gate=infra_stabilization')
            $decisionConfidence = 0.94
            break
        }
    }
}
elseif ($scriptDiagnoseOnly) {
    $classification = 'incident-script-diagnose-only'
    $recommendedAction = 'investigate-script-fault-and-report-proposal-only'
    $mustTriggerBusinessResume = $false
    $mustAvoidStageRestart = $true
    $allowedActions = @('read-only-evidence', 'root-cause-analysis', 'remediation-proposal', 'chat-report', 'handled_at')
    $blockedActions = @('script_edit', 'source_edit', 'task_definition_edit', 'self_heal', 'business_resume', 'stage_restart', 'guard_restart', 'process_kill', 'environment_mutation', 'new_script', 'continue_watch_command', 'business_command')
    $reason = 'Script self-heal is disabled by start-file policy; investigate and report only. File edits, process control, restart, resume, and environment mutation are forbidden.'
    [void]$decisionFactors.Add('incident_like=true')
    [void]$decisionFactors.Add('incident_lane=script-diagnose')
    [void]$decisionFactors.Add('script_self_heal_enabled=false')
    [void]$decisionFactors.Add('diagnose_only=true')
    $decisionConfidence = 0.99
}
elseif ($isIncidentLike -and $canAutoResume) {
    $classification = ('incident-auto-resume-{0}' -f $incidentLane)
    $recommendedAction = ('trigger-{0}-business-resume-now' -f $incidentLane)
    $mustTriggerBusinessResume = $true
    $allowedActions = @('root-cause-report', ('{0}-workflow' -f $incidentLane), 'business_resume', 'continue_watch_command', 'handled_at')
    $blockedActions = @('unbounded-retry', 'new_non_tmp_script_without_approval')
    $reason = ('Incident ticket uses {0} lane and is self-healable without budget/cooldown/nonrecoverable blockers.' -f $incidentLane)
    [void]$decisionFactors.Add('incident_like=true')
    [void]$decisionFactors.Add(('incident_lane={0}' -f $incidentLane))
    [void]$decisionFactors.Add('auto_resume_eligible=true')
    $decisionConfidence = 0.90
}
elseif ($isIncidentLike) {
    $classification = ('incident-manual-{0}' -f $incidentLane)
    $recommendedAction = ('report-root-cause-and-{0}-blockers' -f $incidentLane)
    $allowedActions = @('root-cause-report', ('{0}-manual-decision' -f $incidentLane), 'handled_at')
    $blockedActions = @('blind-business-resume')

    $blockers = New-Object 'System.Collections.Generic.List[string]'
    if (-not $selfHealable) { [void]$blockers.Add('self_healable=false') }
    if ($nonRecoverableEnv) { [void]$blockers.Add('non_recoverable_env=true') }
    if ($budgetExhausted) { [void]$blockers.Add('budget_exhausted=true') }
    if ($cooldownExhausted) { [void]$blockers.Add('cooldown_exhausted=true') }
    if ([string]::IsNullOrWhiteSpace($businessStage) -or $businessStage -eq 'none') { [void]$blockers.Add('business_command_stage=none') }
    $reason = ('Incident ticket ({0} lane) is not auto-resume eligible: {1}' -f $incidentLane, (($blockers.ToArray()) -join ', '))
    [void]$decisionFactors.Add('incident_like=true')
    [void]$decisionFactors.Add(('incident_lane={0}' -f $incidentLane))
    [void]$decisionFactors.Add('auto_resume_eligible=false')
    foreach ($blocker in @($blockers.ToArray())) {
        [void]$decisionFactors.Add(('blocker:{0}' -f [string]$blocker))
    }
    $decisionConfidence = 0.88
}
else {
    if ($isLowDisturbMode) {
        $classification = 'event-review-low-disturb-text-only'
        $recommendedAction = 'text-receipt-only'
        $allowedActions = @('text-receipt', 'handled_at')
        $blockedActions = @('contract-review', 'file-artifact-write', 'unsafe-restart', 'source_edit', 'new_non_tmp_script')
        $reason = 'Low-disturb mode enforces event-review downgrade: text receipt only, no contract-review file artifacts.'
        $lowDisturbEventReviewDowngraded = $true
        [void]$decisionFactors.Add('event_review=true')
        [void]$decisionFactors.Add('low_disturb=true')
        [void]$decisionFactors.Add('text_receipt_only=true')
        $decisionConfidence = 0.86
    }
    else {
        $classification = 'event-review'
        $recommendedAction = $eventReviewRecommendedAction
        $allowedActions = @('contract-review', 'handled_at')
        $blockedActions = @('unsafe-restart', 'source_edit')
        $reason = 'Event type is outside predefined status/incident routing profile.'
        [void]$decisionFactors.Add('event_review=true')
        [void]$decisionFactors.Add('low_disturb=false')
        $decisionConfidence = 0.75
    }
}

$output = [ordered]@{
    schema = 'AB_TAKEOVER_ROUTE_GUARD_V1'
    generated_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    brief_path = (Convert-ToRepoRelativePath -Path $briefFilePath)
    queue_path = (Convert-ToRepoRelativePath -Path $queueFilePath)
    ticket = [ordered]@{
        ticket_id = $ticketId
        event = $eventName
        created_at = if ($null -eq $ticketCreatedAt) { '' } else { $ticketCreatedAt.ToString('yyyy-MM-dd HH:mm:ss') }
        start_file = $startFileRel
        run_dir = $runDirRel
    }
    route = [ordered]@{
        classification = $classification
        recommended_action = $recommendedAction
        reason = $reason
        decision_confidence = [double]$decisionConfidence
        decision_factors = @($decisionFactors.ToArray())
        superseded_by_newer_incident = [bool]$supersededByNewerIncident
        must_trigger_business_resume = [bool]$mustTriggerBusinessResume
        must_avoid_stage_restart = [bool]$mustAvoidStageRestart
        low_disturb_event_review_downgraded = [bool]$lowDisturbEventReviewDowngraded
        allowed_actions = @($allowedActions)
        blocked_actions = @($blockedActions)
    }
    eligibility = [ordered]@{
        self_healable = [bool]$selfHealable
        script_self_heal_enabled = [bool]$scriptSelfHealEnabled
        script_diagnose_only = [bool]$scriptDiagnoseOnly
        fallback_auto_resume_eligible = [bool]$fallbackAutoResumeEligible
        effective_auto_resume_eligible = [bool]$canAutoResume
        non_recoverable_env = [bool]$nonRecoverableEnv
        budget_exhausted = [bool]$budgetExhausted
        cooldown_exhausted = [bool]$cooldownExhausted
        business_command_stage = $businessStage
        auto_resume_eligible = [bool]$canAutoResume
    }
    newer_barrier_tickets = @($newerBarrierTickets)
}

if ($AsJson.IsPresent) {
    $output | ConvertTo-Json -Depth 10
}
else {
    Write-Output ('[AB-ROUTE-GUARD] ticket={0} event={1} class={2} action={3}' -f $output.ticket.ticket_id, $output.ticket.event, $output.route.classification, $output.route.recommended_action)
    Write-Output ('[AB-ROUTE-GUARD] reason={0}' -f $output.route.reason)
    Write-Output ('[AB-ROUTE-GUARD] confidence={0} factors={1}' -f [double]$output.route.decision_confidence, (($output.route.decision_factors -join ';')))
    Write-Output ('[AB-ROUTE-GUARD] superseded={0} must_resume={1} avoid_restart={2}' -f [bool]$output.route.superseded_by_newer_incident, [bool]$output.route.must_trigger_business_resume, [bool]$output.route.must_avoid_stage_restart)
    if ($output.newer_barrier_tickets.Count -gt 0) {
        Write-Output ('[AB-ROUTE-GUARD] newer_barrier_count={0} latest_ticket={1} latest_event={2}' -f $output.newer_barrier_tickets.Count, [string]$output.newer_barrier_tickets[0].ticket_id, [string]$output.newer_barrier_tickets[0].event)
    }
}
