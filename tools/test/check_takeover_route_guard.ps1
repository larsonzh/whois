param(
    [Parameter(Mandatory = $true)][string]$BriefPath,
    [AllowEmptyString()][string]$QueuePath = '',
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

function ConvertTo-PathLikeValue {
    param([AllowEmptyString()][string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return ''
    }

    $normalized = $Value.Trim()
    if ($normalized.Length -ge 2) {
        if (($normalized.StartsWith('"') -and $normalized.EndsWith('"')) -or
            ($normalized.StartsWith("'") -and $normalized.EndsWith("'"))) {
            $normalized = $normalized.Substring(1, $normalized.Length - 2).Trim()
        }
    }

    return $normalized
}

function Resolve-RepoPathAllowMissing {
    param([AllowEmptyString()][string]$Path)

    $normalized = ConvertTo-PathLikeValue -Value $Path
    if ([string]::IsNullOrWhiteSpace($normalized)) {
        return ''
    }

    if ([System.IO.Path]::IsPathRooted($normalized)) {
        return [System.IO.Path]::GetFullPath($normalized)
    }

    return [System.IO.Path]::GetFullPath((Join-Path $script:RepoRoot $normalized))
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
$preferredStage = (Convert-ToSingleLineText -Text ([string]$brief.preferred_stage)).ToUpperInvariant()

$policyWorkMode = ''
$dispatchDeliveryProfile = ''
$isLowDisturbMode = $false
if (-not [string]::IsNullOrWhiteSpace($startFileRel)) {
    $startFilePath = Resolve-RepoPathAllowMissing -Path $startFileRel
    if (-not [string]::IsNullOrWhiteSpace($startFilePath) -and (Test-Path -LiteralPath $startFilePath)) {
        try {
            $startSettings = Read-KeyValueFile -Path $startFilePath
            if ($startSettings.Contains('AI_CHAT_POLICY_WORK_MODE')) {
                $policyWorkMode = (Convert-ToSingleLineText -Text ([string]$startSettings.AI_CHAT_POLICY_WORK_MODE)).ToLowerInvariant()
            }
            if ($startSettings.Contains('AI_CHAT_DISPATCH_DELIVERY_PROFILE')) {
                $dispatchDeliveryProfile = (Convert-ToSingleLineText -Text ([string]$startSettings.AI_CHAT_DISPATCH_DELIVERY_PROFILE)).ToLowerInvariant()
            }
        }
        catch {
            $policyWorkMode = ''
            $dispatchDeliveryProfile = ''
        }
    }
}
if ($policyWorkMode -eq 'low-disturb') {
    $isLowDisturbMode = $true
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
        $failureCategory -in @('script-fault', 'code-or-unknown')
    )
)
$canAutoResume = (($selfHealable -or $fallbackAutoResumeEligible) -and -not $nonRecoverableEnv -and -not $budgetExhausted -and -not $cooldownExhausted -and -not [string]::IsNullOrWhiteSpace($businessStage) -and $businessStage -ne 'none')

$incidentLane = 'noncode'
if ($failureCategory -eq 'script-fault') {
    $incidentLane = 'script-fix'
}
elseif ($failureCategory -eq 'code-or-unknown') {
    $incidentLane = 'code-fix'
}
elseif ($failureCategory -in @('noncode-transient', 'monitor-chain', 'environment', 'infra-transient')) {
    $incidentLane = 'noncode'
}
elseif ($failureKind -in @('task-definition-mismatch', 'compile-failure', 'compile-warning', 'verify-failure', 'code-edit-failure')) {
    $incidentLane = 'code-fix'
}
elseif ($failureKind -in @('script-failure', 'script-edit-failure', 'main-process-exit')) {
    $incidentLane = 'script-fix'
}

if ($isStatusTicket -and $hasNewerBarrier) {
    $classification = 'superseded-status-ticket'
    $recommendedAction = 'switch-to-newer-incident-ticket'
    $supersededByNewerIncident = $true
    $mustAvoidStageRestart = $true
    $allowedActions = @('mark-handled', 'read-only-watch')
    $blockedActions = @('business_resume', 'stage_restart', 'source_edit', 'new_non_tmp_script')
    $reason = 'A newer barrier/incident ticket exists after this status ticket; do not execute recovery from this status ticket.'
}
elseif ($isStatusTicket) {
    $classification = 'status-health-check-only'
    $recommendedAction = 'run-minimal-health-check-and-continue-watch'
    $mustAvoidStageRestart = $true
    $allowedActions = @('business_command', 'continue_watch_command', 'handled_at')
    $blockedActions = @('business_resume', 'stage_restart', 'source_edit', 'new_non_tmp_script')
    $reason = 'Running-status ticket in low-disturb flow should execute only minimal health check and continue watch.'
}
elseif ($isNoticeEvent) {
    switch ($eventName) {
        'manual-wait-paused' {
            $classification = 'notice-manual-wait'
            $recommendedAction = 'manual-recovery-gated-decision'
            $allowedActions = @('root-cause-report', 'manual-recovery-decision', 'handled_at')
            $blockedActions = @('blind-business-resume', 'stage_restart', 'source_edit', 'new_non_tmp_script')
            $reason = 'Manual-wait notice requires explicit recovery decision before any restart/resume action.'
            break
        }
        'budget-exhausted-stop' {
            $classification = 'notice-budget-exhausted'
            $recommendedAction = 'budget-aware-rerun-scope-decision'
            $allowedActions = @('root-cause-report', 'rerun-scope-decision', 'handled_at')
            $blockedActions = @('blind-business-resume', 'unbounded-retry', 'stage_restart')
            $reason = 'Recovery budget is exhausted; decide rerun scope and mitigation before any restart.'
            break
        }
        'known-infra-transient-stop' {
            $classification = 'notice-known-infra-transient'
            $recommendedAction = 'environment-stabilization-first'
            $allowedActions = @('root-cause-report', 'environment-stabilization-decision', 'handled_at')
            $blockedActions = @('business_resume', 'stage_restart', 'source_edit')
            $reason = 'Known infrastructure transient stop requires stabilization workflow before resume.'
            break
        }
    }
}
elseif ($isIncidentLike -and $canAutoResume) {
    $classification = ('incident-auto-resume-{0}' -f $incidentLane)
    $recommendedAction = ('trigger-{0}-business-resume-now' -f $incidentLane)
    $mustTriggerBusinessResume = $true
    $allowedActions = @('root-cause-report', ('{0}-workflow' -f $incidentLane), 'business_resume', 'continue_watch_command', 'handled_at')
    $blockedActions = @('unbounded-retry', 'new_non_tmp_script_without_approval')
    $reason = ('Incident ticket uses {0} lane and is self-healable without budget/cooldown/nonrecoverable blockers.' -f $incidentLane)
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
}
else {
    if ($isLowDisturbMode) {
        $classification = 'event-review-low-disturb-text-only'
        $recommendedAction = 'text-receipt-only'
        $allowedActions = @('text-receipt', 'handled_at')
        $blockedActions = @('contract-review', 'file-artifact-write', 'unsafe-restart', 'source_edit', 'new_non_tmp_script')
        $reason = 'Low-disturb mode enforces event-review downgrade: text receipt only, no contract-review file artifacts.'
        $lowDisturbEventReviewDowngraded = $true
    }
    else {
        $classification = 'event-review'
        $recommendedAction = 'review-ticket-contract'
        $allowedActions = @('contract-review', 'handled_at')
        $blockedActions = @('unsafe-restart', 'source_edit')
        $reason = 'Event type is outside predefined status/incident routing profile.'
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
        superseded_by_newer_incident = [bool]$supersededByNewerIncident
        must_trigger_business_resume = [bool]$mustTriggerBusinessResume
        must_avoid_stage_restart = [bool]$mustAvoidStageRestart
        low_disturb_event_review_downgraded = [bool]$lowDisturbEventReviewDowngraded
        allowed_actions = @($allowedActions)
        blocked_actions = @($blockedActions)
    }
    eligibility = [ordered]@{
        self_healable = [bool]$selfHealable
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
    Write-Output ('[AB-ROUTE-GUARD] superseded={0} must_resume={1} avoid_restart={2}' -f [bool]$output.route.superseded_by_newer_incident, [bool]$output.route.must_trigger_business_resume, [bool]$output.route.must_avoid_stage_restart)
    if ($output.newer_barrier_tickets.Count -gt 0) {
        Write-Output ('[AB-ROUTE-GUARD] newer_barrier_count={0} latest_ticket={1} latest_event={2}' -f $output.newer_barrier_tickets.Count, [string]$output.newer_barrier_tickets[0].ticket_id, [string]$output.newer_barrier_tickets[0].event)
    }
}
