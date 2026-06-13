param(
    [string]$OutDirRoot = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'unattended_exit_result.ps1')
$script:UnhandledExitTag = 'CLASSIFICATION-CONTRACT-TESTS'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
if ([string]::IsNullOrWhiteSpace($OutDirRoot)) {
    $OutDirRoot = Join-Path $repoRoot 'out\artifacts\classification_contract_tests'
}

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$outDir = Join-Path $OutDirRoot $stamp
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

$guardScript = Join-Path $repoRoot 'tools\test\check_takeover_route_guard.ps1'
if (-not (Test-Path -LiteralPath $guardScript)) {
    throw ('route guard script not found: {0}' -f $guardScript)
}

function Write-KeyValueFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][hashtable]$Values
    )

    $lines = New-Object 'System.Collections.Generic.List[string]'
    foreach ($key in $Values.Keys) {
        $value = [string]$Values[$key]
        [void]$lines.Add(('{0}={1}' -f $key, $value))
    }

    Set-Content -LiteralPath $Path -Value $lines -Encoding utf8
}

function Convert-ToSingleLineText {
    param([AllowEmptyString()][string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return ''
    }

    return ([regex]::Replace((($Text -split "`r?`n") -join ' '), '\s+', ' ')).Trim()
}

function New-ContractCase {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [hashtable]$StartFileValues = @{},
        [object[]]$AdditionalQueueTickets = @(),
        [Parameter(Mandatory = $true)][hashtable]$Brief,
        [Parameter(Mandatory = $true)][hashtable]$QueueTicket,
        [Parameter(Mandatory = $true)][hashtable]$Expect
    )

    $caseDir = Join-Path $outDir $Name
    New-Item -ItemType Directory -Path $caseDir -Force | Out-Null

    $startFile = Join-Path $caseDir 'startfile.md'
    $queueFile = Join-Path $caseDir 'queue.jsonl'
    $briefFile = Join-Path $caseDir 'brief.md'

    $startValues = [ordered]@{
        AI_CHAT_POLICY_WORK_MODE = 'normal'
        SESSION_FINAL_STATUS = 'RUNNING'
        A_FINAL_STATUS = 'RUNNING'
        B_FINAL_STATUS = 'RUNNING'
        SESSION_CLOSED = 'false'
    }
    foreach ($key in $StartFileValues.Keys) {
        $startValues[$key] = $StartFileValues[$key]
    }

    Write-KeyValueFile -Path $startFile -Values $startValues

    if ($Brief.ContainsKey('start_file')) {
        $Brief['start_file'] = $startFile
    }
    if ($QueueTicket.ContainsKey('start_file')) {
        $QueueTicket['start_file'] = $startFile
    }

    Write-KeyValueFile -Path $briefFile -Values $Brief

    $queueTicket = [ordered]@{}
    foreach ($key in $QueueTicket.Keys) {
        $queueTicket[$key] = $QueueTicket[$key]
    }

    $queueEntries = New-Object 'System.Collections.Generic.List[object]'
    [void]$queueEntries.Add([pscustomobject]$queueTicket)
    foreach ($extraTicket in @($AdditionalQueueTickets)) {
        if ($null -ne $extraTicket) {
            [void]$queueEntries.Add($extraTicket)
        }
    }

    $queueEntries | ForEach-Object { $_ | ConvertTo-Json -Compress -Depth 10 } | Set-Content -LiteralPath $queueFile -Encoding utf8

    $guardRaw = & $guardScript -BriefPath $briefFile -QueuePath $queueFile -AsJson 2>&1 | Out-String
    $guard = $guardRaw.Trim() | ConvertFrom-Json

    $errors = New-Object 'System.Collections.Generic.List[string]'
    function Assert-Equal {
        param(
            [string]$Label,
            [AllowNull()]$Actual,
            [AllowNull()]$Expected
        )

        if ($Actual -ne $Expected) {
            [void]$errors.Add(("{0}: expected '{1}' got '{2}'" -f $Label, $Expected, $Actual))
        }
    }

    function Assert-Contains {
        param(
            [string]$Label,
            [object[]]$Values,
            [string]$Expected
        )

        $normalized = @($Values | ForEach-Object { Convert-ToSingleLineText -Text ([string]$_) })
        if ($normalized -notcontains $Expected) {
            [void]$errors.Add(("{0}: expected list to contain '{1}' but got [{2}]" -f $Label, $Expected, ($normalized -join ', ')))
        }
    }

    Assert-Equal -Label "$Name.classification" -Actual ([string]$guard.route.classification) -Expected ([string]$Expect.classification)
    Assert-Equal -Label "$Name.recommended_action" -Actual ([string]$guard.route.recommended_action) -Expected ([string]$Expect.recommended_action)
    Assert-Equal -Label "$Name.decision_confidence" -Actual ([double]$guard.route.decision_confidence) -Expected ([double]$Expect.decision_confidence)

    foreach ($factor in @($Expect.decision_factors)) {
        Assert-Contains -Label "$Name.decision_factors" -Values @($guard.route.decision_factors) -Expected $factor
    }
    foreach ($action in @($Expect.allowed_actions)) {
        Assert-Contains -Label "$Name.allowed_actions" -Values @($guard.route.allowed_actions) -Expected $action
    }

    foreach ($key in $Expect.Keys) {
        if ($key -in @('classification', 'recommended_action', 'decision_confidence', 'decision_factors', 'allowed_actions')) {
            continue
        }
        Assert-Equal -Label "$Name.$key" -Actual $guard.route.$key -Expected $Expect[$key]
    }

    if ($errors.Count -gt 0) {
        throw ($errors -join '; ')
    }

    return [pscustomobject]@{
        name = $Name
        pass = $true
        classification = [string]$guard.route.classification
        recommended_action = [string]$guard.route.recommended_action
        confidence = [double]$guard.route.decision_confidence
    }
}

$cases = @(
    [pscustomobject]@{
        Name = 'status-health-check'
        Brief = [ordered]@{
            ticket_id = 'T-CLASS-STATUS'
            event = 'running-status-report'
            start_file = ''
            run_dir = 'out/artifacts/dev_verify_multiround/20260609-195321'
            generated_at = '2026-06-14 02:00:00'
            business_command_stage = 'b'
            self_healable = 'false'
            non_recoverable_env = 'false'
            failure_kind = 'none'
            failure_category = 'none'
            failure_evidence = ''
            preferred_stage = 'B'
            recommended_action = 'health-check'
        }
        QueueTicket = [ordered]@{
            schema = 'AB_AGENT_TICKET_V1'
            ticket_id = 'T-CLASS-STATUS'
            created_at = '2026-06-14 02:00:00'
            event = 'running-status-report'
            start_file = ''
            queue_path = 'out/artifacts/classification_contract_tests/queue.jsonl'
            session_final_status = 'RUNNING'
            a_final_status = 'RUNNING'
            b_final_status = 'RUNNING'
            severity = 'info'
            requires_confirmation = $false
            self_healable = $false
            non_recoverable_env = $false
        }
        Expect = [ordered]@{
            classification = 'status-health-check-only'
            recommended_action = 'run-minimal-health-check-and-continue-watch'
            decision_confidence = 0.95
            decision_factors = @('status_ticket=true', 'health_check_only=true')
            allowed_actions = @('business_command', 'continue_watch_command', 'handled_at')
            must_avoid_stage_restart = $true
        }
        StartFileValues = @{}
        AdditionalQueueTickets = @()
    }
    [pscustomobject]@{
        Name = 'status-superseded-by-newer-barrier'
        Brief = [ordered]@{
            ticket_id = 'T-CLASS-STATUS-SUPERSEDED'
            event = 'running-status-report'
            start_file = ''
            run_dir = 'out/artifacts/dev_verify_multiround/20260609-195321'
            generated_at = '2026-06-14 02:01:00'
            business_command_stage = 'b'
            self_healable = 'false'
            non_recoverable_env = 'false'
            failure_kind = 'none'
            failure_category = 'none'
            failure_evidence = ''
            preferred_stage = 'B'
            recommended_action = 'health-check'
        }
        QueueTicket = [ordered]@{
            schema = 'AB_AGENT_TICKET_V1'
            ticket_id = 'T-CLASS-STATUS-SUPERSEDED'
            created_at = '2026-06-14 02:01:00'
            event = 'running-status-report'
            start_file = ''
            queue_path = 'out/artifacts/classification_contract_tests/queue.jsonl'
            session_final_status = 'RUNNING'
            a_final_status = 'RUNNING'
            b_final_status = 'RUNNING'
            severity = 'info'
            requires_confirmation = $false
            self_healable = $false
            non_recoverable_env = $false
        }
        AdditionalQueueTickets = @(
            [ordered]@{
                schema = 'AB_AGENT_TICKET_V1'
                ticket_id = 'T-CLASS-STATUS-SUPERSEDED-BARRIER'
                created_at = '2026-06-14 02:01:10'
                event = 'incident-captured'
                start_file = ''
                run_dir = 'out/artifacts/dev_verify_multiround/20260609-195321'
                queue_path = 'out/artifacts/classification_contract_tests/queue.jsonl'
                session_final_status = 'BLOCKED'
                a_final_status = 'PASS'
                b_final_status = 'FAIL'
                severity = 'high'
                requires_confirmation = $false
                self_healable = $true
                non_recoverable_env = $false
            }
        )
        Expect = [ordered]@{
            classification = 'superseded-status-ticket'
            recommended_action = 'switch-to-newer-incident-ticket'
            decision_confidence = 0.98
            decision_factors = @('status_ticket=true', 'has_newer_barrier=true', 'safety_preemption=true')
            allowed_actions = @('mark-handled', 'read-only-watch')
            must_avoid_stage_restart = $true
            superseded_by_newer_incident = $true
        }
        StartFileValues = @{}
    }
    [pscustomobject]@{
        Name = 'incident-code-fix-auto-resume'
        Brief = [ordered]@{
            ticket_id = 'T-CLASS-INC-AUTO'
            event = 'incident-captured'
            start_file = ''
            run_dir = 'out/artifacts/dev_verify_multiround/20260609-195321'
            generated_at = '2026-06-14 02:00:10'
            business_command_stage = 'b'
            self_healable = 'true'
            non_recoverable_env = 'false'
            failure_kind = 'compile-failure'
            failure_category = 'script-fault'
            failure_evidence = 'src/core/net.c:42: conflicting types for wc_retry_connect'
            preferred_stage = 'B'
            recommended_action = 'code-fix'
        }
        QueueTicket = [ordered]@{
            schema = 'AB_AGENT_TICKET_V1'
            ticket_id = 'T-CLASS-INC-AUTO'
            created_at = '2026-06-14 02:00:10'
            event = 'incident-captured'
            start_file = ''
            queue_path = 'out/artifacts/classification_contract_tests/queue.jsonl'
            session_final_status = 'BLOCKED'
            a_final_status = 'PASS'
            b_final_status = 'FAIL'
            severity = 'high'
            requires_confirmation = $false
            self_healable = $true
            non_recoverable_env = $false
        }
        Expect = [ordered]@{
            classification = 'incident-auto-resume-code-fix'
            recommended_action = 'trigger-code-fix-business-resume-now'
            decision_confidence = 0.90
            decision_factors = @('incident_like=true', 'incident_lane=code-fix', 'auto_resume_eligible=true')
            allowed_actions = @('root-cause-report', 'code-fix-workflow', 'business_resume', 'continue_watch_command', 'handled_at')
            must_trigger_business_resume = $true
        }
        StartFileValues = @{}
        AdditionalQueueTickets = @()
    }
    [pscustomobject]@{
        Name = 'incident-code-fix-manual'
        Brief = [ordered]@{
            ticket_id = 'T-CLASS-INC-MAN'
            event = 'incident-captured'
            start_file = ''
            run_dir = 'out/artifacts/dev_verify_multiround/20260609-195321'
            generated_at = '2026-06-14 02:00:20'
            business_command_stage = 'b'
            self_healable = 'false'
            non_recoverable_env = 'true'
            failure_kind = 'compile-failure'
            failure_category = 'script-fault'
            failure_evidence = 'src/core/net.c:42: conflicting types for wc_retry_connect'
            preferred_stage = 'B'
            recommended_action = 'code-fix'
        }
        QueueTicket = [ordered]@{
            schema = 'AB_AGENT_TICKET_V1'
            ticket_id = 'T-CLASS-INC-MAN'
            created_at = '2026-06-14 02:00:20'
            event = 'incident-captured'
            start_file = ''
            queue_path = 'out/artifacts/classification_contract_tests/queue.jsonl'
            session_final_status = 'BLOCKED'
            a_final_status = 'PASS'
            b_final_status = 'FAIL'
            severity = 'high'
            requires_confirmation = $false
            self_healable = $false
            non_recoverable_env = $false
        }
        Expect = [ordered]@{
            classification = 'incident-manual-code-fix'
            recommended_action = 'report-root-cause-and-code-fix-blockers'
            decision_confidence = 0.88
            decision_factors = @('incident_like=true', 'incident_lane=code-fix', 'auto_resume_eligible=false')
            allowed_actions = @('root-cause-report', 'code-fix-manual-decision', 'handled_at')
            must_trigger_business_resume = $false
        }
        StartFileValues = @{}
        AdditionalQueueTickets = @()
    }
    [pscustomobject]@{
        Name = 'notice-budget-exhausted'
        Brief = [ordered]@{
            ticket_id = 'T-CLASS-BUDGET'
            event = 'budget-exhausted-stop'
            start_file = ''
            run_dir = 'out/artifacts/dev_verify_multiround/20260609-195321'
            generated_at = '2026-06-14 02:00:40'
            business_command_stage = 'b'
            self_healable = 'false'
            non_recoverable_env = 'false'
            failure_kind = 'main-process-exit'
            failure_category = 'noncode-transient'
            failure_evidence = ''
            preferred_stage = 'B'
            recommended_action = 'budget-receipt'
            budget_exhausted = 'true'
        }
        QueueTicket = [ordered]@{
            schema = 'AB_AGENT_TICKET_V1'
            ticket_id = 'T-CLASS-BUDGET'
            created_at = '2026-06-14 02:00:40'
            event = 'budget-exhausted-stop'
            start_file = ''
            queue_path = 'out/artifacts/classification_contract_tests/queue.jsonl'
            session_final_status = 'BLOCKED'
            a_final_status = 'PASS'
            b_final_status = 'FAIL'
            severity = 'high'
            requires_confirmation = $false
            self_healable = $false
            non_recoverable_env = $false
            budget_exhausted = $true
        }
        Expect = [ordered]@{
            classification = 'notice-budget-exhausted'
            recommended_action = 'budget-aware-rerun-scope-decision'
            decision_confidence = 0.95
            decision_factors = @('notice_event=budget-exhausted-stop', 'decision_gate=budget')
            allowed_actions = @('root-cause-report', 'rerun-scope-decision', 'handled_at')
        }
        StartFileValues = @{}
        AdditionalQueueTickets = @()
    }
    [pscustomobject]@{
        Name = 'notice-known-infra-transient'
        Brief = [ordered]@{
            ticket_id = 'T-CLASS-INFRA'
            event = 'known-infra-transient-stop'
            start_file = ''
            run_dir = 'out/artifacts/dev_verify_multiround/20260609-195321'
            generated_at = '2026-06-14 02:00:50'
            business_command_stage = 'b'
            self_healable = 'false'
            non_recoverable_env = 'false'
            failure_kind = 'main-process-exit'
            failure_category = 'infra-transient'
            failure_evidence = ''
            preferred_stage = 'B'
            recommended_action = 'infra-receipt'
        }
        QueueTicket = [ordered]@{
            schema = 'AB_AGENT_TICKET_V1'
            ticket_id = 'T-CLASS-INFRA'
            created_at = '2026-06-14 02:00:50'
            event = 'known-infra-transient-stop'
            start_file = ''
            queue_path = 'out/artifacts/classification_contract_tests/queue.jsonl'
            session_final_status = 'BLOCKED'
            a_final_status = 'PASS'
            b_final_status = 'FAIL'
            severity = 'high'
            requires_confirmation = $false
            self_healable = $false
            non_recoverable_env = $false
        }
        Expect = [ordered]@{
            classification = 'notice-known-infra-transient'
            recommended_action = 'environment-stabilization-first'
            decision_confidence = 0.94
            decision_factors = @('notice_event=known-infra-transient-stop', 'decision_gate=infra_stabilization')
            allowed_actions = @('root-cause-report', 'environment-stabilization-decision', 'handled_at')
        }
        StartFileValues = @{}
        AdditionalQueueTickets = @()
    }
    [pscustomobject]@{
        Name = 'event-review-low-disturb'
        Brief = [ordered]@{
            ticket_id = 'T-CLASS-REVIEW'
            event = 'doc-update-needed'
            start_file = ''
            run_dir = 'out/artifacts/dev_verify_multiround/20260609-195321'
            generated_at = '2026-06-14 02:00:30'
            business_command_stage = 'none'
            self_healable = 'false'
            non_recoverable_env = 'false'
            failure_kind = 'none'
            failure_category = 'none'
            failure_evidence = ''
            preferred_stage = 'B'
            recommended_action = 'text-receipt'
        }
        QueueTicket = [ordered]@{
            schema = 'AB_AGENT_TICKET_V1'
            ticket_id = 'T-CLASS-REVIEW'
            created_at = '2026-06-14 02:00:30'
            event = 'doc-update-needed'
            start_file = ''
            queue_path = 'out/artifacts/classification_contract_tests/queue.jsonl'
            session_final_status = 'RUNNING'
            a_final_status = 'RUNNING'
            b_final_status = 'RUNNING'
            severity = 'info'
            requires_confirmation = $false
            self_healable = $false
            non_recoverable_env = $false
        }
        Expect = [ordered]@{
            classification = 'event-review-low-disturb-text-only'
            recommended_action = 'text-receipt-only'
            decision_confidence = 0.86
            decision_factors = @('event_review=true', 'low_disturb=true', 'text_receipt_only=true')
            allowed_actions = @('text-receipt', 'handled_at')
            low_disturb_event_review_downgraded = $true
        }
        StartFileValues = @{
            AI_CHAT_POLICY_WORK_MODE = 'low-disturb'
        }
        AdditionalQueueTickets = @()
    }
)

$results = New-Object 'System.Collections.Generic.List[object]'
foreach ($case in $cases) {
    $caseResult = New-ContractCase -Name $case.Name -StartFileValues $case.StartFileValues -AdditionalQueueTickets $case.AdditionalQueueTickets -Brief $case.Brief -QueueTicket $case.QueueTicket -Expect $case.Expect
    [void]$results.Add($caseResult)
    Write-Output ('[CLASSIFICATION-CONTRACT] case={0} pass=true class={1} action={2} confidence={3}' -f $caseResult.name, $caseResult.classification, $caseResult.recommended_action, $caseResult.confidence)
}

$summary = [pscustomobject]@{
    schema = 'AB_CLASSIFICATION_CONTRACT_TESTS_V1'
    generated_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    pass = $true
    case_count = $results.Count
    cases = @($results.ToArray())
    out_dir = $outDir
}

$summaryJson = Join-Path $outDir 'summary.json'
$summaryTxt = Join-Path $outDir 'summary.txt'
$summary | ConvertTo-Json -Depth 10 | Out-File -LiteralPath $summaryJson -Encoding utf8
$summary | Format-List | Out-String | Out-File -LiteralPath $summaryTxt -Encoding utf8

Write-Output ('[CLASSIFICATION-CONTRACT] out_dir={0}' -f $outDir)
Write-Output ('[CLASSIFICATION-CONTRACT] summary_json={0}' -f $summaryJson)
Write-Output ('[CLASSIFICATION-CONTRACT] result=pass')
exit 0
