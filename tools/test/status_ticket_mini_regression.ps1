param(
    [string]$DispatchScript = 'tools/test/dispatch_takeover_to_chat.ps1',
    [string]$MainHealthScript = 'tools/test/check_unattended_main_process_health.ps1',
    [string]$PollScript = 'tools/test/poll_agent_tickets.ps1',
    [string]$PromptDoc = 'docs/UNATTENDED_AB_PROMPTS_CN.md',
    [string]$OutDirRoot = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'unattended_exit_result.ps1')
. (Join-Path $PSScriptRoot 'unattended_startfile_identity.ps1')
$script:UnhandledExitTag = 'STATUS-TICKET-MINI-REGRESSION'

if (-not $OutDirRoot -or $OutDirRoot.Trim().Length -eq 0) {
    $OutDirRoot = Join-Path $PSScriptRoot '..\..\out\artifacts\status_ticket_mini_regression'
}

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$outDir = Join-Path $OutDirRoot $stamp
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

function Convert-ToSingleLineText {
    param([AllowEmptyString()][string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return ''
    }

    $singleLine = (($Text -split "`r?`n") -join ' ')
    return ([regex]::Replace($singleLine, '\s+', ' ')).Trim()
}

function Write-Utf8BomText {
    param(
        [string]$Path,
        [AllowEmptyString()][string]$Text
    )

    $parent = Split-Path -Parent $Path
    if (-not [string]::IsNullOrWhiteSpace($parent) -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }

    $value = if ($null -eq $Text) { '' } else { [string]$Text }
    [System.IO.File]::WriteAllText($Path, $value, [System.Text.UTF8Encoding]::new($true))
}

function Add-Utf8LineWithRetry {
    param(
        [string]$Path,
        [string]$Line,
        [int]$MaxAttempts = 8,
        [int]$RetryDelayMs = 120
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        Write-Utf8BomText -Path $Path -Text $Line
        return
    }

    $lastError = $null
    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite)
            try {
                $writer = New-Object System.IO.StreamWriter($stream, [System.Text.UTF8Encoding]::new($false))
                try {
                    $writer.WriteLine($Line)
                    $writer.Flush()
                    return
                }
                finally {
                    $writer.Dispose()
                }
            }
            finally {
                $stream.Dispose()
            }
        }
        catch {
            $lastError = $_
            if ($attempt -lt $MaxAttempts) {
                Start-Sleep -Milliseconds $RetryDelayMs
                continue
            }
        }
    }

    if ($null -ne $lastError) {
        throw $lastError.Exception
    }
}

function New-SyntheticDispatchEvidence {
    param(
        [string]$StartFilePath,
        [string]$TicketId,
        [string]$EventName
    )

    if ([string]::IsNullOrWhiteSpace($StartFilePath) -or [string]::IsNullOrWhiteSpace($TicketId)) {
        return
    }

    $token = Get-StableStartFileToken -StartFilePath $StartFilePath
    $queueRoot = Join-Path (Get-UnattendedRepoRoot) 'out\artifacts\ab_agent_queue'
    $dispatchRoot = Join-Path $queueRoot 'chat_dispatch'
    New-Item -ItemType Directory -Path $queueRoot -Force | Out-Null
    New-Item -ItemType Directory -Path $dispatchRoot -Force | Out-Null

    $triggerLogPath = Join-Path $queueRoot ("takeover_trigger_{0}.log" -f $token)
    $dispatchLogPath = Join-Path $dispatchRoot ("dispatch_{0}.log" -f $token)
    $relayPath = Join-Path $dispatchRoot ("relay_{0}_{1}.md" -f $TicketId, (Get-Date -Format 'yyyyMMdd-HHmmssfff'))
    $nowText = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')

    Add-Utf8LineWithRetry -Path $triggerLogPath -Line ("[SYNTHETIC] ticket_dispatch id={0} event={1} at={2}" -f $TicketId, $EventName, $nowText)
    Add-Utf8LineWithRetry -Path $dispatchLogPath -Line ("[SYNTHETIC] relay_created ticket={0} event={1} at={2}" -f $TicketId, $EventName, $nowText)
    Write-Utf8BomText -Path $relayPath -Text (("# synthetic relay`nticket: {0}`nevent: {1}`ncreated_at: {2}" -f $TicketId, $EventName, $nowText))
}

function Get-CaseResult {
    param(
        [string]$Name,
        [bool]$Pass,
        [string]$Reason
    )

    return [pscustomobject]@{
        case = $Name
        pass = [bool]$Pass
        reason = $Reason
    }
}

function Get-FingerprintProbeText {
    param([AllowEmptyString()][string]$Text)

    $normalized = Convert-ToSingleLineText -Text $Text
    if ([string]::IsNullOrWhiteSpace($normalized)) {
        return ''
    }

    $normalized = $normalized.ToLowerInvariant()
    $normalized = [regex]::Replace($normalized, '(?i)(^|[\s(])((?:[a-z]:[\\/])?[A-Za-z0-9._-]+(?:[\\/][A-Za-z0-9._-]+)*\.(?:c|h|cc|cpp|cxx|cs|ps1|psm1|psd1|py|json|xml|yml|yaml|md|txt)):\d+(?::\d+)?\s*:?\s*', '$1<source-location> ')
    $normalized = [regex]::Replace($normalized, '(?i)\bline\s+\d+\b', 'line <n>')
    $normalized = [regex]::Replace($normalized, '(?i)\bcolumn\s+\d+\b', 'column <n>')
    $normalized = [regex]::Replace($normalized, '(?i)\bconflicting\s+types\s+for\s+[^\s,;:]+', 'conflicting types')
    $normalized = [regex]::Replace($normalized, '(?i)\bundefined\s+reference\s+to\s+[^\s,;:]+', 'undefined reference')
    $normalized = [regex]::Replace($normalized, '(?i)\bno\s+such\s+file\s+or\s+directory\b', 'missing file')
    $normalized = [regex]::Replace($normalized, '(?i)\berror\s+c\d+\b', 'error c<num>')
    $normalized = [regex]::Replace($normalized, '\s+', ' ')
    return $normalized.Trim()
}

$dispatchPath = Resolve-RepoPath -Path $DispatchScript
$mainHealthPath = Resolve-RepoPath -Path $MainHealthScript
$pollPath = Resolve-RepoPath -Path $PollScript
$promptDocPath = Resolve-RepoPath -Path $PromptDoc
$stageWindowPath = Resolve-RepoPath -Path 'tools/test/open_unattended_ab_stage_window.ps1'
$sessionGuardPath = Resolve-RepoPath -Path 'tools/test/unattended_ab_session_guard.ps1'
$takeoverTriggerPath = Resolve-RepoPath -Path 'tools/test/unattended_ab_takeover_trigger.ps1'

$dispatchText = Get-Content -LiteralPath $dispatchPath -Raw -Encoding utf8
$mainHealthText = Get-Content -LiteralPath $mainHealthPath -Raw -Encoding utf8
$pollText = Get-Content -LiteralPath $pollPath -Raw -Encoding utf8
$promptDocText = Get-Content -LiteralPath $promptDocPath -Raw -Encoding utf8
$stageWindowText = Get-Content -LiteralPath $stageWindowPath -Raw -Encoding utf8
$sessionGuardText = Get-Content -LiteralPath $sessionGuardPath -Raw -Encoding utf8
$takeoverTriggerText = Get-Content -LiteralPath $takeoverTriggerPath -Raw -Encoding utf8
$multiRoundText = Get-Content -LiteralPath (Resolve-RepoPath -Path 'tools/test/start_dev_verify_8round_multiround.ps1') -Raw -Encoding utf8
$operationFlowPath = Resolve-RepoPath -Path 'docs/UNATTENDED_AB_OPERATION_FLOW_CN.md'
$copilotInstructionsPath = Resolve-RepoPath -Path '.github/copilot-instructions.md'
$operationFlowText = Get-Content -LiteralPath $operationFlowPath -Raw -Encoding utf8
$copilotInstructionsText = Get-Content -LiteralPath $copilotInstructionsPath -Raw -Encoding utf8
$startTemplateText = Get-Content -LiteralPath (Resolve-RepoPath -Path 'docs/UNATTENDED_AB_START_TEMPLATE_CN.md') -Raw -Encoding utf8
$createStartFileText = Get-Content -LiteralPath (Resolve-RepoPath -Path 'tools/test/create_unattended_ab_start_file.ps1') -Raw -Encoding utf8
$resetStartFileText = Get-Content -LiteralPath (Resolve-RepoPath -Path 'tools/test/reset_unattended_ab_start_file.ps1') -Raw -Encoding utf8
$launchReadyText = Get-Content -LiteralPath (Resolve-RepoPath -Path 'tools/test/check_unattended_ab_launch_ready.ps1') -Raw -Encoding utf8
$startFieldSyncText = Get-Content -LiteralPath (Resolve-RepoPath -Path 'tools/test/check_unattended_start_field_sync.ps1') -Raw -Encoding utf8

$results = New-Object 'System.Collections.Generic.List[object]'

# New start files and missing/invalid reset modes must converge on event-only.
$eventOnlyCreateDefault = $createStartFileText.Contains("[string]`$Mode = 'event-only'")
$eventOnlyCreateUsesPolicyCompiler = $createStartFileText.Contains(". (Join-Path `$PSScriptRoot 'chat_dispatch_policy_compiler.ps1')") -and $createStartFileText.Contains('Get-ChatDispatchPolicyPlan -Settings $Values')
$eventOnlyCreateUsesCanonicalTemplate = $createStartFileText.Contains("if (`$SelectedMode -in @('normal', 'anti-missent', 'low-disturb', 'event-only'))") -and $createStartFileText.Contains('return Resolve-RepoPath -Path $DefaultTemplateFile -MustExist $true')
$eventOnlyCreateAvoidsSmokeTemplates = -not $createStartFileText.Contains('unattended_ab_start_event_only_smoke.md') -and -not $createStartFileText.Contains('unattended_ab_start_status_ticket_low_disturb_smoke.md')
$eventOnlyTemplateDefaults = $startTemplateText.Contains('AI_CHAT_POLICY_WORK_MODE=event-only') -and $startTemplateText.Contains('LOCAL_GUARD_STATUS_TICKET_ENABLED=false') -and $startTemplateText.Contains('AI_CHAT_TRIGGER_DISPATCH_STATUS_REPORTS=false') -and $startTemplateText.Contains('AI_CHAT_DISPATCH_STATUS_REPORT_INTERACTIVE=false')
$eventOnlyResetFallback = ([regex]::Matches($resetStartFileText, "return 'event-only'")).Count -ge 2
$eventOnlyDefaultPass = ($eventOnlyCreateDefault -and $eventOnlyCreateUsesPolicyCompiler -and $eventOnlyCreateUsesCanonicalTemplate -and $eventOnlyCreateAvoidsSmokeTemplates -and $eventOnlyTemplateDefaults -and $eventOnlyResetFallback)
$eventOnlyDefaultReason = if ($eventOnlyDefaultPass) { 'event-only-default-contract-present' } else { 'missing-event-only-default-contract' }
[void]$results.Add((Get-CaseResult -Name 'event-only-default-contract' -Pass $eventOnlyDefaultPass -Reason $eventOnlyDefaultReason))

# Launch-ready must reject stale running-status messages in the selected start file.
$launchReadyUsesSelectedStartFile = $launchReadyText.Contains("'-StartFile', `$startFilePath")
$launchReadyEnforcesMessageMatch = $launchReadyText.Contains("'-EnforceRunningStatusMessageTemplateMatch'")
$launchReadyMessageGatePass = ($launchReadyUsesSelectedStartFile -and $launchReadyEnforcesMessageMatch)
$launchReadyMessageGateReason = if ($launchReadyMessageGatePass) { 'launch-ready-running-status-message-gate-present' } else { 'missing-launch-ready-running-status-message-gate' }
[void]$results.Add((Get-CaseResult -Name 'launch-ready-running-status-message-gate' -Pass $launchReadyMessageGatePass -Reason $launchReadyMessageGateReason))

# Scheduled status tickets are strictly read-only reports and cannot initiate remediation or process control.
$guardStatusIsReportOnly = $sessionGuardText.Contains('Scheduled status report only: report observed runtime state') -and $sessionGuardText.Contains('Do not execute self-heal, fault handling, process restart, business_resume, source/script edits, or operational recovery from this ticket.')
$briefSuppressesStatusActions = $takeoverTriggerText.Contains("`$nextCommandPolicy = 'status-report-only-readonly'") -and $takeoverTriggerText.Contains('status_ticket_action_policy={0}') -and -not $takeoverTriggerText.Contains("`$nextCommandPolicy = 'status-healthcheck'")
$pollDisablesStatusSelfHeal = $pollText.Contains("`$statusReportEnableMainProcessAutoHeal = `$false") -and -not $pollText.Contains('LOCAL_GUARD_POLL_STATUS_REPORT_ENABLE_MAIN_PROCESS_SELF_HEAL')
$dispatchHasReadOnlyStatusContract = $dispatchText.Contains('STATUS-REPORT-ONLY') -and $dispatchText.Contains('不得执行自愈修复、故障处理、主进程或 guard 重启、business_resume、源码/脚本/任务定义修改、环境稳定化或任何恢复动作')
$templateHasReadOnlyStatusContract = $startTemplateText.Contains('AI_CHAT_DISPATCH_MESSAGE_RUNNING_STATUS_FULL=[FULL-RUNBOOK][STATUS-REPORT-ONLY]') -and $startTemplateText.Contains('LOCAL_GUARD_POLL_STATUS_REPORT_ENABLE_MAIN_PROCESS_SELF_HEAL=false')
$statusReportOnlyPass = ($guardStatusIsReportOnly -and $briefSuppressesStatusActions -and $pollDisablesStatusSelfHeal -and $dispatchHasReadOnlyStatusContract -and $templateHasReadOnlyStatusContract)
$statusReportOnlyReason = if ($statusReportOnlyPass) { 'scheduled-status-report-only-contract-present' } else { 'missing-scheduled-status-report-only-contract' }
[void]$results.Add((Get-CaseResult -Name 'scheduled-status-report-only' -Pass $statusReportOnlyPass -Reason $statusReportOnlyReason))

# Runtime ticket handling is passive: delivery belongs to guard/trigger/dispatch, not agent-created polling loops.
$promptHasPassiveWaitInAllVariants = ([regex]::Matches($promptDocText, '静默等待')).Count -ge 4 -and $promptDocText.Contains('不得自行定时调用 heartbeat 或 `poll_agent_tickets.ps1`') -and $promptDocText.Contains('长时间跨轮次巡检命令') -and $promptDocText.Contains('重启主进程后 3 分钟内')
$templateHasPassiveWaitContract = $startTemplateText.Contains('进入事件驱动被动接收模式') -and $startTemplateText.Contains('等待本身不执行任何命令') -and $startTemplateText.Contains('不是 AI 自建定时巡检的依据') -and ([regex]::Matches($startTemplateText, '真实准确的 handled_at')).Count -ge 4 -and ([regex]::Matches($startTemplateText, '重启主进程后 3 分钟内')).Count -ge 4 -and ([regex]::Matches($startTemplateText, '长时间跨轮次巡检命令')).Count -ge 4
$operationFlowHasPassiveWaitContract = $operationFlowText.Contains('guard/trigger/dispatch 链负责生成并投送') -and $operationFlowText.Contains('工单完成真实回执与闭环后只需静默等待下一条投送消息') -and $operationFlowText.Contains('3 分钟内完成当前自愈修复/故障处理的收尾')
$copilotHasPassiveWaitHardRule = $copilotInstructionsText.Contains('**运行期被动收票与三分钟收尾（硬规则）**') -and $copilotInstructionsText.Contains('禁止 Agent 自行创建或运行任何定时巡检监控脚本') -and $copilotInstructionsText.Contains('3 分钟是闭环上限，不是继续巡检的窗口')
$guardHasPassiveWaitTicketSuffix = $sessionGuardText.Contains('wait silently for the next ticket delivered by guard/trigger/dispatch') -and $sessionGuardText.Contains('finish closure, receipt validation, and mark_processed within 3 minutes') -and $sessionGuardText.Contains('long-running cross-round monitoring commands')
$stageWindowHasPassiveWaitTicketSuffix = ([regex]::Matches($stageWindowText, 'finish closure, receipt validation, and mark_processed within 3 minutes')).Count -ge 3 -and $stageWindowText.Contains('long-running cross-round monitoring commands')
$dispatchHasPassiveWaitSuffixes = $dispatchText.Contains("`$passiveWaitSuffixEn = ' Follow every ticket step without omission") -and $dispatchText.Contains("`$passiveWaitSuffixZh = ' 严格按票据流程执行") -and $dispatchText.Contains('重启主进程后，必须在 3 分钟内') -and $dispatchText.Contains('Add-PassiveWaitConstraint') -and $dispatchText.Contains('$selectedPassiveWaitSuffix = if ($useChineseDispatchMessage)') -and $dispatchText.Contains('Add-PassiveWaitConstraint -Template $runningStatusFullMessage -Suffix $selectedPassiveWaitSuffix')
$passiveTicketWaitPass = ($promptHasPassiveWaitInAllVariants -and $templateHasPassiveWaitContract -and $operationFlowHasPassiveWaitContract -and $copilotHasPassiveWaitHardRule -and $guardHasPassiveWaitTicketSuffix -and $stageWindowHasPassiveWaitTicketSuffix -and $dispatchHasPassiveWaitSuffixes)
$passiveTicketWaitReason = if ($passiveTicketWaitPass) { 'passive-ticket-wait-contract-present' } else { 'missing-passive-ticket-wait-contract' }
[void]$results.Add((Get-CaseResult -Name 'passive-ticket-wait-no-agent-polling' -Pass $passiveTicketWaitPass -Reason $passiveTicketWaitReason))

# Static precheck failures may enter the runtime ticket workflow only when explicitly configured.
$launchReadyHasBlockDefault = $launchReadyText.Contains("'block'") -and $launchReadyText.Contains("@('block', 'runtime-ticket')")
$launchReadyDefersStaticFailure = $launchReadyText.Contains("if (`$taskStaticPrecheckFailureMode -eq 'runtime-ticket')") -and $launchReadyText.Contains('deferred to runtime repair ticket')
$stageWindowHasBlockDefault = $stageWindowText.Contains("`$taskStaticPrecheckFailureMode = 'block'")
$stageWindowDefersToRuntimeGate = $stageWindowText.Contains('DEFERRED_TO_RUNTIME_GATE ticket=deferred_until_main_exit') -and $stageWindowText.Contains("if (-not `$overLimit -and `$taskStaticPrecheckFailureMode -ne 'runtime-ticket')")
$multiRoundPrintsStaticResult = $multiRoundText.Contains('task_static_runtime_gate_begin') -and $multiRoundText.Contains('task_static_runtime_gate_result=')
$multiRoundDoesNotQueueStaticTicket = -not $multiRoundText.Contains('function Add-RoundTaskStaticGateTicket') -and -not $multiRoundText.Contains("event = 'task-definition-fix-required'")
$guardWaitsForMainExit = $sessionGuardText.Contains('task_definition_repair_wait reason=main-process-still-running') -and $sessionGuardText.Contains("Get-StageBusinessProcessSnapshot -Stage 'A' -ExpectedProcessId `$repairProcessId") -and $sessionGuardText.Contains("Get-StageBusinessProcessSnapshot -Stage 'B' -ExpectedProcessId `$repairProcessId") -and $sessionGuardText.Contains('task_definition_repair_ready reason=main-process-stopped')
$templateEnablesRuntimeTicket = $startTemplateText.Contains('TASK_STATIC_PRECHECK_FAILURE_MODE=runtime-ticket')
$staticRepairWaitPass = ($launchReadyHasBlockDefault -and $launchReadyDefersStaticFailure -and $stageWindowHasBlockDefault -and $stageWindowDefersToRuntimeGate -and $multiRoundPrintsStaticResult -and $multiRoundDoesNotQueueStaticTicket -and $guardWaitsForMainExit -and $templateEnablesRuntimeTicket)
$staticRepairWaitReason = if ($staticRepairWaitPass) { 'task-static-runtime-ticket-contract-present' } else { 'missing-task-static-runtime-ticket-contract' }
[void]$results.Add((Get-CaseResult -Name 'task-static-runtime-ticket-contract' -Pass $staticRepairWaitPass -Reason $staticRepairWaitReason))

# Every fault-handling or self-heal ticket must wait until all A/B business processes stop.
$guardHasFaultBranchGate = $sessionGuardText.Contains('fault_processing_wait reason=main-process-still-running') -and $sessionGuardText.Contains('fault_processing_ready reason=all-main-processes-stopped')
$guardHasTicketWriteGate = $sessionGuardText.Contains('fault_action_ticket_wait event=') -and $sessionGuardText.Contains('fault_action_ticket_ready event=') -and $sessionGuardText.Contains("`$faultActionTicket = `$eventNormalized -notin @('running-status-report', 'a-pass-conclusion-b-started', 'chat-session-final-status')")
$guardFiltersNoExitHostStrictly = $sessionGuardText.Contains('function Get-StageBusinessProcessSnapshot') -and $sessionGuardText.Contains('[bool]$exitEvidence.StartFileMatch') -and $sessionGuardText.Contains('$artifactFresh -and') -and $sessionGuardText.Contains('([bool]$exitEvidence.ProcessIdMatch -or $artifactMatchesCandidate)') -and $sessionGuardText.Contains("ResolvedSource = if (`$terminalExitConfirmed) { 'terminal-exit-artifact-filtered' }")
$d1BlockStart = $sessionGuardText.IndexOf('d1_stall_detected detail=')
$d1BlockEnd = if ($d1BlockStart -ge 0) { $sessionGuardText.IndexOf('# Log periodic stall heartbeat', $d1BlockStart) } else { -1 }
$d1BlockText = if ($d1BlockStart -ge 0 -and $d1BlockEnd -gt $d1BlockStart) { $sessionGuardText.Substring($d1BlockStart, $d1BlockEnd - $d1BlockStart) } else { '' }
$d1StopIndex = $d1BlockText.IndexOf('Stop-ProcessTree -RootPids')
$d1SnapshotIndex = $d1BlockText.IndexOf("Get-StageBusinessProcessSnapshot -Stage 'A' -ExpectedProcessId")
$d1TicketIndex = $d1BlockText.IndexOf("Add-AgentTicket -Enabled `$agentQueueEnabled")
$d1StopsBeforeTicket = ($d1StopIndex -ge 0 -and $d1SnapshotIndex -gt $d1StopIndex -and $d1TicketIndex -gt $d1SnapshotIndex -and $d1BlockText.Contains('$null = Stop-ProcessTree -RootPids') -and -not $d1BlockText.Contains("Invoke-StageRestartByPolicy -Stage 'A'"))
$stageWindowDoesNotReuseStaleRunDir = -not $stageWindowText.Contains("`$hintRunDir = Get-LatestAnchorValueFromNoteText -Notes ([string]`$Settings.SESSION_FINAL_NOTES) -Key 'run_dir'") -and $stageWindowText.Contains('$candidate.CreationTime -ge $LaunchTime.AddSeconds(-2)') -and $stageWindowText.Contains("-Anchors @{ run_dir = 'unknown' }")
$guardRequiresExistingRunDirForStall = $sessionGuardText.Contains("-not (Test-Path -LiteralPath `$d1ResolvedRunDir)") -and $sessionGuardText.Contains('Reset-D1ProgressTracking -StallSince ([ref]$script:d1StallSince)')
$healthDefersDegradedTicket = $mainHealthText.Contains('$anyMainProcessAlive = ($aAlive -or $bHasAliveProcess)') -and $mainHealthText.Contains("`$reason = 'fault-action-ticket-deferred-main-process-running'")
$allFaultActionsAfterExitPass = ($guardHasFaultBranchGate -and $guardHasTicketWriteGate -and $guardFiltersNoExitHostStrictly -and $d1StopsBeforeTicket -and $stageWindowDoesNotReuseStaleRunDir -and $guardRequiresExistingRunDirForStall -and $healthDefersDegradedTicket)
$allFaultActionsAfterExitReason = if ($allFaultActionsAfterExitPass) { 'all-fault-actions-after-main-exit-contract-present' } else { 'missing-all-fault-actions-after-main-exit-contract' }
[void]$results.Add((Get-CaseResult -Name 'all-fault-actions-after-main-exit' -Pass $allFaultActionsAfterExitPass -Reason $allFaultActionsAfterExitReason))

# Field-sync output must identify the actual start files checked.
$fieldSyncHasScope = $startFieldSyncText.Contains('check_scope = $checkScope')
$fieldSyncHasJsonFiles = $startFieldSyncText.Contains('checked_start_files = @($checkedStartFiles.ToArray())')
$fieldSyncHasTextFiles = $startFieldSyncText.Contains('[START-FIELD-SYNC] checked_start_file={0}')
$fieldSyncTargetOutputPass = ($fieldSyncHasScope -and $fieldSyncHasJsonFiles -and $fieldSyncHasTextFiles)
$fieldSyncTargetOutputReason = if ($fieldSyncTargetOutputPass) { 'start-field-sync-target-output-present' } else { 'missing-start-field-sync-target-output' }
[void]$results.Add((Get-CaseResult -Name 'start-field-sync-target-output' -Pass $fieldSyncTargetOutputPass -Reason $fieldSyncTargetOutputReason))

# Task-definition no-op contract must distinguish design-time empty rounds from runtime absorption.
$noopContractSources = @($operationFlowText, $copilotInstructionsText, $promptDocText, $dispatchText)
$noopHasMinimalShape = (@($noopContractSources | Where-Object { $_ -match 'type.?=.?noop|type=noop|"type"\s*:\s*"noop"' }).Count -eq $noopContractSources.Count)
$noopRejectsSelfReplacement = (@($noopContractSources | Where-Object { $_ -match '自替换|self-replacement' }).Count -eq $noopContractSources.Count)
$noopPreservesAbsorbedRegexPatch = (@($noopContractSources | Where-Object { $_ -match 'absorbed-by-prior-round' }).Count -eq $noopContractSources.Count)
$noopContractPass = ($noopHasMinimalShape -and $noopRejectsSelfReplacement -and $noopPreservesAbsorbedRegexPatch)
$noopContractReason = if ($noopContractPass) { 'task-definition-noop-contract-present' } else { 'missing-task-definition-noop-contract' }
[void]$results.Add((Get-CaseResult -Name 'task-definition-noop-contract' -Pass $noopContractPass -Reason $noopContractReason))

# Case 1: healthy status ticket should map to continue-watch-only guidance.
$healthyHasSummary = $mainHealthText.Contains('B main process is alive; treat this status ticket as normal monitoring and do not infer a B restart from stale history.')
$healthyHasAction = $mainHealthText.Contains('$recommendedAction = ''continue-watch-only''')
$healthyPass = ($healthyHasSummary -and $healthyHasAction)
$healthyReason = if ($healthyPass) { 'healthy-status-ticket-guidance-present' } else { 'missing-healthy-status-ticket-guidance' }
[void]$results.Add((Get-CaseResult -Name 'healthy-status-ticket' -Pass $healthyPass -Reason $healthyReason))

# Case 2: stale latest_b_exit must be identified explicitly and surfaced in output verdict.
$staleHasSignal = $mainHealthText.Contains('$staleExitEvidence = ([bool]$bExitEvidence.Available -and (-not [bool]$reasonMatched))')
$staleHasOutput = $mainHealthText.Contains('stale_exit_evidence = [bool]$staleExitEvidence')
$stalePass = ($staleHasSignal -and $staleHasOutput)
$staleReason = if ($stalePass) { 'stale-latest-b-exit-signal-present' } else { 'missing-stale-latest-b-exit-signal' }
[void]$results.Add((Get-CaseResult -Name 'stale-latest-b-exit' -Pass $stalePass -Reason $staleReason))

# Case 3: low-disturb response must enforce two-line healthy reply contract.
$lowDisturbEnTwoLine = $dispatchText.Contains('reply with only two lines: "Running normal" and "handled_at: YYYY-MM-DD HH:mm:ss"')
$lowDisturbHasHandledAtToken = $dispatchText.Contains('handled_at: YYYY-MM-DD HH:mm:ss')
$lowDisturbHasLowDisturbToken = $dispatchText.Contains('[LOW-DISTURB]')
$lowDisturbPass = ($lowDisturbEnTwoLine -and $lowDisturbHasHandledAtToken -and $lowDisturbHasLowDisturbToken)
$lowDisturbReason = if ($lowDisturbPass) { 'low-disturb-two-line-contract-present' } else { 'missing-low-disturb-two-line-contract' }
[void]$results.Add((Get-CaseResult -Name 'low-disturb-two-line-reply' -Pass $lowDisturbPass -Reason $lowDisturbReason))

# Case 4: do-not-create-non-tmp-script guardrail must be present in runtime prompt channels.
$dispatchNoNonTmp = $dispatchText.Contains('do not create new scripts outside tmp')
$promptNoNonTmp = [regex]::IsMatch($promptDocText, 'chat_heartbeat\*\.jsonl.*handled.*tmp', [System.Text.RegularExpressions.RegexOptions]::Singleline)
$noNonTmpPass = ($dispatchNoNonTmp -and $promptNoNonTmp)
$noNonTmpReason = if ($noNonTmpPass) { 'no-non-tmp-script-guardrail-present' } else { 'missing-no-non-tmp-script-guardrail' }
[void]$results.Add((Get-CaseResult -Name 'no-non-tmp-script-creation' -Pass $noNonTmpPass -Reason $noNonTmpReason))

# Case 5: task-definition repair prompts must preserve the two-layer static-check contract.
$taskSafetyHasFocusedLimitEn = $dispatchText.Contains('A focused -OperationIndex check is only a diagnostic fast check and does not run whole-round replay/assertions.')
$taskSafetyHasFocusedLimitZh = $dispatchText.Contains('带 -OperationIndex 的目标检查只是诊断快检，不执行整轮 replay/断言。')
$taskSafetyHasFullRoundEn = $dispatchText.Contains('full-round static checks without -OperationIndex for every affected D round')
$taskSafetyHasFullRoundZh = $dispatchText.Contains('对每个受影响 D 轮执行不带 -OperationIndex 的整轮静态检查')
$taskSafetyHasAssertionBoundary = $dispatchText.Contains('Update same-round postApplyAssertions only when operation results change') -and $dispatchText.Contains('仅当 operation 结构结果变化时同步更新同轮 postApplyAssertions')
$taskSafetySuffixAttached = $dispatchText.Contains('$selfHealRuleSuffixEn += $taskDefinitionSafetySuffixEn') -and $dispatchText.Contains('$selfHealRuleSuffixZh += $taskDefinitionSafetySuffixZh')
$taskSafetyPass = ($taskSafetyHasFocusedLimitEn -and $taskSafetyHasFocusedLimitZh -and $taskSafetyHasFullRoundEn -and $taskSafetyHasFullRoundZh -and $taskSafetyHasAssertionBoundary -and $taskSafetySuffixAttached)
$taskSafetyReason = if ($taskSafetyPass) { 'task-definition-two-layer-static-check-contract-present' } else { 'missing-task-definition-two-layer-static-check-contract' }
[void]$results.Add((Get-CaseResult -Name 'task-definition-two-layer-static-check' -Pass $taskSafetyPass -Reason $taskSafetyReason))

# Case 6: poll output must expose triage summary contract for fast diagnosis.
$stageWindowHasForceFlag = $stageWindowText.Contains("`$bForceMonitorRestart = (`$Stage -eq 'B' -and `$EnableBMonitorRestart.IsPresent)")
$stageWindowHasRebindPolicy = $stageWindowText.Contains("monitor_restart_policy={0}") -and $stageWindowText.Contains("rebind-existing")
$stageWindowKeepsMonitorStateInRestart = $stageWindowText.Contains("if (-not `$bForceMonitorRestart) {")
$stageWindowSelfManagedMonitor = $stageWindowText.Contains("action=self-managed") -and $stageWindowText.Contains("self-managed")
$stageWindowRebindPass = ($stageWindowHasForceFlag -and $stageWindowHasRebindPolicy -and $stageWindowKeepsMonitorStateInRestart -and $stageWindowSelfManagedMonitor)
$stageWindowRebindReason = if ($stageWindowRebindPass) { 'stage-window-monitor-rebind-default-present' } else { 'missing-stage-window-monitor-rebind-default' }
[void]$results.Add((Get-CaseResult -Name 'stage-window-monitor-rebind-default' -Pass $stageWindowRebindPass -Reason $stageWindowRebindReason))

# Case 7: stage window must emit monitor continuity timeline artifacts.
$stageWindowHasTimelinePath = $stageWindowText.Contains('MONITOR_CHAIN_TIMELINE') -and $stageWindowText.Contains('Get-MonitorTimelinePath')
$stageWindowHasTimelineWriter = $stageWindowText.Contains('function Write-MonitorTimelineEvent')
$stageWindowHasTimelineLaunch = $stageWindowText.Contains("-EventName 'stage_launch'")
$stageWindowHasTimelineReuse = $stageWindowText.Contains("-EventName 'monitor_reuse'")
$stageWindowHasTimelineAnchorUpdate = $stageWindowText.Contains("-EventName 'anchor_update'")
$stageWindowTimelinePass = ($stageWindowHasTimelinePath -and $stageWindowHasTimelineWriter -and $stageWindowHasTimelineLaunch -and $stageWindowHasTimelineReuse -and $stageWindowHasTimelineAnchorUpdate)
$stageWindowTimelineReason = if ($stageWindowTimelinePass) { 'stage-window-monitor-timeline-present' } else { 'missing-stage-window-monitor-timeline' }
[void]$results.Add((Get-CaseResult -Name 'stage-window-monitor-timeline' -Pass $stageWindowTimelinePass -Reason $stageWindowTimelineReason))

# Case 8: session guard must keep monitors alive during main-exit grace before shutdown.
$sessionGuardHasGraceSetting = $sessionGuardText.Contains('LOCAL_GUARD_MAIN_EXIT_MONITOR_GRACE_MINUTES')
$sessionGuardHasGraceStart = $sessionGuardText.Contains('main_process_exit_grace_start stage=B')
$sessionGuardHasGraceWaitLegacy = $sessionGuardText.Contains('main_process_exit_grace_wait stage={0}')
$sessionGuardHasGraceWaitHelper = $sessionGuardText.Contains("Write-GraceWaitLog -Prefix 'main_process_exit_grace_wait'")
$sessionGuardHasGraceWait = ($sessionGuardHasGraceWaitLegacy -or $sessionGuardHasGraceWaitHelper)
$sessionGuardHasGraceClear = $sessionGuardText.Contains('main_process_exit_grace_cleared stage={0}')
$sessionGuardGracePass = ($sessionGuardHasGraceSetting -and $sessionGuardHasGraceStart -and $sessionGuardHasGraceWait -and $sessionGuardHasGraceClear)
$sessionGuardGraceReason = if ($sessionGuardGracePass) { 'session-guard-main-exit-grace-present' } else { 'missing-session-guard-main-exit-grace' }
[void]$results.Add((Get-CaseResult -Name 'session-guard-main-exit-grace' -Pass $sessionGuardGracePass -Reason $sessionGuardGraceReason))

# Case 9: poll output must expose triage summary contract for fast diagnosis.
$triageSummaryHasTopCause = $pollText.Contains('top_cause = $triageTopCause')
$triageSummaryHasEvidenceHint = $pollText.Contains('evidence_hint = $triageEvidenceHint')
$triageSummaryHasActionHint = $pollText.Contains('action_hint = $triageActionHint')
$triageSummaryHasConfidence = $pollText.Contains('confidence = [double]$triageConfidence')
$triageLogTopCause = $pollText.Contains("[AB-TICKET-POLL] triage_top_cause={0} triage_confidence={1}")
$triageLogEvidence = $pollText.Contains("[AB-TICKET-POLL] triage_evidence_hint={0}")
$triageLogAction = $pollText.Contains("[AB-TICKET-POLL] triage_action_hint={0}")
$triagePass = ($triageSummaryHasTopCause -and $triageSummaryHasEvidenceHint -and $triageSummaryHasActionHint -and $triageSummaryHasConfidence -and $triageLogTopCause -and $triageLogEvidence -and $triageLogAction)
$triageReason = if ($triagePass) { 'poll-triage-summary-contract-present' } else { 'missing-poll-triage-summary-contract' }
[void]$results.Add((Get-CaseResult -Name 'poll-triage-summary-contract' -Pass $triagePass -Reason $triageReason))

# Case 9: poll runtime JSON must surface triage_summary fields for downstream automation.
$pollRuntimeStartFile = Resolve-RepoPath -Path 'testdata/unattended_start/smoke/unattended_ab_start_status_ticket_smoke.md'
$pollRuntimeRaw = & $pollPath -StartFile $pollRuntimeStartFile -Last 20 -AsJson | Out-String
$pollRuntimeJson = $null
try {
    $pollRuntimeJson = $pollRuntimeRaw | ConvertFrom-Json -ErrorAction Stop
}
catch {
    $pollRuntimeJson = $null
}
$pollRuntimeHasTriagedSummary = ($null -ne $pollRuntimeJson -and $pollRuntimeJson.PSObject.Properties.Name -contains 'triage_summary')
$pollRuntimeSummary = if ($pollRuntimeHasTriagedSummary) { $pollRuntimeJson.triage_summary } else { $null }
$pollRuntimeHasTopCause = ($null -ne $pollRuntimeSummary -and $pollRuntimeSummary.PSObject.Properties.Name -contains 'top_cause')
$pollRuntimeHasEvidenceHint = ($null -ne $pollRuntimeSummary -and $pollRuntimeSummary.PSObject.Properties.Name -contains 'evidence_hint')
$pollRuntimeHasActionHint = ($null -ne $pollRuntimeSummary -and $pollRuntimeSummary.PSObject.Properties.Name -contains 'action_hint')
$pollRuntimeHasConfidence = ($null -ne $pollRuntimeSummary -and $pollRuntimeSummary.PSObject.Properties.Name -contains 'confidence')
$pollRuntimeConfidenceOk = ($pollRuntimeHasConfidence -and ([double]$pollRuntimeSummary.confidence -ge 0.0) -and ([double]$pollRuntimeSummary.confidence -le 1.0))
$pollRuntimePass = ($pollRuntimeHasTriagedSummary -and $pollRuntimeHasTopCause -and $pollRuntimeHasEvidenceHint -and $pollRuntimeHasActionHint -and $pollRuntimeHasConfidence -and $pollRuntimeConfidenceOk)
$pollRuntimeReason = if ($pollRuntimePass) { 'poll-triage-runtime-json-present' } else { 'missing-poll-triage-runtime-json' }
[void]$results.Add((Get-CaseResult -Name 'poll-triage-runtime-json' -Pass $pollRuntimePass -Reason $pollRuntimeReason))

# Case 10: runtime poll ordering must place route guard first for status-ticket execution.
$pollOrderQueue = Join-Path $outDir 'poll_next_command_order_queue.jsonl'
$pollOrderTicket = [ordered]@{
    schema = 'AB_AGENT_TICKET_V1'
    ticket_id = 'T-MINI-ORDER-' + $stamp
    created_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    source = 'status-ticket-mini-regression'
    event = 'running-status-report'
    severity = 'info'
    requires_confirmation = $false
    start_file = $pollRuntimeStartFile
    queue_path = $pollOrderQueue
    session_final_status = 'RUNNING'
    a_final_status = 'RUNNING'
    b_final_status = 'RUNNING'
    run_dir = 'out/artifacts/dev_verify_multiround/20260626-013810'
    detail = 'status order probe'
    recommended_action = 'probe'
    preferred_stage = 'B'
    self_healable = $false
    non_recoverable_env = $false
}
Set-Content -LiteralPath $pollOrderQueue -Encoding utf8 -Value (($pollOrderTicket | ConvertTo-Json -Compress -Depth 10))

$pollOrderJson = $null
$pollRetry = 0
while ($pollRetry -lt 3 -and $null -eq $pollOrderJson) {
    $pollRetry++
    try {
        $pollOrderRaw = & $pollPath -StartFile $pollRuntimeStartFile -QueuePath $pollOrderQueue -IncludeStatusReports -Last 20 -AsJson
        if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($pollOrderRaw)) {
            $pollOrderJson = $pollOrderRaw | ConvertFrom-Json -ErrorAction Stop
        }
    }
    catch {
        $pollOrderJson = $null
    }
    if ($null -eq $pollOrderJson -and $pollRetry -lt 3) {
        Start-Sleep -Milliseconds 500
    }
}
$pollOrderRow = if ($null -ne $pollOrderJson -and $pollOrderJson.PSObject.Properties.Name -contains 'rows' -and $pollOrderJson.rows.Count -gt 0) { $pollOrderJson.rows[0] } else { $null }
$pollOrderHasOrder = ($null -ne $pollOrderRow -and ($pollOrderRow.PSObject.Properties.Name -contains 'next_command_order'))
$pollOrderNames = if ($pollOrderHasOrder) { @($pollOrderRow.next_command_order) } else { @() }
$pollOrderPass = ($pollOrderHasOrder -and $pollOrderNames.Count -ge 2 -and $pollOrderNames[0] -eq 'route_guard_command' -and $pollOrderNames[1] -eq 'business_command')
$pollOrderReason = if ($pollOrderPass) { 'poll-next-command-order-runtime-present' } else { 'missing-poll-next-command-order-runtime' }
if (-not $pollOrderPass) {
    $debugDir = Join-Path (Split-Path $pollOrderQueue -Parent) ('debug_case10_' + (Get-Date -Format 'HHmmss'))
    $null = New-Item -ItemType Directory -Path $debugDir -Force -ErrorAction SilentlyContinue
    if ($null -ne $pollOrderJson) {
        $pollOrderJson | ConvertTo-Json -Depth 10 | Out-File (Join-Path $debugDir 'poll_parsed.json') -Encoding utf8
    }
    $pollOrderRaw | Out-File (Join-Path $debugDir 'poll_raw.txt') -Encoding utf8
    Copy-Item -LiteralPath $pollOrderQueue -Destination (Join-Path $debugDir 'queue.jsonl') -Force -ErrorAction SilentlyContinue
    # Diagnostic: write key intermediate values
    $diagNamesCount = -1
    $diagNames0 = 'N/A'
    $diagNames1 = 'N/A'
    try { $diagNamesCount = $pollOrderNames.Count } catch { $diagNamesCount = -99 }
    try { if ($pollOrderNames.Count -gt 0) { $diagNames0 = [string]$pollOrderNames[0] } } catch { $diagNames0 = 'ERR' }
    try { if ($pollOrderNames.Count -gt 1) { $diagNames1 = [string]$pollOrderNames[1] } } catch { $diagNames1 = 'ERR' }
    $diagRowsCount = -1
    try { $diagRowsCount = if ($null -ne $pollOrderJson -and $pollOrderJson.PSObject.Properties.Name -contains 'rows') { $pollOrderJson.rows.Count } else { -99 } } catch { $diagRowsCount = -99 }
    (@{
        hasOrder = $pollOrderHasOrder
        namesCount = $diagNamesCount
        names0 = $diagNames0
        names1 = $diagNames1
        rowsCount = $diagRowsCount
        exitCode = $LASTEXITCODE
        rawType = $pollOrderRaw.GetType().Name
        jsonType = if ($null -ne $pollOrderJson) { $pollOrderJson.GetType().Name } else { 'null' }
        rowType = if ($null -ne $pollOrderRow) { $pollOrderRow.GetType().Name } else { 'null' }
        namesIsNull = ($null -eq $pollOrderNames)
    } | ConvertTo-Json -Depth 5) | Out-File (Join-Path $debugDir 'diagnostic.json') -Encoding utf8
}
[void]$results.Add((Get-CaseResult -Name 'poll-next-command-order-runtime' -Pass $pollOrderPass -Reason $pollOrderReason))

# Case 11: status-ticket rows must not expose recovery, closure, or post-check commands.
$pollStatusBusinessCommand = if ($null -ne $pollOrderRow) { [string]$pollOrderRow.business_command } else { '' }
$pollStatusForbiddenOrderNames = @('continue_watch_command', 'post_check_command', 'ticket_closure_check_command', 'event_dedup_health_check_command', 'final_status_closeout_command', 'final_status_closeout_apply_ack_command')
$pollStatusOrderHasForbiddenCommand = @($pollOrderNames | Where-Object { $_ -in $pollStatusForbiddenOrderNames }).Count -gt 0
$pollStatusReadonlyPass = (
    $null -ne $pollOrderRow -and
    [string]::IsNullOrWhiteSpace([string]$pollOrderRow.continue_watch_command) -and
    [string]::IsNullOrWhiteSpace([string]$pollOrderRow.ticket_closure_check_command) -and
    [string]::IsNullOrWhiteSpace([string]$pollOrderRow.event_dedup_health_check_command) -and
    [string]::IsNullOrWhiteSpace([string]$pollOrderRow.final_status_closeout_command) -and
    [string]::IsNullOrWhiteSpace([string]$pollOrderRow.final_status_closeout_apply_ack_command) -and
    [string]::IsNullOrWhiteSpace([string]$pollOrderRow.post_check_command) -and
    $pollStatusBusinessCommand -notmatch '(?i)-AutoHeal|-EscalateMonitorChainDegraded|business_resume|open_unattended_ab_session_guard_window' -and
    -not $pollStatusOrderHasForbiddenCommand
)
$pollStatusReadonlyReason = if ($pollStatusReadonlyPass) { 'poll-status-row-report-only-runtime-present' } else { 'poll-status-row-exposes-side-effect-command' }
[void]$results.Add((Get-CaseResult -Name 'poll-status-row-report-only-runtime' -Pass $pollStatusReadonlyPass -Reason $pollStatusReadonlyReason))

# Case 12: notice/manual events must also expose command order with route guard first.
$pollNoticeQueue = Join-Path $outDir 'poll_notice_command_order_queue.jsonl'
$pollNoticeTicket = [ordered]@{
    schema = 'AB_AGENT_TICKET_V1'
    ticket_id = 'T-MINI-NOTICE-' + $stamp
    created_at = (Get-Date).AddMinutes(10).ToString('yyyy-MM-dd HH:mm:ss')
    source = 'status-ticket-mini-regression'
    event = 'budget-exhausted-stop'
    severity = 'high'
    requires_confirmation = $false
    start_file = $pollRuntimeStartFile
    queue_path = $pollNoticeQueue
    session_final_status = 'BLOCKED'
    a_final_status = 'PASS'
    b_final_status = 'FAIL'
    run_dir = 'out/artifacts/dev_verify_multiround/20260609-195321'
    detail = 'notice order probe'
    recommended_action = 'probe'
    preferred_stage = 'B'
    self_healable = $false
    non_recoverable_env = $false
    budget_exhausted = $true
}
Set-Content -LiteralPath $pollNoticeQueue -Encoding utf8 -Value (($pollNoticeTicket | ConvertTo-Json -Compress -Depth 10))
New-SyntheticDispatchEvidence -StartFilePath $pollRuntimeStartFile -TicketId ([string]$pollNoticeTicket.ticket_id) -EventName ([string]$pollNoticeTicket.event)

$pollNoticeRaw = & $pollPath -StartFile $pollRuntimeStartFile -QueuePath $pollNoticeQueue -Last 20 -AsJson | Out-String
$pollNoticeJson = $null
try {
    $pollNoticeJson = $pollNoticeRaw | ConvertFrom-Json -ErrorAction Stop
}
catch {
    $pollNoticeJson = $null
}
$pollNoticeRows = @()
if ($null -ne $pollNoticeJson) {
    try { $pollNoticeRows = @($pollNoticeJson.rows) } catch { $pollNoticeRows = @() }
}
if ($null -eq $pollNoticeRows -or $pollNoticeRows -isnot [Array]) { $pollNoticeRows = @() }
$pollNoticeRow = @($pollNoticeRows | Where-Object { [string]$_.event -eq 'budget-exhausted-stop' } | Select-Object -First 1)
$pollNoticeTarget = if ($pollNoticeRow.Count -gt 0) { $pollNoticeRow[0] } else { $null }
$pollNoticeHasOrder = ($null -ne $pollNoticeTarget -and ($pollNoticeTarget.PSObject.Properties.Name -contains 'next_command_order'))
$pollNoticeNames = if ($pollNoticeHasOrder) { @($pollNoticeTarget.next_command_order) } else { @() }
$pollNoticePass = ($pollNoticeHasOrder -and $pollNoticeNames.Count -ge 2 -and $pollNoticeNames[0] -eq 'route_guard_command' -and $pollNoticeNames[1] -eq 'business_command')
$pollNoticeReason = if ($pollNoticePass) { 'poll-notice-command-order-runtime-present' } else { 'missing-poll-notice-command-order-runtime' }
[void]$results.Add((Get-CaseResult -Name 'poll-notice-command-order-runtime' -Pass $pollNoticePass -Reason $pollNoticeReason))

# Case 9: manual-wait (drain-safe event) should map to route guard first and
# keep continue-watch in order list.  For drain-safe events, business_command
# is empty (not emitted) so we only check route_guard_command + continue_watch.
$pollManualQueue = Join-Path $outDir 'poll_manual_command_order_queue.jsonl'
$pollManualTicket = [ordered]@{
    schema = 'AB_AGENT_TICKET_V1'
    ticket_id = 'T-MINI-MANUAL-' + $stamp
    created_at = (Get-Date).AddMinutes(11).ToString('yyyy-MM-dd HH:mm:ss')
    source = 'status-ticket-mini-regression'
    event = 'manual-wait-paused'
    severity = 'high'
    requires_confirmation = $false
    start_file = $pollRuntimeStartFile
    queue_path = $pollManualQueue
    session_final_status = 'BLOCKED'
    a_final_status = 'PASS'
    b_final_status = 'FAIL'
    run_dir = 'out/artifacts/dev_verify_multiround/20260609-195321'
    detail = 'manual wait order probe'
    recommended_action = 'probe'
    preferred_stage = 'B'
    self_healable = $false
    non_recoverable_env = $false
}
Set-Content -LiteralPath $pollManualQueue -Encoding utf8 -Value (($pollManualTicket | ConvertTo-Json -Compress -Depth 10))
New-SyntheticDispatchEvidence -StartFilePath $pollRuntimeStartFile -TicketId ([string]$pollManualTicket.ticket_id) -EventName ([string]$pollManualTicket.event)

$pollManualRaw = & $pollPath -StartFile $pollRuntimeStartFile -QueuePath $pollManualQueue -Last 20 -AsJson | Out-String
$pollManualJson = $null
try {
    $pollManualJson = $pollManualRaw | ConvertFrom-Json -ErrorAction Stop
}
catch {
    $pollManualJson = $null
}
$pollManualRows = if ($null -ne $pollManualJson) { @($pollManualJson.rows) } else { @() }
$pollManualRow = @($pollManualRows | Where-Object { [string]$_.event -eq 'manual-wait-paused' } | Select-Object -First 1)
$pollManualTarget = if ($pollManualRow.Count -gt 0) { $pollManualRow[0] } else { $null }
$pollManualHasOrder = ($null -ne $pollManualTarget -and ($pollManualTarget.PSObject.Properties.Name -contains 'next_command_order'))
$pollManualNames = if ($pollManualHasOrder) { @($pollManualTarget.next_command_order) } else { @() }
$pollManualHasContinueWatch = ($pollManualNames -contains 'continue_watch_command')
$pollManualPass = ($pollManualHasOrder -and $pollManualNames.Count -ge 2 -and $pollManualNames[0] -eq 'route_guard_command' -and $pollManualHasContinueWatch)
$pollManualReason = if ($pollManualPass) { 'poll-manual-command-order-runtime-present' } else { 'missing-poll-manual-command-order-runtime' }
[void]$results.Add((Get-CaseResult -Name 'poll-manual-command-order-runtime' -Pass $pollManualPass -Reason $pollManualReason))

# Case 10: fingerprint normalization must collapse the same issue with different line numbers to one token.
$fingerprintProbeA = 'src/core/net.c:42: conflicting types for wc_retry_connect'
$fingerprintProbeB = 'src/core/net.c:57: conflicting types for wc_retry_connect'
$fingerprintProbeNormalizedA = Get-FingerprintProbeText -Text $fingerprintProbeA
$fingerprintProbeNormalizedB = Get-FingerprintProbeText -Text $fingerprintProbeB
$fingerprintProbePass = ($fingerprintProbeNormalizedA -eq $fingerprintProbeNormalizedB -and $fingerprintProbeNormalizedA -eq '<source-location> conflicting types')
$fingerprintProbeReason = if ($fingerprintProbePass) { 'failure-fingerprint-normalization-present' } else { 'missing-failure-fingerprint-normalization' }
[void]$results.Add((Get-CaseResult -Name 'failure-fingerprint-normalization' -Pass $fingerprintProbePass -Reason $fingerprintProbeReason))

$failedCases = @($results | Where-Object { -not [bool]$_.pass })
$pass = ($failedCases.Count -eq 0)

$summary = [pscustomobject]@{
    schema = 'AB_STATUS_TICKET_MINI_REGRESSION_V1'
    generated_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    pass = [bool]$pass
    total_cases = $results.Count
    failed_cases = $failedCases.Count
    inputs = [pscustomobject]@{
        dispatch_script = (Convert-ToRepoRelativePath -Path $dispatchPath)
        main_health_script = (Convert-ToRepoRelativePath -Path $mainHealthPath)
        poll_script = (Convert-ToRepoRelativePath -Path $pollPath)
        prompt_doc = (Convert-ToRepoRelativePath -Path $promptDocPath)
    }
    cases = @($results.ToArray())
}

$summaryJson = Join-Path $outDir 'summary.json'
$summaryTxt = Join-Path $outDir 'summary.txt'
$summary | ConvertTo-Json -Depth 8 | Out-File -LiteralPath $summaryJson -Encoding utf8
$summary | Format-List | Out-String | Out-File -LiteralPath $summaryTxt -Encoding utf8

Write-Output ('[STATUS-TICKET-MINI] out_dir={0}' -f $outDir)
Write-Output ('[STATUS-TICKET-MINI] summary_json={0}' -f $summaryJson)
Write-Output ('[STATUS-TICKET-MINI] summary_txt={0}' -f $summaryTxt)
foreach ($entry in $results.ToArray()) {
    Write-Output ('[STATUS-TICKET-MINI] case={0} pass={1} reason={2}' -f [string]$entry.case, [bool]$entry.pass, [string]$entry.reason)
}

if (-not $pass) {
    Write-Output '[STATUS-TICKET-MINI] result=fail'
    Exit-UnattendedFailure -Tag $script:UnhandledExitTag -Reason 'status-ticket-mini-regression failed' -ExitCode 1
}

Write-Output '[STATUS-TICKET-MINI] result=pass'
exit 0
