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
$atomicCloseoutPath = Resolve-RepoPath -Path 'tools/test/complete_agent_ticket_closeout.ps1'
$recoveryTransactionPath = Resolve-RepoPath -Path 'tools/test/complete_recovery_ticket_transaction.ps1'
$ticketClosurePath = Resolve-RepoPath -Path 'tools/test/check_unattended_ticket_closure.ps1'

$dispatchText = Get-Content -LiteralPath $dispatchPath -Raw -Encoding utf8
$mainHealthText = Get-Content -LiteralPath $mainHealthPath -Raw -Encoding utf8
$pollText = Get-Content -LiteralPath $pollPath -Raw -Encoding utf8
$promptDocText = Get-Content -LiteralPath $promptDocPath -Raw -Encoding utf8
$stageWindowText = Get-Content -LiteralPath $stageWindowPath -Raw -Encoding utf8
$sessionGuardText = Get-Content -LiteralPath $sessionGuardPath -Raw -Encoding utf8
$takeoverTriggerText = Get-Content -LiteralPath $takeoverTriggerPath -Raw -Encoding utf8
$atomicCloseoutText = Get-Content -LiteralPath $atomicCloseoutPath -Raw -Encoding utf8
$recoveryTransactionText = Get-Content -LiteralPath $recoveryTransactionPath -Raw -Encoding utf8
$ticketClosureText = Get-Content -LiteralPath $ticketClosurePath -Raw -Encoding utf8
$statusOnlyAutoflowText = Get-Content -LiteralPath (Resolve-RepoPath -Path 'tools/test/run_unattended_status_only_autoflow.ps1') -Raw -Encoding utf8
$multiRoundText = Get-Content -LiteralPath (Resolve-RepoPath -Path 'tools/test/start_dev_verify_8round_multiround.ps1') -Raw -Encoding utf8
$codeChangeWrapperPath = Resolve-RepoPath -Path 'tools/test/start_autopilot_8round_code_change.ps1'
$codeStepText = Get-Content -LiteralPath (Resolve-RepoPath -Path 'tools/test/autopilot_code_step_rounds.ps1') -Raw -Encoding utf8
$fastModeBText = Get-Content -LiteralPath (Resolve-RepoPath -Path 'tools/test/start_dev_verify_fastmode_B.ps1') -Raw -Encoding utf8
$snapshotIntegrityText = Get-Content -LiteralPath (Resolve-RepoPath -Path 'tools/test/a_success_snapshot_integrity.ps1') -Raw -Encoding utf8
$operationFlowPath = Resolve-RepoPath -Path 'docs/UNATTENDED_AB_OPERATION_FLOW_CN.md'
$copilotInstructionsPath = Resolve-RepoPath -Path '.github/copilot-instructions.md'
$operationFlowText = Get-Content -LiteralPath $operationFlowPath -Raw -Encoding utf8
$copilotInstructionsText = Get-Content -LiteralPath $copilotInstructionsPath -Raw -Encoding utf8
$startTemplateText = Get-Content -LiteralPath (Resolve-RepoPath -Path 'docs/UNATTENDED_AB_START_TEMPLATE_CN.md') -Raw -Encoding utf8
$createStartFileText = Get-Content -LiteralPath (Resolve-RepoPath -Path 'tools/test/create_unattended_ab_start_file.ps1') -Raw -Encoding utf8
$resetStartFileText = Get-Content -LiteralPath (Resolve-RepoPath -Path 'tools/test/reset_unattended_ab_start_file.ps1') -Raw -Encoding utf8
$launchReadyText = Get-Content -LiteralPath (Resolve-RepoPath -Path 'tools/test/check_unattended_ab_launch_ready.ps1') -Raw -Encoding utf8
$startFieldSyncText = Get-Content -LiteralPath (Resolve-RepoPath -Path 'tools/test/check_unattended_start_field_sync.ps1') -Raw -Encoding utf8
$ps51FormatGuardPath = Resolve-RepoPath -Path 'tools/test/check_ps51_format_inline_if_guard.ps1'
$ps51FormatGuardText = Get-Content -LiteralPath $ps51FormatGuardPath -Raw -Encoding utf8

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
$briefOmitsLegacyMonitorLogs = -not $takeoverTriggerText.Contains("('supervisor_log={0}' -f `$supervisorLog)") -and -not $takeoverTriggerText.Contains("('companion_log={0}' -f `$companionLog)")
$statusReportOnlyPass = ($guardStatusIsReportOnly -and $briefSuppressesStatusActions -and $pollDisablesStatusSelfHeal -and $dispatchHasReadOnlyStatusContract -and $templateHasReadOnlyStatusContract -and $briefOmitsLegacyMonitorLogs)
$statusReportOnlyReason = if ($statusReportOnlyPass) { 'scheduled-status-report-only-contract-present' } else { 'missing-scheduled-status-report-only-contract' }
[void]$results.Add((Get-CaseResult -Name 'scheduled-status-report-only' -Pass $statusReportOnlyPass -Reason $statusReportOnlyReason))

# Runtime ticket handling is passive: delivery belongs to guard/trigger/dispatch, not agent-created polling loops.
$promptHasPassiveWaitInAllVariants = ([regex]::Matches($promptDocText, '静默等待')).Count -ge 4 -and $promptDocText.Contains('不得自行定时调用 heartbeat 或 `poll_agent_tickets.ps1`') -and $promptDocText.Contains('长时间跨轮次巡检命令') -and $promptDocText.Contains('重启主进程后 3 分钟内')
$templateHasPassiveWaitContract = $startTemplateText.Contains('进入事件驱动被动接收模式') -and $startTemplateText.Contains('等待本身不执行任何命令') -and $startTemplateText.Contains('不是 AI 自建定时巡检的依据') -and ([regex]::Matches($startTemplateText, 'atomic_closeout_command')).Count -ge 5 -and ([regex]::Matches($startTemplateText, '重启主进程后 3 分钟内')).Count -ge 4 -and ([regex]::Matches($startTemplateText, '长时间跨轮次巡检命令')).Count -ge 4 -and -not $startTemplateText.Contains('回执校验与 mark_processed')
$operationFlowHasPassiveWaitContract = $operationFlowText.Contains('guard/trigger/dispatch 链负责生成并投送') -and $operationFlowText.Contains('工单通过事务命令或唯一原子收尾命令完成真实回执与闭环后只需静默等待下一条投送消息') -and $operationFlowText.Contains('3 分钟内完成事件票的 `recovery_transaction_command` 或唯一的 `atomic_closeout_command`') -and $operationFlowText.Contains('仅作审计兼容展示；事件票不得逐条执行这些旧分步命令') -and -not $operationFlowText.Contains('回执校验与 `mark_processed`')
$copilotHasPassiveWaitHardRule = $copilotInstructionsText.Contains('**运行期被动收票与三分钟收尾（硬规则）**') -and $copilotInstructionsText.Contains('禁止 Agent 自行创建或运行定时巡检监控脚本') -and $copilotInstructionsText.Contains('3 分钟是闭环上限，不是继续巡检的窗口')
$guardHasPassiveWaitTicketSuffix = $sessionGuardText.Contains('wait silently for the next ticket delivered by guard/trigger/dispatch') -and $sessionGuardText.Contains('complete atomic closeout within 3 minutes') -and $sessionGuardText.Contains('long-running cross-round monitoring commands') -and -not $sessionGuardText.Contains('finish closure, receipt validation, and mark_processed within 3 minutes')
$stageWindowHasPassiveWaitTicketSuffix = ([regex]::Matches($stageWindowText, 'complete atomic closeout within 3 minutes')).Count -ge 3 -and $stageWindowText.Contains('long-running cross-round monitoring commands') -and -not $stageWindowText.Contains('finish closure, receipt validation, and mark_processed within 3 minutes')
$dispatchHasPassiveWaitSuffixes = $dispatchText.Contains("`$passiveWaitSuffixEn = ' Follow every ticket step without omission") -and $dispatchText.Contains("`$passiveWaitSuffixZh = ' 严格按票据流程执行") -and $dispatchText.Contains('重启主进程后，必须在 3 分钟内') -and $dispatchText.Contains('Add-PassiveWaitConstraint') -and $dispatchText.Contains('$selectedPassiveWaitSuffix = if ($useChineseDispatchMessage)') -and $dispatchText.Contains('Add-PassiveWaitConstraint -Template $runningStatusFullMessage -Suffix $selectedPassiveWaitSuffix')
$passiveTicketWaitPass = ($promptHasPassiveWaitInAllVariants -and $templateHasPassiveWaitContract -and $operationFlowHasPassiveWaitContract -and $copilotHasPassiveWaitHardRule -and $guardHasPassiveWaitTicketSuffix -and $stageWindowHasPassiveWaitTicketSuffix -and $dispatchHasPassiveWaitSuffixes)
$passiveTicketWaitReason = if ($passiveTicketWaitPass) { 'passive-ticket-wait-contract-present' } else { 'missing-passive-ticket-wait-contract' }
[void]$results.Add((Get-CaseResult -Name 'passive-ticket-wait-no-agent-polling' -Pass $passiveTicketWaitPass -Reason $passiveTicketWaitReason))

# Event tickets close through one machine-verified command; missing command data must fail closed.
$atomicCloseoutVerifiesFacts = $atomicCloseoutText.Contains("schema = 'AB_AGENT_TICKET_CLOSEOUT_V1'") -and $atomicCloseoutText.Contains('ticket is absent from persisted processed_ids') -and $atomicCloseoutText.Contains('persisted handled receipt is invalid') -and $atomicCloseoutText.Contains('ticket closure check returned pass=false') -and $atomicCloseoutText.Contains('[ValidateRange(10, 600)][int]$AcknowledgeTimeoutSec = 120') -and $atomicCloseoutText.Contains('acknowledge timed out after {0}ms')
$recoveryTransactionVerifiesFacts = $recoveryTransactionText.Contains("schema = 'AB_RECOVERY_TICKET_TRANSACTION_V1'") -and $recoveryTransactionText.Contains('route_guard_command is empty') -and $recoveryTransactionText.Contains('atomic closeout machine-fact gate failed') -and $recoveryTransactionText.Contains('business_command') -and $recoveryTransactionText.Contains('continue_watch_command') -and $recoveryTransactionText.Contains('stage_main_process_verified') -and $recoveryTransactionText.Contains('business_command did not start stage-{0} main process within {1}ms') -and $recoveryTransactionText.Contains('[ValidateRange(30, 900)][int]$BusinessCommandVerifyTimeoutSec = 240') -and $recoveryTransactionText.Contains('[switch]$ShowBusinessCommandWindow') -and $recoveryTransactionText.Contains('if ($ShowBusinessCommandWindow.IsPresent) { ''Normal'' } else { ''Hidden'' }') -and $recoveryTransactionText.Contains('business_command_window_style={0}') -and $recoveryTransactionText.Contains('business_command_verify_timeout_ms={0}') -and $recoveryTransactionText.Contains('latest_{0}_exit.json') -and $recoveryTransactionText.Contains('Test-ProcessFilteredByTerminalExitArtifact') -and $pollText.Contains('$ackOnlyMode') -and $pollText.Contains('ack_only_mode = [bool]$ackOnlyMode')
$ps51FormatGuardUsesAst = $ps51FormatGuardText.Contains('[System.Management.Automation.Language.Parser]::ParseFile') -and $ps51FormatGuardText.Contains('[System.Management.Automation.Language.BinaryExpressionAst]') -and $ps51FormatGuardText.Contains('[System.Management.Automation.Language.TokenKind]::Format') -and $ps51FormatGuardText.Contains('[System.Management.Automation.Language.IfStatementAst]')
$ps51FormatGuardProbeRoot = Join-Path $outDir 'ps51_format_guard_runtime'
$ps51FormatGuardBadRoot = Join-Path $ps51FormatGuardProbeRoot 'bad'
$ps51FormatGuardLiteralRoot = Join-Path $ps51FormatGuardProbeRoot 'literal'
New-Item -ItemType Directory -Path $ps51FormatGuardBadRoot -Force | Out-Null
New-Item -ItemType Directory -Path $ps51FormatGuardLiteralRoot -Force | Out-Null
Write-Utf8BomText -Path (Join-Path $ps51FormatGuardBadRoot 'probe.ps1') -Text "'value={0}' -f `$(if (`$true) { 'yes' } else { 'no' })"
Write-Utf8BomText -Path (Join-Path $ps51FormatGuardLiteralRoot 'probe.ps1') -Text "`$sample = '-f `$(if (`$true) { yes } else { no })'"
$ps51FormatGuardBadOutput = @(& powershell -NoProfile -ExecutionPolicy Bypass -File $ps51FormatGuardPath -RepoRoot $ps51FormatGuardBadRoot -Scope all 2>&1)
$ps51FormatGuardBadExitCode = $LASTEXITCODE
$ps51FormatGuardLiteralOutput = @(& powershell -NoProfile -ExecutionPolicy Bypass -File $ps51FormatGuardPath -RepoRoot $ps51FormatGuardLiteralRoot -Scope all 2>&1)
$ps51FormatGuardLiteralExitCode = $LASTEXITCODE
$ps51FormatGuardRuntimePass = ($ps51FormatGuardBadExitCode -ne 0 -and ($ps51FormatGuardBadOutput -join "`n").Contains('violations=1') -and $ps51FormatGuardLiteralExitCode -eq 0 -and ($ps51FormatGuardLiteralOutput -join "`n").Contains('violations=0'))
$takeoverProjectsAtomicCloseout = $ps51FormatGuardUsesAst -and $ps51FormatGuardRuntimePass -and $takeoverTriggerText.Contains("`$nextCommandNames.Add('recovery_transaction_command')") -and $takeoverTriggerText.Contains("`$nextCommandNames.Add('atomic_closeout_command')") -and $takeoverTriggerText.Contains("`$atomicCloseoutExecutionPolicy = if (`$eventNameNormalized -eq 'running-status-report')") -and $takeoverTriggerText.Contains("('recovery_transaction_command={0}' -f `$recoveryTransactionCommand)") -and $takeoverTriggerText.Contains("('atomic_closeout_command={0}' -f `$atomicCloseoutCommand)") -and $takeoverTriggerText.Contains('complete_recovery_ticket_transaction.ps1') -and $takeoverTriggerText.Contains('-QueuePath "{2}" -Last 20 -AsJson')
$pollProjectsAtomicCloseout = $pollText.Contains('function Get-AtomicCloseoutCommand') -and $pollText.Contains('function Get-RecoveryTransactionCommand') -and $pollText.Contains("`$order.Add('recovery_transaction_command')") -and $pollText.Contains("`$order.Add('atomic_closeout_command')") -and ([regex]::Matches($pollText, 'atomic_closeout_command = \(Get-AtomicCloseoutCommand')).Count -eq 2 -and $pollText.Contains("-not `$ledgerRecords.ContainsKey(`$ticketId) -and `$ticketById.ContainsKey(`$ticketId)") -and $pollText.Contains('Initialize-LedgerRecord -LedgerRecords $ledgerRecords -TicketId $ticketId') -and $statusOnlyAutoflowText.Contains("'atomic_closeout_command' { return @('handled_at', 'mark-handled') }") -and $statusOnlyAutoflowText.Contains("atomic_closeout_command = Get-ObjectPropertyString -InputObject `$selectedTicket -Name 'atomic_closeout_command'")
$closureCheckerProjectsAtomicCloseout = $ticketClosureText.Contains('tools/test/complete_agent_ticket_closeout.ps1') -and $ticketClosureText.Contains('use the atomic closeout command instead of split acknowledgement') -and -not $ticketClosureText.Contains('-AcknowledgeTicketIds')
$promptRejectsSplitCloseout = $promptDocText.Contains('其职责已由 recovery_transaction_command 或 atomic_closeout_command 统一覆盖') -and -not $promptDocText.Contains('也必须按 next_command_order 继续执行')
$dispatchRequiresMachineFacts = $dispatchText.Contains('当前 brief 提供 recovery_transaction_command') -and $dispatchText.Contains('this brief provides recovery_transaction_command') -and $dispatchText.Contains('本地验证通过后不得停下') -and $dispatchText.Contains('do not stop at local validation') -and $dispatchText.Contains('pre_restart_launch_ready_command') -and $dispatchText.Contains('最终聊天回复必须以独立末行 `handled_at: YYYY-MM-DD HH:mm:ss` 结束') -and $dispatchText.Contains('final chat reply must end with a standalone line `handled_at: YYYY-MM-DD HH:mm:ss`') -and $dispatchText.Contains('同时缺少 recovery_transaction_command 与 atomic_closeout_command') -and $dispatchText.Contains('both recovery_transaction_command and atomic_closeout_command are missing') -and $dispatchText.Contains('success=true、processed=true、ledger_status=done、receipt_valid=true、closure_pass=true') -and $dispatchText.Contains("if (`$eventNormalized -ne 'running-status-report')")
$dispatchRoutesDiscoveredScriptFault = $dispatchText.Contains('若处理本代码修复票时发现脚本故障，必须停止代码修复流程并按脚本策略重新分类') -and $dispatchText.Contains('If a true script fault is discovered while handling this code-fix ticket, stop the code-fix flow') -and $dispatchText.Contains('structured child result or exit_code exists')
$dispatchRecognizesCompileOrTestFailure = $dispatchText.Contains("'compile-or-test-failure'") -and $dispatchText.Contains("'compile-or-test'")
$guardClassifiesStructuredValidationBeforeScriptStack = $sessionGuardText.Contains('$markerRegistry = [ordered]@{') -and $sessionGuardText.Contains('StructuredCodeValidation') -and $sessionGuardText.Contains('StructuredChildExit') -and $sessionGuardText.Contains('WrapperStack') -and $sessionGuardText.Contains('PREFLIGHT|CHECK|GOLDEN|SELFTEST|MATRIX|VERIFY|SMOKE|PRECLASS') -and $sessionGuardText.Contains("if (-not [string]::IsNullOrWhiteSpace(`$structuredCodeEvidence))") -and $sessionGuardText.Contains("`$result.Evidence = ('validation={0}' -f `$structuredCodeEvidence)") -and -not $sessionGuardText.Contains("`$scriptFaultRegex = '(?im)(parsererror|unexpectedtoken|propertynotfoundexception|argumentexception|参数类型不匹配|is not recognized as the name of a cmdlet|cannot find path\s+.*\.ps1|所在位置")
$guardScriptFaultRequiresStrongMarkerOrNoStructuredExit = $sessionGuardText.Contains("`$scriptMarker.Success -or (`$scriptStackMarker.Success -and -not `$structuredChildExitMarker.Success)") -and $sessionGuardText.Contains('[AB-UNATTENDED-RESULT\][^\r\n]*exit_code=\d+') -and $sessionGuardText.Contains('oneclick_end exit_code=\d+')
$guardDelegatesCodeFaultRecovery = $sessionGuardText.Contains("`$failureCategory -in @('noncode-transient', 'monitor-chain', 'environment', 'infra-transient')") -and $sessionGuardText.Contains('if ($autoFixCompileEnabled -and $guardRestartAllowedForFailure') -and $sessionGuardText.Contains('function Get-NormalizedStageRestartResult')
$copilotForbidsInlineEditing = $copilotInstructionsText.Contains('**Agent 工具与机器回执门禁（硬规则）**') -and $copilotInstructionsText.Contains('禁止使用终端内联 Python') -and $copilotInstructionsText.Contains('事件票若提供 brief 的 `recovery_transaction_command`，必须优先执行该事务命令')
$atomicCloseoutContractPass = ($atomicCloseoutVerifiesFacts -and $recoveryTransactionVerifiesFacts -and $takeoverProjectsAtomicCloseout -and $pollProjectsAtomicCloseout -and $closureCheckerProjectsAtomicCloseout -and $promptRejectsSplitCloseout -and $dispatchRequiresMachineFacts -and $dispatchRoutesDiscoveredScriptFault -and $dispatchRecognizesCompileOrTestFailure -and $guardClassifiesStructuredValidationBeforeScriptStack -and $guardScriptFaultRequiresStrongMarkerOrNoStructuredExit -and $guardDelegatesCodeFaultRecovery -and $copilotForbidsInlineEditing)
$atomicCloseoutContractReason = if ($atomicCloseoutContractPass) { 'atomic-ticket-closeout-contract-present' } else { 'missing-atomic-ticket-closeout-contract' }
[void]$results.Add((Get-CaseResult -Name 'atomic-ticket-closeout-contract' -Pass $atomicCloseoutContractPass -Reason $atomicCloseoutContractReason))

# Task-definition semantic edits must name apply_patch explicitly in every operator-facing layer.
$copilotRequiresApplyPatch = $copilotInstructionsText.Contains('任务定义 JSON 的语义修改必须使用 VS Code `apply_patch` 编辑工具')
$promptRequiresApplyPatch = ([regex]::Matches($promptDocText, '任务定义 JSON 的语义修改.*VS Code `apply_patch`')).Count -ge 3
$operationFlowRequiresApplyPatch = $operationFlowText.Contains('任务定义 JSON 的语义修改必须使用 VS Code `apply_patch` 编辑工具')
$startTemplateRequiresApplyPatch = $startTemplateText.Contains('只能使用 VS Code `apply_patch` 修改当前阶段任务定义 JSON')
$dispatchRequiresApplyPatch = $dispatchText.Contains('Task-definition JSON semantic edits must use the VS Code `apply_patch` editing tool') -and $dispatchText.Contains('任务定义 JSON 的语义修改必须使用 VS Code `apply_patch` 编辑工具')
$takeoverRequiresApplyPatch = $takeoverTriggerText.Contains('code-fix: use VS Code apply_patch to edit only allowed task-definition operations') -and $takeoverTriggerText.Contains('validate SyntaxOnly and target-op when locatable')
$taskDefinitionApplyPatchPass = ($copilotRequiresApplyPatch -and $promptRequiresApplyPatch -and $operationFlowRequiresApplyPatch -and $startTemplateRequiresApplyPatch -and $dispatchRequiresApplyPatch -and $takeoverRequiresApplyPatch)
$taskDefinitionApplyPatchReason = if ($taskDefinitionApplyPatchPass) { 'task-definition-apply-patch-contract-present' } else { 'missing-task-definition-apply-patch-contract' }
[void]$results.Add((Get-CaseResult -Name 'task-definition-apply-patch-contract' -Pass $taskDefinitionApplyPatchPass -Reason $taskDefinitionApplyPatchReason))

# Startup validates loadable structure only; each DEV round validates and binds an effective source before code-step.
$stageWindowUsesSyntaxOnly = $stageWindowText.Contains("'-SyntaxOnly'") -and -not $stageWindowText.Contains('DEFERRED_TO_RUNTIME_GATE ticket=deferred_until_main_exit')
$stageWindowDoesNotPrecheckD1Op = -not $stageWindowText.Contains("`$precheckScopeRoundTag = 'D1'") -and -not $stageWindowText.Contains("'-OperationIndex'")
$staticGateIndex = $multiRoundText.IndexOf('Invoke-RoundTaskStaticGate')
$codeStepStartIndex = $multiRoundText.IndexOf('code_step_start=')
$multiRoundRunsStaticBeforeCodeStep = $staticGateIndex -ge 0 -and $codeStepStartIndex -gt $staticGateIndex -and $multiRoundText.Contains("`$roundDecision = 'TASK-STATIC-FAIL'") -and $multiRoundText.Contains('TASK_STATIC_VALIDATED_ARTIFACT_V1') -and $multiRoundText.Contains('RoundTaskStaticGate cannot be disabled') -and $multiRoundText.Contains('RoundTaskStaticGateOperationIndex must be 0')
$codeStepConsumesBoundArtifact = $codeStepText.Contains('Get-ValidatedEffectiveSource') -and $codeStepText.Contains('validated artifact hash binding mismatch') -and $codeStepText.Contains('validated_artifact=accepted') -and $codeStepText.Contains('validated artifact required') -and $codeStepText.Contains('failure_kind={1} failure_category={2}')
$runnerPersistsCodeStepCategory = $multiRoundText.Contains('FailureCategory = $failureCategory') -and $multiRoundText.Contains('FailureCategory = if ($null -ne $firstFailedRow)')
$guardPrefersStructuredCategory = $sessionGuardText.Contains('StructuredFailureCategory') -and $sessionGuardText.Contains('$failureCategory = $structuredFailureCategory')
$multiRoundDoesNotQueueStaticTicket = -not $multiRoundText.Contains('function Add-RoundTaskStaticGateTicket') -and -not $multiRoundText.Contains("event = 'task-definition-fix-required'")
$guardWaitsForMainExit = $sessionGuardText.Contains('task_definition_repair_wait reason=main-process-still-running') -and $sessionGuardText.Contains("Get-StageBusinessProcessSnapshot -Stage 'A' -ExpectedProcessId `$repairProcessId") -and $sessionGuardText.Contains("Get-StageBusinessProcessSnapshot -Stage 'B' -ExpectedProcessId `$repairProcessId") -and $sessionGuardText.Contains('task_definition_repair_ready reason=main-process-stopped')
$staticRepairWaitPass = ($stageWindowUsesSyntaxOnly -and $stageWindowDoesNotPrecheckD1Op -and $multiRoundRunsStaticBeforeCodeStep -and $codeStepConsumesBoundArtifact -and $runnerPersistsCodeStepCategory -and $guardPrefersStructuredCategory -and $multiRoundDoesNotQueueStaticTicket -and $guardWaitsForMainExit)
$staticRepairWaitReason = if ($staticRepairWaitPass) { 'task-static-bound-artifact-contract-present' } else { 'missing-task-static-bound-artifact-contract' }
[void]$results.Add((Get-CaseResult -Name 'task-static-bound-artifact-contract' -Pass $staticRepairWaitPass -Reason $staticRepairWaitReason))

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
$lowDisturbEnTwoLine = $dispatchText.Contains('Report observed runtime status in two lines using read-only checks: "Running normal" or a concise anomaly summary, then "handled_at: YYYY-MM-DD HH:mm:ss"')
$lowDisturbHasHandledAtToken = $dispatchText.Contains('handled_at: YYYY-MM-DD HH:mm:ss')
$lowDisturbHasLowDisturbToken = $dispatchText.Contains('[LOW-DISTURB][STATUS-REPORT-ONLY]')
$lowDisturbPass = ($lowDisturbEnTwoLine -and $lowDisturbHasHandledAtToken -and $lowDisturbHasLowDisturbToken)
$lowDisturbReason = if ($lowDisturbPass) { 'low-disturb-two-line-contract-present' } else { 'missing-low-disturb-two-line-contract' }
[void]$results.Add((Get-CaseResult -Name 'low-disturb-two-line-reply' -Pass $lowDisturbPass -Reason $lowDisturbReason))

# Case 4: status tickets must forbid file edits, including creation of non-tmp scripts.
$dispatchNoNonTmp = $dispatchText.Contains('Never self-heal, handle faults, restart processes/guard, run business_resume, edit files, stabilize the environment, or recover from this status ticket.')
$promptNoNonTmp = [regex]::IsMatch($promptDocText, 'chat_heartbeat\*\.jsonl.*handled.*tmp', [System.Text.RegularExpressions.RegexOptions]::Singleline)
$noNonTmpPass = ($dispatchNoNonTmp -and $promptNoNonTmp)
$noNonTmpReason = if ($noNonTmpPass) { 'no-non-tmp-script-guardrail-present' } else { 'missing-no-non-tmp-script-guardrail' }
[void]$results.Add((Get-CaseResult -Name 'no-non-tmp-script-creation' -Pass $noNonTmpPass -Reason $noNonTmpReason))

# Case 5: repair prompts must keep per-round fail-fast checks and honor the explicit cross-round switch.
$taskSafetyHasFocusedLimitEn = $dispatchText.Contains('optionally a focused -OperationIndex check')
$taskSafetyHasFocusedLimitZh = $dispatchText.Contains('可定位时运行 -OperationIndex 快检')
$taskSafetyHasSwitchDefault = $startTemplateText.Contains('TASK_STATIC_CROSS_ROUND_REPAIR_ENABLED=false') -and $resetStartFileText.Contains('TASK_STATIC_CROSS_ROUND_REPAIR_ENABLED')
$taskSafetyBriefProjectsSwitch = $takeoverTriggerText.Contains('task_static_cross_round_repair_enabled={0}') -and $takeoverTriggerText.Contains('check only the current failing D round before restart; later rounds remain runtime-gated') -and $takeoverTriggerText.Contains('check and repair each later D round through D4 in order before restart')
$taskSafetyDispatchBranches = $dispatchText.Contains('[Cross-round repair enabled]') -and $dispatchText.Contains('[Cross-round repair disabled]') -and $dispatchText.Contains('[跨轮次修复已开启]') -and $dispatchText.Contains('[跨轮次修复已关闭]') -and $dispatchText.Contains('$taskStaticCrossRoundRepairEnabled -and $briefTaskStaticCrossRoundRepairEnabled')
$taskSafetyHasFailFast = $dispatchText.Contains('stops at the first failure') -and $dispatchText.Contains('首错即停') -and $dispatchText.Contains('validates one round at a time') -and $dispatchText.Contains('每次只验证一轮')
$taskSafetyHasAssertionBoundary = $dispatchText.Contains('Update same-round postApplyAssertions only when operation results change') -and $dispatchText.Contains('仅当 operation 结果变化时同步更新同轮 postApplyAssertions')
$taskSafetySuffixAttached = $dispatchText.Contains('$selfHealRuleSuffixEn += $taskDefinitionSafetySuffixEn') -and $dispatchText.Contains('$selfHealRuleSuffixZh += $taskDefinitionSafetySuffixZh')
$taskSafetyHasPhaseBoundary = $dispatchText.Contains('every code-step failure is noncode') -and $dispatchText.Contains('任何 code-step 故障均属于 noncode') -and $dispatchText.Contains('independent task-static checker') -and $dispatchText.Contains('独立 task-static checker') -and $takeoverTriggerText.Contains("if (`$ticketFailurePhase -eq 'code-step')") -and $takeoverTriggerText.Contains("`$ticketFailureCategory = 'noncode-transient'")
$taskSafetyHasRetryScope = $dispatchText.Contains('local checker calls do not consume the identical-fingerprint main-process relaunch budget') -and $dispatchText.Contains('本地检查不消耗相同指纹主进程重启预算') -and $takeoverTriggerText.Contains('checker reruns within one repair ticket are not limited') -and $sessionGuardText.Contains('Checker reruns inside this ticket are unlimited') -and $startTemplateText.Contains('工单内可按首错诊断反复调用 checker')
$taskSafetyPass = ($taskSafetyHasFocusedLimitEn -and $taskSafetyHasFocusedLimitZh -and $taskSafetyHasSwitchDefault -and $taskSafetyBriefProjectsSwitch -and $taskSafetyDispatchBranches -and $taskSafetyHasFailFast -and $taskSafetyHasAssertionBoundary -and $taskSafetySuffixAttached -and $taskSafetyHasPhaseBoundary -and $taskSafetyHasRetryScope)
$taskSafetyReason = if ($taskSafetyPass) { 'task-definition-progressive-static-check-contract-present' } else { 'missing-task-definition-progressive-static-check-contract' }
[void]$results.Add((Get-CaseResult -Name 'task-definition-progressive-static-check' -Pass $taskSafetyPass -Reason $taskSafetyReason))

$fastPassHasExactTerminalDevPolicy = $multiRoundText.Contains('function Test-ResumeHasNoPostResumeDevRounds') -and $multiRoundText.Contains("`$FailedRound -eq 'D4' -or `$FailedRound -match '^V[1-4]`$'")
$fastPassUsesExactRuntimeGatePolicy = $multiRoundText.Contains('$phaseRound -gt $StartRound -and $resumeHasNoPostResumeDevRounds')
$fastPassUsesPreResumeOnly = $multiRoundText.Contains('round_fast_pass_skip=$roundTag role=pre-resume') -and -not $multiRoundText.Contains("-not (`$ResumeFailedRound -match '^D[23]`$')") -and -not $multiRoundText.Contains('round_resume_skip=$roundTag')
$fastPassPolicyRaw = & powershell -NoProfile -ExecutionPolicy Bypass -File (Resolve-RepoPath -Path 'tools/test/start_dev_verify_8round_multiround.ps1') -DescribeResumePolicy | Out-String
$fastPassPolicy = $fastPassPolicyRaw | ConvertFrom-Json -ErrorAction Stop
$fastPassCases = @{}
foreach ($policyCase in @($fastPassPolicy.cases)) { $fastPassCases[[string]$policyCase.failed_round] = $policyCase }
$fastPassExpectedRoles = @{
    D1 = @('resume', 'normal', 'normal', 'normal')
    D2 = @('pre-resume', 'resume', 'normal', 'normal')
    D3 = @('pre-resume', 'pre-resume', 'resume', 'normal')
    D4 = @('pre-resume', 'pre-resume', 'pre-resume', 'resume')
    V1 = @('pre-resume', 'pre-resume', 'pre-resume', 'resume')
    V2 = @('pre-resume', 'pre-resume', 'pre-resume', 'resume')
    V3 = @('pre-resume', 'pre-resume', 'pre-resume', 'resume')
    V4 = @('pre-resume', 'pre-resume', 'pre-resume', 'resume')
}
$fastPassRuntimeMatrixPass = ([string]$fastPassPolicy.schema -eq 'AB_FAST_PASS_RESUME_POLICY_V1' -and $fastPassCases.Count -eq 8)
foreach ($failedRound in @($fastPassExpectedRoles.Keys)) {
    if (-not $fastPassCases.ContainsKey($failedRound)) { $fastPassRuntimeMatrixPass = $false; continue }
    $actualRounds = @($fastPassCases[$failedRound].rounds)
    $actualRoles = @($actualRounds | ForEach-Object { [string]$_.role })
    $expectedRoles = @($fastPassExpectedRoles[$failedRound])
    if ([string]::Join(',', $actualRoles) -ne [string]::Join(',', $expectedRoles)) { $fastPassRuntimeMatrixPass = $false }
    for ($roundIndex = 0; $roundIndex -lt $actualRounds.Count; $roundIndex++) {
        if ([bool]$actualRounds[$roundIndex].fast_pass -ne ($expectedRoles[$roundIndex] -eq 'pre-resume')) { $fastPassRuntimeMatrixPass = $false }
        if ([bool]$actualRounds[$roundIndex].full_autopilot -ne ($expectedRoles[$roundIndex] -ne 'pre-resume')) { $fastPassRuntimeMatrixPass = $false }
    }
}
$d1RuntimeGateEligibility = @($fastPassCases['D1'].rounds | ForEach-Object { [bool]$_.runtime_gate_eligible })
if ([string]::Join(',', $d1RuntimeGateEligibility) -ne 'False,True,True,True') { $fastPassRuntimeMatrixPass = $false }
$fastPassPolicyPass = ($fastPassHasExactTerminalDevPolicy -and $fastPassUsesExactRuntimeGatePolicy -and $fastPassUsesPreResumeOnly -and $fastPassRuntimeMatrixPass)
$fastPassPolicyReason = if ($fastPassPolicyPass) { 'fast-pass-resume-matrix-is-exact' } else { 'fast-pass-resume-matrix-regressed' }
[void]$results.Add((Get-CaseResult -Name 'fast-pass-resume-matrix' -Pass $fastPassPolicyPass -Reason $fastPassPolicyReason))

$wrapperPolicyRaw = & powershell -NoProfile -ExecutionPolicy Bypass -File $codeChangeWrapperPath -EnableGateOnlySourceDrivenSkip true -EnableFastV2Skip false -EnableGuardedFastMode 1 -DescribeInvocationPolicy | Out-String
$wrapperPolicy = $wrapperPolicyRaw | ConvertFrom-Json -ErrorAction Stop
$wrapperBoolBindingPass = (
    [string]$wrapperPolicy.schema -eq 'AUTOPILOT_CODE_CHANGE_INVOCATION_POLICY_V1' -and
    [bool]$wrapperPolicy.enable_gate_only_source_driven_skip -and
    -not [bool]$wrapperPolicy.enable_fast_v2_skip -and
    [bool]$wrapperPolicy.enable_guarded_fast_mode
)
$wrapperBoolBindingReason = if ($wrapperBoolBindingPass) { 'wrapper-accepts-task-string-booleans' } else { 'wrapper-task-string-boolean-binding-regressed' }
[void]$results.Add((Get-CaseResult -Name 'code-change-wrapper-string-booleans' -Pass $wrapperBoolBindingPass -Reason $wrapperBoolBindingReason))

$monitorExitBlockMatch = [regex]::Match($multiRoundText, '(?s)# Health-check monitor chain before exit only for an explicitly bound A/B run\.(?<block>.*?)if \(\$allPass\)')
$monitorExitBlock = if ($monitorExitBlockMatch.Success) { [string]$monitorExitBlockMatch.Groups['block'].Value } else { '' }
$monitorContextGatePass = (
    $monitorExitBlockMatch.Success -and
    $monitorExitBlock.Contains("Get-EnvRawValue -Name 'AUTO_START_FILE_PATH'") -and
    $monitorExitBlock.Contains('if (-not [string]::IsNullOrWhiteSpace($hcStartFilePath))') -and
    $monitorExitBlock.Contains('Invoke-MonitorChainHealthCheck') -and
    $monitorExitBlock.Contains('monitor_health_check_skip reason=no-explicit-ab-start-file') -and
    $stageWindowText.Contains("Set-Item -Path 'Env:AUTO_START_FILE_PATH' -Value `$startFilePath") -and
    -not $monitorExitBlock.Contains('unattended_ab_start_')
)
$monitorContextGateReason = if ($monitorContextGatePass) { 'standalone-skips-monitor-launch-ab-context-keeps-health-check' } else { 'monitor-health-check-context-gate-regressed' }
[void]$results.Add((Get-CaseResult -Name 'monitor-health-check-explicit-ab-context' -Pass $monitorContextGatePass -Reason $monitorContextGateReason))

$snapshotIntegrityChainPass = (
    $snapshotIntegrityText.Contains('A_SUCCESS_SNAPSHOT_MANIFEST_V1') -and
    $snapshotIntegrityText.Contains('snapshot-hash-mismatch:') -and
    $snapshotIntegrityText.Contains('path-not-allowed:') -and
    $snapshotIntegrityText.Contains('destination-hash-mismatch:') -and
    $sessionGuardText.Contains('Write-ASuccessSnapshotManifest -SnapshotDir $snapshotDir') -and
    $sessionGuardText.Contains('Test-ASuccessSnapshotIntegrity -SnapshotDir $snapshotDir') -and
    $stageWindowText.Contains('Get-ASnapshotTaskTargetPaths -TaskDefinitionFile $aTaskDefinitionPath') -and
    $stageWindowText.Contains('b_start_gate blocked: A snapshot integrity failed') -and
    $fastModeBText.Contains('A snapshot restore blocked by integrity check') -and
    $fastModeBText.Contains('A snapshot post-encoding verification failed')
)
$snapshotIntegrityChainReason = if ($snapshotIntegrityChainPass) { 'a-snapshot-integrity-active-chain-present' } else { 'a-snapshot-integrity-active-chain-regressed' }
[void]$results.Add((Get-CaseResult -Name 'a-snapshot-integrity-active-chain' -Pass $snapshotIntegrityChainPass -Reason $snapshotIntegrityChainReason))

# Case 6: poll output must expose triage summary contract for fast diagnosis.
$stageWindowHasForceFlag = $stageWindowText.Contains("`$bForceMonitorRestart = (`$Stage -eq 'B' -and `$EnableBMonitorRestart.IsPresent)")
$stageWindowHasRebindPolicy = $stageWindowText.Contains("monitor_restart_policy={0}") -and $stageWindowText.Contains("rebind-existing")
$stageWindowKeepsMonitorStateInRestart = $stageWindowText.Contains("if (-not `$bForceMonitorRestart) {")
$stageWindowSelfManagedMonitor = $stageWindowText.Contains("action=self-managed") -and $stageWindowText.Contains("self-managed")
$stageWindowRebindPass = ($stageWindowHasForceFlag -and $stageWindowHasRebindPolicy -and $stageWindowKeepsMonitorStateInRestart -and $stageWindowSelfManagedMonitor)
$stageWindowRebindReason = if ($stageWindowRebindPass) { 'stage-window-monitor-rebind-default-present' } else { 'missing-stage-window-monitor-rebind-default' }
[void]$results.Add((Get-CaseResult -Name 'stage-window-monitor-rebind-default' -Pass $stageWindowRebindPass -Reason $stageWindowRebindReason))

$guardBRestartUsesAutoRebind = $sessionGuardText.Contains("`$restartLauncherSwitch = if (`$Stage -eq 'B') { '' } else { '-StartMonitors' }") -and -not $sessionGuardText.Contains("`$restartLauncherSwitch = if (`$Stage -eq 'B') { '-EnableBMonitorRestart' } else { '-StartMonitors' }")
$guardBRestartUsesAutoRebindReason = if ($guardBRestartUsesAutoRebind) { 'guard-b-restart-auto-rebind-present' } else { 'missing-guard-b-restart-auto-rebind' }
[void]$results.Add((Get-CaseResult -Name 'guard-b-restart-auto-rebind' -Pass $guardBRestartUsesAutoRebind -Reason $guardBRestartUsesAutoRebindReason))

$aPassReviewNormalPriority = $dispatchText.Contains("`$normalPriorityEvents = @('running-status-report', 'a-pass-conclusion-b-started')") -and $dispatchText.Contains("`$ipcPriority = if (`$eventNormalized -in `$normalPriorityEvents) { 'normal' } else { 'high' }") -and $dispatchText.Contains('Actionable recovery tickets stay high priority')
$aPassReviewNormalPriorityReason = if ($aPassReviewNormalPriority) { 'a-pass-review-normal-priority-present' } else { 'missing-a-pass-review-normal-priority' }
[void]$results.Add((Get-CaseResult -Name 'a-pass-review-normal-priority' -Pass $aPassReviewNormalPriority -Reason $aPassReviewNormalPriorityReason))

$aPassReviewStableDedupNewShape = '$aPassConclusionDedup = ("{0}|{1}|{2}" -f'
$aPassReviewStableDedupOldShape = '$aPassConclusionDedup = ("{0}|{1}|{2}|{3}|{4}|{5}" -f'
$aPassReviewStableDedup = $sessionGuardText.Contains('function Resolve-RunDirAnchorForFailurePolicy') -and $sessionGuardText.Contains('failure_policy_run_dir_override') -and $sessionGuardText.Contains($aPassReviewStableDedupNewShape) -and -not $sessionGuardText.Contains($aPassReviewStableDedupOldShape)
$aPassReviewStableDedupReason = if ($aPassReviewStableDedup) { 'a-pass-review-stable-dedup-present' } else { 'missing-a-pass-review-stable-dedup' }
[void]$results.Add((Get-CaseResult -Name 'a-pass-review-stable-dedup' -Pass $aPassReviewStableDedup -Reason $aPassReviewStableDedupReason))

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
$graceDefaultIsSixty = $startTemplateText.Contains('MONITOR_CHAIN_GRACE_MINUTES=60') -and $takeoverTriggerText.Contains('$monitorChainGraceMinutes = 60') -and $sessionGuardText.Contains('$mainProcessExitMonitorGraceMinutes = 60')
$sessionGuardGracePass = ($sessionGuardHasGraceSetting -and $sessionGuardHasGraceStart -and $sessionGuardHasGraceWait -and $sessionGuardHasGraceClear -and $graceDefaultIsSixty)
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

# Recovery transaction needs a targeted poll path: recovery-drain must not hide the explicitly selected incident ticket.
$pollSelectRoot = Join-Path $outDir 'poll_select_ticket_drain'
New-Item -ItemType Directory -Path $pollSelectRoot -Force | Out-Null
$pollSelectTicketId = 'T-MINI-SELECT-DRAIN'
$pollSelectQueue = Join-Path $pollSelectRoot 'agent_tickets.jsonl'
$pollSelectState = Join-Path $pollSelectRoot 'poll_state.json'
$pollSelectLedger = Join-Path $pollSelectRoot 'ledger.json'
$pollSelectTicket = [ordered]@{
    schema = 'AB_AGENT_TICKET_V1'
    ticket_id = $pollSelectTicketId
    created_at = '2026-07-18 19:00:00'
    source = 'status-ticket-mini-regression'
    event = 'incident-captured'
    severity = 'high'
    requires_confirmation = $false
    start_file = 'testdata/unattended_start/smoke/unattended_ab_start_status_ticket_smoke.md'
    queue_path = 'out/artifacts/status_ticket_mini_regression/poll_select_ticket_drain/agent_tickets.jsonl'
    session_final_status = 'FAIL'
    a_final_status = 'FAIL'
    b_final_status = 'NOT_RUN'
    preferred_stage = 'A'
    main_round = 'D1'
    failure_phase = 'task-static'
    failure_kind = 'task-definition-mismatch'
    failure_category = 'task-definition-mismatch'
    failure_source = 'synthetic-D1.log'
    failure_evidence = '[TASK-STATIC-CHECK] severity=error detail=synthetic'
    self_healable = $true
    non_recoverable_env = $false
    recommended_action = 'synthetic code-fix'
}
Write-Utf8BomText -Path $pollSelectQueue -Text (($pollSelectTicket | ConvertTo-Json -Depth 8 -Compress) + "`n")
Write-Utf8BomText -Path $pollSelectState -Text (([ordered]@{
            schema = 'AB_AI_TICKET_POLL_STATE_V1'
            processed_ids = @()
            recovery_drain_pending = $true
            last_drain_at = ''
            last_recovery_drain_at = ''
            event_queue_floor_at = '2026-01-01 00:00:00'
            event_queue_floor_source = 'mini-regression'
            event_queue_skip_existing_on_start = $true
        } | ConvertTo-Json -Depth 8) + "`n")
Write-Utf8BomText -Path $pollSelectLedger -Text (([ordered]@{
            schema = 'AB_AI_TICKET_LEDGER_V3'
            records = @()
        } | ConvertTo-Json -Depth 8) + "`n")
$pollSelectRaw = & $pollPath -StartFile $pollRuntimeStartFile -QueuePath $pollSelectQueue -StatePath $pollSelectState -LedgerPath $pollSelectLedger -SelectTicketId $pollSelectTicketId -Last 20 -AsJson | Out-String
$pollSelectJson = $null
try {
    $pollSelectJson = $pollSelectRaw | ConvertFrom-Json -ErrorAction Stop
}
catch {
    $pollSelectJson = $null
}
$pollSelectRows = @(if ($null -ne $pollSelectJson) { @($pollSelectJson.rows) } else { @() })
$pollSelectRow = if ($pollSelectRows.Count -gt 0) { $pollSelectRows[0] } else { $null }
$pollSelectRuntimePass = (
    $null -ne $pollSelectJson -and
    [string]$pollSelectJson.drain_mode -eq 'recovery-drain' -and
    [string]$pollSelectJson.select_ticket_id -eq $pollSelectTicketId -and
    $null -ne $pollSelectRow -and
    [string]$pollSelectRow.ticket_id -eq $pollSelectTicketId -and
    -not [string]::IsNullOrWhiteSpace([string]$pollSelectRow.recovery_transaction_command) -and
    @($pollSelectRow.next_command_order) -contains 'recovery_transaction_command'
)
$pollSelectRuntimeReason = if ($pollSelectRuntimePass) { 'poll-select-ticket-drain-runtime-present' } else { 'poll-select-ticket-drain-runtime-regressed' }
[void]$results.Add((Get-CaseResult -Name 'poll-select-ticket-drain-runtime' -Pass $pollSelectRuntimePass -Reason $pollSelectRuntimeReason))

# Case 10: runtime poll ordering must place route guard first for status-ticket execution.
$pollOrderQueue = Join-Path $outDir 'poll_next_command_order_queue.jsonl'
$pollOrderState = Join-Path $outDir 'poll_next_command_order_state.json'
$pollOrderLedger = Join-Path $outDir 'poll_next_command_order_ledger.json'
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
        $pollOrderRaw = & $pollPath -StartFile $pollRuntimeStartFile -QueuePath $pollOrderQueue -StatePath $pollOrderState -LedgerPath $pollOrderLedger -IncludeStatusReports -Last 20 -AsJson
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
$pollOrderPass = ($pollOrderHasOrder -and $pollOrderNames.Count -ge 2 -and $pollOrderNames[0] -eq 'route_guard_command' -and $pollOrderNames[1] -eq 'business_command' -and -not ($pollOrderNames -contains 'atomic_closeout_command'))
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
$pollNoticeState = Join-Path $outDir 'poll_notice_command_order_state.json'
$pollNoticeLedger = Join-Path $outDir 'poll_notice_command_order_ledger.json'
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

$pollNoticeRaw = & $pollPath -StartFile $pollRuntimeStartFile -QueuePath $pollNoticeQueue -StatePath $pollNoticeState -LedgerPath $pollNoticeLedger -Last 20 -AsJson | Out-String
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
$pollNoticeLegacySteps = @($pollNoticeNames | Where-Object { $_ -in @('handled_receipt_command', 'validate_receipt_command', 'mark_processed_command', 'post_check_command', 'ticket_closure_check_command', 'event_dedup_health_check_command', 'final_status_closeout_command', 'final_status_closeout_apply_ack_command') })
$pollNoticePass = ($pollNoticeHasOrder -and $pollNoticeNames.Count -eq 2 -and $pollNoticeNames[0] -eq 'route_guard_command' -and $pollNoticeNames[1] -eq 'atomic_closeout_command' -and $pollNoticeLegacySteps.Count -eq 0)
$pollNoticeReason = if ($pollNoticePass) { 'poll-notice-command-order-runtime-present' } else { 'missing-poll-notice-command-order-runtime' }
[void]$results.Add((Get-CaseResult -Name 'poll-notice-command-order-runtime' -Pass $pollNoticePass -Reason $pollNoticeReason))

# Case 9: manual-wait is a decision-only notice and must close out without
# business, continue-watch, or legacy split-receipt commands.
$pollManualQueue = Join-Path $outDir 'poll_manual_command_order_queue.jsonl'
$pollManualState = Join-Path $outDir 'poll_manual_command_order_state.json'
$pollManualLedger = Join-Path $outDir 'poll_manual_command_order_ledger.json'
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

$pollManualRaw = & $pollPath -StartFile $pollRuntimeStartFile -QueuePath $pollManualQueue -StatePath $pollManualState -LedgerPath $pollManualLedger -Last 20 -AsJson | Out-String
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
$pollManualLegacySteps = @($pollManualNames | Where-Object { $_ -in @('handled_receipt_command', 'validate_receipt_command', 'mark_processed_command', 'post_check_command', 'ticket_closure_check_command', 'event_dedup_health_check_command', 'final_status_closeout_command', 'final_status_closeout_apply_ack_command') })
$pollManualPass = ($pollManualHasOrder -and $pollManualNames.Count -eq 2 -and $pollManualNames[0] -eq 'route_guard_command' -and $pollManualNames[1] -eq 'atomic_closeout_command' -and $pollManualLegacySteps.Count -eq 0)
$pollManualReason = if ($pollManualPass) { 'poll-manual-command-order-runtime-present' } else { 'missing-poll-manual-command-order-runtime' }
[void]$results.Add((Get-CaseResult -Name 'poll-manual-command-order-runtime' -Pass $pollManualPass -Reason $pollManualReason))

# Atomic closeout must persist receipt and processed state, and replay idempotently.
$closeoutRoot = Join-Path $outDir 'atomic_closeout_runtime'
$closeoutQueue = Join-Path $closeoutRoot 'queue.jsonl'
$closeoutState = Join-Path $closeoutRoot 'state.json'
$closeoutLedger = Join-Path $closeoutRoot 'ledger.json'
$closeoutTakeover = Join-Path $closeoutRoot 'takeover'
New-Item -ItemType Directory -Path $closeoutTakeover -Force | Out-Null
$closeoutTicket = [ordered]@{
    schema = 'AB_AGENT_TICKET_V1'
    ticket_id = 'T-MINI-CLOSEOUT-' + $stamp
    created_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    source = 'status-ticket-mini-regression'
    event = 'incident-captured'
    severity = 'high'
    requires_confirmation = $false
    start_file = $pollRuntimeStartFile
    queue_path = $closeoutQueue
    session_final_status = 'RUNNING'
    a_final_status = 'FAIL'
    b_final_status = 'PENDING'
    detail = 'atomic closeout runtime probe'
    recommended_action = 'probe'
    preferred_stage = 'A'
    self_healable = $true
    non_recoverable_env = $false
}
Set-Content -LiteralPath $closeoutQueue -Encoding utf8 -Value (($closeoutTicket | ConvertTo-Json -Compress -Depth 10))
$closeoutLedgerAbsentBeforeFirstCall = -not (Test-Path -LiteralPath $closeoutLedger)

$unrelatedBriefPath = Join-Path $closeoutTakeover 'unrelated-orphan.md'
$unrelatedBriefLines = @(
    'ticket_id=T-MINI-CLOSEOUT-UNRELATED-' + $stamp,
    'start_file=' + $pollRuntimeStartFile,
    'queue_path=' + $closeoutQueue
)
[System.IO.File]::WriteAllText($unrelatedBriefPath, ([string]::Join("`n", $unrelatedBriefLines) + "`n"), [System.Text.UTF8Encoding]::new($false))
$globalClosureRaw = & $ticketClosurePath -StartFile $pollRuntimeStartFile -QueuePath $closeoutQueue -LedgerPath $closeoutLedger -TakeoverRoot $closeoutTakeover -AsJson | Out-String
$globalClosureJsonStart = $globalClosureRaw.IndexOf('{')
$globalClosure = if ($globalClosureJsonStart -ge 0) { $globalClosureRaw.Substring($globalClosureJsonStart) | ConvertFrom-Json -ErrorAction Stop } else { $null }
$globalClosureDetectsUnrelatedBrief = ($null -ne $globalClosure -and -not [bool]$globalClosure.pass -and [int]$globalClosure.counts.brief_without_queue_or_ledger -eq 1)

$closeoutFirst = $null
$closeoutReplay = $null
try {
    $closeoutFirstRaw = & $atomicCloseoutPath -StartFile $pollRuntimeStartFile -TicketId ([string]$closeoutTicket.ticket_id) -QueuePath $closeoutQueue -StatePath $closeoutState -LedgerPath $closeoutLedger -TakeoverRoot $closeoutTakeover -Last 20 -AsJson | Out-String
    $closeoutFirst = $closeoutFirstRaw | ConvertFrom-Json -ErrorAction Stop
    $closeoutReplayRaw = & $atomicCloseoutPath -StartFile $pollRuntimeStartFile -TicketId ([string]$closeoutTicket.ticket_id) -QueuePath $closeoutQueue -StatePath $closeoutState -LedgerPath $closeoutLedger -TakeoverRoot $closeoutTakeover -Last 20 -AsJson | Out-String
    $closeoutReplay = $closeoutReplayRaw | ConvertFrom-Json -ErrorAction Stop
}
catch {
    $closeoutFirst = $null
    $closeoutReplay = $null
}
$closeoutFirstPass = ($null -ne $closeoutFirst -and [bool]$closeoutFirst.success -and [bool]$closeoutFirst.processed -and [string]$closeoutFirst.ledger_status -eq 'done' -and [bool]$closeoutFirst.receipt_valid -and [bool]$closeoutFirst.closure_pass)
$closeoutReplayPass = ($null -ne $closeoutReplay -and [bool]$closeoutReplay.success -and [bool]$closeoutReplay.processed -and [string]$closeoutReplay.ledger_status -eq 'done' -and [bool]$closeoutReplay.receipt_valid -and [bool]$closeoutReplay.closure_pass)
$atomicCloseoutRuntimePass = ($globalClosureDetectsUnrelatedBrief -and $closeoutLedgerAbsentBeforeFirstCall -and $closeoutFirstPass -and $closeoutReplayPass -and [string]$closeoutFirst.handled_at -eq [string]$closeoutReplay.handled_at)
$atomicCloseoutRuntimeReason = if ($atomicCloseoutRuntimePass) { 'atomic-ticket-closeout-runtime-present' } else { 'atomic-ticket-closeout-runtime-failed' }
[void]$results.Add((Get-CaseResult -Name 'atomic-ticket-closeout-runtime' -Pass $atomicCloseoutRuntimePass -Reason $atomicCloseoutRuntimeReason))

# An unknown ticket must fail closed with parseable machine facts and a nonzero exit code.
$closeoutMissingTicketId = 'T-MINI-CLOSEOUT-MISSING-' + $stamp
$closeoutMissingRaw = @(& powershell -NoProfile -ExecutionPolicy Bypass -File $atomicCloseoutPath -StartFile $pollRuntimeStartFile -TicketId $closeoutMissingTicketId -QueuePath $closeoutQueue -StatePath $closeoutState -LedgerPath $closeoutLedger -TakeoverRoot $closeoutTakeover -Last 20 -AsJson 2>&1)
$closeoutMissingExitCode = $LASTEXITCODE
$closeoutMissing = $null
try {
    $closeoutMissingText = [string]::Join("`n", @($closeoutMissingRaw | ForEach-Object { [string]$_ }))
    $closeoutMissingJsonStart = $closeoutMissingText.IndexOf('{')
    if ($closeoutMissingJsonStart -lt 0) {
        throw 'fail-closed probe did not return JSON'
    }
    $closeoutMissing = ($closeoutMissingText.Substring($closeoutMissingJsonStart) | ConvertFrom-Json -ErrorAction Stop)
}
catch {
    $closeoutMissing = $null
}
$atomicCloseoutFailClosedPass = ($closeoutMissingExitCode -ne 0 -and $null -ne $closeoutMissing -and -not [bool]$closeoutMissing.success -and (-not [bool]$closeoutMissing.processed -or -not [bool]$closeoutMissing.receipt_valid -or [string]$closeoutMissing.ledger_status -ne 'done' -or -not [bool]$closeoutMissing.closure_pass) -and [string]::IsNullOrWhiteSpace([string]$closeoutMissing.handled_at))
$atomicCloseoutFailClosedReason = if ($atomicCloseoutFailClosedPass) { 'atomic-ticket-closeout-fail-closed-runtime-present' } else { 'atomic-ticket-closeout-fail-closed-runtime-failed' }
[void]$results.Add((Get-CaseResult -Name 'atomic-ticket-closeout-fail-closed-runtime' -Pass $atomicCloseoutFailClosedPass -Reason $atomicCloseoutFailClosedReason))

# Poll mutex contention must fail closed and preserve the lock-busy machine fact.
$closeoutMutexStartKey = [System.IO.Path]::GetFullPath($pollRuntimeStartFile).ToLowerInvariant()
$closeoutMutexQueueKey = [System.IO.Path]::GetFullPath($closeoutQueue).ToLowerInvariant()
$closeoutMutexBytes = [System.Text.Encoding]::UTF8.GetBytes(("{0}|{1}" -f $closeoutMutexStartKey, $closeoutMutexQueueKey))
$closeoutMutexSha1 = [System.Security.Cryptography.SHA1]::Create()
try {
    $closeoutMutexHashBytes = $closeoutMutexSha1.ComputeHash($closeoutMutexBytes)
}
finally {
    $closeoutMutexSha1.Dispose()
}
$closeoutMutexHash = [System.BitConverter]::ToString($closeoutMutexHashBytes).Replace('-', '')
$closeoutMutex = New-Object System.Threading.Mutex($false, ("Global\whois-poll-state-ledger-{0}" -f $closeoutMutexHash))
$closeoutMutexAcquired = $false
$closeoutLockBusy = $null
$closeoutLockBusyExitCode = 0
try {
    $closeoutMutexAcquired = $closeoutMutex.WaitOne(0)
    if (-not $closeoutMutexAcquired) {
        throw 'atomic closeout regression could not acquire poll mutex'
    }

    $closeoutLockBusyRaw = @(& powershell -NoProfile -ExecutionPolicy Bypass -File $atomicCloseoutPath -StartFile $pollRuntimeStartFile -TicketId ([string]$closeoutTicket.ticket_id) -QueuePath $closeoutQueue -StatePath $closeoutState -LedgerPath $closeoutLedger -TakeoverRoot $closeoutTakeover -Last 20 -AsJson 2>&1)
    $closeoutLockBusyExitCode = $LASTEXITCODE
    $closeoutLockBusyText = [string]::Join("`n", @($closeoutLockBusyRaw | ForEach-Object { [string]$_ }))
    $closeoutLockBusyJsonStart = $closeoutLockBusyText.IndexOf('{')
    if ($closeoutLockBusyJsonStart -lt 0) {
        throw 'lock-busy closeout probe did not return JSON'
    }
    $closeoutLockBusy = ($closeoutLockBusyText.Substring($closeoutLockBusyJsonStart) | ConvertFrom-Json -ErrorAction Stop)
}
catch {
    $closeoutLockBusy = $null
}
finally {
    if ($closeoutMutexAcquired) {
        $closeoutMutex.ReleaseMutex() | Out-Null
    }
    $closeoutMutex.Dispose()
}
$atomicCloseoutLockBusyPass = ($closeoutLockBusyExitCode -ne 0 -and $null -ne $closeoutLockBusy -and -not [bool]$closeoutLockBusy.success -and [bool]$closeoutLockBusy.poll_lock_busy -and [string]$closeoutLockBusy.reason -eq 'acknowledge poll lock is busy' -and [string]::IsNullOrWhiteSpace([string]$closeoutLockBusy.handled_at))
$atomicCloseoutLockBusyReason = if ($atomicCloseoutLockBusyPass) { 'atomic-ticket-closeout-lock-busy-fail-closed' } else { 'atomic-ticket-closeout-lock-busy-facts-missing' }
[void]$results.Add((Get-CaseResult -Name 'atomic-ticket-closeout-lock-busy-runtime' -Pass $atomicCloseoutLockBusyPass -Reason $atomicCloseoutLockBusyReason))

# Render a real dispatch message with all interactive senders disabled.
$dispatchRuntimeRoot = Join-Path $outDir 'atomic_dispatch_runtime'
$dispatchRuntimeStartFile = Join-Path $dispatchRuntimeRoot 'start.md'
$dispatchRuntimeQueue = Join-Path $dispatchRuntimeRoot 'queue.jsonl'
$dispatchRuntimeBrief = Join-Path $dispatchRuntimeRoot 'brief.md'
$dispatchRuntimeTicketId = 'T-MINI-DISPATCH-' + $stamp
$dispatchRuntimeAtomicMarker = 'ATOMIC-CLOSEOUT-RUNTIME-MARKER-' + $stamp
Write-Utf8BomText -Path $dispatchRuntimeStartFile -Text @"
AI_CHAT_POLICY_WORK_MODE=event-only
AI_CHAT_DISPATCH_USE_IPC=false
AI_CHAT_DISPATCH_USE_PY_SENDER=false
AI_CHAT_DISPATCH_USE_AHK=false
SESSION_FINAL_STATUS=RUNNING
A_FINAL_STATUS=FAIL
B_FINAL_STATUS=PENDING
"@
$dispatchRuntimeTicket = [ordered]@{
    schema = 'AB_AGENT_TICKET_V1'
    ticket_id = $dispatchRuntimeTicketId
    created_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    event = 'incident-captured'
    start_file = $dispatchRuntimeStartFile
    queue_path = $dispatchRuntimeQueue
    failure_phase = 'compile-or-test'
    failure_kind = 'compile-or-test-failure'
    failure_category = 'code-or-unknown'
    main_round = 'D3'
}
Set-Content -LiteralPath $dispatchRuntimeQueue -Encoding utf8 -Value (($dispatchRuntimeTicket | ConvertTo-Json -Compress -Depth 6))
Write-Utf8BomText -Path $dispatchRuntimeBrief -Text @"
ticket_id=$dispatchRuntimeTicketId
event=incident-captured
route_guard_expected=incident-manual-code-fix
failure_phase=compile-or-test
failure_kind=compile-or-test-failure
failure_category=code-or-unknown
main_round=D3
atomic_closeout_command=$dispatchRuntimeAtomicMarker
"@
$dispatchRuntimeState = $null
try {
    $null = & $dispatchPath -TicketId $dispatchRuntimeTicketId -TicketEvent 'incident-captured' -StartFile $dispatchRuntimeStartFile -QueuePath $dispatchRuntimeQueue -BriefPath $dispatchRuntimeBrief -NoOpenEditor -SkipClipboard
    $dispatchRuntimeToken = Get-StableStartFileToken -StartFilePath $dispatchRuntimeStartFile
    $dispatchRuntimeStatePath = Join-Path (Get-UnattendedRepoRoot) ("out\artifacts\ab_agent_queue\chat_dispatch\latest_relay_{0}.json" -f $dispatchRuntimeToken)
    $dispatchRuntimeState = Get-Content -LiteralPath $dispatchRuntimeStatePath -Raw -Encoding utf8 | ConvertFrom-Json -ErrorAction Stop
}
catch {
    $dispatchRuntimeState = $null
}
$dispatchRuntimeMessage = if ($null -ne $dispatchRuntimeState) { [string]$dispatchRuntimeState.dispatch_message } else { '' }
$dispatchRuntimeMarkerCount = ([regex]::Matches($dispatchRuntimeMessage, [regex]::Escape($dispatchRuntimeAtomicMarker))).Count
$mandatoryReceiptSuffix = "强制回执`nhandled_at: YYYY-MM-DD HH:mm:ss（必填，不得省略）"
$dispatchRuntimeNormalized = $dispatchRuntimeMessage.Replace("`r`n", "`n")
$dispatchRuntimePass = ($dispatchRuntimeMarkerCount -eq 1 -and $dispatchRuntimeMessage.Contains('机器事实闭环门禁：每张事件票处理结束时，atomic_closeout_command 只能执行一次，无论成功或失败均不得再次执行') -and $dispatchRuntimeMessage.Contains('success=true') -and $dispatchRuntimeMessage.Contains('closure_pass=true') -and $dispatchRuntimeMessage.Contains('VS Code `apply_patch`') -and $dispatchRuntimeMessage.Contains('只能在 D3 operations 数组末尾连续追加') -and -not $dispatchRuntimeMessage.Contains('缺少被允许的 task-static 或编译/验证代码故障阶段') -and $dispatchRuntimeMessage.Contains('若处理本代码修复票时发现脚本故障，必须停止代码修复流程并按脚本策略重新分类') -and $dispatchRuntimeNormalized.EndsWith($mandatoryReceiptSuffix))
$dispatchRuntimeReason = if ($dispatchRuntimePass) { 'atomic-dispatch-message-runtime-present' } else { 'atomic-dispatch-message-runtime-failed' }
[void]$results.Add((Get-CaseResult -Name 'atomic-dispatch-message-runtime' -Pass $dispatchRuntimePass -Reason $dispatchRuntimeReason))

# A real event dispatch without atomic_closeout_command must explicitly fail closed.
$dispatchMissingBrief = Join-Path $dispatchRuntimeRoot 'brief_missing_atomic.md'
Write-Utf8BomText -Path $dispatchMissingBrief -Text @"
ticket_id=$dispatchRuntimeTicketId
event=incident-captured
route_guard_expected=incident-manual-code-fix
failure_phase=compile-or-test
failure_kind=compile-or-test-failure
failure_category=code-or-unknown
main_round=D3
"@
$dispatchMissingState = $null
try {
    $null = & $dispatchPath -TicketId $dispatchRuntimeTicketId -TicketEvent 'incident-captured' -StartFile $dispatchRuntimeStartFile -QueuePath $dispatchRuntimeQueue -BriefPath $dispatchMissingBrief -NoOpenEditor -SkipClipboard
    $dispatchMissingToken = Get-StableStartFileToken -StartFilePath $dispatchRuntimeStartFile
    $dispatchMissingStatePath = Join-Path (Get-UnattendedRepoRoot) ("out\artifacts\ab_agent_queue\chat_dispatch\latest_relay_{0}.json" -f $dispatchMissingToken)
    $dispatchMissingState = Get-Content -LiteralPath $dispatchMissingStatePath -Raw -Encoding utf8 | ConvertFrom-Json -ErrorAction Stop
}
catch {
    $dispatchMissingState = $null
}
$dispatchMissingMessage = if ($null -ne $dispatchMissingState) { [string]$dispatchMissingState.dispatch_message } else { '' }
$dispatchMissingNormalized = $dispatchMissingMessage.Replace("`r`n", "`n")
$dispatchMissingAtomicPass = ($dispatchMissingMessage.Contains('同时缺少 recovery_transaction_command 与 atomic_closeout_command') -and $dispatchMissingMessage.Contains('必须 fail-close') -and $dispatchMissingMessage.Contains('不得自行生成 handled_at') -and $dispatchMissingNormalized.EndsWith($mandatoryReceiptSuffix))
$dispatchMissingAtomicReason = if ($dispatchMissingAtomicPass) { 'atomic-dispatch-missing-command-fail-closed-runtime-present' } else { 'atomic-dispatch-missing-command-fail-closed-runtime-failed' }
[void]$results.Add((Get-CaseResult -Name 'atomic-dispatch-missing-command-fail-closed-runtime' -Pass $dispatchMissingAtomicPass -Reason $dispatchMissingAtomicReason))

# A real scheduled status dispatch must end with the same receipt rule without authorizing atomic closeout.
$dispatchStatusTicketId = 'T-MINI-STATUS-DISPATCH-' + $stamp
$dispatchStatusTicket = [ordered]@{
    schema = 'AB_AGENT_TICKET_V1'
    ticket_id = $dispatchStatusTicketId
    created_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    event = 'running-status-report'
    start_file = $dispatchRuntimeStartFile
    queue_path = $dispatchRuntimeQueue
    session_final_status = 'RUNNING'
    a_final_status = 'RUNNING'
    b_final_status = 'PENDING'
}
Set-Content -LiteralPath $dispatchRuntimeQueue -Encoding utf8 -Value (($dispatchStatusTicket | ConvertTo-Json -Compress -Depth 6))
$dispatchStatusBrief = Join-Path $dispatchRuntimeRoot 'brief_status.md'
Write-Utf8BomText -Path $dispatchStatusBrief -Text @"
ticket_id=$dispatchStatusTicketId
event=running-status-report
route_guard_expected=status-health-check-only
session_final_status=RUNNING
a_final_status=RUNNING
b_final_status=PENDING
"@
$dispatchStatusState = $null
try {
    $null = & $dispatchPath -TicketId $dispatchStatusTicketId -TicketEvent 'running-status-report' -StartFile $dispatchRuntimeStartFile -QueuePath $dispatchRuntimeQueue -BriefPath $dispatchStatusBrief -NoOpenEditor -SkipClipboard
    $dispatchStatusToken = Get-StableStartFileToken -StartFilePath $dispatchRuntimeStartFile
    $dispatchStatusStatePath = Join-Path (Get-UnattendedRepoRoot) ("out\artifacts\ab_agent_queue\chat_dispatch\latest_relay_{0}.json" -f $dispatchStatusToken)
    $dispatchStatusState = Get-Content -LiteralPath $dispatchStatusStatePath -Raw -Encoding utf8 | ConvertFrom-Json -ErrorAction Stop
}
catch {
    $dispatchStatusState = $null
}
$dispatchStatusMessage = if ($null -ne $dispatchStatusState) { [string]$dispatchStatusState.dispatch_message } else { '' }
$dispatchStatusNormalized = $dispatchStatusMessage.Replace("`r`n", "`n")
$dispatchStatusPass = ($dispatchStatusNormalized.EndsWith($mandatoryReceiptSuffix) -and -not $dispatchStatusMessage.Contains('机器事实闭环门禁') -and -not $dispatchStatusMessage.Contains('最终回复前必须执行以下唯一原子收尾命令'))
$dispatchStatusReason = if ($dispatchStatusPass) { 'status-dispatch-mandatory-receipt-last-runtime-present' } else { 'status-dispatch-mandatory-receipt-last-runtime-failed' }
[void]$results.Add((Get-CaseResult -Name 'status-dispatch-mandatory-receipt-last-runtime' -Pass $dispatchStatusPass -Reason $dispatchStatusReason))

# Fingerprint normalization must collapse the same issue with different line numbers to one token.
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
