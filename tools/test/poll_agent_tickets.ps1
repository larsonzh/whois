param(
    [Parameter(Mandatory = $true)][string]$StartFile,
    [AllowEmptyString()][string]$QueuePath = '',
    [AllowEmptyString()][string]$StatePath = '',
    [AllowEmptyString()][string]$LedgerPath = '',
    [AllowNull()][object]$EnableLedgerCompaction = $false,
    [ValidateRange(1, 365)][int]$LedgerCompactionDays = 7,
    [ValidateRange(1, 365)][int]$LedgerArchiveRetentionDays = 30,
    [ValidateRange(1, 200)][int]$Last = 20,
    [ValidateRange(0, 200000)][int]$MaxProcessedIds = 200000,
    [switch]$IncludeStatusReports,
    [AllowNull()][object]$MarkProcessed = $false,
    [AllowNull()][object]$EnableFallbackStatus = $true,
    [AllowNull()][object]$EventPolicyStrict = $null,
    [AllowEmptyString()][string]$AcknowledgeTicketIds = '',
    [switch]$AsJson
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'unattended_exit_result.ps1')
$script:UnhandledExitTag = 'POLL-AGENT-TICKETS'

trap {
    $exitCode = Get-UnattendedExitCodeFromRecord -Tag $script:UnhandledExitTag -Record $_ -DefaultExitCode 1
    Write-UnattendedUnhandledResult -Tag $script:UnhandledExitTag -Record $_ -ExitCode $exitCode
    exit $exitCode
}

# Normalize start-file encoding (UTF-8 with BOM + LF) only when necessary.
# The function below is intentionally conservative: it reads bytes, checks for
# UTF-8 BOM and CRLF occurrences, and rewrites the file only if a change is
# required. This avoids unnecessary writes and preserves timestamps when not
# needed. The function accepts a repo-relative or absolute path.
function Set-StartFileEncoding {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory=$true)][string]$Path)

    try {
        if (-not $PSCmdlet.ShouldProcess($Path, 'Normalize start-file encoding via incremental encoding policy script')) {
            return $false
        }

        $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
        $fullPath = if ([System.IO.Path]::IsPathRooted($Path)) {
            [System.IO.Path]::GetFullPath($Path)
        }
        else {
            [System.IO.Path]::GetFullPath((Join-Path $repoRoot $Path))
        }

        if (-not (Test-Path -LiteralPath $fullPath)) {
            return $false
        }

        $changedScript = Join-Path $repoRoot 'tools\dev\enforce_utf8_bom_lf_changed.ps1'
        if (-not (Test-Path -LiteralPath $changedScript)) {
            return $false
        }

        $relativePath = $fullPath
        $repoRootNorm = [System.IO.Path]::GetFullPath($repoRoot)
        if ($fullPath.StartsWith($repoRootNorm, [System.StringComparison]::OrdinalIgnoreCase)) {
            $relativePath = $fullPath.Substring($repoRootNorm.Length).TrimStart('\\').Replace('\\', '/')
        }

        $lines = @((& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $changedScript -Mode fix -Policy warn -TargetPaths @($relativePath) 2>&1) | ForEach-Object { [string]$_ })
        $exitCode = if ($null -eq $LASTEXITCODE) { 0 } else { [int]$LASTEXITCODE }
        if ($exitCode -ne 0) {
            Write-Verbose ((@($lines) -join ' | '))
            return $false
        }

        return ($lines -join "`n") -match '\[ENCODING-POLICY-CHANGED\] fixed path='
    }
    catch {
        Write-Verbose $_.Exception.Message
        return $false
    }
}

$script:EventSetStatusReport = @{ 'running-status-report' = $true }
$script:EventSetDrainSafe = @{
    'running-status-report' = $true
    'manual-wait-paused' = $true
    'budget-exhausted-stop' = $true
    'known-infra-transient-stop' = $true
}
$script:EventSetBarrier = @{
    'incident-captured' = $true
    'recovery-await-confirmation' = $true
    'auto-fix-await-confirmation' = $true
    'task-definition-fix-required' = $true
    'main-process-exit-review' = $true
    'manual-wait-paused' = $true
    'budget-exhausted-stop' = $true
    'known-infra-transient-stop' = $true
}
$script:EventSetRestartSensitive = @{
    'incident-captured' = $true
    'recovery-await-confirmation' = $true
    'auto-fix-await-confirmation' = $true
    'task-definition-fix-required' = $true
    'main-process-exit-review' = $true
}
$script:EventSetContractGate = @{ 'task-definition-fix-required' = $true }

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

function Resolve-RepoPath {
    param(
        [string]$Path,
        [bool]$MustExist = $true
    )

    $Path = ConvertTo-PathLikeValue -Value $Path
    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw 'Path must not be empty.'
    }

        $fullPath = ''
        if ([System.IO.Path]::IsPathRooted($Path)) {
            $fullPath = [System.IO.Path]::GetFullPath($Path)
        }
        else {
            $fullPath = [System.IO.Path]::GetFullPath((Join-Path $script:RepoRoot $Path))
        }

    if ($MustExist -and -not (Test-Path -LiteralPath $fullPath)) {
        throw ("Path not found: {0}" -f $fullPath)
    }

    return $fullPath
}

function Resolve-RepoPathAllowMissing {
    param([AllowEmptyString()][string]$Path)

    $Path = ConvertTo-PathLikeValue -Value $Path
    if ([string]::IsNullOrWhiteSpace($Path)) {
        return ''
    }

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return [System.IO.Path]::GetFullPath($Path)
    }

    return [System.IO.Path]::GetFullPath((Join-Path $script:RepoRoot $Path))
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

function Convert-ToSingleLineText {
    param([AllowEmptyString()][string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return ''
    }

    $singleLine = (($Text -split "`r?`n") -join ' ')
    return ([regex]::Replace($singleLine, '\s+', ' ')).Trim()
}

function Get-EffectiveRequiresConfirmation {
    param([bool]$Requested)

    if ([bool]$script:PreauthorizedExecution) {
        return $false
    }

    return $Requested
}

function Get-AuthorizationPolicyTag {
    param([bool]$OriginalRequiresConfirmation)

    if ([bool]$script:PreauthorizedExecution) {
        if ($OriginalRequiresConfirmation) {
            return 'preauthorized-unattended-override'
        }

        return 'preauthorized-unattended'
    }

    if ($OriginalRequiresConfirmation) {
        return 'ticket-confirmation-required'
    }

    return 'ticket-direct-execute'
}

function Get-EffectiveRecommendedAction {
    param(
        [AllowEmptyString()][string]$RecommendedAction,
        [bool]$OriginalRequiresConfirmation
    )

    $normalized = Convert-ToSingleLineText -Text $RecommendedAction
    if ([bool]$script:PreauthorizedExecution -and $OriginalRequiresConfirmation) {
        return 'Preauthorized unattended action: execute business_command immediately, then continue_watch_command, then mark_processed_command and handled_receipt_command; do not ask for an extra restart approval.'
    }

    return $normalized
}

function Get-NextCommandOrder {
    param(
        [AllowEmptyString()][string]$RouteGuardCommand,
        [AllowEmptyString()][string]$BusinessCommand,
        [AllowEmptyString()][string]$ContinueWatchCommand,
        [AllowEmptyString()][string]$HandledReceiptCommand,
        [AllowEmptyString()][string]$ValidateReceiptCommand,
        [AllowEmptyString()][string]$MarkProcessedCommand,
        [AllowEmptyString()][string]$PostCheckCommand,
        [AllowEmptyString()][string]$TicketClosureCheckCommand,
        [AllowEmptyString()][string]$EventDedupHealthCheckCommand,
        [AllowEmptyString()][string]$FinalStatusCloseoutCommand,
        [AllowEmptyString()][string]$FinalStatusCloseoutApplyAckCommand
    )

    $order = New-Object 'System.Collections.Generic.List[string]'
    if (-not [string]::IsNullOrWhiteSpace($RouteGuardCommand)) { [void]$order.Add('route_guard_command') }
    if (-not [string]::IsNullOrWhiteSpace($BusinessCommand)) { [void]$order.Add('business_command') }
    if (-not [string]::IsNullOrWhiteSpace($ContinueWatchCommand)) { [void]$order.Add('continue_watch_command') }
    if (-not [string]::IsNullOrWhiteSpace($HandledReceiptCommand)) { [void]$order.Add('handled_receipt_command') }
    if (-not [string]::IsNullOrWhiteSpace($ValidateReceiptCommand)) { [void]$order.Add('validate_receipt_command') }
    if (-not [string]::IsNullOrWhiteSpace($MarkProcessedCommand)) { [void]$order.Add('mark_processed_command') }
    if (-not [string]::IsNullOrWhiteSpace($PostCheckCommand)) { [void]$order.Add('post_check_command') }
    if (-not [string]::IsNullOrWhiteSpace($TicketClosureCheckCommand)) { [void]$order.Add('ticket_closure_check_command') }
    if (-not [string]::IsNullOrWhiteSpace($EventDedupHealthCheckCommand)) { [void]$order.Add('event_dedup_health_check_command') }
    if (-not [string]::IsNullOrWhiteSpace($FinalStatusCloseoutCommand)) { [void]$order.Add('final_status_closeout_command') }
    if (-not [string]::IsNullOrWhiteSpace($FinalStatusCloseoutApplyAckCommand)) { [void]$order.Add('final_status_closeout_apply_ack_command') }

    return @($order.ToArray())
}

function Convert-ToBooleanValue {
    param(
        [object]$Value,
        [bool]$Default = $false
    )

    if ($null -eq $Value) {
        return $Default
    }

    if ($Value -is [bool]) {
        return [bool]$Value
    }

    $raw = Convert-ToSingleLineText -Text ([string]$Value)
    if ([string]::IsNullOrWhiteSpace($raw)) {
        return $Default
    }

    return $raw.Trim().ToLowerInvariant() -in @('1', 'true', 'yes', 'on')
}

function Get-NormalizedListValue {
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

function Get-MarkProcessedCommand {
    param(
        [string]$StartFileRel,
        [string]$TicketId,
        [int]$Last
    )

    $ticket = Convert-ToSingleLineText -Text $TicketId
    if ([string]::IsNullOrWhiteSpace($ticket)) {
        return ''
    }

    return ('powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/poll_agent_tickets.ps1 -StartFile "{0}" -AcknowledgeTicketIds "{1}" -Last {2} -AsJson' -f $StartFileRel, $ticket, $Last)
}

function Get-ValidateHandledReceiptCommand {
    param(
        [string]$StartFileRel,
        [string]$TicketId
    )

    $ticket = Convert-ToSingleLineText -Text $TicketId
    if ([string]::IsNullOrWhiteSpace($ticket)) {
        return ''
    }

    return ('powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/validate_ticket_handled_receipt.ps1 -StartFile "{0}" -TicketId "{1}" -AsJson' -f $StartFileRel, $ticket)
}

function Get-TicketClosureCheckCommand {
    param([string]$StartFileRel)

    if ([string]::IsNullOrWhiteSpace($StartFileRel)) {
        return ''
    }

    return ('powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/check_unattended_ticket_closure.ps1 -StartFile "{0}" -AsJson' -f $StartFileRel)
}

function Get-EventDedupHealthCheckCommand {
    param([string]$StartFileRel)

    if ([string]::IsNullOrWhiteSpace($StartFileRel)) {
        return ''
    }

    return ('powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/check_unattended_event_dedup_health.ps1 -StartFile "{0}" -AsJson' -f $StartFileRel)
}

function Get-FinalStatusCloseoutCommand {
    param(
        [string]$StartFileRel,
        [switch]$ApplyAcknowledge
    )

    if ([string]::IsNullOrWhiteSpace($StartFileRel)) {
        return ''
    }

    if ($ApplyAcknowledge.IsPresent) {
        return ('powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/check_unattended_final_status_closeout.ps1 -StartFile "{0}" -ApplyAcknowledge -AsJson' -f $StartFileRel)
    }

    return ('powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/check_unattended_final_status_closeout.ps1 -StartFile "{0}" -AsJson' -f $StartFileRel)
}

function Get-ContractGateCommand {
    param(
        [AllowEmptyString()][string]$EventName
    )

    $normalizedEvent = (Convert-ToSingleLineText -Text $EventName).ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($normalizedEvent)) {
        return ''
    }

    if (-not (Test-EventInSet -Set $script:EventSetContractGate -EventName $normalizedEvent)) {
        return ''
    }

    return ('powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/status_ticket_mini_regression.ps1')
}

$script:WriteHandledArtifacts = $false

function Get-PostExecutionCheckCommand {
    param(
        [string]$StartFileRel,
        [int]$Last
    )

    $statusCheckLast = [Math]::Max(1, [Math]::Min(50, $Last))
    return ('powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/poll_agent_tickets.ps1 -StartFile "{0}" -IncludeStatusReports -Last {1} -AsJson' -f $StartFileRel, $statusCheckLast)
}

function Get-RouteGuardCommand {
    param(
        [string]$StartFileRel,
        [AllowEmptyString()][string]$QueuePathRel,
        [AllowEmptyString()][string]$TicketId
    )

    $ticket = Convert-ToSingleLineText -Text $TicketId
    if ([string]::IsNullOrWhiteSpace($ticket)) {
        return ''
    }

    $queueValue = Convert-ToSingleLineText -Text $QueuePathRel
    if ([string]::IsNullOrWhiteSpace($queueValue)) {
        $queueValue = 'out\artifacts\ab_agent_queue\agent_tickets.jsonl'
    }

    return ('powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/check_takeover_route_guard_by_ticket.ps1 -StartFile "{0}" -QueuePath "{1}" -TicketId "{2}" -AsJson' -f $StartFileRel, $queueValue, $ticket)
}

function Get-StatusReportBusinessCommand {
    param(
        [string]$StartFileRel,
        [AllowEmptyString()][string]$QueuePathRel,
        [AllowEmptyString()][string]$TicketId,
        [int]$Last,
        [bool]$IncludeTicketChainCheck = $false,
        [bool]$IncludeMainProcessHealthCheck = $true,
        [bool]$EnableMainProcessAutoHeal = $true,
        [bool]$EnableMonitorChainDegradedEscalation = $false,
        [ValidateRange(1, 20)][int]$MonitorChainDegradedEscalationThreshold = 3,
        [bool]$LowDisturbMode = $false
    )

    $healthCommand = ''
    if ($IncludeMainProcessHealthCheck) {
        $healthScript = Resolve-RepoPathAllowMissing -Path 'tools\test\check_unattended_main_process_health.ps1'
        if (-not [string]::IsNullOrWhiteSpace($healthScript) -and (Test-Path -LiteralPath $healthScript)) {
            $healthArgs = New-Object 'System.Collections.Generic.List[string]'
            [void]$healthArgs.Add('powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/check_unattended_main_process_health.ps1')
            [void]$healthArgs.Add(('-StartFile "{0}"' -f $StartFileRel))
            if ($EnableMainProcessAutoHeal) {
                [void]$healthArgs.Add('-AutoHeal')
            }
            if ($EnableMonitorChainDegradedEscalation) {
                [void]$healthArgs.Add('-EscalateMonitorChainDegraded')
                [void]$healthArgs.Add(('-EscalateMonitorChainDegradedThreshold {0}' -f [int]$MonitorChainDegradedEscalationThreshold))
            }
            $healthCommand = (($healthArgs.ToArray()) -join ' ')
        }
    }

    if ($LowDisturbMode -and -not [string]::IsNullOrWhiteSpace($healthCommand)) {
        return $healthCommand
    }

    $watchCommand = 'powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/watch_ab_light.ps1 -StartFile "{0}" -Once -NoClear' -f $StartFileRel
    if (-not $IncludeTicketChainCheck) {
        if ([string]::IsNullOrWhiteSpace($healthCommand)) {
            return $watchCommand
        }

        return ('{0}; {1}' -f $healthCommand, $watchCommand)
    }

    $statusCheckLast = [Math]::Max(1, [Math]::Min(50, $Last))

    $queueForCheck = Convert-ToSingleLineText -Text $QueuePathRel
    if ([string]::IsNullOrWhiteSpace($queueForCheck)) {
        $queueForCheck = 'out\artifacts\ab_agent_queue\agent_tickets.jsonl'
    }

    $ticketToken = Convert-ToSingleLineText -Text $TicketId
    if ([string]::IsNullOrWhiteSpace($ticketToken)) {
        if ([string]::IsNullOrWhiteSpace($healthCommand)) {
            return $watchCommand
        }

        return ('{0}; {1}' -f $healthCommand, $watchCommand)
    }

    $chainCommand = 'powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/check_takeover_ticket_status.ps1 -StartFile "{0}" -QueuePath "{1}" -TicketId "{2}" -Last {3}' -f $StartFileRel, $queueForCheck, $ticketToken, $statusCheckLast
    $steps = New-Object 'System.Collections.Generic.List[string]'
    if (-not [string]::IsNullOrWhiteSpace($healthCommand)) {
        [void]$steps.Add($healthCommand)
    }
    [void]$steps.Add($watchCommand)
    [void]$steps.Add($chainCommand)

    return (($steps.ToArray()) -join '; ')
}

function Resolve-BusinessResumePlan {
    param(
        [string]$StartFileRel,
        [AllowEmptyString()][string]$SessionStatus,
        [AllowEmptyString()][string]$AStatus,
        [AllowEmptyString()][string]$BStatus,
        [AllowEmptyString()][string]$PreferredStage = '',
        [bool]$DisableResume = $false
    )

    $normalizedSession = Get-StatusValue -Value $SessionStatus
    $normalizedA = Get-StatusValue -Value $AStatus
    $normalizedB = Get-StatusValue -Value $BStatus
    $stageHint = (Convert-ToSingleLineText -Text $PreferredStage).ToUpperInvariant()

    if ($DisableResume) {
        return [pscustomobject]@{
            command = ''
            stage = 'none'
            reason = 'resume-disabled'
            session_status = $normalizedSession
            a_status = $normalizedA
            b_status = $normalizedB
        }
    }

    $targetStage = 'A'
    $reason = 'default-a-resume'
    if ($stageHint -eq 'B') {
        $targetStage = 'B'
        $reason = 'ticket-hint-b'
    }
    elseif ($stageHint -eq 'A') {
        $targetStage = 'A'
        $reason = 'ticket-hint-a'
    }
    elseif ($normalizedA -eq 'PASS' -and $normalizedB -in @('FAIL', 'BLOCKED', 'NOT_RUN')) {
        $targetStage = 'B'
        $reason = 'a-pass-b-pending'
    }
    elseif ($normalizedA -in @('FAIL', 'BLOCKED', 'NOT_RUN')) {
        $targetStage = 'A'
        $reason = 'a-needs-recovery'
    }

    $command = 'powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/open_unattended_ab_stage_window.ps1 -Stage {0} -StartFile "{1}" -StartMonitors' -f $targetStage, $StartFileRel

    return [pscustomobject]@{
        command = $command
        stage = $targetStage
        reason = $reason
        session_status = $normalizedSession
        a_status = $normalizedA
        b_status = $normalizedB
    }
}

function Get-TaskDefinitionFixBusinessCommand {
    param(
        [string]$StartFileRel,
        [AllowEmptyString()][string]$QueuePathRel,
        [AllowEmptyString()][string]$TicketId,
        [int]$Last
    )

    $commands = New-Object 'System.Collections.Generic.List[string]'
    $statusCheckLast = [Math]::Max(1, [Math]::Min(50, $Last))

    $queueForCheck = Convert-ToSingleLineText -Text $QueuePathRel
    if ([string]::IsNullOrWhiteSpace($queueForCheck)) {
        $queueForCheck = 'out\artifacts\ab_agent_queue\agent_tickets.jsonl'
    }

    $ticketToken = Convert-ToSingleLineText -Text $TicketId
    if (-not [string]::IsNullOrWhiteSpace($ticketToken)) {
        $chainCommand = 'powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/check_takeover_ticket_status.ps1 -StartFile "{0}" -QueuePath "{1}" -TicketId "{2}" -Last {3}' -f $StartFileRel, $queueForCheck, $ticketToken, $statusCheckLast
        [void]$commands.Add($chainCommand)
    }

    $showExitReasonCommand = 'powershell -NoProfile -ExecutionPolicy Bypass -Command "$p=''out\artifacts\ab_stage_exit\latest_b_exit.json''; if (Test-Path -LiteralPath $p) { Get-Content -LiteralPath $p -Raw -Encoding utf8 } else { Write-Output ''[TASKDEF] latest_b_exit_missing'' }"'
    [void]$commands.Add($showExitReasonCommand)

    return ($commands.ToArray() -join '; ')
}

function New-EventNameSet {
    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([hashtable])]
    param([string[]]$Values)

    if (-not $PSCmdlet.ShouldProcess('event-name-set', 'Create in-memory event name set')) {
        return @{}
    }

    $set = @{}
    foreach ($value in @($Values)) {
        $normalized = (Convert-ToSingleLineText -Text ([string]$value)).ToLowerInvariant()
        if ([string]::IsNullOrWhiteSpace($normalized)) {
            continue
        }

        $set[$normalized] = $true
    }

    return $set
}

function Add-EventSetValue {
    param(
        [hashtable]$TargetSet,
        [string[]]$Values
    )

    if ($null -eq $TargetSet) {
        return
    }

    foreach ($value in @($Values)) {
        $normalized = (Convert-ToSingleLineText -Text ([string]$value)).ToLowerInvariant()
        if ([string]::IsNullOrWhiteSpace($normalized)) {
            continue
        }

        $TargetSet[$normalized] = $true
    }
}

function Get-ConfiguredEventNameList {
    param(
        [System.Collections.IDictionary]$Settings,
        [string]$SettingKey,
        [string[]]$Fallback
    )

    $raw = ''
    if ($null -ne $Settings -and -not [string]::IsNullOrWhiteSpace($SettingKey) -and $Settings.Contains($SettingKey)) {
        $raw = [string]$Settings[$SettingKey]
    }

    if ([string]::IsNullOrWhiteSpace($raw)) {
        return @($Fallback)
    }

    $list = New-Object 'System.Collections.Generic.List[string]'
    foreach ($token in @($raw -split '[,;\r\n]+')) {
        $normalized = (Convert-ToSingleLineText -Text ([string]$token)).ToLowerInvariant()
        if ([string]::IsNullOrWhiteSpace($normalized)) {
            continue
        }

        [void]$list.Add($normalized)
    }

    if ($list.Count -eq 0) {
        return @($Fallback)
    }

    return @($list.ToArray())
}

function Test-EventInSet {
    param(
        [hashtable]$Set,
        [AllowEmptyString()][string]$EventName
    )

    if ($null -eq $Set) {
        return $false
    }

    $normalized = (Convert-ToSingleLineText -Text $EventName).ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($normalized)) {
        return $false
    }

    return $Set.ContainsKey($normalized)
}

function Initialize-EventSetIfEmpty {
    param(
        [hashtable]$TargetSet,
        [string[]]$FallbackValues,
        [System.Collections.Generic.List[string]]$Adjustments,
        [string]$AdjustmentTag
    )

    if ($null -eq $TargetSet) {
        $TargetSet = @{}
    }

    if ($TargetSet.Count -gt 0) {
        return $TargetSet
    }

    Add-EventSetValue -TargetSet $TargetSet -Values $FallbackValues
    if ($null -ne $Adjustments -and -not [string]::IsNullOrWhiteSpace($AdjustmentTag)) {
        [void]$Adjustments.Add($AdjustmentTag)
    }

    return $TargetSet
}

function Add-EventSetRequiredValue {
    param(
        [hashtable]$TargetSet,
        [string[]]$RequiredValues,
        [System.Collections.Generic.List[string]]$Adjustments,
        [string]$AdjustmentPrefix
    )

    if ($null -eq $TargetSet) {
        return
    }

    foreach ($value in @($RequiredValues)) {
        $normalized = (Convert-ToSingleLineText -Text ([string]$value)).ToLowerInvariant()
        if ([string]::IsNullOrWhiteSpace($normalized)) {
            continue
        }

        if ($TargetSet.ContainsKey($normalized)) {
            continue
        }

        $TargetSet[$normalized] = $true
        if ($null -ne $Adjustments -and -not [string]::IsNullOrWhiteSpace($AdjustmentPrefix)) {
            [void]$Adjustments.Add(('{0}:{1}' -f $AdjustmentPrefix, $normalized))
        }
    }
}

function Test-EventSetIntersect {
    param(
        [hashtable]$TargetSet,
        [string[]]$CandidateValues
    )

    if ($null -eq $TargetSet -or $TargetSet.Count -eq 0) {
        return $false
    }

    foreach ($value in @($CandidateValues)) {
        $normalized = (Convert-ToSingleLineText -Text ([string]$value)).ToLowerInvariant()
        if ([string]::IsNullOrWhiteSpace($normalized)) {
            continue
        }

        if ($TargetSet.ContainsKey($normalized)) {
            return $true
        }
    }

    return $false
}

function Get-ObjectPropertyString {
    param(
        [object]$InputObject,
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
        [object]$InputObject,
        [string]$Name,
        [bool]$Default = $false
    )

    if ($null -eq $InputObject -or [string]::IsNullOrWhiteSpace($Name)) {
        return $Default
    }

    if ($InputObject -is [System.Collections.IDictionary]) {
        if ($InputObject.Contains($Name)) {
            return (Convert-ToBooleanValue -Value $InputObject[$Name] -Default $Default)
        }
        return $Default
    }

    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $Default
    }

    return (Convert-ToBooleanValue -Value $property.Value -Default $Default)
}

function Get-StatusValue {
    param([AllowEmptyString()][string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return 'NOT_RUN'
    }

    return $Value.Trim().ToUpperInvariant()
}

function Get-SessionCloseGateState {
    param([System.Collections.IDictionary]$Settings)

    $sessionStatus = 'NOT_RUN'
    if ($null -ne $Settings -and $Settings.Contains('SESSION_FINAL_STATUS')) {
        $sessionStatus = Get-StatusValue -Value ([string]$Settings.SESSION_FINAL_STATUS)
    }

    $aStatus = 'NOT_RUN'
    if ($null -ne $Settings -and $Settings.Contains('A_FINAL_STATUS')) {
        $aStatus = Get-StatusValue -Value ([string]$Settings.A_FINAL_STATUS)
    }

    $bStatus = 'NOT_RUN'
    if ($null -ne $Settings -and $Settings.Contains('B_FINAL_STATUS')) {
        $bStatus = Get-StatusValue -Value ([string]$Settings.B_FINAL_STATUS)
    }

    $closedByFlagRaw = $false
    if ($null -ne $Settings -and $Settings.Contains('SESSION_CLOSED')) {
        $closedByFlagRaw = Convert-ToBooleanValue -Value ([string]$Settings.SESSION_CLOSED) -Default $false
    }

    $closedByPassFinal = ($sessionStatus -eq 'PASS') -or ($aStatus -eq 'PASS' -and $bStatus -eq 'PASS')
    $closedByFlag = $closedByFlagRaw -and $closedByPassFinal
    $closed = $closedByFlag -or $closedByPassFinal

    $reason = 'none'
    if ($closedByFlag) {
        $reason = 'session-closed-flag'
    }
    elseif ($closedByPassFinal) {
        $reason = 'pass-final-status'
    }

    return [pscustomobject]@{
        closed = [bool]$closed
        reason = $reason
        closed_by_flag = [bool]$closedByFlag
        closed_by_pass_final = [bool]$closedByPassFinal
        session_status = $sessionStatus
        a_status = $aStatus
        b_status = $bStatus
    }
}

function Get-NowText {
    return (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
}

function Get-PollStateMutexName {
    param(
        [string]$StartFilePath,
        [string]$QueueFilePath
    )

    $startKey = [System.IO.Path]::GetFullPath($StartFilePath).ToLowerInvariant()
    $queueKey = [System.IO.Path]::GetFullPath($QueueFilePath).ToLowerInvariant()
    $composite = "${startKey}|${queueKey}"
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($composite)
    $sha1 = [System.Security.Cryptography.SHA1]::Create()
    try {
        $hashBytes = $sha1.ComputeHash($bytes)
    }
    finally {
        $sha1.Dispose()
    }

    $hash = [System.BitConverter]::ToString($hashBytes).Replace('-', '')
    return "Global\whois-poll-state-ledger-$hash"
}

function Enter-PollStateMutex {
    param(
        [string]$StartFilePath,
        [string]$QueueFilePath
    )

    $name = Get-PollStateMutexName -StartFilePath $StartFilePath -QueueFilePath $QueueFilePath
    $mutex = New-Object System.Threading.Mutex($false, $name)
    $acquired = $false
    $waitWatch = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        try {
            $acquired = $mutex.WaitOne(0)
        }
        catch [System.Threading.AbandonedMutexException] {
            $acquired = $true
        }
        finally {
            $waitWatch.Stop()
        }

        if (-not $acquired) {
            try { $mutex.Dispose() } catch { Write-Verbose ("Suppress dispose failure: {0}" -f $_.Exception.Message) }
            return $null
        }

        return [pscustomobject]@{ Name = $name; Mutex = $mutex; WaitMs = [int]$waitWatch.ElapsedMilliseconds }
    }
    catch {
        if ($null -ne $mutex) {
            try { $mutex.Dispose() } catch { Write-Verbose ("Suppress dispose failure: {0}" -f $_.Exception.Message) }
        }
        throw
    }
}

function Write-PollLockBusyAndExit {
    param(
        [string]$StartFileRel,
        [string]$QueueFilePath,
        [string]$StateFilePath,
        [string]$LedgerFilePath,
        [string]$LockName,
        [int]$LockWaitMs,
        [bool]$AsJsonOutput
    )

    if ($AsJsonOutput) {
        $output = [ordered]@{
            schema = 'AB_AGENT_TICKET_POLL_V1'
            generated_at = (Get-NowText)
            start_file = $StartFileRel
            queue_path = (Convert-ToRepoRelativePath -Path $QueueFilePath)
            state_path = (Convert-ToRepoRelativePath -Path $StateFilePath)
            ledger_path = (Convert-ToRepoRelativePath -Path $LedgerFilePath)
            lock_busy = $true
            lock_name = $LockName
            lock_wait_ms = [int]$LockWaitMs
            rows = @()
        }
        $output | ConvertTo-Json -Depth 6
    }
    else {
        Write-Output ('[AB-TICKET-POLL] generated_at={0} start_file={1}' -f (Get-NowText), $StartFileRel)
        Write-Output ('[AB-TICKET-POLL] queue={0} state={1}' -f (Convert-ToRepoRelativePath -Path $QueueFilePath), (Convert-ToRepoRelativePath -Path $StateFilePath))
        Write-Output ('[AB-TICKET-POLL] ledger={0}' -f (Convert-ToRepoRelativePath -Path $LedgerFilePath))
        Write-Output ('[AB-TICKET-POLL] lock_busy=true lock_name={0} lock_wait_ms={1} action=skip' -f $LockName, [int]$LockWaitMs)
        Write-Output '[AB-TICKET-POLL] no_pending_rows'
    }

    exit 0
}

# If a StartFile parameter was provided, ensure its encoding is correct before
# further processing. This mirrors the behavior of tools/test/fix_startfile_encoding.ps1
# but only rewrites when required.
try {
    if ($PSBoundParameters.ContainsKey('StartFile') -and -not [string]::IsNullOrWhiteSpace($StartFile)) {
        Set-StartFileEncoding -Path $StartFile | Out-Null
    }
}
catch {
    Write-Verbose "Set-StartFileEncoding failed: $($_.Exception.Message)"
}

function Get-DateTimeOrNull {
    param([AllowEmptyString()][string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return $null
    }

    $parsed = [datetimeoffset]::MinValue
    if ([datetimeoffset]::TryParse($Text, [ref]$parsed)) {
        return $parsed.UtcDateTime
    }

    return $null
}

function Get-TicketEventMeta {
    param([AllowEmptyString()][string]$EventName)

    $normalized = (Convert-ToSingleLineText -Text $EventName).ToLowerInvariant()
    $isStatusReport = Test-EventInSet -Set $script:EventSetStatusReport -EventName $normalized
    $isDrainSafeFromSet = Test-EventInSet -Set $script:EventSetDrainSafe -EventName $normalized
    $isTerminalNotice = $isDrainSafeFromSet -and (-not $isStatusReport)
    $isBarrierExplicit = Test-EventInSet -Set $script:EventSetBarrier -EventName $normalized
    $isBarrierByPattern = (-not [string]::IsNullOrWhiteSpace($normalized)) -and ($normalized -match '(restart|resume|recovery|blocked|incident)')
    $isBarrier = $isBarrierExplicit -or $isBarrierByPattern
    $isRestartSensitiveFromSet = Test-EventInSet -Set $script:EventSetRestartSensitive -EventName $normalized
    $isRestartSensitive = $isBarrier -or $isRestartSensitiveFromSet
    $isDrainSafe = $isStatusReport -or $isDrainSafeFromSet

    return [pscustomobject]@{
        normalized_event = $normalized
        is_status_report = [bool]$isStatusReport
        is_terminal_notice = [bool]$isTerminalNotice
        is_barrier = [bool]$isBarrier
        is_restart_sensitive = [bool]$isRestartSensitive
        is_drain_safe = [bool]$isDrainSafe
    }
}

function Test-IsStatusReportEvent {
    param([AllowEmptyString()][string]$EventName)

    $eventMeta = Get-TicketEventMeta -EventName $EventName
    return [bool]$eventMeta.is_status_report
}

function Test-IsBarrierEvent {
    param([AllowEmptyString()][string]$EventName)

    $eventMeta = Get-TicketEventMeta -EventName $EventName
    return [bool]$eventMeta.is_barrier
}

function Test-IsDrainSafeEvent {
    param([AllowEmptyString()][string]$EventName)

    $eventMeta = Get-TicketEventMeta -EventName $EventName
    return [bool]$eventMeta.is_drain_safe
}

function Get-DrainMode {
    param(
        [object]$FallbackMonitoring,
        [bool]$RecoveryDrainPending
    )

    if ($RecoveryDrainPending) {
        return [pscustomobject]@{
            mode = 'recovery-drain'
            reason = 'state-recovery-drain-pending'
        }
    }

    if ($null -eq $FallbackMonitoring) {
        return [pscustomobject]@{
            mode = 'none'
            reason = 'fallback-disabled'
        }
    }

    $sessionFinal = (Convert-ToSingleLineText -Text ([string]$FallbackMonitoring.session_final_status)).ToUpperInvariant()
    if ($sessionFinal -in @('PASS', 'FAIL', 'BLOCKED')) {
        return [pscustomobject]@{
            mode = 'drain-pass'
            reason = 'session-final-status'
        }
    }

    $liveState = (Convert-ToSingleLineText -Text ([string]$FallbackMonitoring.live_status_state)).ToLowerInvariant()
    if ($liveState -in @('complete', 'completed', 'shutdown', 'stopped', 'pass', 'fail', 'blocked')) {
        return [pscustomobject]@{
            mode = 'drain-pass'
            reason = 'live-status-state'
        }
    }

    $liveEvent = (Convert-ToSingleLineText -Text ([string]$FallbackMonitoring.live_status_event)).ToLowerInvariant()
    if ($liveEvent -match '(complete|completed|shutdown|terminated|final|stage_complete|session_complete|session_final|known-infra-transient-stop)') {
        return [pscustomobject]@{
            mode = 'drain-pass'
            reason = 'live-status-event'
        }
    }

    return [pscustomobject]@{
        mode = 'none'
        reason = 'not-final'
    }
}

function Test-IsRetryDue {
    param(
        [AllowEmptyString()][string]$NextRetryAt,
        [datetime]$NowUtc = ((Get-Date).ToUniversalTime())
    )

    $retryAtUtc = Get-DateTimeOrNull -Text $NextRetryAt
    if ($null -eq $retryAtUtc) {
        return $true
    }

    return $retryAtUtc -le $NowUtc
}

function Get-NextRetryAtText {
    param(
        [int]$RetryCount,
        [datetime]$NowLocal = (Get-Date)
    )

    $delayMinutes = switch ($RetryCount) {
        { $_ -le 0 } { 5 }
        1 { 5 }
        2 { 15 }
        default { 30 }
    }

    return $NowLocal.AddMinutes($delayMinutes).ToString('yyyy-MM-dd HH:mm:ss')
}

function Get-LedgerTerminalAtUtc {
    param([object]$Record)

    foreach ($candidate in @(
            [string]$Record.done_at,
            [string]$Record.failed_at,
            [string]$Record.last_updated_at,
            [string]$Record.created_at
        )) {
        $dt = Get-DateTimeOrNull -Text $candidate
        if ($null -ne $dt) {
            return $dt
        }
    }

    return $null
}

function Add-JsonLineSafely {
    param(
        [string]$Path,
        $Value
    )

    $parent = Split-Path -Parent $Path
    if (-not [string]::IsNullOrWhiteSpace($parent) -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }

    $jsonLine = $Value | ConvertTo-Json -Depth 12 -Compress
    Add-Content -LiteralPath $Path -Value $jsonLine -Encoding utf8
}

function Invoke-LedgerCompaction {
    param(
        [hashtable]$LedgerRecords,
        [string]$RepoRoot,
        [string]$StartToken,
        [bool]$Enabled,
        [int]$CompactionDays,
        [int]$ArchiveRetentionDays
    )

    $result = [ordered]@{
        enabled = $Enabled
        archived = 0
        removed = 0
        archive_path = ''
        removed_archive_files = 0
    }

    if (-not $Enabled) {
        return [pscustomobject]$result
    }

    $nowUtc = (Get-Date).ToUniversalTime()
    $cutoffUtc = $nowUtc.AddDays(-1 * [double]$CompactionDays)
    $archiveRoot = Join-Path $RepoRoot 'out\artifacts\ab_agent_queue\archive'
    $archivePath = Join-Path $archiveRoot ("ai_ticket_ledger_archive_{0}_{1}.jsonl" -f $StartToken, (Get-Date).ToString('yyyyMMdd'))

    $terminalStatuses = @('done', 'failed', 'stale_by_restart', 'stale_status_superseded')
    foreach ($ticketId in @($LedgerRecords.Keys)) {
        $record = Convert-ToLedgerRecord -InputRecord $LedgerRecords[$ticketId] -FallbackTicketId $ticketId
        $statusName = (Convert-ToSingleLineText -Text ([string]$record.status)).ToLowerInvariant()
        if (-not ($statusName -in $terminalStatuses)) {
            continue
        }

        $terminalAtUtc = Get-LedgerTerminalAtUtc -Record $record
        if ($null -eq $terminalAtUtc -or $terminalAtUtc -gt $cutoffUtc) {
            continue
        }

        Add-JsonLineSafely -Path $archivePath -Value ([ordered]@{
                schema = 'AB_AI_TICKET_LEDGER_ARCHIVE_V1'
                archived_at = Get-NowText
                ticket = $record
            })
        $result.archived = [int]$result.archived + 1

        $LedgerRecords.Remove($ticketId) | Out-Null
        $result.removed = [int]$result.removed + 1
    }

    if ([int]$result.archived -gt 0 -and (Test-Path -LiteralPath $archivePath)) {
        $result.archive_path = Convert-ToRepoRelativePath -Path $archivePath
    }
    else {
        $result.archive_path = ''
    }

    if (Test-Path -LiteralPath $archiveRoot) {
        $archiveCutoffUtc = $nowUtc.AddDays(-1 * [double]$ArchiveRetentionDays)
        $pattern = "ai_ticket_ledger_archive_{0}_*.jsonl" -f $StartToken
        foreach ($file in @(Get-ChildItem -LiteralPath $archiveRoot -Filter $pattern -File -ErrorAction SilentlyContinue)) {
            $fileUtc = [datetime]$file.LastWriteTimeUtc
            if ($fileUtc -lt $archiveCutoffUtc) {
                Remove-Item -LiteralPath $file.FullName -Force -ErrorAction SilentlyContinue
                $result.removed_archive_files = [int]$result.removed_archive_files + 1
            }
        }
    }

    return [pscustomobject]$result
}

function Remove-RowByTicketId {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [System.Collections.Generic.List[object]]$Rows,
        [string]$TicketId
    )

    if ([string]::IsNullOrWhiteSpace($TicketId)) {
        return
    }

    if (-not $PSCmdlet.ShouldProcess($TicketId, 'Remove matching rows by ticket id from in-memory list')) {
        return
    }

    for ($index = $Rows.Count - 1; $index -ge 0; $index--) {
        $rowTicketId = Convert-ToSingleLineText -Text ([string]$Rows[$index].ticket_id)
        if ($rowTicketId -eq $TicketId) {
            $Rows.RemoveAt($index)
        }
    }
}

function Get-StaleByBarrierReason {
    param(
        [AllowEmptyString()][string]$EventName,
        [AllowEmptyString()][string]$TicketBatchId,
        [AllowEmptyString()][string]$TicketCreatedAt,
        [AllowEmptyString()][string]$TicketRestartGeneration,
        [AllowEmptyString()][string]$LastBarrierBatchId,
        [AllowEmptyString()][string]$LastBarrierAt,
        [AllowEmptyString()][string]$LastBarrierRestartGeneration
    )

    $eventMeta = Get-TicketEventMeta -EventName $EventName
    if (-not [bool]$eventMeta.is_restart_sensitive) {
        return ''
    }

    $ticketGeneration = (Convert-ToSingleLineText -Text $TicketRestartGeneration).ToLowerInvariant()
    $barrierGeneration = (Convert-ToSingleLineText -Text $LastBarrierRestartGeneration).ToLowerInvariant()
    if ((-not [string]::IsNullOrWhiteSpace($ticketGeneration)) -and
        (-not [string]::IsNullOrWhiteSpace($barrierGeneration)) -and
        ($ticketGeneration -ne $barrierGeneration)) {
        return 'barrier-generation-stale'
    }

    if ([string]::IsNullOrWhiteSpace($TicketBatchId) -or [string]::IsNullOrWhiteSpace($LastBarrierBatchId)) {
        return ''
    }

    if ($TicketBatchId -ne $LastBarrierBatchId) {
        return ''
    }

    $ticketCreatedUtc = Get-DateTimeOrNull -Text $TicketCreatedAt
    $barrierAtUtc = Get-DateTimeOrNull -Text $LastBarrierAt
    if ($null -eq $ticketCreatedUtc -or $null -eq $barrierAtUtc) {
        return ''
    }

    if ($ticketCreatedUtc -le $barrierAtUtc) {
        return 'barrier-context-stale'
    }

    return ''
}

function Get-LatestAnchorValueFromNote {
    param(
        [AllowEmptyString()][string]$Notes,
        [string]$Key
    )

    if ([string]::IsNullOrWhiteSpace($Notes) -or [string]::IsNullOrWhiteSpace($Key)) {
        return ''
    }

    $parts = @($Notes -split ';')
    for ($index = $parts.Count - 1; $index -ge 0; $index--) {
        $segment = [string]$parts[$index]
        if ([string]::IsNullOrWhiteSpace($segment)) {
            continue
        }

        if ($segment -match ('^\s*' + [regex]::Escape($Key) + '=(.+)$')) {
            return $Matches[1].Trim()
        }
    }

    return ''
}

function Resolve-AnchorPath {
    param([AllowEmptyString()][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return ''
    }

    try {
        return Resolve-RepoPath -Path $Path -MustExist $false
    }
    catch {
        return ''
    }
}

function Get-FallbackMonitoringState {
    param(
        [System.Collections.IDictionary]$Settings,
        [string]$StartFileRel,
        [bool]$DisableResume = $false
    )

        $sessionStatusRaw = ''
        if ($Settings.Contains('SESSION_FINAL_STATUS')) {
            $sessionStatusRaw = [string]$Settings.SESSION_FINAL_STATUS
        }
        $sessionStatus = Get-StatusValue -Value $sessionStatusRaw

        $aStatusRaw = ''
        if ($Settings.Contains('A_FINAL_STATUS')) {
            $aStatusRaw = [string]$Settings.A_FINAL_STATUS
        }
        $aStatus = Get-StatusValue -Value $aStatusRaw

        $bStatusRaw = ''
        if ($Settings.Contains('B_FINAL_STATUS')) {
            $bStatusRaw = [string]$Settings.B_FINAL_STATUS
        }
        $bStatus = Get-StatusValue -Value $bStatusRaw

    $notes = ''
    if ($Settings.Contains('SESSION_FINAL_NOTES')) {
        $notes = [string]$Settings.SESSION_FINAL_NOTES
    }
    $liveStatusAnchor = Get-LatestAnchorValueFromNote -Notes $notes -Key 'live_status'
    $guardLogAnchor = Get-LatestAnchorValueFromNote -Notes $notes -Key 'guard_log'

    $liveStatusPath = Resolve-AnchorPath -Path $liveStatusAnchor
    $guardLogPath = Resolve-AnchorPath -Path $guardLogAnchor

    $liveStatusRaw = Read-JsonFileSafely -Path $liveStatusPath
    $liveStatusState = ''
    $liveStatusEvent = ''
    $liveStatusErrorDetail = ''
    $blockedEvidence = ''
    if ($null -ne $liveStatusRaw) {
        $liveStatusState = (Convert-ToSingleLineText -Text ([string](Get-ObjectPropertyString -InputObject $liveStatusRaw -Name 'status'))).ToLowerInvariant()
        $liveStatusEvent = (Convert-ToSingleLineText -Text ([string](Get-ObjectPropertyString -InputObject $liveStatusRaw -Name 'event'))).ToLowerInvariant()
        $liveStatusErrorDetail = Convert-ToSingleLineText -Text ([string](Get-ObjectPropertyString -InputObject $liveStatusRaw -Name 'error_detail'))
        $blockedEvidence = Convert-ToSingleLineText -Text ([string](Get-ObjectPropertyString -InputObject $liveStatusRaw -Name 'blocked_evidence'))
    }

    $fallbackRequired = $false
    $fallbackReason = 'none'

    if ($sessionStatus -in @('FAIL', 'BLOCKED')) {
        $fallbackRequired = $true
        $fallbackReason = 'session-final-status'
    }

    if (-not $fallbackRequired -and $liveStatusState -in @('fail', 'blocked')) {
        $fallbackRequired = $true
        $fallbackReason = 'live-status-state'
    }

    if (-not $fallbackRequired -and $liveStatusEvent -in @('blocked_package', 'd1_no_progress', 'post_d1_no_progress', 'stage_process_exit_no_final')) {
        $fallbackRequired = $true
        $fallbackReason = 'live-status-event'
    }

    $blockedEvidencePath = Resolve-AnchorPath -Path $blockedEvidence
    $blockedEvidenceRel = Convert-ToRepoRelativePath -Path $blockedEvidencePath

    $watchOnceCommand = 'powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/watch_ab_light.ps1 -StartFile "{0}" -Once -NoClear' -f $StartFileRel
    $resumePlan = Resolve-BusinessResumePlan -StartFileRel $StartFileRel -SessionStatus $sessionStatus -AStatus $aStatus -BStatus $bStatus -DisableResume:$DisableResume
    $resumeCommand = [string]$resumePlan.command
    $continueWatchCommand = 'powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/open_unattended_ab_session_guard_window.ps1 -StartFile "{0}" -NoRestartIfRunning' -f $StartFileRel

    $inspectEvidenceCommand = ''
    if (-not [string]::IsNullOrWhiteSpace($blockedEvidencePath) -and (Test-Path -LiteralPath $blockedEvidencePath)) {
        $summaryPath = Join-Path $blockedEvidencePath 'summary.txt'
        if (Test-Path -LiteralPath $summaryPath) {
            $summaryRel = Convert-ToRepoRelativePath -Path $summaryPath
            $inspectEvidenceCommand = 'powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-Content -LiteralPath ''{0}''"' -f $summaryRel
        }
    }

    return [pscustomobject]@{
        required = [bool]$fallbackRequired
        reason = $fallbackReason
        session_final_status = $sessionStatus
        a_final_status = $aStatus
        b_final_status = $bStatus
        live_status_state = $liveStatusState
        live_status_event = $liveStatusEvent
        live_status_error_detail = $liveStatusErrorDetail
        live_status_path = (Convert-ToRepoRelativePath -Path $liveStatusPath)
        guard_log = (Convert-ToRepoRelativePath -Path $guardLogPath)
        blocked_evidence = $blockedEvidenceRel
        business_stage = [string]$resumePlan.stage
        business_reason = [string]$resumePlan.reason
        commands = [ordered]@{
            watch_once = $watchOnceCommand
            investigate = $inspectEvidenceCommand
            business_resume = $resumeCommand
            continue_watch = $continueWatchCommand
        }
    }
}

function Read-KeyValueFile {
    param([string]$Path)

    $keyLineMap = @{}
    $map = [ordered]@{}
    $lineNo = 0
    foreach ($line in @(Get-Content -LiteralPath $Path -Encoding utf8 -ErrorAction Stop)) {
        $lineNo++
        if ($line -match '^([^=]+)=(.*)$') {
            $key = $Matches[1].Trim()
            if ($map.Contains($key)) {
                $firstLine = [int]$keyLineMap[$key]
                throw ("Duplicate key '{0}' detected in {1} at line {2} and line {3}." -f $key, $Path, $firstLine, $lineNo)
            }

            $keyLineMap[$key] = $lineNo
            $map[$key] = $Matches[2]
        }
    }

    return $map
}

function Read-JsonFileSafely {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) {
        return $null
    }

    try {
        $raw = Get-Content -LiteralPath $Path -Raw -Encoding utf8 -ErrorAction Stop
        return ($raw | ConvertFrom-Json -ErrorAction Stop)
    }
    catch {
        return $null
    }
}

function Write-JsonFileSafely {
    param(
        [string]$Path,
        $Value
    )

    $parent = Split-Path -Parent $Path
    if (-not [string]::IsNullOrWhiteSpace($parent) -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }

    $json = ($Value | ConvertTo-Json -Depth 10)
    $normalizedJson = [string]$json -replace "`r`n", "`n"
    [System.IO.File]::WriteAllText($Path, $normalizedJson, [System.Text.UTF8Encoding]::new($false))
}

function Write-TicketHandled {
    param(
        [string]$TicketId,
        [string]$Handler = 'autonomous_agent (GPT-5 mini)',
        [string]$Action = 'skip',
        [string]$Command = '',
        [string]$Outcome = '',
        [string]$Notes = ''
    )

    if ([string]::IsNullOrWhiteSpace($TicketId)) {
        return
    }

    if (-not $script:WriteHandledArtifacts) {
        return
    }

    $handledDir = Resolve-RepoPathAllowMissing -Path 'out\artifacts\ab_agent_queue\handled_tickets'
    if (-not (Test-Path -LiteralPath $handledDir)) {
        New-Item -ItemType Directory -Path $handledDir -Force | Out-Null
    }

    $fileName = ('{0}_handled.md' -f $TicketId)
    $filePath = Join-Path $handledDir $fileName
    $handledAt = Get-NowText

    $content = @()
    $content += '---'
    $content += ('ticket_id: {0}' -f $TicketId)
    $content += ('handled_at: {0}' -f $handledAt)
    $content += ('handler: {0}' -f $Handler)
    $content += ('action: {0}' -f $Action)
    if (-not [string]::IsNullOrWhiteSpace($Command)) {
        $content += 'command: |'
        $cmdLines = ($Command -split "`n")
        foreach ($ln in $cmdLines) { $content += ('  {0}' -f $ln) }
    }
    if (-not [string]::IsNullOrWhiteSpace($Outcome)) {
        $content += 'outcome: |'
        $outLines = ($Outcome -split "`n")
        foreach ($ln in $outLines) { $content += ('  {0}' -f $ln) }
    }
    if (-not [string]::IsNullOrWhiteSpace($Notes)) {
        $content += ('notes: "{0}"' -f ($Notes -replace '"', '""'))
    }
    $content += '---'

    try {
        $normalizedLines = @($content | ForEach-Object { [string]$_ })
        $text = [string]::Join("`n", $normalizedLines)
        if ($normalizedLines.Count -gt 0) {
            $text += "`n"
        }
        [System.IO.File]::WriteAllText($filePath, $text, [System.Text.UTF8Encoding]::new($false))
    }
    catch {
        Write-Verbose ("Failed to write ticket markdown '{0}': {1}" -f $filePath, $_.Exception.Message)
    }
}

function Test-TicketEventExist {
    param(
        [string]$StartFileRel,
        [string]$TicketId,
        [string]$QueuePath = ''
    )

    if ([string]::IsNullOrWhiteSpace($TicketId)) { return $false }

    # Synthetic tickets from regression tests use a non-default queue path.
    # Bypass the event-existence check for these tickets because the synthetic
    # dispatch evidence may be cleaned up between test runs, causing false
    # negatives that skip the ticket and break regression assertions.
    $defaultAgentQueue = Resolve-RepoPathAllowMissing -Path 'out\artifacts\ab_agent_queue\agent_tickets.jsonl'
    if (-not [string]::IsNullOrWhiteSpace($QueuePath)) {
        $normalizedQueue = Resolve-RepoPathAllowMissing -Path $QueuePath
        if (-not [string]::IsNullOrWhiteSpace($normalizedQueue) -and -not [string]::IsNullOrWhiteSpace($defaultAgentQueue) -and $normalizedQueue -ne $defaultAgentQueue) {
            return $true
        }
    }

    $checkScript = Resolve-RepoPathAllowMissing -Path 'tools\test\check_takeover_ticket_status.ps1'
    if (-not (Test-Path -LiteralPath $checkScript)) {
        return $true
    }

    try {
        $invokeArgs = @{
            StartFile = $StartFileRel
            TicketId = $TicketId
            AsJson = $true
        }
        if (-not [string]::IsNullOrWhiteSpace($QueuePath)) {
            $invokeArgs['QueuePath'] = $QueuePath
        }

        $raw = & $checkScript @invokeArgs 2>$null
        if ($null -eq $raw) { return $false }
        $joined = ($raw -join "`n")
        $obj = $null
        try {
            $obj = $joined | ConvertFrom-Json -ErrorAction Stop
        }
        catch {
            Write-Verbose ("ConvertFrom-Json failed in Test-TicketEventExist: {0}" -f $_.Exception.Message)
            $obj = $null
        }
        if ($null -eq $obj) { return $true }

        if ($obj.rows -and $obj.rows.Count -gt 0) {
            $row = $obj.rows[0]
            $verdict = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $row -Name 'verdict')
            if ($verdict -eq 'NOT_FOUND' -or $verdict -eq 'QUEUED_NOT_DISPATCHED') {
                return $false
            }
        }

        return $true
    }
    catch {
        Write-Verbose ("Test-TicketEventExist fallback due to check failure: {0}" -f $_.Exception.Message)
        return $true
    }
}

function Get-IntegerSettingValue {
    param(
        [System.Collections.IDictionary]$Settings,
        [string]$Key,
        [int]$Default,
        [int]$Min,
        [int]$Max
    )

    if ($null -eq $Settings -or [string]::IsNullOrWhiteSpace($Key) -or -not $Settings.Contains($Key)) {
        return $Default
    }

    $raw = Convert-ToSingleLineText -Text ([string]$Settings[$Key])
    if ([string]::IsNullOrWhiteSpace($raw)) {
        return $Default
    }

    $parsed = 0
    if (-not [int]::TryParse($raw, [ref]$parsed)) {
        return $Default
    }

    if ($parsed -lt $Min -or $parsed -gt $Max) {
        return $Default
    }

    return $parsed
}

function Get-ChatHeartbeatPath {
    param(
        [System.Collections.IDictionary]$Settings,
        [string]$StartToken
    )

    $pathValue = ''
    if ($null -ne $Settings -and $Settings.Contains('AI_CHAT_HEARTBEAT_PATH')) {
        $pathValue = ConvertTo-PathLikeValue -Value ([string]$Settings.AI_CHAT_HEARTBEAT_PATH)
    }

    if ([string]::IsNullOrWhiteSpace($pathValue)) {
        $pathValue = Join-Path 'out\artifacts\ab_agent_queue' ("chat_session_heartbeat_{0}.json" -f $StartToken)
    }

    return Resolve-RepoPathAllowMissing -Path $pathValue
}

function Resolve-PreferredDefaultPath {
    param(
        [string]$PreferredPath,
        [string]$LegacyPath
    )

    if (-not [string]::IsNullOrWhiteSpace($LegacyPath) -and -not (Test-Path -LiteralPath $PreferredPath) -and (Test-Path -LiteralPath $LegacyPath)) {
        return $LegacyPath
    }

    return $PreferredPath
}

function Write-ChatSessionHeartbeat {
    param(
        [string]$Path,
        [string]$StartFileRel,
        [string]$QueueFilePath,
        [string]$StateFilePath,
        [string]$DrainMode,
        [string]$DrainReason
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return [pscustomobject]@{
            enabled = $false
            path = ''
            updated_at = ''
            write_ok = $false
            reason = 'path-empty'
            write_on_poll = $true
            source = 'poll_agent_tickets.ps1'
        }
    }

    $nowText = Get-NowText
    $payload = [ordered]@{
        schema = 'AB_CHAT_SESSION_HEARTBEAT_V1'
        updated_at = $nowText
        start_file = $StartFileRel
        queue_path = (Convert-ToRepoRelativePath -Path $QueueFilePath)
        state_path = (Convert-ToRepoRelativePath -Path $StateFilePath)
        source = 'poll_agent_tickets.ps1'
        pid = [int]$PID
        host = [string]$env:COMPUTERNAME
        user = [string]$env:USERNAME
        drain_mode = $DrainMode
        drain_reason = $DrainReason
    }

    try {
        Write-JsonFileSafely -Path $Path -Value $payload
        return [pscustomobject]@{
            enabled = $true
            path = (Convert-ToRepoRelativePath -Path $Path)
            updated_at = $nowText
            write_ok = $true
            reason = 'ok'
            write_on_poll = $true
            source = 'poll_agent_tickets.ps1'
        }
    }
    catch {
        return [pscustomobject]@{
            enabled = $true
            path = (Convert-ToRepoRelativePath -Path $Path)
            updated_at = $nowText
            write_ok = $false
            reason = (Convert-ToSingleLineText -Text $_.Exception.Message)
            write_on_poll = $true
            source = 'poll_agent_tickets.ps1'
        }
    }
}

function Get-ChatSessionHeartbeatInfo {
    param(
        [string]$Path,
        [bool]$WriteOnPoll
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return [pscustomobject]@{
            enabled = $true
            path = ''
            updated_at = ''
            write_ok = $false
            reason = 'path-empty'
            write_on_poll = [bool]$WriteOnPoll
            source = ''
        }
    }

    $pathRel = Convert-ToRepoRelativePath -Path $Path
    if (-not (Test-Path -LiteralPath $Path)) {
        return [pscustomobject]@{
            enabled = $true
            path = $pathRel
            updated_at = ''
            write_ok = $false
            reason = 'missing'
            write_on_poll = [bool]$WriteOnPoll
            source = ''
        }
    }

    $raw = Read-JsonFileSafely -Path $Path
    if ($null -eq $raw) {
        return [pscustomobject]@{
            enabled = $true
            path = $pathRel
            updated_at = ''
            write_ok = $false
            reason = 'invalid-json'
            write_on_poll = [bool]$WriteOnPoll
            source = ''
        }
    }

    $updatedAt = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $raw -Name 'updated_at')
    $source = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $raw -Name 'source')
    $reason = if ([string]::IsNullOrWhiteSpace($updatedAt)) { 'missing-updated-at' } else { 'ok' }
    $ok = -not [string]::IsNullOrWhiteSpace($updatedAt)

    return [pscustomobject]@{
        enabled = $true
        path = $pathRel
        updated_at = $updatedAt
        write_ok = [bool]$ok
        reason = $reason
        write_on_poll = [bool]$WriteOnPoll
        source = $source
    }
}

function New-LedgerRecord {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [string]$TicketId,
        [string]$EventName,
        [string]$Severity,
        [string]$CreatedAt,
        [string]$BatchId,
        [string]$RestartGeneration
    )

    if (-not $PSCmdlet.ShouldProcess($TicketId, 'Create in-memory ledger record')) {
        return [ordered]@{}
    }

    $nowText = Get-NowText
    return [ordered]@{
        ticket_id = $TicketId
        status = 'new'
        event = $EventName
        severity = $Severity
        created_at = $CreatedAt
        claimed_at = ''
        executed_at = ''
        watch_resumed_at = ''
        handled_at = ''
        done_at = ''
        failed_at = ''
        retry_count = 0
        next_retry_at = ''
        failure_reason = ''
        batch_id = $BatchId
        restart_generation = $RestartGeneration
        notes = ''
        status_history = @([ordered]@{ status = 'new'; at = $nowText; note = '' })
        last_updated_at = $nowText
    }
}

function Convert-ToLedgerRecord {
    param(
        [object]$InputRecord,
        [string]$FallbackTicketId
    )

    $ticketId = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $InputRecord -Name 'ticket_id')
    if ([string]::IsNullOrWhiteSpace($ticketId)) {
        $ticketId = $FallbackTicketId
    }

    $status = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $InputRecord -Name 'status')
    if ([string]::IsNullOrWhiteSpace($status)) {
        $status = 'new'
    }

    $retryCount = 0
    $retryRaw = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $InputRecord -Name 'retry_count')
    if (-not [string]::IsNullOrWhiteSpace($retryRaw)) {
        $parsedRetry = 0
        if ([int]::TryParse($retryRaw, [ref]$parsedRetry)) {
            $retryCount = $parsedRetry
        }
    }

    $historyItems = @()
    $rawHistory = $null
    if ($InputRecord -is [System.Collections.IDictionary]) {
        if ($InputRecord.Contains('status_history')) {
            $rawHistory = $InputRecord['status_history']
        }
    }
    elseif ($null -ne $InputRecord -and ($InputRecord.PSObject.Properties.Name -contains 'status_history')) {
        $rawHistory = $InputRecord.status_history
    }
    foreach ($entry in @($rawHistory)) {
        if ($null -eq $entry) {
            continue
        }

        $historyStatus = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $entry -Name 'status')
        if ([string]::IsNullOrWhiteSpace($historyStatus)) {
            continue
        }

        $historyAt = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $entry -Name 'at')
        if ([string]::IsNullOrWhiteSpace($historyAt)) {
            $historyAt = Get-NowText
        }

        $historyNote = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $entry -Name 'note')
        $historyItems += [ordered]@{
            status = $historyStatus
            at = $historyAt
            note = $historyNote
        }
    }

    if ($historyItems.Count -eq 0) {
        $historyItems = @([ordered]@{
                status = $status
                at = Get-NowText
                note = ''
            })
    }

    return [ordered]@{
        ticket_id = $ticketId
        status = $status
        event = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $InputRecord -Name 'event')
        severity = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $InputRecord -Name 'severity')
        created_at = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $InputRecord -Name 'created_at')
        claimed_at = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $InputRecord -Name 'claimed_at')
        executed_at = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $InputRecord -Name 'executed_at')
        watch_resumed_at = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $InputRecord -Name 'watch_resumed_at')
        handled_at = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $InputRecord -Name 'handled_at')
        done_at = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $InputRecord -Name 'done_at')
        failed_at = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $InputRecord -Name 'failed_at')
        retry_count = $retryCount
        next_retry_at = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $InputRecord -Name 'next_retry_at')
        failure_reason = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $InputRecord -Name 'failure_reason')
        batch_id = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $InputRecord -Name 'batch_id')
        restart_generation = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $InputRecord -Name 'restart_generation')
        notes = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $InputRecord -Name 'notes')
        status_history = @($historyItems)
        last_updated_at = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $InputRecord -Name 'last_updated_at')
    }
}

function Initialize-LedgerRecord {
    param(
        [hashtable]$LedgerRecords,
        [string]$TicketId,
        [string]$EventName,
        [string]$Severity,
        [string]$CreatedAt,
        [string]$BatchId,
        [string]$RestartGeneration
    )

    if (-not $LedgerRecords.ContainsKey($TicketId)) {
        $LedgerRecords[$TicketId] = New-LedgerRecord -TicketId $TicketId -EventName $EventName -Severity $Severity -CreatedAt $CreatedAt -BatchId $BatchId -RestartGeneration $RestartGeneration
        return
    }

    $record = Convert-ToLedgerRecord -InputRecord $LedgerRecords[$TicketId] -FallbackTicketId $TicketId
    if ([string]::IsNullOrWhiteSpace([string]$record.event)) {
        $record.event = $EventName
    }
    if ([string]::IsNullOrWhiteSpace([string]$record.severity)) {
        $record.severity = $Severity
    }
    if ([string]::IsNullOrWhiteSpace([string]$record.created_at)) {
        $record.created_at = $CreatedAt
    }
    if ([string]::IsNullOrWhiteSpace([string]$record.batch_id)) {
        $record.batch_id = $BatchId
    }
    if ([string]::IsNullOrWhiteSpace([string]$record.restart_generation)) {
        $record.restart_generation = $RestartGeneration
    }
    if ([string]::IsNullOrWhiteSpace([string]$record.last_updated_at)) {
        $record.last_updated_at = Get-NowText
    }

    $LedgerRecords[$TicketId] = $record
}

function Update-LedgerStatus {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [hashtable]$LedgerRecords,
        [string]$TicketId,
        [string]$Status,
        [string]$At,
        [AllowEmptyString()][string]$Note = ''
    )

    if (-not $PSCmdlet.ShouldProcess($TicketId, 'Update in-memory ledger status')) {
        return
    }

    if (-not $LedgerRecords.ContainsKey($TicketId)) {
        return
    }

    $record = Convert-ToLedgerRecord -InputRecord $LedgerRecords[$TicketId] -FallbackTicketId $TicketId
    if ([string]::IsNullOrWhiteSpace($At)) {
        $At = Get-NowText
    }

    if ([string]::IsNullOrWhiteSpace([string]$record.status) -or [string]$record.status -ne $Status) {
        $history = @($record.status_history)
        $history += [ordered]@{
            status = $Status
            at = $At
            note = (Convert-ToSingleLineText -Text $Note)
        }
        $record.status_history = $history
    }

    $record.status = $Status
    $record.last_updated_at = $At

    $cleanNote = Convert-ToSingleLineText -Text $Note
    if (-not [string]::IsNullOrWhiteSpace($cleanNote)) {
        if ([string]::IsNullOrWhiteSpace([string]$record.notes)) {
            $record.notes = $cleanNote
        }
        else {
            $record.notes = ([string]$record.notes + '; ' + $cleanNote)
        }
    }

    switch ($Status) {
        'claimed' {
            if ([string]::IsNullOrWhiteSpace([string]$record.claimed_at)) {
                $record.claimed_at = $At
            }
        }
        'executed' {
            if ([string]::IsNullOrWhiteSpace([string]$record.executed_at)) {
                $record.executed_at = $At
            }
        }
        'watch-resumed' {
            if ([string]::IsNullOrWhiteSpace([string]$record.watch_resumed_at)) {
                $record.watch_resumed_at = $At
            }
        }
        'done' {
            if ([string]::IsNullOrWhiteSpace([string]$record.handled_at)) {
                $record.handled_at = $At
            }
            if ([string]::IsNullOrWhiteSpace([string]$record.done_at)) {
                $record.done_at = $At
            }
        }
        'stale_status_superseded' {
            if ([string]::IsNullOrWhiteSpace([string]$record.handled_at)) {
                $record.handled_at = $At
            }
            if ([string]::IsNullOrWhiteSpace([string]$record.done_at)) {
                $record.done_at = $At
            }
        }
        'failed' {
            if ([string]::IsNullOrWhiteSpace([string]$record.handled_at)) {
                $record.handled_at = $At
            }
            if ([string]::IsNullOrWhiteSpace([string]$record.failed_at)) {
                $record.failed_at = $At
            }
        }
    }

    $LedgerRecords[$TicketId] = $record
}

function Set-LedgerDeferred {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [hashtable]$LedgerRecords,
        [string]$TicketId,
        [string]$NowAt,
        [AllowEmptyString()][string]$Reason = ''
    )

    if (-not $PSCmdlet.ShouldProcess($TicketId, 'Mark in-memory ledger record as deferred')) {
        return
    }

    if (-not $LedgerRecords.ContainsKey($TicketId)) {
        return
    }

    if ([string]::IsNullOrWhiteSpace($NowAt)) {
        $NowAt = Get-NowText
    }

    Update-LedgerStatus -LedgerRecords $LedgerRecords -TicketId $TicketId -Status 'deferred' -At $NowAt -Note $Reason
    $record = Convert-ToLedgerRecord -InputRecord $LedgerRecords[$TicketId] -FallbackTicketId $TicketId
    $record.retry_count = [int]$record.retry_count + 1
    $record.next_retry_at = Get-NextRetryAtText -RetryCount ([int]$record.retry_count) -NowLocal (Get-Date)
    $LedgerRecords[$TicketId] = $record
}

function Clear-LedgerRetrySchedule {
    param(
        [hashtable]$LedgerRecords,
        [string]$TicketId
    )

    if (-not $LedgerRecords.ContainsKey($TicketId)) {
        return
    }

    $record = Convert-ToLedgerRecord -InputRecord $LedgerRecords[$TicketId] -FallbackTicketId $TicketId
    $record.next_retry_at = ''
    $LedgerRecords[$TicketId] = $record
}

function Get-LedgerStatusCount {
    param([hashtable]$LedgerRecords)

    $counts = [ordered]@{}
    foreach ($ticketId in $LedgerRecords.Keys) {
        $record = $LedgerRecords[$ticketId]
        $statusName = Convert-ToSingleLineText -Text ([string]$record.status)
        if ([string]::IsNullOrWhiteSpace($statusName)) {
            $statusName = 'unknown'
        }

        if (-not $counts.Contains($statusName)) {
            $counts[$statusName] = 0
        }
        $counts[$statusName] = [int]$counts[$statusName] + 1
    }

    return $counts
}

function Get-TicketsFromQueue {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) {
        return @()
    }

    $tickets = New-Object 'System.Collections.Generic.List[object]'
    foreach ($line in @(Get-Content -LiteralPath $Path -Encoding utf8 -ErrorAction SilentlyContinue)) {
        $jsonLine = Convert-ToSingleLineText -Text ([string]$line)
        if ([string]::IsNullOrWhiteSpace($jsonLine)) {
            continue
        }

        try {
            $ticket = $jsonLine | ConvertFrom-Json -ErrorAction Stop
            [void]$tickets.Add($ticket)
        }
        catch {
            continue
        }
    }

    return $tickets.ToArray()
}

$script:RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$startFilePath = Resolve-RepoPath -Path $StartFile -MustExist $true
$startFileRel = Convert-ToRepoRelativePath -Path $startFilePath
$startToken = Get-StableStartFileToken -StartFilePath $startFilePath
$legacyStartToken = Get-LegacyStartFileToken -StartFilePath $startFilePath
$settings = Read-KeyValueFile -Path $startFilePath
$script:PreauthorizedExecution = $true
if ($settings.Contains('LOCAL_GUARD_POLL_PREAUTHORIZED_EXECUTION')) {
    $script:PreauthorizedExecution = Convert-ToBooleanValue -Value ([string]$settings.LOCAL_GUARD_POLL_PREAUTHORIZED_EXECUTION) -Default $true
}

$defaultStatusReportEvents = @('running-status-report')
$defaultDrainSafeEvents = @('running-status-report', 'manual-wait-paused', 'budget-exhausted-stop', 'known-infra-transient-stop')
$defaultBarrierEvents = @('incident-captured', 'recovery-await-confirmation', 'auto-fix-await-confirmation', 'task-definition-fix-required', 'main-process-exit-review', 'manual-wait-paused', 'budget-exhausted-stop', 'known-infra-transient-stop')
$defaultRestartSensitiveEvents = @('incident-captured', 'recovery-await-confirmation', 'auto-fix-await-confirmation', 'task-definition-fix-required', 'main-process-exit-review')
$defaultContractGateEvents = @('task-definition-fix-required')
$coreRestartSensitiveEvents = @('incident-captured', 'recovery-await-confirmation', 'auto-fix-await-confirmation', 'task-definition-fix-required', 'main-process-exit-review')
$eventPolicyAdjustments = New-Object 'System.Collections.Generic.List[string]'
$eventPolicyStrictModeValue = $EventPolicyStrict
if ($null -eq $eventPolicyStrictModeValue -and $settings.Contains('LOCAL_GUARD_POLL_EVENT_POLICY_STRICT')) {
    $eventPolicyStrictModeValue = [string]$settings.LOCAL_GUARD_POLL_EVENT_POLICY_STRICT
}
$eventPolicyStrictModeFlag = Convert-ToBooleanValue -Value $eventPolicyStrictModeValue -Default $false

$script:EventSetStatusReport = New-EventNameSet -Values (Get-ConfiguredEventNameList -Settings $settings -SettingKey 'LOCAL_GUARD_POLL_STATUS_REPORT_EVENTS' -Fallback $defaultStatusReportEvents)
$script:EventSetStatusReport = Initialize-EventSetIfEmpty -TargetSet $script:EventSetStatusReport -FallbackValues $defaultStatusReportEvents -Adjustments $eventPolicyAdjustments -AdjustmentTag 'status-report:fallback-defaults'
Add-EventSetRequiredValue -TargetSet $script:EventSetStatusReport -RequiredValues @('running-status-report') -Adjustments $eventPolicyAdjustments -AdjustmentPrefix 'status-report:add-required-event'

$script:EventSetDrainSafe = New-EventNameSet -Values (Get-ConfiguredEventNameList -Settings $settings -SettingKey 'LOCAL_GUARD_POLL_DRAIN_SAFE_EVENTS' -Fallback $defaultDrainSafeEvents)
$script:EventSetDrainSafe = Initialize-EventSetIfEmpty -TargetSet $script:EventSetDrainSafe -FallbackValues $defaultDrainSafeEvents -Adjustments $eventPolicyAdjustments -AdjustmentTag 'drain-safe:fallback-defaults'
Add-EventSetRequiredValue -TargetSet $script:EventSetDrainSafe -RequiredValues @($script:EventSetStatusReport.Keys) -Adjustments $eventPolicyAdjustments -AdjustmentPrefix 'drain-safe:add-status-report-event'

$script:EventSetBarrier = New-EventNameSet -Values (Get-ConfiguredEventNameList -Settings $settings -SettingKey 'LOCAL_GUARD_POLL_BARRIER_EVENTS' -Fallback $defaultBarrierEvents)
$script:EventSetBarrier = Initialize-EventSetIfEmpty -TargetSet $script:EventSetBarrier -FallbackValues $defaultBarrierEvents -Adjustments $eventPolicyAdjustments -AdjustmentTag 'barrier:fallback-defaults'
if (-not (Test-EventSetIntersect -TargetSet $script:EventSetBarrier -CandidateValues $coreRestartSensitiveEvents)) {
    Add-EventSetRequiredValue -TargetSet $script:EventSetBarrier -RequiredValues $coreRestartSensitiveEvents -Adjustments $eventPolicyAdjustments -AdjustmentPrefix 'barrier:add-core-restart-event'
}

$script:EventSetRestartSensitive = New-EventNameSet -Values (Get-ConfiguredEventNameList -Settings $settings -SettingKey 'LOCAL_GUARD_POLL_RESTART_SENSITIVE_EVENTS' -Fallback $defaultRestartSensitiveEvents)
$script:EventSetRestartSensitive = Initialize-EventSetIfEmpty -TargetSet $script:EventSetRestartSensitive -FallbackValues $defaultRestartSensitiveEvents -Adjustments $eventPolicyAdjustments -AdjustmentTag 'restart-sensitive:fallback-defaults'
if (-not (Test-EventSetIntersect -TargetSet $script:EventSetRestartSensitive -CandidateValues $coreRestartSensitiveEvents)) {
    Add-EventSetRequiredValue -TargetSet $script:EventSetRestartSensitive -RequiredValues $coreRestartSensitiveEvents -Adjustments $eventPolicyAdjustments -AdjustmentPrefix 'restart-sensitive:add-core-restart-event'
}

$script:EventSetContractGate = New-EventNameSet -Values (Get-ConfiguredEventNameList -Settings $settings -SettingKey 'LOCAL_GUARD_POLL_CONTRACT_GATE_EVENTS' -Fallback $defaultContractGateEvents)
$script:EventSetContractGate = Initialize-EventSetIfEmpty -TargetSet $script:EventSetContractGate -FallbackValues $defaultContractGateEvents -Adjustments $eventPolicyAdjustments -AdjustmentTag 'contract-gate:fallback-defaults'
Add-EventSetRequiredValue -TargetSet $script:EventSetContractGate -RequiredValues @('task-definition-fix-required') -Adjustments $eventPolicyAdjustments -AdjustmentPrefix 'contract-gate:add-required-event'

# Keep task-definition repair lane enabled for backward-compatible strict policies.
if (-not $script:EventSetBarrier.ContainsKey('task-definition-fix-required')) {
    $script:EventSetBarrier['task-definition-fix-required'] = $true
}
if (-not $script:EventSetRestartSensitive.ContainsKey('task-definition-fix-required')) {
    $script:EventSetRestartSensitive['task-definition-fix-required'] = $true
}

if ($eventPolicyStrictModeFlag -and $eventPolicyAdjustments.Count -gt 0) {
    $adjustmentText = ($eventPolicyAdjustments.ToArray() -join ',')
    throw ('Event policy strict mode violation: normalization is required ({0}). Please fix LOCAL_GUARD_POLL_* settings in start file.' -f $adjustmentText)
}

$markProcessedFlag = Convert-ToBooleanValue -Value $MarkProcessed -Default $false
$enableFallbackStatusFlag = Convert-ToBooleanValue -Value $EnableFallbackStatus -Default $true
$enableLedgerCompactionFlag = Convert-ToBooleanValue -Value $EnableLedgerCompaction -Default $false
$eventQueueSkipExistingOnStart = $true
if ($settings.Contains('AI_CHAT_TRIGGER_SKIP_EXISTING_QUEUE_ON_START')) {
    $eventQueueSkipExistingOnStart = Convert-ToBooleanValue -Value ([string]$settings.AI_CHAT_TRIGGER_SKIP_EXISTING_QUEUE_ON_START) -Default $true
}
$statusReportIncludeTicketChainCheck = $false
if ($settings.Contains('LOCAL_GUARD_POLL_STATUS_REPORT_INCLUDE_TICKET_CHAIN_CHECK')) {
    $statusReportIncludeTicketChainCheck = Convert-ToBooleanValue -Value ([string]$settings.LOCAL_GUARD_POLL_STATUS_REPORT_INCLUDE_TICKET_CHAIN_CHECK) -Default $false
}
$statusReportIncludeMainProcessHealthCheck = $true
if ($settings.Contains('LOCAL_GUARD_POLL_STATUS_REPORT_INCLUDE_MAIN_PROCESS_HEALTH_CHECK')) {
    $statusReportIncludeMainProcessHealthCheck = Convert-ToBooleanValue -Value ([string]$settings.LOCAL_GUARD_POLL_STATUS_REPORT_INCLUDE_MAIN_PROCESS_HEALTH_CHECK) -Default $true
}
$statusReportEnableMainProcessAutoHeal = $true
if ($settings.Contains('LOCAL_GUARD_POLL_STATUS_REPORT_ENABLE_MAIN_PROCESS_SELF_HEAL')) {
    $statusReportEnableMainProcessAutoHeal = Convert-ToBooleanValue -Value ([string]$settings.LOCAL_GUARD_POLL_STATUS_REPORT_ENABLE_MAIN_PROCESS_SELF_HEAL) -Default $true
}

$statusReportEnableMonitorChainDegradedEscalation = $false
if ($settings.Contains('LOCAL_GUARD_POLL_STATUS_REPORT_ENABLE_MONITOR_CHAIN_DEGRADED_ESCALATION')) {
    $statusReportEnableMonitorChainDegradedEscalation = Convert-ToBooleanValue -Value ([string]$settings.LOCAL_GUARD_POLL_STATUS_REPORT_ENABLE_MONITOR_CHAIN_DEGRADED_ESCALATION) -Default $false
}

$statusReportMonitorChainDegradedEscalationThreshold = 3
if ($settings.Contains('LOCAL_GUARD_POLL_STATUS_REPORT_MONITOR_CHAIN_DEGRADED_ESCALATION_THRESHOLD')) {
    $rawThreshold = Convert-ToSingleLineText -Text ([string]$settings.LOCAL_GUARD_POLL_STATUS_REPORT_MONITOR_CHAIN_DEGRADED_ESCALATION_THRESHOLD)
    $parsedThreshold = 0
    if ([int]::TryParse($rawThreshold, [ref]$parsedThreshold)) {
        $statusReportMonitorChainDegradedEscalationThreshold = [Math]::Max(1, [Math]::Min(20, $parsedThreshold))
    }
}

$script:WriteHandledArtifacts = $false
if ($settings.Contains('LOCAL_GUARD_WRITE_HANDLED_ARTIFACTS')) {
    $script:WriteHandledArtifacts = Convert-ToBooleanValue -Value ([string]$settings.LOCAL_GUARD_WRITE_HANDLED_ARTIFACTS) -Default $false
}
$sessionCloseGate = Get-SessionCloseGateState -Settings $settings

$fallbackMonitoring = $null
if ($enableFallbackStatusFlag) {
    $fallbackMonitoring = Get-FallbackMonitoringState -Settings $settings -StartFileRel $startFileRel -DisableResume ([bool]$sessionCloseGate.closed)
}

$queuePathValue = $QueuePath
if ([string]::IsNullOrWhiteSpace($queuePathValue) -and $settings.Contains('LOCAL_GUARD_AGENT_QUEUE_PATH')) {
    $queuePathValue = ConvertTo-PathLikeValue -Value ([string]$settings.LOCAL_GUARD_AGENT_QUEUE_PATH)
}
if ([string]::IsNullOrWhiteSpace($queuePathValue)) {
    $queuePathValue = 'out\artifacts\ab_agent_queue\agent_tickets.jsonl'
}
$queueFilePath = Resolve-RepoPathAllowMissing -Path $queuePathValue

$statePathValue = $StatePath
if ([string]::IsNullOrWhiteSpace($statePathValue)) {
    $statePathValue = Resolve-PreferredDefaultPath -PreferredPath (Resolve-RepoPathAllowMissing -Path (Join-Path 'out\artifacts\ab_agent_queue' ("ai_ticket_poll_state_{0}.json" -f $startToken))) -LegacyPath (Resolve-RepoPathAllowMissing -Path (Join-Path 'out\artifacts\ab_agent_queue' ("ai_ticket_poll_state_{0}.json" -f $legacyStartToken)))
}
$stateFilePath = Resolve-RepoPathAllowMissing -Path $statePathValue

$ledgerPathValue = $LedgerPath
if ([string]::IsNullOrWhiteSpace($ledgerPathValue)) {
    $ledgerPathValue = Resolve-PreferredDefaultPath -PreferredPath (Resolve-RepoPathAllowMissing -Path (Join-Path 'out\artifacts\ab_agent_queue' ("ai_ticket_ledger_{0}.json" -f $startToken))) -LegacyPath (Resolve-RepoPathAllowMissing -Path (Join-Path 'out\artifacts\ab_agent_queue' ("ai_ticket_ledger_{0}.json" -f $legacyStartToken)))
}
$ledgerFilePath = Resolve-RepoPathAllowMissing -Path $ledgerPathValue

$pollMutexContext = Enter-PollStateMutex -StartFilePath $startFilePath -QueueFilePath $queueFilePath
if ($null -eq $pollMutexContext) {
    Write-PollLockBusyAndExit -StartFileRel $startFileRel -QueueFilePath $queueFilePath -StateFilePath $stateFilePath -LedgerFilePath $ledgerFilePath -LockName (Get-PollStateMutexName -StartFilePath $startFilePath -QueueFilePath $queueFilePath) -LockWaitMs 0 -AsJsonOutput:$AsJson.IsPresent
}

try {

$chatHeartbeatEnabled = $true
if ($settings.Contains('AI_CHAT_HEARTBEAT_ENABLED')) {
    $chatHeartbeatEnabled = Convert-ToBooleanValue -Value ([string]$settings.AI_CHAT_HEARTBEAT_ENABLED) -Default $true
}

$chatHeartbeatWriteOnPoll = $false
if ($settings.Contains('AI_CHAT_HEARTBEAT_WRITE_ON_POLL')) {
    $chatHeartbeatWriteOnPoll = Convert-ToBooleanValue -Value ([string]$settings.AI_CHAT_HEARTBEAT_WRITE_ON_POLL) -Default $false
}

$chatPolicyWorkMode = ''
if ($settings.Contains('AI_CHAT_POLICY_WORK_MODE')) {
    $chatPolicyWorkMode = (Convert-ToSingleLineText -Text ([string]$settings.AI_CHAT_POLICY_WORK_MODE)).ToLowerInvariant()
}
$statusReportLowDisturbMode = ($chatPolicyWorkMode -eq 'low-disturb')
if ($statusReportLowDisturbMode) {
    # In low-disturb mode, keep health checks and bounded self-heal, but reduce verbose chain checks.
    $statusReportEnableMainProcessAutoHeal = $true
    $statusReportIncludeTicketChainCheck = $false
    $statusReportIncludeMainProcessHealthCheck = $true

    if (-not $settings.Contains('LOCAL_GUARD_POLL_STATUS_REPORT_ENABLE_MONITOR_CHAIN_DEGRADED_ESCALATION')) {
        $statusReportEnableMonitorChainDegradedEscalation = $true
    }
}

$chatHeartbeatPath = ''
if ($chatHeartbeatEnabled) {
    if ($settings.Contains('AI_CHAT_HEARTBEAT_PATH') -and -not [string]::IsNullOrWhiteSpace((ConvertTo-PathLikeValue -Value ([string]$settings.AI_CHAT_HEARTBEAT_PATH)))) {
        $chatHeartbeatPath = Get-ChatHeartbeatPath -Settings $settings -StartToken $startToken
    }
    else {
        $chatHeartbeatPath = Resolve-PreferredDefaultPath -PreferredPath (Get-ChatHeartbeatPath -Settings $settings -StartToken $startToken) -LegacyPath (Get-ChatHeartbeatPath -Settings $settings -StartToken $legacyStartToken)
    }
}

$stateRaw = Read-JsonFileSafely -Path $stateFilePath
$processedIds = New-Object 'System.Collections.Generic.List[string]'
$processedSet = @{}
$recoveryDrainPending = $false
$lastDrainAt = ''
$lastRecoveryDrainAt = ''
$eventQueueFloorAt = ''
$eventQueueFloorSource = ''
if ($null -ne $stateRaw -and $stateRaw.PSObject.Properties.Name -contains 'processed_ids') {
    foreach ($id in @($stateRaw.processed_ids)) {
        $ticketId = Convert-ToSingleLineText -Text ([string]$id)
        if ([string]::IsNullOrWhiteSpace($ticketId)) {
            continue
        }

        if (-not $processedSet.Contains($ticketId)) {
            $processedSet[$ticketId] = $true
            [void]$processedIds.Add($ticketId)
        }
    }
}
if ($null -ne $stateRaw) {
    $recoveryDrainPending = Convert-ToBooleanValue -Value (Get-ObjectPropertyString -InputObject $stateRaw -Name 'recovery_drain_pending') -Default $false
    $lastDrainAt = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $stateRaw -Name 'last_drain_at')
    $lastRecoveryDrainAt = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $stateRaw -Name 'last_recovery_drain_at')
    $eventQueueFloorAt = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $stateRaw -Name 'event_queue_floor_at')
    $eventQueueFloorSource = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $stateRaw -Name 'event_queue_floor_source')
}

if ([string]::IsNullOrWhiteSpace($eventQueueFloorAt) -and $eventQueueSkipExistingOnStart) {
    $eventQueueFloorAt = Get-NowText
    $eventQueueFloorSource = 'poll-initialized'
}
elseif (-not $eventQueueSkipExistingOnStart) {
    $eventQueueFloorAt = ''
    $eventQueueFloorSource = 'skip-existing-disabled'
}
elseif ([string]::IsNullOrWhiteSpace($eventQueueFloorSource) -and -not [string]::IsNullOrWhiteSpace($eventQueueFloorAt)) {
    $eventQueueFloorSource = 'state'
}

$eventQueueFloorUtc = Get-DateTimeOrNull -Text $eventQueueFloorAt

$drainModeInfo = Get-DrainMode -FallbackMonitoring $fallbackMonitoring -RecoveryDrainPending $recoveryDrainPending
$drainMode = Convert-ToSingleLineText -Text ([string]$drainModeInfo.mode)
$drainReason = Convert-ToSingleLineText -Text ([string]$drainModeInfo.reason)
$isDrainMode = $drainMode -in @('drain-pass', 'recovery-drain')

$chatHeartbeatInfo = if ($chatHeartbeatEnabled) {
    if ($chatHeartbeatWriteOnPoll) {
        Write-ChatSessionHeartbeat -Path $chatHeartbeatPath -StartFileRel $startFileRel -QueueFilePath $queueFilePath -StateFilePath $stateFilePath -DrainMode $drainMode -DrainReason $drainReason
    }
    else {
        Get-ChatSessionHeartbeatInfo -Path $chatHeartbeatPath -WriteOnPoll $false
    }
}
else {
    [pscustomobject]@{
        enabled = $false
        path = ''
        updated_at = ''
        write_ok = $false
        reason = 'disabled'
        write_on_poll = $false
        source = ''
    }
}

$ledgerRaw = Read-JsonFileSafely -Path $ledgerFilePath
$ledgerRecords = @{}
$lastBarrierTicketId = ''
$lastBarrierAt = ''
$lastBarrierBatchId = ''
$lastBarrierRestartGeneration = ''
if ($null -ne $ledgerRaw -and $ledgerRaw.PSObject.Properties.Name -contains 'records') {
    foreach ($entry in @($ledgerRaw.records)) {
        $ticketId = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $entry -Name 'ticket_id')
        if ([string]::IsNullOrWhiteSpace($ticketId)) {
            continue
        }

        $ledgerRecords[$ticketId] = Convert-ToLedgerRecord -InputRecord $entry -FallbackTicketId $ticketId
    }
}
if ($null -ne $ledgerRaw) {
    $lastBarrierTicketId = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $ledgerRaw -Name 'last_barrier_ticket_id')
    $lastBarrierAt = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $ledgerRaw -Name 'last_barrier_at')
    $lastBarrierBatchId = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $ledgerRaw -Name 'last_barrier_batch_id')
    $lastBarrierRestartGeneration = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $ledgerRaw -Name 'last_barrier_restart_generation')
}

$acknowledgeTicketSet = @{}
foreach ($ticketId in @(Get-NormalizedListValue -Value $AcknowledgeTicketIds)) {
    if (-not $acknowledgeTicketSet.Contains($ticketId)) {
        $acknowledgeTicketSet[$ticketId] = $true
    }
}

$acknowledgedThisPoll = 0
$doneThisPoll = 0
$handledReceipts = New-Object 'System.Collections.Generic.List[object]'
if ($acknowledgeTicketSet.Count -gt 0) {
    foreach ($ticketId in @($acknowledgeTicketSet.Keys)) {
        if (-not $ledgerRecords.ContainsKey($ticketId)) {
            continue
        }

        $record = Convert-ToLedgerRecord -InputRecord $ledgerRecords[$ticketId] -FallbackTicketId $ticketId
        $statusName = Convert-ToSingleLineText -Text ([string]$record.status)
        if ($statusName -in @('done', 'failed', 'stale_by_restart', 'stale_status_superseded')) {
            continue
        }

        $ackAt = Get-NowText
        Update-LedgerStatus -LedgerRecords $ledgerRecords -TicketId $ticketId -Status 'executed' -At $ackAt -Note 'acknowledged-by-consumer'
        Update-LedgerStatus -LedgerRecords $ledgerRecords -TicketId $ticketId -Status 'watch-resumed' -At $ackAt -Note 'acknowledged-by-consumer'
        Update-LedgerStatus -LedgerRecords $ledgerRecords -TicketId $ticketId -Status 'done' -At $ackAt -Note 'acknowledged-by-consumer'
        Clear-LedgerRetrySchedule -LedgerRecords $ledgerRecords -TicketId $ticketId
        Write-TicketHandled -TicketId $ticketId -Action 'acknowledge' -Outcome 'acknowledged-by-consumer' -Command ('poll_agent_tickets.ps1 -AcknowledgeTicketIds "{0}"' -f $ticketId) -Notes ('ticket acknowledged and closed at {0}' -f $ackAt)
        [void]$handledReceipts.Add([ordered]@{ ticket_id = $ticketId; handled_at = $ackAt; action = 'acknowledge'; outcome = 'acknowledged-by-consumer' })

        if (Test-IsBarrierEvent -EventName ([string]$record.event)) {
            $barrierRecord = Convert-ToLedgerRecord -InputRecord $ledgerRecords[$ticketId] -FallbackTicketId $ticketId
            $lastBarrierTicketId = $ticketId
            $lastBarrierAt = $ackAt
            $lastBarrierBatchId = Convert-ToSingleLineText -Text ([string]$barrierRecord.batch_id)
            $lastBarrierRestartGeneration = Convert-ToSingleLineText -Text ([string]$barrierRecord.restart_generation)
        }

        if (-not $processedSet.Contains($ticketId)) {
            $processedSet[$ticketId] = $true
            [void]$processedIds.Add($ticketId)
        }

        $acknowledgedThisPoll++
        $doneThisPoll++
    }

    if ($MaxProcessedIds -gt 0) {
        while ($processedIds.Count -gt $MaxProcessedIds) {
            $oldId = [string]$processedIds[0]
            $processedIds.RemoveAt(0)
            if ($processedSet.Contains($oldId)) {
                $processedSet.Remove($oldId) | Out-Null
            }
        }
    }
}

$continueWatchCommand = 'powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/open_unattended_ab_session_guard_window.ps1 -StartFile "{0}" -NoRestartIfRunning' -f $startFileRel

$tickets = @(Get-TicketsFromQueue -Path $queueFilePath)
$rows = New-Object 'System.Collections.Generic.List[object]'
$claimedIds = New-Object 'System.Collections.Generic.List[string]'
$skippedStatusReports = 0
$deferredThisPoll = 0
$staleByRestartThisPoll = 0
$statusSupersededThisPoll = 0
$selectedActionTicketId = ''
$selectedBarrierTicketId = ''
$latestStatusTicketId = ''
$eventDrivenTicketSelected = $false
$selectedEventTicketIds = New-Object 'System.Collections.Generic.List[string]'

foreach ($ticket in $tickets) {
    $ticketId = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $ticket -Name 'ticket_id')
    if ([string]::IsNullOrWhiteSpace($ticketId)) {
        continue
    }

    $eventName = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $ticket -Name 'event')
    $createdAt = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $ticket -Name 'created_at')
    $severity = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $ticket -Name 'severity')
    $batchId = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $ticket -Name 'batch_id')
    if ([string]::IsNullOrWhiteSpace($batchId)) {
        $batchId = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $ticket -Name 'dedup_suffix')
    }
    $restartGeneration = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $ticket -Name 'restart_generation')

    $ticketSessionStatusRaw = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $ticket -Name 'session_final_status')
    if ([string]::IsNullOrWhiteSpace($ticketSessionStatusRaw)) {
        $ticketSessionStatusRaw = [string]$sessionCloseGate.session_status
    }

    $ticketAStatusRaw = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $ticket -Name 'a_final_status')
    if ([string]::IsNullOrWhiteSpace($ticketAStatusRaw)) {
        $ticketAStatusRaw = [string]$sessionCloseGate.a_status
    }

    $ticketBStatusRaw = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $ticket -Name 'b_final_status')
    if ([string]::IsNullOrWhiteSpace($ticketBStatusRaw)) {
        $ticketBStatusRaw = [string]$sessionCloseGate.b_status
    }

    $ticketPreferredStage = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $ticket -Name 'preferred_stage')
    if ([string]::IsNullOrWhiteSpace($ticketPreferredStage) -and $eventName -eq 'task-definition-fix-required') {
        $ticketPreferredStage = 'B'
    }

    $ticketMainRound = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $ticket -Name 'main_round')
    $ticketFailureKind = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $ticket -Name 'failure_kind')
    $ticketFailureCategory = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $ticket -Name 'failure_category')
    $ticketFailureSource = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $ticket -Name 'failure_source')
    $ticketFailureEvidence = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $ticket -Name 'failure_evidence')
    $ticketSelfHealable = Get-ObjectPropertyBoolean -InputObject $ticket -Name 'self_healable' -Default $false
    $ticketNonRecoverableEnv = Get-ObjectPropertyBoolean -InputObject $ticket -Name 'non_recoverable_env' -Default $false

    $ticketResumePlan = Resolve-BusinessResumePlan -StartFileRel $startFileRel -SessionStatus $ticketSessionStatusRaw -AStatus $ticketAStatusRaw -BStatus $ticketBStatusRaw -PreferredStage $ticketPreferredStage -DisableResume:([bool]$sessionCloseGate.closed)

    $eventMeta = Get-TicketEventMeta -EventName $eventName
    $isStatusReport = [bool]$eventMeta.is_status_report
    $isDrainSafeEvent = [bool]$eventMeta.is_drain_safe

    Initialize-LedgerRecord -LedgerRecords $ledgerRecords -TicketId $ticketId -EventName $eventName -Severity $severity -CreatedAt $createdAt -BatchId $batchId -RestartGeneration $restartGeneration
    $ledgerRecord = $ledgerRecords[$ticketId]
    $currentStatus = Convert-ToSingleLineText -Text ([string]$ledgerRecord.status)

    if ($processedSet.Contains($ticketId)) {
        if ([string]$ledgerRecord.status -ne 'done') {
            Update-LedgerStatus -LedgerRecords $ledgerRecords -TicketId $ticketId -Status 'done' -At (Get-NowText) -Note 'legacy-processed-id-skip'
            Clear-LedgerRetrySchedule -LedgerRecords $ledgerRecords -TicketId $ticketId
            Write-TicketHandled -TicketId $ticketId -Action 'skip' -Outcome 'legacy-processed-id-skip' -Notes 'Skipped: already recorded in processed_ids by previous poll run.'
        }
        continue
    }

    if ($currentStatus -in @('done', 'failed', 'stale_by_restart', 'stale_status_superseded')) {
        continue
    }

    if (-not $isStatusReport -and $null -ne $eventQueueFloorUtc) {
        $ticketCreatedUtc = Get-DateTimeOrNull -Text $createdAt
        if ($null -ne $ticketCreatedUtc -and $ticketCreatedUtc -lt $eventQueueFloorUtc) {
            $skipAt = Get-NowText
            Update-LedgerStatus -LedgerRecords $ledgerRecords -TicketId $ticketId -Status 'done' -At $skipAt -Note 'pre_session_event_skipped'
            Clear-LedgerRetrySchedule -LedgerRecords $ledgerRecords -TicketId $ticketId
            Write-TicketHandled -TicketId $ticketId -Action 'skip' -Outcome 'pre_session_event_skipped' -Notes ('Skipped because created_at {0} is before session event queue floor {1}.' -f $createdAt, $eventQueueFloorAt)
            if (-not $processedSet.Contains($ticketId)) {
                $processedSet[$ticketId] = $true
                [void]$processedIds.Add($ticketId)
                $doneThisPoll++
            }
            continue
        }
    }

    $staleReason = Get-StaleByBarrierReason -EventName $eventName -TicketBatchId $batchId -TicketCreatedAt $createdAt -TicketRestartGeneration $restartGeneration -LastBarrierBatchId $lastBarrierBatchId -LastBarrierAt $lastBarrierAt -LastBarrierRestartGeneration $lastBarrierRestartGeneration
    if (-not [string]::IsNullOrWhiteSpace($staleReason)) {
        Update-LedgerStatus -LedgerRecords $ledgerRecords -TicketId $ticketId -Status 'stale_by_restart' -At (Get-NowText) -Note $staleReason
        Clear-LedgerRetrySchedule -LedgerRecords $ledgerRecords -TicketId $ticketId
        $staleByRestartThisPoll++
        continue
    }

    if ($currentStatus -eq 'deferred') {
        $nextRetryAt = Convert-ToSingleLineText -Text ([string]$ledgerRecord.next_retry_at)
        if (-not (Test-IsRetryDue -NextRetryAt $nextRetryAt)) {
            continue
        }
    }

    if (-not $IncludeStatusReports.IsPresent -and $isStatusReport) {
        $skippedStatusReports++
        Write-TicketHandled -TicketId $ticketId -Action 'skip' -Outcome 'status_reports_disabled' -Notes 'Skipped because IncludeStatusReports not set.'
        continue
    }

    if ($isStatusReport -and $eventDrivenTicketSelected) {
        # Event-driven tickets have higher priority. If any event-driven ticket is
        # pending in this poll cycle, postpone status-report handling.
        $skippedStatusReports++
        Write-TicketHandled -TicketId $ticketId -Action 'skip' -Outcome 'preempted_by_event' -Notes 'Skipped because an event-driven ticket was selected in this poll cycle.'
        continue
    }

    if (-not $isStatusReport) {
        $eventDrivenTicketSelected = $true

        if ($rows.Count -gt 0 -or -not [string]::IsNullOrWhiteSpace($latestStatusTicketId)) {
            $preemptedStatusTicketIds = New-Object 'System.Collections.Generic.List[string]'
            for ($rowIndex = $rows.Count - 1; $rowIndex -ge 0; $rowIndex--) {
                $rowEventName = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $rows[$rowIndex] -Name 'event')
                if (-not (Test-IsStatusReportEvent -EventName $rowEventName)) {
                    continue
                }

                $rowTicketId = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $rows[$rowIndex] -Name 'ticket_id')
                if (-not [string]::IsNullOrWhiteSpace($rowTicketId)) {
                    [void]$preemptedStatusTicketIds.Add($rowTicketId)
                }

                $rows.RemoveAt($rowIndex)
            }

            foreach ($statusTicketId in @($preemptedStatusTicketIds.ToArray())) {
                [void]$claimedIds.Remove($statusTicketId)
                if ($ledgerRecords.ContainsKey($statusTicketId)) {
                    Set-LedgerDeferred -LedgerRecords $ledgerRecords -TicketId $statusTicketId -NowAt (Get-NowText) -Reason 'status_preempted_by_event'
                    $deferredThisPoll++
                }

                if ($statusTicketId -eq $latestStatusTicketId) {
                    $latestStatusTicketId = ''
                }
            }
        }
    }

    if ($isDrainMode -and $isDrainSafeEvent -and -not $isStatusReport) {
        # Verify the ticket's event still exists in the ticket chain before selecting it.
        if (-not (Test-TicketEventExist -StartFileRel $startFileRel -TicketId $ticketId -QueuePath $queueFilePath)) {
            Update-LedgerStatus -LedgerRecords $ledgerRecords -TicketId $ticketId -Status 'done' -At (Get-NowText) -Note 'event_no_longer_present'
            Clear-LedgerRetrySchedule -LedgerRecords $ledgerRecords -TicketId $ticketId
            Write-TicketHandled -TicketId $ticketId -Action 'skip' -Outcome 'event_no_longer_present' -Notes 'Event not present when selected by poll.'
            $deferredThisPoll++
            continue
        }
        $originalRequiresConfirmation = Get-ObjectPropertyBoolean -InputObject $ticket -Name 'requires_confirmation' -Default $false
        $requiresConfirmation = Get-EffectiveRequiresConfirmation -Requested $originalRequiresConfirmation
        $detail = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $ticket -Name 'detail')
        $recommendedAction = Get-EffectiveRecommendedAction -RecommendedAction (Get-ObjectPropertyString -InputObject $ticket -Name 'recommended_action') -OriginalRequiresConfirmation $originalRequiresConfirmation
        $queueRel = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $ticket -Name 'queue_path')
        $ticketClosureCheckCommand = Get-TicketClosureCheckCommand -StartFileRel $startFileRel
        $eventDedupHealthCheckCommand = Get-EventDedupHealthCheckCommand -StartFileRel $startFileRel
        $finalStatusCloseoutCommand = Get-FinalStatusCloseoutCommand -StartFileRel $startFileRel
        $finalStatusCloseoutApplyAckCommand = if ($eventName -eq 'chat-session-final-status') { Get-FinalStatusCloseoutCommand -StartFileRel $startFileRel -ApplyAcknowledge } else { '' }

        Update-LedgerStatus -LedgerRecords $ledgerRecords -TicketId $ticketId -Status 'claimed' -At (Get-NowText) -Note 'selected-drain-safe-event'
        Clear-LedgerRetrySchedule -LedgerRecords $ledgerRecords -TicketId $ticketId

        Remove-RowByTicketId -Rows $rows -TicketId $ticketId
        $rows.Add([pscustomobject]@{
                ticket_id = $ticketId
                event = $eventName
                created_at = $createdAt
                severity = $severity
                requires_confirmation = $requiresConfirmation
                original_requires_confirmation = $originalRequiresConfirmation
                authorization_policy = (Get-AuthorizationPolicyTag -OriginalRequiresConfirmation $originalRequiresConfirmation)
                detail = $detail
                recommended_action = $recommendedAction
                queue_path = $queueRel
                main_round = $ticketMainRound
                failure_kind = $ticketFailureKind
                failure_category = $ticketFailureCategory
                failure_source = $ticketFailureSource
                failure_evidence = $ticketFailureEvidence
                self_healable = [bool]$ticketSelfHealable
                non_recoverable_env = [bool]$ticketNonRecoverableEnv
                preferred_stage = [string]$ticketResumePlan.stage
                launcher_policy = 'stage-window-only'
                business_command_stage = [string]$ticketResumePlan.stage
                business_command_reason = [string]$ticketResumePlan.reason
                business_command = ''
                continue_watch_command = $continueWatchCommand
                mark_processed_command = (Get-MarkProcessedCommand -StartFileRel $startFileRel -TicketId $ticketId -Last $Last)
                handled_receipt_command = (Get-MarkProcessedCommand -StartFileRel $startFileRel -TicketId $ticketId -Last $Last)
                validate_receipt_command = (Get-ValidateHandledReceiptCommand -StartFileRel $startFileRel -TicketId $ticketId)
                contract_gate_command = (Get-ContractGateCommand -EventName $eventName)
                route_guard_command = (Get-RouteGuardCommand -StartFileRel $startFileRel -QueuePathRel $queueRel -TicketId $ticketId)
                ticket_closure_check_command = $ticketClosureCheckCommand
                event_dedup_health_check_command = $eventDedupHealthCheckCommand
                final_status_closeout_command = $finalStatusCloseoutCommand
                final_status_closeout_apply_ack_command = $finalStatusCloseoutApplyAckCommand
                next_command_order = @(Get-NextCommandOrder -RouteGuardCommand (Get-RouteGuardCommand -StartFileRel $startFileRel -QueuePathRel $queueRel -TicketId $ticketId) -BusinessCommand '' -ContinueWatchCommand $continueWatchCommand -HandledReceiptCommand (Get-MarkProcessedCommand -StartFileRel $startFileRel -TicketId $ticketId -Last $Last) -ValidateReceiptCommand (Get-ValidateHandledReceiptCommand -StartFileRel $startFileRel -TicketId $ticketId) -MarkProcessedCommand (Get-MarkProcessedCommand -StartFileRel $startFileRel -TicketId $ticketId -Last $Last) -PostCheckCommand (Get-PostExecutionCheckCommand -StartFileRel $startFileRel -Last $Last) -TicketClosureCheckCommand $ticketClosureCheckCommand -EventDedupHealthCheckCommand $eventDedupHealthCheckCommand -FinalStatusCloseoutCommand $finalStatusCloseoutCommand -FinalStatusCloseoutApplyAckCommand $finalStatusCloseoutApplyAckCommand)
                route_guard_required = $true
                receipt_required = $true
                receipt_type = 'handled_at'
                post_check_command = (Get-PostExecutionCheckCommand -StartFileRel $startFileRel -Last $Last)
            }) | Out-Null

        if (-not $claimedIds.Contains($ticketId)) {
            [void]$claimedIds.Add($ticketId)
        }
        continue
    }

    if ($isDrainMode -and -not $isDrainSafeEvent) {
        $drainDeferReason = if ($drainMode -eq 'recovery-drain') { 'recovery_drain_guard' } else { 'drain_guard' }
        Set-LedgerDeferred -LedgerRecords $ledgerRecords -TicketId $ticketId -NowAt (Get-NowText) -Reason $drainDeferReason
        $deferredThisPoll++
        continue
    }

    $originalRequiresConfirmation = Get-ObjectPropertyBoolean -InputObject $ticket -Name 'requires_confirmation' -Default $false
    $requiresConfirmation = Get-EffectiveRequiresConfirmation -Requested $originalRequiresConfirmation
    $detail = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $ticket -Name 'detail')
    $recommendedAction = Get-EffectiveRecommendedAction -RecommendedAction (Get-ObjectPropertyString -InputObject $ticket -Name 'recommended_action') -OriginalRequiresConfirmation $originalRequiresConfirmation
    $queueRel = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $ticket -Name 'queue_path')
    $ticketClosureCheckCommand = Get-TicketClosureCheckCommand -StartFileRel $startFileRel
    $eventDedupHealthCheckCommand = Get-EventDedupHealthCheckCommand -StartFileRel $startFileRel
    $finalStatusCloseoutCommand = Get-FinalStatusCloseoutCommand -StartFileRel $startFileRel
    $finalStatusCloseoutApplyAckCommand = if ($eventName -eq 'chat-session-final-status') { Get-FinalStatusCloseoutCommand -StartFileRel $startFileRel -ApplyAcknowledge } else { '' }

    $selectedBusinessCommand = [string]$ticketResumePlan.command
    if ($eventName -eq 'task-definition-fix-required') {
        $selectedBusinessCommand = Get-TaskDefinitionFixBusinessCommand -StartFileRel $startFileRel -QueuePathRel $queueRel -TicketId $ticketId -Last $Last
    }

    if ($isStatusReport) {
        if (-not [string]::IsNullOrWhiteSpace($latestStatusTicketId) -and $latestStatusTicketId -ne $ticketId) {
            $supersededStatusTicketId = [string]$latestStatusTicketId
            $supersedeAt = Get-NowText

            # Keep only the latest status-report ticket executable; older pending
            # status tickets are auto-acknowledged to avoid duplicate short-cycle work.
            Update-LedgerStatus -LedgerRecords $ledgerRecords -TicketId $supersededStatusTicketId -Status 'executed' -At $supersedeAt -Note 'newer-running-status-report-auto-ack'
            Update-LedgerStatus -LedgerRecords $ledgerRecords -TicketId $supersededStatusTicketId -Status 'watch-resumed' -At $supersedeAt -Note 'newer-running-status-report-auto-ack'
            Update-LedgerStatus -LedgerRecords $ledgerRecords -TicketId $supersededStatusTicketId -Status 'done' -At $supersedeAt -Note 'newer-running-status-report-auto-ack'
            Clear-LedgerRetrySchedule -LedgerRecords $ledgerRecords -TicketId $supersededStatusTicketId
            Remove-RowByTicketId -Rows $rows -TicketId $supersededStatusTicketId
            [void]$claimedIds.Remove($supersededStatusTicketId)

            if (-not $processedSet.Contains($supersededStatusTicketId)) {
                $processedSet[$supersededStatusTicketId] = $true
                [void]$processedIds.Add($supersededStatusTicketId)
                $doneThisPoll++
            }

            if ($MaxProcessedIds -gt 0) {
                while ($processedIds.Count -gt $MaxProcessedIds) {
                    $oldId = [string]$processedIds[0]
                    $processedIds.RemoveAt(0)
                    if ($processedSet.Contains($oldId)) {
                        $processedSet.Remove($oldId) | Out-Null
                    }
                }
            }

            $statusSupersededThisPoll++
            # Write a handled artifact for the superseded status ticket
            Write-TicketHandled -TicketId $supersededStatusTicketId -Action 'skip' -Outcome 'superseded_by_newer_status' -Notes ("Superseded by newer status ticket {0} at {1}" -f $ticketId, $supersedeAt)
        }

        Update-LedgerStatus -LedgerRecords $ledgerRecords -TicketId $ticketId -Status 'claimed' -At (Get-NowText) -Note 'selected-latest-status-report'
        Clear-LedgerRetrySchedule -LedgerRecords $ledgerRecords -TicketId $ticketId
        $latestStatusTicketId = $ticketId

        Remove-RowByTicketId -Rows $rows -TicketId $ticketId
        $rows.Add([pscustomobject]@{
                ticket_id = $ticketId
                event = $eventName
                created_at = $createdAt
                severity = $severity
                requires_confirmation = $requiresConfirmation
                original_requires_confirmation = $originalRequiresConfirmation
                authorization_policy = (Get-AuthorizationPolicyTag -OriginalRequiresConfirmation $originalRequiresConfirmation)
                detail = $detail
                recommended_action = $recommendedAction
                queue_path = $queueRel
                main_round = $ticketMainRound
                failure_kind = $ticketFailureKind
                failure_category = $ticketFailureCategory
                failure_source = $ticketFailureSource
                failure_evidence = $ticketFailureEvidence
                self_healable = [bool]$ticketSelfHealable
                non_recoverable_env = [bool]$ticketNonRecoverableEnv
                preferred_stage = [string]$ticketResumePlan.stage
                launcher_policy = 'stage-window-only'
                business_command_stage = [string]$ticketResumePlan.stage
                business_command_reason = [string]$ticketResumePlan.reason
                business_command = (Get-StatusReportBusinessCommand -StartFileRel $startFileRel -QueuePathRel $queueRel -TicketId $ticketId -Last $Last -IncludeTicketChainCheck $statusReportIncludeTicketChainCheck -IncludeMainProcessHealthCheck $statusReportIncludeMainProcessHealthCheck -EnableMainProcessAutoHeal $statusReportEnableMainProcessAutoHeal -EnableMonitorChainDegradedEscalation $statusReportEnableMonitorChainDegradedEscalation -MonitorChainDegradedEscalationThreshold $statusReportMonitorChainDegradedEscalationThreshold -LowDisturbMode $statusReportLowDisturbMode)
                continue_watch_command = $continueWatchCommand
                mark_processed_command = (Get-MarkProcessedCommand -StartFileRel $startFileRel -TicketId $ticketId -Last $Last)
                handled_receipt_command = (Get-MarkProcessedCommand -StartFileRel $startFileRel -TicketId $ticketId -Last $Last)
                validate_receipt_command = (Get-ValidateHandledReceiptCommand -StartFileRel $startFileRel -TicketId $ticketId)
                contract_gate_command = (Get-ContractGateCommand -EventName $eventName)
                route_guard_command = (Get-RouteGuardCommand -StartFileRel $startFileRel -QueuePathRel $queueRel -TicketId $ticketId)
                ticket_closure_check_command = $ticketClosureCheckCommand
                event_dedup_health_check_command = $eventDedupHealthCheckCommand
                final_status_closeout_command = $finalStatusCloseoutCommand
                final_status_closeout_apply_ack_command = $finalStatusCloseoutApplyAckCommand
                next_command_order = @(Get-NextCommandOrder -RouteGuardCommand (Get-RouteGuardCommand -StartFileRel $startFileRel -QueuePathRel $queueRel -TicketId $ticketId) -BusinessCommand $selectedBusinessCommand -ContinueWatchCommand $continueWatchCommand -HandledReceiptCommand (Get-MarkProcessedCommand -StartFileRel $startFileRel -TicketId $ticketId -Last $Last) -ValidateReceiptCommand (Get-ValidateHandledReceiptCommand -StartFileRel $startFileRel -TicketId $ticketId) -MarkProcessedCommand (Get-MarkProcessedCommand -StartFileRel $startFileRel -TicketId $ticketId -Last $Last) -PostCheckCommand (Get-PostExecutionCheckCommand -StartFileRel $startFileRel -Last $Last) -TicketClosureCheckCommand $ticketClosureCheckCommand -EventDedupHealthCheckCommand $eventDedupHealthCheckCommand -FinalStatusCloseoutCommand $finalStatusCloseoutCommand -FinalStatusCloseoutApplyAckCommand $finalStatusCloseoutApplyAckCommand)
                route_guard_required = $true
                receipt_required = $true
                receipt_type = 'handled_at'
                post_check_command = (Get-PostExecutionCheckCommand -StartFileRel $startFileRel -Last $Last)
            }) | Out-Null

        if (-not $claimedIds.Contains($ticketId)) {
            [void]$claimedIds.Add($ticketId)
        }
        continue
    }

    # Verify the ticket's event still exists before consuming action budget.
    if (-not (Test-TicketEventExist -StartFileRel $startFileRel -TicketId $ticketId -QueuePath $queueFilePath)) {
        Update-LedgerStatus -LedgerRecords $ledgerRecords -TicketId $ticketId -Status 'done' -At (Get-NowText) -Note 'event_no_longer_present'
        Clear-LedgerRetrySchedule -LedgerRecords $ledgerRecords -TicketId $ticketId
        Write-TicketHandled -TicketId $ticketId -Action 'skip' -Outcome 'event_no_longer_present' -Notes 'Event not present when selected by poll.'
        $deferredThisPoll++
        continue
    }

    $selectedActionTicketId = $ticketId
    if (-not $selectedEventTicketIds.Contains($ticketId)) {
        [void]$selectedEventTicketIds.Add($ticketId)
    }
    if (Test-IsBarrierEvent -EventName $eventName) {
        $selectedBarrierTicketId = $ticketId
    }

    Update-LedgerStatus -LedgerRecords $ledgerRecords -TicketId $ticketId -Status 'claimed' -At (Get-NowText) -Note 'selected-by-poller'
    Clear-LedgerRetrySchedule -LedgerRecords $ledgerRecords -TicketId $ticketId

    Remove-RowByTicketId -Rows $rows -TicketId $ticketId

    $rows.Add([pscustomobject]@{
            ticket_id = $ticketId
            event = $eventName
            created_at = $createdAt
            severity = $severity
            requires_confirmation = $requiresConfirmation
            original_requires_confirmation = $originalRequiresConfirmation
            authorization_policy = (Get-AuthorizationPolicyTag -OriginalRequiresConfirmation $originalRequiresConfirmation)
            detail = $detail
            recommended_action = $recommendedAction
            queue_path = $queueRel
            main_round = $ticketMainRound
            failure_kind = $ticketFailureKind
            failure_category = $ticketFailureCategory
            failure_source = $ticketFailureSource
            failure_evidence = $ticketFailureEvidence
            self_healable = [bool]$ticketSelfHealable
            non_recoverable_env = [bool]$ticketNonRecoverableEnv
            preferred_stage = [string]$ticketResumePlan.stage
            launcher_policy = 'stage-window-only'
            business_command_stage = [string]$ticketResumePlan.stage
            business_command_reason = [string]$ticketResumePlan.reason
            business_command = $selectedBusinessCommand
            continue_watch_command = $continueWatchCommand
            mark_processed_command = (Get-MarkProcessedCommand -StartFileRel $startFileRel -TicketId $ticketId -Last $Last)
            handled_receipt_command = (Get-MarkProcessedCommand -StartFileRel $startFileRel -TicketId $ticketId -Last $Last)
            validate_receipt_command = (Get-ValidateHandledReceiptCommand -StartFileRel $startFileRel -TicketId $ticketId)
            contract_gate_command = (Get-ContractGateCommand -EventName $eventName)
            route_guard_command = (Get-RouteGuardCommand -StartFileRel $startFileRel -QueuePathRel $queueRel -TicketId $ticketId)
            ticket_closure_check_command = $ticketClosureCheckCommand
            event_dedup_health_check_command = $eventDedupHealthCheckCommand
            final_status_closeout_command = $finalStatusCloseoutCommand
            final_status_closeout_apply_ack_command = $finalStatusCloseoutApplyAckCommand
            next_command_order = @(Get-NextCommandOrder -RouteGuardCommand (Get-RouteGuardCommand -StartFileRel $startFileRel -QueuePathRel $queueRel -TicketId $ticketId) -BusinessCommand $selectedBusinessCommand -ContinueWatchCommand $continueWatchCommand -HandledReceiptCommand (Get-MarkProcessedCommand -StartFileRel $startFileRel -TicketId $ticketId -Last $Last) -ValidateReceiptCommand (Get-ValidateHandledReceiptCommand -StartFileRel $startFileRel -TicketId $ticketId) -MarkProcessedCommand (Get-MarkProcessedCommand -StartFileRel $startFileRel -TicketId $ticketId -Last $Last) -PostCheckCommand (Get-PostExecutionCheckCommand -StartFileRel $startFileRel -Last $Last) -TicketClosureCheckCommand $ticketClosureCheckCommand -EventDedupHealthCheckCommand $eventDedupHealthCheckCommand -FinalStatusCloseoutCommand $finalStatusCloseoutCommand -FinalStatusCloseoutApplyAckCommand $finalStatusCloseoutApplyAckCommand)
            route_guard_required = $true
            receipt_required = $true
            receipt_type = 'handled_at'
            post_check_command = (Get-PostExecutionCheckCommand -StartFileRel $startFileRel -Last $Last)
        }) | Out-Null
    if (-not $claimedIds.Contains($ticketId)) {
        [void]$claimedIds.Add($ticketId)
    }
}

if ($markProcessedFlag -and $claimedIds.Count -gt 0) {
    foreach ($ticketId in @($claimedIds)) {
        if ($processedSet.Contains($ticketId)) {
            continue
        }

        $finalizeAt = Get-NowText
        Update-LedgerStatus -LedgerRecords $ledgerRecords -TicketId $ticketId -Status 'executed' -At $finalizeAt -Note 'mark-processed'
        Update-LedgerStatus -LedgerRecords $ledgerRecords -TicketId $ticketId -Status 'watch-resumed' -At $finalizeAt -Note 'mark-processed'
        Update-LedgerStatus -LedgerRecords $ledgerRecords -TicketId $ticketId -Status 'done' -At $finalizeAt -Note 'mark-processed'
        Clear-LedgerRetrySchedule -LedgerRecords $ledgerRecords -TicketId $ticketId
        Write-TicketHandled -TicketId $ticketId -Action 'acknowledge' -Outcome 'mark-processed' -Command ('poll_agent_tickets.ps1 -AcknowledgeTicketIds "{0}"' -f $ticketId) -Notes ('ticket mark-processed and closed at {0}' -f $finalizeAt)
        [void]$handledReceipts.Add([ordered]@{ ticket_id = $ticketId; handled_at = $finalizeAt; action = 'mark-processed'; outcome = 'mark-processed' })

        if ($ticketId -eq $selectedBarrierTicketId) {
            $barrierRecord = Convert-ToLedgerRecord -InputRecord $ledgerRecords[$ticketId] -FallbackTicketId $ticketId
            $lastBarrierTicketId = $ticketId
            $lastBarrierAt = $finalizeAt
            $lastBarrierBatchId = Convert-ToSingleLineText -Text ([string]$barrierRecord.batch_id)
            $lastBarrierRestartGeneration = Convert-ToSingleLineText -Text ([string]$barrierRecord.restart_generation)
        }

        $processedSet[$ticketId] = $true
        [void]$processedIds.Add($ticketId)
        $doneThisPoll++
    }

    if ($MaxProcessedIds -gt 0) {
        while ($processedIds.Count -gt $MaxProcessedIds) {
            $oldId = [string]$processedIds[0]
            $processedIds.RemoveAt(0)
            if ($processedSet.Contains($oldId)) {
                $processedSet.Remove($oldId) | Out-Null
            }
        }
    }

}

$stateRecoveryDrainPending = $recoveryDrainPending
if ($drainMode -eq 'drain-pass') {
    $stateRecoveryDrainPending = $true
    $lastDrainAt = Get-NowText
}
elseif ($drainMode -eq 'recovery-drain') {
    $stateRecoveryDrainPending = $false
    $lastRecoveryDrainAt = Get-NowText
}

$state = [ordered]@{
    schema = 'AB_AI_TICKET_POLL_STATE_V1'
    updated_at = (Get-NowText)
    start_file = $startFileRel
    queue_path = (Convert-ToRepoRelativePath -Path $queueFilePath)
    processed_ids = @($processedIds)
    recovery_drain_pending = [bool]$stateRecoveryDrainPending
    last_drain_at = $lastDrainAt
    last_recovery_drain_at = $lastRecoveryDrainAt
    event_queue_floor_at = $eventQueueFloorAt
    event_queue_floor_source = $eventQueueFloorSource
    event_queue_skip_existing_on_start = [bool]$eventQueueSkipExistingOnStart
    drain_mode = $drainMode
    drain_reason = $drainReason
}
Write-JsonFileSafely -Path $stateFilePath -Value $state

$compactionResult = Invoke-LedgerCompaction -LedgerRecords $ledgerRecords -RepoRoot $script:RepoRoot -StartToken $startToken -Enabled $enableLedgerCompactionFlag -CompactionDays $LedgerCompactionDays -ArchiveRetentionDays $LedgerArchiveRetentionDays

$ledgerRecordList = New-Object 'System.Collections.Generic.List[object]'
foreach ($ticketId in @($ledgerRecords.Keys | Sort-Object)) {
    [void]$ledgerRecordList.Add($ledgerRecords[$ticketId])
}

$ledgerState = [ordered]@{
    schema = 'AB_AI_TICKET_LEDGER_V3'
    updated_at = (Get-NowText)
    start_file = $startFileRel
    queue_path = (Convert-ToRepoRelativePath -Path $queueFilePath)
    state_path = (Convert-ToRepoRelativePath -Path $stateFilePath)
    last_barrier_ticket_id = $lastBarrierTicketId
    last_barrier_at = $lastBarrierAt
    last_barrier_batch_id = $lastBarrierBatchId
    last_barrier_restart_generation = $lastBarrierRestartGeneration
    records = @($ledgerRecordList.ToArray())
}
Write-JsonFileSafely -Path $ledgerFilePath -Value $ledgerState

$ledgerStatusCounts = Get-LedgerStatusCount -LedgerRecords $ledgerRecords

$rowsOutput = $rows.ToArray()
$triageTopCause = ''
$triageEvidenceHint = ''
$triageActionHint = ''
$triageConfidence = 0.40

if ($rowsOutput.Count -gt 0) {
    $firstRow = $rowsOutput[0]
    $firstEvent = Convert-ToSingleLineText -Text ([string](Get-ObjectPropertyString -InputObject $firstRow -Name 'event'))
    $firstFailureKind = Convert-ToSingleLineText -Text ([string](Get-ObjectPropertyString -InputObject $firstRow -Name 'failure_kind'))
    $firstFailureCategory = Convert-ToSingleLineText -Text ([string](Get-ObjectPropertyString -InputObject $firstRow -Name 'failure_category'))
    $firstFailureEvidence = Convert-ToSingleLineText -Text ([string](Get-ObjectPropertyString -InputObject $firstRow -Name 'failure_evidence'))
    $firstRecommendedAction = Convert-ToSingleLineText -Text ([string](Get-ObjectPropertyString -InputObject $firstRow -Name 'recommended_action'))
    $firstBusinessCommand = Convert-ToSingleLineText -Text ([string](Get-ObjectPropertyString -InputObject $firstRow -Name 'business_command'))
    $firstContinueWatchCommand = Convert-ToSingleLineText -Text ([string](Get-ObjectPropertyString -InputObject $firstRow -Name 'continue_watch_command'))

    if (-not [string]::IsNullOrWhiteSpace($firstFailureKind)) {
        $triageTopCause = $firstFailureKind
    }
    elseif (-not [string]::IsNullOrWhiteSpace($firstFailureCategory)) {
        $triageTopCause = $firstFailureCategory
    }
    else {
        $triageTopCause = $firstEvent
    }

    if (-not [string]::IsNullOrWhiteSpace($firstFailureEvidence)) {
        $triageEvidenceHint = $firstFailureEvidence
    }
    elseif ($null -ne $fallbackMonitoring -and -not [string]::IsNullOrWhiteSpace([string]$fallbackMonitoring.blocked_evidence)) {
        $triageEvidenceHint = [string]$fallbackMonitoring.blocked_evidence
    }
    elseif ($null -ne $fallbackMonitoring -and -not [string]::IsNullOrWhiteSpace([string]$fallbackMonitoring.live_status_error_detail)) {
        $triageEvidenceHint = [string]$fallbackMonitoring.live_status_error_detail
    }

    if (-not [string]::IsNullOrWhiteSpace($firstRecommendedAction)) {
        $triageActionHint = $firstRecommendedAction
    }
    elseif (-not [string]::IsNullOrWhiteSpace($firstBusinessCommand)) {
        $triageActionHint = $firstBusinessCommand
    }
    elseif (-not [string]::IsNullOrWhiteSpace($firstContinueWatchCommand)) {
        $triageActionHint = $firstContinueWatchCommand
    }

    $triageConfidence = 0.88
}
elseif ($null -ne $fallbackMonitoring -and [bool]$fallbackMonitoring.required) {
    if (-not [string]::IsNullOrWhiteSpace([string]$fallbackMonitoring.live_status_event)) {
        $triageTopCause = [string]$fallbackMonitoring.live_status_event
    }
    else {
        $triageTopCause = [string]$fallbackMonitoring.reason
    }

    if (-not [string]::IsNullOrWhiteSpace([string]$fallbackMonitoring.live_status_error_detail)) {
        $triageEvidenceHint = [string]$fallbackMonitoring.live_status_error_detail
    }
    elseif (-not [string]::IsNullOrWhiteSpace([string]$fallbackMonitoring.blocked_evidence)) {
        $triageEvidenceHint = [string]$fallbackMonitoring.blocked_evidence
    }

    if (-not [string]::IsNullOrWhiteSpace([string]$fallbackMonitoring.commands.business_resume)) {
        $triageActionHint = [string]$fallbackMonitoring.commands.business_resume
    }
    elseif (-not [string]::IsNullOrWhiteSpace([string]$fallbackMonitoring.commands.watch_once)) {
        $triageActionHint = [string]$fallbackMonitoring.commands.watch_once
    }

    $triageConfidence = 0.82
}

$output = [ordered]@{
    schema = 'AB_AGENT_TICKET_POLL_V1'
    generated_at = (Get-NowText)
    start_file = $startFileRel
    queue_path = (Convert-ToRepoRelativePath -Path $queueFilePath)
    state_path = (Convert-ToRepoRelativePath -Path $stateFilePath)
    ledger_path = (Convert-ToRepoRelativePath -Path $ledgerFilePath)
    ledger_schema = 'AB_AI_TICKET_LEDGER_V3'
    mark_processed = [bool]$markProcessedFlag
    drain_mode = $drainMode
    drain_reason = $drainReason
    recovery_drain_pending = [bool]$stateRecoveryDrainPending
    include_status_reports = [bool]$IncludeStatusReports.IsPresent
    skipped_running_status_reports = $skippedStatusReports
    acknowledged_this_poll = $acknowledgedThisPoll
    claimed_this_poll = $claimedIds.Count
    done_this_poll = $doneThisPoll
    handled_receipts = @($handledReceipts.ToArray())
    deferred_this_poll = $deferredThisPoll
    stale_by_restart_this_poll = $staleByRestartThisPoll
    status_superseded_this_poll = $statusSupersededThisPoll
    selected_action_ticket_id = $selectedActionTicketId
    selected_barrier_ticket_id = $selectedBarrierTicketId
    selected_event_ticket_ids = @($selectedEventTicketIds.ToArray())
    last_barrier_ticket_id = $lastBarrierTicketId
    last_barrier_at = $lastBarrierAt
    event_policy = [ordered]@{
        strict_mode = [bool]$eventPolicyStrictModeFlag
        status_report_chain_check_enabled = [bool]$statusReportIncludeTicketChainCheck
        status_report_main_process_health_check_enabled = [bool]$statusReportIncludeMainProcessHealthCheck
        status_report_main_process_auto_heal_enabled = [bool]$statusReportEnableMainProcessAutoHeal
        status_report_monitor_chain_degraded_escalation_enabled = [bool]$statusReportEnableMonitorChainDegradedEscalation
        status_report_monitor_chain_degraded_escalation_threshold = [int]$statusReportMonitorChainDegradedEscalationThreshold
        status_report_events = @($script:EventSetStatusReport.Keys | Sort-Object)
        drain_safe_events = @($script:EventSetDrainSafe.Keys | Sort-Object)
        barrier_events = @($script:EventSetBarrier.Keys | Sort-Object)
        restart_sensitive_events = @($script:EventSetRestartSensitive.Keys | Sort-Object)
        contract_gate_events = @($script:EventSetContractGate.Keys | Sort-Object)
        adjustments = @($eventPolicyAdjustments.ToArray())
    }
    event_queue_policy = [ordered]@{
        skip_existing_on_start = [bool]$eventQueueSkipExistingOnStart
        event_queue_floor_at = $eventQueueFloorAt
        event_queue_floor_source = $eventQueueFloorSource
    }
    compaction = $compactionResult
    ledger_status_counts = $ledgerStatusCounts
    fallback_monitoring = $fallbackMonitoring
    session_close_gate = $sessionCloseGate
    chat_session_heartbeat = $chatHeartbeatInfo
    poll_lock = [ordered]@{
        lock_busy = $false
        lock_name = [string]$pollMutexContext.Name
        lock_wait_ms = [int]$pollMutexContext.WaitMs
    }
    triage_summary = [ordered]@{
        top_cause = $triageTopCause
        evidence_hint = $triageEvidenceHint
        action_hint = $triageActionHint
        confidence = [double]$triageConfidence
    }
    rows = $rowsOutput
    rescan_commands = [ordered]@{
        every_5m = ('powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/poll_agent_tickets.ps1 -StartFile "{0}" -Last {1} -AsJson' -f $startFileRel, $Last)
        every_10m = ('powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/poll_agent_tickets.ps1 -StartFile "{0}" -Last {1} -AsJson' -f $startFileRel, $Last)
        routine_check = ('powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/check_unattended_routine_status.ps1 -StartFile "{0}" -Last {1} -AsJson' -f $startFileRel, $Last)
        acknowledge_template = ('powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/poll_agent_tickets.ps1 -StartFile "{0}" -AcknowledgeTicketIds "<ticket-id>" -Last {1} -AsJson' -f $startFileRel, $Last)
        post_execution_check = (Get-PostExecutionCheckCommand -StartFileRel $startFileRel -Last $Last)
        heartbeat_ping = ('powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/update_chat_session_heartbeat.ps1 -StartFile "{0}" -Source "chat-session-active" -AsJson' -f $startFileRel)
    }
}

if ($AsJson.IsPresent) {
    $output | ConvertTo-Json -Depth 8
}
else {
    Write-Output ('[AB-TICKET-POLL] generated_at={0} start_file={1}' -f $output.generated_at, $output.start_file)
    Write-Output ('[AB-TICKET-POLL] queue={0} state={1}' -f $output.queue_path, $output.state_path)
    Write-Output ('[AB-TICKET-POLL] ledger={0} schema={1}' -f $output.ledger_path, $output.ledger_schema)
    Write-Output ('[AB-TICKET-POLL] drain_mode={0} drain_reason={1} recovery_drain_pending={2}' -f [string]$output.drain_mode, [string]$output.drain_reason, [bool]$output.recovery_drain_pending)
    Write-Output ('[AB-TICKET-POLL] rows={0} skipped_running_status_reports={1} mark_processed={2} acknowledged_this_poll={3}' -f $rows.Count, $skippedStatusReports, [bool]$markProcessedFlag, [int]$output.acknowledged_this_poll)
    Write-Output ('[AB-TICKET-POLL] claimed_this_poll={0} done_this_poll={1}' -f [int]$output.claimed_this_poll, [int]$output.done_this_poll)
    Write-Output ('[AB-TICKET-POLL] deferred_this_poll={0} stale_by_restart_this_poll={1} status_superseded_this_poll={2}' -f [int]$output.deferred_this_poll, [int]$output.stale_by_restart_this_poll, [int]$output.status_superseded_this_poll)
    Write-Output ('[AB-TICKET-POLL] selected_action_ticket={0} selected_barrier_ticket={1} last_barrier_ticket={2} last_barrier_at={3}' -f [string]$output.selected_action_ticket_id, [string]$output.selected_barrier_ticket_id, [string]$output.last_barrier_ticket_id, [string]$output.last_barrier_at)
    Write-Output ('[AB-TICKET-POLL] event_policy_strict_mode={0}' -f [bool]$output.event_policy.strict_mode)
    Write-Output ('[AB-TICKET-POLL] status_report_chain_check_enabled={0}' -f [bool]$output.event_policy.status_report_chain_check_enabled)
    Write-Output ('[AB-TICKET-POLL] status_report_monitor_chain_degraded_escalation_enabled={0} threshold={1}' -f [bool]$output.event_policy.status_report_monitor_chain_degraded_escalation_enabled, [int]$output.event_policy.status_report_monitor_chain_degraded_escalation_threshold)
    Write-Output ('[AB-TICKET-POLL] event_policy status_report={0} drain_safe={1} barrier={2} restart_sensitive={3}' -f (($output.event_policy.status_report_events -join ',')), (($output.event_policy.drain_safe_events -join ',')), (($output.event_policy.barrier_events -join ',')), (($output.event_policy.restart_sensitive_events -join ',')))
    Write-Output ('[AB-TICKET-POLL] event_policy_adjustments={0}' -f (($output.event_policy.adjustments -join ',')))
    Write-Output ('[AB-TICKET-POLL] compaction_enabled={0} archived={1} removed={2} archive_path={3} removed_archive_files={4}' -f [bool]$output.compaction.enabled, [int]$output.compaction.archived, [int]$output.compaction.removed, [string]$output.compaction.archive_path, [int]$output.compaction.removed_archive_files)
    Write-Output ('[AB-TICKET-POLL] session_closed={0} reason={1} by_flag={2} by_pass_final={3}' -f [bool]$output.session_close_gate.closed, [string]$output.session_close_gate.reason, [bool]$output.session_close_gate.closed_by_flag, [bool]$output.session_close_gate.closed_by_pass_final)
    Write-Output ('[AB-TICKET-POLL] chat_heartbeat enabled={0} write_on_poll={1} write_ok={2} path={3} updated_at={4} source={5} reason={6}' -f [bool]$output.chat_session_heartbeat.enabled, [bool]$output.chat_session_heartbeat.write_on_poll, [bool]$output.chat_session_heartbeat.write_ok, [string]$output.chat_session_heartbeat.path, [string]$output.chat_session_heartbeat.updated_at, [string]$output.chat_session_heartbeat.source, [string]$output.chat_session_heartbeat.reason)
    Write-Output ('[AB-TICKET-POLL] lock_busy={0} lock_name={1} lock_wait_ms={2}' -f [bool]$output.poll_lock.lock_busy, [string]$output.poll_lock.lock_name, [int]$output.poll_lock.lock_wait_ms)
    Write-Output ('[AB-TICKET-POLL] triage_top_cause={0} triage_confidence={1}' -f [string]$output.triage_summary.top_cause, [double]$output.triage_summary.confidence)
    if (-not [string]::IsNullOrWhiteSpace([string]$output.triage_summary.evidence_hint)) {
        Write-Output ('[AB-TICKET-POLL] triage_evidence_hint={0}' -f [string]$output.triage_summary.evidence_hint)
    }
    if (-not [string]::IsNullOrWhiteSpace([string]$output.triage_summary.action_hint)) {
        Write-Output ('[AB-TICKET-POLL] triage_action_hint={0}' -f [string]$output.triage_summary.action_hint)
    }
    if ($null -ne $fallbackMonitoring) {
        Write-Output ('[AB-TICKET-POLL] fallback_required={0} reason={1} session={2} a={3} b={4} live_status_state={5} live_status_event={6} live_status_error_detail={7}' -f
            [bool]$fallbackMonitoring.required,
            [string]$fallbackMonitoring.reason,
            [string]$fallbackMonitoring.session_final_status,
            [string]$fallbackMonitoring.a_final_status,
            [string]$fallbackMonitoring.b_final_status,
            [string]$fallbackMonitoring.live_status_state,
            [string]$fallbackMonitoring.live_status_event,
            [string]$fallbackMonitoring.live_status_error_detail)
    }

    if ($rows.Count -eq 0) {
        Write-Output '[AB-TICKET-POLL] no_pending_rows'
        if ($null -ne $fallbackMonitoring -and [bool]$fallbackMonitoring.required) {
            Write-Output '[AB-TICKET-POLL] no_ticket_fallback_actions:'
            Write-Output ('  watch_once_command={0}' -f [string]$fallbackMonitoring.commands.watch_once)
            if (-not [string]::IsNullOrWhiteSpace([string]$fallbackMonitoring.commands.investigate)) {
                Write-Output ('  investigate_command={0}' -f [string]$fallbackMonitoring.commands.investigate)
            }
            Write-Output ('  business_command={0}' -f [string]$fallbackMonitoring.commands.business_resume)
            Write-Output ('  continue_watch_command={0}' -f [string]$fallbackMonitoring.commands.continue_watch)
        }
    }
    else {
        $rows | Select-Object ticket_id, event, severity, requires_confirmation, created_at |
            Format-Table -AutoSize | Out-String | Write-Output

        foreach ($row in $rows) {
            Write-Output ('[AB-TICKET-POLL] ticket={0} event={1}' -f [string]$row.ticket_id, [string]$row.event)
            Write-Output ('  business_command={0}' -f [string]$row.business_command)
            Write-Output ('  continue_watch_command={0}' -f [string]$row.continue_watch_command)
            Write-Output ('  route_guard_command={0}' -f [string]$row.route_guard_command)
            Write-Output ('  mark_processed_command={0}' -f [string]$row.mark_processed_command)
            if ([bool]$row.receipt_required) {
                Write-Output ('  receipt_type={0}' -f [string]$row.receipt_type)
                Write-Output ('  handled_receipt_command={0}' -f [string]$row.handled_receipt_command)
                Write-Output ('  validate_receipt_command={0}' -f [string]$row.validate_receipt_command)
            }
            Write-Output ('  post_check_command={0}' -f [string]$row.post_check_command)
        }
    }
}
}
finally {
    if ($null -ne $pollMutexContext -and $null -ne $pollMutexContext.Mutex) {
        try { $pollMutexContext.Mutex.ReleaseMutex() | Out-Null } catch { Write-Verbose ("Suppress release failure: {0}" -f $_.Exception.Message) }
        try { $pollMutexContext.Mutex.Dispose() } catch { Write-Verbose ("Suppress dispose failure: {0}" -f $_.Exception.Message) }
    }
}
