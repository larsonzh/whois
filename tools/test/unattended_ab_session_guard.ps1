param(
    [Parameter(Mandatory = $true)][string]$StartFile,
    [ValidateRange(15, 300)][int]$PollSec = 60,
    [ValidateRange(0, 10)][int]$MaxBRecoveryAttempts = 2,
    [ValidateRange(1, 180)][int]$RecoveryCooldownMinutes = 10,
    [bool]$StopOnBudgetExhausted = $true
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'unattended_exit_result.ps1')
. (Join-Path $PSScriptRoot 'unattended_startfile_identity.ps1')
. (Join-Path $PSScriptRoot 'a_success_snapshot_integrity.ps1')
$script:UnhandledExitTag = 'UNATTENDED-AB-SESSION-GUARD'
$PSDefaultParameterValues['Invoke-KeyValueFileValueUpdateCore:CommitMode'] = 'Move'
$PSDefaultParameterValues['Invoke-KeyValueFileValueUpdateCore:ReadMaxAttempts'] = 8
$PSDefaultParameterValues['Invoke-KeyValueFileValueUpdateCore:WriteMaxAttempts'] = 8
$PSDefaultParameterValues['Invoke-KeyValueFileValueUpdateCore:RetryDelayMs'] = @(50, 100, 200, 400, 800)
$PSDefaultParameterValues['Invoke-KeyValueFileValueUpdateCore:RequireExistingFile'] = $true

trap {
    # Write terminal marker to guard state if path is initialized,
    # so zombie detection can immediately identify this as a dead process.
    if (-not [string]::IsNullOrWhiteSpace($script:GuardStatePath)) {
        try {
            @{ status = 'stopped'; event = 'trap-exit'; error = ("$_" -replace '"', '\"') } | ConvertTo-Json | Out-File -LiteralPath $script:GuardStatePath -Encoding utf8 -Force -ErrorAction SilentlyContinue
        }
        catch { $null = $_ }
    }
    $exitCode = Get-UnattendedExitCodeFromRecord -Tag $script:UnhandledExitTag -Record $_ -DefaultExitCode 1
    Write-UnattendedUnhandledResult -Tag $script:UnhandledExitTag -Record $_ -ExitCode $exitCode
    exit $exitCode
}

$pathGuardModulePath = Join-Path $PSScriptRoot 'path_write_guard.ps1'
if (-not (Test-Path -LiteralPath $pathGuardModulePath)) {
    throw "Missing script: $pathGuardModulePath"
}
. $pathGuardModulePath



function Get-FilteredRuntimeTailLineList {
    param([string[]]$Lines)

    $filtered = New-Object 'System.Collections.Generic.List[string]'
    foreach ($record in @($Lines)) {
        $line = Convert-ToSingleLineText -Text ([string]$record)
        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }

        if ($line -match '^\*{8,}') {
            continue
        }

        if ($line -imatch '^windows powershell transcript (start|end)$' -or
            $line -imatch '^start time:' -or
            $line -imatch '^end time:' -or
            $line -imatch '^username:' -or
            $line -imatch '^runas user:' -or
            $line -imatch '^machine:' -or
            $line -imatch '^host application:' -or
            $line -imatch '^process id:' -or
            $line -imatch '^psversion:' -or
            $line -imatch '^serializationversion:' -or
            $line -imatch '^wsman stack version:') {
            continue
        }

        [void]$filtered.Add($line)
    }

    return @($filtered)
}

function Lock-InstanceMutex {
    param(
        [string]$Role,
        [string]$StartFilePath
    )

    $name = Get-StartFileRoleMutexName -Role $Role -StartFilePath $StartFilePath
    $mutex = New-Object System.Threading.Mutex($false, $name)
    $acquired = $false
    try {
        try {
            $acquired = $mutex.WaitOne(0)
        }
        catch [System.Threading.AbandonedMutexException] {
            $acquired = $true
        }

        if (-not $acquired) {
            Write-Output "[AB-SESSION-GUARD] single_instance_conflict mutex=$name start_file=$StartFilePath"
            $mutex.Dispose()
            throw 'Another unattended_ab_session_guard instance is already active for this start file'
        }
    }
    catch {
        if (-not $acquired -and $null -ne $mutex) {
            try { $mutex.Dispose() } catch { Write-Verbose ("Suppressed exception: {0}" -f $_.Exception.Message) }
        }
        throw
    }

    return $mutex
}

function Add-DelimitedNote {
    param(
        [AllowEmptyString()][string]$Existing,
        [AllowEmptyString()][string]$Append
    )

    if ([string]::IsNullOrWhiteSpace($Append)) {
        return $Existing
    }

    if ([string]::IsNullOrWhiteSpace($Existing)) {
        return $Append.Trim()
    }

    return ($Existing.TrimEnd() + '; ' + $Append.Trim())
}

function Resolve-RunDirAnchorFromNotes {
    param([AllowEmptyString()][string]$Notes)

    if ([string]::IsNullOrWhiteSpace($Notes)) {
        return ''
    }

    $runDirAnchor = Get-LatestAnchorValueFromNoteText -Notes $Notes -Key 'b_run_dir'
    if ([string]::IsNullOrWhiteSpace($runDirAnchor)) {
        $runDirAnchor = Get-LatestAnchorValueFromNoteText -Notes $Notes -Key 'run_dir'
    }
    if ([string]::IsNullOrWhiteSpace($runDirAnchor)) {
        $runDirAnchor = Get-LatestAnchorValueFromNoteText -Notes $Notes -Key 'a_run_dir'
    }

    return (Convert-ToSingleLineText -Text $runDirAnchor)
}

function Resolve-AnchorPath {
    param([AllowEmptyString()][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return ''
    }

    try {
        return Resolve-RepoPath -Path $Path
    }
    catch {
        return ''
    }
}

function Get-SettingValueWithAlias {
    param(
        [System.Collections.IDictionary]$Settings,
        [string]$PrimaryKey,
        [string]$FallbackKey
    )

    if ($null -eq $Settings) {
        return ''
    }

    if (-not [string]::IsNullOrWhiteSpace($PrimaryKey) -and $Settings.Contains($PrimaryKey)) {
        return (Convert-ToSingleLineText -Text ([string]$Settings[$PrimaryKey]))
    }

    if (-not [string]::IsNullOrWhiteSpace($FallbackKey) -and $Settings.Contains($FallbackKey)) {
        return (Convert-ToSingleLineText -Text ([string]$Settings[$FallbackKey]))
    }

    return ''
}

function Copy-FileIfPresent {
    param(
        [AllowEmptyString()][string]$Source,
        [string]$Destination
    )

    if ([string]::IsNullOrWhiteSpace($Source)) {
        return
    }

    if (-not (Test-Path -LiteralPath $Source)) {
        return
    }

    $parent = Split-Path -Parent $Destination
    if (-not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }

    Copy-Item -LiteralPath $Source -Destination $Destination -Force
}

function Export-FileTail {
    param(
        [AllowEmptyString()][string]$Source,
        [string]$Destination,
        [ValidateRange(1, 2000)][int]$Tail = 400
    )

    if ([string]::IsNullOrWhiteSpace($Source)) {
        return
    }

    if (-not (Test-Path -LiteralPath $Source)) {
        return
    }

    $parent = Split-Path -Parent $Destination
    if (-not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }

    $tailLines = @((Get-Content -LiteralPath $Source -Tail $Tail -ErrorAction SilentlyContinue) | ForEach-Object { [string]$_ })
    $tailText = [string]::Join("`n", $tailLines)
    if ($tailLines.Count -gt 0) {
        $tailText += "`n"
    }
    [System.IO.File]::WriteAllText($Destination, $tailText, [System.Text.UTF8Encoding]::new($false))
}

function Write-GuardLog {
    param([string]$Message)

    $safeMessage = Convert-ToSingleLineText -Text ([string]$Message)
    $line = "[AB-SESSION-GUARD] timestamp={0} {1}" -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'), $safeMessage
    Write-Output $line
    Write-GuardLogLineWithRetry -Line $line
}

function Write-GuardRawLine {
    param([string]$Message)

    if ([string]::IsNullOrWhiteSpace($Message)) {
        return
    }

    $safeMessage = Convert-ToSingleLineText -Text ([string]$Message)
    Write-Output $safeMessage
    Write-GuardLogLineWithRetry -Line $safeMessage
}

function Write-GuardLogLineWithRetry {
    param(
        [string]$Line,
        [ValidateRange(1, 8)][int]$MaxAttempts = 5
    )

    $lastError = ''
    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            $stream = [System.IO.File]::Open($script:GuardLogPath, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite)
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
            $lastError = Convert-ToSingleLineText -Text $_.Exception.Message
            if ($attempt -lt $MaxAttempts) {
                Start-Sleep -Milliseconds (40 * $attempt)
            }
        }
    }

    $now = Get-Date
    if ($null -eq $script:GuardLogWriteFailureLastReportAt -or (($now - $script:GuardLogWriteFailureLastReportAt).TotalSeconds -ge 60)) {
        $script:GuardLogWriteFailureLastReportAt = $now
        Write-Warning ("[AB-SESSION-GUARD] log_write_failed path={0} attempts={1} detail={2}" -f $script:GuardLogPath, $MaxAttempts, $lastError)
    }
}

function Write-GuardPastedBlock {
    param(
        [string]$Tag,
        [string[]]$Lines,
        [ValidateRange(12, 160)][int]$SeparatorWidth = 72
    )

    if ([string]::IsNullOrWhiteSpace($Tag)) {
        $Tag = 'guard_paste_block'
    }

    $normalized = @(
        @($Lines) |
            ForEach-Object { Convert-ToSingleLineText -Text ([string]$_) } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    )
    if ($normalized.Count -lt 1) {
        return
    }

    $separator = ('-' * $SeparatorWidth)
    Write-GuardLog ("{0}_begin" -f $Tag)
    Write-GuardRawLine -Message $separator
    foreach ($entry in $normalized) {
        Write-GuardLog ("{0} {1}" -f $Tag, $entry)
    }
    Write-GuardRawLine -Message $separator
    Write-GuardLog ("{0}_end" -f $Tag)
}

function Write-Utf8NoBomTextFileAtomically {
    param(
        [string]$Path,
        [AllowEmptyString()][string]$Text,
        [bool]$EmitBom = $false
    )

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $parent = Split-Path -Parent $fullPath
    $commitToken = ([guid]::NewGuid().ToString('N'))
    $tempPath = Join-Path $parent ('.{0}.{1}.{2}.tmp' -f (Split-Path -Leaf $fullPath), $PID, $commitToken)
    $backupPath = Join-Path $parent ('.{0}.{1}.{2}.bak' -f (Split-Path -Leaf $fullPath), $PID, $commitToken)
    try {
        [System.IO.File]::WriteAllText($tempPath, $Text, [System.Text.UTF8Encoding]::new($EmitBom))
        if ([System.IO.File]::Exists($fullPath)) {
            [System.IO.File]::Replace($tempPath, $fullPath, $backupPath)
        }
        else {
            [System.IO.File]::Move($tempPath, $fullPath)
        }
    }
    finally {
        if ([System.IO.File]::Exists($tempPath)) {
            [System.IO.File]::Delete($tempPath)
        }
        if ([System.IO.File]::Exists($backupPath)) {
            [System.IO.File]::Delete($backupPath)
        }
    }
}

function Write-GuardState {
    param([hashtable]$Values)

    foreach ($key in $Values.Keys) {
        $script:GuardState[$key] = $Values[$key]
    }
    $script:GuardState.updated_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')

    $json = $script:GuardState | ConvertTo-Json -Depth 8
    $maxAttempts = 8
    $writeSucceeded = $false
    $lastError = ''

    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        try {
            $normalizedJson = [string]$json -replace "`r`n", "`n"
            Write-Utf8NoBomTextFileAtomically -Path $script:GuardStatePath -Text $normalizedJson
            $writeSucceeded = $true
            break
        }
        catch {
            $lastError = Convert-ToSingleLineText -Text $_.Exception.Message
            if ($attempt -lt $maxAttempts) {
                $delayMs = switch ($attempt) {
                    1 { 40 }
                    2 { 80 }
                    3 { 120 }
                    4 { 200 }
                    5 { 300 }
                    default { 500 }
                }
                Start-Sleep -Milliseconds $delayMs
            }
        }
    }

    if ($writeSucceeded) {
        # Also write same content as live_status.json for backward compatibility
        try {
            $normalizedJsonLive = [string]$json -replace "`r`n", "`n"
            Write-Utf8NoBomTextFileAtomically -Path $script:LiveStatusPath -Text $normalizedJsonLive
        }
        catch {
            $null = $_
        }

        if (($script:GuardStateWriteFailureCount -as [int]) -gt 0) {
            Write-GuardLog ("state_write_recovered path={0} suppressed_failures={1}" -f $script:GuardStatePath, [int]$script:GuardStateWriteFailureCount)
            $script:GuardStateWriteFailureCount = 0
            $script:GuardStateWriteFailureSignature = ''
            $script:GuardStateWriteFailureLastReportAt = [datetime]::MinValue
        }
        return
    }

    $script:GuardStateWriteFailureCount = ([int]$script:GuardStateWriteFailureCount) + 1
    $signature = "{0}|{1}" -f $script:GuardStatePath, $lastError
    $now = Get-Date
    $shouldReport = $false

    if ($signature -ne [string]$script:GuardStateWriteFailureSignature) {
        $shouldReport = $true
    }
    elseif ($script:GuardStateWriteFailureLastReportAt -eq [datetime]::MinValue) {
        $shouldReport = $true
    }
    elseif ((($now - $script:GuardStateWriteFailureLastReportAt).TotalSeconds) -ge 120) {
        $shouldReport = $true
    }

    if ($shouldReport) {
        $script:GuardStateWriteFailureSignature = $signature
        $script:GuardStateWriteFailureLastReportAt = $now
        Write-Warning ("[AB-SESSION-GUARD] state_write_failed path={0} detail={1} failure_count={2}" -f $script:GuardStatePath, $lastError, [int]$script:GuardStateWriteFailureCount)
    }
}

function Add-AgentTicket {
    param(
        [bool]$Enabled,
        [AllowEmptyString()][string]$QueuePath,
        [string]$EventName,
        [string]$Severity,
        [bool]$RequiresConfirmation,
        [AllowEmptyString()][string]$SessionStatus,
        [AllowEmptyString()][string]$AStatus,
        [AllowEmptyString()][string]$BStatus,
        [AllowEmptyString()][string]$RunDirAnchor,
        [AllowEmptyString()][string]$IncidentDir,
        [AllowEmptyString()][string]$Detail,
        [AllowEmptyString()][string]$DedupSuffix,
        [AllowEmptyString()][string]$RecommendedAction,
        [AllowEmptyString()][string]$PreferredStage = '',
        [AllowEmptyString()][string]$MainRound = '',
        [AllowEmptyString()][string]$FailurePhase = '',
        [AllowEmptyString()][string]$FailureKind = '',
        [AllowEmptyString()][string]$FailureCategory = '',
        [AllowEmptyString()][string]$FailureSource = '',
        [AllowEmptyString()][string]$FailureEvidence = '',
        [bool]$SelfHealable = $false,
        [bool]$NonRecoverableEnv = $false,
        [AllowEmptyString()][string]$SelfHealHint = ''
    )

    $result = [ordered]@{
        Queued = $false
        TicketId = ''
        Reason = ''
        QueuePath = ''
    }

    if (-not $Enabled) {
        $result.Reason = 'queue-disabled'
        return [pscustomobject]$result
    }

    $eventNormalized = (Convert-ToSingleLineText -Text $EventName).ToLowerInvariant()
    $scriptSelfHealEnabled = $false
    try {
        $ticketPolicySettings = Read-KeyValueFile -Path $script:StartFilePath
        if ($ticketPolicySettings.Contains('LOCAL_GUARD_SCRIPT_SELF_HEAL_ENABLED')) {
            $scriptSelfHealEnabled = Convert-ToBooleanSetting -Value ([string]$ticketPolicySettings.LOCAL_GUARD_SCRIPT_SELF_HEAL_ENABLED) -Default $false
        }
    }
    catch {
        $scriptSelfHealEnabled = $false
    }
    $scriptFaultTicket = (
        (Convert-ToSingleLineText -Text $FailureCategory).ToLowerInvariant() -eq 'script-fault' -or
        (Convert-ToSingleLineText -Text $FailureKind).ToLowerInvariant() -in @('script-failure', 'script-edit-failure')
    )
    if ($scriptFaultTicket -and -not $scriptSelfHealEnabled) {
        $SelfHealable = $false
        $RecommendedAction = 'Script self-heal is disabled. Investigate read-only evidence, identify the root cause, and report a remediation proposal in chat. Do not edit files, control processes, restart, resume, mutate the environment, or create scripts.'
    }
    $faultActionTicket = $eventNormalized -notin @('running-status-report', 'a-pass-conclusion-b-started', 'chat-session-final-status')
    if ($faultActionTicket) {
        $livenessKnown = $false
        $aProcessSnapshot = $null
        $bProcessSnapshot = $null
        try {
            $ticketSettings = Read-KeyValueFile -Path $script:StartFilePath
            $ticketALaunchPid = if ($ticketSettings.Contains('A_LAUNCH_PID')) { Get-ParsedPositiveInt -Value ([string]$ticketSettings.A_LAUNCH_PID) } else { 0 }
            $ticketBLaunchPid = if ($ticketSettings.Contains('B_LAUNCH_PID')) { Get-ParsedPositiveInt -Value ([string]$ticketSettings.B_LAUNCH_PID) } else { 0 }
            $aProcessSnapshot = Get-StageBusinessProcessSnapshot -Stage 'A' -ExpectedProcessId $ticketALaunchPid
            $bProcessSnapshot = Get-StageBusinessProcessSnapshot -Stage 'B' -ExpectedProcessId $ticketBLaunchPid
            $livenessKnown = $true
        }
        catch {
            Write-GuardLog ("fault_action_ticket_wait event={0} reason=main-process-liveness-unknown detail={1}" -f $eventNormalized, (Convert-ToSingleLineText -Text $_.Exception.Message))
        }

        if (-not $livenessKnown -or [bool]$aProcessSnapshot.HasAliveProcess -or [bool]$bProcessSnapshot.HasAliveProcess) {
            $result.Reason = if ($livenessKnown) { 'main-process-running' } else { 'main-process-liveness-unknown' }
            $aAliveText = if ($null -ne $aProcessSnapshot) { [bool]$aProcessSnapshot.HasAliveProcess } else { 'unknown' }
            $aResolvedProcessId = if ($null -ne $aProcessSnapshot) { [int]$aProcessSnapshot.ResolvedProcessId } else { 0 }
            $bAliveText = if ($null -ne $bProcessSnapshot) { [bool]$bProcessSnapshot.HasAliveProcess } else { 'unknown' }
            $bResolvedProcessId = if ($null -ne $bProcessSnapshot) { [int]$bProcessSnapshot.ResolvedProcessId } else { 0 }
            Write-GuardLog ("fault_action_ticket_wait event={0} reason={1} a_alive={2} a_pid={3} b_alive={4} b_pid={5}" -f $eventNormalized, $result.Reason, $aAliveText, $aResolvedProcessId, $bAliveText, $bResolvedProcessId)
            return [pscustomobject]$result
        }

        Write-GuardLog ("fault_action_ticket_ready event={0} reason=all-main-processes-stopped" -f $eventNormalized)
    }

    $resolvedQueuePath = Resolve-RepoPathAllowMissing -Path $QueuePath
    if ([string]::IsNullOrWhiteSpace($resolvedQueuePath)) {
        $result.Reason = 'queue-path-empty'
        return [pscustomobject]$result
    }

    $detailCompact = Convert-ToBoundedSingleLineText -Text $Detail -MaxChars 360
    $incidentRel = ''
    if (-not [string]::IsNullOrWhiteSpace($IncidentDir)) {
        $incidentRel = Convert-ToRepoRelativePath -Path $IncidentDir
    }
    $eventCompact = Convert-ToSingleLineText -Text $EventName
    $recommendedActionMaxChars = if ($eventCompact.ToLowerInvariant() -eq 'running-status-report') { 2000 } else { 280 }
    $failurePhaseCompact = (Convert-ToSingleLineText -Text $FailurePhase).ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($failurePhaseCompact)) {
        $failurePhaseCompact = switch ((Convert-ToSingleLineText -Text $FailureKind).ToLowerInvariant()) {
            'task-definition-mismatch' { 'task-static' }
            'code-edit-failure' { 'code-step' }
            'compile-failure' { 'compile' }
            'compile-warning' { 'compile' }
            'verify-failure' { 'verify' }
            'environment-transient' { 'environment' }
            'script-edit-failure' { 'script' }
            'script-failure' { 'script' }
            default { 'unknown' }
        }
    }

    $signature = "{0}|{1}|{2}|{3}|{4}|{5}|{6}|{7}" -f
        $eventCompact,
        (Convert-ToSingleLineText -Text $SessionStatus),
        (Convert-ToSingleLineText -Text $AStatus),
        (Convert-ToSingleLineText -Text $BStatus),
        (Convert-ToSingleLineText -Text $RunDirAnchor),
        (Convert-ToSingleLineText -Text $incidentRel),
        (Convert-ToSingleLineText -Text $detailCompact),
        (Convert-ToSingleLineText -Text $DedupSuffix)

    if ($signature -eq [string]$script:AgentTicketLastSignature) {
        $result.Reason = 'duplicate-signature'
        $result.TicketId = [string]$script:AgentTicketLastId
        $result.QueuePath = (Convert-ToRepoRelativePath -Path $resolvedQueuePath)
        return [pscustomobject]$result
    }

    $ticketId = ("T{0}-{1}" -f (Get-Date).ToString('yyyyMMdd-HHmmssfff'), ([System.Guid]::NewGuid().ToString('N').Substring(0, 8)))
    $ticket = [ordered]@{
        schema = 'AB_AGENT_TICKET_V1'
        ticket_id = $ticketId
        created_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        source = 'unattended_ab_session_guard'
        event = $eventCompact
        severity = (Convert-ToSingleLineText -Text $Severity)
        requires_confirmation = [bool]$RequiresConfirmation
        confirmation_key = if ($RequiresConfirmation) { 'LOCAL_GUARD_RESTART_APPROVED' } else { '' }
        start_file = (Convert-ToRepoRelativePath -Path $script:StartFilePath)
        guard_log = (Convert-ToRepoRelativePath -Path $script:GuardLogPath)
        guard_state = (Convert-ToRepoRelativePath -Path $script:GuardStatePath)
        queue_path = (Convert-ToRepoRelativePath -Path $resolvedQueuePath)
        session_final_status = (Convert-ToSingleLineText -Text $SessionStatus)
        a_final_status = (Convert-ToSingleLineText -Text $AStatus)
        b_final_status = (Convert-ToSingleLineText -Text $BStatus)
        run_dir = (Convert-ToSingleLineText -Text $RunDirAnchor)
        incident_dir = (Convert-ToSingleLineText -Text $incidentRel)
        detail = $detailCompact
        recommended_action = (Convert-ToBoundedSingleLineText -Text $RecommendedAction -MaxChars $recommendedActionMaxChars)
        preferred_stage = (Convert-ToSingleLineText -Text $PreferredStage).ToUpperInvariant()
        main_round = (Convert-ToSingleLineText -Text $MainRound).ToUpperInvariant()
        failure_phase = $failurePhaseCompact
        failure_kind = (Convert-ToSingleLineText -Text $FailureKind).ToLowerInvariant()
        failure_category = (Convert-ToSingleLineText -Text $FailureCategory).ToLowerInvariant()
        failure_source = (Convert-ToSingleLineText -Text $FailureSource)
        failure_evidence = (Convert-ToBoundedSingleLineText -Text $FailureEvidence -MaxChars 260)
        self_healable = [bool]$SelfHealable
        script_self_heal_enabled = [bool]$scriptSelfHealEnabled
        script_fault_action_policy = if ($scriptFaultTicket -and -not $scriptSelfHealEnabled) { 'diagnose-only' } elseif ($scriptFaultTicket) { 'self-heal' } else { 'not-applicable' }
        non_recoverable_env = [bool]$NonRecoverableEnv
        self_heal_hint = if ([string]::IsNullOrWhiteSpace($SelfHealHint)) { '' } else { (Convert-ToBoundedSingleLineText -Text $SelfHealHint -MaxChars 120) }
        dedup_signature = $signature
    }

    $line = $ticket | ConvertTo-Json -Compress -Depth 8
    $appendOk = Write-JsonLineWithRetry -Path $resolvedQueuePath -Line $line
    if (-not $appendOk) {
        $result.Reason = 'queue-write-failed'
        $result.QueuePath = (Convert-ToRepoRelativePath -Path $resolvedQueuePath)
        Write-GuardLog ("agent_ticket_write_failed event={0} queue={1}" -f $ticket.event, $result.QueuePath)
        return [pscustomobject]$result
    }

    $script:AgentTicketLastSignature = $signature
    $script:AgentTicketLastId = $ticketId
    $script:AgentTicketLastEvent = [string]$ticket.event

    $result.Queued = $true
    $result.TicketId = $ticketId
    $result.Reason = 'queued'
    $result.QueuePath = (Convert-ToRepoRelativePath -Path $resolvedQueuePath)
    Write-GuardLog ("agent_ticket_queued id={0} event={1} severity={2} queue={3}" -f $ticketId, $ticket.event, $ticket.severity, $result.QueuePath)
    return [pscustomobject]$result
}

function Get-MonitorChainShutdownRequest {
    param([System.Collections.IDictionary]$Settings)

    $requestedRaw = ''
    $reason = ''
    $source = ''
    $requestedAt = ''
    $detail = ''

    if ($null -ne $Settings) {
        if ($Settings.Contains('MONITOR_CHAIN_SHUTDOWN_REQUESTED')) {
            $requestedRaw = [string]$Settings.MONITOR_CHAIN_SHUTDOWN_REQUESTED
        }
        if ($Settings.Contains('MONITOR_CHAIN_SHUTDOWN_REASON')) {
            $reason = Convert-ToSingleLineText -Text ([string]$Settings.MONITOR_CHAIN_SHUTDOWN_REASON)
        }
        if ($Settings.Contains('MONITOR_CHAIN_SHUTDOWN_SOURCE')) {
            $source = Convert-ToSingleLineText -Text ([string]$Settings.MONITOR_CHAIN_SHUTDOWN_SOURCE)
        }
        if ($Settings.Contains('MONITOR_CHAIN_SHUTDOWN_AT')) {
            $requestedAt = Convert-ToSingleLineText -Text ([string]$Settings.MONITOR_CHAIN_SHUTDOWN_AT)
        }
        if ($Settings.Contains('MONITOR_CHAIN_SHUTDOWN_DETAIL')) {
            $detail = Convert-ToBoundedSingleLineText -Text ([string]$Settings.MONITOR_CHAIN_SHUTDOWN_DETAIL) -MaxChars 220
        }
    }

    return [pscustomobject]@{
        Requested = (Convert-ToBooleanSetting -Value $requestedRaw -Default $false)
        Reason = $reason
        Source = $source
        RequestedAt = $requestedAt
        Detail = $detail
    }
}

function Request-MonitorChainShutdown {
    param(
        [System.Collections.IDictionary]$Settings,
        [string]$Reason,
        [string]$Source,
        [AllowEmptyString()][string]$Detail
    )

    $existing = Get-MonitorChainShutdownRequest -Settings $Settings
    if ([bool]$existing.Requested) {
        Write-GuardLog ("monitor_chain_shutdown_request already_set reason={0} source={1} at={2}" -f [string]$existing.Reason, [string]$existing.Source, [string]$existing.RequestedAt)
        return $Settings
    }

    $reasonCompact = Convert-ToSingleLineText -Text $Reason
    if ([string]::IsNullOrWhiteSpace($reasonCompact)) {
        $reasonCompact = 'guard-requested'
    }

    $sourceCompact = Convert-ToSingleLineText -Text $Source
    if ([string]::IsNullOrWhiteSpace($sourceCompact)) {
        $sourceCompact = 'unattended_ab_session_guard'
    }

    $detailCompact = Convert-ToBoundedSingleLineText -Text $Detail -MaxChars 280
    $updates = @{
        MONITOR_CHAIN_SHUTDOWN_REQUESTED = 'true'
        MONITOR_CHAIN_SHUTDOWN_REASON = $reasonCompact
        MONITOR_CHAIN_SHUTDOWN_SOURCE = $sourceCompact
        MONITOR_CHAIN_SHUTDOWN_AT = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        MONITOR_CHAIN_SHUTDOWN_KEEP_WINDOW = 'true'
    }
    if (-not [string]::IsNullOrWhiteSpace($detailCompact)) {
        $updates['MONITOR_CHAIN_SHUTDOWN_DETAIL'] = $detailCompact
    }

    Invoke-KeyValueFileValueUpdateCore -Path $script:StartFilePath -Values $updates
    Write-GuardLog ("monitor_chain_shutdown_request applied reason={0} source={1} detail={2}" -f $reasonCompact, $sourceCompact, $detailCompact)
    return (Read-KeyValueFileWithRetry -Path $script:StartFilePath)
}

function Get-StatusValue {
    param([AllowEmptyString()][string]$Value)

    return (Get-NormalizedStatusToken -Value $Value -Default 'NOT_RUN')
}

function Convert-ToNullablePositiveInt {
    param([AllowEmptyString()][string]$Value)

    $parsed = Get-ParsedPositiveInt -Value $Value
    if ($parsed -le 0) {
        return $null
    }

    return [int]$parsed
}

function Get-AStageProcessCandidateList {
    $startFileLeaf = [string]$script:StartFileLeaf
    $candidates = @(
        Get-CimInstance Win32_Process |
            Where-Object {
                $line = [string]$_.CommandLine
                if ([string]::IsNullOrWhiteSpace($line)) {
                    return $false
                }

                $lineLower = $line.ToLowerInvariant()
                if (-not [string]::IsNullOrWhiteSpace($startFileLeaf) -and -not $lineLower.Contains($startFileLeaf)) {
                    return $false
                }

                if ($lineLower.Contains('unattended_ab_session_guard.ps1') -or
                    $lineLower.Contains('open_unattended_ab_stage_window.ps1')) {
                    return $false
                }

                return ($lineLower -match 'start_dev_verify_fastmode_a\.ps1|start_dev_verify_8round_multiround\.ps1|one_click_release\.ps1')
            } |
            Select-Object ProcessId, Name, CreationDate, CommandLine |
            Sort-Object CreationDate, ProcessId -Descending
    )

    return @($candidates)
}

function Get-AStageProcessSnapshot {
    param([int]$ExpectedProcessId)

    $expectedAlive = Test-ProcessAlive -ProcessId $ExpectedProcessId
    $candidates = @(Get-AStageProcessCandidateList)
    $candidateIds = @($candidates | Select-Object -ExpandProperty ProcessId -Unique)

    $resolvedProcessId = 0
    $resolvedSource = 'none'

    if ($expectedAlive -and $ExpectedProcessId -gt 0) {
        $resolvedProcessId = [int]$ExpectedProcessId
        $resolvedSource = 'expected'
    }
    elseif ($candidateIds.Count -eq 1) {
        $resolvedProcessId = [int]$candidateIds[0]
        $resolvedSource = 'single-candidate'
    }
    elseif ($candidateIds.Count -gt 1) {
        $resolvedSource = 'ambiguous-candidates'
    }

    $hasAliveProcess = $expectedAlive -or ($candidateIds.Count -gt 0)
    $anchorUpdateRequired = ($resolvedProcessId -gt 0 -and $resolvedProcessId -ne $ExpectedProcessId)

    return [pscustomobject]@{
        ExpectedProcessId = [int]$ExpectedProcessId
        ExpectedAlive = [bool]$expectedAlive
        CandidateCount = [int]$candidateIds.Count
        CandidateIds = @($candidateIds)
        ResolvedProcessId = [int]$resolvedProcessId
        ResolvedSource = [string]$resolvedSource
        HasAliveProcess = [bool]$hasAliveProcess
        AnchorUpdateRequired = [bool]$anchorUpdateRequired
    }
}

function Get-BStageProcessCandidateList {
    $startFileLeaf = [string]$script:StartFileLeaf
    $candidates = @(
        Get-CimInstance Win32_Process |
            Where-Object {
                $line = [string]$_.CommandLine
                if ([string]::IsNullOrWhiteSpace($line)) {
                    return $false
                }

                $lineLower = $line.ToLowerInvariant()
                if (-not [string]::IsNullOrWhiteSpace($startFileLeaf) -and -not $lineLower.Contains($startFileLeaf)) {
                    return $false
                }

                if ($lineLower.Contains('unattended_ab_session_guard.ps1') -or
                    $lineLower.Contains('open_unattended_ab_stage_window.ps1')) {
                    return $false
                }

                return ($lineLower -match 'start_dev_verify_fastmode_b\.ps1|start_dev_verify_8round_multiround\.ps1|one_click_release\.ps1')
            } |
            Select-Object ProcessId, Name, CreationDate, CommandLine |
            Sort-Object CreationDate, ProcessId -Descending
    )

    return @($candidates)
}

function Get-BStageProcessSnapshot {
    param([int]$ExpectedProcessId)

    $expectedAlive = Test-ProcessAlive -ProcessId $ExpectedProcessId
    $candidates = @(Get-BStageProcessCandidateList)
    $candidateIds = @($candidates | Select-Object -ExpandProperty ProcessId -Unique)

    $resolvedProcessId = 0
    $resolvedSource = 'none'

    if ($expectedAlive -and $ExpectedProcessId -gt 0) {
        $resolvedProcessId = [int]$ExpectedProcessId
        $resolvedSource = 'expected'
    }
    elseif ($candidateIds.Count -eq 1) {
        $resolvedProcessId = [int]$candidateIds[0]
        $resolvedSource = 'single-candidate'
    }
    elseif ($candidateIds.Count -gt 1) {
        $resolvedSource = 'ambiguous-candidates'
    }

    $hasAliveProcess = $expectedAlive -or ($candidateIds.Count -gt 0)
    $anchorUpdateRequired = ($resolvedProcessId -gt 0 -and $resolvedProcessId -ne $ExpectedProcessId)

    return [pscustomobject]@{
        ExpectedProcessId = [int]$ExpectedProcessId
        ExpectedAlive = [bool]$expectedAlive
        CandidateCount = [int]$candidateIds.Count
        CandidateIds = @($candidateIds)
        ResolvedProcessId = [int]$resolvedProcessId
        ResolvedSource = [string]$resolvedSource
        HasAliveProcess = [bool]$hasAliveProcess
        AnchorUpdateRequired = [bool]$anchorUpdateRequired
    }
}

function Get-StageExitReasonArtifactPath {
    param([string]$Stage)

    $stageLower = $Stage.Trim().ToLowerInvariant()
    return (Join-Path $script:RepoRoot (Join-Path 'out\artifacts\ab_stage_exit' ("latest_{0}_exit.json" -f $stageLower)))
}

function Get-BStageExitReasonEvidence {
    param([int]$ExpectedProcessId)

    $artifactPath = Get-StageExitReasonArtifactPath -Stage 'B'
    $result = [ordered]@{
        Available = $false
        ArtifactPath = (Convert-ToRepoRelativePath -Path $artifactPath)
        Stage = 'B'
        ProcessId = 0
        ExitCode = 0
        Result = ''
        FailCategory = ''
        FailReason = ''
        GeneratedAt = ''
        StartFilePath = ''
        RuntimeLogPath = ''
        TaskDefinitionPath = ''
        SourceScript = ''
        LaunchToken = ''
        StartFileMatch = $false
        ProcessIdMatch = $false
        LaunchTokenMatch = $false
        ParseError = ''
    }

    if (-not (Test-Path -LiteralPath $artifactPath)) {
        return [pscustomobject]$result
    }

    $payload = $null
    try {
        $payloadRaw = Get-Content -LiteralPath $artifactPath -Raw -Encoding utf8 -ErrorAction Stop
        $payload = $payloadRaw | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        $result.ParseError = Convert-ToSingleLineText -Text $_.Exception.Message
        return [pscustomobject]$result
    }

    $result.Available = $true

    if ($payload.PSObject.Properties.Name -contains 'stage') {
        $result.Stage = (Convert-ToSingleLineText -Text ([string]$payload.stage)).ToUpperInvariant()
    }

    if ($payload.PSObject.Properties.Name -contains 'process_id') {
        $parsedPid = Convert-ToNullablePositiveInt -Value ([string]$payload.process_id)
        if ($null -ne $parsedPid) {
            $result.ProcessId = [int]$parsedPid
        }
    }

    if ($payload.PSObject.Properties.Name -contains 'exit_code') {
        $parsedExitCode = 0
        if ([int]::TryParse(([string]$payload.exit_code), [ref]$parsedExitCode)) {
            $result.ExitCode = [int]$parsedExitCode
        }
    }

    if ($payload.PSObject.Properties.Name -contains 'result') {
        $result.Result = (Convert-ToSingleLineText -Text ([string]$payload.result)).ToLowerInvariant()
    }

    if ($payload.PSObject.Properties.Name -contains 'fail_category') {
        $result.FailCategory = Convert-ToSingleLineText -Text ([string]$payload.fail_category)
    }

    if ($payload.PSObject.Properties.Name -contains 'fail_reason') {
        $result.FailReason = Convert-ToSingleLineText -Text ([string]$payload.fail_reason)
    }

    if ($payload.PSObject.Properties.Name -contains 'generated_at') {
        $result.GeneratedAt = Convert-ToSingleLineText -Text ([string]$payload.generated_at)
    }

    $artifactStartFilePath = ''
    if ($payload.PSObject.Properties.Name -contains 'start_file_path') {
        $artifactStartFilePath = Convert-ToSingleLineText -Text ([string]$payload.start_file_path)
        $result.StartFilePath = $artifactStartFilePath
    }

    if ($payload.PSObject.Properties.Name -contains 'runtime_log_path') {
        $result.RuntimeLogPath = Convert-ToSingleLineText -Text ([string]$payload.runtime_log_path)
    }

    if ($payload.PSObject.Properties.Name -contains 'task_definition') {
        $result.TaskDefinitionPath = Convert-ToSingleLineText -Text ([string]$payload.task_definition)
    }

    if ($payload.PSObject.Properties.Name -contains 'source_script') {
        $result.SourceScript = Convert-ToSingleLineText -Text ([string]$payload.source_script)
    }

    if ($payload.PSObject.Properties.Name -contains 'launch_token') {
        $result.LaunchToken = Convert-ToSingleLineText -Text ([string]$payload.launch_token)
    }

    if ([string]::IsNullOrWhiteSpace($artifactStartFilePath)) {
        $result.StartFileMatch = $true
    }
    else {
        try {
            $expectedStartFile = [System.IO.Path]::GetFullPath($script:StartFilePath)
            $artifactStartFile = [System.IO.Path]::GetFullPath($artifactStartFilePath)
            $result.StartFileMatch = $artifactStartFile.Equals($expectedStartFile, [System.StringComparison]::OrdinalIgnoreCase)
        }
        catch {
            $result.StartFileMatch = $false
        }
    }

    $expectedLaunchToken = ''
    try {
        $currentSettings = Read-KeyValueFile -Path $script:StartFilePath
        if ($currentSettings.Contains('B_LAUNCH_TOKEN')) {
            $expectedLaunchToken = Convert-ToSingleLineText -Text ([string]$currentSettings.B_LAUNCH_TOKEN)
        }
    }
    catch {
        $expectedLaunchToken = ''
    }
    $result.LaunchTokenMatch = if ([string]::IsNullOrWhiteSpace($expectedLaunchToken)) {
        $true
    }
    else {
        -not [string]::IsNullOrWhiteSpace([string]$result.LaunchToken) -and
        [string]$result.LaunchToken -eq $expectedLaunchToken
    }
    $result.ProcessIdMatch = (
        $ExpectedProcessId -gt 0 -and
        [int]$result.ProcessId -eq $ExpectedProcessId -and
        [bool]$result.LaunchTokenMatch
    )
    return [pscustomobject]$result
}

function Get-AStageExitReasonEvidence {
    param([int]$ExpectedProcessId)

    $artifactPath = Get-StageExitReasonArtifactPath -Stage 'A'
    $result = [ordered]@{
        Available = $false
        ArtifactPath = (Convert-ToRepoRelativePath -Path $artifactPath)
        Stage = 'A'
        ProcessId = 0
        ExitCode = 0
        Result = ''
        FailCategory = ''
        FailReason = ''
        GeneratedAt = ''
        StartFilePath = ''
        RuntimeLogPath = ''
        TaskDefinitionPath = ''
        SourceScript = ''
        StartFileMatch = $false
        ProcessIdMatch = $false
        ParseError = ''
    }

    if (-not (Test-Path -LiteralPath $artifactPath)) {
        return [pscustomobject]$result
    }

    $payload = $null
    try {
        $payloadRaw = Get-Content -LiteralPath $artifactPath -Raw -Encoding utf8 -ErrorAction Stop
        $payload = $payloadRaw | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        $result.ParseError = Convert-ToSingleLineText -Text $_.Exception.Message
        return [pscustomobject]$result
    }

    $result.Available = $true

    if ($payload.PSObject.Properties.Name -contains 'stage') {
        $result.Stage = (Convert-ToSingleLineText -Text ([string]$payload.stage)).ToUpperInvariant()
    }

    if ($payload.PSObject.Properties.Name -contains 'process_id') {
        $parsedPid = Convert-ToNullablePositiveInt -Value ([string]$payload.process_id)
        if ($null -ne $parsedPid) {
            $result.ProcessId = [int]$parsedPid
        }
    }

    if ($payload.PSObject.Properties.Name -contains 'exit_code') {
        $parsedExitCode = 0
        if ([int]::TryParse(([string]$payload.exit_code), [ref]$parsedExitCode)) {
            $result.ExitCode = [int]$parsedExitCode
        }
    }

    if ($payload.PSObject.Properties.Name -contains 'result') {
        $result.Result = (Convert-ToSingleLineText -Text ([string]$payload.result)).ToLowerInvariant()
    }

    if ($payload.PSObject.Properties.Name -contains 'fail_category') {
        $result.FailCategory = Convert-ToSingleLineText -Text ([string]$payload.fail_category)
    }

    if ($payload.PSObject.Properties.Name -contains 'fail_reason') {
        $result.FailReason = Convert-ToSingleLineText -Text ([string]$payload.fail_reason)
    }

    if ($payload.PSObject.Properties.Name -contains 'generated_at') {
        $result.GeneratedAt = Convert-ToSingleLineText -Text ([string]$payload.generated_at)
    }

    $artifactStartFilePath = ''
    if ($payload.PSObject.Properties.Name -contains 'start_file_path') {
        $artifactStartFilePath = Convert-ToSingleLineText -Text ([string]$payload.start_file_path)
        $result.StartFilePath = $artifactStartFilePath
    }

    if ($payload.PSObject.Properties.Name -contains 'runtime_log_path') {
        $result.RuntimeLogPath = Convert-ToSingleLineText -Text ([string]$payload.runtime_log_path)
    }

    if ($payload.PSObject.Properties.Name -contains 'task_definition') {
        $result.TaskDefinitionPath = Convert-ToSingleLineText -Text ([string]$payload.task_definition)
    }

    if ($payload.PSObject.Properties.Name -contains 'source_script') {
        $result.SourceScript = Convert-ToSingleLineText -Text ([string]$payload.source_script)
    }

    if ([string]::IsNullOrWhiteSpace($artifactStartFilePath)) {
        $result.StartFileMatch = $true
    }
    else {
        try {
            $expectedStartFile = [System.IO.Path]::GetFullPath($script:StartFilePath)
            $artifactStartFile = [System.IO.Path]::GetFullPath($artifactStartFilePath)
            $result.StartFileMatch = $artifactStartFile.Equals($expectedStartFile, [System.StringComparison]::OrdinalIgnoreCase)
        }
        catch {
            $result.StartFileMatch = $false
        }
    }

    $result.ProcessIdMatch = ($ExpectedProcessId -gt 0 -and [int]$result.ProcessId -eq $ExpectedProcessId)
    return [pscustomobject]$result
}

function Get-StageBusinessProcessSnapshot {
    param(
        [ValidateSet('A', 'B')][string]$Stage,
        [int]$ExpectedProcessId
    )

    $rawSnapshot = if ($Stage -eq 'B') {
        Get-BStageProcessSnapshot -ExpectedProcessId $ExpectedProcessId
    }
    else {
        Get-AStageProcessSnapshot -ExpectedProcessId $ExpectedProcessId
    }
    $exitEvidence = if ($Stage -eq 'B') {
        Get-BStageExitReasonEvidence -ExpectedProcessId $ExpectedProcessId
    }
    else {
        Get-AStageExitReasonEvidence -ExpectedProcessId $ExpectedProcessId
    }

    $artifactProcessId = if ($null -ne $exitEvidence) { [int]$exitEvidence.ProcessId } else { 0 }
    $artifactMatchesCandidate = ($artifactProcessId -gt 0 -and @($rawSnapshot.CandidateIds) -contains $artifactProcessId)
    $artifactFresh = $false
    if ($null -ne $exitEvidence -and -not [string]::IsNullOrWhiteSpace([string]$exitEvidence.GeneratedAt)) {
        $artifactGeneratedAt = [datetime]::MinValue
        if ([datetime]::TryParse(([string]$exitEvidence.GeneratedAt), [ref]$artifactGeneratedAt)) {
            $artifactAgeMinutes = ((Get-Date) - $artifactGeneratedAt).TotalMinutes
            $artifactFresh = ($artifactAgeMinutes -ge -1 -and $artifactAgeMinutes -le 10)
        }
    }
    $terminalExitConfirmed = (
        $null -ne $exitEvidence -and
        [bool]$exitEvidence.Available -and
        [bool]$exitEvidence.StartFileMatch -and
        $artifactFresh -and
        [string]$exitEvidence.Result -in @('pass', 'fail') -and
        ([bool]$exitEvidence.ProcessIdMatch -or $artifactMatchesCandidate)
    )

    $remainingCandidateIds = @($rawSnapshot.CandidateIds)
    $expectedAlive = [bool]$rawSnapshot.ExpectedAlive
    if ($terminalExitConfirmed) {
        $remainingCandidateIds = @($remainingCandidateIds | Where-Object { [int]$_ -ne $artifactProcessId })
        if ($ExpectedProcessId -eq $artifactProcessId) {
            $expectedAlive = $false
        }
    }

    $resolvedProcessId = if ($expectedAlive -and $ExpectedProcessId -gt 0) {
        $ExpectedProcessId
    }
    elseif ($remainingCandidateIds.Count -gt 0) {
        [int]$remainingCandidateIds[0]
    }
    else {
        0
    }

    return [pscustomobject]@{
        HasAliveProcess = [bool]($expectedAlive -or $remainingCandidateIds.Count -gt 0)
        ResolvedProcessId = [int]$resolvedProcessId
        CandidateCount = [int]$remainingCandidateIds.Count
        CandidateIds = @($remainingCandidateIds)
        ResolvedSource = if ($terminalExitConfirmed) { 'terminal-exit-artifact-filtered' } else { [string]$rawSnapshot.ResolvedSource }
        TerminalExitConfirmed = [bool]$terminalExitConfirmed
    }
}

function Get-BPassFailConflictEvidence {
    param(
        [System.Collections.IDictionary]$Settings,
        [string]$StartFilePath
    )

    $artifactPath = Get-StageExitReasonArtifactPath -Stage 'B'
    $result = [ordered]@{
        conflict = $false
        reason = 'status-not-pass'
        artifact_path = (Convert-ToRepoRelativePath -Path $artifactPath)
        stage = ''
        exit_result = ''
        exit_code = -1
        process_id = 0
        process_id_match = $true
        start_file_match = $true
        generated_at = ''
        fresh = $false
        fail_category = ''
        fail_reason = ''
    }

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

    if ($sessionStatus -ne 'PASS' -or $aStatus -ne 'PASS' -or $bStatus -ne 'PASS') {
        return [pscustomobject]$result
    }

    if (-not (Test-Path -LiteralPath $artifactPath)) {
        $result.reason = 'artifact-missing'
        return [pscustomobject]$result
    }

    $payload = Read-JsonFileSafely -Path $artifactPath
    if ($null -eq $payload) {
        $result.reason = 'artifact-parse-failed'
        return [pscustomobject]$result
    }

    $result.stage = (Convert-ToSingleLineText -Text ([string]$payload.stage)).ToUpperInvariant()
    if ([string]$result.stage -ne 'B') {
        $result.reason = 'stage-mismatch'
        return [pscustomobject]$result
    }

    $result.exit_result = (Convert-ToSingleLineText -Text ([string]$payload.result)).ToLowerInvariant()
    if ([string]$result.exit_result -ne 'fail') {
        $result.reason = 'result-not-fail'
        return [pscustomobject]$result
    }

    $exitCodeValue = -1
    if ([int]::TryParse(([string]$payload.exit_code), [ref]$exitCodeValue)) {
        $result.exit_code = [int]$exitCodeValue
    }

    $processIdValue = Convert-ToNullablePositiveInt -Value ([string]$payload.process_id)
    if ($null -ne $processIdValue) {
        $result.process_id = [int]$processIdValue
    }

    $expectedProcessId = 0
    if ($null -ne $Settings -and $Settings.Contains('B_LAUNCH_PID')) {
        $parsedExpectedPid = Convert-ToNullablePositiveInt -Value ([string]$Settings.B_LAUNCH_PID)
        if ($null -ne $parsedExpectedPid) {
            $expectedProcessId = [int]$parsedExpectedPid
        }
    }

    if ($expectedProcessId -gt 0) {
        $result.process_id_match = ([int]$result.process_id -eq $expectedProcessId)
    }

    if (-not [bool]$result.process_id_match) {
        $result.reason = 'pid-mismatch'
        return [pscustomobject]$result
    }

    $startFileArtifact = Convert-ToSingleLineText -Text ([string]$payload.start_file_path)
    if (-not [string]::IsNullOrWhiteSpace($startFileArtifact)) {
        try {
            $expectedStart = [System.IO.Path]::GetFullPath($StartFilePath)
            $artifactStart = [System.IO.Path]::GetFullPath($startFileArtifact)
            $result.start_file_match = $artifactStart.Equals($expectedStart, [System.StringComparison]::OrdinalIgnoreCase)
        }
        catch {
            $result.start_file_match = $false
        }
    }

    if (-not [bool]$result.start_file_match) {
        $result.reason = 'start-file-mismatch'
        return [pscustomobject]$result
    }

    $notes = ''
    if ($null -ne $Settings -and $Settings.Contains('SESSION_FINAL_NOTES')) {
        $notes = [string]$Settings.SESSION_FINAL_NOTES
    }

    $runDirAnchor = Resolve-RunDirAnchorFromNotes -Notes $notes
    $runDirResolved = Resolve-AnchorPath -Path $runDirAnchor

    $result.generated_at = Convert-ToSingleLineText -Text ([string]$payload.generated_at)
    $generatedUtc = [datetime]::MinValue
    $parsedGenerated = [datetime]::TryParse(
        [string]$result.generated_at,
        [System.Globalization.CultureInfo]::InvariantCulture,
        [System.Globalization.DateTimeStyles]::AllowWhiteSpaces -bor [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal,
        [ref]$generatedUtc)
    if (-not $parsedGenerated) {
        $parsedGenerated = [datetime]::TryParse([string]$result.generated_at, [ref]$generatedUtc)
        if ($parsedGenerated) {
            $generatedUtc = $generatedUtc.ToUniversalTime()
        }
    }

    if (-not $parsedGenerated) {
        $result.reason = 'generated-at-invalid'
        return [pscustomobject]$result
    }

    if (-not [string]::IsNullOrWhiteSpace($runDirResolved) -and (Test-Path -LiteralPath $runDirResolved)) {
        $runCreatedUtc = (Get-Item -LiteralPath $runDirResolved).CreationTimeUtc
        $result.fresh = ([datetime]$generatedUtc -ge [datetime]$runCreatedUtc.AddMinutes(-2))
    }
    else {
        $ageMinutes = ((Get-Date).ToUniversalTime() - [datetime]$generatedUtc).TotalMinutes
        $result.fresh = ($ageMinutes -ge 0 -and $ageMinutes -le 240)
    }

    if (-not [bool]$result.fresh) {
        $result.reason = 'artifact-not-fresh'
        return [pscustomobject]$result
    }

    $result.fail_category = Convert-ToSingleLineText -Text ([string]$payload.fail_category)
    $result.fail_reason = Convert-ToSingleLineText -Text ([string]$payload.fail_reason)
    $result.conflict = $true
    $result.reason = 'conflict-detected'
    return [pscustomobject]$result
}

function Get-BRuntimeLogHint {
    param(
        [System.Collections.IDictionary]$Settings,
        [AllowEmptyString()][string]$ArtifactRuntimeLogPath
    )

    if (-not [string]::IsNullOrWhiteSpace($ArtifactRuntimeLogPath)) {
        return $ArtifactRuntimeLogPath
    }

    if ($null -ne $Settings -and $Settings.Contains('B_RUNTIME_LOG')) {
        $value = Convert-ToSingleLineText -Text ([string]$Settings.B_RUNTIME_LOG)
        if (-not [string]::IsNullOrWhiteSpace($value)) {
            return $value
        }
    }

    $notes = ''
    if ($null -ne $Settings -and $Settings.Contains('SESSION_FINAL_NOTES')) {
        $notes = [string]$Settings.SESSION_FINAL_NOTES
    }

    $anchor = Get-LatestAnchorValueFromNoteText -Notes $notes -Key 'b_runtime_log'
    if (-not [string]::IsNullOrWhiteSpace($anchor)) {
        return $anchor
    }

    return ''
}

function Resolve-RunDirFromRuntimeLog {
    param([AllowEmptyString()][string]$RuntimeLogPath)

    $resolvedRuntimeLog = Resolve-AnchorPath -Path $RuntimeLogPath
    if ([string]::IsNullOrWhiteSpace($resolvedRuntimeLog) -or -not (Test-Path -LiteralPath $resolvedRuntimeLog)) {
        return ''
    }

    try {
        $outDirLine = @(Get-Content -LiteralPath $resolvedRuntimeLog -Encoding utf8 -Tail 220 -ErrorAction Stop | Where-Object {
            [string]$_ -match '^\[DEV-VERIFY-MULTI\]\s+out_dir=(.+)$'
        } | Select-Object -Last 1)
        if ($outDirLine.Count -lt 1) {
            return ''
        }

        $line = Convert-ToSingleLineText -Text ([string]$outDirLine[0])
        if ($line -notmatch '^\[DEV-VERIFY-MULTI\]\s+out_dir=(.+)$') {
            return ''
        }

        $candidate = Resolve-AnchorPath -Path ($Matches[1].Trim())
        if ([string]::IsNullOrWhiteSpace($candidate) -or -not (Test-Path -LiteralPath $candidate)) {
            return ''
        }

        return (Convert-ToRepoRelativePath -Path $candidate)
    }
    catch {
        return ''
    }
}

function Resolve-RunDirFromStageExitReasonText {
    param([AllowEmptyString()][string]$FailReason)

    $reason = Convert-ToSingleLineText -Text $FailReason
    if ([string]::IsNullOrWhiteSpace($reason)) {
        return ''
    }

    $candidatePaths = New-Object 'System.Collections.Generic.List[string]'
    foreach ($pattern in @('final_status=(\S*final_status\.json)', 'source=(\S+\.(?:log|json|txt))')) {
        $matches = [regex]::Matches($reason, $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        foreach ($match in $matches) {
            if ($match.Groups.Count -gt 1) {
                $candidate = Convert-ToSingleLineText -Text ([string]$match.Groups[1].Value)
                if (-not [string]::IsNullOrWhiteSpace($candidate)) {
                    [void]$candidatePaths.Add($candidate.Trim('"', "'"))
                }
            }
        }
    }

    foreach ($candidatePath in $candidatePaths) {
        $resolvedPath = Resolve-AnchorPath -Path $candidatePath
        if ([string]::IsNullOrWhiteSpace($resolvedPath) -or -not (Test-Path -LiteralPath $resolvedPath)) {
            continue
        }

        $runDir = Split-Path -Parent $resolvedPath
        if ([string]::IsNullOrWhiteSpace($runDir) -or -not (Test-Path -LiteralPath $runDir)) {
            continue
        }

        return (Convert-ToRepoRelativePath -Path $runDir)
    }

    return ''
}

function Test-StageExitReasonEvidenceUsableForRunDir {
    param(
        [object]$ExitReasonEvidence,
        [int]$ExpectedProcessId
    )

    if ($null -eq $ExitReasonEvidence) { return $false }
    if (-not [bool]$ExitReasonEvidence.Available) { return $false }
    if (-not [bool]$ExitReasonEvidence.StartFileMatch) { return $false }
    if ([string]$ExitReasonEvidence.Result -notin @('pass', 'fail')) { return $false }
    if ($ExpectedProcessId -gt 0) { return [bool]$ExitReasonEvidence.ProcessIdMatch }

    $generatedAt = [datetime]::MinValue
    if (-not [datetime]::TryParse(([string]$ExitReasonEvidence.GeneratedAt), [ref]$generatedAt)) {
        return $false
    }

    $ageMinutes = ((Get-Date) - $generatedAt).TotalMinutes
    return ($ageMinutes -ge -1 -and $ageMinutes -le 30)
}

function Resolve-RunDirFromStageExitReasonEvidence {
    param(
        [object]$ExitReasonEvidence,
        [int]$ExpectedProcessId
    )

    if (-not (Test-StageExitReasonEvidenceUsableForRunDir -ExitReasonEvidence $ExitReasonEvidence -ExpectedProcessId $ExpectedProcessId)) {
        return ''
    }

    $artifactRunDir = Resolve-RunDirFromRuntimeLog -RuntimeLogPath ([string]$ExitReasonEvidence.RuntimeLogPath)
    if (-not [string]::IsNullOrWhiteSpace($artifactRunDir)) {
        return $artifactRunDir
    }

    return (Resolve-RunDirFromStageExitReasonText -FailReason ([string]$ExitReasonEvidence.FailReason))
}

function Resolve-RunDirAnchorForFailurePolicy {
    param(
        [System.Collections.IDictionary]$Settings,
        [AllowEmptyString()][string]$CurrentRunDirAnchor,
        [AllowEmptyString()][string]$AStatus = '',
        [AllowEmptyString()][string]$BStatus = '',
        [int]$ALaunchPid = 0,
        [int]$BLaunchPid
    )

    $resolvedRunDirAnchor = Convert-ToSingleLineText -Text $CurrentRunDirAnchor
    if (-not [string]::IsNullOrWhiteSpace($resolvedRunDirAnchor)) {
        return $resolvedRunDirAnchor
    }

    $normalizedA = Get-StatusValue -Value $AStatus
    $normalizedB = Get-StatusValue -Value $BStatus

    if ($normalizedA -in @('FAIL', 'BLOCKED') -and $normalizedB -ne 'RUNNING') {
        $aExitEvidence = Get-AStageExitReasonEvidence -ExpectedProcessId $ALaunchPid
        $aArtifactRunDir = Resolve-RunDirFromStageExitReasonEvidence -ExitReasonEvidence $aExitEvidence -ExpectedProcessId $ALaunchPid
        if (-not [string]::IsNullOrWhiteSpace($aArtifactRunDir)) {
            return $aArtifactRunDir
        }
    }

    if ($normalizedB -in @('FAIL', 'BLOCKED') -or $BLaunchPid -gt 0) {
        $bExitEvidence = Get-BStageExitReasonEvidence -ExpectedProcessId $BLaunchPid
        $bArtifactRunDir = Resolve-RunDirFromStageExitReasonEvidence -ExitReasonEvidence $bExitEvidence -ExpectedProcessId $BLaunchPid
        if (-not [string]::IsNullOrWhiteSpace($bArtifactRunDir)) {
            return $bArtifactRunDir
        }
    }

    return $resolvedRunDirAnchor
}

function Get-BRuntimeTailEvidence {
    param(
        [AllowEmptyString()][string]$RuntimeLogPath,
        [ValidateRange(5, 200)][int]$PrimaryTail = 10,
        [ValidateRange(10, 400)][int]$ExpandedTail = 30,
        [ValidateRange(20, 1000)][int]$MaxTail = 80,
        [ValidateRange(1, 50)][int]$MinimumUsefulLines = 6
    )

    $result = [ordered]@{
        Available = $false
        RuntimeLogPath = ''
        UsedTail = 0
        Escalated = $false
        Lines = @()
        Error = ''
    }

    if ([string]::IsNullOrWhiteSpace($RuntimeLogPath)) {
        return [pscustomobject]$result
    }

    $resolvedPath = Resolve-AnchorPath -Path $RuntimeLogPath
    if ([string]::IsNullOrWhiteSpace($resolvedPath)) {
        $result.Error = 'resolve-log-path-failed'
        return [pscustomobject]$result
    }

    $result.RuntimeLogPath = Convert-ToRepoRelativePath -Path $resolvedPath
    if (-not (Test-Path -LiteralPath $resolvedPath)) {
        $result.Error = 'runtime-log-not-found'
        return [pscustomobject]$result
    }

    $tailCandidates = @($PrimaryTail, $ExpandedTail, $MaxTail)
    $bestLines = @()
    $usedTail = $PrimaryTail

    foreach ($tail in $tailCandidates) {
        if ($tail -le 0) {
            continue
        }

        try {
            $rawTail = @(Get-Content -LiteralPath $resolvedPath -Tail $tail -ErrorAction Stop)
            $filteredTail = @(Get-FilteredRuntimeTailLineList -Lines $rawTail)
            if ($filteredTail.Count -eq 0) {
                $filteredTail = @($rawTail | ForEach-Object { Convert-ToSingleLineText -Text ([string]$_) } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
            }

            $bestLines = @($filteredTail)
            $usedTail = $tail

            if ($bestLines.Count -ge $MinimumUsefulLines) {
                break
            }
        }
        catch {
            $result.Error = Convert-ToSingleLineText -Text $_.Exception.Message
            return [pscustomobject]$result
        }
    }

    $result.UsedTail = [int]$usedTail
    $result.Escalated = ([int]$usedTail -gt [int]$PrimaryTail)
    $result.Lines = @($bestLines)
    $result.Available = ($bestLines.Count -gt 0)
    return [pscustomobject]$result
}

function Format-AgeMinutesForLog {
    param([double]$AgeMinutes)

    if ([double]::IsNaN($AgeMinutes) -or [double]::IsInfinity($AgeMinutes) -or $AgeMinutes -lt 0) {
        return 'n/a'
    }

    return ([Math]::Round($AgeMinutes, 1).ToString('0.0'))
}

function Get-PathFreshnessEvidence {
    param(
        [AllowEmptyString()][string]$Path,
        [ValidateRange(1, 180)][int]$WindowMinutes = 6
    )

    $result = [ordered]@{
        Exists = $false
        Fresh = $false
        AgeMinutes = -1.0
        Path = ''
        ResolvedPath = ''
    }

    $resolvedPath = Resolve-AnchorPath -Path $Path
    if ([string]::IsNullOrWhiteSpace($resolvedPath)) {
        return [pscustomobject]$result
    }

    $result.ResolvedPath = $resolvedPath
    $result.Path = Convert-ToRepoRelativePath -Path $resolvedPath

    if (-not (Test-Path -LiteralPath $resolvedPath)) {
        return [pscustomobject]$result
    }

    try {
        $item = Get-Item -LiteralPath $resolvedPath -ErrorAction Stop
        $ageMinutes = ((Get-Date) - $item.LastWriteTime).TotalMinutes
        $result.Exists = $true
        $result.AgeMinutes = [double]$ageMinutes
        $result.Fresh = ($ageMinutes -le $WindowMinutes)
    }
    catch { Write-Verbose ("Suppressed exception: {0}" -f $_.Exception.Message) }

    return [pscustomobject]$result
}

function Get-RunDirFreshnessEvidence {
    param(
        [AllowEmptyString()][string]$RunDirPath,
        [ValidateRange(1, 180)][int]$WindowMinutes = 6
    )

    $result = [ordered]@{
        Exists = $false
        Fresh = $false
        AgeMinutes = -1.0
        Path = ''
        ResolvedPath = ''
    }

    $resolvedPath = Resolve-AnchorPath -Path $RunDirPath
    if ([string]::IsNullOrWhiteSpace($resolvedPath)) {
        return [pscustomobject]$result
    }

    $result.ResolvedPath = $resolvedPath
    $result.Path = Convert-ToRepoRelativePath -Path $resolvedPath

    if (-not (Test-Path -LiteralPath $resolvedPath)) {
        return [pscustomobject]$result
    }

    try {
        $latestWriteTime = (Get-Item -LiteralPath $resolvedPath -ErrorAction Stop).LastWriteTime
        $latestFile = $null
        foreach ($file in @(Get-ChildItem -LiteralPath $resolvedPath -File -Recurse -Force -ErrorAction SilentlyContinue)) {
            if ($null -eq $latestFile -or $file.LastWriteTime -gt $latestFile.LastWriteTime) {
                $latestFile = $file
            }
        }

        if ($null -ne $latestFile -and $latestFile.LastWriteTime -gt $latestWriteTime) {
            $latestWriteTime = $latestFile.LastWriteTime
        }

        $ageMinutes = ((Get-Date) - $latestWriteTime).TotalMinutes
        $result.Exists = $true
        $result.AgeMinutes = [double]$ageMinutes
        $result.Fresh = ($ageMinutes -le $WindowMinutes)
    }
    catch { Write-Verbose ("Suppressed exception: {0}" -f $_.Exception.Message) }

    return [pscustomobject]$result
}

function Get-BudgetExhaustedLivenessEvidence {
    param(
        [System.Collections.IDictionary]$Settings,
        [ValidateRange(2, 180)][int]$WindowMinutes = 6,
        [int]$FallbackProcessId = 0
    )

    $notes = ''
    if ($null -ne $Settings -and $Settings.Contains('SESSION_FINAL_NOTES')) {
        $notes = [string]$Settings.SESSION_FINAL_NOTES
    }

    $bLaunchPid = $FallbackProcessId
    if ($null -ne $Settings -and $Settings.Contains('B_LAUNCH_PID')) {
        $parsedPid = Convert-ToNullablePositiveInt -Value ([string]$Settings.B_LAUNCH_PID)
        if ($null -ne $parsedPid) {
            $bLaunchPid = [int]$parsedPid
        }
    }

    $guardLogAnchor = Get-LatestAnchorValueFromNoteText -Notes $notes -Key 'guard_log'
    $liveStatusAnchor = Get-LatestAnchorValueFromNoteText -Notes $notes -Key 'live_status'
    $runDirAnchor = Resolve-RunDirAnchorFromNotes -Notes $notes
    $runtimeLogHint = Get-BRuntimeLogHint -Settings $Settings -ArtifactRuntimeLogPath ''

    $pidAlive = Test-ProcessAlive -ProcessId $bLaunchPid
    $guardFreshness = Get-PathFreshnessEvidence -Path $guardLogAnchor -WindowMinutes $WindowMinutes
    $liveStatusFreshness = Get-PathFreshnessEvidence -Path $liveStatusAnchor -WindowMinutes $WindowMinutes
    $runtimeFreshness = Get-PathFreshnessEvidence -Path $runtimeLogHint -WindowMinutes $WindowMinutes
    $runDirFreshness = Get-RunDirFreshnessEvidence -RunDirPath $runDirAnchor -WindowMinutes $WindowMinutes

    $hostFresh = ([bool]$guardFreshness.Fresh -or [bool]$liveStatusFreshness.Fresh)
    $artifactFresh = ([bool]$runtimeFreshness.Fresh -or [bool]$runDirFreshness.Fresh)
    $active = ($pidAlive -or ($hostFresh -and $artifactFresh))

    $detail = ("pid={0} pid_alive={1} window_min={2} guard_age_min={3} live_status_age_min={4} runtime_age_min={5} run_dir_age_min={6}" -f
        $bLaunchPid,
        $pidAlive,
        $WindowMinutes,
        (Format-AgeMinutesForLog -AgeMinutes ([double]$guardFreshness.AgeMinutes)),
        (Format-AgeMinutesForLog -AgeMinutes ([double]$liveStatusFreshness.AgeMinutes)),
        (Format-AgeMinutesForLog -AgeMinutes ([double]$runtimeFreshness.AgeMinutes)),
        (Format-AgeMinutesForLog -AgeMinutes ([double]$runDirFreshness.AgeMinutes)))

    return [pscustomobject]@{
        Active = [bool]$active
        BLaunchPid = [int]$bLaunchPid
        ProcessAlive = [bool]$pidAlive
        Detail = $detail
    }
}

function Save-IncidentPackage {
    param(
        [System.Collections.IDictionary]$Settings,
        [string]$SessionStatus,
        [string]$AStatus,
        [string]$BStatus,
        [AllowEmptyString()][string]$RunDirAnchorOverride = ''
    )

    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $incidentDir = Join-Path $script:GuardOutDir ("incident_" + $stamp)
    New-Item -ItemType Directory -Path $incidentDir -Force | Out-Null

    $notes = if ($Settings.Contains('SESSION_FINAL_NOTES')) { [string]$Settings.SESSION_FINAL_NOTES } else { '' }
    $runDirAnchor = Resolve-RunDirAnchorFromNotes -Notes $notes
    if (-not [string]::IsNullOrWhiteSpace($RunDirAnchorOverride)) {
        $runDirAnchor = Convert-ToSingleLineText -Text $RunDirAnchorOverride
    }
    $liveStatusAnchor = Get-LatestAnchorValueFromNoteText -Notes $notes -Key 'live_status'

    $runDir = Resolve-AnchorPath -Path $runDirAnchor
    $liveStatus = Resolve-AnchorPath -Path $liveStatusAnchor

    Copy-FileIfPresent -Source $script:StartFilePath -Destination (Join-Path $incidentDir 'start_file_snapshot.md')
    Copy-FileIfPresent -Source $liveStatus -Destination (Join-Path $incidentDir 'live_status.json')

    # Copy guard log tail
    if (-not [string]::IsNullOrWhiteSpace($script:GuardLogPath) -and (Test-Path -LiteralPath $script:GuardLogPath)) {
        Export-FileTail -Source $script:GuardLogPath -Destination (Join-Path $incidentDir 'guard_tail.log') -Tail 300
    }

    if (-not [string]::IsNullOrWhiteSpace($runDir) -and (Test-Path -LiteralPath $runDir)) {
        Copy-FileIfPresent -Source (Join-Path $runDir 'final_status.json') -Destination (Join-Path $incidentDir 'run_final_status.json')
        Copy-FileIfPresent -Source (Join-Path $runDir 'final_status.txt') -Destination (Join-Path $incidentDir 'run_final_status.txt')
        Copy-FileIfPresent -Source (Join-Path $runDir 'summary.csv') -Destination (Join-Path $incidentDir 'summary.csv')
        Copy-FileIfPresent -Source (Join-Path $runDir 'summary_partial.csv') -Destination (Join-Path $incidentDir 'summary_partial.csv')

        # Copy stage runtime logs
        $stageLogFiles = @(Get-ChildItem -LiteralPath $runDir -Filter '*.log' -File -ErrorAction SilentlyContinue)
        foreach ($logFile in $stageLogFiles) {
            Copy-FileIfPresent -Source $logFile.FullName -Destination (Join-Path $incidentDir $logFile.Name)
        }
    }

    $startFileLeaf = [System.IO.Path]::GetFileName($script:StartFilePath).ToLowerInvariant()
    $processSnapshot = @(
        Get-CimInstance Win32_Process |
            Where-Object {
                $line = [string]$_.CommandLine
                if ([string]::IsNullOrWhiteSpace($line)) {
                    return $false
                }

                $lineLower = $line.ToLowerInvariant()
                if (-not [string]::IsNullOrWhiteSpace($startFileLeaf) -and -not $lineLower.Contains($startFileLeaf)) {
                    return $false
                }

                return ($lineLower -match 'unattended_ab_|start_dev_verify_fastmode_|start_dev_verify_8round_multiround')
            } |
            Select-Object ProcessId, Name, CreationDate, CommandLine |
            Sort-Object ProcessId
    )
    $processSnapshotJson = (($processSnapshot | ConvertTo-Json -Depth 6) -replace "`r`n", "`n")
    [System.IO.File]::WriteAllText((Join-Path $incidentDir 'process_snapshot.json'), $processSnapshotJson, [System.Text.UTF8Encoding]::new($false))

    $gitStatus = @((& git -C $script:RepoRoot status --short 2>&1) | ForEach-Object { [string]$_ })
    $gitStatusLines = @($gitStatus | ForEach-Object { [string]$_ })
    $gitStatusText = [string]::Join("`n", $gitStatusLines)
    if ($gitStatusLines.Count -gt 0) {
        $gitStatusText += "`n"
    }
    [System.IO.File]::WriteAllText((Join-Path $incidentDir 'git_status_short.txt'), $gitStatusText, [System.Text.UTF8Encoding]::new($false))

    $summary = @(
        "captured_at=$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))",
        "session_status=$SessionStatus",
        "a_status=$AStatus",
        "b_status=$BStatus",
        "run_dir_anchor=$runDirAnchor",
        "live_status_anchor=$liveStatusAnchor",
        "guard_log_anchor=$script:GuardLogPath"
    )
    $summaryLines = @($summary | ForEach-Object { [string]$_ })
    $summaryText = [string]::Join("`n", $summaryLines)
    if ($summaryLines.Count -gt 0) {
        $summaryText += "`n"
    }
    [System.IO.File]::WriteAllText((Join-Path $incidentDir 'summary.txt'), $summaryText, [System.Text.UTF8Encoding]::new($false))

    return $incidentDir
}

function Save-ASuccessSnapshot {
    param([string]$RunDir)

    $snapshotDir = Join-Path $RunDir 'a_success_snapshot'
    $sourceDir = Join-Path $snapshotDir 'source'
    New-Item -ItemType Directory -Path $sourceDir -Force | Out-Null

    $result = [pscustomobject]@{
        FinalStatus = (Convert-ToRepoRelativePath -Path (Join-Path $RunDir 'final_status.json'))
        Summary = (Convert-ToRepoRelativePath -Path (Join-Path $RunDir 'summary.csv'))
        SourceState = ''
        SnapshotDir = ''
    }

    try {
        $gitWarningPattern = '^\s*(warning:|git(\.exe)?\s*:\s*warning:)'
        $invokeGitCapture = {
            param([string[]]$GitArgs)
            $nativePrefExists = $null -ne (Get-Variable -Name 'PSNativeCommandUseErrorActionPreference' -ErrorAction SilentlyContinue)
            if ($nativePrefExists) { $PSNativeCommandUseErrorActionPreference = $false }
            $eaBackup = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
            $lines = @(); $exitCode = 0
            try {
                $lines = @((& git -C $script:RepoRoot @GitArgs 2>&1) | ForEach-Object { [string]$_ })
                $exitCode = $LASTEXITCODE
            }
            finally {
                $ErrorActionPreference = $eaBackup
                if ($nativePrefExists) { $PSNativeCommandUseErrorActionPreference = $false }
            }
            if ($exitCode -ne 0) { throw "git exit=$exitCode args=$($GitArgs -join ' ')" }
            return @($lines)
        }

        $statusRaw = @(& $invokeGitCapture @('status', '--short'))
        $statusFiltered = @($statusRaw | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) -and [string]$_ -notmatch $gitWarningPattern })
        $result.SourceState = if ($statusFiltered.Count -eq 0) { 'CLEAN' } else { ($statusFiltered -join ' | ') }
        $result.SourceState | Out-File -FilePath (Join-Path $snapshotDir 'source_state.txt') -Encoding utf8

        $diffNamesRaw = @(& $invokeGitCapture @('diff', '--name-only', '--', 'src', 'include'))
        $diffNames = @($diffNamesRaw | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) -and [string]$_ -notmatch $gitWarningPattern })
        $diffNames | Out-File -FilePath (Join-Path $snapshotDir 'source_files.txt') -Encoding utf8

        foreach ($relPath in $diffNames) {
            $srcPath = Join-Path $script:RepoRoot $relPath
            if (-not (Test-Path -LiteralPath $srcPath)) { continue }
            $dstPath = Join-Path $sourceDir ($relPath -replace '/', '\\')
            $dstParent = Split-Path -Parent $dstPath
            if (-not (Test-Path -LiteralPath $dstParent)) { New-Item -ItemType Directory -Path $dstParent -Force | Out-Null }
            Copy-Item -LiteralPath $srcPath -Destination $dstPath -Force
        }

        $null = Write-ASuccessSnapshotManifest -SnapshotDir $snapshotDir
        $integrity = Test-ASuccessSnapshotIntegrity -SnapshotDir $snapshotDir
        if (-not $integrity.Pass) {
            throw "A success snapshot integrity check failed: $($integrity.Errors -join ',')"
        }

        $patchRaw = @(& $invokeGitCapture @('diff', '--binary', '--', 'src', 'include'))
        $patchFiltered = @($patchRaw | Where-Object { [string]$_ -notmatch $gitWarningPattern })
        $patchFiltered | Out-File -FilePath (Join-Path $snapshotDir 'source.patch') -Encoding utf8

        $result.SnapshotDir = Convert-ToRepoRelativePath -Path $snapshotDir
    }
    catch {
        Write-GuardLog ("a_snapshot_error detail={0}" -f $_.Exception.Message.Replace("`r", ' ').Replace("`n", ' '))
    }

    return $result
}

function Get-ChildProcessMap {
    param([hashtable]$ProcessMap)

    $childMap = @{}
    foreach ($processInfo in $ProcessMap.Values) {
        $parentPid = [int]$processInfo.ParentProcessId
        if (-not $childMap.ContainsKey($parentPid)) { $childMap[$parentPid] = @() }
        $childMap[$parentPid] += [int]$processInfo.ProcessId
    }
    return $childMap
}

function Get-DescendantProcessIdList {
    param([int]$RootPid, [hashtable]$ChildMap)

    $queue = New-Object 'System.Collections.Generic.Queue[int]'
    $seen = New-Object 'System.Collections.Generic.HashSet[int]'
    $queue.Enqueue($RootPid)
    [void]$seen.Add($RootPid)
    while ($queue.Count -gt 0) {
        $targetPid = $queue.Dequeue()
        if (-not $ChildMap.ContainsKey($targetPid)) { continue }
        foreach ($childPid in @($ChildMap[$targetPid])) {
            $resolvedChildPid = [int]$childPid
            if ($seen.Add($resolvedChildPid)) { $queue.Enqueue($resolvedChildPid) }
        }
    }
    return @($seen)
}

function Get-ProcessDepthFromParentMap {
    param([int]$TargetPid, [hashtable]$ProcessMap)

    $depth = 0
    $cursorPid = $TargetPid
    while ($ProcessMap.ContainsKey($cursorPid)) {
        $parentPid = [int]$ProcessMap[$cursorPid].ParentProcessId
        if ($parentPid -le 0 -or $parentPid -eq $cursorPid) { break }
        $depth++
        $cursorPid = $parentPid
    }
    return $depth
}

function Stop-ProcessTree {
    param([int[]]$RootPids)

    if ($RootPids.Count -eq 0) { return @() }

    $processMap = @{}
    foreach ($processInfo in @(Get-CimInstance Win32_Process)) {
        $processMap[[int]$processInfo.ProcessId] = $processInfo
    }
    $childMap = Get-ChildProcessMap -ProcessMap $processMap

    $killSet = New-Object 'System.Collections.Generic.HashSet[int]'
    foreach ($rootPid in $RootPids) {
        foreach ($descendantPid in @(Get-DescendantProcessIdList -RootPid $rootPid -ChildMap $childMap)) {
            [void]$killSet.Add($descendantPid)
        }
    }

    $killed = @()
    $orderedTargets = @($killSet | Sort-Object { Get-ProcessDepthFromParentMap -TargetPid ([int]$_) -ProcessMap $processMap } -Descending)
    foreach ($targetPid in $orderedTargets) {
        try { Stop-Process -Id ([int]$targetPid) -Force -ErrorAction Stop; $killed += [int]$targetPid } catch { $null = $_ }
    }
    return @($killed)
}

function Invoke-SafeRemoteLockCleanup {
    $lockCleanupScript = Join-Path $script:RepoRoot 'tools\dev\clear_remote_lock.ps1'
    if (-not (Test-Path -LiteralPath $lockCleanupScript)) { return }
    try {
        $statusRefresh = Read-SessionStatusRefresh -StartFilePath $script:StartFilePath
        $settings = $statusRefresh.Settings
        $remoteIp = if ($settings.Contains('REMOTE_IP')) { [string]$settings.REMOTE_IP } else { '10.0.0.199' }
        $remoteUser = if ($settings.Contains('REMOTE_USER')) { [string]$settings.REMOTE_USER } else { 'larson' }
        $output = @(& $lockCleanupScript -RemoteIp $remoteIp -RemoteUser $remoteUser 2>&1 | ForEach-Object { [string]$_ })
        $text = ($output -join ' | ')
        Write-GuardLog ("remote_lock_cleanup result={0}" -f $text)
    }
    catch { Write-GuardLog ("remote_lock_cleanup error={0}" -f $_.Exception.Message) }
}

function Invoke-BStageRestart {
    param([int]$Attempt)

    return (Invoke-StageRestartCore -Stage 'B' -Attempt $Attempt)
}

function Invoke-StageRestartCore {
    param(
        [ValidateSet('A', 'B')][string]$Stage,
        [int]$Attempt,
        [AllowEmptyString()][string]$RoundTag = ''
    )

    $stagePolicy = Get-StagePolicy -Stage $Stage
    $stageLauncher = Join-Path $script:RepoRoot 'tools\test\open_unattended_ab_stage_window.ps1'
    $powershellPath = Join-Path $PSHOME 'powershell.exe'
    if (-not (Test-Path -LiteralPath $powershellPath)) {
        $powershellPath = 'powershell.exe'
    }

    if ([bool]$stagePolicy.RestartIncludeRoundInLog) {
        Write-GuardLog ("restart_begin stage={0} round={1} attempt={2} launcher={3}" -f [string]$stagePolicy.Stage, $RoundTag, $Attempt, (Convert-ToRepoRelativePath -Path $stageLauncher))
    }
    else {
        Write-GuardLog ("restart_begin stage={0} attempt={1} launcher={2}" -f [string]$stagePolicy.Stage, $Attempt, (Convert-ToRepoRelativePath -Path $stageLauncher))
    }

    $launcherArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $stageLauncher, '-Stage', [string]$stagePolicy.Stage, '-StartFile', $script:StartFilePath)
    if (-not [string]::IsNullOrWhiteSpace([string]$stagePolicy.RestartLauncherSwitch)) {
        $launcherArgs += [string]$stagePolicy.RestartLauncherSwitch
    }

    $output = @(& $powershellPath @launcherArgs 2>&1 | ForEach-Object { [string]$_ })
    $exitCode = if ($null -eq $LASTEXITCODE) { 0 } else { [int]$LASTEXITCODE }

    $outputLines = @(
        @($output) |
            ForEach-Object { Convert-ToSingleLineText -Text ([string]$_) } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    )
    if ($outputLines.Count -gt 0) {
        if ([bool]$stagePolicy.RestartIncludeRoundInLog) {
            Write-GuardLog ("restart_output_summary stage={0} round={1} attempt={2} lines={3}" -f [string]$stagePolicy.Stage, $RoundTag, $Attempt, $outputLines.Count)
        }
        else {
            Write-GuardLog ("restart_output_summary attempt={0} lines={1}" -f $Attempt, $outputLines.Count)
        }

        $outputBlockLines = New-Object 'System.Collections.Generic.List[string]'
        if ([bool]$stagePolicy.RestartIncludeRoundInLog) {
            [void]$outputBlockLines.Add(("stage={0} round={1} attempt={2}" -f [string]$stagePolicy.Stage, $RoundTag, $Attempt))
        }
        else {
            [void]$outputBlockLines.Add(("attempt={0}" -f $Attempt))
        }

        foreach ($line in $outputLines) {
            [void]$outputBlockLines.Add(("line={0}" -f $line))
        }
        Write-GuardPastedBlock -Tag 'restart_output_block' -Lines @($outputBlockLines)
    }

    return [pscustomobject]@{
        ExitCode = [int]$exitCode
        Succeeded = ([int]$exitCode -eq 0)
    }
}

function Invoke-StageRestartByPolicy {
    param(
        [ValidateSet('A', 'B')][string]$Stage,
        [int]$Attempt,
        [AllowEmptyString()][string]$RoundTag = ''
    )

    return (Invoke-StageRestartCore -Stage $Stage -Attempt $Attempt -RoundTag $RoundTag)
}

function Get-StagePolicy {
    param([ValidateSet('A', 'B')][string]$Stage)

    $stageLower = $Stage.ToLowerInvariant()
    $taskDefinitionKey = if ($Stage -eq 'B') { 'B_TASK_DEFINITION' } else { 'A_TASK_DEFINITION' }
    $restartEventSuffix = if ($Stage -eq 'B') { 'b' } else { 'a' }
    $restartLauncherSwitch = if ($Stage -eq 'B') { '' } else { '-StartMonitors' }
    $restartIncludeRoundInLog = ($Stage -eq 'A')
    $preferredStage = $Stage
    $guardRecoveryAction = ('restart-{0}' -f $restartEventSuffix)
    $verifyRestartEventName = ('verify-restart-{0}' -f $restartEventSuffix)
    $devTransientRestartEventName = ('dev-transient-restart-{0}' -f $restartEventSuffix)
    $autoFixRestartEventName = ('auto-fix-restart-{0}' -f $restartEventSuffix)

    return [pscustomobject]@{
        Stage = $Stage
        StageLower = $stageLower
        TaskDefinitionKey = $taskDefinitionKey
        RestartEventSuffix = $restartEventSuffix
        RestartLauncherSwitch = $restartLauncherSwitch
        RestartIncludeRoundInLog = $restartIncludeRoundInLog
        PreferredStage = $preferredStage
        GuardRecoveryAction = $guardRecoveryAction
        VerifyRestartEventName = $verifyRestartEventName
        DevTransientRestartEventName = $devTransientRestartEventName
        AutoFixRestartEventName = $autoFixRestartEventName
    }
}

function Format-StageRestartNote {
    param(
        [ValidateSet('A', 'B')][string]$Stage,
        [int]$Attempt,
        [string]$AtText
    )

    $stagePolicy = Get-StagePolicy -Stage $Stage
    return ("guard_recovery action={0} attempt={1} at={2}" -f [string]$stagePolicy.GuardRecoveryAction, $Attempt, $AtText)
}

function Write-RecoveryWaitingConfirmationLog {
    param(
        [ValidateSet('A', 'B')][string]$Stage,
        [int]$Attempts,
        [int]$MaxAttempts,
        [AllowEmptyString()][string]$SessionStatus,
        [AllowEmptyString()][string]$AStatus,
        [AllowEmptyString()][string]$BStatus
    )

    Write-GuardLog ("recovery_waiting_confirmation stage={0} attempts={1}/{2} status={3} a={4} b={5}" -f $Stage, $Attempts, $MaxAttempts, $SessionStatus, $AStatus, $BStatus)
}

function Resolve-RecoveryStageByStatus {
    param(
        [AllowEmptyString()][string]$AStatus,
        [AllowEmptyString()][string]$BStatus,
        [bool]$AllowBRecovery = $false,
        [bool]$AutoRecoverB = $false,
        [bool]$CanRecoverB = $false,
        [bool]$GuardRestartAllowedForFailure = $false
    )

    if ($AStatus -eq 'FAIL') {
        return 'A'
    }

    if ($AllowBRecovery -and $BStatus -eq 'FAIL' -and $AutoRecoverB -and $CanRecoverB -and $GuardRestartAllowedForFailure) {
        return 'B'
    }

    return ''
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

function Get-ArtifactState {
    param([string[]]$Paths)

    $files = @()
    foreach ($path in @($Paths | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })) {
        if (-not (Test-Path -LiteralPath $path)) { continue }
        $files += @(Get-ChildItem -LiteralPath $path -File -Recurse -Force -ErrorAction SilentlyContinue)
    }
    if ($files.Count -eq 0) {
        return [pscustomobject]@{ FileCount = 0; LatestWriteTime = [datetime]'2000-01-01'; LatestPath = '' }
    }
    $latest = $files | Sort-Object LastWriteTime, FullName | Select-Object -Last 1
    return [pscustomobject]@{ FileCount = $files.Count; LatestWriteTime = $latest.LastWriteTime; LatestPath = $latest.FullName }
}

function Get-RemoteChainCount {
    param([hashtable]$Settings)

    $remoteIp = [string]$Settings.REMOTE_IP
    if ([string]::IsNullOrWhiteSpace($remoteIp)) { $remoteIp = '10.0.0.199' }
    $remoteUser = [string]$Settings.REMOTE_USER
    if ([string]::IsNullOrWhiteSpace($remoteUser)) { $remoteUser = 'larson' }

    $count = 0
    foreach ($processInfo in @(Get-CimInstance Win32_Process)) {
        $cl = [string]$processInfo.CommandLine
        if ([string]::IsNullOrWhiteSpace($cl)) { continue }
        $clLower = $cl.ToLowerInvariant()
        $pName = ([string]$processInfo.Name).ToLowerInvariant()
        if ($pName -eq 'ssh-agent.exe' -or $clLower -match '(^|\s)ssh-agent(?:\.exe)?(\s|$)') { continue }
        $isRemote = $false
        if ($clLower -match 'remote_build_and_test\.sh|whois-win64\.exe|whois-x86_64') { $isRemote = $true }
        elseif ($pName -eq 'ssh.exe' -or $clLower -match '(^|\s)ssh(?:\.exe)?(\s|$)') {
            $hasEndpoint = ($clLower.Contains($remoteIp.ToLowerInvariant()) -or $clLower.Contains(($remoteUser.ToLowerInvariant() + '@')))
            $hasIntent = ($clLower -match 'remote_build_and_test\.sh|check_remote_lock\.ps1|clear_remote_lock\.ps1')
            if ($hasEndpoint -or $hasIntent) { $isRemote = $true }
        }
        if ($isRemote) { $count++ }
    }
    return $count
}

function Get-CsvRowCount {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) { return 0 }
    try {
        $lines = @(Get-Content -LiteralPath $Path -Encoding utf8 -ErrorAction SilentlyContinue)
        $header = $lines | Select-Object -First 1
        if ($null -eq $header) { return 0 }
        $dataLines = @($lines | Select-Object -Skip 1 | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        return $dataLines.Count
    } catch { return 0 }
}

function Import-CsvSafely {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) {
        return @()
    }

    try {
        return @(Import-Csv -LiteralPath $Path -ErrorAction Stop)
    }
    catch {
        return @()
    }
}

function Get-PropertyValueOrEmpty {
    param(
        [AllowNull()]$Object,
        [string]$PropertyName
    )

    if ($null -eq $Object -or [string]::IsNullOrWhiteSpace($PropertyName)) {
        return ''
    }

    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($PropertyName)) {
            return [string]$Object[$PropertyName]
        }
        return ''
    }

    if ($Object.PSObject.Properties.Name -contains $PropertyName) {
        return [string]$Object.$PropertyName
    }

    return ''
}

function Get-NormalizedStageRestartResult {
    param([AllowNull()][object]$InputObject)

    $candidates = @($InputObject)
    for ($index = $candidates.Count - 1; $index -ge 0; $index--) {
        $candidate = $candidates[$index]
        if ($null -eq $candidate) {
            continue
        }

        $propertyNames = @($candidate.PSObject.Properties.Name)
        if ($propertyNames -contains 'Succeeded' -or $propertyNames -contains 'ExitCode') {
            $succeeded = if ($propertyNames -contains 'Succeeded') { [bool]$candidate.Succeeded } else { $false }
            $exitCode = if ($propertyNames -contains 'ExitCode') { [int]$candidate.ExitCode } elseif ($succeeded) { 0 } else { 1 }
            return [pscustomobject]@{
                Succeeded = $succeeded
                ExitCode = $exitCode
            }
        }
    }

    return [pscustomobject]@{
        Succeeded = $false
        ExitCode = 1
    }
}

function Get-RoundFailureCategoryFromLogText {
    param(
        [AllowEmptyString()][string]$RunDir,
        [AllowEmptyString()][string]$RoundTag,
        [AllowEmptyString()][string]$AutopilotOutDir
    )

    $result = [ordered]@{
        Category = 'code-or-unknown'
        Evidence = 'no-script-or-network-marker'
        SourceLog = ''
        HasScriptFault = $false
        HasNetworkTransient = $false
        HasCodeFault = $false
    }

    if ([string]::IsNullOrWhiteSpace($RunDir) -or [string]::IsNullOrWhiteSpace($RoundTag)) {
        return [pscustomobject]$result
    }

    $logCandidates = New-Object 'System.Collections.Generic.List[object]'

    $runLogPath = Join-Path $RunDir ($RoundTag + '.log')
    if (Test-Path -LiteralPath $runLogPath) {
        [void]$logCandidates.Add([pscustomobject]@{ Path = $runLogPath; Label = 'run-round-log' })
    }

    if (-not [string]::IsNullOrWhiteSpace($AutopilotOutDir) -and (Test-Path -LiteralPath $AutopilotOutDir)) {
        $autopilotSummaryPath = Join-Path $AutopilotOutDir 'summary.csv'
        $autopilotRows = @(Import-CsvSafely -Path $autopilotSummaryPath)
        foreach ($row in $autopilotRows) {
            $rowRoundTag = Convert-ToSingleLineText -Text ([string](Get-PropertyValueOrEmpty -Object $row -PropertyName 'RoundTag'))
            if ($rowRoundTag -ne $RoundTag) {
                continue
            }

            $noDeltaStdoutLog = Resolve-AnchorPath -Path (Convert-ToSingleLineText -Text ([string](Get-PropertyValueOrEmpty -Object $row -PropertyName 'NoDeltaStdoutLog')))
            if (-not [string]::IsNullOrWhiteSpace($noDeltaStdoutLog) -and (Test-Path -LiteralPath $noDeltaStdoutLog)) {
                [void]$logCandidates.Add([pscustomobject]@{ Path = $noDeltaStdoutLog; Label = 'no-delta-stdout-log' })
            }

            $noDeltaOutDir = Resolve-AnchorPath -Path (Convert-ToSingleLineText -Text ([string](Get-PropertyValueOrEmpty -Object $row -PropertyName 'NoDeltaOutDir')))
            if (-not [string]::IsNullOrWhiteSpace($noDeltaOutDir) -and (Test-Path -LiteralPath $noDeltaOutDir)) {
                $dryRunLogPath = Join-Path $noDeltaOutDir 'oneclick_dryrun.log'
                if (Test-Path -LiteralPath $dryRunLogPath) {
                    [void]$logCandidates.Add([pscustomobject]@{ Path = $dryRunLogPath; Label = 'no-delta-dryrun-log' })
                }
            }

            break
        }

        $strictLogs = @(
            Get-ChildItem -LiteralPath $AutopilotOutDir -Recurse -File -Filter 'round*_strict.log' -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending |
                Select-Object -First 24
        )
        foreach ($strictLog in $strictLogs) {
            [void]$logCandidates.Add([pscustomobject]@{ Path = $strictLog.FullName; Label = 'strict-compile-log' })
        }
    }

    $markerRegistry = [ordered]@{
        TaskDefinition = '(?im)(\[DEV-VERIFY-MULTI\]\s+round_task_static_gate_fail=|\[TASK-STATIC-CHECK\]\s+severity=(?:error|warn)\s+detail=)'
        StructuredCodeValidation = '(?im)(\[AB-UNATTENDED-RESULT\][^\r\n]*script=[^\r\n]*(?:PREFLIGHT|CHECK|GOLDEN|SELFTEST|MATRIX|VERIFY|SMOKE|PRECLASS)[^\r\n]*result=FAIL[^\r\n]*exit_code=\d+|\[[A-Z0-9_-]*(?:PREFLIGHT|CHECK|GOLDEN|SELFTEST|MATRIX|VERIFY|SMOKE|PRECLASS)[A-Z0-9_-]*\][^\r\n]*(?:result=fail|FAIL)|\[remote_build\]\[ERROR\][^\r\n]*(?:preflight|golden|selftest|matrix|check|validation|verify|preclass)[^\r\n]*FAIL)'
        StructuredChildExit = '(?im)(\[AB-UNATTENDED-RESULT\][^\r\n]*exit_code=\d+|\[ONECLICK-DRYRUN-SMOKE\]\s+oneclick_end exit_code=\d+)'
        StrongScriptFault = '(?im)(parsererror|unexpectedtoken|propertynotfoundexception|argumentexception|参数类型不匹配|is not recognized as the name of a cmdlet|cannot find path\s+.*\.ps1)'
        WrapperStack = '(?im)(所在位置\s+.*\.ps1:\d+|at\s+.*\.ps1:\d+|line:\s*\d+\s*char:\s*\d+)'
        Infrastructure = '(?im)(connect-timeout|timed_out|connection\s+timed\s+out|temporary\s+failure|name\s+or\s+service\s+not\s+known|network\s+is\s+unreachable|connection\s+refused|connection\s+reset|no\s+route\s+to\s+host|eai_again|lookup\s+timeout|%error:201:\s*access\s+denied|rate\s*limit|too\s+many\s+requests|service\s+unavailable)'
        SourceCode = '(?im)(\[CODE-STEP\]\s+fatal_error=\s*[^\r\n]+|code-step\s+fatal\s+error[^\r\n]*|src[\\/].*\.(c|h):\d+:\d+:\s*error:[^\r\n]*|error\s+C\d{4}\b[^\r\n]*|undefined\s+reference\s+to[^\r\n]*|compilation\s+terminated[^\r\n]*|was\s+not\s+declared\s+in\s+this\s+scope[^\r\n]*|conflicting\s+types\s+for[^\r\n]*|redefinition\s+of[^\r\n]*|no\s+member\s+named[^\r\n]*|fatal\s+error:\s+[^\r\n]*)'
    }

    $taskDefinitionEvidence = ''
    $taskDefinitionSourceLog = ''
    $scriptEvidence = ''
    $networkEvidence = ''
    $codeEvidence = ''
    $structuredCodeEvidence = ''
    $scriptSourceLog = ''
    $networkSourceLog = ''
    $codeSourceLog = ''
    $structuredCodeSourceLog = ''

    foreach ($candidate in $logCandidates) {
        $path = [string]$candidate.Path
        if ([string]::IsNullOrWhiteSpace($path) -or -not (Test-Path -LiteralPath $path)) {
            continue
        }

        $text = ''
        try {
            $text = (@(Get-Content -LiteralPath $path -Tail 600 -ErrorAction Stop) -join "`n")
        }
        catch {
            continue
        }

        $taskDefinitionMarker = [regex]::Match($text, [string]$markerRegistry['TaskDefinition'])
        if ($taskDefinitionMarker.Success -and [string]::IsNullOrWhiteSpace($taskDefinitionEvidence)) {
            $taskDefinitionEvidence = Convert-ToBoundedSingleLineText -Text ([string]$taskDefinitionMarker.Value) -MaxChars 120
            $taskDefinitionSourceLog = Convert-ToRepoRelativePath -Path $path
        }

        $structuredCodeMarker = [regex]::Match($text, [string]$markerRegistry['StructuredCodeValidation'])
        if ($structuredCodeMarker.Success) {
            $result.HasCodeFault = $true
            if ([string]::IsNullOrWhiteSpace($structuredCodeEvidence)) {
                $structuredCodeEvidence = Convert-ToBoundedSingleLineText -Text ([string]$structuredCodeMarker.Value) -MaxChars 120
                $structuredCodeSourceLog = Convert-ToRepoRelativePath -Path $path
            }
        }

        $scriptMarker = [regex]::Match($text, [string]$markerRegistry['StrongScriptFault'])
        $scriptStackMarker = [regex]::Match($text, [string]$markerRegistry['WrapperStack'])
        $structuredChildExitMarker = [regex]::Match($text, [string]$markerRegistry['StructuredChildExit'])
        if ($scriptMarker.Success -or ($scriptStackMarker.Success -and -not $structuredChildExitMarker.Success)) {
            $result.HasScriptFault = $true
            if ([string]::IsNullOrWhiteSpace($scriptEvidence)) {
                $scriptEvidenceValue = if ($scriptMarker.Success) { [string]$scriptMarker.Value } else { [string]$scriptStackMarker.Value }
                $scriptEvidence = Convert-ToBoundedSingleLineText -Text $scriptEvidenceValue -MaxChars 120
                $scriptSourceLog = Convert-ToRepoRelativePath -Path $path
            }
        }

        $networkMarker = [regex]::Match($text, [string]$markerRegistry['Infrastructure'])
        if ($networkMarker.Success) {
            $result.HasNetworkTransient = $true
            if ([string]::IsNullOrWhiteSpace($networkEvidence)) {
                $networkEvidence = Convert-ToBoundedSingleLineText -Text ([string]$networkMarker.Value) -MaxChars 120
                $networkSourceLog = Convert-ToRepoRelativePath -Path $path
            }
        }

        $codeMarker = [regex]::Match($text, [string]$markerRegistry['SourceCode'])
        if ($codeMarker.Success) {
            $result.HasCodeFault = $true
            if ([string]::IsNullOrWhiteSpace($codeEvidence)) {
                $codeEvidence = Convert-ToBoundedSingleLineText -Text ([string]$codeMarker.Value) -MaxChars 120
                $codeSourceLog = Convert-ToRepoRelativePath -Path $path
            }
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($taskDefinitionEvidence)) {
        $result.Category = 'task-definition-mismatch'
        $result.Evidence = ('matched={0}' -f $taskDefinitionEvidence)
        $result.SourceLog = $taskDefinitionSourceLog
        return [pscustomobject]$result
    }

    if (-not [string]::IsNullOrWhiteSpace($structuredCodeEvidence)) {
        if ([bool]$result.HasNetworkTransient) {
            $result.Category = 'noncode-transient'
            $result.Evidence = ('validation={0};infra={1}' -f $structuredCodeEvidence, $networkEvidence)
            $result.SourceLog = if (-not [string]::IsNullOrWhiteSpace($networkSourceLog)) { $networkSourceLog } else { $structuredCodeSourceLog }
            return [pscustomobject]$result
        }

        $result.Category = 'code-or-unknown'
        $result.Evidence = ('validation={0}' -f $structuredCodeEvidence)
        $result.SourceLog = $structuredCodeSourceLog
        return [pscustomobject]$result
    }

    if ([bool]$result.HasCodeFault -and [bool]$result.HasScriptFault) {
        # Compile/type/link errors take precedence over wrapper script stack traces.
        # Route to code-fix lane to avoid repeatedly misclassifying known compile failures.
        $result.Category = 'code-or-unknown'
        $result.Evidence = ('code={0};script={1}' -f $codeEvidence, $scriptEvidence)
        $result.SourceLog = if (-not [string]::IsNullOrWhiteSpace($codeSourceLog)) { $codeSourceLog } else { $scriptSourceLog }
        return [pscustomobject]$result
    }

    if ([bool]$result.HasScriptFault) {
        $result.Category = 'script-fault'
        $result.Evidence = ('matched={0}' -f $scriptEvidence)
        $result.SourceLog = $scriptSourceLog
        return [pscustomobject]$result
    }

    if ([bool]$result.HasCodeFault) {
        $result.Category = 'code-or-unknown'
        $result.Evidence = ('code={0}' -f $codeEvidence)
        $result.SourceLog = $codeSourceLog
        return [pscustomobject]$result
    }

    if ([bool]$result.HasNetworkTransient) {
        $result.Category = 'noncode-transient'
        $result.Evidence = ('matched={0}' -f $networkEvidence)
        $result.SourceLog = $networkSourceLog
    }

    # Fallback: if no code/script/network markers found, check whether the
    # no-delta attempt compiled successfully (exit_code=0).  If yes, the
    # round failure is NOT a code/compile issue — it is an infrastructure
    # or consistency-check failure (e.g. Step47 preflight mini-regression).
    # Downgrade from default 'code-or-unknown' to 'noncode-transient' so
    # the ticket routes to resume-only instead of code-fix lane.
    if ([string]$result.Category -eq 'code-or-unknown' -and -not [bool]$result.HasCodeFault -and -not [bool]$result.HasScriptFault) {
        $noDeltaCompilePass = $false
        foreach ($candidate in $logCandidates) {
            if ([string]$candidate.Label -eq 'no-delta-stdout-log' -or [string]$candidate.Label -eq 'no-delta-dryrun-log') {
                $checkPath = [string]$candidate.Path
                if (-not [string]::IsNullOrWhiteSpace($checkPath) -and (Test-Path -LiteralPath $checkPath)) {
                    try {
                        if (Select-String -LiteralPath $checkPath -Pattern 'oneclick_end exit_code=0' -Quiet -ErrorAction Stop) {
                            $noDeltaCompilePass = $true
                            break
                        }
                    }
                    catch { $null = $_ }
                }
            }
        }
        if ($noDeltaCompilePass) {
            $result.Category = 'noncode-transient'
            $result.Evidence = 'no-delta-compile-passed-but-round-failed-consistency-check'
            $result.SourceLog = ''
        }
    }

    return [pscustomobject]$result
}

function Get-VerifyFailureCategoryFromLogText {
    param(
        [AllowEmptyString()][string]$RunDir,
        [AllowEmptyString()][string]$RoundTag,
        [AllowEmptyString()][string]$AutopilotOutDir
    )

    return (Get-RoundFailureCategoryFromLogText -RunDir $RunDir -RoundTag $RoundTag -AutopilotOutDir $AutopilotOutDir)
}

function Get-FailureTicketPolicy {
    param(
        [AllowEmptyString()][string]$RunDirAnchor
    )

    $result = [ordered]@{
        Mode = 'default'
        FailedRoundTag = ''
        FailurePhase = ''
        StructuredFailureKind = ''
        StructuredFailureCategory = ''
        StructuredFailureSourceLog = ''
        IsVerifyRound = $false
        IsDevRound = $false
        RunDir = ''
        AutopilotOutDir = ''
        FailureCategory = 'unknown'
        FailureEvidence = ''
        FailureSourceLog = ''
        FailureHasScriptFault = $false
        FailureHasNetworkTransient = $false
        FailureHasCodeFault = $false
        VerifyFailureCategory = 'unknown'
        VerifyFailureEvidence = ''
        VerifyFailureSourceLog = ''
        DevFailureCategory = 'unknown'
        DevFailureEvidence = ''
        DevFailureSourceLog = ''
    }

    $runDir = Resolve-AnchorPath -Path $RunDirAnchor
    if ([string]::IsNullOrWhiteSpace($runDir) -or -not (Test-Path -LiteralPath $runDir)) {
        return [pscustomobject]$result
    }
    $result.RunDir = Convert-ToRepoRelativePath -Path $runDir

    $summaryPath = Join-Path $runDir 'summary.csv'
    $rows = @(Import-CsvSafely -Path $summaryPath)
    $failedVerifyRow = $null
    $failedRoundRow = $null
    foreach ($row in $rows) {
        $phase = (Convert-ToSingleLineText -Text ([string](Get-PropertyValueOrEmpty -Object $row -PropertyName 'Phase'))).ToUpperInvariant()
        $roundTag = Convert-ToSingleLineText -Text ([string](Get-PropertyValueOrEmpty -Object $row -PropertyName 'RoundTag'))
        $roundPass = (Convert-ToSingleLineText -Text ([string](Get-PropertyValueOrEmpty -Object $row -PropertyName 'RoundPass'))).ToLowerInvariant()
        if ([string]::IsNullOrWhiteSpace($roundTag)) {
            continue
        }

        if ([string]::IsNullOrWhiteSpace([string]$result.FailedRoundTag) -and $roundPass -in @('false', '0')) {
            $result.FailedRoundTag = $roundTag
            $failedRoundRow = $row
        }

        if ($phase -eq 'VERIFY' -and $roundTag -match '^V[0-9]+$' -and $roundPass -in @('false', '0')) {
            $failedVerifyRow = $row
            $failedRoundRow = $row
            $result.FailedRoundTag = $roundTag
            break
        }
    }

    $finalStatusPath = Join-Path $runDir 'final_status.json'
    $finalStatus = Read-JsonFileSafely -Path $finalStatusPath
    if ($null -ne $finalStatus -and ($finalStatus.PSObject.Properties.Name -contains 'FailedRoundTags')) {
        foreach ($tag in @($finalStatus.FailedRoundTags)) {
            $roundTag = Convert-ToSingleLineText -Text ([string]$tag)
            if ([string]::IsNullOrWhiteSpace($roundTag)) {
                continue
            }

            if ([string]::IsNullOrWhiteSpace([string]$result.FailedRoundTag)) {
                $result.FailedRoundTag = $roundTag
            }

            if ($roundTag -match '^V[0-9]+$' -and $null -eq $failedVerifyRow) {
                $result.FailedRoundTag = $roundTag
            }
        }
    }

    if (-not [string]::IsNullOrWhiteSpace([string]$result.FailedRoundTag) -and $null -eq $failedRoundRow) {
        foreach ($row in $rows) {
            $rowRoundTag = Convert-ToSingleLineText -Text ([string](Get-PropertyValueOrEmpty -Object $row -PropertyName 'RoundTag'))
            if ($rowRoundTag -eq [string]$result.FailedRoundTag) {
                $failedRoundRow = $row
                break
            }
        }
    }

    if ($null -ne $failedRoundRow) {
        $result.FailurePhase = (Convert-ToSingleLineText -Text ([string](Get-PropertyValueOrEmpty -Object $failedRoundRow -PropertyName 'FailurePhase'))).ToLowerInvariant()
        $result.StructuredFailureKind = (Convert-ToSingleLineText -Text ([string](Get-PropertyValueOrEmpty -Object $failedRoundRow -PropertyName 'FailureKind'))).ToLowerInvariant()
        $result.StructuredFailureCategory = (Convert-ToSingleLineText -Text ([string](Get-PropertyValueOrEmpty -Object $failedRoundRow -PropertyName 'FailureCategory'))).ToLowerInvariant()
        $result.StructuredFailureSourceLog = Convert-ToSingleLineText -Text ([string](Get-PropertyValueOrEmpty -Object $failedRoundRow -PropertyName 'FailureSourceLog'))
    }
    if ($null -ne $finalStatus) {
        if ([string]::IsNullOrWhiteSpace([string]$result.FailurePhase)) {
            $result.FailurePhase = (Convert-ToSingleLineText -Text ([string](Get-PropertyValueOrEmpty -Object $finalStatus -PropertyName 'FailurePhase'))).ToLowerInvariant()
        }
        if ([string]::IsNullOrWhiteSpace([string]$result.StructuredFailureKind)) {
            $result.StructuredFailureKind = (Convert-ToSingleLineText -Text ([string](Get-PropertyValueOrEmpty -Object $finalStatus -PropertyName 'FailureKind'))).ToLowerInvariant()
        }
        if ([string]::IsNullOrWhiteSpace([string]$result.StructuredFailureCategory)) {
            $result.StructuredFailureCategory = (Convert-ToSingleLineText -Text ([string](Get-PropertyValueOrEmpty -Object $finalStatus -PropertyName 'FailureCategory'))).ToLowerInvariant()
        }
        if ([string]::IsNullOrWhiteSpace([string]$result.StructuredFailureSourceLog)) {
            $result.StructuredFailureSourceLog = Convert-ToSingleLineText -Text ([string](Get-PropertyValueOrEmpty -Object $finalStatus -PropertyName 'FailureSourceLog'))
        }
    }

    $autopilotOutDir = ''
    if ($null -ne $failedRoundRow) {
        $autopilotOutDir = Resolve-AnchorPath -Path (Convert-ToSingleLineText -Text ([string](Get-PropertyValueOrEmpty -Object $failedRoundRow -PropertyName 'AutopilotOutDir')))
    }
    if (-not [string]::IsNullOrWhiteSpace($autopilotOutDir)) {
        $result.AutopilotOutDir = Convert-ToRepoRelativePath -Path $autopilotOutDir
    }

    if ([string]$result.FailedRoundTag -match '^[VD][0-9]+$') {
        $categoryInfo = Get-RoundFailureCategoryFromLogText -RunDir $runDir -RoundTag ([string]$result.FailedRoundTag) -AutopilotOutDir $autopilotOutDir
        $result.FailureCategory = [string]$categoryInfo.Category
        $result.FailureEvidence = [string]$categoryInfo.Evidence
        $result.FailureSourceLog = [string]$categoryInfo.SourceLog
        $result.FailureHasScriptFault = [bool]$categoryInfo.HasScriptFault
        $result.FailureHasNetworkTransient = [bool]$categoryInfo.HasNetworkTransient
        $result.FailureHasCodeFault = [bool]$categoryInfo.HasCodeFault
    }

    if ([string]$result.FailedRoundTag -match '^V[0-9]+$') {
        $result.Mode = 'verify-diagnose-only'
        $result.IsVerifyRound = $true
        $result.VerifyFailureCategory = [string]$result.FailureCategory
        $result.VerifyFailureEvidence = [string]$result.FailureEvidence
        $result.VerifyFailureSourceLog = [string]$result.FailureSourceLog
    }
    elseif ([string]$result.FailedRoundTag -match '^D[0-9]+$') {
        $result.Mode = 'dev-repair-and-restart'
        $result.IsDevRound = $true
        $result.DevFailureCategory = [string]$result.FailureCategory
        $result.DevFailureEvidence = [string]$result.FailureEvidence
        $result.DevFailureSourceLog = [string]$result.FailureSourceLog
    }

    return [pscustomobject]$result
}

function Test-KnownInfraTransientFailurePolicy {
    param([object]$FailurePolicy)

    if ($null -eq $FailurePolicy) {
        return $false
    }

    $failedRoundTag = Convert-ToSingleLineText -Text ([string]$FailurePolicy.FailedRoundTag)
    if ([string]::IsNullOrWhiteSpace($failedRoundTag) -or $failedRoundTag -notmatch '^D[0-9]+$') {
        return $false
    }

    $category = (Convert-ToSingleLineText -Text ([string]$FailurePolicy.DevFailureCategory)).ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($category)) {
        $category = (Convert-ToSingleLineText -Text ([string]$FailurePolicy.FailureCategory)).ToLowerInvariant()
    }
    if ($category -ne 'noncode-transient') {
        return $false
    }

    $evidence = Convert-ToSingleLineText -Text ([string]$FailurePolicy.DevFailureEvidence)
    if ([string]::IsNullOrWhiteSpace($evidence)) {
        $evidence = Convert-ToSingleLineText -Text ([string]$FailurePolicy.FailureEvidence)
    }
    $sourceLog = Convert-ToSingleLineText -Text ([string]$FailurePolicy.DevFailureSourceLog)
    if ([string]::IsNullOrWhiteSpace($sourceLog)) {
        $sourceLog = Convert-ToSingleLineText -Text ([string]$FailurePolicy.FailureSourceLog)
    }

    $composite = ('{0} {1}' -f $evidence, $sourceLog).Trim()
    if ([string]::IsNullOrWhiteSpace($composite)) {
        return $false
    }

    $knownInfraRegex = '(?im)(network_precheck_error|ssh_command_timed_out_after_[0-9]+_seconds|check_dualstack_whois_connectivity|connect-timeout|timed_out|connection\s+timed\s+out|network\s+is\s+unreachable|no\s+route\s+to\s+host|name\s+or\s+service\s+not\s+known|eai_again|whois\s+connectivity|ipv6|ipv4)'
    return [regex]::IsMatch($composite, $knownInfraRegex)
}

function Get-FailureTicketMeta {
    param(
        [object]$FailurePolicy,
        [bool]$KnownInfraTransient = $false,
        [bool]$AutoRecoverB = $false,
        [bool]$RestartApproved = $true,
        [AllowEmptyString()][string]$AStatus = '',
        [AllowEmptyString()][string]$BStatus = ''
    )

    $result = [ordered]@{
        MainRound = ''
        PreferredStage = ''
        FailurePhase = 'unknown'
        FailureKind = 'unknown-failure'
        FailureCategory = 'unknown'
        FailureSource = ''
        FailureEvidence = ''
        SelfHealable = $false
        NonRecoverableEnv = [bool]$KnownInfraTransient
    }

    $normalizedA = Get-StatusValue -Value $AStatus
    $normalizedB = Get-StatusValue -Value $BStatus
    if ($normalizedA -eq 'PASS' -and $normalizedB -in @('FAIL', 'BLOCKED', 'NOT_RUN')) {
        $result.PreferredStage = 'B'
    }
    elseif ($normalizedA -in @('FAIL', 'BLOCKED', 'NOT_RUN')) {
        $result.PreferredStage = 'A'
    }

    if ($null -eq $FailurePolicy) {
        return [pscustomobject]$result
    }

    $roundTag = Convert-ToSingleLineText -Text ([string]$FailurePolicy.FailedRoundTag)
    $result.MainRound = $roundTag.ToUpperInvariant()

    $failureCategory = (Convert-ToSingleLineText -Text ([string]$FailurePolicy.FailureCategory)).ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($failureCategory)) {
        $failureCategory = 'unknown'
    }

    $failureEvidence = Convert-ToSingleLineText -Text ([string]$FailurePolicy.FailureEvidence)
    $failureSource = Convert-ToSingleLineText -Text ([string]$FailurePolicy.FailureSourceLog)
    $structuredFailurePhase = (Convert-ToSingleLineText -Text ([string]$FailurePolicy.FailurePhase)).ToLowerInvariant()
    $structuredFailureKind = (Convert-ToSingleLineText -Text ([string]$FailurePolicy.StructuredFailureKind)).ToLowerInvariant()
    $structuredFailureCategory = (Convert-ToSingleLineText -Text ([string]$FailurePolicy.StructuredFailureCategory)).ToLowerInvariant()
    $structuredFailureSource = Convert-ToSingleLineText -Text ([string]$FailurePolicy.StructuredFailureSourceLog)
    if (-not [string]::IsNullOrWhiteSpace($structuredFailurePhase)) {
        $result.FailurePhase = $structuredFailurePhase
    }
    if (-not [string]::IsNullOrWhiteSpace($structuredFailureSource)) {
        $failureSource = $structuredFailureSource
    }

    $taskDefinitionMismatchRegex = '(?im)(task[- ]definition|regex[- ]patch|expected\s+exactly\s+one\s+match,\s*actual\s*=\s*0|replacement\s+likely\s+double-escaped|double-escaped|failonwarnings|check_task_definition_static|static\s+precheck|auto-inject\s+failed|forward\s+declarations?\s+needed)'
    $compileErrorRegex = '(?im)(error:|compilation\s+terminated|failed\s+to\s+build|build\s+failed|undefined\s+reference|fatal\s+error)'
    $compileWarningRegex = '(?im)(warning:|\bwarning\b)'

    if ([bool]$FailurePolicy.IsVerifyRound) {
        $failureCategory = (Convert-ToSingleLineText -Text ([string]$FailurePolicy.VerifyFailureCategory)).ToLowerInvariant()
        if ([string]::IsNullOrWhiteSpace($failureCategory)) {
            $failureCategory = 'unknown'
        }
        $failureEvidence = Convert-ToSingleLineText -Text ([string]$FailurePolicy.VerifyFailureEvidence)
        $failureSource = Convert-ToSingleLineText -Text ([string]$FailurePolicy.VerifyFailureSourceLog)
        $verifyComposite = ('{0} {1}' -f $failureEvidence, $failureSource)
        if ([regex]::IsMatch($verifyComposite, $taskDefinitionMismatchRegex)) {
            $result.FailureKind = 'task-definition-mismatch'
        }
        else {
            $result.FailureKind = 'verify-failure'
        }
    }
    elseif ([bool]$FailurePolicy.IsDevRound) {
        $failureCategory = (Convert-ToSingleLineText -Text ([string]$FailurePolicy.DevFailureCategory)).ToLowerInvariant()
        if ([string]::IsNullOrWhiteSpace($failureCategory)) {
            $failureCategory = (Convert-ToSingleLineText -Text ([string]$FailurePolicy.FailureCategory)).ToLowerInvariant()
        }
        if ([string]::IsNullOrWhiteSpace($failureCategory)) {
            $failureCategory = 'unknown'
        }

        $failureEvidence = Convert-ToSingleLineText -Text ([string]$FailurePolicy.DevFailureEvidence)
        if ([string]::IsNullOrWhiteSpace($failureEvidence)) {
            $failureEvidence = Convert-ToSingleLineText -Text ([string]$FailurePolicy.FailureEvidence)
        }
        $failureSource = Convert-ToSingleLineText -Text ([string]$FailurePolicy.DevFailureSourceLog)
        if ([string]::IsNullOrWhiteSpace($failureSource)) {
            $failureSource = Convert-ToSingleLineText -Text ([string]$FailurePolicy.FailureSourceLog)
        }

        if ($failureCategory -eq 'script-fault' -and [bool]$FailurePolicy.FailureHasCodeFault) {
            # Upstream may tag script-fault because of wrapper stack traces,
            # but code markers indicate this belongs to code-fix handling.
            $failureCategory = 'code-or-unknown'
        }

        if (-not [string]::IsNullOrWhiteSpace($structuredFailureCategory)) {
            $failureCategory = $structuredFailureCategory
        }

        if ($failureCategory -match '^task-definition(?:-|$)') {
            $result.FailureKind = 'task-definition-mismatch'
        }
        else {
            switch ($failureCategory) {
                'script-fault' {
                    $result.FailureKind = 'script-edit-failure'
                }
                'noncode-transient' {
                    $result.FailureKind = 'environment-transient'
                }
                default {
                    $composite = ('{0} {1}' -f $failureEvidence, $failureSource)
                    $hasTaskDefinitionMismatchMarker = [regex]::IsMatch($composite, $taskDefinitionMismatchRegex)
                    $hasCompileErrorMarker = [regex]::IsMatch($composite, $compileErrorRegex)
                    $hasCompileWarningMarker = [regex]::IsMatch($composite, $compileWarningRegex)
                    if ($hasTaskDefinitionMismatchMarker) {
                        $result.FailureKind = 'task-definition-mismatch'
                    }
                    elseif ($hasCompileErrorMarker -or [bool]$FailurePolicy.FailureHasCodeFault) {
                        $result.FailureKind = 'compile-failure'
                    }
                    elseif ($hasCompileWarningMarker) {
                        $result.FailureKind = 'compile-warning'
                    }
                    elseif ($failureCategory -eq 'code-or-unknown') {
                        $result.FailureKind = 'verify-failure'
                    }
                    else {
                        $result.FailureKind = 'unknown-failure'
                    }
                }
            }
        }
    }
    elseif ($failureCategory -eq 'script-fault') {
        $result.FailureKind = 'script-edit-failure'
    }
    elseif ($failureCategory -eq 'noncode-transient') {
        $result.FailureKind = 'environment-transient'
    }

    if (-not [string]::IsNullOrWhiteSpace($structuredFailureCategory)) {
        $failureCategory = $structuredFailureCategory
    }

    if (-not [string]::IsNullOrWhiteSpace($structuredFailureKind)) {
        $result.FailureKind = $structuredFailureKind
    }

    if ($structuredFailurePhase -eq 'code-step') {
        $result.FailureKind = 'environment-transient'
        $failureCategory = 'noncode-transient'
    }
    elseif ($result.FailureKind -eq 'code-edit-failure') {
        $result.FailureKind = 'environment-transient'
        $failureCategory = 'noncode-transient'
    }
    elseif ($structuredFailurePhase -eq 'task-static') {
        $result.FailureKind = 'task-definition-mismatch'
        $failureCategory = 'task-definition-mismatch'
    }

    $result.FailureCategory = $failureCategory
    $result.FailureSource = $failureSource
    $result.FailureEvidence = $failureEvidence

    $selfHealable = $false
    if ($result.FailureKind -in @('script-failure', 'script-edit-failure', 'environment-transient', 'compile-failure', 'compile-warning', 'verify-failure', 'task-definition-mismatch', 'main-process-exit')) {
        $selfHealable = $true
    }
    # Keep B-stage recovery eligibility mode-agnostic: work mode should not
    # downgrade incident self-heal capability just because confirmation gate is pending.
    if ($result.PreferredStage -eq 'B' -and $AutoRecoverB) {
        $selfHealable = $true
    }
    if ([bool]$KnownInfraTransient) {
        $selfHealable = $false
    }
    $result.SelfHealable = [bool]$selfHealable

    return [pscustomobject]$result
}

function Get-StageCompileFailureContext {
    param(
        [ValidateSet('A', 'B')][string]$Stage,
        [System.Collections.IDictionary]$Settings,
        [AllowEmptyString()][string]$RunDirAnchor
    )

    $result = [ordered]@{
        Eligible = $false
        Reason = ''
        Detail = ''
        RunDir = ''
        RoundTag = ''
        RoundLogPath = ''
        AutopilotOutDir = ''
        D6OutDir = ''
        StrictLogPath = ''
        StrictLogText = ''
        Signatures = @()
        TargetSourceFiles = @()
        TaskDefinitionPath = ''
        TaskDefinitionHint = ''
    }

    $stagePolicy = Get-StagePolicy -Stage $Stage

    $runDir = Resolve-AnchorPath -Path $RunDirAnchor
    if ([string]::IsNullOrWhiteSpace($runDir) -or -not (Test-Path -LiteralPath $runDir)) {
        $result.Reason = 'run-dir-missing'
        return [pscustomobject]$result
    }
    $result.RunDir = Convert-ToRepoRelativePath -Path $runDir

    $failedRoundCandidates = New-Object 'System.Collections.Generic.List[string]'
    $runFinalStatusPath = Join-Path $runDir 'final_status.json'
    $runFinalStatus = Read-JsonFileSafely -Path $runFinalStatusPath
    if ($null -ne $runFinalStatus -and ($runFinalStatus.PSObject.Properties.Name -contains 'FailedRoundTags')) {
        foreach ($tag in @($runFinalStatus.FailedRoundTags)) {
            $roundTag = Convert-ToSingleLineText -Text ([string]$tag)
            if ($roundTag -match '^D[1-4]$') {
                [void]$failedRoundCandidates.Add($roundTag)
            }
        }
    }

    $runSummaryPath = Join-Path $runDir 'summary.csv'
    $runRows = @(Import-CsvSafely -Path $runSummaryPath)
    if ($runRows.Count -lt 1) {
        $result.Reason = 'run-summary-missing'
        return [pscustomobject]$result
    }

    $failedRoundTag = ''
    if ($failedRoundCandidates.Count -gt 0) {
        $failedRoundTag = [string]$failedRoundCandidates[0]
    }
    else {
        $failedRows = @()
        foreach ($row in $runRows) {
            $phase = Convert-ToSingleLineText -Text ([string]$row.Phase)
            $roundTag = Convert-ToSingleLineText -Text ([string]$row.RoundTag)
            $roundPass = (Convert-ToSingleLineText -Text ([string]$row.RoundPass)).ToLowerInvariant()
            if ($phase -eq 'DEV' -and $roundTag -match '^D[1-4]$' -and $roundPass -in @('false', '0')) {
                $failedRows += $row
            }
        }

        if ($failedRows.Count -gt 0) {
            $failedRoundTag = [string]($failedRows | Sort-Object { [int]($_.Round) } -Descending | Select-Object -First 1).RoundTag
        }
    }

    if ([string]::IsNullOrWhiteSpace($failedRoundTag) -or $failedRoundTag -notmatch '^D[1-4]$') {
        $result.Reason = 'no-failed-d-round'
        return [pscustomobject]$result
    }
    $result.RoundTag = $failedRoundTag

    $failedRunRow = $null
    foreach ($row in $runRows) {
        if ((Convert-ToSingleLineText -Text ([string]$row.RoundTag)) -eq $failedRoundTag) {
            $failedRunRow = $row
        }
    }
    if ($null -eq $failedRunRow) {
        $result.Reason = 'failed-round-row-missing'
        return [pscustomobject]$result
    }

    $roundLogPath = Resolve-AnchorPath -Path (Convert-ToSingleLineText -Text (Get-PropertyValueOrEmpty -Object $failedRunRow -PropertyName 'LogFile'))
    if ([string]::IsNullOrWhiteSpace($roundLogPath) -or -not (Test-Path -LiteralPath $roundLogPath)) {
        $fallbackRoundLog = Join-Path $runDir ($failedRoundTag + '.log')
        if (Test-Path -LiteralPath $fallbackRoundLog) {
            $roundLogPath = $fallbackRoundLog
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($roundLogPath)) {
        $result.RoundLogPath = Convert-ToRepoRelativePath -Path $roundLogPath
    }

    $autopilotOutDir = Resolve-AnchorPath -Path (Convert-ToSingleLineText -Text (Get-PropertyValueOrEmpty -Object $failedRunRow -PropertyName 'AutopilotOutDir'))
    if ([string]::IsNullOrWhiteSpace($autopilotOutDir) -and -not [string]::IsNullOrWhiteSpace($roundLogPath) -and (Test-Path -LiteralPath $roundLogPath)) {
        foreach ($line in @(Get-Content -LiteralPath $roundLogPath -Tail 400 -ErrorAction SilentlyContinue)) {
            if ([string]$line -match '^\[AUTOPILOT-8R\] out_dir=(.+)$') {
                $autopilotOutDir = Resolve-AnchorPath -Path (Convert-ToSingleLineText -Text $Matches[1])
            }
        }
    }

    if ([string]::IsNullOrWhiteSpace($autopilotOutDir) -or -not (Test-Path -LiteralPath $autopilotOutDir)) {
        $result.Reason = 'autopilot-out-dir-missing'
        return [pscustomobject]$result
    }
    $result.AutopilotOutDir = Convert-ToRepoRelativePath -Path $autopilotOutDir

    $autopilotSummaryPath = Join-Path $autopilotOutDir 'summary.csv'
    $autopilotRows = @(Import-CsvSafely -Path $autopilotSummaryPath)
    if ($autopilotRows.Count -lt 1) {
        $result.Reason = 'autopilot-summary-missing'
        return [pscustomobject]$result
    }

    $autopilotRoundRow = $null
    foreach ($row in $autopilotRows) {
        if ((Convert-ToSingleLineText -Text ([string]$row.RoundTag)) -eq $failedRoundTag) {
            $autopilotRoundRow = $row
            break
        }
    }

    if ($null -eq $autopilotRoundRow) {
        $result.Reason = 'autopilot-round-row-missing'
        return [pscustomobject]$result
    }

    $taskDefinitionHint = Convert-ToSingleLineText -Text (Get-PropertyValueOrEmpty -Object $autopilotRoundRow -PropertyName 'TaskDefinitionFile')
    if (-not [string]::IsNullOrWhiteSpace($taskDefinitionHint)) {
        $result.TaskDefinitionHint = $taskDefinitionHint
    }

    $d6OutDir = Resolve-AnchorPath -Path (Convert-ToSingleLineText -Text (Get-PropertyValueOrEmpty -Object $autopilotRoundRow -PropertyName 'D6OutDir'))
    if ([string]::IsNullOrWhiteSpace($d6OutDir)) {
        $d6StdoutLog = Resolve-AnchorPath -Path (Convert-ToSingleLineText -Text (Get-PropertyValueOrEmpty -Object $autopilotRoundRow -PropertyName 'D6StdoutLog'))
        if (-not [string]::IsNullOrWhiteSpace($d6StdoutLog) -and (Test-Path -LiteralPath $d6StdoutLog)) {
            foreach ($line in @(Get-Content -LiteralPath $d6StdoutLog -Tail 240 -ErrorAction SilentlyContinue)) {
                if ([string]$line -match '^\[D6-CONSISTENCY\] out_dir=(.+)$') {
                    $d6OutDir = Resolve-AnchorPath -Path (Convert-ToSingleLineText -Text $Matches[1])
                }
            }
        }
    }

    if ([string]::IsNullOrWhiteSpace($d6OutDir) -or -not (Test-Path -LiteralPath $d6OutDir)) {
        $result.Reason = 'd6-out-dir-missing'
        return [pscustomobject]$result
    }
    $result.D6OutDir = Convert-ToRepoRelativePath -Path $d6OutDir

    $d6SummaryPath = Join-Path $d6OutDir 'summary.csv'
    $d6Rows = @(Import-CsvSafely -Path $d6SummaryPath)
    if ($d6Rows.Count -lt 1) {
        $result.Reason = 'd6-summary-missing'
        return [pscustomobject]$result
    }

    $strictLogPath = ''
    foreach ($row in $d6Rows) {
        $strictExit = 0
        [void][int]::TryParse((Convert-ToSingleLineText -Text (Get-PropertyValueOrEmpty -Object $row -PropertyName 'StrictExit')), [ref]$strictExit)
        $strictLogCandidate = Resolve-AnchorPath -Path (Convert-ToSingleLineText -Text (Get-PropertyValueOrEmpty -Object $row -PropertyName 'StrictLog'))
        if ($strictExit -ne 0 -and -not [string]::IsNullOrWhiteSpace($strictLogCandidate) -and (Test-Path -LiteralPath $strictLogCandidate)) {
            $strictLogPath = $strictLogCandidate
        }
    }

    if ([string]::IsNullOrWhiteSpace($strictLogPath)) {
        foreach ($row in $d6Rows) {
            $strictLogCandidate = Resolve-AnchorPath -Path (Convert-ToSingleLineText -Text (Get-PropertyValueOrEmpty -Object $row -PropertyName 'StrictLog'))
            if (-not [string]::IsNullOrWhiteSpace($strictLogCandidate) -and (Test-Path -LiteralPath $strictLogCandidate)) {
                $strictLogPath = $strictLogCandidate
            }
        }
    }

    if ([string]::IsNullOrWhiteSpace($strictLogPath) -or -not (Test-Path -LiteralPath $strictLogPath)) {
        $result.Reason = 'strict-log-missing'
        $result.Detail = ('round={0} strict_log=missing' -f [string]$failedRoundTag)
        return [pscustomobject]$result
    }
    $result.StrictLogPath = Convert-ToRepoRelativePath -Path $strictLogPath

    $strictLogText = ''
    try {
        $strictLogText = Get-Content -LiteralPath $strictLogPath -Raw -Encoding utf8 -ErrorAction Stop
    }
    catch {
        $result.Reason = 'strict-log-read-failed'
        $result.Detail = ('round={0} strict_log={1} read_failed={2}' -f [string]$failedRoundTag, [string]$result.StrictLogPath, (Convert-ToSingleLineText -Text $_.Exception.Message))
        return [pscustomobject]$result
    }

    $result.StrictLogText = $strictLogText
    $targetSourceFiles = @('src/core/preclass.c')
    $matchedTargetSources = New-Object 'System.Collections.Generic.List[string]'
    foreach ($targetSource in $targetSourceFiles) {
        $sourcePattern = ''
        switch ($targetSource) {
            'src/core/preclass.c' { $sourcePattern = '(?im)src/core/preclass\.c:.*\berror:' }
            default { $sourcePattern = '' }
        }

        if (-not [string]::IsNullOrWhiteSpace($sourcePattern) -and $strictLogText -match $sourcePattern) {
            [void]$matchedTargetSources.Add([string]$targetSource)
        }
    }

    if ($matchedTargetSources.Count -lt 1) {
        $result.Reason = 'not-target-source-compile-error'
        $result.Detail = ('round={0} strict_log={1} detail=strict-log-exists-but-target-source-signature-mismatch' -f [string]$failedRoundTag, [string]$result.StrictLogPath)
        return [pscustomobject]$result
    }

    $signatures = New-Object 'System.Collections.Generic.List[string]'
    if ($strictLogText -match '(?im)wc_preclass_set_special_tuple') {
        [void]$signatures.Add('preclass-special-tuple-forward-decl')
    }
    if ($strictLogText -match '(?im)wc_preclass_reason_unknown_hint_literal|wc_preclass_set_unknown_v6_hint_result') {
        [void]$signatures.Add('preclass-remove-unused-hint-helpers')
    }
    if ($strictLogText -match '(?im)wc_preclass_match_layer_cidr_literal|wc_preclass_match_layer_ip_literal') {
        [void]$signatures.Add('preclass-match-layer-wrapper')
    }

    if ($signatures.Count -lt 1) {
        $result.Reason = 'no-known-signature'
        return [pscustomobject]$result
    }

    $taskDefinitionRaw = ''
    $taskDefinitionKey = [string]$stagePolicy.TaskDefinitionKey
    if ($null -ne $Settings -and $Settings.Contains($taskDefinitionKey)) {
        $taskDefinitionRaw = Convert-ToSingleLineText -Text ([string]$Settings[$taskDefinitionKey])
    }
    if ([string]::IsNullOrWhiteSpace($taskDefinitionRaw)) {
        $taskDefinitionRaw = $taskDefinitionHint
    }

    $taskDefinitionPath = Resolve-AnchorPath -Path $taskDefinitionRaw
    if ([string]::IsNullOrWhiteSpace($taskDefinitionPath) -or -not (Test-Path -LiteralPath $taskDefinitionPath)) {
        $result.Reason = 'task-definition-missing'
        return [pscustomobject]$result
    }

    $result.TaskDefinitionPath = $taskDefinitionPath
    $result.Signatures = @($signatures)
    $result.TargetSourceFiles = @($matchedTargetSources)
    $result.Eligible = $true
    return [pscustomobject]$result
}

function Resolve-RegexPatchOperation {
    param(
        [System.Collections.Generic.List[psobject]]$Operations,
        [string]$Pattern,
        [AllowEmptyString()][string]$Replacement
    )

    for ($index = 0; $index -lt $Operations.Count; $index++) {
        if ([string]$Operations[$index].pattern -ne $Pattern) {
            continue
        }

        if ([string]$Operations[$index].replacement -eq $Replacement) {
            return 'present'
        }

        $Operations[$index].replacement = $Replacement
        return 'updated'
    }

    [void]$Operations.Add([pscustomobject]@{
            pattern = $Pattern
            replacement = $Replacement
        })
    return 'added'
}

function Invoke-TaskDefinitionStaticCheck {
    param(
        [string]$TaskDefinitionPath,
        [AllowEmptyString()][string]$RoundTag = ''
    )

    $checkScript = Join-Path $script:RepoRoot 'tools\test\check_task_definition_static.ps1'
    if (-not (Test-Path -LiteralPath $checkScript)) {
        return [pscustomobject]@{
            Passed = $false
            ExitCode = 1
            OutputLines = @('[AB-SESSION-GUARD] task static checker script missing')
        }
    }

    $powershellPath = Join-Path $PSHOME 'powershell.exe'
    if (-not (Test-Path -LiteralPath $powershellPath)) {
        $powershellPath = 'powershell.exe'
    }

    $checkArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $checkScript, '-TaskDefinitionFile', $TaskDefinitionPath, '-Policy', 'enforce', '-StartFilePath', $script:StartFilePath, '-Stage', 'A', '-EnableFingerprintCheck')
    if (-not [string]::IsNullOrWhiteSpace($RoundTag)) {
        $checkArgs += @('-RoundTag', $RoundTag)
    }
    $output = @(& $powershellPath @checkArgs 2>&1 | ForEach-Object { [string]$_ })
    $exitCode = if ($null -eq $LASTEXITCODE) { 0 } else { [int]$LASTEXITCODE }
    return [pscustomobject]@{
        Passed = ($exitCode -eq 0)
        ExitCode = $exitCode
        OutputLines = @($output)
    }
}

function Invoke-ApplyKnownPreclassTaskFixSet {
    param(
        [string]$TaskDefinitionPath,
        [string]$RoundTag,
        [string[]]$TargetSourceFiles
    )

    $result = [ordered]@{
        Success = $false
        Changed = $false
        Reason = ''
        BackupPath = ''
        UpdatedOperations = 0
        CheckExitCode = 0
        CheckOutput = @()
    }

    $effectiveTargets = @($TargetSourceFiles | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($effectiveTargets.Count -lt 1) {
        $effectiveTargets = @('src/core/preclass.c')
    }

    $unsupportedTargets = @($effectiveTargets | Where-Object { $_ -ne 'src/core/preclass.c' })
    if ($unsupportedTargets.Count -gt 0) {
        $result.Reason = ('unsupported-target-sources:{0}' -f (@($unsupportedTargets) -join ','))
        return [pscustomobject]$result
    }

    if ([string]::IsNullOrWhiteSpace($TaskDefinitionPath) -or -not (Test-Path -LiteralPath $TaskDefinitionPath)) {
        $result.Reason = 'task-definition-path-invalid'
        return [pscustomobject]$result
    }

    $taskDefinition = Read-JsonFileSafely -Path $TaskDefinitionPath
    if ($null -eq $taskDefinition) {
        $result.Reason = 'task-definition-parse-failed'
        return [pscustomobject]$result
    }

    if (-not ($taskDefinition.PSObject.Properties.Name -contains 'rounds')) {
        $result.Reason = 'task-definition-rounds-missing'
        return [pscustomobject]$result
    }

    $roundProperty = $null
    foreach ($entry in @($taskDefinition.rounds.PSObject.Properties)) {
        if ([string]$entry.Name -eq $RoundTag) {
            $roundProperty = $entry
            break
        }
    }

    if ($null -eq $roundProperty) {
        $result.Reason = 'round-missing'
        return [pscustomobject]$result
    }

    $roundTask = $roundProperty.Value
    $roundType = 'builtin'
    if ($roundTask.PSObject.Properties.Name -contains 'type') {
        $roundType = (Convert-ToSingleLineText -Text ([string]$roundTask.type)).ToLowerInvariant()
    }
    if ($roundType -ne 'regex-patch') {
        $result.Reason = 'round-not-regex-patch'
        return [pscustomobject]$result
    }

    $operationItems = @()
    if ($roundTask.PSObject.Properties.Name -contains 'operations') {
        $operationItems = @($roundTask.operations)
    }

    $operations = New-Object 'System.Collections.Generic.List[psobject]'
    foreach ($operation in $operationItems) {
        [void]$operations.Add([pscustomobject]@{
                pattern = [string]$operation.pattern
                replacement = [string]$operation.replacement
            })
    }
            $TaskDefinitionPath = Assert-GuardTaskDefinitionMutationPath -RepoRoot $script:RepoRoot -Path $TaskDefinitionPath


    $replacementSpecialTuple = @"
static void wc_preclass_set_special_tuple(const char** cls,
        const char** rir,
        const char** reason,
        const char** confidence,
        const char* reason_value);

static void wc_preclass_set_v6_branch_special_result(const char** cls,
        const char** rir,
        const char** reason,
        const char** confidence,
        const char* reason_value)
{
    wc_preclass_set_special_tuple(cls, rir, reason, confidence, reason_value);
}

static int wc_preclass_is_v6_loopback(const struct in6_addr* addr6)
"@

    $replacementMatchLayer = @"
static const char* wc_preclass_match_layer_cidr_literal(void);
static const char* wc_preclass_match_layer_ip_literal(void);

static const char* wc_preclass_match_layer_from_query_kind(int query_is_cidr)
{
    return query_is_cidr ? wc_preclass_match_layer_cidr_literal() : wc_preclass_match_layer_ip_literal();
}
"@

    $changeStates = @()
    $changeStates += (Resolve-RegexPatchOperation -Operations $operations -Pattern 'static int wc_preclass_is_v6_loopback\(const struct in6_addr\* addr6\)' -Replacement $replacementSpecialTuple)
    $changeStates += (Resolve-RegexPatchOperation -Operations $operations -Pattern 'static const char\* wc_preclass_match_layer_from_query_kind\(int query_is_cidr\)\r?\n\{\r?\n\treturn query_is_cidr \? wc_preclass_match_layer_cidr_output_literal\(\) : wc_preclass_match_layer_ip_output_literal\(\);\r?\n\}' -Replacement $replacementMatchLayer)
    $changeStates += (Resolve-RegexPatchOperation -Operations $operations -Pattern 'static const char\* wc_preclass_reason_unknown_hint_literal\(void\)\r?\n\{\r?\n\treturn wc_preclass_reason_unknown_literal\(\);\r?\n\}' -Replacement '')
    $changeStates += (Resolve-RegexPatchOperation -Operations $operations -Pattern 'static void wc_preclass_set_unknown_v6_hint_result\(const char\*\* rir,\r?\n\t\tconst char\*\* reason,\r?\n\t\tconst char\*\* confidence\)\r?\n\{\r?\n\t\*rir = "unknown";\r?\n\t\*reason = "V6_NO_RIR_HINT";\r?\n\t\*confidence = "low";\r?\n\}' -Replacement '')

    $updatedOperations = 0
    foreach ($state in $changeStates) {
        if ($state -in @('added', 'updated')) {
            $updatedOperations++
        }
    }

    if ($updatedOperations -lt 1) {
        $result.Success = $true
        $result.Changed = $false
        $result.Reason = 'already-up-to-date'
        return [pscustomobject]$result
    }

    $backupName = 'taskdef_backup_{0}_{1}.json' -f $RoundTag, (Get-Date -Format 'yyyyMMdd-HHmmss')
    $backupPath = Join-Path $script:GuardOutDir $backupName
    Copy-Item -LiteralPath $TaskDefinitionPath -Destination $backupPath -Force
    $result.BackupPath = Convert-ToRepoRelativePath -Path $backupPath

    if ($roundTask.PSObject.Properties.Name -contains 'operations') {
        $roundTask.operations = @($operations)
    }
    else {
        Add-Member -InputObject $roundTask -MemberType NoteProperty -Name 'operations' -Value @($operations)
    }

    try {
        $json = ($taskDefinition | ConvertTo-Json -Depth 64) -replace "`r`n", "`n"
        Write-Utf8NoBomTextFileAtomically -Path $TaskDefinitionPath -Text $json -EmitBom $true
    }
    catch {
        Copy-Item -LiteralPath $backupPath -Destination $TaskDefinitionPath -Force
        $result.Reason = 'task-definition-write-failed'
        return [pscustomobject]$result
    }

    $checkResult = Invoke-TaskDefinitionStaticCheck -TaskDefinitionPath $TaskDefinitionPath -RoundTag $RoundTag
    $result.CheckExitCode = [int]$checkResult.ExitCode
    $result.CheckOutput = @($checkResult.OutputLines)
    if (-not [bool]$checkResult.Passed) {
        Copy-Item -LiteralPath $backupPath -Destination $TaskDefinitionPath -Force
        $result.Reason = 'task-definition-static-check-failed'
        return [pscustomobject]$result
    }

    $result.Success = $true
    $result.Changed = $true
    $result.Reason = 'updated'
    $result.UpdatedOperations = $updatedOperations
    return [pscustomobject]$result
}

function Invoke-AStageRestart {
    param(
        [int]$Attempt,
        [string]$RoundTag
    )

    return (Invoke-StageRestartCore -Stage 'A' -Attempt $Attempt -RoundTag $RoundTag)
}

function Invoke-StageVerifyRoundRecovery {
    param(
        [ValidateSet('A', 'B')][string]$Stage,
        [object]$FailurePolicy,
        [bool]$RestartAllowed = $true,
        [ValidateRange(1, 10)][int]$MaxAttemptsPerRound = 2,
        [ValidateRange(0, 180)][int]$CooldownMinutes = 10
    )

    $result = [ordered]@{
        Attempted = $false
        Restarted = $false
        Reason = 'not-eligible'
        RoundTag = ''
        Attempt = 0
        Detail = ''
        Category = ''
        Evidence = ''
        SourceLog = ''
    }

    if ($null -eq $FailurePolicy -or -not [bool]$FailurePolicy.IsVerifyRound) {
        $result.Reason = 'not-verify-round'
        return [pscustomobject]$result
    }

    $roundTag = Convert-ToSingleLineText -Text ([string]$FailurePolicy.FailedRoundTag)
    $category = (Convert-ToSingleLineText -Text ([string]$FailurePolicy.VerifyFailureCategory)).ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($category)) {
        $category = 'code-or-unknown'
    }

    $result.RoundTag = $roundTag
    $result.Category = $category
    $result.Evidence = Convert-ToSingleLineText -Text ([string]$FailurePolicy.VerifyFailureEvidence)
    $result.SourceLog = Convert-ToSingleLineText -Text ([string]$FailurePolicy.VerifyFailureSourceLog)

    if ($category -notin @('script-fault', 'noncode-transient')) {
        $result.Reason = 'code-or-unknown'
        $result.Detail = 'verify_round_requires_manual_code_handling'
        return [pscustomobject]$result
    }

    $ledgerKey = ('{0}|{1}|{2}' -f $Stage, $roundTag, $category)
    if (-not $script:VerifyRecoveryAttemptCounts.ContainsKey($ledgerKey)) {
        $script:VerifyRecoveryAttemptCounts[$ledgerKey] = 0
    }

    $attemptCount = [int]$script:VerifyRecoveryAttemptCounts[$ledgerKey]
    if ($attemptCount -ge $MaxAttemptsPerRound) {
        $result.Reason = 'attempt-budget-exhausted'
        $result.Detail = ('attempts={0} max={1}' -f $attemptCount, $MaxAttemptsPerRound)
        return [pscustomobject]$result
    }

    $now = Get-Date
    if ($CooldownMinutes -gt 0 -and $script:VerifyRecoveryLastAttemptAt.ContainsKey($ledgerKey)) {
        $lastAttemptAt = [datetime]$script:VerifyRecoveryLastAttemptAt[$ledgerKey]
        if ($lastAttemptAt -ne [datetime]::MinValue -and $now -lt $lastAttemptAt.AddMinutes($CooldownMinutes)) {
            $result.Reason = 'cooldown'
            $result.Detail = ('next_at={0}' -f $lastAttemptAt.AddMinutes($CooldownMinutes).ToString('yyyy-MM-dd HH:mm:ss'))
            return [pscustomobject]$result
        }
    }

    $attempt = $attemptCount + 1
    $script:VerifyRecoveryAttemptCounts[$ledgerKey] = $attempt
    $script:VerifyRecoveryLastAttemptAt[$ledgerKey] = $now

    $result.Attempted = $true
    $result.Attempt = $attempt

    if (-not $RestartAllowed) {
        $result.Reason = 'restart-await-confirmation'
        $result.Detail = 'restart_requires_user_confirmation'
        return [pscustomobject]$result
    }

    $restartResult = Get-NormalizedStageRestartResult -InputObject @(Invoke-StageRestartByPolicy -Stage $Stage -Attempt $attempt -RoundTag $roundTag)
    if ([bool]$restartResult.Succeeded) {
        $result.Restarted = $true
        $result.Reason = 'restart-triggered'
    }
    else {
        $result.Reason = 'restart-failed'
        $result.Detail = ('exit_code={0}' -f [int]$restartResult.ExitCode)
    }

    return [pscustomobject]$result
}

function Invoke-StageDevRoundTransientRecovery {
    param(
        [ValidateSet('A', 'B')][string]$Stage,
        [object]$FailurePolicy,
        [bool]$RestartAllowed = $true,
        [ValidateRange(1, 10)][int]$MaxAttemptsPerRound = 2,
        [ValidateRange(0, 180)][int]$CooldownMinutes = 10
    )

    $result = [ordered]@{
        Attempted = $false
        Restarted = $false
        Reason = 'not-eligible'
        RoundTag = ''
        Attempt = 0
        Detail = ''
        Category = ''
        Evidence = ''
        SourceLog = ''
    }

    if ($null -eq $FailurePolicy -or -not [bool]$FailurePolicy.IsDevRound) {
        $result.Reason = 'not-dev-round'
        return [pscustomobject]$result
    }

    $roundTag = Convert-ToSingleLineText -Text ([string]$FailurePolicy.FailedRoundTag)
    $category = (Convert-ToSingleLineText -Text ([string]$FailurePolicy.DevFailureCategory)).ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($category)) {
        $category = (Convert-ToSingleLineText -Text ([string]$FailurePolicy.FailureCategory)).ToLowerInvariant()
    }
    if ([string]::IsNullOrWhiteSpace($category)) {
        $category = 'code-or-unknown'
    }

    $result.RoundTag = $roundTag
    $result.Category = $category
    $result.Evidence = Convert-ToSingleLineText -Text ([string]$FailurePolicy.DevFailureEvidence)
    $result.SourceLog = Convert-ToSingleLineText -Text ([string]$FailurePolicy.DevFailureSourceLog)

    if ($category -ne 'noncode-transient') {
        $result.Reason = 'not-noncode-transient'
        return [pscustomobject]$result
    }

    $ledgerKey = ('{0}|{1}|{2}' -f $Stage, $roundTag, $category)
    if (-not $script:DevRecoveryAttemptCounts.ContainsKey($ledgerKey)) {
        $script:DevRecoveryAttemptCounts[$ledgerKey] = 0
    }

    $attemptCount = [int]$script:DevRecoveryAttemptCounts[$ledgerKey]
    if ($attemptCount -ge $MaxAttemptsPerRound) {
        $result.Reason = 'attempt-budget-exhausted'
        $result.Detail = ('attempts={0} max={1}' -f $attemptCount, $MaxAttemptsPerRound)
        return [pscustomobject]$result
    }

    $now = Get-Date
    if ($CooldownMinutes -gt 0 -and $script:DevRecoveryLastAttemptAt.ContainsKey($ledgerKey)) {
        $lastAttemptAt = [datetime]$script:DevRecoveryLastAttemptAt[$ledgerKey]
        if ($lastAttemptAt -ne [datetime]::MinValue -and $now -lt $lastAttemptAt.AddMinutes($CooldownMinutes)) {
            $result.Reason = 'cooldown'
            $result.Detail = ('next_at={0}' -f $lastAttemptAt.AddMinutes($CooldownMinutes).ToString('yyyy-MM-dd HH:mm:ss'))
            return [pscustomobject]$result
        }
    }

    $attempt = $attemptCount + 1
    $script:DevRecoveryAttemptCounts[$ledgerKey] = $attempt
    $script:DevRecoveryLastAttemptAt[$ledgerKey] = $now

    $result.Attempted = $true
    $result.Attempt = $attempt

    if (-not $RestartAllowed) {
        $result.Reason = 'restart-await-confirmation'
        $result.Detail = 'restart_requires_user_confirmation'
        return [pscustomobject]$result
    }

    $restartResult = Get-NormalizedStageRestartResult -InputObject @(Invoke-StageRestartByPolicy -Stage $Stage -Attempt $attempt -RoundTag $roundTag)
    if ([bool]$restartResult.Succeeded) {
        $result.Restarted = $true
        $result.Reason = 'restart-triggered'
    }
    else {
        $result.Reason = 'restart-failed'
        $result.Detail = ('exit_code={0}' -f [int]$restartResult.ExitCode)
    }

    return [pscustomobject]$result
}

function Invoke-StageCompileAutoFixRecovery {
    param(
        [ValidateSet('A', 'B')][string]$Stage,
        [System.Collections.IDictionary]$Settings,
        [AllowEmptyString()][string]$RunDirAnchor,
        [ValidateRange(1, 8)][int]$MaxAttemptsPerRound = 3,
        [ValidateRange(0, 180)][int]$CooldownMinutes = 1,
        [bool]$RestartAllowed = $true
    )

    $result = [ordered]@{
        Attempted = $false
        Restarted = $false
        Reason = 'not-eligible'
        RoundTag = ''
        Attempt = 0
        Detail = ''
        TaskDefinitionPath = ''
        StrictLogPath = ''
    }

    $stageToken = $Stage.ToUpperInvariant()

    $context = Get-StageCompileFailureContext -Stage $stageToken -Settings $Settings -RunDirAnchor $RunDirAnchor
    if (-not [bool]$context.Eligible) {
        $result.Reason = [string]$context.Reason
        $result.Detail = Convert-ToSingleLineText -Text ([string]$context.Detail)
        return [pscustomobject]$result
    }

    $result.RoundTag = [string]$context.RoundTag
    $result.TaskDefinitionPath = Convert-ToRepoRelativePath -Path ([string]$context.TaskDefinitionPath)
    $result.StrictLogPath = [string]$context.StrictLogPath

    $ledgerKey = ('{0}|{1}' -f [string]$context.RoundTag, ([string]$context.TaskDefinitionPath).ToLowerInvariant())
    if (-not $script:AutoFixAttemptCounts.ContainsKey($ledgerKey)) {
        $script:AutoFixAttemptCounts[$ledgerKey] = 0
    }

    $attemptCount = [int]$script:AutoFixAttemptCounts[$ledgerKey]
    if ($attemptCount -ge $MaxAttemptsPerRound) {
        $result.Reason = 'attempt-budget-exhausted'
        $result.Detail = ('attempts={0} max={1}' -f $attemptCount, $MaxAttemptsPerRound)
        return [pscustomobject]$result
    }

    $now = Get-Date
    if ($CooldownMinutes -gt 0 -and $script:AutoFixLastAttemptAt.ContainsKey($ledgerKey)) {
        $lastAttemptAt = [datetime]$script:AutoFixLastAttemptAt[$ledgerKey]
        if ($lastAttemptAt -ne [datetime]::MinValue -and $now -lt $lastAttemptAt.AddMinutes($CooldownMinutes)) {
            $nextAt = $lastAttemptAt.AddMinutes($CooldownMinutes).ToString('yyyy-MM-dd HH:mm:ss')
            $result.Reason = 'cooldown'
            $result.Detail = ('next_at={0}' -f $nextAt)
            return [pscustomobject]$result
        }
    }

    $attempt = $attemptCount + 1
    $script:AutoFixAttemptCounts[$ledgerKey] = $attempt
    $script:AutoFixLastAttemptAt[$ledgerKey] = $now

    $result.Attempted = $true
    $result.Attempt = $attempt

    $signatureSummary = (@($context.Signatures) -join ',')
    $targetSourcesSummary = (@($context.TargetSourceFiles) -join ',')
    Write-GuardLog ("auto_fix_begin stage={0} round={1} attempt={2}/{3} signatures={4} strict_log={5} sources={6}" -f
        $stageToken,
        [string]$context.RoundTag,
        $attempt,
        $MaxAttemptsPerRound,
        $signatureSummary,
        [string]$context.StrictLogPath,
        $targetSourcesSummary)

    $applyResult = Invoke-ApplyKnownPreclassTaskFixSet -TaskDefinitionPath ([string]$context.TaskDefinitionPath) -RoundTag ([string]$context.RoundTag) -TargetSourceFiles @($context.TargetSourceFiles)
    if (-not [bool]$applyResult.Success) {
        $result.Reason = 'task-definition-fix-failed'
        $result.Detail = [string]$applyResult.Reason
        $checkPreview = Convert-ToBoundedSingleLineText -Text ((@($applyResult.CheckOutput) -join ' | ')) -MaxChars 240
        if (-not [string]::IsNullOrWhiteSpace($checkPreview)) {
            Write-GuardLog ("auto_fix_fail stage={0} round={1} attempt={2}/{3} reason={4} check={5}" -f $stageToken, [string]$context.RoundTag, $attempt, $MaxAttemptsPerRound, [string]$applyResult.Reason, $checkPreview)
        }
        else {
            Write-GuardLog ("auto_fix_fail stage={0} round={1} attempt={2}/{3} reason={4}" -f $stageToken, [string]$context.RoundTag, $attempt, $MaxAttemptsPerRound, [string]$applyResult.Reason)
        }
        return [pscustomobject]$result
    }

    if ([bool]$applyResult.Changed) {
        Write-GuardLog ("auto_fix_taskdef_updated stage={0} round={1} attempt={2}/{3} task={4} updated_ops={5} backup={6}" -f
            $stageToken,
            [string]$context.RoundTag,
            $attempt,
            $MaxAttemptsPerRound,
            (Convert-ToRepoRelativePath -Path ([string]$context.TaskDefinitionPath)),
            [int]$applyResult.UpdatedOperations,
            [string]$applyResult.BackupPath)
    }
    else {
        Write-GuardLog ("auto_fix_taskdef_nochange stage={0} round={1} attempt={2}/{3} task={4}" -f
            $stageToken,
            [string]$context.RoundTag,
            $attempt,
            $MaxAttemptsPerRound,
            (Convert-ToRepoRelativePath -Path ([string]$context.TaskDefinitionPath)))
    }

    if (-not $RestartAllowed) {
        $result.Reason = 'restart-await-confirmation'
        $result.Detail = 'restart_requires_user_confirmation'
        Write-GuardLog ("auto_fix_restart_blocked stage={0} round={1} attempt={2}/{3} reason=await_user_confirmation" -f $stageToken, [string]$context.RoundTag, $attempt, $MaxAttemptsPerRound)
        return [pscustomobject]$result
    }

    $restartResult = Get-NormalizedStageRestartResult -InputObject @(Invoke-StageRestartByPolicy -Stage $stageToken -Attempt $attempt -RoundTag ([string]$context.RoundTag))
    if ([bool]$restartResult.Succeeded) {
        $result.Restarted = $true
        $result.Reason = 'restart-triggered'
        Write-GuardLog ("auto_fix_restart_triggered stage={0} round={1} attempt={2}/{3}" -f $stageToken, [string]$context.RoundTag, $attempt, $MaxAttemptsPerRound)
    }
    else {
        $result.Reason = 'restart-failed'
        $result.Detail = ('exit_code={0}' -f [int]$restartResult.ExitCode)
        Write-GuardLog ("auto_fix_restart_failed stage={0} round={1} attempt={2}/{3} exit_code={4}" -f $stageToken, [string]$context.RoundTag, $attempt, $MaxAttemptsPerRound, [int]$restartResult.ExitCode)
    }

    try {
        $statusRefresh = Read-SessionStatusRefresh -StartFilePath $script:StartFilePath
        $statusView = Get-StatusSnapshotView -StatusSnapshot $statusRefresh.StatusSnapshot
        $existingNotes = $statusView.Notes
        $note = ('guard_autofix stage={0} round={1} attempt={2}/{3} restarted={4} reason={5} strict_log={6} sources={7}' -f
            $stageToken,
            [string]$context.RoundTag,
            $attempt,
            $MaxAttemptsPerRound,
            [bool]$result.Restarted,
            [string]$result.Reason,
            [string]$context.StrictLogPath,
            $targetSourcesSummary)
        $newNotes = Add-DelimitedNote -Existing $existingNotes -Append $note
        Invoke-KeyValueFileValueUpdateCore -Path $script:StartFilePath -Values @{ SESSION_FINAL_NOTES = $newNotes }
    }
    catch {
        Write-GuardLog ("auto_fix_note_update_failed detail={0}" -f (Convert-ToSingleLineText -Text $_.Exception.Message))
    }

    return [pscustomobject]$result
}

$script:RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$script:StartFilePath = Resolve-RepoPath -Path $StartFile
$script:StartFileLeaf = [System.IO.Path]::GetFileName($script:StartFilePath).ToLowerInvariant()

try {
    $startFileHash = [System.BitConverter]::ToString(
        [System.Security.Cryptography.SHA1]::Create().ComputeHash(
            [System.Text.Encoding]::UTF8.GetBytes(
                [System.IO.Path]::GetFullPath($script:StartFilePath).ToLowerInvariant()
            )
        )
    ).Replace('-', '').Substring(0, 12).ToLowerInvariant()

    $targetWindowPrefix = 'whois-mon-session-guard-'
    $targetWindowTitle = "whois-mon-session-guard-$startFileHash"
    $currentWindowTitle = ''
    try {
        $currentWindowTitle = [string]$host.UI.RawUI.WindowTitle
    }
    catch {
        $currentWindowTitle = ''
    }

    $normalizedWindowTitle = if ([string]::IsNullOrWhiteSpace($currentWindowTitle)) {
        ''
    }
    else {
        $currentWindowTitle.Trim().ToLowerInvariant()
    }

    $isWhoisTitle = $normalizedWindowTitle.StartsWith('whois-')
    $isOwnWindow = $normalizedWindowTitle.StartsWith($targetWindowPrefix)
    if ($isWhoisTitle -and -not $isOwnWindow) {
        Write-Output ("[AB-SESSION-GUARD] window_title_update=skip reason=foreign-whois-window-protected current_title={0}" -f $currentWindowTitle)
    }
    else {
        $host.UI.RawUI.WindowTitle = $targetWindowTitle
    }
}
catch { $null = $_ }

$script:InstanceMutex = Lock-InstanceMutex -Role 'session-guard' -StartFilePath $script:StartFilePath

$guardStamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$script:GuardOutDir = Join-Path $script:RepoRoot (Join-Path 'out\artifacts\ab_session_guard' $guardStamp)
New-Item -ItemType Directory -Path $script:GuardOutDir -Force | Out-Null
$script:GuardLogPath = Join-Path $script:GuardOutDir 'guard.log'
$script:GuardStatePath = Join-Path $script:GuardOutDir 'guard_state.json'
$script:LiveStatusPath = Join-Path $script:GuardOutDir 'live_status.json'
$script:GuardState = [ordered]@{
    schema = 'AB_SESSION_GUARD_STATE_V1'
    status = 'starting'
    start_file = (Convert-ToRepoRelativePath -Path $script:StartFilePath)
    guard_log = (Convert-ToRepoRelativePath -Path $script:GuardLogPath)
    guard_state = (Convert-ToRepoRelativePath -Path $script:GuardStatePath)
    poll_sec = [int]$PollSec
    max_recovery_attempts = [int]$MaxBRecoveryAttempts
    max_b_recovery_attempts = [int]$MaxBRecoveryAttempts
    recovery_cooldown_minutes = [int]$RecoveryCooldownMinutes
    stop_on_budget_exhausted = [bool]$StopOnBudgetExhausted
    auto_recover = $true
    auto_recover_b = $true
    restart_requires_confirmation = $false
    restart_approved = $true
    suppress_known_infra_tickets = $true
    exit_on_known_infra_transient = $true
    agent_ticket_queue_enabled = $true
    agent_ticket_queue_path = ''
    status_ticket_enabled = $false
    status_ticket_interval_minutes = 30
    last_status_ticket_at = ''
    last_ticket_id = ''
    last_ticket_event = ''
    recovery_attempts = 0
    recovery_last_at = ''
    b_recovery_attempts = 0
    last_recovery_at = ''
    d1_auto_restart_enabled = $true
}

$script:GuardStateWriteFailureCount = 0
$script:GuardStateWriteFailureSignature = ''
$script:GuardStateWriteFailureLastReportAt = [datetime]::MinValue

$script:AutoFixAttemptCounts = @{}
$script:AutoFixLastAttemptAt = @{}
$script:VerifyRecoveryAttemptCounts = @{}
$script:VerifyRecoveryLastAttemptAt = @{}
$script:DevRecoveryAttemptCounts = @{}
$script:DevRecoveryLastAttemptAt = @{}
$script:AgentTicketLastSignature = ''
$script:AgentTicketLastId = ''
$script:AgentTicketLastEvent = ''

Write-GuardState -Values @{}
$MaxRecoveryAttempts = [int]$MaxBRecoveryAttempts
Write-GuardLog ("startup start_file={0} poll_sec={1} max_recovery_attempts={2} max_b_recovery_attempts={3} recovery_cooldown_minutes={4} stop_on_budget_exhausted={5} guard_log={6} guard_state={7}" -f (Convert-ToRepoRelativePath -Path $script:StartFilePath), $PollSec, $MaxRecoveryAttempts, $MaxBRecoveryAttempts, $RecoveryCooldownMinutes, $StopOnBudgetExhausted, (Convert-ToRepoRelativePath -Path $script:GuardLogPath), (Convert-ToRepoRelativePath -Path $script:GuardStatePath))
$guardParentPid = 0
try {
    $guardSelfProcess = Get-CimInstance Win32_Process -Filter ("ProcessId={0}" -f $PID) -ErrorAction Stop
    if ($null -ne $guardSelfProcess) {
        $guardParentPid = [int]$guardSelfProcess.ParentProcessId
    }
}
catch {
    $guardParentPid = 0
}
Write-GuardLog ("startup_pid pid={0} parent_pid={1}" -f $PID, $guardParentPid)

$bRecoveryAttempts = 0
$RecoveryAttempts = [int]$bRecoveryAttempts
$lastRecoveryAt = [datetime]::MinValue
$lastIncidentSignature = ''
$graceClearedAt = $null
$startupWarmupMin = 5
$lastHeartbeatAt = [datetime]::MinValue
$lastBudgetExhaustedSignature = ''
$aRunningNoProcessSince = $null
$lastMissingAProcessReportAt = $null
$bRunningNoProcessSince = $null
$lastMissingBProcessReportAt = $null
$lastBMissingExitReasonEvidence = $null
$lastBMissingRuntimeTailEvidence = $null
$script:GuardStartAt = Get-Date
$guardStartupAStatus = ''
$guardStartupSessionStatus = ''

# D1 round progress stall detection state
$d1StallPrevFileCount = -1
$d1StallPrevLatestWrite = [datetime]::MinValue
$d1StallPrevRowCount = -1
$script:d1StallSince = $null
$d1StallLastReportAt = $null
$d1StallTriggeredSignature = ''
$script:D1ObserveStartedAt = $null
$d1StallFailMinutes = 20
$d1AutoRestartEnabled = $true
$d1AutoRestartAttempted = $false
$script:LastWatchHeartbeatAt = $null
$manualPauseActive = $false
$manualPauseSignature = ''
$manualPauseNoticeCount = 0
$manualPauseNoticeRepeat = 2
$manualPauseEnabled = $true
$forceExitOnFinalNoFollowup = $true
$autoFixCompileEnabled = $true
$autoFixMaxPerDRound = 3
$autoFixCooldownMinutes = 1
$lastAutoFixStatusSignature = ''
$restartRequiresConfirmation = $false
$restartApproved = $true
$suppressKnownInfraTickets = $true
$exitOnKnownInfraTransient = $true
$lastRestartApprovalWaitSignature = ''
$statusTicketEnabled = $false
$statusTicketIntervalMinutes = 30
$lastStatusTicketAt = [datetime]::MinValue
$lastMainProcessExitReviewSignature = ''
$lastAPassConclusionSignature = ''
$aExitEvidenceForIncident = $null
$aMainExitReviewRecommendedAction = 'Review A-stage main-process exit evidence and root cause, then run script-level self-heal for recoverable faults before deciding the next restart step.'
$mainExitReviewRecommendedAction = 'Review main-process exit evidence and provide a clear failure conclusion; then perform post-failure cleanup by letting monitor scripts exit gracefully (keep NoExit terminal windows for forensics) before next restart decision.'
$aSuccessSnapshotDir = ''
$mainProcessExitGraceStartedAt = $null
$mainProcessExitGraceLastNoticeAt = $null
$mainProcessExitGraceShutdownDetail = ''
$mainProcessExitGraceStage = ''
$monitorChainGraceStartedAt = $null
$monitorChainGraceLastNoticeAt = $null
$monitorChainGraceShutdownDetail = ''
$monitorChainGraceShutdownStage = ''
$monitorChainGraceShutdownReason = ''
$monitorChainGraceShutdownSource = ''
$healthCheckIterationCounter = 0
$script:StartupSuppressLastSignature = ''
$script:StartupSuppressLastRemainingBucket = ''
$script:StartupSuppressLastReportAt = [datetime]::MinValue
$script:StartupSuppressHiddenCount = 0
$script:TriggerHealthSkipLastReason = ''
$script:TriggerHealthSkipLastReportAt = [datetime]::MinValue
$script:TriggerHealthSkipHiddenCount = 0

function Test-D1ProgressSince {
    param(
        [string]$RunDirPath,
        [int]$PrevFileCount,
        [datetime]$PrevLatestWrite,
        [int]$PrevRowCount,
        [System.Collections.IDictionary]$SessionSettings
    )

    $result = [pscustomobject]@{
        HasProgress = $false
        FileCount = -1
        LatestWrite = [datetime]::MinValue
        LatestPath = ''
        RowCount = -1
        RemoteChainCount = 0
        Detail = ''
    }

    if ([string]::IsNullOrWhiteSpace($RunDirPath) -or -not (Test-Path -LiteralPath $RunDirPath)) {
        $result.Detail = 'run-dir-unavailable'
        return $result
    }

    # Scan artifacts
    $artifactState = Get-ArtifactState -Paths @($RunDirPath)
    $result.FileCount = [int]$artifactState.FileCount
    $result.LatestWrite = [datetime]$artifactState.LatestWriteTime
    $result.LatestPath = [string]$artifactState.LatestPath

    # Scan CSV row count
    $csvPath = Join-Path $RunDirPath 'summary_partial.csv'
    $result.RowCount = Get-CsvRowCount -Path $csvPath

    # Scan remote chain
    $result.RemoteChainCount = Get-RemoteChainCount -Settings $SessionSettings

    if ($PrevFileCount -lt 0) {
        $result.Detail = 'initial-count'
        return $result
    }

    $result.HasProgress = (
        ($result.FileCount -gt $PrevFileCount) -or
        ($result.LatestWrite -gt $PrevLatestWrite) -or
        ($result.RowCount -gt $PrevRowCount)
    )

    $result.Detail = if ($result.HasProgress) {
        'progress-detected'
    }
    else {
        "no_progress file=$($result.FileCount) prev_file=$PrevFileCount csv=$($result.RowCount) prev_csv=$PrevRowCount remote=$($result.RemoteChainCount)"
    }

    return $result
}

function Write-StructuredWatchHeartbeat {
    param(
        [AllowEmptyString()][string]$RunDirAnchor,
        [hashtable]$Settings,
        [AllowEmptyString()][string]$StageName,
        [int]$IntervalMinutes,
        [AllowEmptyString()][string]$Scopes
    )

    $scanStartedAt = Get-Date
    $resolvedRunDir = ''
    if (Test-HasUsableRunDirAnchor -RunDirAnchor $RunDirAnchor) {
        $resolvedRunDir = Resolve-RepoPathAllowMissing -Path $RunDirAnchor
    }

    $artifactState = Get-ArtifactState -Paths @($resolvedRunDir)
    $rowCount = 0
    if (-not [string]::IsNullOrWhiteSpace($resolvedRunDir)) {
        $rowCount = Get-CsvRowCount -Path (Join-Path $resolvedRunDir 'summary_partial.csv')
    }

    $remoteChainCount = Get-RemoteChainCount -Settings $Settings
    $scanDurationMs = [int][Math]::Round(((Get-Date) - $scanStartedAt).TotalMilliseconds)

    Write-GuardLog ("watch_heartbeat required=true interval_min={0} scopes={1} stage={2} row_count={3} file_count={4} latest_path={5} remote_chain_count={6} mode=guard scan_age_sec=0 scan_duration_ms={7}" -f
        $IntervalMinutes,
        $Scopes,
        $StageName,
        $rowCount,
        [int]$artifactState.FileCount,
        (Convert-ToRepoRelativePath -Path ([string]$artifactState.LatestPath)),
        [int]$remoteChainCount,
        $scanDurationMs)
}

function Get-SessionStatusSnapshot {
    param([System.Collections.IDictionary]$Settings)

    $sessionStatusRaw = 'NOT_RUN'
    if ($Settings.Contains('SESSION_FINAL_STATUS')) {
        $sessionStatusRaw = [string]$Settings.SESSION_FINAL_STATUS
    }

    $aStatusRaw = 'NOT_RUN'
    if ($Settings.Contains('A_FINAL_STATUS')) {
        $aStatusRaw = [string]$Settings.A_FINAL_STATUS
    }

    $bStatusRaw = 'NOT_RUN'
    if ($Settings.Contains('B_FINAL_STATUS')) {
        $bStatusRaw = [string]$Settings.B_FINAL_STATUS
    }

    $sessionStatus = Get-StatusValue -Value $sessionStatusRaw
    $aStatus = Get-StatusValue -Value $aStatusRaw
    $bStatus = Get-StatusValue -Value $bStatusRaw

    $aLaunchPid = 0
    if ($Settings.Contains('A_LAUNCH_PID')) {
        $parsedALaunchPid = Convert-ToNullablePositiveInt -Value ([string]$Settings.A_LAUNCH_PID)
        if ($null -ne $parsedALaunchPid) {
            $aLaunchPid = [int]$parsedALaunchPid
        }
    }

    $bLaunchPid = 0
    if ($Settings.Contains('B_LAUNCH_PID')) {
        $parsedBLaunchPid = Convert-ToNullablePositiveInt -Value ([string]$Settings.B_LAUNCH_PID)
        if ($null -ne $parsedBLaunchPid) {
            $bLaunchPid = [int]$parsedBLaunchPid
        }
    }

    $notes = if ($Settings.Contains('SESSION_FINAL_NOTES')) { [string]$Settings.SESSION_FINAL_NOTES } else { '' }
    $runDirAnchor = Resolve-RunDirAnchorFromNotes -Notes $notes

    return [pscustomobject]@{
        SessionStatusRaw = $sessionStatusRaw
        AStatusRaw = $aStatusRaw
        BStatusRaw = $bStatusRaw
        SessionStatus = $sessionStatus
        AStatus = $aStatus
        BStatus = $bStatus
        ALaunchPid = $aLaunchPid
        BLaunchPid = $bLaunchPid
        Notes = $notes
        RunDirAnchor = $runDirAnchor
    }
}

function Read-SessionStatusRefresh {
    param([string]$StartFilePath)

    $settings = Read-KeyValueFileWithRetry -Path $StartFilePath
    $statusSnapshot = Get-SessionStatusSnapshot -Settings $settings

    return [pscustomobject]@{
        Settings = $settings
        StatusSnapshot = $statusSnapshot
    }
}

function Expand-StatusSnapshotTuple {
    param([pscustomobject]$StatusSnapshot)

    return @(
        $StatusSnapshot.SessionStatusRaw,
        $StatusSnapshot.AStatusRaw,
        $StatusSnapshot.BStatusRaw,
        $StatusSnapshot.SessionStatus,
        $StatusSnapshot.AStatus,
        $StatusSnapshot.BStatus,
        [int]$StatusSnapshot.ALaunchPid,
        [int]$StatusSnapshot.BLaunchPid,
        [string]$StatusSnapshot.Notes,
        [string]$StatusSnapshot.RunDirAnchor
    )
}

function Expand-StatusRefreshTuple {
    param([pscustomobject]$StatusRefresh)

    return Expand-StatusSnapshotTuple -StatusSnapshot $StatusRefresh.StatusSnapshot
}

function Update-StatusAndExpandTuple {
    param([string]$StartFilePath)

    $statusRefresh = Read-SessionStatusRefresh -StartFilePath $StartFilePath
    return @($statusRefresh.Settings) + (Expand-StatusRefreshTuple -StatusRefresh $statusRefresh)
}

function Get-StatusSnapshotView {
    param([pscustomobject]$StatusSnapshot)

    return [pscustomobject]@{
        SessionStatus = $StatusSnapshot.SessionStatus
        AStatus = $StatusSnapshot.AStatus
        BStatus = $StatusSnapshot.BStatus
        BStatusRaw = $StatusSnapshot.BStatusRaw
        Notes = [string]$StatusSnapshot.Notes
    }
}

function Get-MainProcessExitDetailBase {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('A', 'B')][string]$Stage,
        [Parameter(Mandatory = $true)][int]$ExpectedPid,
        [Parameter(Mandatory = $true)][double]$ElapsedSec,
        [Parameter(Mandatory = $true)][double]$GraceSec
    )

    return ("main_process={0} expected_pid={1} elapsed_sec={2} grace_sec={3}" -f $Stage, $ExpectedPid, $ElapsedSec, $GraceSec)
}

function Add-MainProcessExitDetailArtifactSuffix {
    param(
        [Parameter(Mandatory = $true)][string]$Detail,
        [Parameter(Mandatory = $true)][pscustomobject]$ExitReasonEvidence
    )

    return ($Detail + (" artifact={0} exit_result={1} exit_code={2} exit_category={3} exit_reason={4}" -f
            [string]$ExitReasonEvidence.ArtifactPath,
            [string]$ExitReasonEvidence.Result,
            [int]$ExitReasonEvidence.ExitCode,
            [string]$ExitReasonEvidence.FailCategory,
            [string]$ExitReasonEvidence.FailReason))
}

function Add-MainProcessExitDetailTailSuffix {
    param(
        [Parameter(Mandatory = $true)][string]$Detail,
        [Parameter(Mandatory = $true)][string]$RuntimeLogPath,
        [Parameter(Mandatory = $true)][int]$TailUsed,
        [Parameter(Mandatory = $true)][int]$TailLineCount,
        [Parameter(Mandatory = $true)][string]$TailExcerpt
    )

    return ($Detail + (" tail_log={0} tail_used={1} tail_lines={2} tail_excerpt={3}" -f
            $RuntimeLogPath,
            $TailUsed,
            $TailLineCount,
            $TailExcerpt))
}

function Get-MainProcessExitEvidenceTokenFromArtifact {
    param([Parameter(Mandatory = $true)][pscustomobject]$ExitReasonEvidence)

    return ("artifact:{0}|exit:{1}|category:{2}" -f
            [string]$ExitReasonEvidence.ArtifactPath,
            [int]$ExitReasonEvidence.ExitCode,
            [string]$ExitReasonEvidence.FailCategory)
}

function Get-MainProcessExitEvidenceTokenFromTail {
    param(
        [Parameter(Mandatory = $true)][string]$RuntimeLogPath,
        [Parameter(Mandatory = $true)][int]$TailUsed,
        [Parameter(Mandatory = $true)][int]$TailLineCount
    )

    return ("tail:{0}|used:{1}|lines:{2}" -f $RuntimeLogPath, $TailUsed, $TailLineCount)
}

function Get-RoundFailureCategorySet {
    return @('runner-fail', 'script-fault', 'code-or-unknown', 'verify-failure', 'compile-failure', 'compile-warning', 'task-definition-mismatch')
}

function Get-AMainProcessExitDedupSuffix {
    param(
        [Parameter(Mandatory = $true)][string]$SessionStatus,
        [Parameter(Mandatory = $true)][string]$AStatus,
        [Parameter(Mandatory = $true)][string]$BStatus,
        [AllowEmptyString()][string]$RunDirAnchor,
        [Parameter(Mandatory = $true)][int]$ALaunchPid
    )

    return ("{0}|{1}|{2}|{3}|{4}|stage=A" -f $SessionStatus, $AStatus, $BStatus, $RunDirAnchor, $ALaunchPid)
}

function Get-BMainProcessExitDedupSuffix {
    param(
        [Parameter(Mandatory = $true)][string]$SessionStatus,
        [Parameter(Mandatory = $true)][string]$AStatus,
        [Parameter(Mandatory = $true)][string]$BStatus,
        [AllowEmptyString()][string]$RunDirAnchor,
        [Parameter(Mandatory = $true)][int]$BLaunchPid,
        [Parameter(Mandatory = $true)][bool]$AutoRecoverB,
        [Parameter(Mandatory = $true)][string]$MainExitEvidenceToken
    )

    return ("{0}|{1}|{2}|{3}|{4}|{5}|{6}" -f $SessionStatus, $AStatus, $BStatus, $RunDirAnchor, $BLaunchPid, $AutoRecoverB, $MainExitEvidenceToken)
}

function Test-IsRoundFailureCategory {
    param([AllowEmptyString()][string]$Category)

    if ([string]::IsNullOrWhiteSpace($Category)) {
        return $false
    }
    return ((Get-RoundFailureCategorySet) -contains $Category)
}

function Test-ObjectHasProperty {
    param(
        [object]$InputObject,
        [Parameter(Mandatory = $true)][string]$PropertyName
    )

    if ($null -eq $InputObject) {
        return $false
    }

    return ($null -ne $InputObject.PSObject -and $null -ne $InputObject.PSObject.Properties[$PropertyName])
}

function Get-TicketResultQueuedFlag {
    param([object]$TicketResult)

    if (-not (Test-ObjectHasProperty -InputObject $TicketResult -PropertyName 'Queued')) {
        return $false
    }

    return [bool]$TicketResult.Queued
}

function Get-TicketResultReason {
    param([object]$TicketResult)

    if (-not (Test-ObjectHasProperty -InputObject $TicketResult -PropertyName 'Reason')) {
        return ''
    }

    return [string]$TicketResult.Reason
}

function Test-ShouldUpdateTicketSignature {
    param([pscustomobject]$TicketResult)

    if ($null -eq $TicketResult) {
        return $false
    }
    return ((Get-TicketResultQueuedFlag -TicketResult $TicketResult) -or (Get-TicketResultReason -TicketResult $TicketResult) -eq 'duplicate-signature')
}

function Test-HasUsableRunDirAnchor {
    param([AllowEmptyString()][string]$RunDirAnchor)

    return (-not [string]::IsNullOrWhiteSpace($RunDirAnchor) -and $RunDirAnchor -ne 'unknown')
}

function Reset-AMissingProcessTracking {
    param(
        [ref]$RunningNoProcessSince,
        [ref]$LastMissingProcessReportAt
    )

    $RunningNoProcessSince.Value = $null
    $LastMissingProcessReportAt.Value = $null
}

function Reset-BMissingProcessTracking {
    param(
        [ref]$RunningNoProcessSince,
        [ref]$LastMissingProcessReportAt,
        [ref]$LastMissingExitReasonEvidence,
        [ref]$LastMissingRuntimeTailEvidence
    )

    $RunningNoProcessSince.Value = $null
    $LastMissingProcessReportAt.Value = $null
    $LastMissingExitReasonEvidence.Value = $null
    $LastMissingRuntimeTailEvidence.Value = $null
}

function Reset-D1ProgressTracking {
    param(
        [ref]$StallSince,
        [ref]$StallTriggeredSignature,
        [ref]$StallPrevFileCount,
        [ref]$StallPrevLatestWrite,
        [ref]$StallPrevRowCount,
        [ref]$StallLastReportAt,
        [ref]$ObserveStartedAt,
        [bool]$ResetLastReportAt = $false,
        [bool]$ResetObserveStartedAt = $false
    )

    $StallSince.Value = $null
    $StallTriggeredSignature.Value = ''
    $StallPrevFileCount.Value = -1
    $StallPrevLatestWrite.Value = [datetime]::MinValue
    $StallPrevRowCount.Value = -1

    if ($ResetLastReportAt) {
        $StallLastReportAt.Value = $null
    }
    if ($ResetObserveStartedAt) {
        $ObserveStartedAt.Value = $null
    }
}

function Test-IsAnyStageRunning {
    param(
        [Parameter(Mandatory = $true)][string]$AStatus,
        [Parameter(Mandatory = $true)][string]$BStatus
    )

    return ($AStatus -eq 'RUNNING' -or $BStatus -eq 'RUNNING')
}

function Test-ShouldEmitMainExitReview {
    param(
        [Parameter(Mandatory = $true)][string]$DedupSuffix,
        [AllowNull()][AllowEmptyString()][string]$LastSignature = '',
        [Parameter(Mandatory = $true)][bool]$SkipReview
    )

    return ($DedupSuffix -ne $LastSignature -and -not $SkipReview)
}

function Get-HandoverWindowState {
    param(
        [System.Collections.IDictionary]$Settings,
        [ValidateRange(30, 900)][int]$WindowSeconds = 180
    )

    $state = 'unknown'
    $startedAtRaw = ''
    $completedAtRaw = ''
    if ($null -ne $Settings) {
        if ($Settings.Contains('AB_HANDOVER_STATE')) {
            $state = (Convert-ToSingleLineText -Text ([string]$Settings.AB_HANDOVER_STATE)).ToUpperInvariant()
        }
        if ($Settings.Contains('AB_HANDOVER_STARTED_AT')) {
            $startedAtRaw = Convert-ToSingleLineText -Text ([string]$Settings.AB_HANDOVER_STARTED_AT)
        }
        if ($Settings.Contains('AB_HANDOVER_COMPLETED_AT')) {
            $completedAtRaw = Convert-ToSingleLineText -Text ([string]$Settings.AB_HANDOVER_COMPLETED_AT)
        }
    }

    $refRaw = if ($state -eq 'A_TO_B_COMPLETE') { $completedAtRaw } else { $startedAtRaw }
    $refAt = [datetime]::MinValue
    $hasRef = $false
    if (-not [string]::IsNullOrWhiteSpace($refRaw)) {
        $hasRef = [datetime]::TryParse($refRaw, [ref]$refAt)
    }

    $elapsedSec = -1
    $active = $false
    if ($hasRef) {
        $elapsedSec = [Math]::Max(0, [int][Math]::Round(((Get-Date) - $refAt).TotalSeconds))
        if ($elapsedSec -le $WindowSeconds -and $state -in @('A_TO_B_PENDING', 'A_TO_B_COMPLETE')) {
            $active = $true
        }
    }

    return [pscustomobject]@{
        Active = [bool]$active
        State = $state
        ElapsedSec = [int]$elapsedSec
        WindowSec = [int]$WindowSeconds
        StartedAt = $startedAtRaw
        CompletedAt = $completedAtRaw
    }
}

function Get-NormalizedFailureCategory {
    param(
        [AllowEmptyString()][string]$Primary,
        [AllowEmptyString()][string]$Fallback = '',
        [AllowEmptyString()][string]$Default = ''
    )

    $category = (Convert-ToSingleLineText -Text $Primary).ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($category)) {
        $category = (Convert-ToSingleLineText -Text $Fallback).ToLowerInvariant()
    }
    if ([string]::IsNullOrWhiteSpace($category)) {
        $category = $Default
    }
    return $category
}

function Get-RestartAwaitConfirmationTicketContext {
    param(
        [AllowEmptyString()][string]$RoundTag,
        [AllowEmptyString()][string]$Category,
        [int]$Attempt,
        [int]$MaxAttempts,
        [AllowEmptyString()][string]$Reason,
        [AllowEmptyString()][string]$Detail,
        [AllowEmptyString()][string]$RunDirAnchor
    )

    return [pscustomobject]@{
        Detail = ("stage=A round={0} category={1} attempt={2}/{3} reason={4} detail={5}" -f
            [string]$RoundTag,
            [string]$Category,
            [int]$Attempt,
            [int]$MaxAttempts,
            [string]$Reason,
            (Convert-ToBoundedSingleLineText -Text ([string]$Detail) -MaxChars 180))
        DedupSuffix = ("{0}|{1}|{2}|{3}" -f [string]$RoundTag, [string]$Category, [int]$Attempt, [string]$RunDirAnchor)
    }
}

function Get-RecoveryResultLogCompactFields {
    param(
        [AllowEmptyString()][string]$Detail,
        [AllowEmptyString()][string]$Evidence
    )

    return [pscustomobject]@{
        DetailCompact = (Convert-ToBoundedSingleLineText -Text ([string]$Detail) -MaxChars 180)
        EvidenceCompact = (Convert-ToBoundedSingleLineText -Text ([string]$Evidence) -MaxChars 140)
    }
}

function Get-AutoFixResultLogCompactFields {
    param([AllowEmptyString()][string]$Detail)

    return [pscustomobject]@{
        DetailCompact220 = (Convert-ToBoundedSingleLineText -Text ([string]$Detail) -MaxChars 220)
        DetailCompact180 = (Convert-ToBoundedSingleLineText -Text ([string]$Detail) -MaxChars 180)
    }
}

function Reset-RestartRecoveryMonitorState {
    param(
        [ref]$ManualPauseActive,
        [ref]$ManualPauseSignature,
        [ref]$ManualPauseNoticeCount,
        [ref]$LastIncidentSignature,
        [ref]$LastBudgetExhaustedSignature
    )

    $ManualPauseActive.Value = $false
    $ManualPauseSignature.Value = ''
    $ManualPauseNoticeCount.Value = 0
    $LastIncidentSignature.Value = ''
    $LastBudgetExhaustedSignature.Value = ''
}

function Add-RestartAwaitConfirmationTicket {
    param(
        [bool]$Enabled,
        [AllowEmptyString()][string]$QueuePath,
        [AllowEmptyString()][string]$EventName,
        [AllowEmptyString()][string]$SessionStatus,
        [AllowEmptyString()][string]$AStatus,
        [AllowEmptyString()][string]$BStatus,
        [AllowEmptyString()][string]$RunDirAnchor,
        [pscustomobject]$TicketContext,
        [AllowEmptyString()][string]$RecommendedAction,
        [AllowEmptyString()][string]$MainRound,
        [AllowEmptyString()][string]$FailureKind,
        [AllowEmptyString()][string]$FailureCategory,
        [AllowEmptyString()][string]$FailureSource,
        [AllowEmptyString()][string]$FailureEvidence,
        [bool]$NonRecoverableEnv,
        [AllowEmptyString()][string]$PreferredStage = 'A',
        [bool]$SelfHealable = $true
    )

    return Add-AgentTicket -Enabled $Enabled -QueuePath $QueuePath -EventName $EventName -Severity 'high' -RequiresConfirmation $true -SessionStatus $SessionStatus -AStatus $AStatus -BStatus $BStatus -RunDirAnchor $RunDirAnchor -IncidentDir '' -Detail ([string]$TicketContext.Detail) -DedupSuffix ([string]$TicketContext.DedupSuffix) -RecommendedAction $RecommendedAction -PreferredStage $PreferredStage -MainRound $MainRound -FailureKind $FailureKind -FailureCategory $FailureCategory -FailureSource $FailureSource -FailureEvidence $FailureEvidence -SelfHealable $SelfHealable -NonRecoverableEnv $NonRecoverableEnv
}

function Add-BudgetExhaustedStopTicket {
    param(
        [bool]$Enabled,
        [AllowEmptyString()][string]$QueuePath,
        [AllowEmptyString()][string]$SessionStatus,
        [AllowEmptyString()][string]$AStatus,
        [AllowEmptyString()][string]$BStatus,
        [AllowEmptyString()][string]$RunDirAnchor,
        [AllowEmptyString()][string]$Detail,
        [AllowEmptyString()][string]$DedupSuffix,
        [AllowEmptyString()][string]$MainRound,
        [AllowEmptyString()][string]$FailureCategory,
        [AllowEmptyString()][string]$FailureSource,
        [AllowEmptyString()][string]$FailureEvidence,
        [bool]$NonRecoverableEnv
    )

    return Add-AgentTicket -Enabled $Enabled -QueuePath $QueuePath -EventName 'budget-exhausted-stop' -Severity 'high' -RequiresConfirmation $false -SessionStatus $SessionStatus -AStatus $AStatus -BStatus $BStatus -RunDirAnchor $RunDirAnchor -IncidentDir '' -Detail $Detail -DedupSuffix $DedupSuffix -RecommendedAction 'Report the budget/cooldown constraint and decide rerun scope only; this notice grants no new repair, resume, or restart authority.' -PreferredStage 'B' -MainRound $MainRound -FailureKind 'budget-exhausted' -FailureCategory $FailureCategory -FailureSource $FailureSource -FailureEvidence $FailureEvidence -SelfHealable $false -NonRecoverableEnv $NonRecoverableEnv
}

function Get-AutoFixAwaitRecommendedAction {
    param(
        [bool]$IsDevRound,
        [bool]$FailureHasScriptFault,
        [bool]$FailureHasCodeFault
    )

    $recommendedAction = 'Set LOCAL_GUARD_RESTART_APPROVED=true only after evidence review, then resume A-stage restart.'
    if ($IsDevRound -and $FailureHasScriptFault -and $FailureHasCodeFault) {
        return 'Code fault markers exist in this D-round failure. Repair only allowed task-definition operations; run SyntaxOnly, the failed-op target check when locatable, then the current failing round progressively. Do not preflight later rounds; keep absorbed/idempotent rounds as regex-patch rather than noop.'
    }
    if ($IsDevRound -and $FailureHasScriptFault) {
        return 'Fix D-round unattended scripts only (guard/trigger/dispatch/poll), complete script validation evidence, then set LOCAL_GUARD_RESTART_APPROVED=true for guarded restart.'
    }
    if ($IsDevRound -and $FailureHasCodeFault) {
        return 'Review D-round code-fix evidence; run SyntaxOnly, the failed-op target check when locatable, then the current failing round progressively before same-stage restart. Keep absorbed/idempotent rounds as regex-patch; for V1-V4 only append after existing D4 content.'
    }

    return $recommendedAction
}

function Get-AutoFixAwaitConfirmationTicketContext {
    param(
        [AllowEmptyString()][string]$RoundTag,
        [int]$Attempt,
        [int]$MaxAttempts,
        [AllowEmptyString()][string]$Reason,
        [AllowEmptyString()][string]$Detail,
        [AllowEmptyString()][string]$RunDirAnchor
    )

    return [pscustomobject]@{
        Detail = ("stage=A round={0} attempt={1}/{2} reason={3} detail={4}" -f
            [string]$RoundTag,
            [int]$Attempt,
            [int]$MaxAttempts,
            [string]$Reason,
            (Convert-ToBoundedSingleLineText -Text ([string]$Detail) -MaxChars 200))
        DedupSuffix = ("{0}|{1}|{2}|{3}" -f [string]$RoundTag, [int]$Attempt, [string]$Reason, [string]$RunDirAnchor)
    }
}

function Get-RecoveryAwaitConfirmationTicketContext {
    param(
        [int]$Attempts,
        [int]$MaxAttempts,
        [AllowEmptyString()][string]$SessionStatus,
        [AllowEmptyString()][string]$AStatus,
        [AllowEmptyString()][string]$BStatus,
        [AllowEmptyString()][string]$RunDirAnchor
    )

    return [pscustomobject]@{
        Detail = ("stage=B attempts={0}/{1} status={2} a={3} b={4}" -f [int]$Attempts, [int]$MaxAttempts, [string]$SessionStatus, [string]$AStatus, [string]$BStatus)
        DedupSuffix = ("{0}|{1}|{2}|{3}|{4}" -f [string]$SessionStatus, [string]$AStatus, [string]$BStatus, [string]$RunDirAnchor, [int]$Attempts)
    }
}

function Write-RestartRunningState {
    param(
        [AllowEmptyString()][string]$EventName,
        [hashtable]$ExtraValues
    )

    $stateValues = @{
        status = 'running'
        event = $EventName
        stop_reason = ''
    }

    if ($null -ne $ExtraValues) {
        foreach ($key in $ExtraValues.Keys) {
            $stateValues[$key] = $ExtraValues[$key]
        }
    }

    Write-GuardState -Values $stateValues
}

function Write-PausedSessionState {
    param(
        [AllowEmptyString()][string]$EventName,
        [AllowEmptyString()][string]$SessionStatus,
        [AllowEmptyString()][string]$AStatus,
        [AllowEmptyString()][string]$BStatus,
        [hashtable]$ExtraValues = $null
    )

    $stateValues = @{
        status = 'paused'
        event = $EventName
        stop_reason = ''
        session_final_status = $SessionStatus
        a_final_status = $AStatus
        b_final_status = $BStatus
    }

    if ($null -ne $ExtraValues) {
        foreach ($key in $ExtraValues.Keys) {
            $stateValues[$key] = $ExtraValues[$key]
        }
    }

    Write-GuardState -Values $stateValues
}

function Write-StoppedSessionState {
    param(
        [AllowEmptyString()][string]$EventName,
        [AllowEmptyString()][string]$StopReason,
        [AllowEmptyString()][string]$SessionStatus,
        [AllowEmptyString()][string]$AStatus,
        [AllowEmptyString()][string]$BStatus,
        [hashtable]$ExtraValues = $null
    )

    $stateValues = @{
        status = 'stopped'
        event = $EventName
        stop_reason = $StopReason
        session_final_status = $SessionStatus
        a_final_status = $AStatus
        b_final_status = $BStatus
    }

    if ($null -ne $ExtraValues) {
        foreach ($key in $ExtraValues.Keys) {
            $stateValues[$key] = $ExtraValues[$key]
        }
    }

    Write-GuardState -Values $stateValues
}

function Get-SessionStatusTripleDetail {
    param(
        [AllowEmptyString()][string]$SessionStatus,
        [AllowEmptyString()][string]$AStatus,
        [AllowEmptyString()][string]$BStatus
    )

    return ("status={0} a={1} b={2}" -f $SessionStatus, $AStatus, $BStatus)
}

function Get-RecoveryFlagsExtraValues {
    param(
        [bool]$AutoRecoverB,
        [bool]$CanRecoverB
    )

    return (New-RecoveryFlagsExtraValues -AutoRecoverB $AutoRecoverB -CanRecoverB $CanRecoverB)
}

function New-RecoveryFlagsExtraValues {
    param(
        [bool]$AutoRecoverB,
        [bool]$CanRecoverB,
        [AllowEmptyString()][string]$Stage = '',
        [int]$RecoveryAttempts = -1
    )

    $extraValues = @{
        auto_recover = [bool]$AutoRecoverB
        auto_recover_b = [bool]$AutoRecoverB
        can_recover_b = [bool]$CanRecoverB
    }

    if (-not [string]::IsNullOrWhiteSpace($Stage) -and $RecoveryAttempts -ge 0) {
        $extraValues.recovery_stage = $Stage
        $extraValues.recovery_attempts = [int]$RecoveryAttempts

        if ($Stage -eq 'B') {
            $extraValues.b_recovery_attempts = [int]$RecoveryAttempts
        }
    }

    return $extraValues
}

function Get-RecoveryFlagsWithManualNoticeExtraValues {
    param(
        [bool]$AutoRecoverB,
        [bool]$CanRecoverB,
        [int]$ManualNoticeRepeat
    )

    $extraValues = New-RecoveryFlagsExtraValues -AutoRecoverB $AutoRecoverB -CanRecoverB $CanRecoverB
    $extraValues.manual_notice_repeat = [int]$ManualNoticeRepeat
    return $extraValues
}

function Get-RecoveryCapabilityDetail {
    param(
        [bool]$AutoRecoverB,
        [bool]$CanRecoverB
    )

    return ("auto_recover_b={0} can_recover_b={1}" -f [bool]$AutoRecoverB, [bool]$CanRecoverB)
}

function Get-SessionRecoveryStatusDetail {
    param(
        [AllowEmptyString()][string]$SessionStatus,
        [AllowEmptyString()][string]$AStatus,
        [AllowEmptyString()][string]$BStatus,
        [bool]$AutoRecoverB,
        [bool]$CanRecoverB
    )

    $recoveryCapabilityDetail = Get-RecoveryCapabilityDetail -AutoRecoverB $AutoRecoverB -CanRecoverB $CanRecoverB
    return ("status={0} a={1} b={2} {3}" -f $SessionStatus, $AStatus, $BStatus, $recoveryCapabilityDetail)
}

function Get-BudgetExhaustedDetail {
    param(
        [int]$Attempts,
        [int]$MaxAttempts,
        [bool]$StopOnBudgetExhausted
    )

    return ("attempts={0} max={1} stop_on_budget_exhausted={2}" -f $Attempts, $MaxAttempts, $StopOnBudgetExhausted)
}

function Get-BudgetAttemptsDetail {
    param(
        [int]$Attempts,
        [int]$MaxAttempts
    )

    return ("attempts={0}/{1}" -f $Attempts, $MaxAttempts)
}

function Write-WaitingMonitorChainGraceState {
    param(
        [AllowEmptyString()][string]$SessionStatus,
        [AllowEmptyString()][string]$AStatus,
        [AllowEmptyString()][string]$BStatus,
        [AllowEmptyString()][string]$GraceStage,
        [double]$RemainingGraceMinutes,
        [AllowEmptyString()][string]$GraceReason = ''
    )

    $stateValues = @{
        status = 'waiting-monitor-chain-grace'
        event = 'monitor-chain-grace'
        stop_reason = ''
        session_final_status = $SessionStatus
        a_final_status = $AStatus
        b_final_status = $BStatus
        grace_stage = $GraceStage
        grace_remaining_min = ([Math]::Round($RemainingGraceMinutes, 1))
    }

    if (-not [string]::IsNullOrWhiteSpace($GraceReason)) {
        $stateValues.grace_reason = $GraceReason
    }

    Write-GuardState -Values $stateValues
}

function Write-RecoveryCompletionLog {
    param(
        [AllowEmptyString()][string]$Reason,
        [AllowEmptyString()][string]$SessionStatus,
        [AllowEmptyString()][string]$AStatus,
        [AllowEmptyString()][string]$BStatus,
        [bool]$AutoRecoverB,
        [bool]$CanRecoverB
    )

    $recoveryDetail = Get-SessionRecoveryStatusDetail -SessionStatus $SessionStatus -AStatus $AStatus -BStatus $BStatus -AutoRecoverB $AutoRecoverB -CanRecoverB $CanRecoverB
    Write-GuardLog ("complete reason={0} {1}" -f $Reason, $recoveryDetail)
}

function Write-FinalNoFollowupRecoveryCompletionLog {
    param(
        [bool]$Forced,
        [AllowEmptyString()][string]$SessionStatus,
        [AllowEmptyString()][string]$AStatus,
        [AllowEmptyString()][string]$BStatus,
        [bool]$AutoRecoverB,
        [bool]$CanRecoverB
    )

    $reason = if ($Forced) { 'final_state_no_followup_forced' } else { 'final_state_no_followup' }
    Write-RecoveryCompletionLog -Reason $reason -SessionStatus $SessionStatus -AStatus $AStatus -BStatus $BStatus -AutoRecoverB $AutoRecoverB -CanRecoverB $CanRecoverB
}

function Write-BudgetExhaustedDeferActiveState {
    param(
        [ValidateSet('A', 'B')][string]$Stage = 'B',
        [int]$RecoveryAttempts,
        [AllowEmptyString()][string]$LivenessDetail
    )

    $stateValues = @{
        status = 'running'
        event = 'budget-exhausted-defer-active'
        stop_reason = ''
        recovery_stage = $Stage
        recovery_attempts = [int]$RecoveryAttempts
        b_liveness_detail = $LivenessDetail
    }

    if ($Stage -eq 'B') {
        $stateValues.b_recovery_attempts = [int]$RecoveryAttempts
    }

    Write-GuardState -Values $stateValues
}

function Write-RestartTriggeredRunningState {
    param(
        [ValidateSet('A', 'B')][string]$Stage = 'B',
        [int]$RecoveryAttempts,
        [AllowEmptyString()][string]$LastRecoveryAtText
    )

    $stateValues = @{
        status = 'running'
        last_action = 'restart-triggered'
        recovery_stage = $Stage
        recovery_attempts = [int]$RecoveryAttempts
        recovery_last_at = $LastRecoveryAtText
    }

    if ($Stage -eq 'B') {
        $stateValues.b_recovery_attempts = [int]$RecoveryAttempts
        $stateValues.last_recovery_at = $LastRecoveryAtText
    }

    Write-GuardState -Values $stateValues
}

function Write-WaitingMainExitGraceState {
    param(
        [AllowEmptyString()][string]$SessionStatus,
        [AllowEmptyString()][string]$AStatus,
        [AllowEmptyString()][string]$BStatus,
        [AllowEmptyString()][string]$GraceStage,
        [double]$RemainingGraceMinutes
    )

    Write-GuardState -Values @{
        status = 'waiting-main-exit-grace'
        event = 'main-process-exit-grace'
        stop_reason = ''
        session_final_status = $SessionStatus
        a_final_status = $AStatus
        b_final_status = $BStatus
        grace_stage = $GraceStage
        grace_remaining_min = ([Math]::Round($RemainingGraceMinutes, 1))
    }
}

function Get-RecoveryApprovalPauseExtraValues {
    param(
        [bool]$AutoRecoverB,
        [bool]$CanRecoverB,
        [bool]$RestartRequiresConfirmation,
        [bool]$RestartApproved,
        [ValidateSet('A', 'B')][string]$Stage = 'B',
        [int]$RecoveryAttempts
    )

    $extraValues = New-RecoveryFlagsExtraValues -AutoRecoverB $AutoRecoverB -CanRecoverB $CanRecoverB -Stage $Stage -RecoveryAttempts $RecoveryAttempts

    $restartFlags = Get-RestartApprovalFlagsExtraValues -RestartRequiresConfirmation $RestartRequiresConfirmation -RestartApproved $RestartApproved
    foreach ($key in $restartFlags.Keys) {
        $extraValues[$key] = $restartFlags[$key]
    }

    return $extraValues
}

function Write-BudgetExhaustedStoppedState {
    param(
        [ValidateSet('A', 'B')][string]$Stage = 'B',
        [int]$RecoveryAttempts
    )

    $stateValues = @{
        status = 'stopped'
        event = 'budget-exhausted'
        stop_reason = 'budget-exhausted'
        recovery_stage = $Stage
        recovery_attempts = [int]$RecoveryAttempts
    }

    if ($Stage -eq 'B') {
        $stateValues.b_recovery_attempts = [int]$RecoveryAttempts
    }

    Write-GuardState -Values $stateValues
}

function Write-MonitorChainGraceStartLog {
    param(
        [AllowEmptyString()][string]$Stage,
        [int]$GraceMinutes,
        [AllowEmptyString()][string]$Reason,
        [AllowEmptyString()][string]$SessionStatus,
        [AllowEmptyString()][string]$AStatus,
        [AllowEmptyString()][string]$BStatus,
        [AllowEmptyString()][string]$RunDirAnchor
    )

    Write-GuardLog ("monitor_chain_grace_start stage={0} grace_min={1} reason={2} session={3} a={4} b={5} run_dir={6}" -f
        $Stage,
        $GraceMinutes,
        $Reason,
        $SessionStatus,
        $AStatus,
        $BStatus,
        $RunDirAnchor)
}

function Write-MonitorChainGraceExpiredLog {
    param(
        [AllowEmptyString()][string]$Stage,
        [double]$ElapsedMinutes,
        [AllowEmptyString()][string]$Reason
    )

    Write-GuardLog ("monitor_chain_grace_expired stage={0} elapsed_min={1:N1} reason={2}" -f $Stage, $ElapsedMinutes, $Reason)
}

function Write-StageRecoveryResultLog {
    param(
        [ValidateSet('A', 'B')][string]$Stage,
        [ValidateSet('triggered', 'failed')][string]$Result,
        [int]$Attempt,
        [int]$ExitCode = 0
    )

    $stagePolicy = Get-StagePolicy -Stage $Stage

    if ($Result -eq 'triggered') {
        Write-GuardLog ("recovery_triggered stage={0} attempt={1}" -f [string]$stagePolicy.Stage, $Attempt)
        return
    }

    Write-GuardLog ("recovery_failed stage={0} attempt={1} exit_code={2}" -f [string]$stagePolicy.Stage, $Attempt, $ExitCode)
}

function Write-BStageRecoveryResultLog {
    param(
        [ValidateSet('triggered', 'failed')][string]$Result,
        [int]$Attempt,
        [int]$ExitCode = 0
    )

    Write-StageRecoveryResultLog -Stage 'B' -Result $Result -Attempt $Attempt -ExitCode $ExitCode
}

function Write-BudgetExhaustedSkipLog {
    param(
        [int]$Attempts,
        [int]$MaxAttempts
    )

    Write-GuardLog ("recovery_skip reason=budget_exhausted attempts={0} max={1}" -f $Attempts, $MaxAttempts)
}

function Write-BudgetExhaustedCompletionLog {
    param(
        [int]$Attempts,
        [int]$MaxAttempts,
        [bool]$StopOnBudgetExhausted
    )

    Write-GuardLog ("complete reason=budget_exhausted attempts={0} max={1} stop_on_budget_exhausted={2}" -f $Attempts, $MaxAttempts, $StopOnBudgetExhausted)
}

function Write-StoppedRecoverySessionState {
    param(
        [AllowEmptyString()][string]$EventName,
        [AllowEmptyString()][string]$StopReason = '',
        [AllowEmptyString()][string]$SessionStatus,
        [AllowEmptyString()][string]$AStatus,
        [AllowEmptyString()][string]$BStatus,
        [bool]$AutoRecoverB,
        [bool]$CanRecoverB
    )

    if ([string]::IsNullOrWhiteSpace($StopReason)) {
        $StopReason = $EventName
    }

    Write-StoppedSessionState -EventName $EventName -StopReason $StopReason -SessionStatus $SessionStatus -AStatus $AStatus -BStatus $BStatus -ExtraValues (Get-RecoveryFlagsExtraValues -AutoRecoverB $AutoRecoverB -CanRecoverB $CanRecoverB)
}

function Write-RecoveryStatusLog {
    param(
        [AllowEmptyString()][string]$Prefix,
        [AllowEmptyString()][string]$SessionStatus,
        [AllowEmptyString()][string]$AStatus,
        [AllowEmptyString()][string]$BStatus,
        [bool]$AutoRecoverB,
        [bool]$CanRecoverB,
        [AllowEmptyString()][string]$StatusDetail = '',
        [AllowEmptyString()][string]$Suffix = ''
    )

    if ([string]::IsNullOrWhiteSpace($StatusDetail)) {
        $StatusDetail = Get-SessionRecoveryStatusDetail -SessionStatus $SessionStatus -AStatus $AStatus -BStatus $BStatus -AutoRecoverB $AutoRecoverB -CanRecoverB $CanRecoverB
    }
    if ([string]::IsNullOrWhiteSpace($Suffix)) {
        Write-GuardLog ("{0} {1}" -f $Prefix, $StatusDetail)
        return
    }

    Write-GuardLog ("{0} {1} {2}" -f $Prefix, $StatusDetail, $Suffix)
}

function Write-ManualActionRequiredLog {
    param(
        [AllowEmptyString()][string]$SessionStatus,
        [AllowEmptyString()][string]$AStatus,
        [AllowEmptyString()][string]$BStatus,
        [bool]$AutoRecoverB,
        [bool]$CanRecoverB,
        [int]$NoticeIndex = 0,
        [int]$NoticeRepeat = 0
    )

    $statusDetail = Get-SessionRecoveryStatusDetail -SessionStatus $SessionStatus -AStatus $AStatus -BStatus $BStatus -AutoRecoverB $AutoRecoverB -CanRecoverB $CanRecoverB
    if ($NoticeIndex -gt 0 -and $NoticeRepeat -gt 0) {
        Write-RecoveryStatusLog -Prefix 'manual_action_required' -SessionStatus $SessionStatus -AStatus $AStatus -BStatus $BStatus -AutoRecoverB $AutoRecoverB -CanRecoverB $CanRecoverB -StatusDetail $statusDetail -Suffix ("notice={0}/{1}" -f $NoticeIndex, $NoticeRepeat)
        return
    }

    Write-RecoveryStatusLog -Prefix 'manual_action_required' -SessionStatus $SessionStatus -AStatus $AStatus -BStatus $BStatus -AutoRecoverB $AutoRecoverB -CanRecoverB $CanRecoverB -StatusDetail $statusDetail
}

function Write-StartFileMissingStopState {
    param(
        [AllowEmptyString()][string]$MissingStartFile
    )

    Write-GuardState -Values @{
        status = 'stopped'
        event = 'start-file-missing'
        stop_reason = 'start-file-missing'
        missing_start_file = $MissingStartFile
    }
    Write-GuardLog ("complete reason=start_file_missing start_file={0}" -f $MissingStartFile)
}

function Write-GraceWaitLog {
    param(
        [AllowEmptyString()][string]$Prefix,
        [AllowEmptyString()][string]$Stage,
        [double]$ElapsedMinutes,
        [double]$RemainingMinutes,
        [AllowEmptyString()][string]$SessionStatus,
        [AllowEmptyString()][string]$AStatus,
        [AllowEmptyString()][string]$BStatus,
        [AllowEmptyString()][string]$Reason = ''
    )

    if (-not [string]::IsNullOrWhiteSpace($Reason)) {
        Write-GuardLog ("{0} stage={1} elapsed_min={2:N1} remaining_min={3:N1} reason={4} session={5} a={6} b={7}" -f $Prefix, $Stage, $ElapsedMinutes, $RemainingMinutes, $Reason, $SessionStatus, $AStatus, $BStatus)
        return
    }

    Write-GuardLog ("{0} stage={1} elapsed_min={2:N1} remaining_min={3:N1} session={4} a={5} b={6}" -f $Prefix, $Stage, $ElapsedMinutes, $RemainingMinutes, $SessionStatus, $AStatus, $BStatus)
}

function Write-MonitorChainGraceWaitLog {
    param(
        [AllowEmptyString()][string]$Stage,
        [double]$ElapsedMinutes,
        [double]$RemainingMinutes,
        [AllowEmptyString()][string]$SessionStatus,
        [AllowEmptyString()][string]$AStatus,
        [AllowEmptyString()][string]$BStatus,
        [AllowEmptyString()][string]$Reason = ''
    )

    Write-GraceWaitLog -Prefix 'monitor_chain_grace_wait' -Stage $Stage -ElapsedMinutes $ElapsedMinutes -RemainingMinutes $RemainingMinutes -SessionStatus $SessionStatus -AStatus $AStatus -BStatus $BStatus -Reason $Reason
}

function Get-RestartApprovalFlagsExtraValues {
    param(
        [bool]$RestartRequiresConfirmation,
        [bool]$RestartApproved
    )

    return @{
        restart_requires_confirmation = [bool]$RestartRequiresConfirmation
        restart_approved = [bool]$RestartApproved
    }
}

function Get-EvidenceDetailByPrefix {
    param(
        [AllowEmptyString()][string]$Prefix,
        [AllowEmptyString()][string]$SessionStatus,
        [AllowEmptyString()][string]$AStatus,
        [AllowEmptyString()][string]$BStatus,
        [AllowEmptyString()][string]$Evidence
    )

    return ("{0}={1} a={2} b={3} evidence={4}" -f $Prefix, $SessionStatus, $AStatus, $BStatus, $Evidence)
}

function Get-StatusEvidenceDetail {
    param(
        [AllowEmptyString()][string]$SessionStatus,
        [AllowEmptyString()][string]$AStatus,
        [AllowEmptyString()][string]$BStatus,
        [AllowEmptyString()][string]$Evidence
    )

    return (Get-EvidenceDetailByPrefix -Prefix 'status' -SessionStatus $SessionStatus -AStatus $AStatus -BStatus $BStatus -Evidence $Evidence)
}

function Get-SessionEvidenceDetail {
    param(
        [AllowEmptyString()][string]$SessionStatus,
        [AllowEmptyString()][string]$AStatus,
        [AllowEmptyString()][string]$BStatus,
        [AllowEmptyString()][string]$Evidence
    )

    return (Get-EvidenceDetailByPrefix -Prefix 'session' -SessionStatus $SessionStatus -AStatus $AStatus -BStatus $BStatus -Evidence $Evidence)
}

function Write-SessionReviveLog {
    param(
        [ValidateSet('A', 'B')][string]$Stage,
        [int]$ProcessId,
        [AllowEmptyString()][string]$SessionStatus,
        [AllowEmptyString()][string]$StageStatus
    )

    $stageStatusLabel = if ($Stage -eq 'A') { 'a' } else { 'b' }
    Write-GuardLog ("session_revive stage={0} pid={1} session={2} {3}={4} -> RUNNING" -f $Stage, $ProcessId, $SessionStatus, $stageStatusLabel, $StageStatus)
}

function Get-SessionRunningSummaryDetail {
    param(
        [AllowEmptyString()][string]$SessionStatus,
        [AllowEmptyString()][string]$AStatus,
        [AllowEmptyString()][string]$BStatus,
        [bool]$Running,
        [AllowEmptyString()][string]$RunDirAnchor
    )

    return ("session={0} a={1} b={2} running={3} run_dir={4}" -f $SessionStatus, $AStatus, $BStatus, $Running, $RunDirAnchor)
}

function Get-LoopRecoveryStatusDetail {
    param(
        [AllowEmptyString()][string]$SessionStatus,
        [AllowEmptyString()][string]$AStatus,
        [AllowEmptyString()][string]$BStatus,
        [bool]$AutoRecoverB,
        [bool]$CanRecoverB
    )

    return (Get-SessionRecoveryStatusDetail -SessionStatus $SessionStatus -AStatus $AStatus -BStatus $BStatus -AutoRecoverB $AutoRecoverB -CanRecoverB $CanRecoverB)
}

function Get-RecoveryStateArgs {
    param(
        [AllowEmptyString()][string]$SessionStatus,
        [AllowEmptyString()][string]$AStatus,
        [AllowEmptyString()][string]$BStatus,
        [bool]$AutoRecoverB,
        [bool]$CanRecoverB
    )

    return @{
        SessionStatus = $SessionStatus
        AStatus = $AStatus
        BStatus = $BStatus
        AutoRecoverB = [bool]$AutoRecoverB
        CanRecoverB = [bool]$CanRecoverB
    }
}

function Request-FinalNoFollowupShutdown {
    param(
        $Settings,
        [AllowEmptyString()][string]$SessionStatus,
        [AllowEmptyString()][string]$AStatus,
        [AllowEmptyString()][string]$BStatus
    )

    return (Request-MonitorChainShutdown -Settings $Settings -Reason 'final-state-no-followup' -Source 'session-guard' -Detail (Get-SessionStatusTripleDetail -SessionStatus $SessionStatus -AStatus $AStatus -BStatus $BStatus))
}

function Invoke-FinalNoFollowupStopTransition {
    param(
        $Settings,
        [AllowEmptyString()][string]$SessionStatus,
        [AllowEmptyString()][string]$AStatus,
        [AllowEmptyString()][string]$BStatus,
        [bool]$AutoRecoverB,
        [bool]$CanRecoverB
    )

    Write-StoppedRecoverySessionState -EventName 'final-state-no-followup' -SessionStatus $SessionStatus -AStatus $AStatus -BStatus $BStatus -AutoRecoverB $AutoRecoverB -CanRecoverB $CanRecoverB
    return (Request-FinalNoFollowupShutdown -Settings $Settings -SessionStatus $SessionStatus -AStatus $AStatus -BStatus $BStatus)
}

function Invoke-FinalNoFollowupStopAndComplete {
    param(
        $Settings,
        [bool]$Forced,
        [bool]$SkipCompletion = $false,
        [AllowEmptyString()][string]$SessionStatus,
        [AllowEmptyString()][string]$AStatus,
        [AllowEmptyString()][string]$BStatus,
        [bool]$AutoRecoverB,
        [bool]$CanRecoverB
    )

    $nextSettings = Invoke-FinalNoFollowupStopTransition -Settings $Settings -SessionStatus $SessionStatus -AStatus $AStatus -BStatus $BStatus -AutoRecoverB $AutoRecoverB -CanRecoverB $CanRecoverB
    if (-not $SkipCompletion) {
        Write-FinalNoFollowupRecoveryCompletionLog -Forced $Forced -SessionStatus $SessionStatus -AStatus $AStatus -BStatus $BStatus -AutoRecoverB $AutoRecoverB -CanRecoverB $CanRecoverB
    }
    return $nextSettings
}

function Request-MainProcessExitNoAutofixShutdown {
    param(
        $Settings,
        [AllowEmptyString()][string]$Detail
    )

    return (Request-MonitorChainShutdown -Settings $Settings -Reason 'main-process-exit-no-autofix' -Source 'session-guard' -Detail $Detail)
}

function Reset-GuardLoopSignatures {
    param(
        [ref]$BudgetExhaustedSignature,
        [ref]$RestartApprovalWaitSignature
    )

    $BudgetExhaustedSignature.Value = ''
    $RestartApprovalWaitSignature.Value = ''
}

function Write-StartupSuppressLog {
    param(
        [AllowEmptyString()][string]$EventName,
        [AllowEmptyString()][string]$SessionStatus,
        [AllowEmptyString()][string]$AStatus,
        [AllowEmptyString()][string]$BStatus,
        [AllowEmptyString()][string]$Reason,
        [AllowEmptyString()][string]$RemainingLabel,
        [object]$RemainingValue
    )

    $remainingText = Convert-ToSingleLineText -Text ([string]$RemainingValue)
    $remainingBucket = $remainingText
    if ($RemainingLabel -eq 'remaining_min') {
        $remainingMin = 0.0
        if ([double]::TryParse([string]$RemainingValue, [ref]$remainingMin)) {
            $remainingBucket = [string]([int][Math]::Floor($remainingMin))
        }
    }
    elseif ($RemainingLabel -eq 'remaining_sec') {
        $remainingSec = 0.0
        if ([double]::TryParse([string]$RemainingValue, [ref]$remainingSec)) {
            $remainingBucket = [string]([int]([Math]::Floor($remainingSec / 10.0) * 10))
        }
    }

    $signature = ('{0}|{1}|{2}|{3}|{4}|{5}' -f $EventName, $SessionStatus, $AStatus, $BStatus, $Reason, $RemainingLabel)
    $now = Get-Date
    $emit = $false

    if ($signature -ne $script:StartupSuppressLastSignature) {
        $emit = $true
    }
    elseif ($remainingBucket -ne $script:StartupSuppressLastRemainingBucket) {
        $emit = $true
    }
    elseif ($script:StartupSuppressLastReportAt -eq [datetime]::MinValue -or (($now - $script:StartupSuppressLastReportAt).TotalSeconds -ge 30)) {
        $emit = $true
    }

    if (-not $emit) {
        $script:StartupSuppressHiddenCount = [int]$script:StartupSuppressHiddenCount + 1
        return
    }

    $suppressedCount = [int]$script:StartupSuppressHiddenCount
    $script:StartupSuppressLastSignature = $signature
    $script:StartupSuppressLastRemainingBucket = $remainingBucket
    $script:StartupSuppressLastReportAt = $now
    $script:StartupSuppressHiddenCount = 0
    Write-GuardLog ("{0} session={1} a={2} b={3} reason={4} {5}={6} suppressed_count={7}" -f $EventName, $SessionStatus, $AStatus, $BStatus, $Reason, $RemainingLabel, $RemainingValue, $suppressedCount)
}

function Write-TriggerHealthSkipLog {
    param(
        [Parameter(Mandatory = $true)][string]$Reason
    )

    $now = Get-Date
    $emit = $false

    if ($Reason -ne $script:TriggerHealthSkipLastReason) {
        $emit = $true
    }
    elseif ($script:TriggerHealthSkipLastReportAt -eq [datetime]::MinValue -or (($now - $script:TriggerHealthSkipLastReportAt).TotalSeconds -ge 60)) {
        $emit = $true
    }

    if (-not $emit) {
        $script:TriggerHealthSkipHiddenCount = [int]$script:TriggerHealthSkipHiddenCount + 1
        return
    }

    $suppressedCount = [int]$script:TriggerHealthSkipHiddenCount
    $script:TriggerHealthSkipLastReason = $Reason
    $script:TriggerHealthSkipLastReportAt = $now
    $script:TriggerHealthSkipHiddenCount = 0
    Write-GuardLog ("trigger_health_check_skipped reason={0} suppressed_count={1}" -f $Reason, $suppressedCount)
}

function Update-BudgetExhaustedSkipSignature {
    param(
        [AllowEmptyString()][string]$CurrentSignature,
        [AllowEmptyString()][string]$CandidateSignature,
        [int]$Attempts,
        [int]$MaxAttempts
    )

    if ($CandidateSignature -ne $CurrentSignature) {
        Write-BudgetExhaustedSkipLog -Attempts $Attempts -MaxAttempts $MaxAttempts
        return $CandidateSignature
    }

    return $CurrentSignature
}

function Invoke-RestartSettlePause {
    Start-Sleep -Seconds 5
}

function Invoke-BPassFailConflictReconcile {
    param(
        [System.Collections.IDictionary]$Conflict,
        [AllowEmptyString()][string]$ExistingNotes,
        [string]$StartFilePath
    )

    $conflictNote = ('guard_pass_conflict b_exit_fail artifact={0} exit_code={1} fail_category={2}' -f [string]$Conflict.artifact_path, [int]$Conflict.exit_code, [string]$Conflict.fail_category)
    $updatedNotes = Add-DelimitedNote -Existing $ExistingNotes -Append $conflictNote

    Invoke-KeyValueFileValueUpdateCore -Path $StartFilePath -Values @{
        B_FINAL_STATUS = 'FAIL'
        B_LAUNCH_PID = '0'
        SESSION_FINAL_STATUS = 'FAIL'
        SESSION_CLOSED = 'false'
        SESSION_CLOSED_AT = ''
        SESSION_CLOSED_REASON = 'b-exit-fail-conflict'
        SESSION_FINAL_NOTES = $updatedNotes
    }

    $statusRefresh = Read-SessionStatusRefresh -StartFilePath $StartFilePath

    return [pscustomobject]@{
        Settings = $statusRefresh.Settings
        StatusSnapshot = $statusRefresh.StatusSnapshot
    }
}

function Invoke-InitDeadProcessCheck {
    param(
        [System.Collections.IDictionary]$Settings,
        [AllowEmptyString()][string]$Notes,
        [string]$StartFilePath,
        [string]$SessionStatus,
        [string]$AStatus,
        [string]$BStatus,
        [bool]$AutoRecoverB,
        [int]$MainProcessExitMonitorGraceMinutes,
        [AllowEmptyString()][string]$RunDirAnchor,
        [Nullable[datetime]]$MainProcessExitGraceStartedAt = $null
    )

    $result = [pscustomobject]@{
        Settings = $Settings
        MainProcessExitGraceStartedAt = $MainProcessExitGraceStartedAt
        MainProcessExitGraceLastNoticeAt = $null
        MainProcessExitGraceShutdownDetail = ''
        MainProcessExitGraceStage = ''
        MainProcessExitNoAutoFixStopRequested = $false
    }

    if ($null -ne $MainProcessExitGraceStartedAt -or $BStatus -notin @('FAIL', 'BLOCKED') -or $SessionStatus -ne 'RUNNING') {
        return $result
    }

    $deadBLaunchPid = 0
    if ($Settings.Contains('B_LAUNCH_PID')) {
        $parsedDeadBPid = Convert-ToNullablePositiveInt -Value ([string]$Settings.B_LAUNCH_PID)
        if ($null -ne $parsedDeadBPid) {
            $deadBLaunchPid = [int]$parsedDeadBPid
        }
    }

    $deadBProcessAlive = ($deadBLaunchPid -gt 0)
    if ($deadBProcessAlive) {
        try { $null = Get-Process -Id $deadBLaunchPid -ErrorAction Stop } catch { $deadBProcessAlive = $false }
    }

    if ($deadBProcessAlive) {
        return $result
    }

    $initDeadNote = "guard_init_dead_process stage=B status={0} pid={1}" -f $BStatus, $deadBLaunchPid
    $updatedNotes = Add-DelimitedNote -Existing $Notes -Append $initDeadNote
    Invoke-KeyValueFileValueUpdateCore -Path $StartFilePath -Values @{
        B_FINAL_STATUS = 'FAIL'
        B_LAUNCH_PID = '0'
        SESSION_FINAL_NOTES = $updatedNotes
    }

    $canRecoverBAfterMissing = ($AStatus -eq 'PASS' -and $BStatus -in @('FAIL', 'BLOCKED'))
    $shutdownDetail = ("init_dead_process stage=B pid={0} session={1} a={2} b={3} run_dir={4}" -f $deadBLaunchPid, $SessionStatus, $AStatus, $BStatus, $RunDirAnchor)

    if ($MainProcessExitMonitorGraceMinutes -gt 0) {
        $result.MainProcessExitGraceStartedAt = Get-Date
        $result.MainProcessExitGraceLastNoticeAt = $null
        $result.MainProcessExitGraceShutdownDetail = $shutdownDetail
        $result.MainProcessExitGraceStage = 'B'
        $recoveryCapabilityDetail = Get-RecoveryCapabilityDetail -AutoRecoverB $AutoRecoverB -CanRecoverB $canRecoverBAfterMissing
        Write-GuardLog ("init_dead_process_grace_start stage=B grace_min={0} pid={1} session={2} a={3} b={4} {5} run_dir={6}" -f $MainProcessExitMonitorGraceMinutes, $deadBLaunchPid, $SessionStatus, $AStatus, $BStatus, $recoveryCapabilityDetail, $RunDirAnchor)
    }
    else {
        $result.Settings = Request-MonitorChainShutdown -Settings $Settings -Reason 'init-dead-process' -Source 'session-guard' -Detail $shutdownDetail
        $result.MainProcessExitNoAutoFixStopRequested = $true
    }

    return $result
}

try {
    while ($true) {
        try {
            if (-not (Test-Path -LiteralPath $script:StartFilePath)) {
                $missingStartFile = Convert-ToRepoRelativePath -Path $script:StartFilePath
                Write-StartFileMissingStopState -MissingStartFile $missingStartFile
                break
            }

            $settings, $sessionStatusRaw, $aStatusRaw, $bStatusRaw, $sessionStatus, $aStatus, $bStatus, $aLaunchPid, $bLaunchPid, $notes, $runDirAnchor = Update-StatusAndExpandTuple -StartFilePath $script:StartFilePath

            $autoRecoverB = Convert-ToBooleanSetting -Value (Get-SettingValueWithAlias -Settings $settings -PrimaryKey 'LOCAL_GUARD_AUTO_RECOVER' -FallbackKey 'LOCAL_GUARD_AUTO_RECOVER_B') -Default $true
            $scriptSelfHealEnabled = $false
            if ($settings.Contains('LOCAL_GUARD_SCRIPT_SELF_HEAL_ENABLED')) {
                $scriptSelfHealEnabled = Convert-ToBooleanSetting -Value ([string]$settings.LOCAL_GUARD_SCRIPT_SELF_HEAL_ENABLED) -Default $false
            }

            $maxRecoveryAttemptsRaw = Get-SettingValueWithAlias -Settings $settings -PrimaryKey 'LOCAL_GUARD_MAX_RECOVERY_ATTEMPTS' -FallbackKey 'LOCAL_GUARD_MAX_B_RECOVERY_ATTEMPTS'

            if (-not [string]::IsNullOrWhiteSpace($maxRecoveryAttemptsRaw)) {
                $parsedAttempts = 0
                if ([int]::TryParse($maxRecoveryAttemptsRaw, [ref]$parsedAttempts)) {
                    if ($parsedAttempts -ge 0 -and $parsedAttempts -le 10) {
                        $MaxBRecoveryAttempts = $parsedAttempts
                    }
                }
            }
            $MaxRecoveryAttempts = [int]$MaxBRecoveryAttempts

            if ($settings.Contains('LOCAL_GUARD_RECOVERY_COOLDOWN_MINUTES')) {
                $parsedCooldown = 0
                if ([int]::TryParse(([string]$settings.LOCAL_GUARD_RECOVERY_COOLDOWN_MINUTES), [ref]$parsedCooldown)) {
                    if ($parsedCooldown -ge 1 -and $parsedCooldown -le 180) {
                        $RecoveryCooldownMinutes = $parsedCooldown
                    }
                }
            }

            if ($settings.Contains('LOCAL_GUARD_POLL_SEC')) {
                $parsedPoll = 0
                if ([int]::TryParse(([string]$settings.LOCAL_GUARD_POLL_SEC), [ref]$parsedPoll)) {
                    if ($parsedPoll -ge 15 -and $parsedPoll -le 300) {
                        $PollSec = $parsedPoll
                    }
                }
            }

            if ($settings.Contains('LOCAL_GUARD_STOP_ON_BUDGET_EXHAUSTED')) {
                $StopOnBudgetExhausted = Convert-ToBooleanSetting -Value ([string]$settings.LOCAL_GUARD_STOP_ON_BUDGET_EXHAUSTED) -Default $true
            }

            $manualPauseEnabled = $true
            if ($settings.Contains('LOCAL_GUARD_WAIT_FOR_MANUAL_RESTART')) {
                $manualPauseEnabled = Convert-ToBooleanSetting -Value ([string]$settings.LOCAL_GUARD_WAIT_FOR_MANUAL_RESTART) -Default $true
            }

            $manualPauseNoticeRepeat = 2
            if ($settings.Contains('LOCAL_GUARD_MANUAL_NOTICE_REPEAT')) {
                $parsedManualNoticeRepeat = 0
                if ([int]::TryParse(([string]$settings.LOCAL_GUARD_MANUAL_NOTICE_REPEAT), [ref]$parsedManualNoticeRepeat)) {
                    if ($parsedManualNoticeRepeat -ge 1 -and $parsedManualNoticeRepeat -le 10) {
                        $manualPauseNoticeRepeat = $parsedManualNoticeRepeat
                    }
                }
            }

            $forceExitOnFinalNoFollowup = $true
            if ($settings.Contains('LOCAL_GUARD_FORCE_EXIT_ON_FINAL_NO_FOLLOWUP')) {
                $forceExitOnFinalNoFollowup = Convert-ToBooleanSetting -Value ([string]$settings.LOCAL_GUARD_FORCE_EXIT_ON_FINAL_NO_FOLLOWUP) -Default $true
            }

            $autoFixCompileEnabled = $true
            if ($settings.Contains('LOCAL_GUARD_AUTO_FIX_D_COMPILE')) {
                $autoFixCompileEnabled = Convert-ToBooleanSetting -Value ([string]$settings.LOCAL_GUARD_AUTO_FIX_D_COMPILE) -Default $true
            }

            $autoFixMaxPerDRound = 3
            if ($settings.Contains('LOCAL_GUARD_AUTO_FIX_MAX_PER_D_ROUND')) {
                $parsedAutoFixMaxPerRound = 0
                if ([int]::TryParse(([string]$settings.LOCAL_GUARD_AUTO_FIX_MAX_PER_D_ROUND), [ref]$parsedAutoFixMaxPerRound)) {
                    if ($parsedAutoFixMaxPerRound -ge 1 -and $parsedAutoFixMaxPerRound -le 8) {
                        $autoFixMaxPerDRound = $parsedAutoFixMaxPerRound
                    }
                }
            }

            $autoFixCooldownMinutes = 1
            if ($settings.Contains('LOCAL_GUARD_AUTO_FIX_COOLDOWN_MINUTES')) {
                $parsedAutoFixCooldown = 0
                if ([int]::TryParse(([string]$settings.LOCAL_GUARD_AUTO_FIX_COOLDOWN_MINUTES), [ref]$parsedAutoFixCooldown)) {
                    if ($parsedAutoFixCooldown -ge 0 -and $parsedAutoFixCooldown -le 180) {
                        $autoFixCooldownMinutes = $parsedAutoFixCooldown
                    }
                }
            }

            $restartRequiresConfirmation = $false
            if ($settings.Contains('LOCAL_GUARD_RESTART_REQUIRES_CONFIRM')) {
                $restartRequiresConfirmation = Convert-ToBooleanSetting -Value ([string]$settings.LOCAL_GUARD_RESTART_REQUIRES_CONFIRM) -Default $false
            }

            $restartApproved = (-not $restartRequiresConfirmation)
            if ($restartRequiresConfirmation -and $settings.Contains('LOCAL_GUARD_RESTART_APPROVED')) {
                $restartApproved = Convert-ToBooleanSetting -Value ([string]$settings.LOCAL_GUARD_RESTART_APPROVED) -Default $false
            }

            $suppressKnownInfraTickets = $true
            if ($settings.Contains('LOCAL_GUARD_SUPPRESS_KNOWN_INFRA_TICKETS')) {
                $suppressKnownInfraTickets = Convert-ToBooleanSetting -Value ([string]$settings.LOCAL_GUARD_SUPPRESS_KNOWN_INFRA_TICKETS) -Default $true
            }

            $exitOnKnownInfraTransient = $true
            if ($settings.Contains('LOCAL_GUARD_EXIT_ON_KNOWN_INFRA_TRANSIENT')) {
                $exitOnKnownInfraTransient = Convert-ToBooleanSetting -Value ([string]$settings.LOCAL_GUARD_EXIT_ON_KNOWN_INFRA_TRANSIENT) -Default $true
            }

            $agentQueueEnabled = $true
            if ($settings.Contains('LOCAL_GUARD_AGENT_QUEUE_ENABLED')) {
                $agentQueueEnabled = Convert-ToBooleanSetting -Value ([string]$settings.LOCAL_GUARD_AGENT_QUEUE_ENABLED) -Default $true
            }
            $agentQueuePath = Get-AgentTicketQueuePath -Settings $settings

            $statusTicketEnabled = $false
            if ($settings.Contains('LOCAL_GUARD_STATUS_TICKET_ENABLED')) {
                $statusTicketEnabled = Convert-ToBooleanSetting -Value ([string]$settings.LOCAL_GUARD_STATUS_TICKET_ENABLED) -Default $false
            }

            $statusTicketIntervalMinutes = 30
            if ($settings.Contains('LOCAL_GUARD_STATUS_TICKET_INTERVAL_MINUTES')) {
                $parsedStatusTicketInterval = 0
                if ([int]::TryParse(([string]$settings.LOCAL_GUARD_STATUS_TICKET_INTERVAL_MINUTES), [ref]$parsedStatusTicketInterval)) {
                    if ($parsedStatusTicketInterval -ge 1 -and $parsedStatusTicketInterval -le 180) {
                        $statusTicketIntervalMinutes = $parsedStatusTicketInterval
                    }
                }
            }

            $mainProcessExitMonitorGraceMinutes = 60
            if ($settings.Contains('LOCAL_GUARD_MAIN_EXIT_MONITOR_GRACE_MINUTES')) {
                $parsedMainExitGrace = 0
                if ([int]::TryParse(([string]$settings.LOCAL_GUARD_MAIN_EXIT_MONITOR_GRACE_MINUTES), [ref]$parsedMainExitGrace)) {
                    if ($parsedMainExitGrace -ge 0 -and $parsedMainExitGrace -le 120) {
                        $mainProcessExitMonitorGraceMinutes = [int]$parsedMainExitGrace
                    }
                }
            }
            if ($settings.Contains('MONITOR_CHAIN_GRACE_MINUTES')) {
                $parsedChainGrace = 0
                if ([int]::TryParse(([string]$settings.MONITOR_CHAIN_GRACE_MINUTES), [ref]$parsedChainGrace)) {
                    if ($parsedChainGrace -ge 0 -and $parsedChainGrace -le 120) {
                        $mainProcessExitMonitorGraceMinutes = [int]$parsedChainGrace
                    }
                }
            }

            $bRunningNoProcessGraceSec = [Math]::Max(([int]$PollSec * 3), 180)
            if ($settings.Contains('LOCAL_GUARD_B_RUNNING_NO_PROCESS_GRACE_SEC')) {
                $parsedGrace = 0
                if ([int]::TryParse(([string]$settings.LOCAL_GUARD_B_RUNNING_NO_PROCESS_GRACE_SEC), [ref]$parsedGrace)) {
                    if ($parsedGrace -ge 30 -and $parsedGrace -le 1800) {
                        $bRunningNoProcessGraceSec = [int]$parsedGrace
                    }
                }
            }

            $aRunningNoProcessGraceSec = $bRunningNoProcessGraceSec
            if ($settings.Contains('LOCAL_GUARD_A_RUNNING_NO_PROCESS_GRACE_SEC')) {
                $parsedAGrace = 0
                if ([int]::TryParse(([string]$settings.LOCAL_GUARD_A_RUNNING_NO_PROCESS_GRACE_SEC), [ref]$parsedAGrace)) {
                    if ($parsedAGrace -ge 30 -and $parsedAGrace -le 1800) {
                        $aRunningNoProcessGraceSec = [int]$parsedAGrace
                    }
                }
            }

            $handoverSuppressSeconds = 180
            if ($settings.Contains('LOCAL_GUARD_HANDOVER_SUPPRESS_SECONDS')) {
                $parsedHandoverSuppressSeconds = 0
                if ([int]::TryParse(([string]$settings.LOCAL_GUARD_HANDOVER_SUPPRESS_SECONDS), [ref]$parsedHandoverSuppressSeconds)) {
                    if ($parsedHandoverSuppressSeconds -ge 30 -and $parsedHandoverSuppressSeconds -le 900) {
                        $handoverSuppressSeconds = [int]$parsedHandoverSuppressSeconds
                    }
                }
            }

            if ($settings.Contains('GUARD_STARTUP_WARMUP_MINUTES')) {
                $parsedWarmup = 0
                if ([int]::TryParse(([string]$settings.GUARD_STARTUP_WARMUP_MINUTES), [ref]$parsedWarmup)) {
                    if ($parsedWarmup -ge 0 -and $parsedWarmup -le 60) {
                        $startupWarmupMin = [int]$parsedWarmup
                    }
                }
            }

            if ($settings.Contains('LOCAL_GUARD_D1_AUTO_RESTART')) {
                $d1AutoRestartEnabled = Convert-ToBooleanSetting -Value ([string]$settings.LOCAL_GUARD_D1_AUTO_RESTART) -Default $true
            }

            $d1ObserveOnlyMinutes = 30
            if ($settings.Contains('LOCAL_GUARD_D1_OBSERVE_MINUTES')) {
                $parsedD1Observe = 0
                if ([int]::TryParse(([string]$settings.LOCAL_GUARD_D1_OBSERVE_MINUTES), [ref]$parsedD1Observe)) {
                    if ($parsedD1Observe -ge 0 -and $parsedD1Observe -le 180) {
                        $d1ObserveOnlyMinutes = [int]$parsedD1Observe
                    }
                }
            }

            $d1StallFailMinutes = 20
            if ($settings.Contains('LOCAL_GUARD_D1_STALL_MINUTES')) {
                $parsedD1Stall = 0
                if ([int]::TryParse(([string]$settings.LOCAL_GUARD_D1_STALL_MINUTES), [ref]$parsedD1Stall)) {
                    if ($parsedD1Stall -ge 1 -and $parsedD1Stall -le 180) {
                        $d1StallFailMinutes = [int]$parsedD1Stall
                    }
                }
            }

            $watchReportIntervalMin = 10
            if ($settings.Contains('AI_SESSION_BLOCKING_WATCH_REPORT_INTERVAL_MIN')) {
                $parsedWatchInterval = 0
                if ([int]::TryParse(([string]$settings.AI_SESSION_BLOCKING_WATCH_REPORT_INTERVAL_MIN), [ref]$parsedWatchInterval)) {
                    if ($parsedWatchInterval -ge 1 -and $parsedWatchInterval -le 180) {
                        $watchReportIntervalMin = [int]$parsedWatchInterval
                    }
                }
            }
            $watchScopes = if ($settings.Contains('AI_SESSION_BLOCKING_WATCH_SCOPES') -and -not [string]::IsNullOrWhiteSpace([string]$settings.AI_SESSION_BLOCKING_WATCH_SCOPES)) {
                Convert-ToSingleLineText -Text ([string]$settings.AI_SESSION_BLOCKING_WATCH_SCOPES)
            }
            else {
                'artifacts;guard_log;compile-step'
            }

            $triggerRestartRequest = Get-TriggerRestartRequestFromStartFile -StartFilePath $script:StartFilePath
            if ([bool]$triggerRestartRequest.Requested) {
                $consumeSource = Convert-ToSingleLineText -Text ([string]$triggerRestartRequest.Source)
                $consumeReason = Convert-ToSingleLineText -Text ([string]$triggerRestartRequest.Reason)
                $consumeRequestedAt = Convert-ToSingleLineText -Text ([string]$triggerRestartRequest.RequestedAt)
                Write-GuardLog ("event=trigger_restart_request_consume source={0} reason={1} requested_at={2}" -f $consumeSource, $consumeReason, $consumeRequestedAt)

                $isBootstrapConsume = (
                    ([string]$consumeSource -eq 'open_unattended_ab_stage_window.ps1') -and
                    ([string]$consumeReason -like '*monitor_chain_bootstrap*')
                )

                if ($isBootstrapConsume) {
                    $consumeDetail = ('request_source={0} request_reason={1} requested_at={2} policy=bootstrap-no-force' -f $consumeSource, $consumeReason, $consumeRequestedAt)
                    $null = Write-TriggerLastActionInStartFile -StartFilePath $script:StartFilePath -Action 'bootstrap-trigger-request-cleared' -ActionBy 'guard' -Detail $consumeDetail -ClearRequest $true
                    Write-GuardLog ("event=trigger_restart_request_skip reason=bootstrap-no-force")

                    # Bootstrap request is one-shot; after clearing, run a normal health check.
                    # This preserves reuse when trigger is already alive and only starts a new one when missing.
                    Invoke-MonitorChainHealthCheck -Roles @('trigger') -RepoRoot $script:RepoRoot -StartFilePath $script:StartFilePath -LogPrefix 'GUARD-REQ' -ForceTriggerRestartOnRequest $false
                }
                else {
                    Invoke-MonitorChainHealthCheck -Roles @('trigger') -RepoRoot $script:RepoRoot -StartFilePath $script:StartFilePath -LogPrefix 'GUARD-REQ' -ForceTriggerRestartOnRequest $true
                }
            }

            if ($null -ne $mainProcessExitGraceStartedAt) {
                $mainExitGraceRecovered = (
                    ($mainProcessExitGraceStage -eq 'A' -and $aStatus -eq 'RUNNING' -and $aLaunchPid -gt 0 -and (Test-ProcessAlive -ProcessId $aLaunchPid)) -or
                    ($mainProcessExitGraceStage -eq 'B' -and $bStatus -eq 'RUNNING' -and $bLaunchPid -gt 0 -and (Test-ProcessAlive -ProcessId $bLaunchPid))
                )
                if ($mainExitGraceRecovered) {
                    $reboundPid = if ($mainProcessExitGraceStage -eq 'A') { $aLaunchPid } else { $bLaunchPid }
                    Write-GuardLog ("main_process_exit_grace_cleared stage={0} rebound_pid={1} session={2} a={3} b={4}" -f $mainProcessExitGraceStage, $reboundPid, $sessionStatus, $aStatus, $bStatus)
                    $mainProcessExitGraceStartedAt = $null
                    $mainProcessExitGraceLastNoticeAt = $null
                    $mainProcessExitGraceShutdownDetail = ''
                    $mainProcessExitGraceStage = ''
                    $graceClearedAt = Get-Date
                    Write-GuardLog ("startup_warmup window_min={0} reason=main-process-exit-grace-cleared" -f $startupWarmupMin)
                }
            }

            if ($null -ne $monitorChainGraceStartedAt) {
                $monitorChainGraceRecovered = (
                    ($monitorChainGraceShutdownStage -eq 'A' -and $aStatus -eq 'RUNNING' -and $aLaunchPid -gt 0 -and (Test-ProcessAlive -ProcessId $aLaunchPid)) -or
                    ($monitorChainGraceShutdownStage -eq 'B' -and $bStatus -eq 'RUNNING' -and $bLaunchPid -gt 0 -and (Test-ProcessAlive -ProcessId $bLaunchPid)) -or
                    ($monitorChainGraceShutdownStage -eq 'SESSION' -and (
                        ($aStatus -eq 'RUNNING' -and $aLaunchPid -gt 0 -and (Test-ProcessAlive -ProcessId $aLaunchPid)) -or
                        ($bStatus -eq 'RUNNING' -and $bLaunchPid -gt 0 -and (Test-ProcessAlive -ProcessId $bLaunchPid))
                    ))
                )
                if ($monitorChainGraceRecovered) {
                    $reboundPid = 0
                    if ($aStatus -eq 'RUNNING' -and $aLaunchPid -gt 0 -and (Test-ProcessAlive -ProcessId $aLaunchPid)) {
                        $reboundPid = $aLaunchPid
                    }
                    elseif ($bStatus -eq 'RUNNING' -and $bLaunchPid -gt 0 -and (Test-ProcessAlive -ProcessId $bLaunchPid)) {
                        $reboundPid = $bLaunchPid
                    }

                    Write-GuardLog (
                        "monitor_chain_grace_cleared stage={0} rebound_pid={1} reason={2} session={3} a={4} b={5}" -f
                        $monitorChainGraceShutdownStage,
                        $reboundPid,
                        $monitorChainGraceShutdownReason,
                        $sessionStatus,
                        $aStatus,
                        $bStatus)
                    $monitorChainGraceStartedAt = $null
                    $monitorChainGraceLastNoticeAt = $null
                    $monitorChainGraceShutdownDetail = ''
                    $monitorChainGraceShutdownStage = ''
                    $monitorChainGraceShutdownReason = ''
                    $monitorChainGraceShutdownSource = ''
                    $lastIncidentSignature = ''
                    $graceClearedAt = Get-Date
                    Write-GuardLog ("startup_warmup window_min={0} reason=monitor-chain-grace-cleared" -f $startupWarmupMin)
                }
            }

            $mainProcessExitNoAutoFixStopRequested = $false
            $monitorChainShutdownRequest = Get-MonitorChainShutdownRequest -Settings $settings
            $shutdownStale = $false
            if ([bool]$monitorChainShutdownRequest.Requested) {
                $requestedAt = [string]$monitorChainShutdownRequest.RequestedAt
                if (-not [string]::IsNullOrWhiteSpace($requestedAt)) {
                    try {
                        $shutdownAtDt = [datetime]::ParseExact($requestedAt, 'yyyy-MM-dd HH:mm:ss', $null)
                        if (((Get-Date) - $shutdownAtDt).TotalMinutes -gt 10) {
                            $shutdownStale = $true
                            Write-GuardLog ("monitor_chain_shutdown_stale request_at={0} age_min={1:N1}" -f $requestedAt, ((Get-Date) - $shutdownAtDt).TotalMinutes)
                        }
                    }
                    catch { $null = $_ }
                }
            }
            if ([bool]$monitorChainShutdownRequest.Requested -and -not $shutdownStale -and $aStatus -ne 'RUNNING' -and $bStatus -ne 'RUNNING') {
                Write-StoppedSessionState -EventName 'monitor-chain-shutdown-request' -StopReason 'monitor-chain-shutdown-request' -SessionStatus $sessionStatus -AStatus $aStatus -BStatus $bStatus
                Write-GuardLog ("complete reason=monitor_chain_shutdown_request status={0} a={1} b={2} source={3} request_reason={4} request_at={5}" -f
                    $sessionStatus,
                    $aStatus,
                    $bStatus,
                    [string]$monitorChainShutdownRequest.Source,
                    [string]$monitorChainShutdownRequest.Reason,
                    [string]$monitorChainShutdownRequest.RequestedAt)
                break
            }

            # A success snapshot capture (before B starts)
            if ($aStatus -eq 'PASS' -and [string]::IsNullOrWhiteSpace($aSuccessSnapshotDir) -and $runDirAnchor -ne 'unknown' -and -not [string]::IsNullOrWhiteSpace($runDirAnchor)) {
                $resolvedSnapshotRunDir = Resolve-RepoPathAllowMissing -Path $runDirAnchor
                if (-not [string]::IsNullOrWhiteSpace($resolvedSnapshotRunDir) -and (Test-Path -LiteralPath $resolvedSnapshotRunDir)) {
                    $snapshotResult = Save-ASuccessSnapshot -RunDir $resolvedSnapshotRunDir
                    if (-not [string]::IsNullOrWhiteSpace($snapshotResult.SnapshotDir)) {
                        $aSuccessSnapshotDir = $snapshotResult.SnapshotDir
                        $snapshotFinalRel = Convert-ToRepoRelativePath -Path (Join-Path $resolvedSnapshotRunDir 'final_status.json')
                        $snapshotSummaryRel = Convert-ToRepoRelativePath -Path (Join-Path $resolvedSnapshotRunDir 'summary.csv')
                        Invoke-KeyValueFileValueUpdateCore -Path $script:StartFilePath -Values @{
                            A_SUCCESS_SNAPSHOT_FINAL_STATUS = $snapshotFinalRel
                            A_SUCCESS_SNAPSHOT_SUMMARY = $snapshotSummaryRel
                            A_SUCCESS_SNAPSHOT_SOURCE_STATE = $snapshotResult.SourceState
                        }
                        Write-GuardLog ("a_snapshot_captured dir={0} source_state={1}" -f $aSuccessSnapshotDir, $snapshotResult.SourceState)
                    }
                }
            }

            # Auto-launch B after A PASS with snapshot captured
            if ($aStatus -eq 'PASS' -and -not [string]::IsNullOrWhiteSpace($aSuccessSnapshotDir) -and $bStatus -eq 'NOT_RUN' -and ($sessionStatus -eq 'RUNNING' -or $sessionStatus -eq 'NOT_RUN')) {
                $bLauncher = Join-Path $script:RepoRoot 'tools\test\open_unattended_ab_stage_window.ps1'
                $powershellPath = Join-Path $PSHOME 'powershell.exe'
                if (-not (Test-Path -LiteralPath $powershellPath)) { $powershellPath = 'powershell.exe' }
                Write-GuardLog ("b_auto_launch_start launcher={0}" -f (Convert-ToRepoRelativePath -Path $bLauncher))
                $bLaunchOutput = @(& $powershellPath -NoProfile -ExecutionPolicy Bypass -File $bLauncher -Stage B -StartFile $script:StartFilePath -StartMonitors 2>&1 | ForEach-Object { [string]$_ })
                $bLaunchLines = @($bLaunchOutput | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
                if ($bLaunchLines.Count -gt 0) {
                    foreach ($bLine in $bLaunchLines) { Write-GuardLog ("b_auto_launch_output {0}" -f $bLine) }
                }
                Write-GuardLog ("b_auto_launch_done")
                # Force re-read settings on next iteration
                $statusRefresh = Read-SessionStatusRefresh -StartFilePath $script:StartFilePath
                $settings = $statusRefresh.Settings
                $statusView = Get-StatusSnapshotView -StatusSnapshot $statusRefresh.StatusSnapshot
                $bStatusRaw = $statusView.BStatusRaw
                $bStatus = $statusView.BStatus
            }

            $bLaunchPidForConclusion = 0
            if ($settings.Contains('B_LAUNCH_PID')) {
                $parsedBLaunchPidForConclusion = Convert-ToNullablePositiveInt -Value ([string]$settings.B_LAUNCH_PID)
                if ($null -ne $parsedBLaunchPidForConclusion) {
                    $bLaunchPidForConclusion = [int]$parsedBLaunchPidForConclusion
                }
            }

            $bTerminalExitForConclusion = Get-BStageExitReasonEvidence -ExpectedProcessId $bLaunchPidForConclusion
            $bTerminalExitMatchedForConclusion = (
                $null -ne $bTerminalExitForConclusion -and
                [bool]$bTerminalExitForConclusion.Available -and
                [bool]$bTerminalExitForConclusion.StartFileMatch -and
                [bool]$bTerminalExitForConclusion.ProcessIdMatch -and
                ([string]$bTerminalExitForConclusion.Result -in @('pass', 'fail'))
            )

            $aPassConclusionEligible = ($sessionStatus -eq 'RUNNING' -and $aStatus -eq 'PASS' -and $bStatus -eq 'RUNNING' -and -not $bTerminalExitMatchedForConclusion)
            if ($aPassConclusionEligible) {
                $aSnapshotFinalHint = ''
                if ($settings.Contains('A_SUCCESS_SNAPSHOT_FINAL_STATUS')) {
                    $aSnapshotFinalHint = Convert-ToSingleLineText -Text ([string]$settings.A_SUCCESS_SNAPSHOT_FINAL_STATUS)
                }

                $aPassConclusionDedup = ("{0}|{1}|{2}" -f
                    $sessionStatus,
                    $aStatus,
                    $aSnapshotFinalHint)

                # B runs in a different directory from A. The handover ticket requires
                # settled A snapshot evidence, not equality with B's current run directory.
                $aSnapshotSettled = $false
                if (-not [string]::IsNullOrWhiteSpace($aSnapshotFinalHint)) {
                    $aSnapshotFinalPath = Resolve-RepoPathAllowMissing -Path $aSnapshotFinalHint
                    if (-not [string]::IsNullOrWhiteSpace($aSnapshotFinalPath) -and (Test-Path -LiteralPath $aSnapshotFinalPath)) {
                        $aSnapshotDir = Join-Path (Split-Path -Parent $aSnapshotFinalPath) 'a_success_snapshot'
                        $aSnapshotSettled = (Test-Path -LiteralPath $aSnapshotDir)
                    }
                }

                if ($aPassConclusionDedup -ne $lastAPassConclusionSignature -and $aSnapshotSettled) {
                    $aPassConclusionDetail = ("A stage PASS confirmed; B stage launch observed (b_status={0}, b_launch_pid={1}); run_dir={2}" -f $bStatus, $bLaunchPidForConclusion, $runDirAnchor)
                    if (-not [string]::IsNullOrWhiteSpace($aSnapshotFinalHint)) {
                        $aPassConclusionDetail = ("{0}; a_snapshot_final={1}" -f $aPassConclusionDetail, $aSnapshotFinalHint)
                    }

                    $aPassConclusionAction = 'Provide an explicit A PASS completion conclusion with a concise A-stage run summary (key checkpoints and final evidence), then report that B-stage has started.'
                    $aPassConclusionTicketResult = Add-AgentTicket -Enabled $agentQueueEnabled -QueuePath $agentQueuePath -EventName 'a-pass-conclusion-b-started' -Severity 'normal' -RequiresConfirmation $false -SessionStatus $sessionStatus -AStatus $aStatus -BStatus $bStatus -RunDirAnchor $runDirAnchor -IncidentDir '' -Detail $aPassConclusionDetail -DedupSuffix $aPassConclusionDedup -RecommendedAction $aPassConclusionAction -PreferredStage 'B' -MainRound '' -FailureKind 'stage-transition' -FailureCategory '' -FailureSource '' -FailureEvidence '' -SelfHealable $true -NonRecoverableEnv $false
                    if ((Get-TicketResultQueuedFlag -TicketResult $aPassConclusionTicketResult) -or (Get-TicketResultReason -TicketResult $aPassConclusionTicketResult) -in @('duplicate-signature', 'queue-disabled')) {
                        $lastAPassConclusionSignature = $aPassConclusionDedup
                    }
                }
            }

            $bPassFailConflict = Get-BPassFailConflictEvidence -Settings $settings -StartFilePath $script:StartFilePath
            if ([bool]$bPassFailConflict.conflict) {
                Write-GuardLog (
                    'status_conflict_detected reason={0} session={1} a={2} b={3} exit_result={4} exit_code={5} fail_category={6} fail_reason={7} artifact={8}' -f
                    [string]$bPassFailConflict.reason,
                    $sessionStatus,
                    $aStatus,
                    $bStatus,
                    [string]$bPassFailConflict.exit_result,
                    [int]$bPassFailConflict.exit_code,
                    [string]$bPassFailConflict.fail_category,
                    [string]$bPassFailConflict.fail_reason,
                    [string]$bPassFailConflict.artifact_path)

                try {
                    $conflictReconcileResult = Invoke-BPassFailConflictReconcile -Conflict $bPassFailConflict -ExistingNotes $notes -StartFilePath $script:StartFilePath
                    Write-GuardLog ('status_conflict_reconciled action=write_fail_status artifact={0}' -f [string]$bPassFailConflict.artifact_path)

                    $settings = $conflictReconcileResult.Settings
                    $sessionStatusRaw, $aStatusRaw, $bStatusRaw, $sessionStatus, $aStatus, $bStatus, $aLaunchPid, $bLaunchPid, $notes, $runDirAnchor = Expand-StatusRefreshTuple -StatusRefresh $conflictReconcileResult
                }
                catch {
                    Write-GuardLog ('status_conflict_reconcile_failed detail={0}' -f (Convert-ToSingleLineText -Text $_.Exception.Message))
                }
            }

            # INIT-DEAD-PROCESS-CHECK: detect when B stage already terminal (FAIL/BLOCKED)
            # but session is still RUNNING — indicates B process exited before the main
            # guard loop could detect it. Enter main-process-exit grace to allow
            # time for recovery or clean shutdown.
            $initDeadProcessCheckResult = Invoke-InitDeadProcessCheck -Settings $settings -Notes $notes -StartFilePath $script:StartFilePath -SessionStatus $sessionStatus -AStatus $aStatus -BStatus $bStatus -AutoRecoverB ([bool]$autoRecoverB) -MainProcessExitMonitorGraceMinutes $mainProcessExitMonitorGraceMinutes -RunDirAnchor $runDirAnchor -MainProcessExitGraceStartedAt $mainProcessExitGraceStartedAt
            $settings = $initDeadProcessCheckResult.Settings
            $mainProcessExitGraceStartedAt = $initDeadProcessCheckResult.MainProcessExitGraceStartedAt
            $mainProcessExitGraceLastNoticeAt = $initDeadProcessCheckResult.MainProcessExitGraceLastNoticeAt
            $mainProcessExitGraceShutdownDetail = $initDeadProcessCheckResult.MainProcessExitGraceShutdownDetail
            $mainProcessExitGraceStage = $initDeadProcessCheckResult.MainProcessExitGraceStage
            if ([bool]$initDeadProcessCheckResult.MainProcessExitNoAutoFixStopRequested) {
                $mainProcessExitNoAutoFixStopRequested = $true
            }

            $running = Test-IsAnyStageRunning -AStatus $aStatus -BStatus $bStatus

            if ($running -and $manualPauseActive) {
                Write-GuardLog ("manual_wait_resume session={0} a={1} b={2} run_dir={3}" -f $sessionStatus, $aStatus, $bStatus, $runDirAnchor)
                $manualPauseActive = $false
                $manualPauseSignature = ''
                $manualPauseNoticeCount = 0
            }

            $aProcessSnapshot = $null
            if ($aStatus -eq 'RUNNING') {
                $aProcessSnapshot = Get-AStageProcessSnapshot -ExpectedProcessId $aLaunchPid

                if ([bool]$aProcessSnapshot.AnchorUpdateRequired) {
                    $newALaunchPid = [int]$aProcessSnapshot.ResolvedProcessId
                    Invoke-KeyValueFileValueUpdateCore -Path $script:StartFilePath -Values @{
                        A_LAUNCH_PID = [string]$newALaunchPid
                    }
                    Write-GuardLog ("a_anchor_refresh old_pid={0} new_pid={1} source={2} candidate_count={3}" -f $aLaunchPid, $newALaunchPid, $aProcessSnapshot.ResolvedSource, $aProcessSnapshot.CandidateCount)
                    $aLaunchPid = $newALaunchPid
                }

                # Detect no-exit shell cases: process PID is still alive but
                # stage-exit artifact is already terminal.  This mirrors the
                # existing B-stage exit artifact check (Get-BStageExitReasonEvidence).
                if ([bool]$aProcessSnapshot.HasAliveProcess -and $aLaunchPid -gt 0) {
                    $aShellLikeExitEvidence = Get-AStageExitReasonEvidence -ExpectedProcessId $aLaunchPid
                    $aShellLikeExitMatched = (
                        $null -ne $aShellLikeExitEvidence -and
                        [bool]$aShellLikeExitEvidence.Available -and
                        ([string]$aShellLikeExitEvidence.Stage -eq 'A') -and
                        [bool]$aShellLikeExitEvidence.StartFileMatch -and
                        [bool]$aShellLikeExitEvidence.ProcessIdMatch -and
                        ([string]$aShellLikeExitEvidence.Result -in @('pass', 'fail'))
                    )

                    if ($aShellLikeExitMatched) {
                        Write-GuardLog ("a_shell_alive_after_terminal_exit expected_pid={0} artifact_pid={1} result={2} exit_code={3} category={4} artifact={5}" -f
                            $aLaunchPid,
                            [int]$aShellLikeExitEvidence.ProcessId,
                            [string]$aShellLikeExitEvidence.Result,
                            [int]$aShellLikeExitEvidence.ExitCode,
                            [string]$aShellLikeExitEvidence.FailCategory,
                            [string]$aShellLikeExitEvidence.ArtifactPath)

                        $aProcessSnapshot = [pscustomobject]@{
                            ExpectedProcessId = [int]$aProcessSnapshot.ExpectedProcessId
                            ExpectedAlive = $false
                            CandidateCount = [int]$aProcessSnapshot.CandidateCount
                            CandidateIds = @($aProcessSnapshot.CandidateIds)
                            ResolvedProcessId = [int]$aProcessSnapshot.ResolvedProcessId
                            ResolvedSource = 'terminal-exit-artifact'
                            HasAliveProcess = $false
                            AnchorUpdateRequired = $false
                        }
                    }
                }

                if ([bool]$aProcessSnapshot.HasAliveProcess) {
                    Reset-AMissingProcessTracking -RunningNoProcessSince ([ref]$aRunningNoProcessSince) -LastMissingProcessReportAt ([ref]$lastMissingAProcessReportAt)

                    # D1 round progress stall detection
                    $nowA = Get-Date
                    $d1Eligible = (Test-HasUsableRunDirAnchor -RunDirAnchor $runDirAnchor)
                    if ($d1Eligible) {
                        $d1ResolvedRunDir = Resolve-RepoPathAllowMissing -Path $runDirAnchor
                        if ([string]::IsNullOrWhiteSpace($d1ResolvedRunDir) -or -not (Test-Path -LiteralPath $d1ResolvedRunDir)) { $d1Eligible = $false }
                    }

                    if ($d1Eligible) {
                        if ($null -eq $script:D1ObserveStartedAt) {
                            $script:D1ObserveStartedAt = $nowA
                            Write-GuardLog ("d1_observe_start observe_min={0} stall_min={1} run_dir={2}" -f $d1ObserveOnlyMinutes, $d1StallFailMinutes, $runDirAnchor)
                        }

                        $d1ProgressResult = Test-D1ProgressSince -RunDirPath $d1ResolvedRunDir -PrevFileCount $d1StallPrevFileCount -PrevLatestWrite $d1StallPrevLatestWrite -PrevRowCount $d1StallPrevRowCount -SessionSettings $settings

                        if ($d1ProgressResult.FileCount -ge 0) {
                            $d1StallPrevFileCount = $d1ProgressResult.FileCount
                            $d1StallPrevLatestWrite = $d1ProgressResult.LatestWrite
                            $d1StallPrevRowCount = $d1ProgressResult.RowCount
                        }

                        $d1ObserveElapsedMinutes = ($nowA - $script:D1ObserveStartedAt).TotalMinutes
                        $d1ObserveOnlyActive = ($d1ObserveElapsedMinutes -lt $d1ObserveOnlyMinutes)

                        if ($d1ProgressResult.HasProgress) {
                            # Progress detected — reset stall timer
                            $script:d1StallSince = $null
                            $d1StallTriggeredSignature = ''
                            # Allow another D1 auto-restart if progress resumes after previous restart
                            if ($d1AutoRestartAttempted) {
                                $d1AutoRestartAttempted = $false
                                Write-GuardLog ("d1_auto_restart_reset reason=progress-detected")
                            }
                        }
                        else {
                            if ($d1ObserveOnlyActive) {
                                if ($null -eq $d1StallLastReportAt -or (($nowA - $d1StallLastReportAt).TotalMinutes -ge 10)) {
                                    Write-GuardLog ("d1_observe_no_progress elapsed_min={0:N1} observe_min={1} {2}" -f $d1ObserveElapsedMinutes, $d1ObserveOnlyMinutes, $d1ProgressResult.Detail)
                                    $d1StallLastReportAt = $nowA
                                }
                            }
                            else {

                                # No progress — track stall duration
                                if ($null -eq $script:d1StallSince) {
                                    $script:d1StallSince = $nowA
                                }

                                $d1StallMinutes = ($nowA - $script:d1StallSince).TotalMinutes
                                $d1Detail = ("stage=A stall_min={0:N1} threshold={1} {2}" -f $d1StallMinutes, $d1StallFailMinutes, $d1ProgressResult.Detail)

                            if ($d1StallMinutes -ge $d1StallFailMinutes -and $d1ProgressResult.RemoteChainCount -eq 0) {
                                $stallSig = ("{0}|{1}|{2}|{3}" -f $aStatus, $bStatus, $d1ResolvedRunDir, [math]::Floor($d1StallMinutes / 10))
                                if ($stallSig -ne $d1StallTriggeredSignature) {
                                    Write-GuardLog ("d1_stall_detected detail={0}" -f $d1Detail)

                                    try {
                                        $null = Stop-ProcessTree -RootPids @($aLaunchPid)
                                    }
                                    catch {
                                        Write-GuardLog ("d1_stall_process_tree_stop_error pid={0} detail={1}" -f $aLaunchPid, (Convert-ToSingleLineText -Text $_.Exception.Message))
                                    }

                                    $d1StoppedSnapshot = Get-StageBusinessProcessSnapshot -Stage 'A' -ExpectedProcessId $aLaunchPid
                                    if ([bool]$d1StoppedSnapshot.HasAliveProcess) {
                                        Write-GuardLog ("d1_stall_ticket_wait reason=main-process-still-running expected_pid={0} resolved_pid={1} candidates={2}" -f $aLaunchPid, [int]$d1StoppedSnapshot.ResolvedProcessId, [int]$d1StoppedSnapshot.CandidateCount)
                                        continue
                                    }

                                    Write-GuardLog ("d1_stall_process_tree_stopped pid={0}" -f $aLaunchPid)
                                    Invoke-SafeRemoteLockCleanup

                                    $stallFailNote = "guard_d1_stall_stopped_for_agent_repair file_count={0} csv_rows={1} stall_min={2:N1}" -f $d1ProgressResult.FileCount, $d1ProgressResult.RowCount, $d1StallMinutes
                                    $updatedANotes = Add-DelimitedNote -Existing $notes -Append $stallFailNote
                                    Invoke-KeyValueFileValueUpdateCore -Path $script:StartFilePath -Values @{
                                        A_FINAL_STATUS = 'FAIL'
                                        A_LAUNCH_PID = '0'
                                        A_FAIL_CATEGORY = 'd1-stall'
                                        A_FAIL_REASON = ('D1 round stall: no_progress_for_{0:N1}_min file_count={1} csv_rows={2}' -f $d1StallMinutes, $d1ProgressResult.FileCount, $d1ProgressResult.RowCount)
                                        SESSION_FINAL_STATUS = 'FAIL'
                                        SESSION_FINAL_NOTES = $updatedANotes
                                    }
                                    Write-GuardLog ("d1_stall_fail_written restart=deferred-to-agent-ticket")

                                    $d1IncidentDir = Save-IncidentPackage -Settings $settings -SessionStatus 'FAIL' -AStatus 'FAIL' -BStatus $bStatus
                                    $d1IncidentRel = Convert-ToRepoRelativePath -Path $d1IncidentDir
                                    Write-GuardLog ("d1_stall_incident evidence={0}" -f $d1IncidentRel)

                                    $d1StallDetail = ("D1 round stall detected after A main process stopped: {0}; evidence={1}" -f $d1Detail, $d1IncidentRel)
                                    $d1TicketResult = Add-AgentTicket -Enabled $agentQueueEnabled -QueuePath $agentQueuePath -EventName 'incident-captured' -Severity 'high' -RequiresConfirmation $restartRequiresConfirmation -SessionStatus 'FAIL' -AStatus 'FAIL' -BStatus $bStatus -RunDirAnchor $runDirAnchor -IncidentDir $d1IncidentDir -Detail $d1StallDetail -DedupSuffix $stallSig -RecommendedAction 'D1 round stall stopped the A main process. Diagnose and repair while all main processes remain stopped, then restart A only through the standard stage window.' -PreferredStage 'A' -MainRound 'D1' -FailureKind 'runner-fail' -FailureCategory 'd1-stall' -FailureSource 'tools/test/unattended_ab_session_guard.ps1' -FailureEvidence $d1Detail -SelfHealable $true -NonRecoverableEnv $false
                                    if ([bool]$d1TicketResult.Queued) {
                                        $d1StallTriggeredSignature = $stallSig
                                    }

                                    Reset-D1ProgressTracking -StallSince ([ref]$script:d1StallSince) -StallTriggeredSignature ([ref]$d1StallTriggeredSignature) -StallPrevFileCount ([ref]$d1StallPrevFileCount) -StallPrevLatestWrite ([ref]$d1StallPrevLatestWrite) -StallPrevRowCount ([ref]$d1StallPrevRowCount) -StallLastReportAt ([ref]$d1StallLastReportAt) -ObserveStartedAt ([ref]$script:D1ObserveStartedAt) -ResetLastReportAt $true
                                    $d1AutoRestartAttempted = $true
                                    continue
                                }

                                # Log periodic stall heartbeat (every 5 min)
                                if ($null -eq $d1StallLastReportAt -or (($nowA - $d1StallLastReportAt).TotalMinutes -ge 5)) {
                                    Write-GuardLog ("d1_stall_ongoing detail={0}" -f $d1Detail)
                                    $d1StallLastReportAt = $nowA
                                }
                            }
                            elseif (($d1StallMinutes % 10) -lt 1 -or $null -eq $d1StallLastReportAt) {
                                # Periodic no-progress log (every ~10 min)
                                Write-GuardLog ("d1_no_progress detail={0}" -f $d1Detail)
                                $d1StallLastReportAt = $nowA
                            }
                            }
                        }
                    }
                    else {
                        # Run dir unavailable — reset D1 tracking
                        Reset-D1ProgressTracking -StallSince ([ref]$script:d1StallSince) -StallTriggeredSignature ([ref]$d1StallTriggeredSignature) -StallPrevFileCount ([ref]$d1StallPrevFileCount) -StallPrevLatestWrite ([ref]$d1StallPrevLatestWrite) -StallPrevRowCount ([ref]$d1StallPrevRowCount) -StallLastReportAt ([ref]$d1StallLastReportAt) -ObserveStartedAt ([ref]$script:D1ObserveStartedAt) -ResetObserveStartedAt $true
                    }
                }
                else {
                    $nowA = Get-Date
                    if ($null -eq $aRunningNoProcessSince) {
                        $aRunningNoProcessSince = $nowA
                        $lastMissingAProcessReportAt = $nowA
                    }
                    elseif ($null -eq $lastMissingAProcessReportAt -or (($nowA - $lastMissingAProcessReportAt).TotalMinutes -ge 5)) {
                        $missingASecReport = [Math]::Max(0, [int][Math]::Round(($nowA - $aRunningNoProcessSince).TotalSeconds))
                        Write-GuardLog ("a_process_missing_wait expected_pid={0} elapsed_sec={1} grace_sec={2}" -f $aLaunchPid, $missingASecReport, $aRunningNoProcessGraceSec)
                        $lastMissingAProcessReportAt = $nowA
                    }
                    $missingASec = [Math]::Max(0, [int][Math]::Round(((Get-Date) - $aRunningNoProcessSince).TotalSeconds))
                    if ($missingASec -ge $aRunningNoProcessGraceSec) {
                        $aHandoverWindow = Get-HandoverWindowState -Settings $settings -WindowSeconds $handoverSuppressSeconds
                        if ([bool]$aHandoverWindow.Active) {
                            Write-GuardLog ("a_process_missing_suppressed_by_handover expected_pid={0} elapsed_sec={1} grace_sec={2} handover_state={3} handover_elapsed_sec={4} window_sec={5}" -f $aLaunchPid, $missingASec, $aRunningNoProcessGraceSec, [string]$aHandoverWindow.State, [int]$aHandoverWindow.ElapsedSec, [int]$aHandoverWindow.WindowSec)
                            Reset-AMissingProcessTracking -RunningNoProcessSince ([ref]$aRunningNoProcessSince) -LastMissingProcessReportAt ([ref]$lastMissingAProcessReportAt)
                            continue
                        }

                        # Check exit artifact before declaring A=FAIL.
                        # If A actually passed (exit_code=0, result=pass), write PASS instead
                        # so guard can proceed to B auto-launch.
                        $aExitEvidence = Get-AStageExitReasonEvidence -ExpectedProcessId $aLaunchPid
                        $aExitEvidenceForIncident = $aExitEvidence
                        $aActuallyPassed = (
                            $null -ne $aExitEvidence -and
                            [bool]$aExitEvidence.Available -and
                            [bool]$aExitEvidence.ProcessIdMatch -and
                            ([string]$aExitEvidence.Result -eq 'pass') -and
                            [int]$aExitEvidence.ExitCode -eq 0
                        )

                        if ($aActuallyPassed) {
                            $passNote = ("guard_detected a_process_missing expected_pid={0} elapsed_sec={1} grace_sec={2} pass_from_artifact" -f $aLaunchPid, $missingASec, $aRunningNoProcessGraceSec)
                            $newANotes = Add-DelimitedNote -Existing $notes -Append $passNote
                            Invoke-KeyValueFileValueUpdateCore -Path $script:StartFilePath -Values @{
                                A_FINAL_STATUS = 'PASS'
                                SESSION_FINAL_STATUS = 'RUNNING'
                                A_LAUNCH_PID = '0'
                                SESSION_FINAL_NOTES = $newANotes
                            }
                            Write-GuardLog ("a_process_missing_pass expected_pid={0} elapsed_sec={1} grace_sec={2} exit_code=0" -f $aLaunchPid, $missingASec, $aRunningNoProcessGraceSec)
                            # Force re-read status so next poll iteration sees A=PASS and triggers B launch
                            $statusRefresh = Read-SessionStatusRefresh -StartFilePath $script:StartFilePath
                            $settings = $statusRefresh.Settings
                            $statusView = Get-StatusSnapshotView -StatusSnapshot $statusRefresh.StatusSnapshot
                            $aStatus = $statusView.AStatus
                            $sessionStatus = $statusView.SessionStatus
                            continue
                        }

                        $sessionStatusAfterAMissing = if ($bStatus -eq 'RUNNING') { $sessionStatus } else { 'FAIL' }
                        $aFailureNote = ("guard_detected a_process_missing expected_pid={0} elapsed_sec={1} grace_sec={2}" -f $aLaunchPid, $missingASec, $aRunningNoProcessGraceSec)
                        $newANotes = Add-DelimitedNote -Existing $notes -Append $aFailureNote

                        Invoke-KeyValueFileValueUpdateCore -Path $script:StartFilePath -Values @{
                            A_FINAL_STATUS = 'FAIL'
                            SESSION_FINAL_STATUS = $sessionStatusAfterAMissing
                            A_LAUNCH_PID = '0'
                            SESSION_FINAL_NOTES = $newANotes
                        }
                        Write-GuardLog ("a_process_missing_fail expected_pid={0} elapsed_sec={1} grace_sec={2} session_status={3}" -f $aLaunchPid, $missingASec, $aRunningNoProcessGraceSec, $sessionStatusAfterAMissing)

                        $settings, $sessionStatusRaw, $aStatusRaw, $bStatusRaw, $sessionStatus, $aStatus, $bStatus, $aLaunchPid, $bLaunchPid, $notes, $runDirAnchor = Update-StatusAndExpandTuple -StartFilePath $script:StartFilePath
                        $running = Test-IsAnyStageRunning -AStatus $aStatus -BStatus $bStatus

                        # Direct grace-entry fix: when A main process is offline and there is
                        # no active follow-up stage, start main-process-exit grace immediately.
                        # This aligns A with B main-process-exit grace semantics.
                        $noActiveFollowupStage = ($bStatus -ne 'RUNNING')
                        if ($noActiveFollowupStage -and $null -eq $mainProcessExitGraceStartedAt) {
                            $aMainExitShutdownDetail = ("main_process_exit stage=A expected_pid={0} elapsed_sec={1} grace_sec={2} session={3} a={4} b={5} run_dir={6}" -f $aLaunchPid, $missingASec, $aRunningNoProcessGraceSec, $sessionStatus, $aStatus, $bStatus, $runDirAnchor)
                            if ($mainProcessExitMonitorGraceMinutes -gt 0) {
                                $mainProcessExitGraceStartedAt = Get-Date
                                $mainProcessExitGraceLastNoticeAt = $null
                                $mainProcessExitGraceShutdownDetail = $aMainExitShutdownDetail
                                $mainProcessExitGraceStage = 'A'
                                Write-GuardLog ("main_process_exit_grace_start stage=A grace_min={0} expected_pid={1} session={2} a={3} b={4} run_dir={5}" -f $mainProcessExitMonitorGraceMinutes, $aLaunchPid, $sessionStatus, $aStatus, $bStatus, $runDirAnchor)
                            }
                            else {
                                $settings = Request-MainProcessExitNoAutofixShutdown -Settings $settings -Detail $aMainExitShutdownDetail
                                $mainProcessExitNoAutoFixStopRequested = $true
                            }
                        }

                        $aMainExitDetail = Get-MainProcessExitDetailBase -Stage 'A' -ExpectedPid $aLaunchPid -ElapsedSec $missingASec -GraceSec $aRunningNoProcessGraceSec
                        $aMainExitDedupSuffix = Get-AMainProcessExitDedupSuffix -SessionStatus $sessionStatus -AStatus $aStatus -BStatus $bStatus -RunDirAnchor $runDirAnchor -ALaunchPid $aLaunchPid

                        # Skip main-process-exit-review when A's exit artifact indicates a known
                        # round failure. These will be handled by incident-captured via
                        # Get-FailureTicketMeta with proper classification.
                        $skipAMainExitReview = $false
                        if (-not $skipAMainExitReview -and $null -ne $aExitEvidence -and [bool]$aExitEvidence.Available) {
                            $aExitFailCat = [string]$aExitEvidence.FailCategory
                            if (Test-IsRoundFailureCategory -Category $aExitFailCat) { $skipAMainExitReview = $true }
                        }

                        if (Test-ShouldEmitMainExitReview -DedupSuffix $aMainExitDedupSuffix -LastSignature $lastMainProcessExitReviewSignature -SkipReview $skipAMainExitReview) {
                            $aMainExitRecommendedAction = $aMainExitReviewRecommendedAction
                            $aMainExitEvidence = Convert-ToBoundedSingleLineText -Text $aMainExitDetail -MaxChars 220
                            $aMainExitTicketResult = Add-AgentTicket -Enabled $agentQueueEnabled -QueuePath $agentQueuePath -EventName 'main-process-exit-review' -Severity 'high' -RequiresConfirmation $false -SessionStatus $sessionStatus -AStatus $aStatus -BStatus $bStatus -RunDirAnchor $runDirAnchor -IncidentDir '' -Detail $aMainExitDetail -DedupSuffix $aMainExitDedupSuffix -RecommendedAction $aMainExitRecommendedAction -PreferredStage 'A' -MainRound '' -FailureKind 'main-process-exit' -FailureCategory 'script-fault' -FailureSource 'tools/test/unattended_ab_session_guard.ps1' -FailureEvidence $aMainExitEvidence -SelfHealable $true -NonRecoverableEnv $false
                            if (Test-ShouldUpdateTicketSignature -TicketResult $aMainExitTicketResult) {
                                $lastMainProcessExitReviewSignature = $aMainExitDedupSuffix
                            }
                        }

                        $aLaunchPid = 0
                        Reset-AMissingProcessTracking -RunningNoProcessSince ([ref]$aRunningNoProcessSince) -LastMissingProcessReportAt ([ref]$lastMissingAProcessReportAt)
                    }
                }
            }
            else {
                Reset-AMissingProcessTracking -RunningNoProcessSince ([ref]$aRunningNoProcessSince) -LastMissingProcessReportAt ([ref]$lastMissingAProcessReportAt)
            }

            $bProcessSnapshot = $null
            if ($bStatus -eq 'RUNNING') {
                $bProcessSnapshot = Get-BStageProcessSnapshot -ExpectedProcessId $bLaunchPid

                # Detect no-exit shell cases: process PID is still alive but stage-exit artifact is already terminal.
                if ([bool]$bProcessSnapshot.HasAliveProcess -and $bLaunchPid -gt 0) {
                    $shellLikeExitEvidence = Get-BStageExitReasonEvidence -ExpectedProcessId $bLaunchPid
                    $shellLikeExitMatched = (
                        $null -ne $shellLikeExitEvidence -and
                        [bool]$shellLikeExitEvidence.Available -and
                        ([string]$shellLikeExitEvidence.Stage -eq 'B') -and
                        [bool]$shellLikeExitEvidence.StartFileMatch -and
                        [bool]$shellLikeExitEvidence.ProcessIdMatch -and
                        ([string]$shellLikeExitEvidence.Result -in @('pass', 'fail'))
                    )

                    if ($shellLikeExitMatched) {
                        Write-GuardLog ("b_shell_alive_after_terminal_exit expected_pid={0} artifact_pid={1} result={2} exit_code={3} category={4} artifact={5}" -f
                            $bLaunchPid,
                            [int]$shellLikeExitEvidence.ProcessId,
                            [string]$shellLikeExitEvidence.Result,
                            [int]$shellLikeExitEvidence.ExitCode,
                            [string]$shellLikeExitEvidence.FailCategory,
                            [string]$shellLikeExitEvidence.ArtifactPath)

                        # B's work is done (exit artifact is terminal). The -NoExit
                        # PowerShell window is just an empty shell — no real B process.
                        # If the exit artifact shows pass+code 0, treat as B PASS
                        # completion immediately, skipping the grace-period wait and
                        # avoiding incorrect FAIL marking.
                        $bShellPass = (
                            [string]$shellLikeExitEvidence.Result -eq 'pass' -and
                            [int]$shellLikeExitEvidence.ExitCode -eq 0
                        )
                        if ($bShellPass) {
                            Write-GuardLog ("b_shell_pass_detected expected_pid={0} a_status={1}" -f $bLaunchPid, $aStatus)
                            if ($aStatus -eq 'PASS') {
                                Invoke-KeyValueFileValueUpdateCore -Path $script:StartFilePath -Values @{
                                    SESSION_FINAL_STATUS = 'PASS'
                                    SESSION_CLOSED = 'true'
                                    SESSION_CLOSED_AT = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
                                    SESSION_CLOSED_REASON = 'b-pass-shell-exit'
                                }
                            }
                            Reset-BMissingProcessTracking -RunningNoProcessSince ([ref]$bRunningNoProcessSince) -LastMissingProcessReportAt ([ref]$lastMissingBProcessReportAt) -LastMissingExitReasonEvidence ([ref]$lastBMissingExitReasonEvidence) -LastMissingRuntimeTailEvidence ([ref]$lastBMissingRuntimeTailEvidence)
                            continue
                        }

                        $bProcessSnapshot = [pscustomobject]@{
                            ExpectedProcessId = [int]$bProcessSnapshot.ExpectedProcessId
                            ExpectedAlive = $false
                            CandidateCount = [int]$bProcessSnapshot.CandidateCount
                            CandidateIds = @($bProcessSnapshot.CandidateIds)
                            ResolvedProcessId = [int]$bProcessSnapshot.ResolvedProcessId
                            ResolvedSource = 'terminal-exit-artifact'
                            HasAliveProcess = $false
                            AnchorUpdateRequired = $false
                        }
                    }
                }

                if ([bool]$bProcessSnapshot.AnchorUpdateRequired) {
                    $newBLaunchPid = [int]$bProcessSnapshot.ResolvedProcessId
                    Invoke-KeyValueFileValueUpdateCore -Path $script:StartFilePath -Values @{
                        B_LAUNCH_PID = [string]$newBLaunchPid
                    }
                    Write-GuardLog ("b_anchor_refresh old_pid={0} new_pid={1} source={2} candidate_count={3}" -f $bLaunchPid, $newBLaunchPid, $bProcessSnapshot.ResolvedSource, $bProcessSnapshot.CandidateCount)
                    $bLaunchPid = $newBLaunchPid
                }

                if ([bool]$bProcessSnapshot.HasAliveProcess) {
                    Reset-BMissingProcessTracking -RunningNoProcessSince ([ref]$bRunningNoProcessSince) -LastMissingProcessReportAt ([ref]$lastMissingBProcessReportAt) -LastMissingExitReasonEvidence ([ref]$lastBMissingExitReasonEvidence) -LastMissingRuntimeTailEvidence ([ref]$lastBMissingRuntimeTailEvidence)
                }
                else {
                    $now = Get-Date
                    if ($null -eq $bRunningNoProcessSince) {
                        $bRunningNoProcessSince = $now
                        $lastMissingBProcessReportAt = $now
                        Write-GuardLog ("b_process_missing_start expected_pid={0} candidate_count={1} grace_sec={2}" -f $bLaunchPid, $bProcessSnapshot.CandidateCount, $bRunningNoProcessGraceSec)

                        $lastBMissingExitReasonEvidence = Get-BStageExitReasonEvidence -ExpectedProcessId $bLaunchPid
                        $reasonMatched = $false
                        if ($null -ne $lastBMissingExitReasonEvidence) {
                            $reasonMatched = (
                                [bool]$lastBMissingExitReasonEvidence.Available -and
                                ([string]$lastBMissingExitReasonEvidence.Stage -eq 'B') -and
                                [bool]$lastBMissingExitReasonEvidence.StartFileMatch -and
                                [bool]$lastBMissingExitReasonEvidence.ProcessIdMatch
                            )

                            if ($reasonMatched) {
                                Write-GuardLog ("b_process_missing_reason expected_pid={0} artifact_pid={1} result={2} exit_code={3} category={4} detail={5} artifact={6}" -f
                                    $bLaunchPid,
                                    [int]$lastBMissingExitReasonEvidence.ProcessId,
                                    [string]$lastBMissingExitReasonEvidence.Result,
                                    [int]$lastBMissingExitReasonEvidence.ExitCode,
                                    [string]$lastBMissingExitReasonEvidence.FailCategory,
                                    [string]$lastBMissingExitReasonEvidence.FailReason,
                                    [string]$lastBMissingExitReasonEvidence.ArtifactPath)
                            }
                            elseif ([bool]$lastBMissingExitReasonEvidence.Available) {
                                Write-GuardLog ("b_process_missing_reason_unmatched expected_pid={0} artifact_pid={1} stage={2} start_file_match={3} pid_match={4} artifact={5}" -f
                                    $bLaunchPid,
                                    [int]$lastBMissingExitReasonEvidence.ProcessId,
                                    [string]$lastBMissingExitReasonEvidence.Stage,
                                    [bool]$lastBMissingExitReasonEvidence.StartFileMatch,
                                    [bool]$lastBMissingExitReasonEvidence.ProcessIdMatch,
                                    [string]$lastBMissingExitReasonEvidence.ArtifactPath)
                            }
                            elseif (-not [string]::IsNullOrWhiteSpace([string]$lastBMissingExitReasonEvidence.ParseError)) {
                                Write-GuardLog ("b_process_missing_reason_parse_error expected_pid={0} artifact={1} detail={2}" -f
                                    $bLaunchPid,
                                    [string]$lastBMissingExitReasonEvidence.ArtifactPath,
                                    [string]$lastBMissingExitReasonEvidence.ParseError)
                            }
                            else {
                                Write-GuardLog ("b_process_missing_reason_unavailable expected_pid={0} artifact={1}" -f
                                    $bLaunchPid,
                                    [string]$lastBMissingExitReasonEvidence.ArtifactPath)
                            }
                        }

                        if (-not $reasonMatched) {
                            $artifactRuntimeLogPath = ''
                            if ($null -ne $lastBMissingExitReasonEvidence -and
                                    [bool]$lastBMissingExitReasonEvidence.Available -and
                                    ([string]$lastBMissingExitReasonEvidence.Stage -eq 'B') -and
                                    [bool]$lastBMissingExitReasonEvidence.StartFileMatch -and
                                    [bool]$lastBMissingExitReasonEvidence.ProcessIdMatch) {
                                $artifactRuntimeLogPath = [string]$lastBMissingExitReasonEvidence.RuntimeLogPath
                            }

                            $runtimeLogHint = Get-BRuntimeLogHint -Settings $settings -ArtifactRuntimeLogPath $artifactRuntimeLogPath
                            $lastBMissingRuntimeTailEvidence = Get-BRuntimeTailEvidence -RuntimeLogPath $runtimeLogHint -PrimaryTail 10 -ExpandedTail 30 -MaxTail 80 -MinimumUsefulLines 6
                            if ($null -ne $lastBMissingRuntimeTailEvidence -and [bool]$lastBMissingRuntimeTailEvidence.Available) {
                                $tailLines = @($lastBMissingRuntimeTailEvidence.Lines)
                                $tailPreview = Convert-ToBoundedSingleLineText -Text ($tailLines -join ' || ') -MaxChars 240
                                Write-GuardLog ("b_process_missing_tail expected_pid={0} log={1} used_tail={2} escalated={3} lines={4} detail_preview={5}" -f
                                    $bLaunchPid,
                                    [string]$lastBMissingRuntimeTailEvidence.RuntimeLogPath,
                                    [int]$lastBMissingRuntimeTailEvidence.UsedTail,
                                    [bool]$lastBMissingRuntimeTailEvidence.Escalated,
                                    $tailLines.Count,
                                    $tailPreview)

                                $tailBlockLines = New-Object 'System.Collections.Generic.List[string]'
                                [void]$tailBlockLines.Add(("expected_pid={0} log={1} used_tail={2} escalated={3} lines={4}" -f
                                        $bLaunchPid,
                                        [string]$lastBMissingRuntimeTailEvidence.RuntimeLogPath,
                                        [int]$lastBMissingRuntimeTailEvidence.UsedTail,
                                        [bool]$lastBMissingRuntimeTailEvidence.Escalated,
                                        $tailLines.Count))
                                foreach ($tailLine in $tailLines) {
                                    [void]$tailBlockLines.Add(("line={0}" -f [string]$tailLine))
                                }
                                Write-GuardPastedBlock -Tag 'b_process_missing_tail_block' -Lines @($tailBlockLines)
                            }
                            elseif ($null -ne $lastBMissingRuntimeTailEvidence -and -not [string]::IsNullOrWhiteSpace([string]$lastBMissingRuntimeTailEvidence.Error)) {
                                Write-GuardLog ("b_process_missing_tail_error expected_pid={0} log={1} detail={2}" -f
                                    $bLaunchPid,
                                    [string]$runtimeLogHint,
                                    [string]$lastBMissingRuntimeTailEvidence.Error)
                            }
                            else {
                                Write-GuardLog ("b_process_missing_tail_unavailable expected_pid={0} log={1}" -f
                                    $bLaunchPid,
                                    [string]$runtimeLogHint)
                            }
                        }
                        else {
                            $lastBMissingRuntimeTailEvidence = $null
                        }
                    }
                    elseif ($null -eq $lastMissingBProcessReportAt -or (($now - $lastMissingBProcessReportAt).TotalMinutes -ge 5)) {
                        $missingSecReport = [Math]::Max(0, [int][Math]::Round(($now - $bRunningNoProcessSince).TotalSeconds))
                        Write-GuardLog ("b_process_missing_wait expected_pid={0} elapsed_sec={1} grace_sec={2}" -f $bLaunchPid, $missingSecReport, $bRunningNoProcessGraceSec)
                        $lastMissingBProcessReportAt = $now
                    }

                    $missingSec = [Math]::Max(0, [int][Math]::Round(((Get-Date) - $bRunningNoProcessSince).TotalSeconds))
                    if ($missingSec -ge $bRunningNoProcessGraceSec) {
                        $bHandoverWindow = Get-HandoverWindowState -Settings $settings -WindowSeconds $handoverSuppressSeconds
                        if ([bool]$bHandoverWindow.Active) {
                            Write-GuardLog ("b_process_missing_suppressed_by_handover expected_pid={0} elapsed_sec={1} grace_sec={2} handover_state={3} handover_elapsed_sec={4} window_sec={5}" -f $bLaunchPid, $missingSec, $bRunningNoProcessGraceSec, [string]$bHandoverWindow.State, [int]$bHandoverWindow.ElapsedSec, [int]$bHandoverWindow.WindowSec)
                            Reset-BMissingProcessTracking -RunningNoProcessSince ([ref]$bRunningNoProcessSince) -LastMissingProcessReportAt ([ref]$lastMissingBProcessReportAt) -LastMissingExitReasonEvidence ([ref]$lastBMissingExitReasonEvidence) -LastMissingRuntimeTailEvidence ([ref]$lastBMissingRuntimeTailEvidence)
                            continue
                        }

                        $sessionStatusToWrite = if ($aStatus -eq 'RUNNING') { $sessionStatus } else { 'FAIL' }
                        $failureNote = "guard_detected b_process_missing expected_pid={0} elapsed_sec={1} grace_sec={2}" -f $bLaunchPid, $missingSec, $bRunningNoProcessGraceSec

                        $reasonMatchedForNotes = (
                            $null -ne $lastBMissingExitReasonEvidence -and
                            [bool]$lastBMissingExitReasonEvidence.Available -and
                            ([string]$lastBMissingExitReasonEvidence.Stage -eq 'B') -and
                            [bool]$lastBMissingExitReasonEvidence.StartFileMatch -and
                            [bool]$lastBMissingExitReasonEvidence.ProcessIdMatch
                        )
                        if ($reasonMatchedForNotes) {
                            $failureNote = $failureNote + (" exit_category={0} exit_code={1} exit_reason={2}" -f
                                [string]$lastBMissingExitReasonEvidence.FailCategory,
                                [int]$lastBMissingExitReasonEvidence.ExitCode,
                                [string]$lastBMissingExitReasonEvidence.FailReason)
                        }
                        elseif ($null -ne $lastBMissingRuntimeTailEvidence -and [bool]$lastBMissingRuntimeTailEvidence.Available) {
                            $tailLinesForNote = @($lastBMissingRuntimeTailEvidence.Lines)
                            $tailExcerptForNote = Convert-ToBoundedSingleLineText -Text ($tailLinesForNote -join ' || ') -MaxChars 360
                            if (-not [string]::IsNullOrWhiteSpace($tailExcerptForNote)) {
                                $failureNote = $failureNote + (" tail_log={0} tail_lines={1} tail_used={2} tail_excerpt={3}" -f
                                    [string]$lastBMissingRuntimeTailEvidence.RuntimeLogPath,
                                    $tailLinesForNote.Count,
                                    [int]$lastBMissingRuntimeTailEvidence.UsedTail,
                                    $tailExcerptForNote)
                            }
                        }

                        $newNotes = Add-DelimitedNote -Existing $notes -Append $failureNote
                        Invoke-KeyValueFileValueUpdateCore -Path $script:StartFilePath -Values @{
                            B_FINAL_STATUS = 'FAIL'
                            SESSION_FINAL_STATUS = $sessionStatusToWrite
                            B_LAUNCH_PID = '0'
                            SESSION_FINAL_NOTES = $newNotes
                        }
                        Write-GuardLog ("b_process_missing_fail expected_pid={0} elapsed_sec={1} grace_sec={2} session_status={3}" -f $bLaunchPid, $missingSec, $bRunningNoProcessGraceSec, $sessionStatusToWrite)

                        $settings, $sessionStatusRaw, $aStatusRaw, $bStatusRaw, $sessionStatus, $aStatus, $bStatus, $aLaunchPid, $bLaunchPid, $notes, $runDirAnchor = Update-StatusAndExpandTuple -StartFilePath $script:StartFilePath
                        $running = Test-IsAnyStageRunning -AStatus $aStatus -BStatus $bStatus

                        $canRecoverBAfterMissing = ($aStatus -eq 'PASS' -and $bStatus -in @('FAIL', 'BLOCKED'))
                        $mainExitEvidenceToken = ''
                        $mainExitDetail = Get-MainProcessExitDetailBase -Stage 'B' -ExpectedPid $bLaunchPid -ElapsedSec $missingSec -GraceSec $bRunningNoProcessGraceSec

                        if ($reasonMatchedForNotes) {
                            $mainExitEvidenceToken = Get-MainProcessExitEvidenceTokenFromArtifact -ExitReasonEvidence $lastBMissingExitReasonEvidence
                            $mainExitDetail = Add-MainProcessExitDetailArtifactSuffix -Detail $mainExitDetail -ExitReasonEvidence $lastBMissingExitReasonEvidence
                        }
                        elseif ($null -ne $lastBMissingRuntimeTailEvidence -and [bool]$lastBMissingRuntimeTailEvidence.Available) {
                            $tailLinesForTicket = @($lastBMissingRuntimeTailEvidence.Lines)
                            $tailExcerptForTicket = Convert-ToBoundedSingleLineText -Text ($tailLinesForTicket -join ' || ') -MaxChars 240
                            $mainExitEvidenceToken = Get-MainProcessExitEvidenceTokenFromTail -RuntimeLogPath ([string]$lastBMissingRuntimeTailEvidence.RuntimeLogPath) -TailUsed ([int]$lastBMissingRuntimeTailEvidence.UsedTail) -TailLineCount $tailLinesForTicket.Count
                            $mainExitDetail = Add-MainProcessExitDetailTailSuffix -Detail $mainExitDetail -RuntimeLogPath ([string]$lastBMissingRuntimeTailEvidence.RuntimeLogPath) -TailUsed ([int]$lastBMissingRuntimeTailEvidence.UsedTail) -TailLineCount $tailLinesForTicket.Count -TailExcerpt $tailExcerptForTicket
                        }

                        if ([string]::IsNullOrWhiteSpace($mainExitEvidenceToken)) {
                            $mainExitEvidenceToken = 'evidence-unavailable'
                        }

                        $mainExitDedupSuffix = Get-BMainProcessExitDedupSuffix -SessionStatus $sessionStatus -AStatus $aStatus -BStatus $bStatus -RunDirAnchor $runDirAnchor -BLaunchPid $bLaunchPid -AutoRecoverB ([bool]$autoRecoverB) -MainExitEvidenceToken $mainExitEvidenceToken

                        # Skip main-process-exit-review when the exit is caused by a D-round
                        # code-step failure, compile failure, or verify failure. These will be
                        # handled by the incident-captured path via Get-FailureTicketMeta with
                        # proper code-fix classification. Only emit main-process-exit-review for
                        # true script/environment crashes (guard script failure, network issue, etc.).
                        #
                        # Primary: check exit artifact fail_category for known round failure
                        # types (runner-fail = runner script detected non-zero exit, etc.).
                        # Fallback: scan D1-D4 round logs for code-step fatal errors.
                        $skipMainExitReviewForCodeFault = $false
                        $bFailurePolicyForExitReview = Get-FailureTicketPolicy -RunDirAnchor $runDirAnchor
                        if (-not [string]::IsNullOrWhiteSpace([string]$bFailurePolicyForExitReview.FailedRoundTag)) {
                            $skipMainExitReviewForCodeFault = $true
                        }
                        if (-not $skipMainExitReviewForCodeFault -and $reasonMatchedForNotes) {
                            $exitFailCategory = [string]$lastBMissingExitReasonEvidence.FailCategory
                            if (Test-IsRoundFailureCategory -Category $exitFailCategory) { $skipMainExitReviewForCodeFault = $true }
                        }
                        if (-not $skipMainExitReviewForCodeFault -and (Test-HasUsableRunDirAnchor -RunDirAnchor $runDirAnchor)) {
                            $resolvedRunDir = Resolve-RepoPathAllowMissing -Path $runDirAnchor
                            if (-not [string]::IsNullOrWhiteSpace($resolvedRunDir) -and (Test-Path -LiteralPath $resolvedRunDir)) {
                                foreach ($roundTag in @('D1', 'D2', 'D3', 'D4')) {
                                    $roundLog = Join-Path $resolvedRunDir "${roundTag}.log"
                                    if ((Test-Path -LiteralPath $roundLog)) {
                                        $hasFatal = Select-String -LiteralPath $roundLog -Pattern '\[CODE-STEP\]\s+fatal_error=' -Quiet
                                        if ($hasFatal) {
                                            $skipMainExitReviewForCodeFault = $true
                                            break
                                        }
                                    }
                                }
                            }
                        }

                        if (Test-ShouldEmitMainExitReview -DedupSuffix $mainExitDedupSuffix -LastSignature $lastMainProcessExitReviewSignature -SkipReview $skipMainExitReviewForCodeFault) {
                            $mainExitRecommendedAction = $mainExitReviewRecommendedAction
                            $mainExitFailureCategory = ''
                            $mainExitFailureEvidence = ''
                            if ($reasonMatchedForNotes) {
                                $mainExitFailureCategory = Convert-ToSingleLineText -Text ([string]$lastBMissingExitReasonEvidence.FailCategory)
                                $mainExitFailureEvidence = Convert-ToSingleLineText -Text ([string]$lastBMissingExitReasonEvidence.FailReason)
                            }
                            if ([string]::IsNullOrWhiteSpace($mainExitFailureEvidence)) {
                                $mainExitFailureEvidence = Convert-ToBoundedSingleLineText -Text $mainExitDetail -MaxChars 220
                            }

                            $mainExitPreferredStage = ''
                            if ($canRecoverBAfterMissing) {
                                $mainExitPreferredStage = 'B'
                            }
                            elseif ($aStatus -in @('RUNNING', 'FAIL', 'BLOCKED', 'NOT_RUN')) {
                                $mainExitPreferredStage = 'A'
                            }

                            $mainExitTicketResult = Add-AgentTicket -Enabled $agentQueueEnabled -QueuePath $agentQueuePath -EventName 'main-process-exit-review' -Severity 'high' -RequiresConfirmation $false -SessionStatus $sessionStatus -AStatus $aStatus -BStatus $bStatus -RunDirAnchor $runDirAnchor -IncidentDir '' -Detail $mainExitDetail -DedupSuffix $mainExitDedupSuffix -RecommendedAction $mainExitRecommendedAction -PreferredStage $mainExitPreferredStage -MainRound '' -FailureKind 'main-process-exit' -FailureCategory $mainExitFailureCategory -FailureSource 'tools/test/unattended_ab_session_guard.ps1' -FailureEvidence $mainExitFailureEvidence -SelfHealable $true -NonRecoverableEnv $false
                            if (Test-ShouldUpdateTicketSignature -TicketResult $mainExitTicketResult) {
                                $lastMainProcessExitReviewSignature = $mainExitDedupSuffix
                            }
                        }

                        if (-not ([bool]$autoRecoverB -and [bool]$canRecoverBAfterMissing)) {
                            $recoveryCapabilityDetail = Get-RecoveryCapabilityDetail -AutoRecoverB $autoRecoverB -CanRecoverB $canRecoverBAfterMissing
                            $shutdownDetail = ("main_process_exit expected_pid={0} {1} run_dir={2}" -f $bLaunchPid, $recoveryCapabilityDetail, $runDirAnchor)
                            if ($mainProcessExitMonitorGraceMinutes -gt 0) {
                                $mainProcessExitGraceStartedAt = Get-Date
                                $mainProcessExitGraceLastNoticeAt = $null
                                $mainProcessExitGraceShutdownDetail = $shutdownDetail
                                $mainProcessExitGraceStage = 'B'
                                Write-GuardLog ("main_process_exit_grace_start stage=B grace_min={0} expected_pid={1} session={2} a={3} b={4} {5} run_dir={6}" -f $mainProcessExitMonitorGraceMinutes, $bLaunchPid, $sessionStatus, $aStatus, $bStatus, $recoveryCapabilityDetail, $runDirAnchor)
                            }
                            else {
                                $settings = Request-MainProcessExitNoAutofixShutdown -Settings $settings -Detail $shutdownDetail
                                $mainProcessExitNoAutoFixStopRequested = $true
                            }
                        }

                        $bLaunchPid = 0
                        Reset-BMissingProcessTracking -RunningNoProcessSince ([ref]$bRunningNoProcessSince) -LastMissingProcessReportAt ([ref]$lastMissingBProcessReportAt) -LastMissingExitReasonEvidence ([ref]$lastBMissingExitReasonEvidence) -LastMissingRuntimeTailEvidence ([ref]$lastBMissingRuntimeTailEvidence)
                    }
                }
            }
            else {
                Reset-BMissingProcessTracking -RunningNoProcessSince ([ref]$bRunningNoProcessSince) -LastMissingProcessReportAt ([ref]$lastMissingBProcessReportAt) -LastMissingExitReasonEvidence ([ref]$lastBMissingExitReasonEvidence) -LastMissingRuntimeTailEvidence ([ref]$lastBMissingRuntimeTailEvidence)
            }

            $running = Test-IsAnyStageRunning -AStatus $aStatus -BStatus $bStatus

            $guardLoopStatus = 'idle'
            if ($manualPauseActive -and -not $running) {
                $guardLoopStatus = 'paused'
            }
            elseif ($running) {
                $guardLoopStatus = 'running'
            }

            $lastRecoveryAtText = ''
            if ($lastRecoveryAt -ne [datetime]::MinValue) {
                $lastRecoveryAtText = $lastRecoveryAt.ToString('yyyy-MM-dd HH:mm:ss')
            }

            $lastStatusTicketAtText = ''
            if ($lastStatusTicketAt -ne [datetime]::MinValue) {
                $lastStatusTicketAtText = $lastStatusTicketAt.ToString('yyyy-MM-dd HH:mm:ss')
            }

            $RecoveryAttempts = [int]$bRecoveryAttempts

            Write-GuardState -Values @{
                status = $guardLoopStatus
                session_final_status = $sessionStatus
                a_final_status = $aStatus
                b_final_status = $bStatus
                run_dir = $runDirAnchor
                a_launch_pid = [int]$aLaunchPid
                a_stage_process_alive = if ($null -ne $aProcessSnapshot) { [bool]$aProcessSnapshot.HasAliveProcess } else { $null }
                a_stage_process_candidates = if ($null -ne $aProcessSnapshot) { [int]$aProcessSnapshot.CandidateCount } else { 0 }
                a_running_no_process_grace_sec = [int]$aRunningNoProcessGraceSec
                b_launch_pid = [int]$bLaunchPid
                b_stage_process_alive = if ($null -ne $bProcessSnapshot) { [bool]$bProcessSnapshot.HasAliveProcess } else { $null }
                b_stage_process_candidates = if ($null -ne $bProcessSnapshot) { [int]$bProcessSnapshot.CandidateCount } else { 0 }
                b_running_no_process_grace_sec = [int]$bRunningNoProcessGraceSec
                poll_sec = [int]$PollSec
                max_recovery_attempts = [int]$MaxRecoveryAttempts
                max_b_recovery_attempts = [int]$MaxBRecoveryAttempts
                recovery_cooldown_minutes = [int]$RecoveryCooldownMinutes
                stop_on_budget_exhausted = [bool]$StopOnBudgetExhausted
                auto_recover = [bool]$autoRecoverB
                auto_recover_b = [bool]$autoRecoverB
                recovery_attempts = [int]$RecoveryAttempts
                recovery_last_at = $lastRecoveryAtText
                b_recovery_attempts = [int]$bRecoveryAttempts
                last_recovery_at = $lastRecoveryAtText
                manual_wait_for_restart = [bool]$manualPauseEnabled
                manual_wait_paused = [bool]$manualPauseActive
                manual_notice_repeat = [int]$manualPauseNoticeRepeat
                force_exit_on_final_no_followup = [bool]$forceExitOnFinalNoFollowup
                restart_requires_confirmation = [bool]$restartRequiresConfirmation
                restart_approved = [bool]$restartApproved
                suppress_known_infra_tickets = [bool]$suppressKnownInfraTickets
                exit_on_known_infra_transient = [bool]$exitOnKnownInfraTransient
                agent_ticket_queue_enabled = [bool]$agentQueueEnabled
                agent_ticket_queue_path = (Convert-ToRepoRelativePath -Path $agentQueuePath)
                status_ticket_enabled = [bool]$statusTicketEnabled
                status_ticket_interval_minutes = [int]$statusTicketIntervalMinutes
                last_status_ticket_at = $lastStatusTicketAtText
                last_ticket_id = [string]$script:AgentTicketLastId
                last_ticket_event = [string]$script:AgentTicketLastEvent
                auto_fix_d_compile = [bool]$autoFixCompileEnabled
                auto_fix_max_per_d_round = [int]$autoFixMaxPerDRound
                auto_fix_cooldown_minutes = [int]$autoFixCooldownMinutes
                d1_auto_restart_enabled = [bool]$d1AutoRestartEnabled
                d1_auto_restart_attempted = [bool]$d1AutoRestartAttempted
                d1_observe_only_minutes = [int]$d1ObserveOnlyMinutes
                d1_stall_fail_minutes = [int]$d1StallFailMinutes
            }

            if ($running) {
                $nowWatchHeartbeat = Get-Date
                $watchHeartbeatDue = ($null -eq $script:LastWatchHeartbeatAt -or (($nowWatchHeartbeat - $script:LastWatchHeartbeatAt).TotalMinutes -ge $watchReportIntervalMin))
                if ($watchHeartbeatDue) {
                    $currentWatchStage = if ($aStatus -eq 'RUNNING') { 'A' } elseif ($bStatus -eq 'RUNNING') { 'B' } else { 'SESSION' }
                    Write-StructuredWatchHeartbeat -RunDirAnchor $runDirAnchor -Settings $settings -StageName $currentWatchStage -IntervalMinutes $watchReportIntervalMin -Scopes $watchScopes
                    $script:LastWatchHeartbeatAt = $nowWatchHeartbeat
                }
            }

            if ($sessionStatus -eq 'PASS' -and -not $running) {
                Write-GuardLog ("complete session_status=PASS a={0} b={1}" -f $aStatus, $bStatus)
                break
            }

            if (($sessionStatus -in @('FAIL', 'BLOCKED')) -and -not $running) {
                $faultAProcessSnapshot = Get-StageBusinessProcessSnapshot -Stage 'A' -ExpectedProcessId $aLaunchPid
                $faultBProcessSnapshot = Get-StageBusinessProcessSnapshot -Stage 'B' -ExpectedProcessId $bLaunchPid
                if ([bool]$faultAProcessSnapshot.HasAliveProcess -or [bool]$faultBProcessSnapshot.HasAliveProcess) {
                    Write-GuardLog ("fault_processing_wait reason=main-process-still-running session={0} a={1} a_pid={2} b={3} b_pid={4}" -f $sessionStatus, [bool]$faultAProcessSnapshot.HasAliveProcess, [int]$faultAProcessSnapshot.ResolvedProcessId, [bool]$faultBProcessSnapshot.HasAliveProcess, [int]$faultBProcessSnapshot.ResolvedProcessId)
                    Start-Sleep -Seconds $PollSec
                    continue
                }

                Write-GuardLog ("fault_processing_ready reason=all-main-processes-stopped session={0} a={1} b={2}" -f $sessionStatus, $aStatus, $bStatus)
                # Capture initial status at guard startup for stale-FAIL suppression
                if ($script:GuardStartAt -and ([string]::IsNullOrWhiteSpace($guardStartupSessionStatus) -or $guardStartupSessionStatus -eq '')) {
                    $guardStartupSessionStatus = $sessionStatus
                    $guardStartupAStatus = $aStatus
                }
                # Suppress incident if FAIL/BLOCKED existed before guard started and guard hasn't seen a subsequent RUNNING transition
                $startupFailStaleSec = 120
                $guardStartupElapsed = ((Get-Date) - $script:GuardStartAt).TotalSeconds
                if ($guardStartupElapsed -lt $startupFailStaleSec -and $guardStartupSessionStatus -eq $sessionStatus -and $guardStartupAStatus -eq $aStatus) {
                    $staleRemainingSec = [math]::Max(0, [math]::Round($startupFailStaleSec - $guardStartupElapsed, 0))
                    Write-StartupSuppressLog -EventName 'startup_stale_fail_suppress' -SessionStatus $sessionStatus -AStatus $aStatus -BStatus $bStatus -Reason 'pre-existing-fail-at-startup' -RemainingLabel 'remaining_sec' -RemainingValue $staleRemainingSec
                    Start-Sleep -Seconds $PollSec
                    continue
                }
                $inWarmupWindow = ($null -ne $graceClearedAt -and ((Get-Date) - $graceClearedAt).TotalMinutes -lt $startupWarmupMin)
                if ($inWarmupWindow) {
                    $warmupRemainingMin = [math]::Max(0, [math]::Round($startupWarmupMin - ((Get-Date) - $graceClearedAt).TotalMinutes, 1))
                    Write-StartupSuppressLog -EventName 'startup_warmup_suppress' -SessionStatus $sessionStatus -AStatus $aStatus -BStatus $bStatus -Reason 'grace-cleared-too-recent' -RemainingLabel 'remaining_min' -RemainingValue $warmupRemainingMin
                    Start-Sleep -Seconds $PollSec
                    continue
                }
                $failureRunDirAnchor = Resolve-RunDirAnchorForFailurePolicy -Settings $settings -CurrentRunDirAnchor $runDirAnchor -AStatus $aStatus -BStatus $bStatus -ALaunchPid $aLaunchPid -BLaunchPid $bLaunchPid
                if ($failureRunDirAnchor -ne $runDirAnchor) {
                    Write-GuardLog ("failure_policy_run_dir_override old={0} new={1} source=stage-exit-artifact a_pid={2} b_pid={3}" -f $runDirAnchor, $failureRunDirAnchor, $aLaunchPid, $bLaunchPid)
                }
                $statusSignature = "{0}|{1}|{2}|{3}" -f $sessionStatus, $aStatus, $bStatus, $failureRunDirAnchor
                $failurePolicy = Get-FailureTicketPolicy -RunDirAnchor $failureRunDirAnchor
                $knownInfraTransient = Test-KnownInfraTransientFailurePolicy -FailurePolicy $failurePolicy
                $knownInfraTicketSuppressed = ([bool]$knownInfraTransient -and [bool]$suppressKnownInfraTickets)
                $incidentRecommendedAction = 'Review incident evidence, report root cause plus remediation path first, then decide restart approval or agent-driven script/code fix workflow.'
                $manualWaitRecommendedAction = 'Open takeover brief, report root cause plus remediation path, then decide script/code fix or manual resume. Fetch via poll_agent_tickets.ps1 from LOCAL_GUARD_AGENT_QUEUE_PATH; execute business_command then continue_watch_command (continue only if business empty); fix LOCAL_GUARD_POLL_* first on strict violation.'
                $failureCategory = (Convert-ToSingleLineText -Text ([string]$failurePolicy.FailureCategory)).ToLowerInvariant()
                if ([string]::IsNullOrWhiteSpace($failureCategory)) {
                    $failureCategory = 'unknown'
                }
                $failureHasScriptFault = [bool]$failurePolicy.FailureHasScriptFault
                $failureHasCodeFault = [bool]$failurePolicy.FailureHasCodeFault
                $failureTicketMeta = Get-FailureTicketMeta -FailurePolicy $failurePolicy -KnownInfraTransient ([bool]$knownInfraTransient) -AutoRecoverB ([bool]$autoRecoverB) -RestartApproved ([bool]$restartApproved) -AStatus $aStatus -BStatus $bStatus
                if ([string]$failureTicketMeta.FailureKind -eq 'task-definition-mismatch') {
                    $repairStage = ([string]$failureTicketMeta.PreferredStage).ToUpperInvariant()
                    $repairProcessId = if ($repairStage -eq 'B') { $bLaunchPid } else { $aLaunchPid }
                    $repairProcessSnapshot = if ($repairStage -eq 'B') {
                        Get-StageBusinessProcessSnapshot -Stage 'B' -ExpectedProcessId $repairProcessId
                    }
                    else {
                        Get-StageBusinessProcessSnapshot -Stage 'A' -ExpectedProcessId $repairProcessId
                    }
                    $repairProcessAlive = [bool]$repairProcessSnapshot.HasAliveProcess

                    if ($repairProcessAlive) {
                        Write-GuardLog ("task_definition_repair_wait reason=main-process-still-running stage={0} pid={1} resolved_pid={2} source={3} candidates={4} round={5}" -f $repairStage, $repairProcessId, [int]$repairProcessSnapshot.ResolvedProcessId, [string]$repairProcessSnapshot.ResolvedSource, [int]$repairProcessSnapshot.CandidateCount, [string]$failureTicketMeta.MainRound)
                        continue
                    }

                    Write-GuardLog ("task_definition_repair_ready reason=main-process-stopped stage={0} pid={1} round={2}" -f $repairStage, $repairProcessId, [string]$failureTicketMeta.MainRound)
                }
                if ([bool]$failurePolicy.IsVerifyRound) {
                    $verifyCategory = (Convert-ToSingleLineText -Text ([string]$failurePolicy.VerifyFailureCategory)).ToLowerInvariant()
                    switch ($verifyCategory) {
                        'script-fault' {
                            if ($failureHasCodeFault) {
                                $incidentRecommendedAction = ('Verify-round failure detected ({0}) category=script-fault with code-marker. Re-run route guard and inspect structured child exit_code; if child compile/validation result exists, reclassify to code-fix, otherwise keep script-diagnose/script-fix policy.' -f [string]$failurePolicy.FailedRoundTag)
                                $manualWaitRecommendedAction = ('Verify-round script fault ({0}) source={1} also has code markers. Treat wrapper stack frames as call-chain evidence only; reclassify by structured child result before any repair.' -f [string]$failurePolicy.FailedRoundTag, [string]$failurePolicy.VerifyFailureSourceLog)
                            }
                            else {
                                $incidentRecommendedAction = ('Verify-round failure detected ({0}) category=script-fault. Fix guard/trigger/dispatch scripts, then allow guarded restart under existing quota/cooldown. Do not issue code-fix instructions in V rounds.' -f [string]$failurePolicy.FailedRoundTag)
                                $manualWaitRecommendedAction = ('Verify-round script fault ({0}) source={1}. Fix scripts and resume guarded restart workflow. Fetch via poll_agent_tickets.ps1 from LOCAL_GUARD_AGENT_QUEUE_PATH; execute business_command then continue_watch_command (continue only if business empty).' -f [string]$failurePolicy.FailedRoundTag, [string]$failurePolicy.VerifyFailureSourceLog)
                            }
                        }
                        'noncode-transient' {
                            $incidentRecommendedAction = ('Verify-round failure detected ({0}) category=noncode-transient. Guard may retry restart under existing quota/cooldown rules after evidence check.' -f [string]$failurePolicy.FailedRoundTag)
                            $manualWaitRecommendedAction = ('Verify-round non-code transient ({0}) evidence={1}. Allow guarded restart retries within quota/cooldown; no code-fix instructions in V rounds.' -f [string]$failurePolicy.FailedRoundTag, [string]$failurePolicy.VerifyFailureEvidence)
                        }
                        default {
                            $incidentRecommendedAction = ('Verify-round failure detected ({0}) category=code-or-unknown. Run code-fix workflow by appending the minimal patch only after existing D4 operations, then validate D4 progressively before same-stage restart.' -f [string]$failurePolicy.FailedRoundTag)
                            $manualWaitRecommendedAction = ('Verify-round code failure ({0}). Preserve D1-D3 and existing D4 content; append the minimal repair operation at the end of D4 and pass the D4 checker before restart.' -f [string]$failurePolicy.FailedRoundTag)
                        }
                    }
                }
                elseif ([bool]$failurePolicy.IsDevRound) {
                    $devCategory = Get-NormalizedFailureCategory -Primary ([string]$failurePolicy.DevFailureCategory) -Fallback $failureCategory -Default $failureCategory
                    $restartStageHint = if ([string]::IsNullOrWhiteSpace([string]$failureTicketMeta.PreferredStage)) { 'current' } else { ([string]$failureTicketMeta.PreferredStage).ToUpperInvariant() }

                    switch ($devCategory) {
                        'script-fault' {
                            $incidentRecommendedAction = ('Dev-round failure detected ({0}) category=script-fault. Repair unattended script chain only (guard/trigger/dispatch/poll), run D-round script validation, then restart guarded {1}-stage flow under existing quota/cooldown.' -f [string]$failurePolicy.FailedRoundTag, $restartStageHint)
                            $manualWaitRecommendedAction = ('Dev-round script fault ({0}) source={1}. Keep scope in script lane only, provide root-cause evidence, and wait restart decision gates before resuming guarded flow.' -f [string]$failurePolicy.FailedRoundTag, [string]$failurePolicy.DevFailureSourceLog)
                        }
                        'noncode-transient' {
                            $incidentRecommendedAction = ('Dev-round failure detected ({0}) category=noncode-transient. Guard may restart {1}-stage under existing quota/cooldown without code-fix actions.' -f [string]$failurePolicy.FailedRoundTag, $restartStageHint)
                            $manualWaitRecommendedAction = ('Dev-round non-code transient ({0}) evidence={1}. Allow guarded restart retries within quota/cooldown.' -f [string]$failurePolicy.FailedRoundTag, [string]$failurePolicy.DevFailureEvidence)
                        }
                        default {
                            if ([string]$failureTicketMeta.FailureKind -eq 'task-definition-mismatch') {
                                $incidentRecommendedAction = ('Dev-round task-definition mismatch ({0}). Edit only allowed operations; run SyntaxOnly, the failed-op -OperationIndex check when locatable, then only the current failing round without -OperationIndex. Rerun checker as needed within this ticket; these local checks do not consume identical-fingerprint relaunch budget. Code-step uses the same checker result and writes only after the full round passes. Absorbed/idempotent rounds stay regex-patch. Restart only the same stage after this round passes.' -f [string]$failurePolicy.FailedRoundTag)
                                $manualWaitRecommendedAction = ('Dev-round task-definition mismatch ({0}). Repair within edit boundaries, pass SyntaxOnly plus target-op when locatable and the current failing-round check, then restart only the same stage. Checker reruns inside this ticket are unlimited and do not consume identical-fingerprint relaunch budget. Do not preflight later rounds.' -f [string]$failurePolicy.FailedRoundTag)
                            }
                            elseif ($failureHasCodeFault) {
                                $incidentRecommendedAction = ('Dev-round failure detected ({0}) category=code-or-unknown with code-marker. Run code-fix workflow and restart after confirmation; if the fix is a self-heal output mismatch, update the matching task-definition round under testdata (prefer D4 append for V1-V4) rather than rewriting D1-D4 validated content.' -f [string]$failurePolicy.FailedRoundTag)
                                $manualWaitRecommendedAction = ('Dev-round code fault ({0}) evidence={1}. Apply code fixes and restart guarded flow after review; if the fix is a self-heal output mismatch, update the matching task-definition round under testdata (prefer D4 append for V1-V4).' -f [string]$failurePolicy.FailedRoundTag, [string]$failurePolicy.DevFailureEvidence)
                            }
                            else {
                                $incidentRecommendedAction = ('Dev-round failure detected ({0}) category=code-or-unknown. Gather evidence and wait manual decision before restart.' -f [string]$failurePolicy.FailedRoundTag)
                                $manualWaitRecommendedAction = ('Dev-round unknown failure ({0}). Keep incident evidence and decide script/code handling manually.' -f [string]$failurePolicy.FailedRoundTag)
                            }
                        }
                    }
                }
                $eventTicketPolicySuffix = ' If eligible, run business_resume immediately. Execute every ticket step without omission, then execute atomic_closeout_command exactly once and claim closure only from its successful machine facts. After a main-process restart, complete atomic closeout within 3 minutes; this is not a monitoring window. Then wait silently for the next ticket delivered by guard/trigger/dispatch. Never run scheduled, persistent, or long-running cross-round monitoring commands.'
                $incidentRecommendedAction = Convert-ToBoundedSingleLineText -Text ($incidentRecommendedAction + $eventTicketPolicySuffix) -MaxChars 600
                $manualWaitRecommendedAction = Convert-ToBoundedSingleLineText -Text ($manualWaitRecommendedAction + $eventTicketPolicySuffix) -MaxChars 600

                $guardRestartAllowedForFailure = (
                    $failureCategory -in @('noncode-transient', 'monitor-chain', 'environment', 'infra-transient') -and
                    [string]$failureTicketMeta.FailureKind -ne 'task-definition-mismatch'
                )

                $suppressDuplicateAExitIncident = $false
                if ($aStatus -eq 'FAIL' -and $bStatus -ne 'RUNNING' -and $null -ne $aExitEvidenceForIncident) {
                    $suppressDuplicateAExitIncident = (
                        [bool]$aExitEvidenceForIncident.Available -and
                        [bool]$aExitEvidenceForIncident.StartFileMatch -and
                        [bool]$aExitEvidenceForIncident.ProcessIdMatch -and
                        [string]$aExitEvidenceForIncident.Result -eq 'fail' -and
                        [string]$aExitEvidenceForIncident.FailCategory -eq 'runtime-fail'
                    )
                }

                if ($suppressDuplicateAExitIncident) {
                    $lastIncidentSignature = $statusSignature
                    Write-GuardLog ('agent_ticket_suppressed event=incident-captured reason=a-runtime-fail-covered-by-main-process-exit-review artifact={0}' -f [string]$aExitEvidenceForIncident.ArtifactPath)
                }
                elseif ($statusSignature -ne $lastIncidentSignature) {
                    $incidentDir = Save-IncidentPackage -Settings $settings -SessionStatus $sessionStatus -AStatus $aStatus -BStatus $bStatus -RunDirAnchorOverride $failureRunDirAnchor
                    $incidentRel = Convert-ToRepoRelativePath -Path $incidentDir
                    $lastIncidentSignature = $statusSignature
                    $statusEvidenceDetail = Get-StatusEvidenceDetail -SessionStatus $sessionStatus -AStatus $aStatus -BStatus $bStatus -Evidence $incidentRel
                    Write-GuardLog ("incident {0}" -f $statusEvidenceDetail)

                    $newNotes = Add-DelimitedNote -Existing $notes -Append ("guard_incident {0}" -f $statusEvidenceDetail)
                    Invoke-KeyValueFileValueUpdateCore -Path $script:StartFilePath -Values @{
                        SESSION_FINAL_NOTES = $newNotes
                    }

                    $incidentDetail = Get-SessionEvidenceDetail -SessionStatus $sessionStatus -AStatus $aStatus -BStatus $bStatus -Evidence $incidentRel
                    if ([bool]$knownInfraTicketSuppressed) {
                        Write-GuardLog ("agent_ticket_suppressed event=incident-captured reason=known_infra_transient round={0} category={1} evidence={2} source={3}" -f
                            [string]$failurePolicy.FailedRoundTag,
                            [string]$failurePolicy.DevFailureCategory,
                            (Convert-ToBoundedSingleLineText -Text ([string]$failurePolicy.DevFailureEvidence) -MaxChars 180),
                            [string]$failurePolicy.DevFailureSourceLog)
                    }
                    else {
                        # Fallback: if failure ticket meta is unknown, try reading
                        # A_FAIL_CATEGORY / A_FAIL_REASON from start file (written
                        # by guard from exit artifact).
                        $startFileFailCategory = ''
                        $startFileFailReason = ''
                        if ($settings.Contains('A_FAIL_CATEGORY')) {
                            $startFileFailCategory = (Convert-ToSingleLineText -Text ([string]$settings.A_FAIL_CATEGORY)).ToLowerInvariant()
                        }
                        if ($settings.Contains('A_FAIL_REASON')) {
                            $startFileFailReason = (Convert-ToSingleLineText -Text ([string]$settings.A_FAIL_REASON))
                        }
                        if (-not [string]::IsNullOrWhiteSpace($startFileFailCategory) -and
                            ([string]$failureTicketMeta.FailureCategory -in @('', 'unknown'))) {
                            $failureTicketMeta.FailureCategory = $startFileFailCategory
                            $failureTicketMeta.FailureEvidence = $startFileFailReason
                            if ($startFileFailCategory -match 'task-definition') {
                                $failureTicketMeta.FailureKind = 'task-definition-mismatch'
                                $failureTicketMeta.SelfHealable = $true
                            }
                            elseif ($startFileFailCategory -match 'code-step') {
                                $failureTicketMeta.FailurePhase = 'code-step'
                                $failureTicketMeta.FailureKind = 'environment-transient'
                                $failureTicketMeta.FailureCategory = 'noncode-transient'
                                $failureTicketMeta.SelfHealable = $true
                            }
                            elseif ($startFileFailCategory -match 'runner-fail') {
                                $failureTicketMeta.FailureKind = 'main-process-exit'
                                $failureTicketMeta.SelfHealable = $true
                            }
                            elseif ($startFileFailCategory -match 'compile') {
                                $failureTicketMeta.FailureKind = 'compile-failure'
                                $failureTicketMeta.SelfHealable = $true
                            }
                        }
                        # Read compile error pattern from guard shutdown write-back
                        $startFileCompilePattern = ''
                        if ($settings.Contains('A_FAIL_COMPILE_PATTERN')) {
                            $startFileCompilePattern = (Convert-ToSingleLineText -Text ([string]$settings.A_FAIL_COMPILE_PATTERN))
                        }
                        $selfHealHint = ''
                        if (-not [string]::IsNullOrWhiteSpace($startFileCompilePattern)) {
                            $selfHealHint = "compile error pattern: $startFileCompilePattern"
                        }
                        elseif ($startFileFailCategory -match 'compile') {
                            # Fallback reminder for compile-related failures without specific pattern
                            $selfHealHint = 'forward-declaration-hint: check if static literal functions are defined after their first usage site in preclass.c'
                        }
                        $null = Add-AgentTicket -Enabled $agentQueueEnabled -QueuePath $agentQueuePath -EventName 'incident-captured' -Severity 'high' -RequiresConfirmation $restartRequiresConfirmation -SessionStatus $sessionStatus -AStatus $aStatus -BStatus $bStatus -RunDirAnchor $failureRunDirAnchor -IncidentDir $incidentDir -Detail $incidentDetail -DedupSuffix $statusSignature -RecommendedAction $incidentRecommendedAction -PreferredStage ([string]$failureTicketMeta.PreferredStage) -MainRound ([string]$failureTicketMeta.MainRound) -FailurePhase ([string]$failureTicketMeta.FailurePhase) -FailureKind ([string]$failureTicketMeta.FailureKind) -FailureCategory ([string]$failureTicketMeta.FailureCategory) -FailureSource ([string]$failureTicketMeta.FailureSource) -FailureEvidence ([string]$failureTicketMeta.FailureEvidence) -SelfHealable ([bool]$failureTicketMeta.SelfHealable) -NonRecoverableEnv ([bool]$failureTicketMeta.NonRecoverableEnv) -SelfHealHint $selfHealHint

                        # Roll failure fingerprint for anti-infinite-loop detection.
                        # Include task-definition hash and round source-output hash so
                        # materially different fixes produce different fingerprints.
                        $fpMainRound = [string]$failureTicketMeta.MainRound
                        $fpStage = [string]$failureTicketMeta.PreferredStage
                        $fpPhase = 'unknown'
                        $fpFailureKind = (Convert-ToSingleLineText -Text ([string]$failureTicketMeta.FailureKind)).ToLowerInvariant()
                        if ($fpFailureKind -eq 'task-definition-mismatch') {
                            $fpPhase = 'task-static'
                        }
                        elseif ($fpFailureKind -in @('compile-failure', 'compile-warning')) {
                            $fpPhase = 'compile'
                        }
                        elseif ($fpFailureKind -eq 'verify-failure') {
                            $fpPhase = 'verify'
                        }
                        $fpKeyPrefix = if ($fpStage -eq 'A') { 'A' } else { 'B' }
                        $fpTaskDefHash = ''
                        $fpRoundSourceHash = ''
                        $fpTaskDefRoundImprintHash = ''
                        $fpFailureOriginRound = $fpMainRound
                        $fpTaskFirstStartAt = ''

                        $fpTaskDefSettingKey = if ($fpStage -eq 'A') { 'A_TASK_DEFINITION' } else { 'B_TASK_DEFINITION' }
                        if ($settings.Contains($fpTaskDefSettingKey)) {
                            try {
                                $fpTaskDefPath = Resolve-RepoPathAllowMissing -Path ([string]$settings[$fpTaskDefSettingKey])
                                if (-not [string]::IsNullOrWhiteSpace($fpTaskDefPath) -and (Test-Path -LiteralPath $fpTaskDefPath)) {
                                    $fpTaskDefBytes = [System.IO.File]::ReadAllBytes($fpTaskDefPath)
                                    $fpTaskDefHashBytes = [System.Security.Cryptography.SHA1]::Create().ComputeHash($fpTaskDefBytes)
                                    $fpTaskDefHash = ([System.BitConverter]::ToString($fpTaskDefHashBytes)).Replace('-', '').ToLowerInvariant()

                                    if (-not [string]::IsNullOrWhiteSpace($fpMainRound)) {
                                        $fpTaskDefRawText = [System.Text.Encoding]::UTF8.GetString($fpTaskDefBytes)
                                        $fpTaskDefJson = $fpTaskDefRawText | ConvertFrom-Json -ErrorAction Stop
                                        $fpRoundOpsNode = $null
                                        if ($null -ne $fpTaskDefJson -and $null -ne $fpTaskDefJson.PSObject.Properties['rounds']) {
                                            $roundsNode = $fpTaskDefJson.rounds
                                            if ($null -ne $roundsNode -and $null -ne $roundsNode.PSObject.Properties[$fpMainRound]) {
                                                $roundNode = $roundsNode.PSObject.Properties[$fpMainRound].Value
                                                if ($null -ne $roundNode -and $null -ne $roundNode.PSObject.Properties['operations']) {
                                                    $fpRoundOpsNode = $roundNode.operations
                                                }
                                            }
                                        }

                                        if ($null -ne $fpRoundOpsNode) {
                                            $fpRoundOpsJson = ($fpRoundOpsNode | ConvertTo-Json -Depth 32 -Compress)
                                            $fpRoundOpsBytes = [System.Text.Encoding]::UTF8.GetBytes([string]$fpRoundOpsJson)
                                            $fpRoundOpsHashBytes = [System.Security.Cryptography.SHA1]::Create().ComputeHash($fpRoundOpsBytes)
                                            $fpTaskDefRoundImprintHash = ([System.BitConverter]::ToString($fpRoundOpsHashBytes)).Replace('-', '').ToLowerInvariant()
                                        }
                                    }
                                }
                            }
                            catch { $null = $_ }
                        }

                        $fpRunDir = Resolve-AnchorPath -Path ([string]$failurePolicy.RunDir)
                        if (-not [string]::IsNullOrWhiteSpace($fpRunDir) -and -not [string]::IsNullOrWhiteSpace($fpMainRound)) {
                            try {
                                $fpRoundHashPath = Join-Path $fpRunDir ("snapshots\{0}_git_diff_source_hash.txt" -f $fpMainRound)
                                if (Test-Path -LiteralPath $fpRoundHashPath) {
                                    $fpRoundSourceHash = Convert-ToSingleLineText -Text ((Get-Content -LiteralPath $fpRoundHashPath -Encoding utf8 -ErrorAction SilentlyContinue | Select-Object -First 1))
                                }
                            }
                            catch { $null = $_ }
                        }

                        if ($settings.Contains("${fpKeyPrefix}_TASK_FIRST_START_AT")) {
                            $fpTaskFirstStartAt = Convert-ToSingleLineText -Text ([string]$settings["${fpKeyPrefix}_TASK_FIRST_START_AT"])
                        }
                        if ([string]::IsNullOrWhiteSpace($fpTaskFirstStartAt) -and -not [string]::IsNullOrWhiteSpace($fpRunDir)) {
                            try {
                                $fpRunDirLeaf = [string](Split-Path -Path $fpRunDir -Leaf)
                                $fpRunDirLeaf = Convert-ToSingleLineText -Text $fpRunDirLeaf
                                if (-not [string]::IsNullOrWhiteSpace($fpRunDirLeaf)) {
                                    $fpTaskFirstStartAt = $fpRunDirLeaf
                                }
                            }
                            catch { $null = $_ }
                        }

                        if ([string]::IsNullOrWhiteSpace($fpTaskDefHash)) { $fpTaskDefHash = '-' }
                        if ([string]::IsNullOrWhiteSpace($fpRoundSourceHash)) { $fpRoundSourceHash = '-' }
                        if ([string]::IsNullOrWhiteSpace($fpTaskDefRoundImprintHash)) { $fpTaskDefRoundImprintHash = '-' }
                        if ([string]::IsNullOrWhiteSpace($fpFailureOriginRound)) { $fpFailureOriginRound = '-' }
                        if ([string]::IsNullOrWhiteSpace($fpTaskFirstStartAt)) { $fpTaskFirstStartAt = '-' }

                        $fpInput = "{0}|phase={1}|origin={2}|task_start={3}|{4}|{5}|taskdef={6}|source={7}|round_imprint={8}" -f $fpMainRound, $fpPhase, $fpFailureOriginRound, $fpTaskFirstStartAt, [string]$failureTicketMeta.FailureCategory, [string]$failureTicketMeta.FailureEvidence, $fpTaskDefHash, $fpRoundSourceHash, $fpTaskDefRoundImprintHash
                        $fpBytes = [System.Text.Encoding]::UTF8.GetBytes($fpInput)
                        $fpHash = [System.Security.Cryptography.SHA1]::Create().ComputeHash($fpBytes)
                        $fpHashed = "fp_{0}" -f ([System.BitConverter]::ToString($fpHash)).Replace('-','').ToLowerInvariant()
                        $fpPrevFp = if ($settings.Contains("${fpKeyPrefix}_FAILURE_FINGERPRINT")) { [string]$settings["${fpKeyPrefix}_FAILURE_FINGERPRINT"] } else { '' }
                        $fpPrevRound = if ($settings.Contains("${fpKeyPrefix}_FAILURE_MAIN_ROUND")) { [string]$settings["${fpKeyPrefix}_FAILURE_MAIN_ROUND"] } else { '' }
                        $fpPrevPhase = if ($settings.Contains("${fpKeyPrefix}_FAILURE_PHASE")) { [string]$settings["${fpKeyPrefix}_FAILURE_PHASE"] } else { '' }
                        $fpPrevOriginRound = if ($settings.Contains("${fpKeyPrefix}_FAILURE_ORIGIN_ROUND")) { [string]$settings["${fpKeyPrefix}_FAILURE_ORIGIN_ROUND"] } else { '' }
                        $fpPrevTaskStartAt = if ($settings.Contains("${fpKeyPrefix}_FAILURE_TASK_START_AT")) { [string]$settings["${fpKeyPrefix}_FAILURE_TASK_START_AT"] } else { '' }
                        $fpPrevTaskDefHash = if ($settings.Contains("${fpKeyPrefix}_FAILURE_TASKDEF_HASH")) { [string]$settings["${fpKeyPrefix}_FAILURE_TASKDEF_HASH"] } else { '' }
                        $fpPrevSourceHash = if ($settings.Contains("${fpKeyPrefix}_FAILURE_SOURCE_HASH")) { [string]$settings["${fpKeyPrefix}_FAILURE_SOURCE_HASH"] } else { '' }
                        $fpPrevRoundImprintHash = if ($settings.Contains("${fpKeyPrefix}_FAILURE_TASKDEF_ROUND_IMPRINT_HASH")) { [string]$settings["${fpKeyPrefix}_FAILURE_TASKDEF_ROUND_IMPRINT_HASH"] } else { '' }
                        Invoke-KeyValueFileValueUpdateCore -Path $script:StartFilePath -Values @{
                            "${fpKeyPrefix}_PREVIOUS_FAILURE_FINGERPRINT" = $fpPrevFp
                            "${fpKeyPrefix}_PREVIOUS_FAILURE_MAIN_ROUND" = $fpPrevRound
                            "${fpKeyPrefix}_PREVIOUS_FAILURE_PHASE" = $fpPrevPhase
                            "${fpKeyPrefix}_PREVIOUS_FAILURE_ORIGIN_ROUND" = $fpPrevOriginRound
                            "${fpKeyPrefix}_PREVIOUS_FAILURE_TASK_START_AT" = $fpPrevTaskStartAt
                            "${fpKeyPrefix}_PREVIOUS_FAILURE_TASKDEF_HASH" = $fpPrevTaskDefHash
                            "${fpKeyPrefix}_PREVIOUS_FAILURE_SOURCE_HASH" = $fpPrevSourceHash
                            "${fpKeyPrefix}_PREVIOUS_FAILURE_TASKDEF_ROUND_IMPRINT_HASH" = $fpPrevRoundImprintHash
                            "${fpKeyPrefix}_FAILURE_FINGERPRINT" = $fpHashed
                            "${fpKeyPrefix}_FAILURE_MAIN_ROUND" = $fpMainRound
                            "${fpKeyPrefix}_FAILURE_PHASE" = $fpPhase
                            "${fpKeyPrefix}_FAILURE_ORIGIN_ROUND" = $fpFailureOriginRound
                            "${fpKeyPrefix}_FAILURE_TASK_START_AT" = $fpTaskFirstStartAt
                            "${fpKeyPrefix}_TASK_FIRST_START_AT" = $fpTaskFirstStartAt
                            "${fpKeyPrefix}_FAILURE_TASKDEF_HASH" = $fpTaskDefHash
                            "${fpKeyPrefix}_FAILURE_SOURCE_HASH" = $fpRoundSourceHash
                            "${fpKeyPrefix}_FAILURE_TASKDEF_ROUND_IMPRINT_HASH" = $fpTaskDefRoundImprintHash
                        }
                        Write-GuardLog ("failure_fingerprint_rolled stage={0} round={1} phase={2} origin_round={3} task_start_at={4} taskdef_hash={5} source_hash={6} round_imprint_hash={7}" -f $fpStage, $fpMainRound, $fpPhase, $fpFailureOriginRound, $fpTaskFirstStartAt, $fpTaskDefHash, $fpRoundSourceHash, $fpTaskDefRoundImprintHash)
                    }
                }

                $monitorChainGraceStopRequested = $false
                if ($null -ne $monitorChainGraceStartedAt) {
                    # Check if the main process has been revived during grace period
                    # (e.g. by AI processing incident ticket and restarting A stage).
                    # If revived, cancel grace and resume normal monitoring.
                    # Re-read start file for fresh status (session may have been re-launched).
                    $freshSettings = Read-KeyValueFileWithRetry -Path $startFilePath
                    $freshAStatus = if ($freshSettings.Contains('A_FINAL_STATUS')) { [string]$freshSettings.A_FINAL_STATUS } else { '' }
                    $freshALaunchPid = if ($freshSettings.Contains('A_LAUNCH_PID')) { [int]$freshSettings.A_LAUNCH_PID } else { 0 }
                    $freshBStatus = if ($freshSettings.Contains('B_FINAL_STATUS')) { [string]$freshSettings.B_FINAL_STATUS } else { '' }
                    $freshBLaunchPid = if ($freshSettings.Contains('B_LAUNCH_PID')) { [int]$freshSettings.B_LAUNCH_PID } else { 0 }
                    $freshAAlive = ($freshAStatus -eq 'RUNNING' -and $freshALaunchPid -gt 0 -and (Test-ProcessAlive -ProcessId $freshALaunchPid))
                    $freshBAlive = ($freshBStatus -eq 'RUNNING' -and $freshBLaunchPid -gt 0 -and (Test-ProcessAlive -ProcessId $freshBLaunchPid))
                    if ($freshAAlive -or $freshBAlive) {
                        $revivedStage = if ($freshAAlive) { 'A' } else { 'B' }
                        $revivedPid = if ($freshAAlive) { $freshALaunchPid } else { $freshBLaunchPid }
                        $monitorChainGraceStartedAt = $null
                        Write-GuardLog ("monitor_chain_grace_cancelled stage={0} reason=session-revived pid={1}" -f $revivedStage, $revivedPid)
                        Start-Sleep -Seconds $PollSec
                        continue
                    }

                    $graceElapsedMinutes = ((Get-Date) - $monitorChainGraceStartedAt).TotalMinutes
                    if ($graceElapsedMinutes -ge $mainProcessExitMonitorGraceMinutes) {
                        $shutdownDetail = $monitorChainGraceShutdownDetail
                        if ([string]::IsNullOrWhiteSpace($shutdownDetail)) {
                            $shutdownDetail = ("monitor_chain_grace_expired stage={0} status={1} a={2} b={3} run_dir={4}" -f $monitorChainGraceShutdownStage, $sessionStatus, $aStatus, $bStatus, $runDirAnchor)
                        }
                        $settings = Request-MonitorChainShutdown -Settings $settings -Reason $monitorChainGraceShutdownReason -Source $monitorChainGraceShutdownSource -Detail $shutdownDetail
                        $monitorChainGraceStopRequested = $true
                    }
                    else {
                        $remainingGraceMinutes = [Math]::Max(0.0, ($mainProcessExitMonitorGraceMinutes - $graceElapsedMinutes))
                        if ($null -eq $monitorChainGraceLastNoticeAt -or (((Get-Date) - $monitorChainGraceLastNoticeAt).TotalMinutes -ge 5)) {
                            Write-MonitorChainGraceWaitLog -Stage $monitorChainGraceShutdownStage -ElapsedMinutes $graceElapsedMinutes -RemainingMinutes $remainingGraceMinutes -SessionStatus $sessionStatus -AStatus $aStatus -BStatus $bStatus -Reason $monitorChainGraceShutdownReason
                            $monitorChainGraceLastNoticeAt = Get-Date
                        }
                        Write-WaitingMonitorChainGraceState -SessionStatus $sessionStatus -AStatus $aStatus -BStatus $bStatus -GraceStage $monitorChainGraceShutdownStage -RemainingGraceMinutes $remainingGraceMinutes -GraceReason $monitorChainGraceShutdownReason
                        Start-Sleep -Seconds $PollSec
                        continue
                    }
                }

                if ($monitorChainGraceStopRequested) {
                    Write-StoppedSessionState -EventName 'monitor-chain-grace-stop' -StopReason ([string]$monitorChainGraceShutdownReason) -SessionStatus $sessionStatus -AStatus $aStatus -BStatus $bStatus
                    Write-GuardLog (
                        "complete reason=monitor_chain_grace_stop shutdown_reason={0} status={1} a={2} b={3}" -f
                        [string]$monitorChainGraceShutdownReason,
                        $sessionStatus,
                        $aStatus,
                        $bStatus)
                    break
                }

                if ([bool]$knownInfraTransient -and [bool]$exitOnKnownInfraTransient) {
                    if ($mainProcessExitMonitorGraceMinutes -gt 0) {
                        if ($null -eq $monitorChainGraceStartedAt) {
                            $monitorChainGraceStartedAt = Get-Date
                            $monitorChainGraceLastNoticeAt = $null
                            $monitorChainGraceShutdownDetail = [string]$failurePolicy.FailedRoundTag
                            $monitorChainGraceShutdownStage = 'SESSION'
                            $monitorChainGraceShutdownReason = 'known-infra-transient-stop'
                            $monitorChainGraceShutdownSource = 'session-guard'
                            Write-MonitorChainGraceStartLog -Stage $monitorChainGraceShutdownStage -GraceMinutes $mainProcessExitMonitorGraceMinutes -Reason $monitorChainGraceShutdownReason -SessionStatus $sessionStatus -AStatus $aStatus -BStatus $bStatus -RunDirAnchor $runDirAnchor
                        }
                        Start-Sleep -Seconds $PollSec
                        continue
                    }

                    $settings = Request-MonitorChainShutdown -Settings $settings -Reason 'known-infra-transient-stop' -Source 'session-guard' -Detail ([string]$failurePolicy.FailedRoundTag)
                    $infraCategory = Get-NormalizedFailureCategory -Primary ([string]$failurePolicy.DevFailureCategory) -Fallback ([string]$failurePolicy.FailureCategory)
                    $infraEvidence = Convert-ToBoundedSingleLineText -Text ([string]$failurePolicy.DevFailureEvidence) -MaxChars 220
                    if ([string]::IsNullOrWhiteSpace($infraEvidence)) {
                        $infraEvidence = Convert-ToBoundedSingleLineText -Text ([string]$failurePolicy.FailureEvidence) -MaxChars 220
                    }
                    $infraSource = Convert-ToSingleLineText -Text ([string]$failurePolicy.DevFailureSourceLog)
                    if ([string]::IsNullOrWhiteSpace($infraSource)) {
                        $infraSource = Convert-ToSingleLineText -Text ([string]$failurePolicy.FailureSourceLog)
                    }

                    Write-StoppedSessionState -EventName 'known-infra-transient-stop' -StopReason 'known-infra-transient-stop' -SessionStatus $sessionStatus -AStatus $aStatus -BStatus $bStatus -ExtraValues @{
                        failed_round = [string]$failurePolicy.FailedRoundTag
                        failure_category = $infraCategory
                        failure_evidence = $infraEvidence
                        failure_source = $infraSource
                    }
                    Write-GuardLog ("complete reason=known_infra_transient_stop round={0} category={1} evidence={2} source={3} suppress_tickets={4}" -f
                        [string]$failurePolicy.FailedRoundTag,
                        $infraCategory,
                        $infraEvidence,
                        $infraSource,
                        [bool]$knownInfraTicketSuppressed)
                    break
                }

                $canRecoverB = ($aStatus -eq 'PASS' -and $bStatus -in @('FAIL', 'BLOCKED'))

                $autoFixResult = [pscustomobject]@{
                    Attempted = $false
                    Restarted = $false
                    Reason = 'not-run'
                    RoundTag = ''
                    Attempt = 0
                    Detail = ''
                    TaskDefinitionPath = ''
                    StrictLogPath = ''
                }

                $verifyRecoveryResult = [pscustomobject]@{
                    Attempted = $false
                    Restarted = $false
                    Reason = 'not-run'
                    RoundTag = [string]$failurePolicy.FailedRoundTag
                    Attempt = 0
                    Detail = ''
                    Category = [string]$failurePolicy.VerifyFailureCategory
                    Evidence = [string]$failurePolicy.VerifyFailureEvidence
                    SourceLog = [string]$failurePolicy.VerifyFailureSourceLog
                }

                $devTransientRecoveryResult = [pscustomobject]@{
                    Attempted = $false
                    Restarted = $false
                    Reason = 'not-run'
                    RoundTag = [string]$failurePolicy.FailedRoundTag
                    Attempt = 0
                    Detail = ''
                    Category = [string]$failurePolicy.DevFailureCategory
                    Evidence = [string]$failurePolicy.DevFailureEvidence
                    SourceLog = [string]$failurePolicy.DevFailureSourceLog
                }
                $skipAutoFixForDevTransient = $false

                if ($aStatus -eq 'FAIL' -and [bool]$failurePolicy.IsVerifyRound) {
                    $verifyRecoveryStage = Resolve-RecoveryStageByStatus -AStatus $aStatus -BStatus $bStatus
                    $verifyStagePolicy = Get-StagePolicy -Stage $verifyRecoveryStage
                    $verifyRecoveryResult = Invoke-StageVerifyRoundRecovery -Stage $verifyRecoveryStage -FailurePolicy $failurePolicy -RestartAllowed $restartApproved -MaxAttemptsPerRound $MaxBRecoveryAttempts -CooldownMinutes $RecoveryCooldownMinutes
                    $verifyRecoveryLogFields = Get-RecoveryResultLogCompactFields -Detail ([string]$verifyRecoveryResult.Detail) -Evidence ([string]$verifyRecoveryResult.Evidence)
                    Write-GuardLog ("verify_recovery_result round={0} category={1} attempted={2} restarted={3} reason={4} detail={5} evidence={6} source={7}" -f
                        [string]$verifyRecoveryResult.RoundTag,
                        [string]$verifyRecoveryResult.Category,
                        [bool]$verifyRecoveryResult.Attempted,
                        [bool]$verifyRecoveryResult.Restarted,
                        [string]$verifyRecoveryResult.Reason,
                        [string]$verifyRecoveryLogFields.DetailCompact,
                        [string]$verifyRecoveryLogFields.EvidenceCompact,
                        [string]$verifyRecoveryResult.SourceLog)

                    if ([bool]$verifyRecoveryResult.Attempted -and ([string]$verifyRecoveryResult.Reason -eq 'restart-await-confirmation')) {
                        $verifyWaitTicketContext = Get-RestartAwaitConfirmationTicketContext -RoundTag ([string]$verifyRecoveryResult.RoundTag) -Category ([string]$verifyRecoveryResult.Category) -Attempt ([int]$verifyRecoveryResult.Attempt) -MaxAttempts ([int]$MaxBRecoveryAttempts) -Reason ([string]$verifyRecoveryResult.Reason) -Detail ([string]$verifyRecoveryResult.Detail) -RunDirAnchor $runDirAnchor
                        $null = Add-RestartAwaitConfirmationTicket -Enabled $agentQueueEnabled -QueuePath $agentQueuePath -EventName 'verify-restart-await-confirmation' -SessionStatus $sessionStatus -AStatus $aStatus -BStatus $bStatus -RunDirAnchor $runDirAnchor -TicketContext $verifyWaitTicketContext -RecommendedAction 'Set LOCAL_GUARD_RESTART_APPROVED=true after evidence review to allow guarded verify restart.' -MainRound ([string]$failureTicketMeta.MainRound) -FailureKind 'verify-failure' -FailureCategory ([string]$verifyRecoveryResult.Category) -FailureSource ([string]$verifyRecoveryResult.SourceLog) -FailureEvidence ([string]$verifyRecoveryResult.Evidence) -NonRecoverableEnv ([bool]$failureTicketMeta.NonRecoverableEnv)
                    }

                    if ([bool]$verifyRecoveryResult.Restarted) {
                        Reset-RestartRecoveryMonitorState -ManualPauseActive ([ref]$manualPauseActive) -ManualPauseSignature ([ref]$manualPauseSignature) -ManualPauseNoticeCount ([ref]$manualPauseNoticeCount) -LastIncidentSignature ([ref]$lastIncidentSignature) -LastBudgetExhaustedSignature ([ref]$lastBudgetExhaustedSignature)

                        $verifyRestartEventName = [string]$verifyStagePolicy.VerifyRestartEventName
                        Write-RestartRunningState -EventName $verifyRestartEventName -ExtraValues @{
                            verify_restart_stage = [string]$verifyRecoveryStage
                            verify_restart_round = [string]$verifyRecoveryResult.RoundTag
                            verify_restart_category = [string]$verifyRecoveryResult.Category
                            verify_restart_attempt = [int]$verifyRecoveryResult.Attempt
                        }
                        Invoke-RestartSettlePause
                        continue
                    }

                    if ([string]$verifyRecoveryResult.Reason -eq 'code-or-unknown') {
                        Write-StoppedSessionState -EventName 'verify-code-wait-manual' -StopReason 'verify-code-wait-manual' -SessionStatus $sessionStatus -AStatus $aStatus -BStatus $bStatus
                        Write-GuardLog ("complete reason=verify_code_or_unknown_wait_manual round={0} category={1}" -f [string]$verifyRecoveryResult.RoundTag, [string]$verifyRecoveryResult.Category)
                        break
                    }
                }

                if ($aStatus -eq 'FAIL' -and [bool]$failurePolicy.IsDevRound) {
                    $devCategory = Get-NormalizedFailureCategory -Primary ([string]$failurePolicy.DevFailureCategory) -Fallback ([string]$failurePolicy.FailureCategory)

                    if ($devCategory -eq 'noncode-transient') {
                        $devRecoveryStage = Resolve-RecoveryStageByStatus -AStatus $aStatus -BStatus $bStatus
                        $devStagePolicy = Get-StagePolicy -Stage $devRecoveryStage
                        $skipAutoFixForDevTransient = $true
                        $devTransientRecoveryResult = Invoke-StageDevRoundTransientRecovery -Stage $devRecoveryStage -FailurePolicy $failurePolicy -RestartAllowed $restartApproved -MaxAttemptsPerRound $MaxBRecoveryAttempts -CooldownMinutes $RecoveryCooldownMinutes
                        $devTransientRecoveryLogFields = Get-RecoveryResultLogCompactFields -Detail ([string]$devTransientRecoveryResult.Detail) -Evidence ([string]$devTransientRecoveryResult.Evidence)
                        Write-GuardLog ("dev_transient_recovery_result round={0} category={1} attempted={2} restarted={3} reason={4} detail={5} evidence={6} source={7}" -f
                            [string]$devTransientRecoveryResult.RoundTag,
                            [string]$devTransientRecoveryResult.Category,
                            [bool]$devTransientRecoveryResult.Attempted,
                            [bool]$devTransientRecoveryResult.Restarted,
                            [string]$devTransientRecoveryResult.Reason,
                            [string]$devTransientRecoveryLogFields.DetailCompact,
                            [string]$devTransientRecoveryLogFields.EvidenceCompact,
                            [string]$devTransientRecoveryResult.SourceLog)

                        if ([bool]$devTransientRecoveryResult.Attempted -and ([string]$devTransientRecoveryResult.Reason -eq 'restart-await-confirmation')) {
                            $devWaitTicketContext = Get-RestartAwaitConfirmationTicketContext -RoundTag ([string]$devTransientRecoveryResult.RoundTag) -Category ([string]$devTransientRecoveryResult.Category) -Attempt ([int]$devTransientRecoveryResult.Attempt) -MaxAttempts ([int]$MaxBRecoveryAttempts) -Reason ([string]$devTransientRecoveryResult.Reason) -Detail ([string]$devTransientRecoveryResult.Detail) -RunDirAnchor $runDirAnchor
                            $null = Add-RestartAwaitConfirmationTicket -Enabled $agentQueueEnabled -QueuePath $agentQueuePath -EventName 'dev-restart-await-confirmation' -SessionStatus $sessionStatus -AStatus $aStatus -BStatus $bStatus -RunDirAnchor $runDirAnchor -TicketContext $devWaitTicketContext -RecommendedAction 'Set LOCAL_GUARD_RESTART_APPROVED=true after evidence review to allow guarded D-round restart.' -MainRound ([string]$failureTicketMeta.MainRound) -FailureKind ([string]$failureTicketMeta.FailureKind) -FailureCategory ([string]$devTransientRecoveryResult.Category) -FailureSource ([string]$devTransientRecoveryResult.SourceLog) -FailureEvidence ([string]$devTransientRecoveryResult.Evidence) -NonRecoverableEnv ([bool]$failureTicketMeta.NonRecoverableEnv)

                            Write-PausedSessionState -EventName 'dev-restart-await-confirmation' -SessionStatus $sessionStatus -AStatus $aStatus -BStatus $bStatus -ExtraValues (Get-RestartApprovalFlagsExtraValues -RestartRequiresConfirmation $restartRequiresConfirmation -RestartApproved $restartApproved)
                            Start-Sleep -Seconds $PollSec
                            continue
                        }

                        if ([bool]$devTransientRecoveryResult.Restarted) {
                            Reset-RestartRecoveryMonitorState -ManualPauseActive ([ref]$manualPauseActive) -ManualPauseSignature ([ref]$manualPauseSignature) -ManualPauseNoticeCount ([ref]$manualPauseNoticeCount) -LastIncidentSignature ([ref]$lastIncidentSignature) -LastBudgetExhaustedSignature ([ref]$lastBudgetExhaustedSignature)

                            $devRestartEventName = [string]$devStagePolicy.DevTransientRestartEventName
                            Write-RestartRunningState -EventName $devRestartEventName -ExtraValues @{
                                dev_restart_stage = [string]$devRecoveryStage
                                dev_restart_round = [string]$devTransientRecoveryResult.RoundTag
                                dev_restart_category = [string]$devTransientRecoveryResult.Category
                                dev_restart_attempt = [int]$devTransientRecoveryResult.Attempt
                            }
                            Invoke-RestartSettlePause
                            continue
                        }
                    }
                }

                $autoFixStage = Resolve-RecoveryStageByStatus -AStatus $aStatus -BStatus $bStatus -AllowBRecovery $true -AutoRecoverB $autoRecoverB -CanRecoverB $canRecoverB -GuardRestartAllowedForFailure $guardRestartAllowedForFailure

                if ($autoFixCompileEnabled -and $guardRestartAllowedForFailure -and -not [string]::IsNullOrWhiteSpace($autoFixStage) -and -not [bool]$failurePolicy.IsVerifyRound -and -not $skipAutoFixForDevTransient) {
                    $autoFixResult = Invoke-StageCompileAutoFixRecovery -Stage $autoFixStage -Settings $settings -RunDirAnchor $runDirAnchor -MaxAttemptsPerRound $autoFixMaxPerDRound -CooldownMinutes $autoFixCooldownMinutes -RestartAllowed $restartApproved
                    $autoFixLogFields = Get-AutoFixResultLogCompactFields -Detail ([string]$autoFixResult.Detail)
                    $autoFixStatusSignature = "{0}|{1}|{2}|{3}" -f [string]$autoFixResult.Reason, [string]$autoFixResult.RoundTag, $runDirAnchor, [int]$autoFixResult.Attempt

                    if ([bool]$autoFixResult.Attempted) {
                        $lastAutoFixStatusSignature = ''
                        Write-GuardLog ("auto_fix_result stage={0} round={1} attempt={2}/{3} restarted={4} reason={5} detail={6} task={7} strict_log={8} category={9} script_fault={10} code_fault={11}" -f
                            $autoFixStage,
                            [string]$autoFixResult.RoundTag,
                            [int]$autoFixResult.Attempt,
                            [int]$autoFixMaxPerDRound,
                            [bool]$autoFixResult.Restarted,
                            [string]$autoFixResult.Reason,
                            [string]$autoFixLogFields.DetailCompact220,
                            [string]$autoFixResult.TaskDefinitionPath,
                            [string]$autoFixResult.StrictLogPath,
                            $failureCategory,
                            $failureHasScriptFault,
                            $failureHasCodeFault)
                    }
                    elseif ($autoFixStatusSignature -ne $lastAutoFixStatusSignature) {
                        $lastAutoFixStatusSignature = $autoFixStatusSignature
                        Write-GuardLog ("auto_fix_skip stage={0} reason={1} round={2} detail={3}" -f
                            $autoFixStage,
                            [string]$autoFixResult.Reason,
                            [string]$autoFixResult.RoundTag,
                            [string]$autoFixLogFields.DetailCompact180)
                    }

                    if ([bool]$autoFixResult.Attempted -and ([string]$autoFixResult.Reason -eq 'restart-await-confirmation')) {
                        $autoFixRecommendedAction = Get-AutoFixAwaitRecommendedAction -IsDevRound ([bool]$failurePolicy.IsDevRound) -FailureHasScriptFault $failureHasScriptFault -FailureHasCodeFault $failureHasCodeFault

                        $autoFixWaitTicketContext = Get-AutoFixAwaitConfirmationTicketContext -RoundTag ([string]$autoFixResult.RoundTag) -Attempt ([int]$autoFixResult.Attempt) -MaxAttempts ([int]$autoFixMaxPerDRound) -Reason ([string]$autoFixResult.Reason) -Detail ([string]$autoFixResult.Detail) -RunDirAnchor $runDirAnchor
                        $null = Add-RestartAwaitConfirmationTicket -Enabled $agentQueueEnabled -QueuePath $agentQueuePath -EventName 'auto-fix-await-confirmation' -SessionStatus $sessionStatus -AStatus $aStatus -BStatus $bStatus -RunDirAnchor $runDirAnchor -TicketContext $autoFixWaitTicketContext -RecommendedAction $autoFixRecommendedAction -MainRound ([string]$failureTicketMeta.MainRound) -FailureKind ([string]$failureTicketMeta.FailureKind) -FailureCategory ([string]$failureTicketMeta.FailureCategory) -FailureSource ([string]$failureTicketMeta.FailureSource) -FailureEvidence ([string]$failureTicketMeta.FailureEvidence) -NonRecoverableEnv ([bool]$failureTicketMeta.NonRecoverableEnv) -SelfHealable ([bool]$failureTicketMeta.SelfHealable)
                    }

                    if ([bool]$autoFixResult.Restarted) {
                        Reset-RestartRecoveryMonitorState -ManualPauseActive ([ref]$manualPauseActive) -ManualPauseSignature ([ref]$manualPauseSignature) -ManualPauseNoticeCount ([ref]$manualPauseNoticeCount) -LastIncidentSignature ([ref]$lastIncidentSignature) -LastBudgetExhaustedSignature ([ref]$lastBudgetExhaustedSignature)

                        $autoFixStagePolicy = Get-StagePolicy -Stage $autoFixStage
                        $autoFixRestartEventName = [string]$autoFixStagePolicy.AutoFixRestartEventName
                        Write-RestartRunningState -EventName $autoFixRestartEventName -ExtraValues @{
                            auto_fix_stage = [string]$autoFixStage
                            auto_fix_round = [string]$autoFixResult.RoundTag
                            auto_fix_attempt = [int]$autoFixResult.Attempt
                            auto_fix_max_per_d_round = [int]$autoFixMaxPerDRound
                        }
                        Invoke-RestartSettlePause
                        continue
                    }
                }

                # SESSION-LEVEL GRACE: when A-stage fails, agent ticket dispatched,
                # and B cannot recover, enter grace period instead of immediate shutdown
                # to keep monitor chain alive for AI handler.
                if ($aStatus -eq 'FAIL' -and -not ($autoRecoverB -and $canRecoverB) -and $mainProcessExitMonitorGraceMinutes -gt 0) {
                    if ($null -eq $monitorChainGraceStartedAt) {
                        $monitorChainGraceStartedAt = Get-Date
                        $monitorChainGraceLastNoticeAt = $null
                        $monitorChainGraceShutdownDetail = Get-LoopRecoveryStatusDetail -SessionStatus $sessionStatus -AStatus $aStatus -BStatus $bStatus -AutoRecoverB $autoRecoverB -CanRecoverB $canRecoverB
                        $monitorChainGraceShutdownStage = 'SESSION'
                        $monitorChainGraceShutdownReason = 'a-fail-incident-ticket'
                        $monitorChainGraceShutdownSource = 'session-guard'
                        Write-MonitorChainGraceStartLog -Stage $monitorChainGraceShutdownStage -GraceMinutes $mainProcessExitMonitorGraceMinutes -Reason $monitorChainGraceShutdownReason -SessionStatus $sessionStatus -AStatus $aStatus -BStatus $bStatus -RunDirAnchor $runDirAnchor
                    }

                    $graceElapsedMinutes = ((Get-Date) - $monitorChainGraceStartedAt).TotalMinutes
                    if ($graceElapsedMinutes -ge $mainProcessExitMonitorGraceMinutes) {
                        Write-MonitorChainGraceExpiredLog -Stage $monitorChainGraceShutdownStage -ElapsedMinutes $graceElapsedMinutes -Reason $monitorChainGraceShutdownReason
                        $monitorChainGraceStartedAt = $null
                    }
                    else {
                        $remainingGraceMinutes = [Math]::Max(0.0, ($mainProcessExitMonitorGraceMinutes - $graceElapsedMinutes))
                        if ($null -eq $monitorChainGraceLastNoticeAt -or (((Get-Date) - $monitorChainGraceLastNoticeAt).TotalMinutes -ge 5)) {
                            Write-MonitorChainGraceWaitLog -Stage $monitorChainGraceShutdownStage -ElapsedMinutes $graceElapsedMinutes -RemainingMinutes $remainingGraceMinutes -SessionStatus $sessionStatus -AStatus $aStatus -BStatus $bStatus
                            $monitorChainGraceLastNoticeAt = Get-Date
                        }
                        Write-WaitingMonitorChainGraceState -SessionStatus $sessionStatus -AStatus $aStatus -BStatus $bStatus -GraceStage $monitorChainGraceShutdownStage -RemainingGraceMinutes $remainingGraceMinutes
                        Start-Sleep -Seconds $PollSec
                        continue
                    }
                }

                if ($autoRecoverB -and $canRecoverB -and $guardRestartAllowedForFailure) {
                    $bRecoveryStagePolicy = Get-StagePolicy -Stage 'B'
                    if (-not $restartApproved) {
                        $recoveryWaitTicketContext = Get-RecoveryAwaitConfirmationTicketContext -Attempts $bRecoveryAttempts -MaxAttempts $MaxBRecoveryAttempts -SessionStatus $sessionStatus -AStatus $aStatus -BStatus $bStatus -RunDirAnchor $runDirAnchor
                        $approvalWaitSignature = [string]$recoveryWaitTicketContext.DedupSuffix
                        if ($approvalWaitSignature -ne $lastRestartApprovalWaitSignature) {
                            Write-RecoveryWaitingConfirmationLog -Stage 'B' -Attempts $bRecoveryAttempts -MaxAttempts $MaxBRecoveryAttempts -SessionStatus $sessionStatus -AStatus $aStatus -BStatus $bStatus
                            $null = Add-RestartAwaitConfirmationTicket -Enabled $agentQueueEnabled -QueuePath $agentQueuePath -EventName 'recovery-await-confirmation' -SessionStatus $sessionStatus -AStatus $aStatus -BStatus $bStatus -RunDirAnchor $runDirAnchor -TicketContext $recoveryWaitTicketContext -RecommendedAction 'Report root cause and remediation path first. After evidence check, set LOCAL_GUARD_RESTART_APPROVED=true and execute business_resume immediately. Execute every ticket step without omission, then execute atomic_closeout_command exactly once and claim closure only from its successful machine facts. After a main-process restart, complete atomic closeout within 3 minutes; this is not a monitoring window. Then wait silently for the next ticket delivered by guard/trigger/dispatch. Never run scheduled, persistent, or long-running cross-round monitoring commands.' -MainRound ([string]$failureTicketMeta.MainRound) -FailureKind ([string]$failureTicketMeta.FailureKind) -FailureCategory ([string]$failureTicketMeta.FailureCategory) -FailureSource ([string]$failureTicketMeta.FailureSource) -FailureEvidence ([string]$failureTicketMeta.FailureEvidence) -NonRecoverableEnv ([bool]$failureTicketMeta.NonRecoverableEnv) -PreferredStage ([string]$bRecoveryStagePolicy.PreferredStage) -SelfHealable $true
                            $lastRestartApprovalWaitSignature = $approvalWaitSignature
                        }

                        Write-PausedSessionState -EventName 'await-restart-confirmation' -SessionStatus $sessionStatus -AStatus $aStatus -BStatus $bStatus -ExtraValues (Get-RecoveryApprovalPauseExtraValues -AutoRecoverB $autoRecoverB -CanRecoverB $canRecoverB -RestartRequiresConfirmation $restartRequiresConfirmation -RestartApproved $restartApproved -Stage 'B' -RecoveryAttempts $bRecoveryAttempts)
                        Start-Sleep -Seconds $PollSec
                        continue
                    }

                    $lastRestartApprovalWaitSignature = ''
                    if ($bRecoveryAttempts -ge $MaxBRecoveryAttempts) {
                        $budgetSignature = "{0}|{1}|{2}|{3}" -f $sessionStatus, $aStatus, $bStatus, $runDirAnchor
                        if ($StopOnBudgetExhausted) {
                            $activityWindowMinutes = [Math]::Max(6, [int][Math]::Ceiling(([double]$PollSec * 4.0) / 60.0))
                            $livenessEvidence = Get-BudgetExhaustedLivenessEvidence -Settings $settings -WindowMinutes $activityWindowMinutes -FallbackProcessId $bLaunchPid
                            if ([bool]$livenessEvidence.Active) {
                                $deferSignature = ($budgetSignature + '|active')
                                if ($deferSignature -ne $lastBudgetExhaustedSignature) {
                                    Write-GuardLog ("recovery_skip reason=budget_exhausted_defer_active attempts={0} max={1} detail={2}" -f $bRecoveryAttempts, $MaxBRecoveryAttempts, [string]$livenessEvidence.Detail)
                                    $lastBudgetExhaustedSignature = $deferSignature
                                }

                                Write-BudgetExhaustedDeferActiveState -Stage 'B' -RecoveryAttempts $bRecoveryAttempts -LivenessDetail ([string]$livenessEvidence.Detail)
                                Start-Sleep -Seconds $PollSec
                                continue
                            }

                            $lastBudgetExhaustedSignature = Update-BudgetExhaustedSkipSignature -CurrentSignature $lastBudgetExhaustedSignature -CandidateSignature $budgetSignature -Attempts $bRecoveryAttempts -MaxAttempts $MaxBRecoveryAttempts

                            Write-BudgetExhaustedStoppedState -Stage 'B' -RecoveryAttempts $bRecoveryAttempts
                            if ($mainProcessExitMonitorGraceMinutes -gt 0) {
                                if ($null -eq $monitorChainGraceStartedAt) {
                                    $monitorChainGraceStartedAt = Get-Date
                                    $monitorChainGraceLastNoticeAt = $null
                                    $monitorChainGraceShutdownDetail = Get-BudgetAttemptsDetail -Attempts $bRecoveryAttempts -MaxAttempts $MaxBRecoveryAttempts
                                    $monitorChainGraceShutdownStage = 'SESSION'
                                    $monitorChainGraceShutdownReason = 'budget-exhausted-stop'
                                    $monitorChainGraceShutdownSource = 'session-guard'
                                    Write-MonitorChainGraceStartLog -Stage $monitorChainGraceShutdownStage -GraceMinutes $mainProcessExitMonitorGraceMinutes -Reason $monitorChainGraceShutdownReason -SessionStatus $sessionStatus -AStatus $aStatus -BStatus $bStatus -RunDirAnchor $runDirAnchor
                                }

                                $budgetDetail = Get-BudgetExhaustedDetail -Attempts $bRecoveryAttempts -MaxAttempts $MaxBRecoveryAttempts -StopOnBudgetExhausted $StopOnBudgetExhausted
                                $null = Add-BudgetExhaustedStopTicket -Enabled $agentQueueEnabled -QueuePath $agentQueuePath -SessionStatus $sessionStatus -AStatus $aStatus -BStatus $bStatus -RunDirAnchor $runDirAnchor -Detail $budgetDetail -DedupSuffix $budgetSignature -MainRound ([string]$failureTicketMeta.MainRound) -FailureCategory ([string]$failureTicketMeta.FailureCategory) -FailureSource ([string]$failureTicketMeta.FailureSource) -FailureEvidence ([string]$failureTicketMeta.FailureEvidence) -NonRecoverableEnv ([bool]$failureTicketMeta.NonRecoverableEnv)
                                Write-GuardLog ("budget_exhausted_grace_started attempts={0} max={1} grace_min={2}" -f $bRecoveryAttempts, $MaxBRecoveryAttempts, $mainProcessExitMonitorGraceMinutes)
                                Start-Sleep -Seconds $PollSec
                                continue
                            }

                            $settings = Request-MonitorChainShutdown -Settings $settings -Reason 'budget-exhausted-stop' -Source 'session-guard' -Detail (Get-BudgetAttemptsDetail -Attempts $bRecoveryAttempts -MaxAttempts $MaxBRecoveryAttempts)
                            $budgetDetail = Get-BudgetExhaustedDetail -Attempts $bRecoveryAttempts -MaxAttempts $MaxBRecoveryAttempts -StopOnBudgetExhausted $StopOnBudgetExhausted
                            $null = Add-BudgetExhaustedStopTicket -Enabled $agentQueueEnabled -QueuePath $agentQueuePath -SessionStatus $sessionStatus -AStatus $aStatus -BStatus $bStatus -RunDirAnchor $runDirAnchor -Detail $budgetDetail -DedupSuffix $budgetSignature -MainRound ([string]$failureTicketMeta.MainRound) -FailureCategory ([string]$failureTicketMeta.FailureCategory) -FailureSource ([string]$failureTicketMeta.FailureSource) -FailureEvidence ([string]$failureTicketMeta.FailureEvidence) -NonRecoverableEnv ([bool]$failureTicketMeta.NonRecoverableEnv)
                            Write-BudgetExhaustedCompletionLog -Attempts $bRecoveryAttempts -MaxAttempts $MaxBRecoveryAttempts -StopOnBudgetExhausted $StopOnBudgetExhausted
                            break
                        }

                        $lastBudgetExhaustedSignature = Update-BudgetExhaustedSkipSignature -CurrentSignature $lastBudgetExhaustedSignature -CandidateSignature $budgetSignature -Attempts $bRecoveryAttempts -MaxAttempts $MaxBRecoveryAttempts
                    }
                    elseif ($lastRecoveryAt -ne [datetime]::MinValue -and ((Get-Date) -lt $lastRecoveryAt.AddMinutes($RecoveryCooldownMinutes))) {
                        $lastBudgetExhaustedSignature = ''
                        $nextAt = $lastRecoveryAt.AddMinutes($RecoveryCooldownMinutes).ToString('yyyy-MM-dd HH:mm:ss')
                        Write-GuardLog ("recovery_skip reason=cooldown next_at={0}" -f $nextAt)
                    }
                    else {
                        $lastBudgetExhaustedSignature = ''
                        $attempt = $bRecoveryAttempts + 1
                        $restartResult = Get-NormalizedStageRestartResult -InputObject @(Invoke-StageRestartByPolicy -Stage 'B' -Attempt $attempt)
                        if ($restartResult.Succeeded) {
                            $bRecoveryAttempts = $attempt
                            $lastRecoveryAt = Get-Date
                            $lastIncidentSignature = ''
                            $lastBudgetExhaustedSignature = ''
                            Write-RestartTriggeredRunningState -Stage 'B' -RecoveryAttempts $bRecoveryAttempts -LastRecoveryAtText $lastRecoveryAt.ToString('yyyy-MM-dd HH:mm:ss')
                            $restartNote = Format-StageRestartNote -Stage 'B' -Attempt $attempt -AtText $lastRecoveryAt.ToString('yyyy-MM-dd HH:mm:ss')
                            $statusRefresh = Read-SessionStatusRefresh -StartFilePath $script:StartFilePath
                            $statusView = Get-StatusSnapshotView -StatusSnapshot $statusRefresh.StatusSnapshot
                            $newNotes = Add-DelimitedNote -Existing $statusView.Notes -Append $restartNote
                            Invoke-KeyValueFileValueUpdateCore -Path $script:StartFilePath -Values @{ SESSION_FINAL_NOTES = $newNotes }
                            Write-StageRecoveryResultLog -Stage 'B' -Result 'triggered' -Attempt $attempt
                            Invoke-RestartSettlePause
                            continue
                        }

                        Write-StageRecoveryResultLog -Stage 'B' -Result 'failed' -Attempt $attempt -ExitCode $restartResult.ExitCode
                    }
                }
                else {
                    Reset-GuardLoopSignatures -BudgetExhaustedSignature ([ref]$lastBudgetExhaustedSignature) -RestartApprovalWaitSignature ([ref]$lastRestartApprovalWaitSignature)

                    if ($null -ne $mainProcessExitGraceStartedAt) {
                        if ($canRecoverB) {
                            Write-GuardLog ("main_process_exit_no_autofix_deferred reason=b-recoverable-ticket session={0} a={1} b={2}" -f $sessionStatus, $aStatus, $bStatus)
                            Write-WaitingMainExitGraceState -SessionStatus $sessionStatus -AStatus $aStatus -BStatus $bStatus -GraceStage $mainProcessExitGraceStage -RemainingGraceMinutes $mainProcessExitMonitorGraceMinutes
                            Start-Sleep -Seconds $PollSec
                            continue
                        }

                        $graceElapsedMinutes = ((Get-Date) - $mainProcessExitGraceStartedAt).TotalMinutes
                        if ($graceElapsedMinutes -ge $mainProcessExitMonitorGraceMinutes) {
                            $shutdownDetail = $mainProcessExitGraceShutdownDetail
                            if ([string]::IsNullOrWhiteSpace($shutdownDetail)) {
                                $shutdownDetail = ("main_process_exit grace_expired stage={0} status={1} a={2} b={3} run_dir={4}" -f $mainProcessExitGraceStage, $sessionStatus, $aStatus, $bStatus, $runDirAnchor)
                            }
                            $settings = Request-MainProcessExitNoAutofixShutdown -Settings $settings -Detail $shutdownDetail
                            $mainProcessExitNoAutoFixStopRequested = $true
                        }
                        else {
                            $remainingGraceMinutes = [Math]::Max(0.0, ($mainProcessExitMonitorGraceMinutes - $graceElapsedMinutes))
                            if ($null -eq $mainProcessExitGraceLastNoticeAt -or (((Get-Date) - $mainProcessExitGraceLastNoticeAt).TotalMinutes -ge 5)) {
                                Write-GraceWaitLog -Prefix 'main_process_exit_grace_wait' -Stage $mainProcessExitGraceStage -ElapsedMinutes $graceElapsedMinutes -RemainingMinutes $remainingGraceMinutes -SessionStatus $sessionStatus -AStatus $aStatus -BStatus $bStatus
                                $mainProcessExitGraceLastNoticeAt = Get-Date
                            }
                            Write-WaitingMainExitGraceState -SessionStatus $sessionStatus -AStatus $aStatus -BStatus $bStatus -GraceStage $mainProcessExitGraceStage -RemainingGraceMinutes $remainingGraceMinutes
                            Start-Sleep -Seconds $PollSec
                            continue
                        }
                    }

                    if ($mainProcessExitNoAutoFixStopRequested) {
                        Write-StoppedRecoverySessionState -EventName 'main-process-exit-no-autofix-stop' -SessionStatus $sessionStatus -AStatus $aStatus -BStatus $bStatus -AutoRecoverB $autoRecoverB -CanRecoverB $canRecoverB
                        Write-RecoveryCompletionLog -Reason 'main_process_exit_no_autofix_stop' -SessionStatus $sessionStatus -AStatus $aStatus -BStatus $bStatus -AutoRecoverB $autoRecoverB -CanRecoverB $canRecoverB
                        break
                    }

                    # Before entering final-state-no-followup grace, check if a
                    # new main process is alive despite stale FAIL status from
                    # an earlier A failure.  If so, treat session as RUNNING
                    # and skip the grace entirely.
                    if (-not $canRecoverB -and $mainProcessExitMonitorGraceMinutes -gt 0) {
                        try {
                            $statusRefresh = Read-SessionStatusRefresh -StartFilePath $script:StartFilePath
                            $reviveSettings = $statusRefresh.Settings
                            if ($null -ne $reviveSettings) {
                                $reviveAPid = 0; $reviveBPid = 0
                                $reviveAPidStr = if ($null -ne $reviveSettings -and $reviveSettings.Contains('A_LAUNCH_PID')) { [string]$reviveSettings.A_LAUNCH_PID } else { '0' }
                                $reviveBPidStr = if ($null -ne $reviveSettings -and $reviveSettings.Contains('B_LAUNCH_PID')) { [string]$reviveSettings.B_LAUNCH_PID } else { '0' }
                                if (-not [string]::IsNullOrWhiteSpace($reviveAPidStr)) { [int]::TryParse($reviveAPidStr, [ref]$reviveAPid) | Out-Null }
                                if (-not [string]::IsNullOrWhiteSpace($reviveBPidStr)) { [int]::TryParse($reviveBPidStr, [ref]$reviveBPid) | Out-Null }
                                $reviveAAlive = ($reviveAPid -gt 0) -and (Get-Process -Id $reviveAPid -ErrorAction SilentlyContinue) -and -not (Get-Process -Id $reviveAPid -ErrorAction SilentlyContinue).HasExited
                                $reviveBAlive = ($reviveBPid -gt 0) -and (Get-Process -Id $reviveBPid -ErrorAction SilentlyContinue) -and -not (Get-Process -Id $reviveBPid -ErrorAction SilentlyContinue).HasExited
                                if ($reviveAAlive) {
                                    Write-SessionReviveLog -Stage 'A' -ProcessId $reviveAPid -SessionStatus $sessionStatus -StageStatus $aStatus
                                    $sessionStatus = 'RUNNING'; $aStatus = 'RUNNING'
                                    $monitorChainGraceStartedAt = $null
                                }
                                elseif ($reviveBAlive) {
                                    Write-SessionReviveLog -Stage 'B' -ProcessId $reviveBPid -SessionStatus $sessionStatus -StageStatus $bStatus
                                    $sessionStatus = 'RUNNING'; $bStatus = 'RUNNING'
                                    $monitorChainGraceStartedAt = $null
                                }
                            }
                        }
                        catch {
                            Write-GuardLog ("session_revive_check_failed detail={0}" -f $_.Exception.Message)
                        }
                        # If revived, skip grace and continue monitoring.
                        if ($sessionStatus -eq 'RUNNING') {
                            Start-Sleep -Seconds $PollSec
                            continue
                        }
                    }
                    $manualWaitSignature = "{0}|{1}|{2}|{3}|{4}" -f $sessionStatus, $aStatus, $bStatus, $runDirAnchor, $canRecoverB
                    $loopRecoveryArgs = Get-RecoveryStateArgs -SessionStatus $sessionStatus -AStatus $aStatus -BStatus $bStatus -AutoRecoverB $autoRecoverB -CanRecoverB $canRecoverB
                    if (-not $canRecoverB -and $mainProcessExitMonitorGraceMinutes -gt 0) {
                        if ($null -eq $monitorChainGraceStartedAt) {
                            $monitorChainGraceStartedAt = Get-Date
                            $monitorChainGraceLastNoticeAt = $null
                            $monitorChainGraceShutdownDetail = Get-SessionStatusTripleDetail -SessionStatus $sessionStatus -AStatus $aStatus -BStatus $bStatus
                            $monitorChainGraceShutdownStage = 'SESSION'
                            $monitorChainGraceShutdownReason = 'final-state-no-followup'
                            $monitorChainGraceShutdownSource = 'session-guard'
                            Write-MonitorChainGraceStartLog -Stage $monitorChainGraceShutdownStage -GraceMinutes $mainProcessExitMonitorGraceMinutes -Reason $monitorChainGraceShutdownReason -SessionStatus $sessionStatus -AStatus $aStatus -BStatus $bStatus -RunDirAnchor $runDirAnchor
                        }
                        Start-Sleep -Seconds $PollSec
                        continue
                    }

                    if ($manualPauseEnabled -and $forceExitOnFinalNoFollowup -and -not $canRecoverB) {
                        $settings = Invoke-FinalNoFollowupStopAndComplete -Settings $settings -Forced $true @loopRecoveryArgs
                        break
                    }

                    if ($manualPauseEnabled) {
                        if ($manualWaitSignature -ne $manualPauseSignature) {
                            $manualPauseSignature = $manualWaitSignature
                            $manualPauseNoticeCount = 0
                            $manualPauseActive = $false
                        }

                        if ($manualPauseNoticeCount -lt $manualPauseNoticeRepeat) {
                            $noticeIndex = $manualPauseNoticeCount + 1
                            Write-ManualActionRequiredLog @loopRecoveryArgs -NoticeIndex $noticeIndex -NoticeRepeat $manualPauseNoticeRepeat
                            $manualPauseNoticeCount++
                        }

                        if ($manualPauseNoticeCount -ge $manualPauseNoticeRepeat -and -not $manualPauseActive) {
                            $manualPauseActive = $true
                            Write-PausedSessionState -EventName 'manual-wait-paused' -SessionStatus $sessionStatus -AStatus $aStatus -BStatus $bStatus -ExtraValues (Get-RecoveryFlagsWithManualNoticeExtraValues -AutoRecoverB $autoRecoverB -CanRecoverB $canRecoverB -ManualNoticeRepeat $manualPauseNoticeRepeat)
                            $manualWaitDetail = Get-LoopRecoveryStatusDetail @loopRecoveryArgs
                            Write-RecoveryStatusLog -Prefix 'manual_wait_paused' @loopRecoveryArgs -StatusDetail $manualWaitDetail
                            $manualWaitNoticeAction = 'Report blockers and provide a recovery decision only; this notice grants no file edit, environment change, resume, continue-watch, or restart authority.'
                            $null = Add-AgentTicket -Enabled $agentQueueEnabled -QueuePath $agentQueuePath -EventName 'manual-wait-paused' -Severity 'medium' -RequiresConfirmation $restartRequiresConfirmation -SessionStatus $sessionStatus -AStatus $aStatus -BStatus $bStatus -RunDirAnchor $runDirAnchor -IncidentDir '' -Detail $manualWaitDetail -DedupSuffix $manualWaitSignature -RecommendedAction $manualWaitNoticeAction -PreferredStage ([string]$failureTicketMeta.PreferredStage) -MainRound ([string]$failureTicketMeta.MainRound) -FailureKind ([string]$failureTicketMeta.FailureKind) -FailureCategory ([string]$failureTicketMeta.FailureCategory) -FailureSource ([string]$failureTicketMeta.FailureSource) -FailureEvidence ([string]$failureTicketMeta.FailureEvidence) -SelfHealable $false -NonRecoverableEnv ([bool]$failureTicketMeta.NonRecoverableEnv)
                        }

                        Start-Sleep -Seconds $PollSec
                        continue
                    }

                    if (-not $canRecoverB) {
                        $settings = Invoke-FinalNoFollowupStopAndComplete -Settings $settings -Forced $false -SkipCompletion $true @loopRecoveryArgs
                        # Emit stop event ticket for downstream consumption
                        $stopEventDetail = Get-SessionEvidenceDetail -SessionStatus $sessionStatus -AStatus $aStatus -BStatus $bStatus -Evidence ([string]$script:Settings.SESSION_FINAL_NOTES)
                        $stopEventId = 'session-stop-' + (Get-Date).ToString('yyyyMMdd-HHmmss')
                        $stopEventTicket = [pscustomobject]@{
                            schema = 'AB_AGENT_TICKET_V1'
                            ticket_id = $stopEventId
                            created_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
                            source = 'unattended_ab_session_guard'
                            event = 'unattended-stop'
                            severity = 'high'
                            requires_confirmation = $false
                            start_file = (Convert-ToRepoRelativePath -Path $script:StartFilePath)
                            queue_path = (Convert-ToRepoRelativePath -Path $script:GuardStatePath)
                            guard_state = 'stopped'
                            session_final_status = $sessionStatus
                            a_final_status = $aStatus
                            b_final_status = $bStatus
                            detail = $stopEventDetail
                            recommended_action = 'review stop reason and decide rerun scope'
                        }
                        $null = Add-TicketToQueue -Ticket $stopEventTicket -QueueFilePath $agentQueuePath
                        Write-GuardLog ("unattended_stop_ticket_queued id={0} detail={1}" -f $stopEventId, $stopEventDetail)
                        Write-FinalNoFollowupRecoveryCompletionLog -Forced $false @loopRecoveryArgs
                        break
                    }

                    Write-ManualActionRequiredLog @loopRecoveryArgs
                }
            }
            else {
                Reset-GuardLoopSignatures -BudgetExhaustedSignature ([ref]$lastBudgetExhaustedSignature) -RestartApprovalWaitSignature ([ref]$lastRestartApprovalWaitSignature)
                $now = Get-Date
                if ($lastHeartbeatAt -eq [datetime]::MinValue -or (($now - $lastHeartbeatAt).TotalMinutes -ge 5)) {
                    $sessionRunningSummary = Get-SessionRunningSummaryDetail -SessionStatus $sessionStatus -AStatus $aStatus -BStatus $bStatus -Running $running -RunDirAnchor $runDirAnchor
                    Write-GuardLog ("heartbeat {0}" -f $sessionRunningSummary)
                    $lastHeartbeatAt = $now
                }

                if ($statusTicketEnabled) {
                    $statusTicketDue = ($lastStatusTicketAt -eq [datetime]::MinValue -or (($now - $lastStatusTicketAt).TotalMinutes -ge $statusTicketIntervalMinutes))
                    if ($statusTicketDue) {
                        $statusDetail = Get-SessionRunningSummaryDetail -SessionStatus $sessionStatus -AStatus $aStatus -BStatus $bStatus -Running $running -RunDirAnchor $runDirAnchor
                        $statusDedupSuffix = ("interval={0}|slot={1}|status={2}|a={3}|b={4}|run={5}" -f $statusTicketIntervalMinutes, $now.ToString('yyyyMMdd-HHmm'), $sessionStatus, $aStatus, $bStatus, $runDirAnchor)
                        $statusRecommendedAction = 'Scheduled status report only: report observed runtime state from read-only status checks. Do not execute self-heal, fault handling, process restart, business_resume, source/script edits, or operational recovery from this ticket. If an abnormal condition is observed, report it and wait for a separate incident ticket; do not handle the fault from the status ticket. Return handled_at (YYYY-MM-DD HH:mm:ss) after reporting. session_closed_at is session-level only and MUST be returned only when stop monitoring is requested or both A/B are terminal.'
                        $lastStatusTicketAt = $now
                        $statusPreferredStage = if ($aStatus -eq 'PASS' -and $bStatus -ne 'PASS') { 'B' } else { 'A' }
                        $statusTicketResult = Add-AgentTicket -Enabled $agentQueueEnabled -QueuePath $agentQueuePath -EventName 'running-status-report' -Severity 'info' -RequiresConfirmation $false -SessionStatus $sessionStatus -AStatus $aStatus -BStatus $bStatus -RunDirAnchor $runDirAnchor -IncidentDir '' -Detail $statusDetail -DedupSuffix $statusDedupSuffix -RecommendedAction $statusRecommendedAction -PreferredStage $statusPreferredStage -MainRound '' -FailureKind 'running-status' -FailureCategory '' -FailureSource '' -FailureEvidence '' -SelfHealable $false -NonRecoverableEnv $false
                        if (-not (Get-TicketResultQueuedFlag -TicketResult $statusTicketResult) -and (Get-TicketResultReason -TicketResult $statusTicketResult) -notin @('duplicate-signature', 'queue-disabled')) {
                            Write-GuardLog ("status_ticket_deferred_next_slot reason={0} interval_min={1}" -f (Get-TicketResultReason -TicketResult $statusTicketResult), $statusTicketIntervalMinutes)
                        }
                    }
                }
            }
        }
        catch {
            Write-GuardLog ("loop_error detail={0}" -f $_.Exception.Message.Replace("`r", ' ').Replace("`n", ' '))
        }
        finally {
            # Health check runs every ~300s even after continue/break to ensure
            # offline monitors (trigger) are restarted.
            $healthCheckIterationCounter++
            $healthCheckIntervalIterations = [Math]::Max(1, [int][Math]::Round(300.0 / [Math]::Max(15, $PollSec)))
            if ($healthCheckIterationCounter -ge $healthCheckIntervalIterations) {
                $healthCheckIterationCounter = 0
                $triggerRequestPending = $false
                try {
                    $triggerRequestState = Get-TriggerRestartRequestFromStartFile -StartFilePath $script:StartFilePath
                    $triggerRequestPending = [bool]$triggerRequestState.Requested
                }
                catch {
                    $triggerRequestPending = $false
                }

                $sessionIdleNotRun = ($sessionStatus -eq 'NOT_RUN' -and $aStatus -eq 'NOT_RUN' -and $bStatus -eq 'NOT_RUN')
                $aMainAlive = ($aStatus -eq 'RUNNING' -and $aLaunchPid -gt 0 -and (Test-ProcessAlive -ProcessId $aLaunchPid))
                $bMainAlive = ($bStatus -eq 'RUNNING' -and $bLaunchPid -gt 0 -and (Test-ProcessAlive -ProcessId $bLaunchPid))
                $mainProcessAlive = ([bool]$aMainAlive -or [bool]$bMainAlive)
                $graceStopActive = ($null -ne $mainProcessExitGraceStartedAt -or $null -ne $monitorChainGraceStartedAt)

                if ($sessionIdleNotRun -and -not $triggerRequestPending) {
                    Write-TriggerHealthSkipLog -Reason 'session_idle_not_run'
                }
                elseif (-not $mainProcessAlive -and -not $triggerRequestPending) {
                    if ($graceStopActive) {
                        Write-TriggerHealthSkipLog -Reason 'main_process_not_running_or_grace_stop'
                    }
                    else {
                        Write-TriggerHealthSkipLog -Reason 'main_process_not_running'
                    }
                }
                else {
                    Write-GuardLog ("trigger_health_check_run reason=interval poll_sec={0} request_pending={1} main_process_alive={2}" -f $PollSec, [bool]$triggerRequestPending, [bool]$mainProcessAlive)
                    Invoke-MonitorChainHealthCheck -Roles @('trigger') -RepoRoot $script:RepoRoot -StartFilePath $script:StartFilePath -LogPrefix 'GUARD-HC'
                }
            }
        }

        Start-Sleep -Seconds $PollSec
    }
}
finally {
    Write-GuardState -Values @{
        status = 'stopped'
        event = 'shutdown'
    }
    Write-GuardLog ("shutdown_pid pid={0}" -f $PID)
    if ($null -ne $script:InstanceMutex) {
        try {
            $script:InstanceMutex.ReleaseMutex() | Out-Null
        }
        catch { Write-Verbose ("Suppressed exception: {0}" -f $_.Exception.Message) }
        finally {
            $script:InstanceMutex.Dispose()
        }
    }
}

exit 0
