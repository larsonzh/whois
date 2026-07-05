param(
    [Parameter(Mandatory = $true)]
    [string]$StartFile,

    [AllowEmptyString()]
    [string]$QueuePath = 'out\artifacts\ab_agent_queue\agent_tickets.jsonl',

    [AllowEmptyString()]
    [string]$TicketEvent = 'chat-session-final-status',

    [AllowEmptyString()]
    [string]$TicketId = '',

    [ValidateRange(10, 3600)]
    [int]$DelaySeconds = 60,

    [AllowEmptyString()]
    [string]$TaskPrefix = 'Whois-Dispatch-Real',

    [switch]$NoUseAhk,
    [switch]$SkipPendingCleanup,
    [switch]$PlanOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$pathGuardModulePath = Join-Path $PSScriptRoot 'path_write_guard.ps1'
if (-not (Test-Path -LiteralPath $pathGuardModulePath)) {
    throw "Missing script: $pathGuardModulePath"
}
. $pathGuardModulePath
. (Join-Path $PSScriptRoot 'unattended_startfile_identity.ps1')

function Convert-ToSingleLineText {
    param([AllowEmptyString()][string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return ''
    }

    $singleLine = (($Text -split "`r?`n") -join ' ')
    return ([regex]::Replace($singleLine, '\s+', ' ')).Trim()
}

function Get-SafeToken {
    param([AllowEmptyString()][string]$Text)

    $raw = Convert-ToSingleLineText -Text $Text
    if ([string]::IsNullOrWhiteSpace($raw)) {
        return 'default'
    }

    return ([regex]::Replace($raw, '[^A-Za-z0-9._-]', '_')).Trim('_')
}

function Convert-ToSingleQuotedLiteral {
    param([AllowEmptyString()][string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return ''
    }

    return $Text.Replace("'", "''")
}

function Get-CeilingMinute {
    param([datetime]$Time)

    $minuteFloor = Get-Date -Year $Time.Year -Month $Time.Month -Day $Time.Day -Hour $Time.Hour -Minute $Time.Minute -Second 0
    if ($minuteFloor -lt $Time) {
        return $minuteFloor.AddMinutes(1)
    }

    return $minuteFloor
}

function Invoke-TaskRemovalBestEffort {
    param([AllowEmptyString()][string]$TaskName)

    if ([string]::IsNullOrWhiteSpace($TaskName)) {
        return $false
    }

    $removed = $false

    try {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
    }
    catch {
        $null = $_
    }

    try {
        schtasks /Delete /TN $TaskName /F 1>$null 2>$null
        if ($LASTEXITCODE -eq 0) {
            $removed = $true
        }
    }
    catch {
        $null = $_
    }

    return $removed
}

function Get-TaskNextRunTimeText {
    param([AllowEmptyString()][string]$TaskName)

    if ([string]::IsNullOrWhiteSpace($TaskName)) {
        return ''
    }

    try {
        $taskInfo = Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction Stop
        if ($null -ne $taskInfo.NextRunTime -and $taskInfo.NextRunTime -gt [datetime]::MinValue) {
            return $taskInfo.NextRunTime.ToString('yyyy-MM-dd HH:mm:ss')
        }
    }
    catch {
        $null = $_
    }

    return ''
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$dispatchDir = Join-Path $repoRoot 'out\artifacts\ab_agent_queue\chat_dispatch'
$wrapperDir = Join-Path $repoRoot 'tmp\scheduled_dispatch'
New-Item -ItemType Directory -Path $dispatchDir -Force | Out-Null
New-Item -ItemType Directory -Path $wrapperDir -Force | Out-Null

$startFileAbs = Resolve-RepoPathAllowMissing -Path $StartFile
if ([string]::IsNullOrWhiteSpace($startFileAbs) -or -not (Test-Path -LiteralPath $startFileAbs)) {
    throw ('StartFile not found: {0}' -f $StartFile)
}

$queuePathAbs = Resolve-RepoPathAllowMissing -Path $QueuePath
$startFileRel = Convert-ToRepoRelativePath -Path $startFileAbs
$queuePathRel = Convert-ToRepoRelativePath -Path $queuePathAbs

$now = Get-Date
$desiredRunAt = $now.AddSeconds($DelaySeconds)
$taskStamp = $now.ToString('yyyyMMdd-HHmmss')
$taskName = ('{0}-{1}' -f (Get-SafeToken -Text $TaskPrefix), $taskStamp)
$ticketIdEffective = Convert-ToSingleLineText -Text $TicketId
if ([string]::IsNullOrWhiteSpace($ticketIdEffective)) {
    $ticketIdEffective = 'manual-real-delay-' + $now.ToString('yyyyMMddHHmmss')
}

$scriptRel = ('tmp\\scheduled_dispatch\\scheduled_dispatch_{0}.ps1' -f $taskStamp)
$scriptAbs = Assert-GuardRepoPathUnderRoots -Path (Join-Path $repoRoot $scriptRel) -RepoRoot $repoRoot -AllowedRelativeRoots @('tmp') -Label 'scheduled dispatch wrapper'
$logRel = ('out\\artifacts\\ab_agent_queue\\chat_dispatch\\scheduled_dispatch_{0}.log' -f $taskStamp)
$null = Assert-GuardRepoPathUnderRoots -Path (Join-Path $repoRoot $logRel) -RepoRoot $repoRoot -AllowedRelativeRoots @('out\artifacts') -Label 'scheduled dispatch log'

$statePath = Join-Path $dispatchDir ('delayed_dispatch_state_{0}.json' -f (Get-SafeToken -Text ([System.IO.Path]::GetFileNameWithoutExtension($startFileAbs))))
$statePath = Assert-GuardRepoPathUnderRoots -Path $statePath -RepoRoot $repoRoot -AllowedRelativeRoots @('out\artifacts') -Label 'scheduled dispatch state'
$cleanupSummary = [ordered]@{
    attempted = $false
    previous_task_name = ''
    removed_previous_task = $false
}

if (-not $SkipPendingCleanup.IsPresent -and (Test-Path -LiteralPath $statePath)) {
    $cleanupSummary.attempted = $true
    try {
        $previousState = Get-Content -LiteralPath $statePath -Raw -Encoding utf8 | ConvertFrom-Json
        if ($null -ne $previousState -and $previousState.PSObject.Properties['task_name']) {
            $previousTaskName = Convert-ToSingleLineText -Text ([string]$previousState.task_name)
            if (-not [string]::IsNullOrWhiteSpace($previousTaskName) -and $previousTaskName -ne $taskName) {
                $cleanupSummary.previous_task_name = $previousTaskName
                $cleanupSummary.removed_previous_task = Invoke-TaskRemovalBestEffort -TaskName $previousTaskName
            }
        }
    }
    catch {
        $null = $_
    }
}

$repoRootEscaped = Convert-ToSingleQuotedLiteral -Text $repoRoot
$ticketEventEscaped = Convert-ToSingleQuotedLiteral -Text $TicketEvent
$ticketIdEscaped = Convert-ToSingleQuotedLiteral -Text $ticketIdEffective
$taskNameEscaped = Convert-ToSingleQuotedLiteral -Text $taskName
$startFileRelEscaped = Convert-ToSingleQuotedLiteral -Text $startFileRel
$queuePathRelEscaped = Convert-ToSingleQuotedLiteral -Text $queuePathRel
$logRelEscaped = Convert-ToSingleQuotedLiteral -Text $logRel
$useAhkArgument = if ($NoUseAhk.IsPresent) { '' } else { ' -UseAhk' }

$wrapperLines = New-Object 'System.Collections.Generic.List[string]'
[void]$wrapperLines.Add(('Set-Location -LiteralPath ''{0}''' -f $repoRootEscaped))
[void]$wrapperLines.Add('$ErrorActionPreference = ''Stop''')
[void]$wrapperLines.Add(('$ticketId = ''{0}''' -f $ticketIdEscaped))
[void]$wrapperLines.Add(('$taskName = ''{0}''' -f $taskNameEscaped))
[void]$wrapperLines.Add(('$logPath = ''{0}''' -f $logRelEscaped))
[void]$wrapperLines.Add('$dispatchExitCode = 0')
[void]$wrapperLines.Add('$started = (Get-Date).ToString(''yyyy-MM-dd HH:mm:ss'')')
[void]$wrapperLines.Add('"[SCHEDULED-DISPATCH] started=$started ticket=$ticketId" | Out-File -LiteralPath $logPath -Encoding utf8 -Append')
[void]$wrapperLines.Add('try {')
[void]$wrapperLines.Add(('    & powershell -NoProfile -ExecutionPolicy Bypass -File ''.\tools\test\dispatch_takeover_to_chat.ps1'' -TicketId $ticketId -TicketEvent ''{0}'' -StartFile ''{1}'' -QueuePath ''{2}''{3} *>&1 | Out-File -LiteralPath $logPath -Encoding utf8 -Append' -f $ticketEventEscaped, $startFileRelEscaped, $queuePathRelEscaped, $useAhkArgument))
[void]$wrapperLines.Add('    $dispatchExitCode = $LASTEXITCODE')
[void]$wrapperLines.Add('}')
[void]$wrapperLines.Add('catch {')
[void]$wrapperLines.Add('    $dispatchExitCode = if ($LASTEXITCODE -is [int]) { [int]$LASTEXITCODE } else { 1 }')
[void]$wrapperLines.Add('    $errorDetail = [regex]::Replace(([string]$_.Exception.Message), ''\s+'', '' '').Trim()')
[void]$wrapperLines.Add('    "[SCHEDULED-DISPATCH] error ticket=$ticketId detail=$errorDetail" | Out-File -LiteralPath $logPath -Encoding utf8 -Append')
[void]$wrapperLines.Add('}')
[void]$wrapperLines.Add('finally {')
[void]$wrapperLines.Add('    $finished = (Get-Date).ToString(''yyyy-MM-dd HH:mm:ss'')')
[void]$wrapperLines.Add('    "[SCHEDULED-DISPATCH] finished=$finished ticket=$ticketId exit_code=$dispatchExitCode" | Out-File -LiteralPath $logPath -Encoding utf8 -Append')
[void]$wrapperLines.Add('    try { Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch { Write-Verbose ("Suppressed exception: {0}" -f $_.Exception.Message) }')
[void]$wrapperLines.Add('    try { schtasks /Delete /TN $taskName /F 1>$null 2>$null } catch { Write-Verbose ("Suppressed exception: {0}" -f $_.Exception.Message) }')
[void]$wrapperLines.Add('}')

$normalizedWrapperLines = @($wrapperLines | ForEach-Object { [string]$_ })
$wrapperText = [string]::Join("`n", $normalizedWrapperLines)
if ($normalizedWrapperLines.Count -gt 0) {
    $wrapperText += "`n"
}
[System.IO.File]::WriteAllText($scriptAbs, $wrapperText, [System.Text.UTF8Encoding]::new($false))

$scheduledRunAt = $desiredRunAt
$registerMode = 'plan-only'
$registrationOutput = ''

if (-not $PlanOnly.IsPresent) {
    try {
        $actionArgs = ('-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}"' -f $scriptAbs)
        $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $actionArgs
        $trigger = New-ScheduledTaskTrigger -Once -At $desiredRunAt
        $principalUser = if ([string]::IsNullOrWhiteSpace($env:USERDOMAIN)) { $env:USERNAME } else { ('{0}\\{1}' -f $env:USERDOMAIN, $env:USERNAME) }
        $principal = New-ScheduledTaskPrincipal -UserId $principalUser -LogonType InteractiveToken -RunLevel LeastPrivilege
        $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 10)

        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
        $registerMode = 'register-scheduledtask'
    }
    catch {
        $registerMode = 'schtasks-fallback'
        $scheduledRunAt = Get-CeilingMinute -Time $desiredRunAt
        $sd = $scheduledRunAt.ToString('yyyy/MM/dd')
        $st = $scheduledRunAt.ToString('HH:mm')
        $taskRunCommand = ('powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}"' -f $scriptAbs)
        $registrationOutput = schtasks /Create /TN $taskName /SC ONCE /SD $sd /ST $st /TR $taskRunCommand /RL LIMITED /IT /F 2>&1 | Out-String
        if ($LASTEXITCODE -ne 0) {
            throw ('Failed to register scheduled task via schtasks. output={0}' -f (Convert-ToSingleLineText -Text $registrationOutput))
        }
    }

    $statePayload = [ordered]@{
        schema = 'AB_CHAT_DELAY_STATE_V1'
        updated_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        task_name = $taskName
        ticket_id = $ticketIdEffective
        scheduled_for = $scheduledRunAt.ToString('yyyy-MM-dd HH:mm:ss')
        register_mode = $registerMode
        script_path = $scriptRel
        log_path = $logRel
        start_file = $startFileRel
        queue_path = $queuePathRel
        ticket_event = $TicketEvent
        delay_seconds = $DelaySeconds
    }

    $stateJson = ($statePayload | ConvertTo-Json -Depth 8) -replace "`r`n", "`n"
    [System.IO.File]::WriteAllText($statePath, $stateJson, [System.Text.UTF8Encoding]::new($false))
}

$result = [ordered]@{
    schema = 'AB_DELAYED_CHAT_DISPATCH_PLAN_V1'
    generated_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    now = $now.ToString('yyyy-MM-dd HH:mm:ss')
    plan_only = $PlanOnly.IsPresent
    delay_seconds = $DelaySeconds
    desired_run_at = $desiredRunAt.ToString('yyyy-MM-dd HH:mm:ss')
    scheduled_run_at = $scheduledRunAt.ToString('yyyy-MM-dd HH:mm:ss')
    register_mode = $registerMode
    task_name = $taskName
    ticket_id = $ticketIdEffective
    ticket_event = $TicketEvent
    start_file = $startFileRel
    queue_path = $queuePathRel
    script_path = $scriptRel
    log_path = $logRel
    next_run_time = if ($PlanOnly.IsPresent) { '' } else { Get-TaskNextRunTimeText -TaskName $taskName }
    cleanup = $cleanupSummary
    registration_output = Convert-ToSingleLineText -Text $registrationOutput
}

$result | ConvertTo-Json -Depth 8
