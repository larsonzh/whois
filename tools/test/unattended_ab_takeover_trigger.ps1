param(
    [Parameter(Mandatory = $true)][string]$StartFile,
    [ValidateRange(5, 300)][int]$PollSec = 30,
    [switch]$Once,
    [AllowEmptyString()][string]$QueuePath = '',
    [AllowEmptyString()][string]$TriggerCommand = '',
    [switch]$ExecuteTriggerCommand,
    [ValidateRange(32, 4096)][int]$MaxProcessedIds = 800
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Resolve-RepoPath {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw 'Path must not be empty.'
    }

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return (Resolve-Path -LiteralPath $Path).Path
    }

    return (Resolve-Path -LiteralPath (Join-Path $script:RepoRoot $Path)).Path
}

function Resolve-RepoPathAllowMissing {
    param([AllowEmptyString()][string]$Path)

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

function Convert-ToBooleanSetting {
    param(
        [AllowEmptyString()][string]$Value,
        [bool]$Default = $false
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $Default
    }

    return $Value.Trim().ToLowerInvariant() -in @('1', 'true', 'yes', 'on')
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

function Get-LatestAnchorValueFromNotes {
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

function Get-SafeToken {
    param([string]$Text)

    $normalized = Convert-ToSingleLineText -Text $Text
    if ([string]::IsNullOrWhiteSpace($normalized)) {
        return 'default'
    }

    return ([regex]::Replace($normalized, '[^A-Za-z0-9._-]', '_')).Trim('_')
}

function Write-TriggerLog {
    param([string]$Message)

    $line = "[AB-TAKEOVER-TRIGGER] timestamp={0} {1}" -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'), (Convert-ToSingleLineText -Text $Message)
    Write-Host $line
    try {
        Add-Content -LiteralPath $script:TriggerLogPath -Value $line -Encoding utf8
    }
    catch {
        Write-Warning ("[AB-TAKEOVER-TRIGGER] log_write_failed path={0}" -f $script:TriggerLogPath)
    }
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

    $json = $Value | ConvertTo-Json -Depth 10
    Set-Content -LiteralPath $Path -Value $json -Encoding utf8
}

function Get-TicketsFromQueue {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) {
        return @()
    }

    $tickets = New-Object 'System.Collections.Generic.List[object]'
    $lineNo = 0
    foreach ($line in @(Get-Content -LiteralPath $Path -Encoding utf8 -ErrorAction SilentlyContinue)) {
        $lineNo++
        $jsonLine = Convert-ToSingleLineText -Text ([string]$line)
        if ([string]::IsNullOrWhiteSpace($jsonLine)) {
            continue
        }

        try {
            $ticket = $jsonLine | ConvertFrom-Json -ErrorAction Stop
            [void]$tickets.Add($ticket)
        }
        catch {
            Write-TriggerLog ("queue_parse_skip line={0} detail={1}" -f $lineNo, (Convert-ToSingleLineText -Text $_.Exception.Message))
        }
    }

    return $tickets.ToArray()
}

function Expand-CommandTemplate {
    param(
        [string]$Template,
        [string]$TicketId,
        [string]$EventName,
        [string]$StartFilePath,
        [string]$QueueFilePath,
        [string]$BriefPath
    )

    $expanded = [string]$Template
    $expanded = $expanded.Replace('%TICKET_ID%', $TicketId)
    $expanded = $expanded.Replace('%EVENT%', $EventName)
    $expanded = $expanded.Replace('%START_FILE%', $StartFilePath)
    $expanded = $expanded.Replace('%QUEUE_PATH%', $QueueFilePath)
    $expanded = $expanded.Replace('%BRIEF_PATH%', $BriefPath)
    return $expanded
}

function Invoke-ExternalTriggerCommand {
    param([string]$CommandLine)

    if ([string]::IsNullOrWhiteSpace($CommandLine)) {
        return [pscustomobject]@{
            Started = $false
            ProcessId = 0
            Reason = 'command-empty'
        }
    }

    try {
        $process = Start-Process -FilePath 'cmd.exe' -ArgumentList @('/c', $CommandLine) -WindowStyle Hidden -PassThru
        return [pscustomobject]@{
            Started = $true
            ProcessId = [int]$process.Id
            Reason = 'started'
        }
    }
    catch {
        return [pscustomobject]@{
            Started = $false
            ProcessId = 0
            Reason = (Convert-ToSingleLineText -Text $_.Exception.Message)
        }
    }
}

function New-TakeoverBrief {
    param(
        [object]$Ticket,
        [System.Collections.IDictionary]$Settings,
        [string]$OutputRoot,
        [string]$QueueFilePath,
        [string]$StartFilePath
    )

    if (-not (Test-Path -LiteralPath $OutputRoot)) {
        New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null
    }

    $ticketId = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $Ticket -Name 'ticket_id')
    $eventName = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $Ticket -Name 'event')
    $fileName = ('takeover_{0}_{1}.md' -f (Get-SafeToken -Text $ticketId), (Get-Date).ToString('yyyyMMdd-HHmmss'))
    $briefPath = Join-Path $OutputRoot $fileName

    $notes = if ($Settings.Contains('SESSION_FINAL_NOTES')) { [string]$Settings.SESSION_FINAL_NOTES } else { '' }
    $runDir = Get-LatestAnchorValueFromNotes -Notes $notes -Key 'run_dir'
    $supervisorLog = Get-LatestAnchorValueFromNotes -Notes $notes -Key 'supervisor_log'
    $companionLog = Get-LatestAnchorValueFromNotes -Notes $notes -Key 'companion_log'
    $liveStatus = Get-LatestAnchorValueFromNotes -Notes $notes -Key 'live_status'

    $lines = @(
        '# AB Takeover Brief',
        '',
        ('generated_at={0}' -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')),
        ('ticket_id={0}' -f $ticketId),
        ('event={0}' -f $eventName),
        ('severity={0}' -f (Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $Ticket -Name 'severity'))),
        ('requires_confirmation={0}' -f (Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $Ticket -Name 'requires_confirmation'))),
        ('start_file={0}' -f (Convert-ToRepoRelativePath -Path $StartFilePath)),
        ('queue_path={0}' -f (Convert-ToRepoRelativePath -Path $QueueFilePath)),
        ('guard_state={0}' -f (Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $Ticket -Name 'guard_state'))),
        ('guard_log={0}' -f (Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $Ticket -Name 'guard_log'))),
        ('incident_dir={0}' -f (Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $Ticket -Name 'incident_dir'))),
        ('session_final_status={0}' -f (Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $Ticket -Name 'session_final_status'))),
        ('a_final_status={0}' -f (Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $Ticket -Name 'a_final_status'))),
        ('b_final_status={0}' -f (Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $Ticket -Name 'b_final_status'))),
        ('run_dir={0}' -f $runDir),
        ('supervisor_log={0}' -f $supervisorLog),
        ('companion_log={0}' -f $companionLog),
        ('live_status={0}' -f $liveStatus),
        ('detail={0}' -f (Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $Ticket -Name 'detail'))),
        ('recommended_action={0}' -f (Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $Ticket -Name 'recommended_action'))),
        '',
        'next_commands:',
        ('powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/open_unattended_ab_resume_window.ps1 -StartFile "{0}" -StartMonitors' -f (Convert-ToRepoRelativePath -Path $StartFilePath)),
        ('powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/open_unattended_ab_session_guard_window.ps1 -StartFile "{0}"' -f (Convert-ToRepoRelativePath -Path $StartFilePath))
    )

    Set-Content -LiteralPath $briefPath -Value $lines -Encoding utf8
    return $briefPath
}

$script:RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$startFilePath = Resolve-RepoPath -Path $StartFile
$startFileToken = Get-SafeToken -Text ([System.IO.Path]::GetFileNameWithoutExtension($startFilePath).ToLowerInvariant())

$queueRoot = Resolve-RepoPathAllowMissing -Path 'out\artifacts\ab_agent_queue'
if (-not (Test-Path -LiteralPath $queueRoot)) {
    New-Item -ItemType Directory -Path $queueRoot -Force | Out-Null
}

$script:TriggerLogPath = Join-Path $queueRoot ("takeover_trigger_{0}.log" -f $startFileToken)
$statePath = Join-Path $queueRoot ("takeover_trigger_state_{0}.json" -f $startFileToken)
$takeoverRoot = Join-Path $queueRoot 'takeover_requests'

$stateRaw = Read-JsonFileSafely -Path $statePath
$processedIds = New-Object 'System.Collections.Generic.List[string]'
$processedSet = @{}
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

Write-TriggerLog ("startup start_file={0} poll_sec={1} once={2} state={3}" -f (Convert-ToRepoRelativePath -Path $startFilePath), $PollSec, [bool]$Once.IsPresent, (Convert-ToRepoRelativePath -Path $statePath))

while ($true) {
    try {
        if (-not (Test-Path -LiteralPath $startFilePath)) {
            Write-TriggerLog ("stop reason=start-file-missing start_file={0}" -f (Convert-ToRepoRelativePath -Path $startFilePath))
            break
        }

        $settings = Read-KeyValueFile -Path $startFilePath

        $queueEnabled = $true
        if ($settings.Contains('LOCAL_GUARD_AGENT_QUEUE_ENABLED')) {
            $queueEnabled = Convert-ToBooleanSetting -Value ([string]$settings.LOCAL_GUARD_AGENT_QUEUE_ENABLED) -Default $true
        }

        $queuePathValue = $QueuePath
        if ([string]::IsNullOrWhiteSpace($queuePathValue)) {
            if ($settings.Contains('LOCAL_GUARD_AGENT_QUEUE_PATH')) {
                $queuePathValue = [string]$settings.LOCAL_GUARD_AGENT_QUEUE_PATH
            }
        }
        if ([string]::IsNullOrWhiteSpace($queuePathValue)) {
            $queuePathValue = 'out\artifacts\ab_agent_queue\agent_tickets.jsonl'
        }

        $queueFilePath = Resolve-RepoPathAllowMissing -Path $queuePathValue

        $triggerCommandValue = $TriggerCommand
        if ([string]::IsNullOrWhiteSpace($triggerCommandValue) -and $settings.Contains('EXTERNAL_TRIGGER_COMMAND')) {
            $triggerCommandValue = [string]$settings.EXTERNAL_TRIGGER_COMMAND
        }

        $executeCommand = $ExecuteTriggerCommand.IsPresent
        if (-not $executeCommand -and $settings.Contains('EXTERNAL_TRIGGER_EXECUTE')) {
            $executeCommand = Convert-ToBooleanSetting -Value ([string]$settings.EXTERNAL_TRIGGER_EXECUTE) -Default $false
        }

        if (-not $queueEnabled) {
            Write-TriggerLog 'queue_disabled action=skip'
            if ($Once.IsPresent) {
                break
            }
            Start-Sleep -Seconds $PollSec
            continue
        }

        $tickets = @(Get-TicketsFromQueue -Path $queueFilePath)
        $newCount = 0

        foreach ($ticket in $tickets) {
            $ticketId = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $ticket -Name 'ticket_id')
            if ([string]::IsNullOrWhiteSpace($ticketId)) {
                continue
            }

            if ($processedSet.Contains($ticketId)) {
                continue
            }

            $briefPath = New-TakeoverBrief -Ticket $ticket -Settings $settings -OutputRoot $takeoverRoot -QueueFilePath $queueFilePath -StartFilePath $startFilePath
            $briefRel = Convert-ToRepoRelativePath -Path $briefPath
            $eventName = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $ticket -Name 'event')

            Write-TriggerLog ("ticket_dispatch id={0} event={1} brief={2}" -f $ticketId, $eventName, $briefRel)

            if (-not [string]::IsNullOrWhiteSpace($triggerCommandValue)) {
                if ($executeCommand) {
                    $expandedCommand = Expand-CommandTemplate -Template $triggerCommandValue -TicketId $ticketId -EventName $eventName -StartFilePath $startFilePath -QueueFilePath $queueFilePath -BriefPath $briefPath
                    $commandResult = Invoke-ExternalTriggerCommand -CommandLine $expandedCommand
                    if ([bool]$commandResult.Started) {
                        Write-TriggerLog ("external_trigger_started id={0} pid={1}" -f $ticketId, [int]$commandResult.ProcessId)
                    }
                    else {
                        Write-TriggerLog ("external_trigger_failed id={0} detail={1}" -f $ticketId, [string]$commandResult.Reason)
                    }
                }
                else {
                    Write-TriggerLog ("external_trigger_skipped id={0} reason=execution-disabled" -f $ticketId)
                }
            }

            $processedSet[$ticketId] = $true
            [void]$processedIds.Add($ticketId)
            $newCount++
        }

        while ($processedIds.Count -gt $MaxProcessedIds) {
            $oldId = [string]$processedIds[0]
            $processedIds.RemoveAt(0)
            if ($processedSet.Contains($oldId)) {
                $processedSet.Remove($oldId) | Out-Null
            }
        }

        if ($newCount -gt 0 -or $null -eq $stateRaw) {
            $state = [ordered]@{
                schema = 'AB_TAKEOVER_TRIGGER_STATE_V1'
                updated_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
                start_file = (Convert-ToRepoRelativePath -Path $startFilePath)
                queue_path = (Convert-ToRepoRelativePath -Path $queueFilePath)
                processed_ids = @($processedIds)
            }
            Write-JsonFileSafely -Path $statePath -Value $state
            $stateRaw = $state
        }

        if ($Once.IsPresent) {
            break
        }
    }
    catch {
        $errorDetail = Convert-ToSingleLineText -Text $_.Exception.Message
        $errorType = if ($null -ne $_.Exception) { [string]$_.Exception.GetType().FullName } else { 'unknown' }
        $errorPos = Convert-ToSingleLineText -Text $_.InvocationInfo.PositionMessage
        Write-TriggerLog ("loop_error type={0} detail={1} pos={2}" -f $errorType, $errorDetail, $errorPos)
        if ($Once.IsPresent) {
            break
        }
    }

    Start-Sleep -Seconds $PollSec
}

Write-TriggerLog 'shutdown'
