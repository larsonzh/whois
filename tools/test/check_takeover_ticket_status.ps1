param(
    [AllowEmptyString()][string]$StartFile = 'tmp\unattended_ab_start_20260425-0500.md',
    [ValidateRange(1, 50)][int]$Last = 8,
    [AllowEmptyString()][string]$TicketId = '',
    [AllowEmptyString()][string]$QueuePath = '',
    [switch]$AsJson
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

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

function Get-SafeToken {
    param([AllowEmptyString()][string]$Text)

    $normalized = Convert-ToSingleLineText -Text $Text
    if ([string]::IsNullOrWhiteSpace($normalized)) {
        return 'default'
    }

    return ([regex]::Replace($normalized, '[^A-Za-z0-9._-]', '_')).Trim('_')
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

function Get-LastMatchingLine {
    param(
        [string]$Path,
        [string]$Pattern
    )

    if ([string]::IsNullOrWhiteSpace($Path) -or [string]::IsNullOrWhiteSpace($Pattern) -or -not (Test-Path -LiteralPath $Path)) {
        return $null
    }

    return (Select-String -Path $Path -SimpleMatch -Pattern $Pattern -ErrorAction SilentlyContinue | Select-Object -Last 1)
}

function Get-Verdict {
    param(
        [bool]$InQueue,
        [bool]$Dispatched,
        [bool]$RelayCreated,
        [bool]$RelayExists
    )

    if ($InQueue -and $Dispatched -and $RelayCreated -and $RelayExists) {
        return 'RECEIVED_AND_EXECUTED'
    }
    if ($InQueue -and $Dispatched -and $RelayCreated -and -not $RelayExists) {
        return 'RELAY_LOGGED_FILE_MISSING'
    }
    if ($InQueue -and $Dispatched -and -not $RelayCreated) {
        return 'DISPATCHED_NO_RELAY_LOG'
    }
    if ($InQueue -and -not $Dispatched) {
        return 'QUEUED_NOT_DISPATCHED'
    }
    return 'NOT_FOUND'
}

$script:RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path

$startFilePath = Resolve-RepoPathAllowMissing -Path $StartFile
$startToken = Get-SafeToken -Text ([System.IO.Path]::GetFileNameWithoutExtension($startFilePath).ToLowerInvariant())

$queuePathValue = $QueuePath
if ([string]::IsNullOrWhiteSpace($queuePathValue)) {
    $queuePathValue = 'out\artifacts\ab_agent_queue\agent_tickets.jsonl'
}
$queueFilePath = Resolve-RepoPathAllowMissing -Path $queuePathValue

$triggerLogPath = Resolve-RepoPathAllowMissing -Path (Join-Path 'out\artifacts\ab_agent_queue' ("takeover_trigger_{0}.log" -f $startToken))
$dispatchRoot = Resolve-RepoPathAllowMissing -Path 'out\artifacts\ab_agent_queue\chat_dispatch'
$dispatchLogPath = Resolve-RepoPathAllowMissing -Path (Join-Path $dispatchRoot ("dispatch_{0}.log" -f $startToken))
$latestRelayStatePath = Resolve-RepoPathAllowMissing -Path (Join-Path $dispatchRoot ("latest_relay_{0}.json" -f $startToken))

$queueTickets = @()
if (Test-Path -LiteralPath $queueFilePath) {
    $queueTickets = @(Get-Content -LiteralPath $queueFilePath -Encoding utf8 -ErrorAction SilentlyContinue |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            ForEach-Object {
                try {
                    $_ | ConvertFrom-Json -ErrorAction Stop
                }
                catch {
                    $null
                }
            } |
            Where-Object { $null -ne $_ })
}

$targets = @()
if (-not [string]::IsNullOrWhiteSpace($TicketId)) {
    $targets = @($queueTickets | Where-Object { [string]$_.ticket_id -eq $TicketId })
    if ($targets.Count -eq 0) {
        $targets = @([pscustomobject]@{
                ticket_id = $TicketId
                event = ''
                created_at = ''
            })
    }
}
else {
    $targets = @($queueTickets | Select-Object -Last $Last)
}

$rows = New-Object 'System.Collections.Generic.List[object]'
foreach ($ticket in $targets) {
    $id = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $ticket -Name 'ticket_id')
    if ([string]::IsNullOrWhiteSpace($id)) {
        continue
    }

    $evt = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $ticket -Name 'event')
    $createdAt = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $ticket -Name 'created_at')

    $triggerDispatch = Get-LastMatchingLine -Path $triggerLogPath -Pattern ("ticket_dispatch id={0}" -f $id)
    $triggerExternal = Get-LastMatchingLine -Path $triggerLogPath -Pattern ("external_trigger_started id={0}" -f $id)
    $dispatchRelay = Get-LastMatchingLine -Path $dispatchLogPath -Pattern ("relay_created ticket={0}" -f $id)

    $relayFile = $null
    if (Test-Path -LiteralPath $dispatchRoot) {
        $relayFile = Get-ChildItem -LiteralPath $dispatchRoot -Filter ("relay_{0}_*.md" -f $id) -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending |
            Select-Object -First 1
    }

    $relayPathRel = if ($null -ne $relayFile) { Convert-ToRepoRelativePath -Path $relayFile.FullName } else { '' }
    $relayTime = if ($null -ne $relayFile) { $relayFile.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss') } else { '' }

    $inQueue = [bool]($queueTickets | Where-Object { (Get-ObjectPropertyString -InputObject $_ -Name 'ticket_id') -eq $id } | Select-Object -First 1)
    $triggerDispatched = ($null -ne $triggerDispatch)
    $relayLogged = ($null -ne $dispatchRelay)
    $relayExists = ($null -ne $relayFile)

    $verdict = Get-Verdict -InQueue $inQueue -Dispatched $triggerDispatched -RelayCreated $relayLogged -RelayExists $relayExists

    $rows.Add([pscustomobject]@{
            ticket_id = $id
            event = $evt
            created_at = $createdAt
            in_queue = $inQueue
            trigger_dispatched = $triggerDispatched
            trigger_external_started = ($null -ne $triggerExternal)
            dispatch_relay_logged = $relayLogged
            relay_exists = $relayExists
            relay_path = $relayPathRel
            relay_time = $relayTime
            verdict = $verdict
        }) | Out-Null
}

$latestRelayState = $null
if (Test-Path -LiteralPath $latestRelayStatePath) {
    try {
        $latestRelayState = Get-Content -LiteralPath $latestRelayStatePath -Raw -Encoding utf8 | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        $latestRelayState = $null
    }
}

$latestRelayStateOutput = $null
if ($null -ne $latestRelayState) {
    $latestRelayStateOutput = [ordered]@{
        ticket_id = [string]$latestRelayState.ticket_id
        event = [string]$latestRelayState.event
        relay_path = [string]$latestRelayState.relay_path
        updated_at = [string]$latestRelayState.updated_at
    }
}

$rowsOutput = $rows.ToArray()

$output = [ordered]@{
    schema = 'AB_TICKET_CHAIN_STATUS_V1'
    generated_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    start_file = (Convert-ToRepoRelativePath -Path $startFilePath)
    queue_path = (Convert-ToRepoRelativePath -Path $queueFilePath)
    trigger_log = (Convert-ToRepoRelativePath -Path $triggerLogPath)
    dispatch_log = (Convert-ToRepoRelativePath -Path $dispatchLogPath)
    latest_relay_state = $latestRelayStateOutput
    rows = $rowsOutput
}

if ($AsJson.IsPresent) {
    $output | ConvertTo-Json -Depth 8
}
else {
    Write-Output ("[AB-TICKET-STATUS] generated_at={0} start_file={1}" -f $output.generated_at, $output.start_file)
    Write-Output ("[AB-TICKET-STATUS] queue={0}" -f $output.queue_path)
    Write-Output ("[AB-TICKET-STATUS] trigger_log={0}" -f $output.trigger_log)
    Write-Output ("[AB-TICKET-STATUS] dispatch_log={0}" -f $output.dispatch_log)

    if ($null -ne $output.latest_relay_state) {
        Write-Output ("[AB-TICKET-STATUS] latest_relay ticket={0} event={1} relay={2} updated_at={3}" -f
            [string]$output.latest_relay_state.ticket_id,
            [string]$output.latest_relay_state.event,
            [string]$output.latest_relay_state.relay_path,
            [string]$output.latest_relay_state.updated_at)
    }

    if ($rows.Count -eq 0) {
        Write-Output '[AB-TICKET-STATUS] no_rows'
    }
    else {
        $rows | Select-Object ticket_id, event, in_queue, trigger_dispatched, dispatch_relay_logged, relay_exists, verdict, relay_time |
            Format-Table -AutoSize | Out-String | Write-Output
    }
}
