param(
    [Parameter(Mandatory = $true)][string]$StartFile,
    [Parameter(Mandatory = $true)][string]$TicketId,
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

function Read-JsonLinesSafely {
    param([string]$Path)

    $items = New-Object 'System.Collections.Generic.List[object]'
    throw 'ticket id must not be empty'
}

$queuePathRaw = ConvertTo-PathLikeValue -Value $QueuePath
if ([string]::IsNullOrWhiteSpace($queuePathRaw)) {
    $queuePathRaw = 'out/artifacts/ab_agent_queue/agent_tickets.jsonl'
}
$queueFilePath = Resolve-RepoPathAllowMissing -Path $queuePathRaw
if ([string]::IsNullOrWhiteSpace($queueFilePath) -or -not (Test-Path -LiteralPath $queueFilePath)) {
    throw ('queue file not found: {0}' -f $queuePathRaw)
}
$queueRel = Convert-ToRepoRelativePath -Path $queueFilePath

$tickets = Read-JsonLinesSafely -Path $queueFilePath
$ticketCandidates = New-Object 'System.Collections.Generic.List[object]'
foreach ($item in @($tickets)) {
    $candidateId = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $item -Name 'ticket_id')
    if ($candidateId -ne $ticketToken) {
        continue
    }

    $candidateStartFile = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $item -Name 'start_file')
    if (-not [string]::IsNullOrWhiteSpace($candidateStartFile)) {
        $candidateStartPath = Resolve-RepoPathAllowMissing -Path $candidateStartFile
        $candidateStartRel = Convert-ToRepoRelativePath -Path $candidateStartPath
        if (-not [string]::IsNullOrWhiteSpace($startFileRel) -and -not [string]::IsNullOrWhiteSpace($candidateStartRel)) {
            if (-not $candidateStartRel.Equals($startFileRel, [System.StringComparison]::OrdinalIgnoreCase)) {
                continue
            }
        }
    }

    [void]$ticketCandidates.Add($item)
}

if ($ticketCandidates.Count -eq 0) {
    throw ('ticket not found in queue for start-file scope: {0}' -f $ticketToken)
}

$selectedTicket = $null
$selectedTicketAt = $null
foreach ($item in @($ticketCandidates.ToArray())) {
    $candidateAt = Get-TicketTimeValue -Value (Get-ObjectPropertyString -InputObject $item -Name 'created_at')
    if ($null -eq $selectedTicket) {
        $selectedTicket = $item
        $selectedTicketAt = $candidateAt
        continue
    }

    if ($null -ne $candidateAt -and ($null -eq $selectedTicketAt -or $candidateAt -gt $selectedTicketAt)) {
        $selectedTicket = $item
        $selectedTicketAt = $candidateAt
    }
}

$takeoverDir = Resolve-RepoPathAllowMissing -Path 'out/artifacts/ab_agent_queue/takeover_requests'
if ([string]::IsNullOrWhiteSpace($takeoverDir) -or -not (Test-Path -LiteralPath $takeoverDir)) {
    throw ('takeover request directory not found: {0}' -f 'out/artifacts/ab_agent_queue/takeover_requests')
}

$briefCandidates = @(Get-ChildItem -LiteralPath $takeoverDir -Filter ('takeover_{0}_*.md' -f $ticketToken) -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)
if ($briefCandidates.Count -eq 0) {
    $briefCandidates = @(Get-ChildItem -LiteralPath $takeoverDir -Filter ('*{0}*.md' -f $ticketToken) -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)
}
if ($briefCandidates.Count -eq 0) {
    throw ('takeover brief not found for ticket: {0}' -f $ticketToken)
}

$briefPath = $briefCandidates[0].FullName
$briefRel = Convert-ToRepoRelativePath -Path $briefPath

$guardScript = Resolve-RepoPathAllowMissing -Path 'tools/test/check_takeover_route_guard.ps1'
if ([string]::IsNullOrWhiteSpace($guardScript) -or -not (Test-Path -LiteralPath $guardScript)) {
    throw ('route guard script not found: {0}' -f 'tools/test/check_takeover_route_guard.ps1')
}

$guardRaw = & $guardScript -BriefPath $briefRel -QueuePath $queueRel -AsJson
$guardJson = (($guardRaw | Out-String).Trim())
if ([string]::IsNullOrWhiteSpace($guardJson)) {
    throw 'route guard returned empty output'
}

$guard = $guardJson | ConvertFrom-Json
$guard | Add-Member -NotePropertyName 'brief_resolution' -NotePropertyValue ([ordered]@{
        ticket_id = $ticketToken
        selected_ticket_created_at = if ($null -eq $selectedTicketAt) { '' } else { $selectedTicketAt.ToString('yyyy-MM-dd HH:mm:ss') }
        start_file = $startFileRel
        queue_path = $queueRel
        brief_path = $briefRel
    }) -Force

if ($AsJson.IsPresent) {
    $guard | ConvertTo-Json -Depth 12
}
else {
    $classification = Convert-ToSingleLineText -Text ([string](Get-ObjectPropertyString -InputObject $guard.route -Name 'classification'))
    $recommendedAction = Convert-ToSingleLineText -Text ([string](Get-ObjectPropertyString -InputObject $guard.route -Name 'recommended_action'))
    $allowedActions = @()
    if ($null -ne $guard.route -and $guard.route.PSObject.Properties['allowed_actions']) {
        foreach ($action in @($guard.route.allowed_actions)) {
            $normalizedAction = Convert-ToSingleLineText -Text ([string]$action)
            if (-not [string]::IsNullOrWhiteSpace($normalizedAction)) {
                $allowedActions += $normalizedAction
            }
        }
    }

    Write-Output ('[AB-ROUTE-GUARD-BY-TICKET] ticket={0} class={1} action={2}' -f $ticketToken, $classification, $recommendedAction)
    Write-Output ('[AB-ROUTE-GUARD-BY-TICKET] brief={0}' -f $briefRel)
    Write-Output ('[AB-ROUTE-GUARD-BY-TICKET] allowed_actions={0}' -f (($allowedActions -join ',')))
}
