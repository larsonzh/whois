param(
    [Parameter(Mandatory = $true)][string]$StartFile,
    [AllowEmptyString()][string]$WorkMode = '',
    [AllowEmptyString()][string]$DeliveryPrimary = '',
    [AllowEmptyString()][string]$DeliveryFallback = '',
    [AllowEmptyString()][string]$ClearInputOnFailure = '',
    [AllowEmptyString()][string]$FinalStopGate = '',
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'unattended_exit_result.ps1')
. (Join-Path $PSScriptRoot 'unattended_startfile_identity.ps1')
$script:UnhandledExitTag = 'SWITCH-UNATTENDED-CHAT-DISPATCH-POLICY'

trap {
    $exitCode = Get-UnattendedExitCodeFromRecord -Tag $script:UnhandledExitTag -Record $_ -DefaultExitCode 1
    Write-UnattendedUnhandledResult -Tag $script:UnhandledExitTag -Record $_ -ExitCode $exitCode
    exit $exitCode
}

function Convert-ToSingleLineText {
    param([AllowEmptyString()][string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return ''
    }

    $singleLine = (($Text -split "`r?`n") -join ' ')
    return ([regex]::Replace($singleLine, '\s+', ' ')).Trim()
}

function Get-DisplayValue {
    param([AllowEmptyString()][string]$Value)

    $text = Convert-ToSingleLineText -Text $Value
    if ([string]::IsNullOrWhiteSpace($text)) {
        return '<empty>'
    }

    return $text
}

function Get-SettingClone {
    param([System.Collections.IDictionary]$Settings)

    $clone = [ordered]@{}
    if ($null -eq $Settings) {
        return $clone
    }

    foreach ($key in $Settings.Keys) {
        $clone[[string]$key] = [string]$Settings[$key]
    }

    return $clone
}

$compilerPath = Join-Path $PSScriptRoot 'chat_dispatch_policy_compiler.ps1'
if (-not (Test-Path -LiteralPath $compilerPath)) {
    throw "Policy compiler not found: $compilerPath"
}

. $compilerPath

$startFilePath = Resolve-RepoPath -Path $StartFile
$startFileRel = Convert-ToRepoRelativePath -Path $startFilePath
$settings = Read-KeyValueFile -Path $startFilePath

$sourceUpdates = [ordered]@{}
if (-not [string]::IsNullOrWhiteSpace($WorkMode)) {
    $sourceUpdates['AI_CHAT_POLICY_WORK_MODE'] = (Convert-ToSingleLineText -Text $WorkMode)
}
if (-not [string]::IsNullOrWhiteSpace($DeliveryPrimary)) {
    $sourceUpdates['AI_CHAT_POLICY_DELIVERY_PRIMARY'] = (Convert-ToSingleLineText -Text $DeliveryPrimary)
}
if (-not [string]::IsNullOrWhiteSpace($DeliveryFallback)) {
    $sourceUpdates['AI_CHAT_POLICY_DELIVERY_FALLBACK'] = (Convert-ToSingleLineText -Text $DeliveryFallback)
}
if (-not [string]::IsNullOrWhiteSpace($ClearInputOnFailure)) {
    $clearToggleToken = (Convert-ToSingleLineText -Text $ClearInputOnFailure).ToLowerInvariant()
    $clearToggleValue = switch ($clearToggleToken) {
        'on' { 'true' }
        'off' { 'false' }
        'true' { 'true' }
        'false' { 'false' }
        '1' { 'true' }
        '0' { 'false' }
        'enabled' { 'true' }
        'disabled' { 'false' }
        default { '' }
    }

    if ([string]::IsNullOrWhiteSpace($clearToggleValue)) {
        throw "Invalid -ClearInputOnFailure value '$ClearInputOnFailure'. Allowed: on/off/true/false/1/0/enabled/disabled."
    }

    $sourceUpdates['AI_CHAT_DISPATCH_CLEAR_INPUT_ON_FAILURE'] = $clearToggleValue
}
if (-not [string]::IsNullOrWhiteSpace($FinalStopGate)) {
    $sourceUpdates['AI_CHAT_POLICY_FINAL_STOP_GATE'] = (Convert-ToSingleLineText -Text $FinalStopGate)
}

$workingSettings = Get-SettingClone -Settings $settings
$sourceChanges = New-Object 'System.Collections.Generic.List[string]'
foreach ($key in $sourceUpdates.Keys) {
    $oldValue = if ($workingSettings.Contains($key)) { [string]$workingSettings[$key] } else { '' }
    $newValue = [string]$sourceUpdates[$key]
    if ((Convert-ToSingleLineText -Text $oldValue) -eq (Convert-ToSingleLineText -Text $newValue)) {
        continue
    }

    $workingSettings[$key] = $newValue
    [void]$sourceChanges.Add(('{0}:{1}->{2}' -f $key, (Get-DisplayValue -Value $oldValue), (Get-DisplayValue -Value $newValue)))
}

$defaultTriggerCommand = 'powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/dispatch_takeover_to_chat.ps1 -TicketId "%TICKET_ID%" -TicketEvent "%EVENT%" -StartFile "%START_FILE%" -QueuePath "%QUEUE_PATH%" -BriefPath "%BRIEF_PATH%" -NoOpenEditor -SkipClipboard'
$policyPlan = Get-ChatDispatchPolicyPlan -Settings $workingSettings -DefaultTriggerCommand $defaultTriggerCommand

$compiledUpdates = [ordered]@{}
$compiledChanges = @()
$resolvedPolicy = $null
if ($null -ne $policyPlan) {
    if ($null -ne $policyPlan.Updates) {
        foreach ($key in $policyPlan.Updates.Keys) {
            $compiledUpdates[[string]$key] = [string]$policyPlan.Updates[$key]
        }
    }

    $compiledChanges = @($policyPlan.Changes)
    $resolvedPolicy = $policyPlan.ResolvedPolicy
}

$finalUpdates = [ordered]@{}
foreach ($key in $sourceUpdates.Keys) {
    $finalUpdates[$key] = [string]$sourceUpdates[$key]
}
foreach ($key in $compiledUpdates.Keys) {
    $finalUpdates[$key] = [string]$compiledUpdates[$key]
}

$resolvedWorkMode = if ($null -ne $resolvedPolicy) { [string]$resolvedPolicy.work_mode } else { '' }
$resolvedPrimary = if ($null -ne $resolvedPolicy) { [string]$resolvedPolicy.delivery_primary } else { '' }
$resolvedFallback = if ($null -ne $resolvedPolicy) { [string]$resolvedPolicy.delivery_fallback } else { '' }
$resolvedFinalGate = if ($null -ne $resolvedPolicy) { [string]$resolvedPolicy.final_stop_gate } else { '' }

if ($DryRun.IsPresent) {
    Write-Output ('[CHAT-POLICY-HOTSWITCH] status=preview start_file={0} source_updates={1} compiled_updates={2} final_updates={3} work_mode={4} primary={5} fallback={6} final_stop_gate={7} apply_scope=running_or_idle effect_dispatch=next-ticket effect_trigger=next-poll' -f $startFileRel, $sourceUpdates.Count, $compiledUpdates.Count, $finalUpdates.Count, $resolvedWorkMode, $resolvedPrimary, $resolvedFallback, $resolvedFinalGate)
    if ($sourceChanges.Count -gt 0) {
        Write-Output ('[CHAT-POLICY-HOTSWITCH] source_changes={0}' -f (($sourceChanges.ToArray()) -join ','))
    }
    else {
        Write-Output '[CHAT-POLICY-HOTSWITCH] source_changes=<none>'
    }

    if ($compiledChanges.Count -gt 0) {
        Write-Output ('[CHAT-POLICY-HOTSWITCH] compiled_changes={0}' -f ($compiledChanges -join ','))
    }
    else {
        Write-Output '[CHAT-POLICY-HOTSWITCH] compiled_changes=<none>'
    }

    exit 0
}

if ($finalUpdates.Count -gt 0) {
    Invoke-KeyValueFileValueUpdateCore -Path $startFilePath -Values $finalUpdates -CommitMode Move
}

$finalSettings = Read-KeyValueFile -Path $startFilePath
$finalPlan = Get-ChatDispatchPolicyPlan -Settings $finalSettings -DefaultTriggerCommand $defaultTriggerCommand
$finalResolved = if ($null -ne $finalPlan) { $finalPlan.ResolvedPolicy } else { $null }

$finalWorkMode = if ($null -ne $finalResolved) { [string]$finalResolved.work_mode } else { '' }
$finalPrimary = if ($null -ne $finalResolved) { [string]$finalResolved.delivery_primary } else { '' }
$finalFallback = if ($null -ne $finalResolved) { [string]$finalResolved.delivery_fallback } else { '' }
$finalFinalGate = if ($null -ne $finalResolved) { [string]$finalResolved.final_stop_gate } else { '' }

Write-Output ('[CHAT-POLICY-HOTSWITCH] status=applied start_file={0} source_updates={1} compiled_updates={2} final_updates={3} work_mode={4} primary={5} fallback={6} final_stop_gate={7} apply_scope=running_or_idle effect_dispatch=next-ticket effect_trigger=next-poll' -f $startFileRel, $sourceUpdates.Count, $compiledUpdates.Count, $finalUpdates.Count, $finalWorkMode, $finalPrimary, $finalFallback, $finalFinalGate)
if ($sourceChanges.Count -gt 0) {
    Write-Output ('[CHAT-POLICY-HOTSWITCH] source_changes={0}' -f (($sourceChanges.ToArray()) -join ','))
}
else {
    Write-Output '[CHAT-POLICY-HOTSWITCH] source_changes=<none>'
}

if ($compiledChanges.Count -gt 0) {
    Write-Output ('[CHAT-POLICY-HOTSWITCH] compiled_changes={0}' -f ($compiledChanges -join ','))
}
else {
    Write-Output '[CHAT-POLICY-HOTSWITCH] compiled_changes=<none>'
}
