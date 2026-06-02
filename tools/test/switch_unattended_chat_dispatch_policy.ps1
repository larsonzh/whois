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

$script:RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path

function Resolve-RepoPath {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw 'Path must not be empty.'
    }

    $combined = if ([System.IO.Path]::IsPathRooted($Path)) { $Path } else { Join-Path $script:RepoRoot $Path }
    $fullPath = [System.IO.Path]::GetFullPath($combined)
    if (-not (Test-Path -LiteralPath $fullPath)) {
        throw "Path not found: $fullPath"
    }

    return $fullPath
}

function Convert-ToRepoRelativePath {
    param([AllowEmptyString()][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return ''
    }

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $repoRoot = [System.IO.Path]::GetFullPath($script:RepoRoot)
    if ($fullPath.StartsWith($repoRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $fullPath.Substring($repoRoot.Length).TrimStart('\\').Replace('\\', '/')
    }

    return $fullPath.Replace('\\', '/')
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

function Get-StartFileMutexName {
    param([string]$StartFilePath)

    $fullPath = [System.IO.Path]::GetFullPath($StartFilePath).ToLowerInvariant()
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($fullPath)
    $sha1 = [System.Security.Cryptography.SHA1]::Create()
    try {
        $hashBytes = $sha1.ComputeHash($bytes)
    }
    finally {
        $sha1.Dispose()
    }

    $hash = [System.BitConverter]::ToString($hashBytes).Replace('-', '')
    return "Local\whois-unattended-startfile-write-$hash"
}

function Read-KeyValueFile {
    param([string]$Path)

    $lines = @(Get-Content -LiteralPath $Path -Encoding utf8 -ErrorAction Stop)
    $keyLineMap = @{}
    $map = [ordered]@{}
    $lineNo = 0

    foreach ($line in $lines) {
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

function Invoke-KeyValueFileValueUpdate {
    param(
        [string]$Path,
        [System.Collections.IDictionary]$Values
    )

    $mutex = New-Object System.Threading.Mutex($false, (Get-StartFileMutexName -StartFilePath $Path))
    $locked = $false
    $tempPath = ''
    try {
        try {
            $locked = $mutex.WaitOne([TimeSpan]::FromSeconds(30))
        }
        catch [System.Threading.AbandonedMutexException] {
            $locked = $true
        }

        if (-not $locked) {
            throw "Failed to acquire start-file write lock within timeout: $Path"
        }

        $sourceLines = @()
        if (Test-Path -LiteralPath $Path) {
            $sourceLines = @(Get-Content -LiteralPath $Path -Encoding utf8 -ErrorAction Stop)
        }

        $seenKeys = @{}
        $lineNo = 0
        foreach ($line in $sourceLines) {
            $lineNo++
            if ($line -match '^([^=]+)=(.*)$') {
                $key = $Matches[1].Trim()
                if ($seenKeys.ContainsKey($key)) {
                    throw ("Duplicate key '{0}' detected in {1} at line {2} and line {3}." -f $key, $Path, [int]$seenKeys[$key], $lineNo)
                }

                $seenKeys[$key] = $lineNo
            }
        }

        $buffer = New-Object 'System.Collections.Generic.List[string]'
        foreach ($line in $sourceLines) {
            [void]$buffer.Add([string]$line)
        }

        foreach ($key in $Values.Keys) {
            $prefix = "$key="
            $found = $false
            for ($index = 0; $index -lt $buffer.Count; $index++) {
                if ($buffer[$index].StartsWith($prefix, [System.StringComparison]::Ordinal)) {
                    $buffer[$index] = $prefix + [string]$Values[$key]
                    $found = $true
                    break
                }
            }

            if (-not $found) {
                [void]$buffer.Add($prefix + [string]$Values[$key])
            }
        }

        $tempPath = "$Path.tmp.$PID.$([guid]::NewGuid().ToString('N'))"
        Set-Content -LiteralPath $tempPath -Value @($buffer) -Encoding utf8 -ErrorAction Stop
        Move-Item -LiteralPath $tempPath -Destination $Path -Force
        $tempPath = ''
    }
    finally {
        if (-not [string]::IsNullOrWhiteSpace($tempPath) -and (Test-Path -LiteralPath $tempPath)) {
            Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue
        }

        if ($locked) {
            try { $mutex.ReleaseMutex() } catch { Write-Verbose ("Suppressed exception: {0}" -f $_.Exception.Message) }
        }
        $mutex.Dispose()
    }
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
    Invoke-KeyValueFileValueUpdate -Path $startFilePath -Values $finalUpdates
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
