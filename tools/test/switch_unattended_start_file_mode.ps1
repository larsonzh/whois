param(
    [Parameter(Mandatory = $true)][string]$StartFile,
    [Parameter(Mandatory = $true)][ValidateSet('normal', 'anti-missent', 'low-disturb', 'event-only')][string]$Mode,
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
        return $fullPath.Substring($repoRoot.Length).TrimStart('\').Replace('\', '/')
    }

    return $fullPath.Replace('\', '/')
}

function Convert-ToSingleLineText {
    param([AllowEmptyString()][string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return ''
    }

    $singleLine = (($Text -split "`r?`n") -join ' ')
    return ([regex]::Replace($singleLine, '\s+', ' ')).Trim()
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
        $content = ($buffer.ToArray() -join "`n")
        $utf8Bom = New-Object System.Text.UTF8Encoding($true)
        [System.IO.File]::WriteAllText($tempPath, $content, $utf8Bom)
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

function Get-RequiredPolicyKeys {
    return @(
        'AI_CHAT_POLICY_WORK_MODE',
        'AI_CHAT_POLICY_DELIVERY_PRIMARY',
        'AI_CHAT_POLICY_DELIVERY_FALLBACK',
        'AI_CHAT_POLICY_FINAL_STOP_GATE',
        'AI_CHAT_POLICY_VERSION',
        'AI_CHAT_DISPATCH_ALLOW_RUNNING_STATUS_MESSAGE_OVERRIDE',
        'LOCAL_GUARD_STATUS_TICKET_ENABLED',
        'AI_CHAT_TRIGGER_DISPATCH_STATUS_REPORTS',
        'AI_CHAT_TRIGGER_SKIP_EXISTING_QUEUE_ON_START',
        'AI_CHAT_DISPATCH_STATUS_REPORT_INTERACTIVE',
        'AI_CHAT_DISPATCH_DELIVERY_PROFILE',
        'AI_CHAT_DISPATCH_ACTIVE_WINDOW_ONLY',
        'AI_CHAT_DISPATCH_STATUS_REPORT_MESSAGE_MODE',
        'AI_CHAT_DISPATCH_STATUS_REPORT_SEND_FULL_ON_FIRST',
        'AI_CHAT_DISPATCH_AHK_EVENT_ALLOWLIST',
        'AI_CHAT_DISPATCH_SENDER_PRIMARY',
        'AI_CHAT_DISPATCH_SENDER_FALLBACK_ENABLED',
        'AI_CHAT_TRIGGER_FINAL_STOP_GATE',
        'EXTERNAL_TRIGGER_EXECUTE',
        'AUTO_START_TAKEOVER_TRIGGER',
        'EXTERNAL_TRIGGER_COMMAND'
    )
}

function Get-MissingRequiredKeys {
    param([System.Collections.IDictionary]$Settings)

    $missing = New-Object 'System.Collections.Generic.List[string]'
    foreach ($key in @(Get-RequiredPolicyKeys)) {
        if ($null -eq $Settings -or -not $Settings.Contains($key)) {
            [void]$missing.Add($key)
            continue
        }

        $value = Convert-ToSingleLineText -Text ([string]$Settings[$key])
        if ([string]::IsNullOrWhiteSpace($value)) {
            [void]$missing.Add($key)
        }
    }

    return @($missing.ToArray())
}

$compilerPath = Join-Path $PSScriptRoot 'chat_dispatch_policy_compiler.ps1'
if (-not (Test-Path -LiteralPath $compilerPath)) {
    throw "Policy compiler not found: $compilerPath"
}
. $compilerPath

$startFilePath = Resolve-RepoPath -Path $StartFile
$startFileRel = Convert-ToRepoRelativePath -Path $startFilePath

$beforeSettings = Read-KeyValueFile -Path $startFilePath
$beforeMissing = @(Get-MissingRequiredKeys -Settings $beforeSettings)
$beforeModeRaw = if ($beforeSettings.Contains('AI_CHAT_POLICY_WORK_MODE')) { [string]$beforeSettings['AI_CHAT_POLICY_WORK_MODE'] } else { '' }
$beforeMode = Resolve-ChatPolicyWorkMode -RawValue $beforeModeRaw -DefaultValue 'normal'

$workingSettings = Get-SettingClone -Settings $beforeSettings
$workingSettings['AI_CHAT_POLICY_WORK_MODE'] = $Mode

$defaultTriggerCommand = 'powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/dispatch_takeover_to_chat.ps1 -TicketId "%TICKET_ID%" -TicketEvent "%EVENT%" -StartFile "%START_FILE%" -QueuePath "%QUEUE_PATH%" -BriefPath "%BRIEF_PATH%" -NoOpenEditor -SkipClipboard'
$policyPlan = Get-ChatDispatchPolicyPlan -Settings $workingSettings -DefaultTriggerCommand $defaultTriggerCommand
if ($null -eq $policyPlan) {
    throw 'Failed to build policy plan.'
}

$finalUpdates = [ordered]@{}
$finalUpdates['AI_CHAT_POLICY_WORK_MODE'] = $Mode
if ($null -ne $policyPlan.Updates) {
    foreach ($key in $policyPlan.Updates.Keys) {
        $finalUpdates[[string]$key] = [string]$policyPlan.Updates[$key]
    }
}

$predictedSettings = Get-SettingClone -Settings $beforeSettings
foreach ($key in $finalUpdates.Keys) {
    $predictedSettings[$key] = [string]$finalUpdates[$key]
}
$predictedMissing = @(Get-MissingRequiredKeys -Settings $predictedSettings)

$resolvedPolicy = $policyPlan.ResolvedPolicy
$predictedMode = if ($null -ne $resolvedPolicy) { [string]$resolvedPolicy.work_mode } else { '' }
if ([string]::IsNullOrWhiteSpace($predictedMode)) {
    $predictedMode = Resolve-ChatPolicyWorkMode -RawValue $Mode -DefaultValue 'normal'
}

if ($DryRun.IsPresent) {
    Write-Output ('[START-MODE-HOTSWITCH] status=preview start_file={0} before_mode={1} target_mode={2} predicted_mode={3} missing_before={4} missing_after={5} final_updates={6} effect_dispatch=next-ticket effect_trigger=next-poll' -f $startFileRel, $beforeMode, $Mode, $predictedMode, $beforeMissing.Count, $predictedMissing.Count, $finalUpdates.Count)
    if ($beforeMissing.Count -gt 0) {
        Write-Output ('[START-MODE-HOTSWITCH] missing_before_keys={0}' -f ($beforeMissing -join ';'))
    }
    else {
        Write-Output '[START-MODE-HOTSWITCH] missing_before_keys=<none>'
    }

    if ($predictedMissing.Count -gt 0) {
        Write-Output ('[START-MODE-HOTSWITCH] missing_after_keys={0}' -f ($predictedMissing -join ';'))
    }
    else {
        Write-Output '[START-MODE-HOTSWITCH] missing_after_keys=<none>'
    }

    exit 0
}

if ($finalUpdates.Count -gt 0) {
    Invoke-KeyValueFileValueUpdate -Path $startFilePath -Values $finalUpdates
}

$afterSettings = Read-KeyValueFile -Path $startFilePath
$afterMissing = @(Get-MissingRequiredKeys -Settings $afterSettings)
$afterPlan = Get-ChatDispatchPolicyPlan -Settings $afterSettings -DefaultTriggerCommand $defaultTriggerCommand
$afterResolved = if ($null -ne $afterPlan) { $afterPlan.ResolvedPolicy } else { $null }
$afterMode = if ($null -ne $afterResolved) { [string]$afterResolved.work_mode } else { '' }
if ([string]::IsNullOrWhiteSpace($afterMode)) {
    $afterModeRaw = if ($afterSettings.Contains('AI_CHAT_POLICY_WORK_MODE')) { [string]$afterSettings['AI_CHAT_POLICY_WORK_MODE'] } else { '' }
    $afterMode = Resolve-ChatPolicyWorkMode -RawValue $afterModeRaw -DefaultValue 'normal'
}

Write-Output ('[START-MODE-HOTSWITCH] status=applied start_file={0} before_mode={1} target_mode={2} final_mode={3} missing_before={4} missing_after={5} final_updates={6} effect_dispatch=next-ticket effect_trigger=next-poll' -f $startFileRel, $beforeMode, $Mode, $afterMode, $beforeMissing.Count, $afterMissing.Count, $finalUpdates.Count)
if ($beforeMissing.Count -gt 0) {
    Write-Output ('[START-MODE-HOTSWITCH] missing_before_keys={0}' -f ($beforeMissing -join ';'))
}
else {
    Write-Output '[START-MODE-HOTSWITCH] missing_before_keys=<none>'
}

if ($afterMissing.Count -gt 0) {
    Write-Output ('[START-MODE-HOTSWITCH] missing_after_keys={0}' -f ($afterMissing -join ';'))
}
else {
    Write-Output '[START-MODE-HOTSWITCH] missing_after_keys=<none>'
}
