param(
    [string]$StartFile = 'tmp\unattended_ab_start_20260422-2300.md',
    [string]$TemplateFile = 'docs\UNATTENDED_AB_START_TEMPLATE_CN.md',
    [AllowEmptyString()][string]$ResetFields = '',
    [switch]$UseDefaultResetFieldList,
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-Utf8Text {
    param([string]$Path)

    $encoding = New-Object System.Text.UTF8Encoding($true, $true)
    try {
        return [System.IO.File]::ReadAllText($Path, $encoding)
    }
    catch {
        throw "Failed to read UTF-8 text file: $Path; detail=$($_.Exception.Message)"
    }
}

function Test-Utf8TextReplacementChar {
    param(
        [string]$Text,
        [string]$Path,
        [string]$Tag
    )

    if ([string]::IsNullOrEmpty($Text)) {
        return
    }

    $replacement = [string][char]0xFFFD
    if ($Text.IndexOf($replacement, [System.StringComparison]::Ordinal) -lt 0) {
        return
    }

    $lineNumbers = New-Object 'System.Collections.Generic.List[string]'
    $lines = @($Text -split "`r?`n", -1)
    for ($index = 0; $index -lt $lines.Count; $index++) {
        if (([string]$lines[$index]).Contains($replacement)) {
            [void]$lineNumbers.Add([string]($index + 1))
        }
    }

    throw ("[{0}] detected replacement character (U+FFFD) in {1} at line(s): {2}. Please repair file encoding/content before proceeding." -f $Tag, $Path, ($lineNumbers -join ','))
}

function Resolve-RepoPath {
    param(
        [string]$RepoRoot,
        [string]$Path,
        [bool]$MustExist = $true
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw 'Path must not be empty.'
    }

    $combined = if ([System.IO.Path]::IsPathRooted($Path)) { $Path } else { Join-Path $RepoRoot $Path }
    $fullPath = [System.IO.Path]::GetFullPath($combined)

    if ($MustExist -and -not (Test-Path -LiteralPath $fullPath)) {
        throw "Path not found: $fullPath"
    }

    return $fullPath
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

function Get-TemplateBlock {
    param([string]$TemplatePath)

    $templateText = Get-Utf8Text -Path $TemplatePath
    Test-Utf8TextReplacementChar -Text $templateText -Path $TemplatePath -Tag 'RESET-START-FILE'

    $lines = @($templateText -split "`r?`n")
    if ($lines.Count -gt 0 -and $lines[$lines.Count - 1] -eq '') {
        if ($lines.Count -eq 1) {
            $lines = @()
        }
        else {
            $lines = @($lines[0..($lines.Count - 2)])
        }
    }

    $inFence = $false
    $block = New-Object 'System.Collections.Generic.List[string]'

    foreach ($line in $lines) {
        if ($line.Trim().StartsWith('```')) {
            if (-not $inFence) {
                $inFence = $true
                $block = New-Object 'System.Collections.Generic.List[string]'
                continue
            }

            $inFence = $false
            $candidate = @($block)
            $hasHeader = $candidate -contains 'AB_UNATTENDED_START_V1'
            $hasKeyValue = @($candidate | Where-Object { $_ -match '^[A-Z0-9_]+=.*$' }).Count -gt 10
            if ($hasHeader -and $hasKeyValue) {
                return $candidate
            }
            continue
        }

        if ($inFence) {
            [void]$block.Add([string]$line)
        }
    }

    throw "Unable to locate start-file template block in $TemplatePath"
}

function Convert-LinesToOrderedMap {
    param([string[]]$Lines)

    $orderedKeys = New-Object 'System.Collections.Generic.List[string]'
    $map = [ordered]@{}
    $keyLineMap = @{}
    $lineNo = 0

    foreach ($line in @($Lines)) {
        $lineNo++
        if ($line -match '^([A-Z0-9_]+)=(.*)$') {
            $key = $Matches[1]
            $value = $Matches[2]

            if ($map.Contains($key)) {
                $firstLine = [int]$keyLineMap[$key]
                throw ("Duplicate key '{0}' detected in template block at line {1} and line {2}." -f $key, $firstLine, $lineNo)
            }

            $keyLineMap[$key] = $lineNo
            [void]$orderedKeys.Add($key)
            $map[$key] = $value
        }
    }

    return [pscustomobject]@{
        OrderedKeys = @($orderedKeys)
        Map = $map
    }
}

function Get-StartFileState {
    param([string]$StartFilePath)

    $startText = Get-Utf8Text -Path $StartFilePath
    Test-Utf8TextReplacementChar -Text $startText -Path $StartFilePath -Tag 'RESET-START-FILE'

    $lines = @($startText -split "`r?`n")
    if ($lines.Count -gt 0 -and $lines[$lines.Count - 1] -eq '') {
        if ($lines.Count -eq 1) {
            $lines = @()
        }
        else {
            $lines = @($lines[0..($lines.Count - 2)])
        }
    }

    $lineIndex = @{}
    $orderedKeys = New-Object 'System.Collections.Generic.List[string]'
    $map = [ordered]@{}

    for ($index = 0; $index -lt $lines.Count; $index++) {
        $line = [string]$lines[$index]
        if ($line -match '^([A-Z0-9_]+)=(.*)$') {
            $key = $Matches[1]
            $value = $Matches[2]

            if ($lineIndex.ContainsKey($key)) {
                $firstLine = ([int]$lineIndex[$key]) + 1
                throw ("Duplicate key '{0}' detected in {1} at line {2} and line {3}." -f $key, $StartFilePath, $firstLine, ($index + 1))
            }

            $lineIndex[$key] = $index
            [void]$orderedKeys.Add($key)
            $map[$key] = $value
        }
    }

    return [pscustomobject]@{
        Lines = $lines
        KeyLineIndex = $lineIndex
        OrderedKeys = @($orderedKeys)
        Map = $map
    }
}

function Get-ResetSelectorSet {
    param([string]$RawSelectors)

    return @(
        $RawSelectors -split ';' |
            ForEach-Object { $_.Trim() } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    )
}

function Resolve-SelectorKeySet {
    param(
        [string[]]$Selectors,
        [string[]]$AvailableKeys
    )

    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($selector in @($Selectors)) {
        if ([string]::IsNullOrWhiteSpace($selector)) {
            continue
        }

        if ($selector.EndsWith('*')) {
            $prefix = $selector.Substring(0, $selector.Length - 1)
            foreach ($key in @($AvailableKeys)) {
                if ($key.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
                    [void]$set.Add($key)
                }
            }
            continue
        }

        foreach ($key in @($AvailableKeys)) {
            if ($key.Equals($selector, [System.StringComparison]::OrdinalIgnoreCase)) {
                [void]$set.Add($key)
            }
        }
    }

    $expanded = New-Object 'System.Collections.Generic.List[string]'
    foreach ($key in @($AvailableKeys)) {
        if ($set.Contains($key)) {
            [void]$expanded.Add($key)
        }
    }

    return @($expanded)
}

function Get-ResetValue {
    param(
        [string]$Key,
        [AllowEmptyString()][string]$CurrentValue,
        [System.Collections.IDictionary]$TemplateMap
    )

    switch -Regex ($Key) {
        '^PRECHECK_REQUIRED$' {
            if ($TemplateMap.Contains($Key)) {
                return [string]$TemplateMap[$Key]
            }
            return $CurrentValue
        }
        '^PRECHECK_OPERATOR$' { return $CurrentValue }
        '^PRECHECK_WORKSPACE_STATUS_DETAIL$' { return 'TO_BE_FILLED' }
        '^PRECHECK_(START_GATE|REMOTE_LOCK)$' { return 'NOT_RUN' }
        '^PRECHECK_(AT|START_BLOCKER|FAILURE_REASON|NOTES)$' { return '' }
        '^PRECHECK_' { return 'NOT_RUN' }
        '^NETWORK_PRECHECK_LAST_RESULT$' { return 'NOT_RUN' }
        '^NETWORK_PRECHECK_LAST_(AT|REASON)$' { return '' }
        '^(A_FINAL_STATUS|B_FINAL_STATUS|SESSION_FINAL_STATUS)$' { return 'NOT_RUN' }
        '^A_SUCCESS_SNAPSHOT_' { return '' }
        '^(SESSION_FINAL_NOTES|RESTART_EVIDENCE_NOTES|AI_SESSION_BLOCKING_WATCH_NOTES)$' { return '' }
    }

    if ($TemplateMap.Contains($Key)) {
        $templateValue = [string]$TemplateMap[$Key]
        if (-not [string]::IsNullOrWhiteSpace($templateValue) -and $templateValue -notmatch '^<.*>$') {
            return $templateValue
        }
    }

    if ($Key -match '(_STATUS|_RESULT)$') {
        return 'NOT_RUN'
    }

    if ($Key -match '(_AT|_NOTES|_REASON|_BLOCKER|_SUMMARY|_STATE)$') {
        return ''
    }

    return $CurrentValue
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$startFilePath = Resolve-RepoPath -RepoRoot $repoRoot -Path $StartFile -MustExist $true
$templatePath = Resolve-RepoPath -RepoRoot $repoRoot -Path $TemplateFile -MustExist $true

$defaultSelectorText = 'PRECHECK_*;NETWORK_PRECHECK_LAST_RESULT;NETWORK_PRECHECK_LAST_AT;NETWORK_PRECHECK_LAST_REASON;A_SUCCESS_SNAPSHOT_FINAL_STATUS;A_SUCCESS_SNAPSHOT_SUMMARY;A_SUCCESS_SNAPSHOT_SOURCE_STATE;A_FINAL_STATUS;B_FINAL_STATUS;SESSION_FINAL_STATUS;SESSION_FINAL_NOTES;AI_SESSION_BLOCKING_WATCH_NOTES;RESTART_EVIDENCE_NOTES;LOCAL_GUARD_WAIT_FOR_MANUAL_RESTART;LOCAL_GUARD_AUTO_RECOVER_B;LOCAL_GUARD_RESTART_REQUIRES_CONFIRM;LOCAL_GUARD_RESTART_APPROVED;LOCAL_GUARD_POLL_STATUS_REPORT_EVENTS;LOCAL_GUARD_POLL_DRAIN_SAFE_EVENTS;LOCAL_GUARD_POLL_BARRIER_EVENTS;LOCAL_GUARD_POLL_RESTART_SENSITIVE_EVENTS;EXTERNAL_TRIGGER_EXECUTE;EXTERNAL_TRIGGER_COMMAND'

$startState = Get-StartFileState -StartFilePath $startFilePath
$templateBlock = Get-TemplateBlock -TemplatePath $templatePath
$templateState = Convert-LinesToOrderedMap -Lines $templateBlock

$selectorText = ''
if (-not [string]::IsNullOrWhiteSpace($ResetFields)) {
    $selectorText = $ResetFields
}
elseif (-not $UseDefaultResetFieldList.IsPresent -and $startState.Map.Contains('RERUN_FROM_A_STARTFILE_RESET_FIELDS') -and -not [string]::IsNullOrWhiteSpace([string]$startState.Map.RERUN_FROM_A_STARTFILE_RESET_FIELDS)) {
    $selectorText = [string]$startState.Map.RERUN_FROM_A_STARTFILE_RESET_FIELDS
}
else {
    $selectorText = $defaultSelectorText
}

$selectors = Get-ResetSelectorSet -RawSelectors $selectorText
$alwaysSelectors = Get-ResetSelectorSet -RawSelectors $defaultSelectorText
$allSelectors = @($selectors + $alwaysSelectors)

$keysToReset = Resolve-SelectorKeySet -Selectors $allSelectors -AvailableKeys $startState.OrderedKeys
if ($keysToReset.Count -lt 1) {
    throw 'No fields matched reset selectors. Nothing to reset.'
}

$newLines = @($startState.Lines)
$changes = New-Object 'System.Collections.Generic.List[object]'
foreach ($key in @($keysToReset)) {
    $oldValue = if ($startState.Map.Contains($key)) { [string]$startState.Map[$key] } else { '' }
    $newValue = Get-ResetValue -Key $key -CurrentValue $oldValue -TemplateMap $templateState.Map

    if ($oldValue -ceq $newValue) {
        continue
    }

    if ($startState.KeyLineIndex.ContainsKey($key)) {
        $lineIndex = [int]$startState.KeyLineIndex[$key]
        $newLines[$lineIndex] = "$key=$newValue"
    }
    else {
        $newLines += "$key=$newValue"
    }

    [void]$changes.Add([pscustomobject]@{
        Key = $key
        OldValue = $oldValue
        NewValue = $newValue
    })
}

Write-Output ("[RESET-START-FILE] start_file={0}" -f $startFilePath)
Write-Output ("[RESET-START-FILE] template_file={0}" -f $templatePath)
Write-Output ("[RESET-START-FILE] selectors={0}" -f ($allSelectors -join ';'))
Write-Output ("[RESET-START-FILE] matched_keys={0}" -f $keysToReset.Count)
Write-Output ("[RESET-START-FILE] changed_keys={0}" -f $changes.Count)

foreach ($change in $changes) {
    Write-Output ("[RESET-START-FILE] change key={0} old='{1}' new='{2}'" -f $change.Key, $change.OldValue, $change.NewValue)
}

if ($DryRun.IsPresent) {
    Write-Output '[RESET-START-FILE] dry_run=true write_skipped=true'
    exit 0
}

Test-Utf8TextReplacementChar -Text ($newLines -join "`n") -Path $startFilePath -Tag 'RESET-START-FILE'
$mutex = New-Object System.Threading.Mutex($false, (Get-StartFileMutexName -StartFilePath $startFilePath))
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
        throw "Failed to acquire start-file write lock within timeout: $startFilePath"
    }

    $tempPath = "$startFilePath.tmp.$PID.$([guid]::NewGuid().ToString('N'))"
    Set-Content -LiteralPath $tempPath -Value $newLines -Encoding utf8 -ErrorAction Stop
    Move-Item -LiteralPath $tempPath -Destination $startFilePath -Force
    $tempPath = ''
}
finally {
    if (-not [string]::IsNullOrWhiteSpace($tempPath) -and (Test-Path -LiteralPath $tempPath)) {
        Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue
    }

    if ($locked) {
        try { $mutex.ReleaseMutex() } catch {}
    }
    $mutex.Dispose()
}
Write-Output '[RESET-START-FILE] dry_run=false write_applied=true'
