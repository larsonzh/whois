param(
    [Parameter(Mandatory = $true)][string]$TaskDefinitionFile,
    [AllowEmptyString()][string]$RepoRoot = '',
    [ValidateSet('off', 'warn', 'enforce')][string]$Policy = 'enforce'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($Policy -eq 'off') {
    Write-Output '[TASK-STATIC-CHECK] policy=off action=skip'
    exit 0
}

if ([string]::IsNullOrWhiteSpace($RepoRoot)) {
    $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
}

$resolvedTaskDefinition = if ([System.IO.Path]::IsPathRooted($TaskDefinitionFile)) {
    (Resolve-Path -LiteralPath $TaskDefinitionFile).Path
}
else {
    (Resolve-Path -LiteralPath (Join-Path $RepoRoot $TaskDefinitionFile)).Path
}

if (-not (Test-Path -LiteralPath $resolvedTaskDefinition)) {
    throw "[TASK-STATIC-CHECK] task definition not found: $TaskDefinitionFile"
}

$errors = New-Object 'System.Collections.Generic.List[string]'
$warnings = New-Object 'System.Collections.Generic.List[string]'
$infos = New-Object 'System.Collections.Generic.List[string]'

function Add-ErrorIssue {
    param([string]$Message)
    [void]$errors.Add($Message)
}

function Add-WarnIssue {
    param([string]$Message)
    [void]$warnings.Add($Message)
}

function Add-InfoIssue {
    param([string]$Message)
    [void]$infos.Add($Message)
}

function Get-RoundTaskType {
    param([object]$RoundTask)

    if ($null -eq $RoundTask) {
        return 'builtin'
    }

    if ($RoundTask.PSObject.Properties.Name -contains 'type') {
        $candidate = [string]$RoundTask.type
        if (-not [string]::IsNullOrWhiteSpace($candidate)) {
            return $candidate.Trim().ToLowerInvariant()
        }
    }

    return 'builtin'
}

function Get-StringArray {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) {
        return @()
    }

    if ($Value -is [string]) {
        if ([string]::IsNullOrWhiteSpace($Value)) {
            return @()
        }

        return @($Value)
    }

    $items = @($Value)
    return @($items | ForEach-Object { [string]$_ } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
}

function Test-LikelyDoubleEscapedReplacement {
    param([AllowEmptyString()][string]$Replacement)

    if ([string]::IsNullOrEmpty($Replacement)) {
        return $false
    }

    $hasLiteralEscapedNewline = ($Replacement.Contains('\n') -or $Replacement.Contains('\r\n'))
    $hasLiteralEscapedTab = $Replacement.Contains('\t')
    $hasActualNewline = $Replacement.Contains("`n")
    $hasActualTab = $Replacement.Contains("`t")

    if ($hasLiteralEscapedNewline -and -not $hasActualNewline) {
        return $true
    }

    if ($hasLiteralEscapedTab -and -not $hasActualTab) {
        return $true
    }

    return $false
}

function Resolve-PrimaryTargetFile {
    param(
        [object]$TaskDefinition,
        [string]$TaskDefinitionPath
    )

    if ($null -eq $TaskDefinition) {
        throw "[TASK-STATIC-CHECK] task definition object is null: $TaskDefinitionPath"
    }

    if ($TaskDefinition.PSObject.Properties.Name -contains 'targetFile') {
        $targetFileRaw = [string]$TaskDefinition.targetFile
        if (-not [string]::IsNullOrWhiteSpace($targetFileRaw)) {
            return $targetFileRaw
        }
    }

    if (-not ($TaskDefinition.PSObject.Properties.Name -contains 'targetFiles')) {
        throw "[TASK-STATIC-CHECK] task definition missing targetFile/targetFiles: $TaskDefinitionPath"
    }

    $targetFiles = @($TaskDefinition.targetFiles)
    if ($targetFiles.Count -lt 1) {
        throw "[TASK-STATIC-CHECK] targetFiles is empty: $TaskDefinitionPath"
    }

    $defaultTarget = ''
    if ($TaskDefinition.PSObject.Properties.Name -contains 'defaultTarget') {
        $defaultTarget = [string]$TaskDefinition.defaultTarget
    }

    $selectedTarget = $null
    if (-not [string]::IsNullOrWhiteSpace($defaultTarget)) {
        foreach ($target in $targetFiles) {
            if ($null -eq $target) {
                continue
            }

            $targetId = ''
            if ($target.PSObject.Properties.Name -contains 'id') {
                $targetId = [string]$target.id
            }

            if ($targetId.Trim().ToLowerInvariant() -eq $defaultTarget.Trim().ToLowerInvariant()) {
                $selectedTarget = $target
                break
            }
        }

        if ($null -eq $selectedTarget) {
            throw "[TASK-STATIC-CHECK] defaultTarget '$defaultTarget' not found in targetFiles: $TaskDefinitionPath"
        }
    }
    elseif ($targetFiles.Count -eq 1) {
        $selectedTarget = $targetFiles[0]
    }
    else {
        throw "[TASK-STATIC-CHECK] unable to resolve target file: multiple targetFiles but defaultTarget missing in $TaskDefinitionPath"
    }

    if ($null -eq $selectedTarget -or -not ($selectedTarget.PSObject.Properties.Name -contains 'file')) {
        throw "[TASK-STATIC-CHECK] selected target in targetFiles missing file: $TaskDefinitionPath"
    }

    $selectedFile = [string]$selectedTarget.file
    if ([string]::IsNullOrWhiteSpace($selectedFile)) {
        throw "[TASK-STATIC-CHECK] selected target file is empty: $TaskDefinitionPath"
    }

    return $selectedFile
}

$taskDefinition = $null
try {
    $taskDefinition = (Get-Content -LiteralPath $resolvedTaskDefinition -Raw) | ConvertFrom-Json
}
catch {
    throw "[TASK-STATIC-CHECK] invalid task definition json: $resolvedTaskDefinition"
}

if ($null -eq $taskDefinition -or -not ($taskDefinition.PSObject.Properties.Name -contains 'rounds')) {
    throw "[TASK-STATIC-CHECK] task definition missing rounds: $resolvedTaskDefinition"
}

$targetFileRaw = Resolve-PrimaryTargetFile -TaskDefinition $taskDefinition -TaskDefinitionPath $resolvedTaskDefinition

$targetFileResolved = if ([System.IO.Path]::IsPathRooted($targetFileRaw)) {
    $targetFileRaw
}
else {
    Join-Path $RepoRoot $targetFileRaw
}

if (-not (Test-Path -LiteralPath $targetFileResolved)) {
    throw "[TASK-STATIC-CHECK] target file not found: $targetFileRaw"
}

$targetText = Get-Content -LiteralPath $targetFileResolved -Raw
$workingText = $targetText
$roundEntries = @($taskDefinition.rounds.PSObject.Properties | Sort-Object Name)

if ($roundEntries.Count -eq 0) {
    Add-ErrorIssue 'rounds section is empty'
}

foreach ($roundEntry in $roundEntries) {
    $roundTag = [string]$roundEntry.Name
    $roundTask = $roundEntry.Value
    $roundType = Get-RoundTaskType -RoundTask $roundTask

    if ($roundType -ne 'regex-patch') {
        Add-InfoIssue ("round={0} type={1} skip=non-regex-patch" -f $roundTag, $roundType)
        continue
    }

    $operations = @()
    if ($roundTask.PSObject.Properties.Name -contains 'operations') {
        $operations = @($roundTask.operations)
    }

    if ($operations.Count -eq 0) {
        Add-ErrorIssue ("round={0} regex-patch missing operations" -f $roundTag)
        continue
    }

    $markers = @()
    if ($roundTask.PSObject.Properties.Name -contains 'idempotentContains') {
        $markers = @(Get-StringArray -Value $roundTask.idempotentContains)
    }

    if ($markers.Count -eq 0) {
        Add-WarnIssue ("round={0} idempotentContains missing or empty" -f $roundTag)
    }

    $roundHasAnyMarkerInWorking = $false
    foreach ($marker in $markers) {
        $markerTrimmed = $marker.Trim()
        if ([string]::IsNullOrWhiteSpace($markerTrimmed)) {
            continue
        }

        $markerInWorking = $workingText.Contains($markerTrimmed)
        if ($markerInWorking) {
            $roundHasAnyMarkerInWorking = $true
            continue
        }

        $markerInReplacement = $false
        foreach ($operation in $operations) {
            $replacementText = [string]$operation.replacement
            if (-not [string]::IsNullOrWhiteSpace($replacementText) -and $replacementText.Contains($markerTrimmed)) {
                $markerInReplacement = $true
                break
            }
        }

        if (-not $markerInReplacement) {
            Add-ErrorIssue ("round={0} anchor marker not found in target/replacement marker={1}" -f $roundTag, $markerTrimmed)
        }
    }

    $operationIndex = 0
    foreach ($operation in $operations) {
        $operationIndex++
        $pattern = [string]$operation.pattern
        if ([string]::IsNullOrWhiteSpace($pattern)) {
            Add-ErrorIssue ("round={0} op={1} missing pattern" -f $roundTag, $operationIndex)
            continue
        }

        $replacement = [string]$operation.replacement
        if (Test-LikelyDoubleEscapedReplacement -Replacement $replacement) {
            Add-ErrorIssue ("round={0} op={1} replacement likely double-escaped (literal \\n/\\t without actual control chars)" -f $roundTag, $operationIndex)
        }

        $regex = $null
        try {
            $regex = [regex]::new($pattern, [System.Text.RegularExpressions.RegexOptions]::Singleline)
        }
        catch {
            Add-ErrorIssue ("round={0} op={1} invalid regex pattern detail={2}" -f $roundTag, $operationIndex, $_.Exception.Message)
            continue
        }

        $matchCount = $regex.Matches($workingText).Count
        if ($matchCount -gt 1) {
            Add-ErrorIssue ("round={0} op={1} pattern not unique match_count={2}" -f $roundTag, $operationIndex, $matchCount)
            continue
        }

        if ($matchCount -eq 1) {
            Add-InfoIssue ("round={0} op={1} pattern_match=1" -f $roundTag, $operationIndex)

            try {
                $workingText = $regex.Replace($workingText, $replacement, 1)
            }
            catch {
                Add-ErrorIssue ("round={0} op={1} replacement_apply_failed detail={2}" -f $roundTag, $operationIndex, $_.Exception.Message)
            }

            continue
        }

        $roundHasAnyMarkerInWorking = $false
        foreach ($marker in $markers) {
            $markerTrimmed = $marker.Trim()
            if ([string]::IsNullOrWhiteSpace($markerTrimmed)) {
                continue
            }

            if ($workingText.Contains($markerTrimmed)) {
                $roundHasAnyMarkerInWorking = $true
                break
            }
        }

        if ($roundHasAnyMarkerInWorking) {
            Add-WarnIssue ("round={0} op={1} pattern_unmatched=0 but idempotent marker exists in effective text (likely already-applied)" -f $roundTag, $operationIndex)
            continue
        }

        Add-ErrorIssue ("round={0} op={1} pattern_unmatched=0 and no idempotent marker found in effective text" -f $roundTag, $operationIndex)
    }
}

Write-Output ("[TASK-STATIC-CHECK] policy={0} task={1} target={2}" -f $Policy, $resolvedTaskDefinition, $targetFileResolved)
foreach ($info in $infos) {
    Write-Output ("[TASK-STATIC-CHECK] severity=info detail={0}" -f $info)
}
foreach ($warning in $warnings) {
    Write-Output ("[TASK-STATIC-CHECK] severity=warn detail={0}" -f $warning)
}
foreach ($errorItem in $errors) {
    Write-Output ("[TASK-STATIC-CHECK] severity=error detail={0}" -f $errorItem)
}

Write-Output ("[TASK-STATIC-CHECK] summary errors={0} warnings={1} infos={2}" -f $errors.Count, $warnings.Count, $infos.Count)

if ($errors.Count -gt 0 -and $Policy -eq 'enforce') {
    exit 2
}

exit 0
