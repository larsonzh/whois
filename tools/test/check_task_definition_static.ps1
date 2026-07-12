param(
    [Parameter(Mandatory = $true)][string]$TaskDefinitionFile,
    [AllowEmptyString()][string]$RepoRoot = '',
    [ValidateSet('off', 'warn', 'enforce')][string]$Policy = 'enforce',
    [switch]$FailOnWarnings,
    [AllowEmptyString()][string]$RoundTag = '',
    [Alias('OperationIndex')][ValidateRange(0, 256)][int]$RequestedOperationIndex = 0,
    [AllowEmptyString()][string]$StartFilePath = '',
    [ValidateSet('A', 'B')][string]$Stage = 'A',
    [switch]$EnableFingerprintCheck
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

$effectiveRoundTag = ''
if (-not [string]::IsNullOrWhiteSpace($RoundTag)) {
    $effectiveRoundTag = $RoundTag.Trim().ToUpperInvariant()
    if ($effectiveRoundTag -notmatch '^[DV][1-4]$') {
        throw "[TASK-STATIC-CHECK] invalid RoundTag: $RoundTag (expected D1-D4 or V1-V4)"
    }
}

if ($RequestedOperationIndex -gt 0 -and [string]::IsNullOrWhiteSpace($effectiveRoundTag)) {
    throw '[TASK-STATIC-CHECK] OperationIndex requires RoundTag'
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

function Read-KeyValuePairs {
    param([string]$Path)

    $map = @{}
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) {
        return $map
    }

    $lines = Get-Content -LiteralPath $Path -Encoding utf8 -ErrorAction SilentlyContinue
    foreach ($line in $lines) {
        if ($null -eq $line) {
            continue
        }

        $text = [string]$line
        if ([string]::IsNullOrWhiteSpace($text)) {
            continue
        }

        $trimmed = $text.Trim()
        if ($trimmed.StartsWith('#')) {
            continue
        }

        $idx = $trimmed.IndexOf('=')
        if ($idx -lt 1) {
            continue
        }

        $k = $trimmed.Substring(0, $idx).Trim()
        $v = $trimmed.Substring($idx + 1).Trim()
        if (-not [string]::IsNullOrWhiteSpace($k)) {
            $map[$k] = $v
        }
    }

    return $map
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

function Test-OperationIdempotentMarkerPresent {
    param(
        [object]$Operation,
        [string]$Text
    )

    if ($null -eq $Operation -or -not ($Operation.PSObject.Properties.Name -contains 'idempotentContains')) {
        return $false
    }

    $markers = @(Get-StringArray -Value $Operation.idempotentContains)
    if ($markers.Count -eq 0) {
        return $false
    }

    foreach ($marker in $markers) {
        if (-not $Text.Contains($marker.Trim())) {
            return $false
        }
    }

    return $true
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

function Add-ResumeRoundBoundaryIssues {
    param(
        [string]$TaskDefinitionPath,
        [string]$RepositoryRoot,
        [System.Collections.IDictionary]$Settings,
        [ValidateSet('A', 'B')][string]$Stage
    )

    if ($null -eq $Settings -or -not $Settings.ContainsKey('RESUME_FAILED_ROUND')) {
        return
    }

    $resumeRound = ([string]$Settings['RESUME_FAILED_ROUND']).Trim().ToUpperInvariant()
    if ($resumeRound -notmatch '^[DV][1-4]$') {
        return
    }

    $repoRootFull = [System.IO.Path]::GetFullPath($RepositoryRoot).TrimEnd([char]92, [char]47)
    $taskPathFull = [System.IO.Path]::GetFullPath($TaskDefinitionPath)
    if (-not $taskPathFull.StartsWith($repoRootFull, [System.StringComparison]::OrdinalIgnoreCase)) {
        Add-ErrorIssue ("resume-boundary-check task-outside-repo resume_round={0} task={1}" -f $resumeRound, $TaskDefinitionPath)
        return
    }
    $relativeTaskPath = $taskPathFull.Substring($repoRootFull.Length).TrimStart([char]92, [char]47).Replace('\', '/')
    $baselineSpec = ('HEAD:{0}' -f $relativeTaskPath)
    $priorErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $baselineLines = @(& git -C $RepositoryRoot show $baselineSpec 2>$null | ForEach-Object { [string]$_ })
    }
    finally {
        $ErrorActionPreference = $priorErrorActionPreference
    }
    if ($LASTEXITCODE -ne 0 -or $baselineLines.Count -eq 0) {
        Add-ErrorIssue ("resume-boundary-check baseline unavailable resume_round={0} task={1}" -f $resumeRound, $relativeTaskPath)
        return
    }

    $baselineTaskDefinition = $null
    $currentTaskDefinition = $null
    try {
        $baselineTaskDefinition = ($baselineLines -join "`n") | ConvertFrom-Json -ErrorAction Stop
        $currentTaskDefinition = (Get-Content -LiteralPath $TaskDefinitionPath -Raw) | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        Add-ErrorIssue ("resume-boundary-check json-parse-failed resume_round={0} task={1}" -f $resumeRound, $relativeTaskPath)
        return
    }

    $roundNames = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in @($baselineTaskDefinition.rounds.PSObject.Properties)) {
        [void]$roundNames.Add([string]$entry.Name)
    }
    foreach ($entry in @($currentTaskDefinition.rounds.PSObject.Properties)) {
        [void]$roundNames.Add([string]$entry.Name)
    }

    $changedRounds = New-Object 'System.Collections.Generic.List[string]'
    foreach ($roundName in $roundNames) {
        $baselineRound = if ($baselineTaskDefinition.rounds.PSObject.Properties.Name -contains $roundName) { $baselineTaskDefinition.rounds.$roundName } else { $null }
        $currentRound = if ($currentTaskDefinition.rounds.PSObject.Properties.Name -contains $roundName) { $currentTaskDefinition.rounds.$roundName } else { $null }
        $baselineText = if ($null -eq $baselineRound) { '' } else { $baselineRound | ConvertTo-Json -Compress -Depth 64 }
        $currentText = if ($null -eq $currentRound) { '' } else { $currentRound | ConvertTo-Json -Compress -Depth 64 }
        if ($baselineText -ne $currentText) {
            [void]$changedRounds.Add([string]$roundName)
        }
    }

    $allowedRounds = @()
    if ($resumeRound -match '^D([1-4])$') {
        $firstAllowedRound = [int]$Matches[1]
        $allowedRounds = @(for ($roundNumber = $firstAllowedRound; $roundNumber -le 4; $roundNumber++) { "D$roundNumber" })
    }
    else {
        $allowedRounds = @('D4')
    }

    $outOfScopeRounds = @($changedRounds | Where-Object { $_ -notin $allowedRounds })
    if ($outOfScopeRounds.Count -gt 0) {
        Add-ErrorIssue ("resume-boundary-check out-of-scope-round-change resume_round={0} allowed_rounds={1} changed_rounds={2}" -f $resumeRound, ($allowedRounds -join ','), ($outOfScopeRounds -join ','))
    }
    else {
        $changedRoundDetail = if ($changedRounds.Count -gt 0) { $changedRounds -join ',' } else { 'none' }
        Add-InfoIssue ("resume-boundary-check status=pass resume_round={0} allowed_rounds={1} changed_rounds={2}" -f $resumeRound, ($allowedRounds -join ','), $changedRoundDetail)
    }

    if ($resumeRound -match '^V[1-4]$' -and ($changedRounds -contains 'D4')) {
        $baselineD4 = $baselineTaskDefinition.rounds.D4
        $currentD4 = $currentTaskDefinition.rounds.D4
        $d4PropertyNames = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        if ($null -ne $baselineD4) {
            foreach ($property in @($baselineD4.PSObject.Properties)) {
                if ($property.Name -ne 'operations') {
                    [void]$d4PropertyNames.Add([string]$property.Name)
                }
            }
        }
        if ($null -ne $currentD4) {
            foreach ($property in @($currentD4.PSObject.Properties)) {
                if ($property.Name -ne 'operations') {
                    [void]$d4PropertyNames.Add([string]$property.Name)
                }
            }
        }
        foreach ($propertyName in $d4PropertyNames) {
            $baselineProperty = if ($null -ne $baselineD4 -and ($baselineD4.PSObject.Properties.Name -contains $propertyName)) { $baselineD4.$propertyName | ConvertTo-Json -Compress -Depth 64 } else { '' }
            $currentProperty = if ($null -ne $currentD4 -and ($currentD4.PSObject.Properties.Name -contains $propertyName)) { $currentD4.$propertyName | ConvertTo-Json -Compress -Depth 64 } else { '' }
            if ($baselineProperty -ne $currentProperty) {
                Add-ErrorIssue ("resume-boundary-check v-round-d4-non-operation-content-modified resume_round={0} property={1}" -f $resumeRound, $propertyName)
            }
        }
        $baselineOperations = if ($null -ne $baselineD4 -and ($baselineD4.PSObject.Properties.Name -contains 'operations')) { @($baselineD4.operations) } else { @() }
        $currentOperations = if ($null -ne $currentD4 -and ($currentD4.PSObject.Properties.Name -contains 'operations')) { @($currentD4.operations) } else { @() }
        if ($currentOperations.Count -lt $baselineOperations.Count) {
            Add-ErrorIssue ("resume-boundary-check v-round-d4-existing-op-removed resume_round={0}" -f $resumeRound)
        }
        else {
            for ($operationIndex = 0; $operationIndex -lt $baselineOperations.Count; $operationIndex++) {
                $baselineOperationText = $baselineOperations[$operationIndex] | ConvertTo-Json -Compress -Depth 64
                $currentOperationText = $currentOperations[$operationIndex] | ConvertTo-Json -Compress -Depth 64
                if ($baselineOperationText -ne $currentOperationText) {
                    Add-ErrorIssue ("resume-boundary-check v-round-d4-existing-op-modified resume_round={0} op={1}" -f $resumeRound, ($operationIndex + 1))
                }
            }
        }
    }

    if ($resumeRound -match '^D[1-4]$' -and ($changedRounds -contains $resumeRound)) {
        $failurePrefix = if ($Stage -eq 'B') { 'B' } else { 'A' }
        $currentFailureRound = if ($Settings.ContainsKey("${failurePrefix}_FAILURE_MAIN_ROUND")) { ([string]$Settings["${failurePrefix}_FAILURE_MAIN_ROUND"]).Trim().ToUpperInvariant() } else { '' }
        $currentFailurePhase = if ($Settings.ContainsKey("${failurePrefix}_FAILURE_PHASE")) { ([string]$Settings["${failurePrefix}_FAILURE_PHASE"]).Trim().ToLowerInvariant() } else { '' }
        $previousFailureRound = if ($Settings.ContainsKey("${failurePrefix}_PREVIOUS_FAILURE_MAIN_ROUND")) { ([string]$Settings["${failurePrefix}_PREVIOUS_FAILURE_MAIN_ROUND"]).Trim().ToUpperInvariant() } else { '' }
        $previousFailurePhase = if ($Settings.ContainsKey("${failurePrefix}_PREVIOUS_FAILURE_PHASE")) { ([string]$Settings["${failurePrefix}_PREVIOUS_FAILURE_PHASE"]).Trim().ToLowerInvariant() } else { '' }

        $matchedFailurePhase = ''
        if ($currentFailureRound -eq $resumeRound -and $currentFailurePhase -in @('compile', 'verify')) {
            $matchedFailurePhase = $currentFailurePhase
        }
        elseif ($previousFailureRound -eq $resumeRound -and $previousFailurePhase -in @('compile', 'verify')) {
            $matchedFailurePhase = $previousFailurePhase
        }

        if (-not [string]::IsNullOrWhiteSpace($matchedFailurePhase)) {
            $baselineFailedRound = $baselineTaskDefinition.rounds.$resumeRound
            $currentFailedRound = $currentTaskDefinition.rounds.$resumeRound
            $failedRoundPropertyNames = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($roundDefinition in @($baselineFailedRound, $currentFailedRound)) {
                if ($null -eq $roundDefinition) {
                    continue
                }
                foreach ($property in @($roundDefinition.PSObject.Properties)) {
                    if ($property.Name -ne 'operations') {
                        [void]$failedRoundPropertyNames.Add([string]$property.Name)
                    }
                }
            }
            foreach ($propertyName in $failedRoundPropertyNames) {
                $baselineProperty = if ($null -ne $baselineFailedRound -and ($baselineFailedRound.PSObject.Properties.Name -contains $propertyName)) { $baselineFailedRound.$propertyName | ConvertTo-Json -Compress -Depth 64 } else { '' }
                $currentProperty = if ($null -ne $currentFailedRound -and ($currentFailedRound.PSObject.Properties.Name -contains $propertyName)) { $currentFailedRound.$propertyName | ConvertTo-Json -Compress -Depth 64 } else { '' }
                if ($baselineProperty -ne $currentProperty) {
                    Add-ErrorIssue ("resume-boundary-check d-round-existing-content-modified resume_round={0} phase={1} property={2}" -f $resumeRound, $matchedFailurePhase, $propertyName)
                }
            }

            $baselineOperations = if ($null -ne $baselineFailedRound -and ($baselineFailedRound.PSObject.Properties.Name -contains 'operations')) { @($baselineFailedRound.operations) } else { @() }
            $currentOperations = if ($null -ne $currentFailedRound -and ($currentFailedRound.PSObject.Properties.Name -contains 'operations')) { @($currentFailedRound.operations) } else { @() }
            if ($currentOperations.Count -lt $baselineOperations.Count) {
                Add-ErrorIssue ("resume-boundary-check d-round-existing-op-removed resume_round={0} phase={1}" -f $resumeRound, $matchedFailurePhase)
            }
            else {
                for ($operationIndex = 0; $operationIndex -lt $baselineOperations.Count; $operationIndex++) {
                    $baselineOperationText = $baselineOperations[$operationIndex] | ConvertTo-Json -Compress -Depth 64
                    $currentOperationText = $currentOperations[$operationIndex] | ConvertTo-Json -Compress -Depth 64
                    if ($baselineOperationText -ne $currentOperationText) {
                        Add-ErrorIssue ("resume-boundary-check d-round-existing-op-modified resume_round={0} phase={1} op={2}" -f $resumeRound, $matchedFailurePhase, ($operationIndex + 1))
                    }
                }
            }
            Add-InfoIssue ("resume-boundary-check d-round-append-only phase={0} resume_round={1}" -f $matchedFailurePhase, $resumeRound)
        }
    }
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
$roundFound = $false

if ($roundEntries.Count -eq 0) {
    Add-ErrorIssue 'rounds section is empty'
}

foreach ($roundEntry in $roundEntries) {
    $roundTag = [string]$roundEntry.Name
    if (-not [string]::IsNullOrWhiteSpace($effectiveRoundTag) -and $roundTag.Trim().ToUpperInvariant() -ne $effectiveRoundTag) {
        continue
    }

    $roundFound = $true
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

    if ($RequestedOperationIndex -gt 0 -and $RequestedOperationIndex -gt $operations.Count) {
        Add-ErrorIssue ("round={0} operation index out of range op={1} total={2}" -f $roundTag, $RequestedOperationIndex, $operations.Count)
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

    $operationOrdinal = 0
    foreach ($operation in $operations) {
        $operationOrdinal++
        if ($RequestedOperationIndex -gt 0 -and $operationOrdinal -gt $RequestedOperationIndex) {
            continue
        }

        $isPrerequisiteSimulation = ($RequestedOperationIndex -gt 0 -and $operationOrdinal -lt $RequestedOperationIndex)

        $pattern = [string]$operation.pattern
        if ([string]::IsNullOrWhiteSpace($pattern)) {
            Add-ErrorIssue ("round={0} op={1} missing pattern" -f $roundTag, $operationOrdinal)
            continue
        }

        $replacement = [string]$operation.replacement
        if (Test-LikelyDoubleEscapedReplacement -Replacement $replacement) {
            Add-ErrorIssue ("round={0} op={1} replacement likely double-escaped (literal \\n/\\t without actual control chars)" -f $roundTag, $operationOrdinal)
        }

        $regex = $null
        try {
            $regex = [regex]::new($pattern, [System.Text.RegularExpressions.RegexOptions]::Singleline)
        }
        catch {
            Add-ErrorIssue ("round={0} op={1} invalid regex pattern detail={2}" -f $roundTag, $operationOrdinal, $_.Exception.Message)
            continue
        }

        $matchCount = $regex.Matches($workingText).Count
        if ($matchCount -gt 1) {
            $issuePrefix = if ($isPrerequisiteSimulation) { 'prerequisite simulation failed ' } else { '' }
            Add-ErrorIssue ("{0}round={1} op={2} pattern not unique match_count={3}" -f $issuePrefix, $roundTag, $operationOrdinal, $matchCount)
            continue
        }

        if ($matchCount -eq 1) {
            if ($isPrerequisiteSimulation) {
                Add-InfoIssue ("round={0} op={1} prerequisite_simulated=true" -f $roundTag, $operationOrdinal)
            }
            else {
                Add-InfoIssue ("round={0} op={1} pattern_match=1" -f $roundTag, $operationOrdinal)
            }

            try {
                $workingText = $regex.Replace($workingText, $replacement, 1)
            }
            catch {
                Add-ErrorIssue ("round={0} op={1} replacement_apply_failed detail={2}" -f $roundTag, $operationOrdinal, $_.Exception.Message)
            }

            continue
        }

        if (Test-OperationIdempotentMarkerPresent -Operation $operation -Text $workingText) {
            $idempotentDetail = if ($isPrerequisiteSimulation) { 'prerequisite_idempotent=true' } else { 'pattern_unmatched=0 operation_idempotent=true' }
            Add-InfoIssue ("round={0} op={1} {2}" -f $roundTag, $operationOrdinal, $idempotentDetail)
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
            Add-ErrorIssue ("round={0} op={1} pattern_unmatched=0 but only round-level idempotent marker exists; add operation.idempotentContains or restore a unique pattern" -f $roundTag, $operationOrdinal)
            continue
        }

        Add-ErrorIssue ("round={0} op={1} pattern_unmatched=0 and no idempotent marker found in effective text" -f $roundTag, $operationOrdinal)
    }
}

if (-not [string]::IsNullOrWhiteSpace($effectiveRoundTag) -and -not $roundFound) {
    if ($effectiveRoundTag -match '^V[1-4]$') {
        Add-InfoIssue ("round={0} not found in task definition (V-rounds have no JSON definition, skipping)" -f $effectiveRoundTag)
    }
    else {
        Add-ErrorIssue ("round={0} not found in task definition" -f $effectiveRoundTag)
    }
}

if ($EnableFingerprintCheck.IsPresent) {
    if ([string]::IsNullOrWhiteSpace($StartFilePath)) {
        Add-WarnIssue 'fingerprint-check skipped: StartFilePath is empty'
    }
    else {
        $resolvedStartFilePath = if ([System.IO.Path]::IsPathRooted($StartFilePath)) {
            $StartFilePath
        }
        else {
            Join-Path $RepoRoot $StartFilePath
        }

        if (-not (Test-Path -LiteralPath $resolvedStartFilePath)) {
            Add-WarnIssue ("fingerprint-check skipped: start file not found path={0}" -f $resolvedStartFilePath)
        }
        else {
            $settings = Read-KeyValuePairs -Path $resolvedStartFilePath
            Add-ResumeRoundBoundaryIssues -TaskDefinitionPath $resolvedTaskDefinition -RepositoryRoot $RepoRoot -Settings $settings -Stage $Stage
            $prefix = if ($Stage -eq 'B') { 'B' } else { 'A' }

            $curRound = if ($settings.ContainsKey("${prefix}_FAILURE_MAIN_ROUND")) { [string]$settings["${prefix}_FAILURE_MAIN_ROUND"] } else { '' }
            $curPhase = if ($settings.ContainsKey("${prefix}_FAILURE_PHASE")) { [string]$settings["${prefix}_FAILURE_PHASE"] } else { '' }
            $curFp = if ($settings.ContainsKey("${prefix}_FAILURE_FINGERPRINT")) { [string]$settings["${prefix}_FAILURE_FINGERPRINT"] } else { '' }
            $curTaskStartAt = if ($settings.ContainsKey("${prefix}_FAILURE_TASK_START_AT")) { [string]$settings["${prefix}_FAILURE_TASK_START_AT"] } else { '' }

            $prevRound = if ($settings.ContainsKey("${prefix}_PREVIOUS_FAILURE_MAIN_ROUND")) { [string]$settings["${prefix}_PREVIOUS_FAILURE_MAIN_ROUND"] } else { '' }
            $prevPhase = if ($settings.ContainsKey("${prefix}_PREVIOUS_FAILURE_PHASE")) { [string]$settings["${prefix}_PREVIOUS_FAILURE_PHASE"] } else { '' }
            $prevFp = if ($settings.ContainsKey("${prefix}_PREVIOUS_FAILURE_FINGERPRINT")) { [string]$settings["${prefix}_PREVIOUS_FAILURE_FINGERPRINT"] } else { '' }
            $prevTaskStartAt = if ($settings.ContainsKey("${prefix}_PREVIOUS_FAILURE_TASK_START_AT")) { [string]$settings["${prefix}_PREVIOUS_FAILURE_TASK_START_AT"] } else { '' }

            $storedTaskDefHash = if ($settings.ContainsKey("${prefix}_FAILURE_TASKDEF_HASH")) { [string]$settings["${prefix}_FAILURE_TASKDEF_HASH"] } else { '' }
            $storedRoundImprintHash = if ($settings.ContainsKey("${prefix}_FAILURE_TASKDEF_ROUND_IMPRINT_HASH")) { [string]$settings["${prefix}_FAILURE_TASKDEF_ROUND_IMPRINT_HASH"] } else { '' }
            $currentTaskDefHash = (Get-FileHash -LiteralPath $resolvedTaskDefinition -Algorithm SHA1).Hash.ToLowerInvariant()
            $currentRoundImprintHash = ''
            if (-not [string]::IsNullOrWhiteSpace($curRound) -and $null -ne $taskDefinition.rounds.PSObject.Properties[$curRound]) {
                $currentRoundNode = $taskDefinition.rounds.PSObject.Properties[$curRound].Value
                if ($null -ne $currentRoundNode -and $null -ne $currentRoundNode.PSObject.Properties['operations']) {
                    $currentRoundJson = $currentRoundNode.operations | ConvertTo-Json -Depth 32 -Compress
                    $sha1 = [System.Security.Cryptography.SHA1]::Create()
                    try {
                        $roundBytes = [System.Text.Encoding]::UTF8.GetBytes([string]$currentRoundJson)
                        $currentRoundImprintHash = ([System.BitConverter]::ToString($sha1.ComputeHash($roundBytes))).Replace('-', '').ToLowerInvariant()
                    }
                    finally {
                        $sha1.Dispose()
                    }
                }
            }
            $hasCurrentRepairEvidence = (
                (-not [string]::IsNullOrWhiteSpace($storedTaskDefHash) -and $storedTaskDefHash -ne '-' -and $currentTaskDefHash -ne $storedTaskDefHash) -or
                (-not [string]::IsNullOrWhiteSpace($storedRoundImprintHash) -and $storedRoundImprintHash -ne '-' -and -not [string]::IsNullOrWhiteSpace($currentRoundImprintHash) -and $currentRoundImprintHash -ne $storedRoundImprintHash)
            )

            $sameTaskStartWindow = $true
            if (-not [string]::IsNullOrWhiteSpace($curTaskStartAt) -and
                -not [string]::IsNullOrWhiteSpace($prevTaskStartAt) -and
                $curTaskStartAt -ne '-' -and
                $prevTaskStartAt -ne '-') {
                $sameTaskStartWindow = ($curTaskStartAt -eq $prevTaskStartAt)
            }

            $isIdentical =
                -not [string]::IsNullOrWhiteSpace($curRound) -and
                -not [string]::IsNullOrWhiteSpace($prevRound) -and
                $curRound -eq $prevRound -and
                -not [string]::IsNullOrWhiteSpace($curPhase) -and
                -not [string]::IsNullOrWhiteSpace($prevPhase) -and
                $curPhase -eq $prevPhase -and
                $sameTaskStartWindow -and
                -not [string]::IsNullOrWhiteSpace($curFp) -and
                -not [string]::IsNullOrWhiteSpace($prevFp) -and
                $curFp -eq $prevFp

            if ($isIdentical -and $hasCurrentRepairEvidence) {
                Add-InfoIssue ("fingerprint-check stage={0} status=pass reason=repair-evidence-changed round={1}" -f $Stage, $curRound)
            }
            elseif ($isIdentical) {
                $retryGrantedFingerprint = if ($settings.ContainsKey("${prefix}_CODESTEP_IDENTICAL_FP_RETRY_GRANTED_FOR")) { [string]$settings["${prefix}_CODESTEP_IDENTICAL_FP_RETRY_GRANTED_FOR"] } else { '' }
                if ($curPhase -eq 'code-step' -and $retryGrantedFingerprint -ne $curFp) {
                    Add-WarnIssue ("fingerprint-check stage={0} identical_failure_detected phase=code-step retry_budget=available round={1} task_start_at={2}" -f $Stage, $curRound, $curTaskStartAt)
                }
                elseif ($curPhase -eq 'code-step' -and $retryGrantedFingerprint -eq $curFp) {
                    Add-ErrorIssue ("fingerprint-check stage={0} identical_failure_detected phase=code-step retry_budget=exhausted round={1} task_start_at={2}" -f $Stage, $curRound, $curTaskStartAt)
                }
                else {
                    Add-ErrorIssue ("fingerprint-check stage={0} identical_failure_detected phase={1} round={2} task_start_at={3}" -f $Stage, $curPhase, $curRound, $curTaskStartAt)
                }
            }
            else {
                Add-InfoIssue ("fingerprint-check stage={0} status=pass" -f $Stage)
            }
        }
    }
}

$scopeText = if ([string]::IsNullOrWhiteSpace($effectiveRoundTag)) {
    'all'
}
elseif ($RequestedOperationIndex -gt 0) {
    ("{0}:op{1}" -f $effectiveRoundTag, $RequestedOperationIndex)
}
else {
    $effectiveRoundTag
}
Write-Output ("[TASK-STATIC-CHECK] policy={0} scope={1} task={2} target={3}" -f $Policy, $scopeText, $resolvedTaskDefinition, $targetFileResolved)
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

if ($warnings.Count -gt 0 -and $FailOnWarnings.IsPresent -and $Policy -eq 'enforce') {
    Write-Output '[TASK-STATIC-CHECK] warning_gate=fail fail_on_warnings=true'
    exit 3
}

if ($errors.Count -gt 0 -and $Policy -eq 'enforce') {
    exit 2
}

exit 0
