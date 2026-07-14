param(
    [Parameter(Mandatory = $true)][string]$TaskDefinitionFile,
    [string[]]$PrerequisiteTaskDefinitionFiles = @(),
    [AllowEmptyString()][string]$RepoRoot = '',
    [ValidateSet('off', 'warn', 'enforce')][string]$Policy = 'enforce',
    [switch]$FailOnWarnings,
    [AllowEmptyString()][string]$RoundTag = '',
    [Alias('OperationIndex')][ValidateRange(0, 256)][int]$RequestedOperationIndex = 0,
    [AllowEmptyString()][string]$StartFilePath = '',
    [ValidateSet('A', 'B')][string]$Stage = 'A',
    [switch]$EnableFingerprintCheck,
    [AllowEmptyString()][string]$BaselineTargetFile = '',
    [AllowEmptyString()][string]$OutputEffectiveTargetFile = '',
    [ValidateRange(100, 30000)][int]$RegexTimeoutMs = 2000,
    [switch]$SyntaxOnly,
    [switch]$SkipSingleInstance,
    [ValidateRange(1000, 300000)][int]$WorkerTimeoutMs = 30000,
    [switch]$InternalWorker,
    [AllowEmptyString()][string]$WorkerExitCodeFile = ''
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

function Get-TaskStaticMutexName {
    param([string]$RepositoryRoot)

    $fullPath = [System.IO.Path]::GetFullPath($RepositoryRoot).ToLowerInvariant()
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($fullPath)
    $sha1 = [System.Security.Cryptography.SHA1]::Create()
    try {
        $hashBytes = $sha1.ComputeHash($bytes)
    }
    finally {
        $sha1.Dispose()
    }

    $hash = [System.BitConverter]::ToString($hashBytes).Replace('-', '')
    return "Local\whois-task-static-check-$hash"
}

$taskStaticMutex = $null
$taskStaticMutexAcquired = $false
if (-not $SkipSingleInstance.IsPresent) {
    $taskStaticMutexName = Get-TaskStaticMutexName -RepositoryRoot $RepoRoot
    $taskStaticMutex = New-Object System.Threading.Mutex($false, $taskStaticMutexName)
    try {
        try {
            $taskStaticMutexAcquired = $taskStaticMutex.WaitOne(0)
        }
        catch [System.Threading.AbandonedMutexException] {
            $taskStaticMutexAcquired = $true
        }

        if (-not $taskStaticMutexAcquired) {
            Write-Output ("[TASK-STATIC-CHECK] single_instance_conflict=true mutex={0}" -f $taskStaticMutexName)
            $taskStaticMutex.Dispose()
            exit 4
        }
    }
    catch {
        if (-not $taskStaticMutexAcquired -and $null -ne $taskStaticMutex) {
            $taskStaticMutex.Dispose()
        }
        throw
    }
}

function Exit-TaskStaticCheck {
    param([int]$ExitCode)

    if ($script:InternalWorker.IsPresent -and -not [string]::IsNullOrWhiteSpace($script:WorkerExitCodeFile)) {
        [System.IO.File]::WriteAllText($script:WorkerExitCodeFile, [string]$ExitCode, [System.Text.Encoding]::ASCII)
    }
    if ($script:taskStaticMutexAcquired -and $null -ne $script:taskStaticMutex) {
        try {
            $script:taskStaticMutex.ReleaseMutex()
        }
        finally {
            $script:taskStaticMutex.Dispose()
            $script:taskStaticMutex = $null
            $script:taskStaticMutexAcquired = $false
        }
    }
    exit $ExitCode
}

if (-not $InternalWorker.IsPresent) {
    $workerParameters = @{}
    foreach ($entry in $PSBoundParameters.GetEnumerator()) {
        if ($entry.Key -notin @('InternalWorker', 'SkipSingleInstance', 'WorkerTimeoutMs')) {
            $workerParameters[$entry.Key] = $entry.Value
        }
    }
    $workerParameters['RepoRoot'] = $RepoRoot
    $workerParameters['InternalWorker'] = $true
    $workerParameters['SkipSingleInstance'] = $true

    $workerToken = [guid]::NewGuid().ToString('N')
    $workerParameterFile = Join-Path $env:TEMP ("whois-task-static-{0}.clixml" -f $workerToken)
    $workerStdoutFile = Join-Path $env:TEMP ("whois-task-static-{0}.stdout" -f $workerToken)
    $workerStderrFile = Join-Path $env:TEMP ("whois-task-static-{0}.stderr" -f $workerToken)
    $workerExitCodeFile = Join-Path $env:TEMP ("whois-task-static-{0}.exit" -f $workerToken)
    $workerProcess = $null

    try {
        $workerParameters['WorkerExitCodeFile'] = $workerExitCodeFile
        $workerParameters | Export-Clixml -LiteralPath $workerParameterFile
        $escapedParameterFile = $workerParameterFile.Replace("'", "''")
        $escapedScriptPath = $PSCommandPath.Replace("'", "''")
        $escapedExitCodeFile = $workerExitCodeFile.Replace("'", "''")
        $workerCommand = "`$ProgressPreference = 'SilentlyContinue'; `$parameters = Import-Clixml -LiteralPath '$escapedParameterFile'; try { & '$escapedScriptPath' @parameters } catch { Write-Error `$_; [IO.File]::WriteAllText('$escapedExitCodeFile', '1', [Text.Encoding]::ASCII) }; exit 0"
        $encodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($workerCommand))

        $workerProcess = Start-Process -FilePath 'powershell.exe' `
            -ArgumentList @('-NoProfile', '-NonInteractive', '-OutputFormat', 'Text', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', $encodedCommand) `
            -RedirectStandardOutput $workerStdoutFile -RedirectStandardError $workerStderrFile `
            -WindowStyle Hidden -PassThru

        if (-not $workerProcess.WaitForExit($WorkerTimeoutMs)) {
            try {
                $workerProcess.Kill()
                [void]$workerProcess.WaitForExit(5000)
            }
            catch {
                [Console]::Error.WriteLine("[TASK-STATIC-CHECK] worker_termination_error={0}" -f $_.Exception.Message)
            }
            Write-Output ("[TASK-STATIC-CHECK] worker_timeout=true timeout_ms={0}" -f $WorkerTimeoutMs)
            Exit-TaskStaticCheck -ExitCode 5
        }
        $workerProcess.WaitForExit()

        if (Test-Path -LiteralPath $workerStdoutFile -PathType Leaf) {
            Get-Content -LiteralPath $workerStdoutFile | ForEach-Object { Write-Output ([string]$_) }
        }
        if (Test-Path -LiteralPath $workerStderrFile -PathType Leaf) {
            Get-Content -LiteralPath $workerStderrFile | ForEach-Object { [Console]::Error.WriteLine([string]$_) }
        }
        $effectiveWorkerExitCode = $workerProcess.ExitCode
        if (Test-Path -LiteralPath $workerExitCodeFile -PathType Leaf) {
            $workerExitCodeText = (Get-Content -LiteralPath $workerExitCodeFile -Raw).Trim()
            $parsedWorkerExitCode = 0
            if ([int]::TryParse($workerExitCodeText, [ref]$parsedWorkerExitCode)) {
                $effectiveWorkerExitCode = $parsedWorkerExitCode
            }
        }
        Exit-TaskStaticCheck -ExitCode $effectiveWorkerExitCode
    }
    finally {
        if ($null -ne $workerProcess) {
            $workerProcess.Dispose()
        }
        foreach ($temporaryFile in @($workerParameterFile, $workerStdoutFile, $workerStderrFile, $workerExitCodeFile)) {
            if (Test-Path -LiteralPath $temporaryFile) {
                Remove-Item -LiteralPath $temporaryFile -Force -ErrorAction SilentlyContinue
            }
        }
    }
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

$taskDefinitionCandidate = if ([System.IO.Path]::IsPathRooted($TaskDefinitionFile)) {
    $TaskDefinitionFile
}
else {
    Join-Path $RepoRoot $TaskDefinitionFile
}

if (-not (Test-Path -LiteralPath $taskDefinitionCandidate -PathType Leaf)) {
    throw "[TASK-STATIC-CHECK] task definition not found: $TaskDefinitionFile"
}
$resolvedTaskDefinition = (Resolve-Path -LiteralPath $taskDefinitionCandidate).Path

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

function Add-OperationSafetyIssue {
    param([string]$Message)

    if ($script:operationSafetyPolicy -eq 'enforce') {
        Add-ErrorIssue $Message
    }
    elseif ($script:operationSafetyPolicy -eq 'warn') {
        Add-WarnIssue $Message
    }
}

function New-TaskRegex {
    param(
        [string]$Pattern,
        [System.Text.RegularExpressions.RegexOptions]$Options = [System.Text.RegularExpressions.RegexOptions]::None
    )

    return [regex]::new($Pattern, $Options, [TimeSpan]::FromMilliseconds($RegexTimeoutMs))
}

function Test-UnsafeNestedQuantifier {
    param([string]$Pattern)

    return [regex]::IsMatch($Pattern, '\((?:\\.|[^()]){0,512}[+*](?:\\.|[^()]){0,512}\)\s*(?:[+*]|\{\d+(?:,\d*)?\})')
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

function Test-LikelyOrphanFunctionBodyReplacement {
    param(
        [AllowEmptyString()][string]$Pattern,
        [AllowEmptyString()][string]$Replacement
    )

    if ([string]::IsNullOrWhiteSpace($Pattern) -or [string]::IsNullOrWhiteSpace($Replacement)) {
        return $false
    }
    if ($Pattern.Contains('\{') -or $Pattern.Contains('{')) {
        return $false
    }

    $definitionPattern = '(?m)^(?:static\s+)?[A-Za-z_][A-Za-z0-9_\s*]*\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^;\r\n]*\)\r?\n\{'
    foreach ($definition in [regex]::Matches($Replacement, $definitionPattern)) {
        $functionName = [string]$definition.Groups[1].Value
        if ($Pattern.Contains([regex]::Escape($functionName))) {
            return $true
        }
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
        $currentTaskDefinition = (Get-Content -LiteralPath $TaskDefinitionPath -Raw -Encoding utf8) | ConvertFrom-Json -ErrorAction Stop
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
    $taskDefinition = (Get-Content -LiteralPath $resolvedTaskDefinition -Raw -Encoding utf8) | ConvertFrom-Json
}
catch {
    throw "[TASK-STATIC-CHECK] invalid task definition json: $resolvedTaskDefinition"
}

if ($null -eq $taskDefinition -or -not ($taskDefinition.PSObject.Properties.Name -contains 'rounds')) {
    throw "[TASK-STATIC-CHECK] task definition missing rounds: $resolvedTaskDefinition"
}

if ($SyntaxOnly.IsPresent) {
    if (-not ($taskDefinition.PSObject.Properties.Name -contains 'targetFile') -or
        [string]::IsNullOrWhiteSpace([string]$taskDefinition.targetFile)) {
        throw "[TASK-STATIC-CHECK] task definition missing targetFile: $resolvedTaskDefinition"
    }
    if ($null -eq $taskDefinition.rounds -or @($taskDefinition.rounds.PSObject.Properties).Count -eq 0) {
        throw "[TASK-STATIC-CHECK] task definition rounds section is empty: $resolvedTaskDefinition"
    }

    Write-Output ("[TASK-STATIC-CHECK] syntax_only=true status=PASS task={0}" -f $resolvedTaskDefinition)
    Exit-TaskStaticCheck -ExitCode 0
}

$script:operationSafetyPolicy = 'off'
if ($taskDefinition.PSObject.Properties.Name -contains 'qualityPolicy' -and
    $null -ne $taskDefinition.qualityPolicy -and
    $taskDefinition.qualityPolicy.PSObject.Properties.Name -contains 'operationSafetyPolicy') {
    $candidateSafetyPolicy = ([string]$taskDefinition.qualityPolicy.operationSafetyPolicy).Trim().ToLowerInvariant()
    if ($candidateSafetyPolicy -notin @('off', 'warn', 'enforce')) {
        Add-ErrorIssue ("qualityPolicy.operationSafetyPolicy invalid value={0}" -f $candidateSafetyPolicy)
    }
    else {
        $script:operationSafetyPolicy = $candidateSafetyPolicy
    }
}
Add-InfoIssue ("operation_safety_policy={0}" -f $script:operationSafetyPolicy)

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

$baselineTargetResolved = ''
if (-not [string]::IsNullOrWhiteSpace($BaselineTargetFile)) {
    $baselineTargetResolved = if ([System.IO.Path]::IsPathRooted($BaselineTargetFile)) {
        $BaselineTargetFile
    }
    else {
        Join-Path $RepoRoot $BaselineTargetFile
    }
    if (-not (Test-Path -LiteralPath $baselineTargetResolved)) {
        throw "[TASK-STATIC-CHECK] baseline target file not found: $BaselineTargetFile"
    }
}

$effectiveBaselinePath = if ([string]::IsNullOrWhiteSpace($baselineTargetResolved)) { $targetFileResolved } else { $baselineTargetResolved }
$baselineSource = if ([string]::IsNullOrWhiteSpace($baselineTargetResolved)) { 'current-source' } else { 'explicit-file' }
$prerequisiteChain = New-Object 'System.Collections.Generic.List[string]'
$ownedBaselinePath = ''
$prerequisiteChainFailed = $false
$prerequisiteRequestedCount = @($PrerequisiteTaskDefinitionFiles | Where-Object { -not [string]::IsNullOrWhiteSpace(([string]$_).Trim()) }).Count

foreach ($prerequisiteTaskDefinitionFile in @($PrerequisiteTaskDefinitionFiles)) {
    $prerequisiteInput = ([string]$prerequisiteTaskDefinitionFile).Trim()
    if ([string]::IsNullOrWhiteSpace($prerequisiteInput)) {
        continue
    }

    $prerequisiteResolved = if ([System.IO.Path]::IsPathRooted($prerequisiteInput)) {
        (Resolve-Path -LiteralPath $prerequisiteInput).Path
    }
    else {
        (Resolve-Path -LiteralPath (Join-Path $RepoRoot $prerequisiteInput)).Path
    }
    $prerequisiteDefinition = (Get-Content -LiteralPath $prerequisiteResolved -Raw -Encoding utf8) | ConvertFrom-Json
    $prerequisiteTargetRaw = Resolve-PrimaryTargetFile -TaskDefinition $prerequisiteDefinition -TaskDefinitionPath $prerequisiteResolved
    $prerequisiteTargetResolved = if ([System.IO.Path]::IsPathRooted($prerequisiteTargetRaw)) {
        [System.IO.Path]::GetFullPath($prerequisiteTargetRaw)
    }
    else {
        [System.IO.Path]::GetFullPath((Join-Path $RepoRoot $prerequisiteTargetRaw))
    }
    if ($prerequisiteTargetResolved -ne [System.IO.Path]::GetFullPath($targetFileResolved)) {
        Add-ErrorIssue ("prerequisite target mismatch task={0} expected={1} actual={2}" -f $prerequisiteResolved, $targetFileResolved, $prerequisiteTargetResolved)
        $prerequisiteChainFailed = $true
        break
    }

    $nextBaselinePath = Join-Path ([System.IO.Path]::GetTempPath()) ('whois-task-static-baseline-{0}.tmp' -f ([guid]::NewGuid().ToString('N')))
    $prerequisiteArgs = @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', $PSCommandPath,
        '-TaskDefinitionFile', $prerequisiteResolved,
        '-RepoRoot', $RepoRoot,
        '-Policy', $Policy,
        '-BaselineTargetFile', $effectiveBaselinePath,
        '-OutputEffectiveTargetFile', $nextBaselinePath
    )
    if ($FailOnWarnings.IsPresent) {
        $prerequisiteArgs += '-FailOnWarnings'
    }
    $prerequisiteArgs += '-SkipSingleInstance'
    $prerequisiteArgs += '-InternalWorker'

    $prerequisiteOutput = @(& powershell @prerequisiteArgs 2>&1 | ForEach-Object { [string]$_ })
    $prerequisiteExitCode = $LASTEXITCODE
    if ($prerequisiteExitCode -ne 0 -or -not (Test-Path -LiteralPath $nextBaselinePath)) {
        $failureDetail = @($prerequisiteOutput | Where-Object { $_ -match 'severity=error|warning_gate=fail|summary errors=' } | Select-Object -Last 1)
        $failureText = if ($failureDetail.Count -gt 0) { [string]$failureDetail[0] } else { 'effective baseline was not produced' }
        Add-ErrorIssue ("prerequisite check failed task={0} exit={1} detail={2}" -f $prerequisiteResolved, $prerequisiteExitCode, $failureText)
        $prerequisiteChainFailed = $true
        if (Test-Path -LiteralPath $nextBaselinePath) {
            Remove-Item -LiteralPath $nextBaselinePath -Force
        }
        break
    }

    if (-not [string]::IsNullOrWhiteSpace($ownedBaselinePath) -and (Test-Path -LiteralPath $ownedBaselinePath)) {
        Remove-Item -LiteralPath $ownedBaselinePath -Force
    }
    $ownedBaselinePath = $nextBaselinePath
    $effectiveBaselinePath = $nextBaselinePath
    $baselineSource = 'prerequisite-chain'
    [void]$prerequisiteChain.Add($prerequisiteResolved)
    Add-InfoIssue ("prerequisite check passed order={0} task={1}" -f $prerequisiteChain.Count, $prerequisiteResolved)
}

$targetText = Get-Content -LiteralPath $effectiveBaselinePath -Raw
if (-not [string]::IsNullOrWhiteSpace($ownedBaselinePath) -and (Test-Path -LiteralPath $ownedBaselinePath)) {
    Remove-Item -LiteralPath $ownedBaselinePath -Force
}
$workingText = $targetText
if ($prerequisiteChainFailed) {
    $baselineSource = 'prerequisite-chain-failed'
}
$roundEntries = @()
if (-not $prerequisiteChainFailed) {
    $roundEntries = @($taskDefinition.rounds.PSObject.Properties | Sort-Object Name)
}
$roundFound = $false

if ($roundEntries.Count -eq 0 -and -not $prerequisiteChainFailed) {
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

    $operationMarkerOwners = @{}
    for ($operationIndex = 0; $operationIndex -lt $operations.Count; $operationIndex++) {
        if ($RequestedOperationIndex -gt 0 -and $operationIndex -ge $RequestedOperationIndex) {
            break
        }
        $operation = $operations[$operationIndex]
        $operationMarkers = @()
        if ($operation.PSObject.Properties.Name -contains 'idempotentContains') {
            $operationMarkers = @(Get-StringArray -Value $operation.idempotentContains)
        }
        if ($operationMarkers.Count -eq 0) {
            Add-OperationSafetyIssue ("round={0} op={1} operation idempotentContains missing or empty" -f $roundTag, ($operationIndex + 1))
            continue
        }

        $ownReplacement = [string]$operation.replacement
        foreach ($operationMarker in $operationMarkers) {
            $markerText = $operationMarker.Trim()
            if ([string]::IsNullOrWhiteSpace($markerText)) {
                Add-OperationSafetyIssue ("round={0} op={1} operation idempotent marker is blank" -f $roundTag, ($operationIndex + 1))
                continue
            }
            if ($operationMarkerOwners.ContainsKey($markerText)) {
                Add-OperationSafetyIssue ("round={0} op={1} operation idempotent marker reused by op={2} marker={3}" -f $roundTag, ($operationIndex + 1), $operationMarkerOwners[$markerText], $markerText)
            }
            else {
                $operationMarkerOwners[$markerText] = $operationIndex + 1
            }
            if ([string]::IsNullOrWhiteSpace($ownReplacement) -or -not $ownReplacement.Contains($markerText)) {
                Add-OperationSafetyIssue ("round={0} op={1} operation idempotent marker not owned by replacement marker={2}" -f $roundTag, ($operationIndex + 1), $markerText)
            }
        }
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
    $roundOperationFailed = $false
    foreach ($operation in $operations) {
        $operationOrdinal++
        if ($RequestedOperationIndex -gt 0 -and $operationOrdinal -gt $RequestedOperationIndex) {
            continue
        }

        $isPrerequisiteSimulation = ($RequestedOperationIndex -gt 0 -and $operationOrdinal -lt $RequestedOperationIndex)

        $pattern = [string]$operation.pattern
        if ([string]::IsNullOrWhiteSpace($pattern)) {
            Add-ErrorIssue ("round={0} op={1} missing pattern" -f $roundTag, $operationOrdinal)
            $roundOperationFailed = $true
            break
        }
        if (Test-UnsafeNestedQuantifier -Pattern $pattern) {
            Add-ErrorIssue ("round={0} op={1} unsafe_nested_quantifier=true" -f $roundTag, $operationOrdinal)
            $roundOperationFailed = $true
            break
        }

        $replacement = [string]$operation.replacement
        if (Test-LikelyDoubleEscapedReplacement -Replacement $replacement) {
            Add-ErrorIssue ("round={0} op={1} replacement likely double-escaped (literal \\n/\\t without actual control chars)" -f $roundTag, $operationOrdinal)
        }
        if (Test-LikelyOrphanFunctionBodyReplacement -Pattern $pattern -Replacement $replacement) {
            Add-OperationSafetyIssue ("round={0} op={1} replacement defines matched function body but pattern does not consume the original body" -f $roundTag, $operationOrdinal)
        }

        $regex = $null
        try {
            $regex = New-TaskRegex -Pattern $pattern -Options ([System.Text.RegularExpressions.RegexOptions]::Singleline)
        }
        catch {
            Add-ErrorIssue ("round={0} op={1} invalid regex pattern detail={2}" -f $roundTag, $operationOrdinal, $_.Exception.Message)
            $roundOperationFailed = $true
            break
        }

        try {
            $matchCount = $regex.Matches($workingText).Count
        }
        catch [System.Text.RegularExpressions.RegexMatchTimeoutException] {
            Add-ErrorIssue ("round={0} op={1} regex_timeout phase=match timeout_ms={2}" -f $roundTag, $operationOrdinal, $RegexTimeoutMs)
            $roundOperationFailed = $true
            break
        }
        if ($matchCount -gt 1) {
            $issuePrefix = if ($isPrerequisiteSimulation) { 'prerequisite simulation failed ' } else { '' }
            Add-ErrorIssue ("{0}round={1} op={2} pattern not unique match_count={3}" -f $issuePrefix, $roundTag, $operationOrdinal, $matchCount)
            $roundOperationFailed = $true
            break
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
                $postReplaceMatchCount = $regex.Matches($workingText).Count
                if ($postReplaceMatchCount -ne 0) {
                    Add-OperationSafetyIssue ("round={0} op={1} pattern remains matchable after replacement match_count={2}" -f $roundTag, $operationOrdinal, $postReplaceMatchCount)
                    if ($script:operationSafetyPolicy -eq 'enforce') {
                        $roundOperationFailed = $true
                        break
                    }
                }
            }
            catch [System.Text.RegularExpressions.RegexMatchTimeoutException] {
                Add-ErrorIssue ("round={0} op={1} regex_timeout phase=replace-or-postcheck timeout_ms={2}" -f $roundTag, $operationOrdinal, $RegexTimeoutMs)
                $roundOperationFailed = $true
                break
            }
            catch {
                Add-ErrorIssue ("round={0} op={1} replacement_apply_failed detail={2}" -f $roundTag, $operationOrdinal, $_.Exception.Message)
                $roundOperationFailed = $true
                break
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
            $roundOperationFailed = $true
            break
        }

        Add-ErrorIssue ("round={0} op={1} pattern_unmatched=0 and no idempotent marker found in effective text" -f $roundTag, $operationOrdinal)
        $roundOperationFailed = $true
        break
    }

    if (-not $roundOperationFailed -and $script:operationSafetyPolicy -ne 'off' -and $RequestedOperationIndex -eq 0) {
        $firstPassText = $workingText
        $replayText = $firstPassText
        for ($operationIndex = 0; $operationIndex -lt $operations.Count; $operationIndex++) {
            $operation = $operations[$operationIndex]
            $pattern = [string]$operation.pattern
            if ([string]::IsNullOrWhiteSpace($pattern)) {
                continue
            }
            try {
                $regex = New-TaskRegex -Pattern $pattern -Options ([System.Text.RegularExpressions.RegexOptions]::Singleline)
            }
            catch {
                continue
            }
            try {
                $replayMatchCount = $regex.Matches($replayText).Count
            }
            catch [System.Text.RegularExpressions.RegexMatchTimeoutException] {
                Add-OperationSafetyIssue ("round={0} op={1} regex_timeout phase=replay timeout_ms={2}" -f $roundTag, ($operationIndex + 1), $RegexTimeoutMs)
                $roundOperationFailed = $true
                break
            }
            if ($replayMatchCount -ne 0) {
                Add-OperationSafetyIssue ("round={0} op={1} replay pattern must be unmatched actual={2}" -f $roundTag, ($operationIndex + 1), $replayMatchCount)
                if ($replayMatchCount -eq 1) {
                    $replayText = $regex.Replace($replayText, [string]$operation.replacement, 1)
                }
                continue
            }
            if (-not (Test-OperationIdempotentMarkerPresent -Operation $operation -Text $replayText)) {
                Add-OperationSafetyIssue ("round={0} op={1} replay missing operation idempotent evidence" -f $roundTag, ($operationIndex + 1))
            }
        }
        if ($replayText -ne $firstPassText) {
            Add-OperationSafetyIssue ("round={0} replay changed effective text" -f $roundTag)
        }
    }

    if (-not $roundOperationFailed -and $script:operationSafetyPolicy -ne 'off' -and $RequestedOperationIndex -eq 0) {
        $postApplyAssertions = @()
        if ($roundTask.PSObject.Properties.Name -contains 'postApplyAssertions') {
            $postApplyAssertions = @($roundTask.postApplyAssertions)
        }
        if ($postApplyAssertions.Count -eq 0) {
            Add-OperationSafetyIssue ("round={0} postApplyAssertions missing or empty" -f $roundTag)
        }
        foreach ($assertion in $postApplyAssertions) {
            $assertionPattern = if ($null -ne $assertion -and $assertion.PSObject.Properties.Name -contains 'pattern') { [string]$assertion.pattern } else { '' }
            $expectedCount = if ($null -ne $assertion -and $assertion.PSObject.Properties.Name -contains 'expectedCount') { [int]$assertion.expectedCount } else { -1 }
            $assertionName = if ($null -ne $assertion -and $assertion.PSObject.Properties.Name -contains 'name') { [string]$assertion.name } else { 'unnamed' }
            if ([string]::IsNullOrWhiteSpace($assertionPattern) -or $expectedCount -lt 0) {
                Add-OperationSafetyIssue ("round={0} postApplyAssertion invalid name={1}" -f $roundTag, $assertionName)
                continue
            }
            try {
                $actualCount = (New-TaskRegex -Pattern $assertionPattern -Options ([System.Text.RegularExpressions.RegexOptions]::Singleline)).Matches($workingText).Count
            }
            catch [System.Text.RegularExpressions.RegexMatchTimeoutException] {
                Add-OperationSafetyIssue ("round={0} postApplyAssertion regex_timeout name={1} timeout_ms={2}" -f $roundTag, $assertionName, $RegexTimeoutMs)
                $roundOperationFailed = $true
                break
            }
            catch {
                Add-OperationSafetyIssue ("round={0} postApplyAssertion invalid regex name={1} detail={2}" -f $roundTag, $assertionName, $_.Exception.Message)
                continue
            }
            if ($actualCount -ne $expectedCount) {
                Add-OperationSafetyIssue ("round={0} postApplyAssertion failed name={1} expected={2} actual={3}" -f $roundTag, $assertionName, $expectedCount, $actualCount)
            }
            else {
                Add-InfoIssue ("round={0} postApplyAssertion pass name={1} count={2}" -f $roundTag, $assertionName, $actualCount)
            }
        }
    }
}

if (-not $prerequisiteChainFailed -and -not [string]::IsNullOrWhiteSpace($effectiveRoundTag) -and -not $roundFound) {
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
Write-Output ("[TASK-STATIC-CHECK] policy={0} scope={1} task={2} target={3} baseline={4} prerequisites_requested={5} prerequisites_applied={6}" -f $Policy, $scopeText, $resolvedTaskDefinition, $targetFileResolved, $baselineSource, $prerequisiteRequestedCount, $prerequisiteChain.Count)
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

$warningGateFailed = ($warnings.Count -gt 0 -and $FailOnWarnings.IsPresent -and $Policy -eq 'enforce')
$errorGateFailed = ($errors.Count -gt 0 -and $Policy -eq 'enforce')
if (-not [string]::IsNullOrWhiteSpace($OutputEffectiveTargetFile) -and -not $warningGateFailed -and -not $errorGateFailed) {
    $outputEffectiveTargetResolved = if ([System.IO.Path]::IsPathRooted($OutputEffectiveTargetFile)) {
        $OutputEffectiveTargetFile
    }
    else {
        Join-Path $RepoRoot $OutputEffectiveTargetFile
    }
    $outputParent = Split-Path -Parent $outputEffectiveTargetResolved
    if (-not [string]::IsNullOrWhiteSpace($outputParent) -and -not (Test-Path -LiteralPath $outputParent)) {
        New-Item -ItemType Directory -Path $outputParent -Force | Out-Null
    }
    [System.IO.File]::WriteAllText($outputEffectiveTargetResolved, $workingText, [System.Text.UTF8Encoding]::new($false))
}

if ($warningGateFailed) {
    Write-Output '[TASK-STATIC-CHECK] warning_gate=fail fail_on_warnings=true'
    Exit-TaskStaticCheck -ExitCode 3
}

if ($errorGateFailed) {
    Exit-TaskStaticCheck -ExitCode 2
}

Exit-TaskStaticCheck -ExitCode 0
