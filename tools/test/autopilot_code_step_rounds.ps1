param(
    [switch]$Reset,
    [switch]$ResetStateOnly,
    [string]$StateDir = "",
    [string]$TargetFile = "",
    [string]$TaskDefinitionFile = "",
    [string]$ValidatedEffectiveSourceFile = "",
    [string]$ValidatedManifestFile = ""
)

$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot 'unattended_exit_result.ps1')
$script:UnhandledExitTag = 'AUTOPILOT-CODE-STEP-ROUNDS'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path

if ([string]::IsNullOrWhiteSpace($TaskDefinitionFile)) {
    $TaskDefinitionFile = Join-Path $repoRoot "testdata\autopilot_code_step_tasks_default.json"
}
elseif (-not [System.IO.Path]::IsPathRooted($TaskDefinitionFile)) {
    $TaskDefinitionFile = Join-Path $repoRoot $TaskDefinitionFile
}

if (-not (Test-Path -LiteralPath $TaskDefinitionFile)) {
    throw "[CODE-STEP] task definition file not found: $TaskDefinitionFile"
}

try {
    $taskDefinition = (Get-Content -LiteralPath $TaskDefinitionFile -Raw -Encoding utf8) | ConvertFrom-Json
}
catch {
    throw "[CODE-STEP] invalid task definition json: $TaskDefinitionFile"
}

$schemaVersionRaw = '1'
$schemaMode = 'v1'
if ($taskDefinition -and ($taskDefinition.PSObject.Properties.Name -contains "schemaVersion")) {
    $schemaVersionRaw = [string]$taskDefinition.schemaVersion
}

$schemaVersionNormalized = $schemaVersionRaw.Trim().ToLowerInvariant()
if ($schemaVersionNormalized -eq 'vx-draft') {
    $schemaMode = 'vx-draft'
}
else {
    $schemaVersionNumeric = 0
    if (-not [int]::TryParse($schemaVersionNormalized, [ref]$schemaVersionNumeric) -or $schemaVersionNumeric -ne 1) {
        throw "[CODE-STEP] unsupported task definition schemaVersion=$schemaVersionRaw in $TaskDefinitionFile"
    }
}

if (-not $taskDefinition.rounds) {
    throw "[CODE-STEP] task definition missing rounds in $TaskDefinitionFile"
}

function Resolve-VxDefaultTargetFile {
    param(
        [object]$TaskDefinition,
        [string]$TaskDefinitionPath
    )

    if ($null -eq $TaskDefinition -or -not ($TaskDefinition.PSObject.Properties.Name -contains 'targetFiles')) {
        return ''
    }

    $targetFiles = @($TaskDefinition.targetFiles)
    if ($targetFiles.Count -lt 1) {
        return ''
    }

    $defaultTargetId = ''
    if ($TaskDefinition.PSObject.Properties.Name -contains 'defaultTarget') {
        $defaultTargetId = [string]$TaskDefinition.defaultTarget
    }

    $selectedTarget = $null
    if (-not [string]::IsNullOrWhiteSpace($defaultTargetId)) {
        foreach ($target in $targetFiles) {
            $targetId = ''
            if ($null -ne $target -and ($target.PSObject.Properties.Name -contains 'id')) {
                $targetId = [string]$target.id
            }

            if ($targetId.Trim().ToLowerInvariant() -eq $defaultTargetId.Trim().ToLowerInvariant()) {
                $selectedTarget = $target
                break
            }
        }

        if ($null -eq $selectedTarget) {
            throw "[CODE-STEP] defaultTarget '$defaultTargetId' not found in targetFiles: $TaskDefinitionPath"
        }
    }
    elseif ($targetFiles.Count -eq 1) {
        $selectedTarget = $targetFiles[0]
    }
    else {
        return ''
    }

    if ($null -eq $selectedTarget -or -not ($selectedTarget.PSObject.Properties.Name -contains 'file')) {
        throw "[CODE-STEP] targetFiles entry missing file for schema vx-draft: $TaskDefinitionPath"
    }

    $selectedFile = [string]$selectedTarget.file
    if ([string]::IsNullOrWhiteSpace($selectedFile)) {
        throw "[CODE-STEP] targetFiles entry has empty file for schema vx-draft: $TaskDefinitionPath"
    }

    return $selectedFile
}

if ([string]::IsNullOrWhiteSpace($StateDir)) {
    $StateDir = Join-Path $repoRoot "out\artifacts\autopilot_dev_recheck_8round\_code_step_state"
}
if ([string]::IsNullOrWhiteSpace($TargetFile)) {
    $taskTargetFile = ""
    if ($taskDefinition.PSObject.Properties.Name -contains "targetFile") {
        $taskTargetFile = [string]$taskDefinition.targetFile
    }

    if ([string]::IsNullOrWhiteSpace($taskTargetFile) -and $schemaMode -eq 'vx-draft') {
        $taskTargetFile = Resolve-VxDefaultTargetFile -TaskDefinition $taskDefinition -TaskDefinitionPath $TaskDefinitionFile
    }

    if ([string]::IsNullOrWhiteSpace($taskTargetFile)) {
        if ($schemaMode -eq 'vx-draft') {
            throw "[CODE-STEP] vx-draft task definition requires targetFile or resolvable targetFiles/defaultTarget: $TaskDefinitionFile"
        }

        $TargetFile = Join-Path $repoRoot "src\core\whois_query_exec.c"
    }
    else {
        if ([System.IO.Path]::IsPathRooted($taskTargetFile)) {
            $TargetFile = $taskTargetFile
        }
        else {
            $TargetFile = Join-Path $repoRoot $taskTargetFile
        }
    }
}
elseif (-not [System.IO.Path]::IsPathRooted($TargetFile)) {
    $TargetFile = Join-Path $repoRoot $TargetFile
}

$stateFile = Join-Path $StateDir "state.json"
$baselineFile = Join-Path $StateDir "target_baseline.c"

function Invoke-FileUtf8NoBomWrite {
    param(
        [string]$Path,
        [string]$Text
    )

    $enc = New-Object System.Text.UTF8Encoding($false)
    $directory = Split-Path -Parent $Path
    $temporaryPath = Join-Path $directory ('.code-step-{0}.tmp' -f ([guid]::NewGuid().ToString('N')))
    $backupPath = Join-Path $directory ('.code-step-{0}.bak' -f ([guid]::NewGuid().ToString('N')))
    try {
        [System.IO.File]::WriteAllText($temporaryPath, $Text, $enc)
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            [System.IO.File]::Replace($temporaryPath, $Path, $backupPath, $true)
        }
        else {
            [System.IO.File]::Move($temporaryPath, $Path)
        }
    }
    finally {
        Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $backupPath -Force -ErrorAction SilentlyContinue
    }
}

function Get-FileSha256 {
    param([string]$Path)

    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-CodeStepFaultClassification {
    param([System.Exception]$Exception)

    $message = [string]$Exception.Message
    if ($message -match 'validated artifact hash binding mismatch') {
        return [pscustomobject]@{ Code = 'validated-artifact-stale'; Kind = 'environment-transient'; Category = 'noncode-transient' }
    }
    if ($message -match 'validated artifact or manifest not found') {
        return [pscustomobject]@{ Code = 'validated-artifact-missing'; Kind = 'environment-transient'; Category = 'noncode-transient' }
    }
    if ($message -match 'validated artifact requires both source and manifest') {
        return [pscustomobject]@{ Code = 'validated-artifact-incomplete'; Kind = 'environment-transient'; Category = 'noncode-transient' }
    }
    if ($message -match 'validated artifact manifest mismatch') {
        return [pscustomobject]@{ Code = 'validated-artifact-contract-mismatch'; Kind = 'environment-transient'; Category = 'noncode-transient' }
    }
    if ($message -match 'validated artifact path binding mismatch') {
        return [pscustomobject]@{ Code = 'validated-artifact-path-mismatch'; Kind = 'environment-transient'; Category = 'noncode-transient' }
    }
    if ($message -match 'validated artifact required') {
        return [pscustomobject]@{ Code = 'validated-artifact-required'; Kind = 'environment-transient'; Category = 'noncode-transient' }
    }
    if ($Exception -is [System.IO.IOException] -or $Exception -is [System.UnauthorizedAccessException]) {
        return [pscustomobject]@{ Code = 'code-step-io-failure'; Kind = 'environment-transient'; Category = 'noncode-transient' }
    }
    return [pscustomobject]@{ Code = 'code-step-contract-failure'; Kind = 'environment-transient'; Category = 'noncode-transient' }
}

function Get-ValidatedEffectiveSource {
    param(
        [string]$ManifestPath,
        [string]$EffectiveSourcePath,
        [string]$ExpectedRound,
        [string]$ExpectedTaskDefinitionPath,
        [string]$ExpectedTargetPath
    )

    if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf) -or
        -not (Test-Path -LiteralPath $EffectiveSourcePath -PathType Leaf)) {
        throw '[CODE-STEP] validated artifact or manifest not found'
    }
    $manifest = Get-Content -LiteralPath $ManifestPath -Raw -Encoding utf8 | ConvertFrom-Json
    if ([string]$manifest.schema -ne 'TASK_STATIC_VALIDATED_ARTIFACT_V1' -or
        [string]$manifest.round -ne $ExpectedRound) {
        throw "[CODE-STEP] validated artifact manifest mismatch round=$ExpectedRound"
    }
    if ([System.IO.Path]::GetFullPath([string]$manifest.task_definition_path) -ne [System.IO.Path]::GetFullPath($ExpectedTaskDefinitionPath) -or
        [System.IO.Path]::GetFullPath([string]$manifest.target_path) -ne [System.IO.Path]::GetFullPath($ExpectedTargetPath)) {
        throw "[CODE-STEP] validated artifact path binding mismatch round=$ExpectedRound"
    }
    if ((Get-FileSha256 -Path $ExpectedTaskDefinitionPath) -ne [string]$manifest.task_definition_sha256 -or
        (Get-FileSha256 -Path $ExpectedTargetPath) -ne [string]$manifest.baseline_source_sha256 -or
        (Get-FileSha256 -Path $EffectiveSourcePath) -ne [string]$manifest.effective_source_sha256) {
        throw "[CODE-STEP] validated artifact hash binding mismatch round=$ExpectedRound"
    }
    return Get-Content -LiteralPath $EffectiveSourcePath -Raw -Encoding utf8
}

function Read-GitHeadBlobBytes {
    param(
        [string]$RepoRoot,
        [string]$RelativePath
    )

    $gitCommand = Get-Command git.exe -ErrorAction Stop
    $escapedRepoRoot = $RepoRoot.Replace('"', '\"')
    $escapedBlob = ("HEAD:{0}" -f $RelativePath).Replace('"', '\"')
    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $gitCommand.Source
    $startInfo.Arguments = ('-c core.safecrlf=false -c core.autocrlf=false -C "{0}" show "{1}"' -f $escapedRepoRoot, $escapedBlob)
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $startInfo
    $memory = New-Object System.IO.MemoryStream
    try {
        if (-not $process.Start()) {
            throw "git process did not start"
        }
        $process.StandardOutput.BaseStream.CopyTo($memory)
        $errorText = $process.StandardError.ReadToEnd()
        $process.WaitForExit()
        if ($process.ExitCode -ne 0) {
            return [pscustomobject]@{
                Success = $false
                Bytes = [byte[]]@()
                Detail = $errorText.Trim()
            }
        }

        return [pscustomobject]@{
            Success = $true
            Bytes = [byte[]]$memory.ToArray()
            Detail = ""
        }
    }
    finally {
        $memory.Dispose()
        $process.Dispose()
    }
}

function Test-ByteArrayEqual {
    param(
        [byte[]]$Left,
        [byte[]]$Right
    )

    if ($Left.Length -ne $Right.Length) {
        return $false
    }
    for ($index = 0; $index -lt $Left.Length; $index++) {
        if ($Left[$index] -ne $Right[$index]) {
            return $false
        }
    }
    return $true
}

function Test-BaselineMatchesHead {
    param(
        [string]$RepoRoot,
        [string]$BaselinePath,
        [string]$TargetPath
    )

    if (-not (Test-Path -LiteralPath $BaselinePath) -or -not (Test-Path -LiteralPath $TargetPath)) {
        return $false
    }

    $relativePath = Convert-ToRepoRelativePath -RepoRoot $RepoRoot -AbsolutePath $TargetPath
    if ([string]::IsNullOrWhiteSpace($relativePath)) {
        return $false
    }

    $headBlob = Read-GitHeadBlobBytes -RepoRoot $RepoRoot -RelativePath $relativePath
    if (-not $headBlob.Success) {
        return $false
    }

    $baselineBytes = [System.IO.File]::ReadAllBytes($BaselinePath)
    return Test-ByteArrayEqual -Left $baselineBytes -Right $headBlob.Bytes
}

function Restore-TargetFromHead {
    param(
        [string]$RepoRoot,
        [string]$TargetPath
    )

    $relativePath = Convert-ToRepoRelativePath -RepoRoot $RepoRoot -AbsolutePath $TargetPath
    if ([string]::IsNullOrWhiteSpace($relativePath)) {
        return [pscustomobject]@{
            Restored = $false
            Reason = "target-outside-repo"
            Detail = ""
        }
    }

    $headBlob = Read-GitHeadBlobBytes -RepoRoot $RepoRoot -RelativePath $relativePath
    if (-not $headBlob.Success) {
        return [pscustomobject]@{
            Restored = $false
            Reason = "git-show-failed"
            Detail = $headBlob.Detail
        }
    }

    [System.IO.File]::WriteAllBytes($TargetPath, $headBlob.Bytes)

    return [pscustomobject]@{
        Restored = $true
        Reason = "restored-from-head"
        Detail = ""
    }
}

if ($Reset) {
    $restored = $false
    $restoredFromHead = $false
    $restorePolicy = "skipped-no-baseline"
    $baselineMatchesHead = $false
    $restoreDetail = "none"

    if ($ResetStateOnly.IsPresent) {
        $restorePolicy = "state-only-no-source-restore"
        $restoreDetail = "state-only"
    }
    else {
        if ((Test-Path -LiteralPath $baselineFile) -and (Test-Path -LiteralPath $TargetFile)) {
            $baselineMatchesHead = Test-BaselineMatchesHead -RepoRoot $repoRoot -BaselinePath $baselineFile -TargetPath $TargetFile
        }

        if ((Test-Path -LiteralPath $baselineFile) -and (Test-Path -LiteralPath $TargetFile) -and $baselineMatchesHead) {
            Copy-Item -LiteralPath $baselineFile -Destination $TargetFile -Force
            $restored = $true
            $restorePolicy = "restored-baseline-matches-head"
        }
        elseif ((Test-Path -LiteralPath $baselineFile) -and (Test-Path -LiteralPath $TargetFile)) {
            $headRestore = Restore-TargetFromHead -RepoRoot $repoRoot -TargetPath $TargetFile
            if ($headRestore.Restored) {
                $restored = $true
                $restoredFromHead = $true
                $restorePolicy = "restored-head-due-baseline-mismatch"
            }
            else {
                $restorePolicy = "skipped-baseline-mismatch-head"
                if (-not [string]::IsNullOrWhiteSpace($headRestore.Detail)) {
                    $restoreDetail = $headRestore.Detail
                }
                elseif (-not [string]::IsNullOrWhiteSpace($headRestore.Reason)) {
                    $restoreDetail = $headRestore.Reason
                }
            }
        }

        $restoreDetail = ($restoreDetail -replace '\s+', '_')
    }

    if (Test-Path -LiteralPath $StateDir) {
        Remove-Item -LiteralPath $StateDir -Recurse -Force
    }
    $resetMode = if ($ResetStateOnly.IsPresent) { "state-only" } else { "restore-source" }
    Write-Output "[CODE-STEP] state_reset=true state_dir=$StateDir reset_mode=$resetMode restored_target=$restored restored_from_head=$restoredFromHead baseline_matches_head=$baselineMatchesHead restore_policy=$restorePolicy restore_detail=$restoreDetail task_definition=$TaskDefinitionFile"
    exit 0
}

try {
    if (-not (Test-Path -LiteralPath $TargetFile)) {
        throw "[CODE-STEP] target file not found: $TargetFile"
    }

    New-Item -ItemType Directory -Path $StateDir -Force | Out-Null

    if (-not (Test-Path -LiteralPath $baselineFile)) {
        $baselineText = Get-Content -LiteralPath $TargetFile -Raw
        Invoke-FileUtf8NoBomWrite -Path $baselineFile -Text $baselineText
    }

    $state = [pscustomobject]@{
        invocationCount = 0
        lastRound = ""
        lastTimestamp = ""
    }

    if (Test-Path -LiteralPath $stateFile) {
        try {
            $rawState = Get-Content -LiteralPath $stateFile -Raw
            if (-not [string]::IsNullOrWhiteSpace($rawState)) {
                $state = $rawState | ConvertFrom-Json
            }
        }
        catch {
            Write-Warning "[CODE-STEP] invalid state file, resetting: $stateFile"
        }
    }

    $next = [int]$state.invocationCount + 1
    $roundTag = switch ($next) {
        1 { "D1" }
        2 { "D2" }
        3 { "D3" }
        4 { "D4" }
        default { "VERIFY_OR_EXTRA" }
    }

    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"

    if ($next -le 4) {
        Write-Output "[CODE-STEP] task_definition=$TaskDefinitionFile round=$roundTag"
        $text = Get-Content -LiteralPath $TargetFile -Raw
        if (-not [string]::IsNullOrWhiteSpace($ValidatedEffectiveSourceFile) -or
            -not [string]::IsNullOrWhiteSpace($ValidatedManifestFile)) {
            if ([string]::IsNullOrWhiteSpace($ValidatedEffectiveSourceFile) -or
                [string]::IsNullOrWhiteSpace($ValidatedManifestFile)) {
                throw "[CODE-STEP] validated artifact requires both source and manifest round=$roundTag"
            }
            $updated = Get-ValidatedEffectiveSource `
                -ManifestPath $ValidatedManifestFile `
                -EffectiveSourcePath $ValidatedEffectiveSourceFile `
                -ExpectedRound $roundTag `
                -ExpectedTaskDefinitionPath $TaskDefinitionFile `
                -ExpectedTargetPath $TargetFile
            Write-Output "[CODE-STEP] round=$roundTag validated_artifact=accepted manifest=$ValidatedManifestFile"
        }
        else {
            throw "[CODE-STEP] validated artifact required round=$roundTag"
        }

        if ($updated -ne $text) {
            Invoke-FileUtf8NoBomWrite -Path $TargetFile -Text $updated
            Write-Output "[CODE-STEP] round=$roundTag action=applied target=$TargetFile timestamp=$timestamp"
        }
        else {
            Write-Output "[CODE-STEP] round=$roundTag action=already-applied target=$TargetFile timestamp=$timestamp"
        }
    }
    else {
        Write-Output "[CODE-STEP] round=$roundTag action=no-op reason=dev-rounds-completed"
    }

    $stateOut = [pscustomobject]@{
        invocationCount = $next
        lastRound = $roundTag
        lastTimestamp = $timestamp
    }

    $stateOut | ConvertTo-Json | Out-File -FilePath $stateFile -Encoding utf8
}
catch {
    $fault = Get-CodeStepFaultClassification -Exception $_.Exception
    Write-Output ("[CODE-STEP] fault_code={0} failure_kind={1} failure_category={2}" -f $fault.Code, $fault.Kind, $fault.Category)
    Write-Output "[CODE-STEP] fatal_error=$($_.Exception.Message.Replace("`r",'').Replace("`n",' '))"
    Exit-UnattendedFailure -Tag $script:UnhandledExitTag -Reason ("code-step fatal error: {0}" -f $_.Exception.Message) -ExitCode 1
}
