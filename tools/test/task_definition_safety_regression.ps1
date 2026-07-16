param(
    [string]$OutDirRoot = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$checker = Join-Path $PSScriptRoot 'check_task_definition_static.ps1'
if ([string]::IsNullOrWhiteSpace($OutDirRoot)) {
    $OutDirRoot = Join-Path $env:TEMP 'whois-task-definition-safety'
}
$caseRoot = Join-Path $OutDirRoot ([guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $caseRoot -Force | Out-Null

function Write-Utf8NoBom {
    param([string]$Path, [string]$Text)
    $encoding = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Text, $encoding)
}

function New-TaskCase {
    param(
        [string]$Name,
        [object[]]$Operations,
        [object[]]$Assertions,
        [ValidateSet('off', 'warn', 'enforce')][string]$SafetyPolicy = 'enforce'
    )

    $directory = Join-Path $caseRoot $Name
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
    $sourcePath = Join-Path $directory 'fixture.c'
    $taskPath = Join-Path $directory 'task.json'
    Write-Utf8NoBom -Path $sourcePath -Text "static int target(void)`n{`n`treturn 1;`n}`n"
    $task = [ordered]@{
        schemaVersion = 1
        name = $Name
        targetFile = 'fixture.c'
        qualityPolicy = [ordered]@{ operationSafetyPolicy = $SafetyPolicy }
        rounds = [ordered]@{
            D1 = [ordered]@{
                type = 'regex-patch'
                idempotentContains = @('target')
                operations = $Operations
                postApplyAssertions = $Assertions
            }
        }
    }
    Write-Utf8NoBom -Path $taskPath -Text ($task | ConvertTo-Json -Depth 16)
    return [pscustomobject]@{ Name = $Name; Directory = $directory; SourcePath = $sourcePath; TaskPath = $taskPath }
}

function Invoke-Case {
    param(
        [object]$Case,
        [int]$ExpectedExitCode,
        [string[]]$ExpectedFragments,
        [string[]]$AbsentFragments = @(),
        [int]$RegexTimeoutMs = 2000,
        [int]$WorkerTimeoutMs = 30000
    )

    $output = @(& powershell -NoProfile -ExecutionPolicy Bypass -File $checker `
        -TaskDefinitionFile $Case.TaskPath -RepoRoot $Case.Directory -Policy enforce -RoundTag D1 `
        -RegexTimeoutMs $RegexTimeoutMs -WorkerTimeoutMs $WorkerTimeoutMs 2>&1 | `
        ForEach-Object { [string]$_ })
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne $ExpectedExitCode) {
        throw "case=$($Case.Name) expected_exit=$ExpectedExitCode actual_exit=$exitCode output=$($output -join ' | ')"
    }
    foreach ($fragment in $ExpectedFragments) {
        if (-not ($output -match [regex]::Escape($fragment))) {
            throw "case=$($Case.Name) missing_fragment=$fragment output=$($output -join ' | ')"
        }
    }
    foreach ($fragment in $AbsentFragments) {
        if ($output -match [regex]::Escape($fragment)) {
            throw "case=$($Case.Name) unexpected_fragment=$fragment output=$($output -join ' | ')"
        }
    }
    Write-Output "[TASK-SAFETY-REGRESSION] case=$($Case.Name) status=pass exit=$exitCode"
}

function Invoke-CodeStepCase {
    param(
        [object]$Case,
        [int]$ExpectedExitCode,
        [string]$ExpectedSourceText,
        [string]$ExpectedOutputFragment,
        [int]$ExpectedCheckerExitCode = 0
    )

    $task = (Get-Content -LiteralPath $Case.TaskPath -Raw) | ConvertFrom-Json
    $task.targetFile = $Case.SourcePath
    Write-Utf8NoBom -Path $Case.TaskPath -Text ($task | ConvertTo-Json -Depth 16)

    $stateDir = Join-Path $Case.Directory 'code-step-state'
    $effectivePath = Join-Path $Case.Directory 'D1_code_step_effective.c'
    $manifestPath = Join-Path $Case.Directory 'D1_code_step_effective.json'
    $checkerOutput = @(& powershell -NoProfile -ExecutionPolicy Bypass -File $checker `
        -TaskDefinitionFile $Case.TaskPath -RepoRoot $Case.Directory -Policy enforce -RoundTag D1 `
        -BaselineTargetFile $Case.SourcePath -OutputEffectiveTargetFile $effectivePath 2>&1 | `
        ForEach-Object { [string]$_ })
    $checkerExitCode = $LASTEXITCODE
    if ($checkerExitCode -ne $ExpectedCheckerExitCode) {
        throw "case=$($Case.Name)-code-step expected_checker_exit=$ExpectedCheckerExitCode actual_checker_exit=$checkerExitCode output=$($checkerOutput -join ' | ')"
    }
    if ($checkerExitCode -ne 0) {
        $actualSourceText = Get-Content -LiteralPath $Case.SourcePath -Raw
        if ($actualSourceText -ne $ExpectedSourceText) {
            throw "case=$($Case.Name)-checker-block source mismatch expected=$ExpectedSourceText actual=$actualSourceText"
        }
        if (-not ($checkerOutput -match [regex]::Escape($ExpectedOutputFragment))) {
            throw "case=$($Case.Name)-checker-block missing_fragment=$ExpectedOutputFragment output=$($checkerOutput -join ' | ')"
        }
        Write-Output "[TASK-SAFETY-REGRESSION] case=$($Case.Name)-checker-block status=pass exit=$checkerExitCode"
        return
    }
    if (-not (Test-Path -LiteralPath $effectivePath -PathType Leaf)) {
        throw "case=$($Case.Name)-code-step checker failed output=$($checkerOutput -join ' | ')"
    }

    $manifest = [ordered]@{
        schema = 'TASK_STATIC_VALIDATED_ARTIFACT_V1'
        stage = 'A'
        round = 'D1'
        task_definition_path = [System.IO.Path]::GetFullPath($Case.TaskPath)
        task_definition_sha256 = (Get-FileHash -LiteralPath $Case.TaskPath -Algorithm SHA256).Hash.ToLowerInvariant()
        target_path = [System.IO.Path]::GetFullPath($Case.SourcePath)
        baseline_source_sha256 = (Get-FileHash -LiteralPath $Case.SourcePath -Algorithm SHA256).Hash.ToLowerInvariant()
        effective_source_sha256 = (Get-FileHash -LiteralPath $effectivePath -Algorithm SHA256).Hash.ToLowerInvariant()
        checker_policy = 'enforce'
        created_at = (Get-Date).ToString('o')
    }
    Write-Utf8NoBom -Path $manifestPath -Text ($manifest | ConvertTo-Json -Depth 8)

    $codeStep = Join-Path $PSScriptRoot 'autopilot_code_step_rounds.ps1'
    $output = @(& powershell -NoProfile -ExecutionPolicy Bypass -File $codeStep `
        -TaskDefinitionFile $Case.TaskPath -TargetFile $Case.SourcePath -StateDir $stateDir `
        -ValidatedEffectiveSourceFile $effectivePath -ValidatedManifestFile $manifestPath 2>&1 | `
        ForEach-Object { [string]$_ })
    $exitCode = $LASTEXITCODE
    $actualSourceText = Get-Content -LiteralPath $Case.SourcePath -Raw

    if ($exitCode -ne $ExpectedExitCode) {
        throw "case=$($Case.Name)-code-step expected_exit=$ExpectedExitCode actual_exit=$exitCode output=$($output -join ' | ')"
    }
    if ($actualSourceText -ne $ExpectedSourceText) {
        throw "case=$($Case.Name)-code-step source mismatch expected=$ExpectedSourceText actual=$actualSourceText"
    }
    if (-not ($output -match [regex]::Escape($ExpectedOutputFragment))) {
        throw "case=$($Case.Name)-code-step missing_fragment=$ExpectedOutputFragment output=$($output -join ' | ')"
    }

    Write-Output "[TASK-SAFETY-REGRESSION] case=$($Case.Name)-code-step status=pass exit=$exitCode"
}

function Invoke-ValidatedArtifactCase {
    param(
        [object]$Case,
        [ValidateSet('pass', 'source-stale', 'task-stale', 'artifact-stale')][string]$Mode
    )

    $effectivePath = Join-Path $Case.Directory 'D1_validated_effective.c'
    $manifestPath = Join-Path $Case.Directory 'D1_validated_effective.json'
    $checkerOutput = @(& powershell -NoProfile -ExecutionPolicy Bypass -File $checker `
        -TaskDefinitionFile $Case.TaskPath -RepoRoot $Case.Directory -Policy enforce -RoundTag D1 `
        -BaselineTargetFile $Case.SourcePath -OutputEffectiveTargetFile $effectivePath 2>&1 | `
        ForEach-Object { [string]$_ })
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $effectivePath -PathType Leaf)) {
        throw "case=validated-artifact-$Mode checker failed output=$($checkerOutput -join ' | ')"
    }

    $manifest = [ordered]@{
        schema = 'TASK_STATIC_VALIDATED_ARTIFACT_V1'
        stage = 'A'
        round = 'D1'
        task_definition_path = [System.IO.Path]::GetFullPath($Case.TaskPath)
        task_definition_sha256 = (Get-FileHash -LiteralPath $Case.TaskPath -Algorithm SHA256).Hash.ToLowerInvariant()
        target_path = [System.IO.Path]::GetFullPath($Case.SourcePath)
        baseline_source_sha256 = (Get-FileHash -LiteralPath $Case.SourcePath -Algorithm SHA256).Hash.ToLowerInvariant()
        effective_source_sha256 = (Get-FileHash -LiteralPath $effectivePath -Algorithm SHA256).Hash.ToLowerInvariant()
        checker_policy = 'enforce'
        created_at = (Get-Date).ToString('o')
    }
    Write-Utf8NoBom -Path $manifestPath -Text ($manifest | ConvertTo-Json -Depth 8)

    switch ($Mode) {
        'source-stale' { Add-Content -LiteralPath $Case.SourcePath -Value '/* stale */' -Encoding ascii }
        'task-stale' { Add-Content -LiteralPath $Case.TaskPath -Value ' ' -Encoding ascii }
        'artifact-stale' { Add-Content -LiteralPath $effectivePath -Value '/* stale */' -Encoding ascii }
    }

    $beforeHash = (Get-FileHash -LiteralPath $Case.SourcePath -Algorithm SHA256).Hash
    $stateDir = Join-Path $Case.Directory 'validated-state'
    $codeStep = Join-Path $PSScriptRoot 'autopilot_code_step_rounds.ps1'
    $output = @(& powershell -NoProfile -ExecutionPolicy Bypass -File $codeStep `
        -TaskDefinitionFile $Case.TaskPath -TargetFile $Case.SourcePath -StateDir $stateDir `
        -ValidatedEffectiveSourceFile $effectivePath -ValidatedManifestFile $manifestPath 2>&1 | `
        ForEach-Object { [string]$_ })
    $exitCode = $LASTEXITCODE

    if ($Mode -eq 'pass') {
        $expected = "static int target(void)`n{`n`treturn 2;`n}`n"
        $actual = Get-Content -LiteralPath $Case.SourcePath -Raw
        if ($exitCode -ne 0 -or $actual -ne $expected -or -not ($output -match 'validated_artifact=accepted')) {
            throw "case=validated-artifact-pass failed exit=$exitCode output=$($output -join ' | ')"
        }
    }
    else {
        $afterHash = (Get-FileHash -LiteralPath $Case.SourcePath -Algorithm SHA256).Hash
        if ($exitCode -ne 1 -or -not ($output -match 'validated artifact hash binding mismatch') -or
            -not ($output -match 'fault_code=validated-artifact-stale failure_kind=environment-transient failure_category=noncode-transient') -or
            $beforeHash -ne $afterHash) {
            throw "case=validated-artifact-$Mode fail-close mismatch exit=$exitCode output=$($output -join ' | ')"
        }
    }
    Write-Output "[TASK-SAFETY-REGRESSION] case=validated-artifact-$Mode status=pass exit=$exitCode"
}

function Invoke-ValidatedArtifactRequiredCase {
    param([object]$Case)

    $beforeHash = (Get-FileHash -LiteralPath $Case.SourcePath -Algorithm SHA256).Hash
    $stateDir = Join-Path $Case.Directory 'required-state'
    $codeStep = Join-Path $PSScriptRoot 'autopilot_code_step_rounds.ps1'
    $output = @(& powershell -NoProfile -ExecutionPolicy Bypass -File $codeStep `
        -TaskDefinitionFile $Case.TaskPath -TargetFile $Case.SourcePath -StateDir $stateDir 2>&1 | `
        ForEach-Object { [string]$_ })
    $exitCode = $LASTEXITCODE
    $afterHash = (Get-FileHash -LiteralPath $Case.SourcePath -Algorithm SHA256).Hash
    if ($exitCode -ne 1 -or
        -not ($output -match 'fault_code=validated-artifact-required failure_kind=environment-transient failure_category=noncode-transient') -or
        $beforeHash -ne $afterHash) {
        throw "case=validated-artifact-required fail-close mismatch exit=$exitCode output=$($output -join ' | ')"
    }
    Write-Output "[TASK-SAFETY-REGRESSION] case=validated-artifact-required status=pass exit=$exitCode"
}

function Invoke-ResetByteFidelityCase {
    $worktree = Join-Path $caseRoot 'reset-byte-fidelity-worktree'
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
    $previousErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $worktreeOutput = @(& git -C $repoRoot worktree add --detach $worktree HEAD 2>&1 | ForEach-Object { [string]$_ })
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    if ($LASTEXITCODE -ne 0) {
        throw "case=reset-byte-fidelity worktree_add_failed output=$($worktreeOutput -join ' | ')"
    }

    try {
        $relativeTarget = 'src/core/whois_query_exec.c'
        $target = Join-Path $worktree $relativeTarget
        $stateDir = Join-Path $worktree 'out/artifacts/reset-byte-fidelity-state'
        $baseline = Join-Path $stateDir 'target_baseline.c'
        New-Item -ItemType Directory -Path $stateDir -Force | Out-Null

        Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'autopilot_code_step_rounds.ps1') `
            -Destination (Join-Path $worktree 'tools/test/autopilot_code_step_rounds.ps1') -Force

        $headBytes = [System.IO.File]::ReadAllBytes($target)
        if ($headBytes.Length -lt 1 -or $headBytes[$headBytes.Length - 1] -ne 10) {
            throw 'case=reset-byte-fidelity fixture must end with LF'
        }
        $withoutFinalLf = New-Object byte[] ($headBytes.Length - 1)
        [System.Array]::Copy($headBytes, $withoutFinalLf, $withoutFinalLf.Length)
        [System.IO.File]::WriteAllBytes($baseline, $withoutFinalLf)
        [System.IO.File]::WriteAllBytes($target, $withoutFinalLf)

        $beforeStatus = @(& git -C $worktree status --porcelain -- $relativeTarget)
        if ($beforeStatus.Count -ne 1 -or $beforeStatus[0] -notmatch '^ M ') {
            throw "case=reset-byte-fidelity expected_dirty_before_reset status=$($beforeStatus -join ' | ')"
        }

        $codeStep = Join-Path $worktree 'tools/test/autopilot_code_step_rounds.ps1'
        $taskDefinition = Join-Path $worktree 'testdata/autopilot_code_step_tasks_default.json'
        $resetOutput = @(& powershell -NoProfile -ExecutionPolicy Bypass -File $codeStep `
            -Reset -TaskDefinitionFile $taskDefinition -TargetFile $target -StateDir $stateDir 2>&1 | `
            ForEach-Object { [string]$_ })
        if ($LASTEXITCODE -ne 0 -or -not ($resetOutput -match 'restore_policy=restored-head-due-baseline-mismatch')) {
            throw "case=reset-byte-fidelity reset_failed output=$($resetOutput -join ' | ')"
        }

        $actualBytes = [System.IO.File]::ReadAllBytes($target)
        if ($actualBytes.Length -ne $headBytes.Length) {
            throw "case=reset-byte-fidelity byte_length_mismatch expected=$($headBytes.Length) actual=$($actualBytes.Length)"
        }
        for ($index = 0; $index -lt $headBytes.Length; $index++) {
            if ($actualBytes[$index] -ne $headBytes[$index]) {
                throw "case=reset-byte-fidelity byte_mismatch offset=$index"
            }
        }

        $afterStatus = @(& git -C $worktree status --porcelain -- $relativeTarget)
        if ($afterStatus.Count -ne 0) {
            throw "case=reset-byte-fidelity expected_clean_after_reset status=$($afterStatus -join ' | ')"
        }

        Write-Output '[TASK-SAFETY-REGRESSION] case=reset-byte-fidelity status=pass bytes=head git_status=clean'
    }
    finally {
        & git -C $repoRoot worktree remove --force $worktree 2>$null | Out-Null
    }
}

function New-ChainTask {
    param(
        [string]$Directory,
        [string]$Name,
        [string]$Pattern,
        [string]$Replacement
    )

    $taskPath = Join-Path $Directory ("{0}.json" -f $Name)
    $task = [ordered]@{
        schemaVersion = 1
        name = $Name
        targetFile = 'fixture.c'
        qualityPolicy = [ordered]@{ operationSafetyPolicy = 'enforce' }
        rounds = [ordered]@{
            D1 = [ordered]@{
                type = 'regex-patch'
                idempotentContains = @($Replacement)
                operations = @(
                    [ordered]@{
                        pattern = [regex]::Escape($Pattern)
                        replacement = $Replacement
                        idempotentContains = @($Replacement)
                    }
                )
                postApplyAssertions = @(
                    [ordered]@{ name = 'replacement-present'; pattern = [regex]::Escape($Replacement); expectedCount = 1 },
                    [ordered]@{ name = 'pattern-removed'; pattern = [regex]::Escape($Pattern); expectedCount = 0 }
                )
            }
        }
    }
    Write-Utf8NoBom -Path $taskPath -Text ($task | ConvertTo-Json -Depth 16)
    return $taskPath
}

try {
    $passCase = New-TaskCase -Name 'pass-convergent' -Operations @(
        [ordered]@{
            pattern = 'return 1;'
            replacement = 'return 2;'
            idempotentContains = @('return 2;')
        }
    ) -Assertions @(
        [ordered]@{ name = 'updated-return'; pattern = 'return 2;'; expectedCount = 1 },
        [ordered]@{ name = 'old-return-removed'; pattern = 'return 1;'; expectedCount = 0 }
    )
    Invoke-Case -Case $passCase -ExpectedExitCode 0 -ExpectedFragments @('summary errors=0')

    $markerConflictCase = New-TaskCase -Name 'fail-marker-conflict' -Operations @(
        [ordered]@{ pattern = 'return 1;'; replacement = "return 2;`n/* shared */"; idempotentContains = @('/* shared */') },
        [ordered]@{ pattern = 'return 2;'; replacement = "return 3;`n/* shared */"; idempotentContains = @('/* shared */') }
    ) -Assertions @([ordered]@{ name = 'final-return'; pattern = 'return 3;'; expectedCount = 1 })
    Invoke-Case -Case $markerConflictCase -ExpectedExitCode 2 -ExpectedFragments @('operation idempotent marker reused')

    $orphanBodyCase = New-TaskCase -Name 'fail-orphan-body' -Operations @(
        [ordered]@{
            pattern = 'static int target\(void\)'
            replacement = "static int helper(void)`n{`n`treturn 0;`n}`n`nstatic int target(void)`n{`n`treturn 2;`n}"
            idempotentContains = @('static int helper(void)')
        }
    ) -Assertions @([ordered]@{ name = 'helper-definition'; pattern = 'static int helper\(void\)\r?\n\{'; expectedCount = 1 })
    Invoke-Case -Case $orphanBodyCase -ExpectedExitCode 2 -ExpectedFragments @('pattern does not consume the original body')

    $nonConvergentCase = New-TaskCase -Name 'fail-non-convergent' -Operations @(
        [ordered]@{
            pattern = 'static int target\(void\)'
            replacement = "static int helper(void);`nstatic int target(void)"
            idempotentContains = @('static int helper(void);')
        }
    ) -Assertions @([ordered]@{ name = 'helper-prototype'; pattern = 'static int helper\(void\);'; expectedCount = 1 })
    Invoke-Case -Case $nonConvergentCase -ExpectedExitCode 2 -ExpectedFragments @('pattern remains matchable after replacement') -AbsentFragments @('replay changed effective text')

    $failFastCase = New-TaskCase -Name 'fail-first-op-stops-round' -Operations @(
        [ordered]@{ pattern = 'missing-token'; replacement = 'first-op-marker'; idempotentContains = @('first-op-marker') },
        [ordered]@{ pattern = 'return 1;'; replacement = 'second-op-marker'; idempotentContains = @('second-op-marker') }
    ) -Assertions @([ordered]@{ name = 'second-op-applied'; pattern = 'second-op-marker'; expectedCount = 1 })
    Invoke-Case -Case $failFastCase -ExpectedExitCode 2 `
        -ExpectedFragments @('op=1 pattern_unmatched=0 but only round-level idempotent marker exists') `
        -AbsentFragments @('op=2 pattern_match=1', 'postApplyAssertion')

    $regexTimeoutCase = New-TaskCase -Name 'fail-regex-timeout' -Operations @(
        [ordered]@{ pattern = '^(a+)+$'; replacement = 'target-timeout-marker'; idempotentContains = @('target-timeout-marker') }
    ) -Assertions @([ordered]@{ name = 'timeout-marker'; pattern = 'target-timeout-marker'; expectedCount = 1 })
    Write-Utf8NoBom -Path (Join-Path $regexTimeoutCase.Directory 'fixture.c') -Text ((('a' * 30000) -join '') + '!')
    Invoke-Case -Case $regexTimeoutCase -ExpectedExitCode 2 `
        -ExpectedFragments @('unsafe_nested_quantifier=true') `
        -RegexTimeoutMs 30000 -WorkerTimeoutMs 10000

    $assertionCase = New-TaskCase -Name 'fail-post-assertion' -Operations @(
        [ordered]@{ pattern = 'return 1;'; replacement = 'return 2;'; idempotentContains = @('return 2;') }
    ) -Assertions @([ordered]@{ name = 'required-helper-call'; pattern = 'helper\(\)'; expectedCount = 1 })
    Invoke-Case -Case $assertionCase -ExpectedExitCode 2 -ExpectedFragments @('postApplyAssertion failed name=required-helper-call')
    Invoke-CodeStepCase -Case $assertionCase -ExpectedExitCode 1 `
        -ExpectedSourceText "static int target(void)`n{`n`treturn 1;`n}`n" `
        -ExpectedOutputFragment 'postApplyAssertion failed name=required-helper-call' `
        -ExpectedCheckerExitCode 2

    $codeStepPassCase = New-TaskCase -Name 'pass-code-step-complete-contract' -Operations @(
        [ordered]@{ pattern = 'return 1;'; replacement = 'return 2;'; idempotentContains = @('return 2;') }
    ) -Assertions @(
        [ordered]@{ name = 'updated-return'; pattern = 'return 2;'; expectedCount = 1 },
        [ordered]@{ name = 'old-return-removed'; pattern = 'return 1;'; expectedCount = 0 }
    )
    Invoke-CodeStepCase -Case $codeStepPassCase -ExpectedExitCode 0 `
        -ExpectedSourceText "static int target(void)`n{`n`treturn 2;`n}`n" `
        -ExpectedOutputFragment 'round=D1 action=applied'

    foreach ($artifactMode in @('pass', 'source-stale', 'task-stale', 'artifact-stale')) {
        $artifactCase = New-TaskCase -Name ("validated-artifact-{0}" -f $artifactMode) -Operations @(
            [ordered]@{ pattern = 'return 1;'; replacement = 'return 2;'; idempotentContains = @('return 2;') }
        ) -Assertions @(
            [ordered]@{ name = 'updated-return'; pattern = 'return 2;'; expectedCount = 1 },
            [ordered]@{ name = 'old-return-removed'; pattern = 'return 1;'; expectedCount = 0 }
        )
        Invoke-ValidatedArtifactCase -Case $artifactCase -Mode $artifactMode
    }

    $artifactRequiredCase = New-TaskCase -Name 'validated-artifact-required' -Operations @(
        [ordered]@{ pattern = 'return 1;'; replacement = 'return 2;'; idempotentContains = @('return 2;') }
    ) -Assertions @()
    Invoke-ValidatedArtifactRequiredCase -Case $artifactRequiredCase

    Invoke-ResetByteFidelityCase

    $warnCase = New-TaskCase -Name 'pass-warn-compatibility' -Operations @(
        [ordered]@{ pattern = 'return 1;'; replacement = 'return 2;' }
    ) -Assertions @() -SafetyPolicy warn
    Invoke-Case -Case $warnCase -ExpectedExitCode 0 -ExpectedFragments @('severity=warn', 'summary errors=0')

    $targetedCase = New-TaskCase -Name 'pass-targeted-op-boundary' -Operations @(
        [ordered]@{ pattern = 'return 1;'; replacement = 'return 2;'; idempotentContains = @('return 2;') },
        [ordered]@{ pattern = 'never'; replacement = 'unused' }
    ) -Assertions @()
    $targetedOutput = @(& powershell -NoProfile -ExecutionPolicy Bypass -File $checker `
        -TaskDefinitionFile $targetedCase.TaskPath -RepoRoot $targetedCase.Directory -Policy enforce `
        -RoundTag D1 -OperationIndex 1 2>&1 | ForEach-Object { [string]$_ })
    if ($LASTEXITCODE -ne 0 -or -not ($targetedOutput -match 'summary errors=0')) {
        throw "case=$($targetedCase.Name) targeted op check failed output=$($targetedOutput -join ' | ')"
    }
    Invoke-Case -Case $targetedCase -ExpectedExitCode 2 -ExpectedFragments @('op=2 operation idempotentContains missing or empty')

    $chainDirectory = Join-Path $caseRoot 'prerequisite-chain'
    New-Item -ItemType Directory -Path $chainDirectory -Force | Out-Null
    Write-Utf8NoBom -Path (Join-Path $chainDirectory 'fixture.c') -Text "baseline-token`n"
    $prerequisiteTask = New-ChainTask -Directory $chainDirectory -Name 'prerequisite-pass' -Pattern 'baseline-token' -Replacement 'prerequisite-token'
    $mainTask = New-ChainTask -Directory $chainDirectory -Name 'main-pass' -Pattern 'prerequisite-token' -Replacement 'main-token'

    $withoutPrerequisiteOutput = @(& powershell -NoProfile -ExecutionPolicy Bypass -File $checker `
        -TaskDefinitionFile $mainTask -RepoRoot $chainDirectory -Policy enforce 2>&1 | ForEach-Object { [string]$_ })
    if ($LASTEXITCODE -ne 2 -or -not ($withoutPrerequisiteOutput -match 'baseline=current-source prerequisites_requested=0 prerequisites_applied=0')) {
        throw "case=prerequisite-default-current-source unexpected output=$($withoutPrerequisiteOutput -join ' | ')"
    }
    Write-Output '[TASK-SAFETY-REGRESSION] case=prerequisite-default-current-source status=pass exit=2'

    $withPrerequisiteOutput = @(& powershell -NoProfile -ExecutionPolicy Bypass -File $checker `
        -TaskDefinitionFile $mainTask -PrerequisiteTaskDefinitionFiles $prerequisiteTask `
        -RepoRoot $chainDirectory -Policy enforce 2>&1 | ForEach-Object { [string]$_ })
    if ($LASTEXITCODE -ne 0 -or
        -not ($withPrerequisiteOutput -match 'baseline=prerequisite-chain prerequisites_requested=1 prerequisites_applied=1') -or
        -not ($withPrerequisiteOutput -match 'prerequisite check passed order=1')) {
        throw "case=prerequisite-chain-pass unexpected output=$($withPrerequisiteOutput -join ' | ')"
    }
    Write-Output '[TASK-SAFETY-REGRESSION] case=prerequisite-chain-pass status=pass exit=0'

    $failedPrerequisiteTask = New-ChainTask -Directory $chainDirectory -Name 'prerequisite-fail' -Pattern 'missing-token' -Replacement 'unreachable-token'
    $failedPrerequisiteOutput = @(& powershell -NoProfile -ExecutionPolicy Bypass -File $checker `
        -TaskDefinitionFile $mainTask -PrerequisiteTaskDefinitionFiles $failedPrerequisiteTask `
        -RepoRoot $chainDirectory -Policy enforce 2>&1 | ForEach-Object { [string]$_ })
    if ($LASTEXITCODE -ne 2 -or
        -not ($failedPrerequisiteOutput -match 'prerequisite check failed') -or
        -not ($failedPrerequisiteOutput -match 'baseline=prerequisite-chain-failed prerequisites_requested=1 prerequisites_applied=0') -or
        ($failedPrerequisiteOutput -match 'round=D1 op=1 pattern_unmatched')) {
        throw "case=prerequisite-chain-fail-blocks-main unexpected output=$($failedPrerequisiteOutput -join ' | ')"
    }
    Write-Output '[TASK-SAFETY-REGRESSION] case=prerequisite-chain-fail-blocks-main status=pass exit=2'

    Write-Output '[TASK-SAFETY-REGRESSION] result=pass'
}
finally {
    if (Test-Path -LiteralPath $caseRoot) {
        Remove-Item -LiteralPath $caseRoot -Recurse -Force
    }
}
