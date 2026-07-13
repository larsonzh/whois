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
    return [pscustomobject]@{ Name = $Name; Directory = $directory; TaskPath = $taskPath }
}

function Invoke-Case {
    param(
        [object]$Case,
        [int]$ExpectedExitCode,
        [string[]]$ExpectedFragments
    )

    $output = @(& powershell -NoProfile -ExecutionPolicy Bypass -File $checker `
        -TaskDefinitionFile $Case.TaskPath -RepoRoot $Case.Directory -Policy enforce -RoundTag D1 2>&1 | `
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
    Write-Output "[TASK-SAFETY-REGRESSION] case=$($Case.Name) status=pass exit=$exitCode"
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
    Invoke-Case -Case $nonConvergentCase -ExpectedExitCode 2 -ExpectedFragments @('pattern remains matchable after replacement', 'replay changed effective text')

    $assertionCase = New-TaskCase -Name 'fail-post-assertion' -Operations @(
        [ordered]@{ pattern = 'return 1;'; replacement = 'return 2;'; idempotentContains = @('return 2;') }
    ) -Assertions @([ordered]@{ name = 'required-helper-call'; pattern = 'helper\(\)'; expectedCount = 1 })
    Invoke-Case -Case $assertionCase -ExpectedExitCode 2 -ExpectedFragments @('postApplyAssertion failed name=required-helper-call')

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
