param([string]$OutDirRoot = '')

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$checker = Join-Path $PSScriptRoot 'check_task_definition_static.ps1'
if ([string]::IsNullOrWhiteSpace($OutDirRoot)) { $OutDirRoot = Join-Path $repoRoot 'tmp\task-definition-vx-checker' }
$caseRoot = Join-Path $OutDirRoot ([guid]::NewGuid().ToString('N'))
$fixtureRoot = Join-Path $caseRoot 'fixture'
New-Item -ItemType Directory -Path $fixtureRoot -Force | Out-Null

function Write-Utf8NoBom([string]$Path, [string]$Text) {
    [IO.File]::WriteAllText($Path, $Text, [Text.UTF8Encoding]::new($false))
}

function Get-TextSha256([string]$Text) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash([Text.UTF8Encoding]::new($false).GetBytes($Text)))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Write-Definition([string]$Name, [object]$Definition) {
    $path = Join-Path $caseRoot "$Name.json"
    Write-Utf8NoBom $path ($Definition | ConvertTo-Json -Depth 30)
    return $path
}

function New-TextDefinition([object[]]$Targets, [object[]]$Operations, [object[]]$Assertions, [string]$DefaultTarget) {
    return [ordered]@{
        schemaVersion = 'vx-draft'
        targetFiles = $Targets
        defaultTarget = $DefaultTarget
        qualityPolicy = [ordered]@{ operationSafetyPolicy = 'enforce' }
        rounds = [ordered]@{
            D1 = [ordered]@{ type = 'regex-patch'; operations = $Operations; postApplyAssertions = $Assertions }
            D2 = [ordered]@{ type = 'noop'; description = 'fixture' }
            D3 = [ordered]@{ type = 'noop'; description = 'fixture' }
            D4 = [ordered]@{ type = 'noop'; description = 'fixture' }
        }
    }
}

function Invoke-CheckerCase {
    param([string]$Name, [object]$Definition, [string[]]$ExtraArgs, [int]$ExpectedExit, [string[]]$ExpectedFragments, [string[]]$RejectedFragments = @())
    $taskPath = Join-Path $caseRoot "$Name.json"
    Write-Utf8NoBom $taskPath ($Definition | ConvertTo-Json -Depth 30)
    $arguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $checker, '-TaskDefinitionFile', $taskPath, '-RepoRoot', $repoRoot, '-Policy', 'enforce', '-SkipSingleInstance', '-InternalWorker') + $ExtraArgs
    $oldPreference = $ErrorActionPreference
    try { $ErrorActionPreference = 'Continue'; $output = @(& powershell @arguments 2>&1 | ForEach-Object { [string]$_ }); $exitCode = $LASTEXITCODE }
    finally { $ErrorActionPreference = $oldPreference }
    $joined = $output -join ' | '
    if ($exitCode -ne $ExpectedExit) { throw "case=$Name expected_exit=$ExpectedExit actual_exit=$exitCode output=$joined" }
    foreach ($fragment in $ExpectedFragments) { if ($joined -notmatch [regex]::Escape($fragment)) { throw "case=$Name missing=$fragment output=$joined" } }
    foreach ($fragment in $RejectedFragments) { if ($joined -match [regex]::Escape($fragment)) { throw "case=$Name rejected_fragment=$fragment output=$joined" } }
    Write-Output "[VX-CHECKER-REGRESSION] case=$Name status=pass exit=$exitCode"
}

try {
    $sourceA = Join-Path $fixtureRoot 'a.c'
    $sourceB = Join-Path $fixtureRoot 'b.c'
    $createdHeader = Join-Path $fixtureRoot 'created.h'
    Write-Utf8NoBom $sourceA "static int alpha(void) { return 1; }`n"
    Write-Utf8NoBom $sourceB "static int beta(void) { return 2; }`n"
    $relativeRoot = $fixtureRoot.Substring($repoRoot.Length).TrimStart('\', '/').Replace('\', '/')
    $headerContent = "#define VX_CREATED_MARKER 1`n"

    $definition = [ordered]@{
        schemaVersion = 'vx-draft'
        targetFile = "$relativeRoot/a.c"
        targetFiles = @(
            [ordered]@{ id = 'source_a'; file = "$relativeRoot/a.c"; kind = 'c-source'; lifecycle = 'existing' },
            [ordered]@{ id = 'source_b'; file = "$relativeRoot/b.c"; kind = 'c-source'; lifecycle = 'existing' },
            [ordered]@{ id = 'created_header'; file = "$relativeRoot/created.h"; kind = 'c-header'; lifecycle = 'create' }
        )
        defaultTarget = 'source_a'
        qualityPolicy = [ordered]@{ operationSafetyPolicy = 'enforce' }
        rounds = [ordered]@{
            D1 = [ordered]@{
                type = 'regex-patch'
                operations = @(
                    [ordered]@{ target = 'source_a'; pattern = 'return 1;'; replacement = 'return 11; /* VX_A_MARKER */'; idempotentContains = @('VX_A_MARKER') },
                    [ordered]@{ target = 'source_b'; pattern = 'return 2;'; replacement = 'return 22; /* VX_B_MARKER */'; idempotentContains = @('VX_B_MARKER') },
                    [ordered]@{ type = 'create-file'; target = 'created_header'; content = $headerContent; contentSha256 = (Get-TextSha256 $headerContent); existingPolicy = 'skip'; idempotentContains = @('VX_CREATED_MARKER') }
                )
                idempotentContainsByTarget = [ordered]@{ source_a = @('VX_A_MARKER'); source_b = @('VX_B_MARKER'); created_header = @('VX_CREATED_MARKER') }
                postApplyAssertions = @(
                    [ordered]@{ name = 'a-bound'; target = 'source_a'; pattern = 'VX_A_MARKER'; expectedCount = 1 },
                    [ordered]@{ name = 'b-bound'; target = 'source_b'; pattern = 'VX_B_MARKER'; expectedCount = 1 },
                    [ordered]@{ name = 'header-bound'; target = 'created_header'; pattern = 'VX_CREATED_MARKER'; expectedCount = 1 }
                )
            }
            D2 = [ordered]@{
                type = 'regex-patch'
                operations = @([ordered]@{ target = 'created_header'; pattern = ' 1'; replacement = ' 2 /* VX_HEADER_D2 */'; idempotentContains = @('VX_HEADER_D2') })
                idempotentContainsByTarget = [ordered]@{ created_header = @('VX_HEADER_D2') }
                postApplyAssertions = @([ordered]@{ name = 'header-d2'; target = 'created_header'; pattern = 'VX_HEADER_D2'; expectedCount = 1 })
            }
            D3 = [ordered]@{ type = 'noop'; description = 'fixture' }
            D4 = [ordered]@{ type = 'noop'; description = 'fixture' }
        }
    }

    $artifact = Join-Path $caseRoot 'artifact-d1'
    Invoke-CheckerCase 'full-d1' $definition @('-RoundTag', 'D1', '-OutputValidatedArtifactDirectory', $artifact) 0 @('target_id=source_a', 'target_id=source_b', 'action=created', 'summary errors=0')
    $manifest = Get-Content -LiteralPath (Join-Path $artifact 'manifest.json') -Raw -Encoding utf8 | ConvertFrom-Json
    if ($manifest.schema -ne 'TASK_STATIC_VALIDATED_ARTIFACT_VX1' -or @($manifest.targets).Count -ne 3) { throw 'D1 manifest schema or target inventory mismatch' }
    foreach ($id in @('source_a', 'source_b', 'created_header')) {
        $entry = @($manifest.targets | Where-Object { $_.id -eq $id })[0]
        if (-not $entry.changed -or -not (Test-Path -LiteralPath (Join-Path $artifact $entry.payload))) { throw "D1 payload missing id=$id" }
    }
    $createdEntry = @($manifest.targets | Where-Object { $_.id -eq 'created_header' })[0]
    if ($createdEntry.baseline_exists -or -not $createdEntry.effective_exists) { throw 'create target existence binding mismatch' }

    Invoke-CheckerCase 'focused-op2' $definition @('-RoundTag', 'D1', '-OperationIndex', '2') 0 @('op=1 target_id=source_a', 'op=2 target_id=source_b')

    $chainArtifact = Join-Path $caseRoot 'artifact-chain'
    Invoke-CheckerCase 'chain' $definition @('-RoundTag', 'D1', '-ChainRounds', '-OutputValidatedArtifactDirectory', $chainArtifact) 0 @('round=D2', 'summary errors=0')
    $chainManifest = Get-Content -LiteralPath (Join-Path $chainArtifact 'manifest.json') -Raw -Encoding utf8 | ConvertFrom-Json
    $chainHeader = @($chainManifest.targets | Where-Object { $_.id -eq 'created_header' })[0]
    $chainPayloadText = [Text.UTF8Encoding]::new($false).GetString([IO.File]::ReadAllBytes((Join-Path $chainArtifact $chainHeader.payload)))
    if ($chainPayloadText -notmatch 'VX_HEADER_D2') { throw 'ChainRounds did not preserve the target mapping into D2' }

    Write-Utf8NoBom $createdHeader $headerContent
    Invoke-CheckerCase 'already-exists-exact' $definition @('-RoundTag', 'D1') 0 @('target_id=created_header action=already-exists')
    Write-Utf8NoBom $createdHeader "#define WRONG 1`n"
    Invoke-CheckerCase 'already-exists-mismatch' $definition @('-RoundTag', 'D1') 2 @('already-exists content mismatch')
    Remove-Item -LiteralPath $createdHeader -Force

    $firstError = $definition | ConvertTo-Json -Depth 30 | ConvertFrom-Json
    $firstError.rounds.D1.operations[0].pattern = 'DOES_NOT_EXIST'
    Invoke-CheckerCase 'first-error-stop' $firstError @('-RoundTag', 'D1') 2 @('op=1 target_id=source_a') @('op=2 target_id=source_b')

    $unionA = Join-Path $fixtureRoot 'union-a.txt'
    $unionB = Join-Path $fixtureRoot 'union-b.txt'
    $unionCreated = Join-Path $fixtureRoot 'union-created.txt'
    Write-Utf8NoBom $unionA "A0`n"
    Write-Utf8NoBom $unionB "B0`n"
    $unionAPath = "$relativeRoot/union-a.txt"
    $unionBPath = "$relativeRoot/union-b.txt"
    $unionCreatedPath = "$relativeRoot/union-created.txt"

    $prerequisiteUnion = New-TextDefinition @(
        [ordered]@{ id = 'pre_a'; file = $unionAPath; kind = 'text'; lifecycle = 'existing' },
        [ordered]@{ id = 'pre_b'; file = $unionBPath; kind = 'text'; lifecycle = 'existing' }
    ) @(
        [ordered]@{ target = 'pre_a'; pattern = 'A0'; replacement = 'A1 PRE_A'; idempotentContains = @('PRE_A') },
        [ordered]@{ target = 'pre_b'; pattern = 'B0'; replacement = 'B1 PRE_B'; idempotentContains = @('PRE_B') }
    ) @(
        [ordered]@{ name = 'pre-a'; target = 'pre_a'; pattern = 'PRE_A'; expectedCount = 1 },
        [ordered]@{ name = 'pre-b'; target = 'pre_b'; pattern = 'PRE_B'; expectedCount = 1 }
    ) 'pre_a'
    $prerequisiteUnionPath = Write-Definition 'prerequisite-union' $prerequisiteUnion

    $currentUnion = New-TextDefinition @(
        [ordered]@{ id = 'current_a'; file = $unionAPath; kind = 'text'; lifecycle = 'existing' },
        [ordered]@{ id = 'current_b'; file = $unionBPath; kind = 'text'; lifecycle = 'existing' }
    ) @(
        [ordered]@{ target = 'current_a'; pattern = 'A1 PRE_A'; replacement = 'A2 CUR_A'; idempotentContains = @('CUR_A') }
    ) @(
        [ordered]@{ name = 'current-a'; target = 'current_a'; pattern = 'CUR_A'; expectedCount = 1 }
    ) 'current_a'
    $unionArtifact = Join-Path $caseRoot 'artifact-prerequisite-union'
    Invoke-CheckerCase 'prerequisite-overlap-union' $currentUnion @(
        '-PrerequisiteTaskDefinitionFiles', $prerequisiteUnionPath,
        '-OutputValidatedArtifactDirectory', $unionArtifact
    ) 0 @('prerequisite check passed order=1', 'target_id=current_a', 'prerequisites_applied=1')
    $unionManifest = Get-Content -LiteralPath (Join-Path $unionArtifact 'manifest.json') -Raw -Encoding utf8 | ConvertFrom-Json
    if (@($unionManifest.prerequisites).Count -ne 1 -or
        [int]$unionManifest.prerequisites[0].order -ne 1 -or
        [string]$unionManifest.prerequisites[0].path -ne $prerequisiteUnionPath -or
        [string]$unionManifest.prerequisites[0].sha256 -ne (Get-FileHash -LiteralPath $prerequisiteUnionPath -Algorithm SHA256).Hash.ToLowerInvariant() -or
        [string]::IsNullOrWhiteSpace([string]$unionManifest.prerequisites[0].target_set_sha256)) {
        throw 'prerequisite manifest binding mismatch'
    }
    if (@($unionManifest.targets).Count -ne 2 -or @($unionManifest.targets | Where-Object { $_.changed }).Count -ne 2) {
        throw 'prerequisite union artifact target closure mismatch'
    }

    $currentMissingClosure = New-TextDefinition @(
        [ordered]@{ id = 'current_a'; file = $unionAPath; kind = 'text'; lifecycle = 'existing' }
    ) @(
        [ordered]@{ target = 'current_a'; pattern = 'A1 PRE_A'; replacement = 'A2 CUR_A'; idempotentContains = @('CUR_A') }
    ) @(
        [ordered]@{ name = 'current-a'; target = 'current_a'; pattern = 'CUR_A'; expectedCount = 1 }
    ) 'current_a'
    Invoke-CheckerCase 'prerequisite-uncovered-closure' $currentMissingClosure @(
        '-PrerequisiteTaskDefinitionFiles', $prerequisiteUnionPath
    ) 2 @('prerequisite changed target outside current registry', 'current registry must cover commit closure') @('definition=current round=D1')

    $createdContent = "CREATE_BASE CREATE_MARK`n"
    $prerequisiteCreate = New-TextDefinition @(
        [ordered]@{ id = 'pre_create'; file = $unionCreatedPath; kind = 'text'; lifecycle = 'create' }
    ) @(
        [ordered]@{ type = 'create-file'; target = 'pre_create'; content = $createdContent; contentSha256 = (Get-TextSha256 $createdContent); existingPolicy = 'skip'; idempotentContains = @('CREATE_MARK') }
    ) @(
        [ordered]@{ name = 'created'; target = 'pre_create'; pattern = 'CREATE_MARK'; expectedCount = 1 }
    ) 'pre_create'
    $prerequisiteCreatePath = Write-Definition 'prerequisite-create' $prerequisiteCreate

    $currentRegexAfterCreate = New-TextDefinition @(
        [ordered]@{ id = 'post_existing'; file = $unionCreatedPath; kind = 'text'; lifecycle = 'existing' }
    ) @(
        [ordered]@{ target = 'post_existing'; pattern = 'CREATE_BASE'; replacement = 'CREATE_FINAL POST_MARK'; idempotentContains = @('POST_MARK') }
    ) @(
        [ordered]@{ name = 'post-create-regex'; target = 'post_existing'; pattern = 'POST_MARK'; expectedCount = 1 }
    ) 'post_existing'
    $createRegexArtifact = Join-Path $caseRoot 'artifact-create-regex'
    Invoke-CheckerCase 'prerequisite-create-current-regex' $currentRegexAfterCreate @(
        '-PrerequisiteTaskDefinitionFiles', $prerequisiteCreatePath,
        '-OutputValidatedArtifactDirectory', $createRegexArtifact
    ) 0 @('target_id=pre_create action=created', 'target_id=post_existing', 'prerequisites_applied=1')
    $createRegexManifest = Get-Content -LiteralPath (Join-Path $createRegexArtifact 'manifest.json') -Raw -Encoding utf8 | ConvertFrom-Json
    $createRegexEntry = @($createRegexManifest.targets)[0]
    if ($createRegexEntry.baseline_exists -or -not $createRegexEntry.effective_exists -or -not $createRegexEntry.changed) {
        throw 'prerequisite create baseline/effective binding mismatch'
    }

    $currentCreateExact = New-TextDefinition @(
        [ordered]@{ id = 'current_create'; file = $unionCreatedPath; kind = 'text'; lifecycle = 'create' }
    ) @(
        [ordered]@{ type = 'create-file'; target = 'current_create'; content = $createdContent; contentSha256 = (Get-TextSha256 $createdContent); existingPolicy = 'skip'; idempotentContains = @('CREATE_MARK') }
    ) @(
        [ordered]@{ name = 'current-create'; target = 'current_create'; pattern = 'CREATE_MARK'; expectedCount = 1 }
    ) 'current_create'
    Invoke-CheckerCase 'prerequisite-duplicate-create-exact' $currentCreateExact @(
        '-PrerequisiteTaskDefinitionFiles', $prerequisiteCreatePath
    ) 0 @('target_id=current_create action=already-exists')

    $mismatchContent = "CREATE_OTHER CREATE_OTHER_MARK`n"
    $currentCreateMismatch = New-TextDefinition @(
        [ordered]@{ id = 'current_create'; file = $unionCreatedPath; kind = 'text'; lifecycle = 'create' }
    ) @(
        [ordered]@{ type = 'create-file'; target = 'current_create'; content = $mismatchContent; contentSha256 = (Get-TextSha256 $mismatchContent); existingPolicy = 'skip'; idempotentContains = @('CREATE_OTHER_MARK') }
    ) @(
        [ordered]@{ name = 'current-create'; target = 'current_create'; pattern = 'CREATE_OTHER_MARK'; expectedCount = 1 }
    ) 'current_create'
    Invoke-CheckerCase 'prerequisite-duplicate-create-mismatch' $currentCreateMismatch @(
        '-PrerequisiteTaskDefinitionFiles', $prerequisiteCreatePath
    ) 2 @('target_id=current_create already-exists content mismatch')

    $prerequisiteFirstError = $prerequisiteUnion | ConvertTo-Json -Depth 30 | ConvertFrom-Json
    $prerequisiteFirstError.rounds.D1.operations[0].pattern = 'MISSING_PRECONDITION'
    $prerequisiteFirstErrorPath = Write-Definition 'prerequisite-first-error' $prerequisiteFirstError
    Invoke-CheckerCase 'prerequisite-first-error-blocks-current' $currentUnion @(
        '-PrerequisiteTaskDefinitionFiles', $prerequisiteFirstErrorPath
    ) 2 @('definition=prerequisite-1 round=D1 op=1', 'prerequisite check stop order=1 reason=first-error', 'prerequisites_applied=0') @('definition=prerequisite-1 round=D1 op=2', 'definition=current round=D1')

    Write-Output '[VX-CHECKER-REGRESSION] status=PASS'
}
finally {
    Remove-Item -LiteralPath $caseRoot -Recurse -Force -ErrorAction SilentlyContinue
    if ((Test-Path -LiteralPath $OutDirRoot) -and @((Get-ChildItem -LiteralPath $OutDirRoot -Force -ErrorAction SilentlyContinue)).Count -eq 0) {
        Remove-Item -LiteralPath $OutDirRoot -Force -ErrorAction SilentlyContinue
    }
}