param([string]$OutDirRoot = '')

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$checker = Join-Path $PSScriptRoot 'check_task_definition_static.ps1'
$codeStep = Join-Path $PSScriptRoot 'autopilot_code_step_rounds.ps1'
if ([string]::IsNullOrWhiteSpace($OutDirRoot)) { $OutDirRoot = Join-Path $repoRoot 'tmp\autopilot-code-step-vx-regression' }
$runRoot = Join-Path $OutDirRoot ([guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $runRoot -Force | Out-Null

function Get-Sha256Bytes([byte[]]$Bytes) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Test-BytesEqual([byte[]]$Left, [byte[]]$Right) {
    if ($Left.Length -ne $Right.Length) { return $false }
    for ($index = 0; $index -lt $Left.Length; $index++) { if ($Left[$index] -ne $Right[$index]) { return $false } }
    return $true
}

function Write-JsonNoBom([string]$Path, [object]$Value) {
    [IO.File]::WriteAllText($Path, ($Value | ConvertTo-Json -Depth 30), [Text.UTF8Encoding]::new($false))
}

function New-VxCase([string]$Name) {
    $caseRoot = Join-Path $runRoot $Name
    $fixture = Join-Path $caseRoot 'fixture'
    New-Item -ItemType Directory -Path $fixture -Force | Out-Null
    $sourceA = Join-Path $fixture 'a.c'
    $sourceB = Join-Path $fixture 'b.c'
    $created = Join-Path $fixture 'created.h'
    $bytesA = [byte[]](0xef, 0xbb, 0xbf) + [Text.UTF8Encoding]::new($false).GetBytes("static int alpha(void) { return 1; }`r`n")
    $bytesB = [Text.UTF8Encoding]::new($false).GetBytes("static int beta(void) { return 2; }`n")
    [IO.File]::WriteAllBytes($sourceA, $bytesA)
    [IO.File]::WriteAllBytes($sourceB, $bytesB)
    $relativeRoot = $fixture.Substring($repoRoot.Length).TrimStart('\', '/').Replace('\', '/')
    $headerText = "#define VX_CREATED_MARKER 1`n"
    $headerHash = Get-Sha256Bytes ([Text.UTF8Encoding]::new($false).GetBytes($headerText))
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
                    [ordered]@{ type = 'create-file'; target = 'created_header'; content = $headerText; contentSha256 = $headerHash; existingPolicy = 'skip'; idempotentContains = @('VX_CREATED_MARKER') }
                )
                idempotentContainsByTarget = [ordered]@{ source_a = @('VX_A_MARKER'); source_b = @('VX_B_MARKER'); created_header = @('VX_CREATED_MARKER') }
                postApplyAssertions = @(
                    [ordered]@{ name = 'a'; target = 'source_a'; pattern = 'VX_A_MARKER'; expectedCount = 1 },
                    [ordered]@{ name = 'b'; target = 'source_b'; pattern = 'VX_B_MARKER'; expectedCount = 1 },
                    [ordered]@{ name = 'header'; target = 'created_header'; pattern = 'VX_CREATED_MARKER'; expectedCount = 1 }
                )
            }
            D2 = [ordered]@{ type = 'noop'; description = 'fixture' }
            D3 = [ordered]@{ type = 'noop'; description = 'fixture' }
            D4 = [ordered]@{ type = 'noop'; description = 'fixture' }
        }
    }
    $taskPath = Join-Path $caseRoot 'task.json'
    Write-JsonNoBom $taskPath $definition
    return [pscustomobject]@{
        Root = $caseRoot; SourceA = $sourceA; SourceB = $sourceB; Created = $created
        InitialA = $bytesA; InitialB = $bytesB; Task = $taskPath
        Artifact = Join-Path $caseRoot 'artifact'; State = Join-Path $caseRoot 'state'
    }
}

function New-Artifact([object]$Case) {
    $arguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $checker,
        '-TaskDefinitionFile', $Case.Task, '-RepoRoot', $repoRoot, '-Policy', 'enforce',
        '-RoundTag', 'D1', '-OutputValidatedArtifactDirectory', $Case.Artifact,
        '-SkipSingleInstance', '-InternalWorker')
    $oldPreference = $ErrorActionPreference
    try { $ErrorActionPreference = 'Continue'; $output = @(& powershell @arguments 2>&1 | ForEach-Object { [string]$_ }); $exitCode = $LASTEXITCODE }
    finally { $ErrorActionPreference = $oldPreference }
    if ($exitCode -ne 0) { throw "checker failed case=$($Case.Root) output=$($output -join ' | ')" }
}

function Invoke-CodeStep([object]$Case, [string[]]$ExtraArguments = @()) {
    $arguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $codeStep,
        '-TaskDefinitionFile', $Case.Task, '-StateDir', $Case.State,
        '-ValidatedArtifactDirectory', $Case.Artifact) + $ExtraArguments
    $oldPreference = $ErrorActionPreference
    try { $ErrorActionPreference = 'Continue'; $output = @(& powershell @arguments 2>&1 | ForEach-Object { [string]$_ }); $exitCode = $LASTEXITCODE }
    finally { $ErrorActionPreference = $oldPreference }
    return [pscustomobject]@{ ExitCode = $exitCode; Output = $output; Joined = ($output -join ' | ') }
}

function Assert-Case([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

try {
    $success = New-VxCase 'success-reset'
    New-Artifact $success
    $result = Invoke-CodeStep $success
    Assert-Case ($result.ExitCode -eq 0) "success exit=$($result.ExitCode) output=$($result.Joined)"
    Assert-Case ((Get-Content -LiteralPath $success.SourceA -Raw) -match 'VX_A_MARKER') 'success source_a not applied'
    Assert-Case ((Get-Content -LiteralPath $success.SourceB -Raw) -match 'VX_B_MARKER') 'success source_b not applied'
    Assert-Case (Test-Path -LiteralPath $success.Created -PathType Leaf) 'success create target missing'
    foreach ($targetId in @('source_a', 'source_b', 'created_header')) {
        Assert-Case ($result.Joined -match "target_id=$targetId") "success log missing target_id=$targetId"
    }
    Assert-Case ($result.Joined -match 'targets_declared=3 targets_touched=3 targets_changed=3 commit=success') 'success summary log missing'
    $state = Get-Content -LiteralPath (Join-Path $success.State 'state.json') -Raw -Encoding utf8 | ConvertFrom-Json
    Assert-Case ($state.schema -eq 'CODE_STEP_VX_STATE_V1' -and $state.invocationCount -eq 1 -and $state.lastRound -eq 'D1') 'success state not advanced after receipt'
    Assert-Case (Test-Path -LiteralPath (Join-Path $success.State 'commit-receipt.json') -PathType Leaf) 'success receipt missing'
    Write-Output '[VX-CODE-STEP-REGRESSION] case=success-two-files-create status=pass'

    $reset = Invoke-CodeStep $success @('-Reset')
    Assert-Case ($reset.ExitCode -eq 0) "reset exit=$($reset.ExitCode) output=$($reset.Joined)"
    Assert-Case (Test-BytesEqual ([IO.File]::ReadAllBytes($success.SourceA)) $success.InitialA) 'reset source_a bytes differ from baseline'
    Assert-Case (Test-BytesEqual ([IO.File]::ReadAllBytes($success.SourceB)) $success.InitialB) 'reset source_b bytes differ from baseline'
    Assert-Case (-not (Test-Path -LiteralPath $success.Created)) 'reset did not delete baseline-absent create target'
    Write-Output '[VX-CODE-STEP-REGRESSION] case=reset-byte-exact-delete-create status=pass'

    $stateOnly = New-VxCase 'reset-state-only'
    New-Artifact $stateOnly
    $result = Invoke-CodeStep $stateOnly
    Assert-Case ($result.ExitCode -eq 0) "state-only setup failed output=$($result.Joined)"
    $effectiveA = [IO.File]::ReadAllBytes($stateOnly.SourceA)
    $effectiveB = [IO.File]::ReadAllBytes($stateOnly.SourceB)
    $result = Invoke-CodeStep $stateOnly @('-Reset', '-ResetStateOnly')
    Assert-Case ($result.ExitCode -eq 0) "state-only reset failed output=$($result.Joined)"
    Assert-Case (Test-BytesEqual ([IO.File]::ReadAllBytes($stateOnly.SourceA)) $effectiveA) 'state-only reset restored source_a unexpectedly'
    Assert-Case (Test-BytesEqual ([IO.File]::ReadAllBytes($stateOnly.SourceB)) $effectiveB) 'state-only reset restored source_b unexpectedly'
    Assert-Case (Test-Path -LiteralPath $stateOnly.Created -PathType Leaf) 'state-only reset deleted create target unexpectedly'
    Assert-Case (-not (Test-Path -LiteralPath $stateOnly.State)) 'state-only reset retained state directory'
    Write-Output '[VX-CODE-STEP-REGRESSION] case=reset-state-only-no-restore status=pass'

    $stale = New-VxCase 'stale'
    New-Artifact $stale
    [IO.File]::AppendAllText($stale.SourceB, "/* stale */`n", [Text.UTF8Encoding]::new($false))
    $beforeA = [IO.File]::ReadAllBytes($stale.SourceA)
    $beforeB = [IO.File]::ReadAllBytes($stale.SourceB)
    $result = Invoke-CodeStep $stale
    Assert-Case ($result.ExitCode -eq 1 -and $result.Joined -match 'validated-artifact-stale') "stale did not fail closed output=$($result.Joined)"
    Assert-Case (Test-BytesEqual ([IO.File]::ReadAllBytes($stale.SourceA)) $beforeA) 'stale changed source_a'
    Assert-Case (Test-BytesEqual ([IO.File]::ReadAllBytes($stale.SourceB)) $beforeB) 'stale changed source_b'
    Assert-Case (-not (Test-Path -LiteralPath $stale.Created)) 'stale created target'
    Write-Output '[VX-CODE-STEP-REGRESSION] case=stale-prewrite-zero-write status=pass'

    $rollback = New-VxCase 'rollback'
    New-Artifact $rollback
    $result = Invoke-CodeStep $rollback @('-VxFaultInjectionAfterTargetId', 'source_b')
    Assert-Case ($result.ExitCode -eq 1 -and $result.Joined -match 'injected code-step failure') "fault injection did not fail output=$($result.Joined)"
    Assert-Case (Test-BytesEqual ([IO.File]::ReadAllBytes($rollback.SourceA)) $rollback.InitialA) 'rollback did not restore first target'
    Assert-Case (Test-BytesEqual ([IO.File]::ReadAllBytes($rollback.SourceB)) $rollback.InitialB) 'rollback changed second target'
    Assert-Case (-not (Test-Path -LiteralPath $rollback.Created)) 'rollback left create target'
    Assert-Case (-not (Test-Path -LiteralPath (Join-Path $rollback.State 'state.json'))) 'rollback advanced state'
    Write-Output '[VX-CODE-STEP-REGRESSION] case=second-target-failure-first-target-rollback status=pass'

    $recovery = New-VxCase 'journal-recovery'
    New-Artifact $recovery
    New-Item -ItemType Directory -Path $recovery.State -Force | Out-Null
    $journalTargets = @()
    foreach ($pair in @(
        [pscustomobject]@{ Id = 'source_a'; Path = $recovery.SourceA },
        [pscustomobject]@{ Id = 'source_b'; Path = $recovery.SourceB },
        [pscustomobject]@{ Id = 'created_header'; Path = $recovery.Created }
    )) {
        $exists = Test-Path -LiteralPath $pair.Path -PathType Leaf
        $bytes = if ($exists) { [IO.File]::ReadAllBytes($pair.Path) } else { $null }
        $journalTargets += [ordered]@{
            target_id = $pair.Id; path = $pair.Path; status = 'prepared'
            baseline_exists = $exists; baseline_length = if ($exists) { $bytes.Length } else { $null }; baseline_sha256 = if ($exists) { Get-Sha256Bytes $bytes } else { $null }
            effective_exists = $exists; effective_length = if ($exists) { $bytes.Length } else { $null }; effective_sha256 = if ($exists) { Get-Sha256Bytes $bytes } else { $null }
            changed = $false; temp_path = (Join-Path (Split-Path -Parent $pair.Path) ".recover-$($pair.Id).tmp"); backup_path = (Join-Path (Split-Path -Parent $pair.Path) ".recover-$($pair.Id).bak")
        }
    }
    Write-JsonNoBom (Join-Path $recovery.State 'commit-journal.json') ([ordered]@{ schema = 'CODE_STEP_VX_COMMIT_JOURNAL_V1'; transaction_id = 'recoverable'; round = 'D1'; rollback_status = 'not-started'; targets = $journalTargets })
    $result = Invoke-CodeStep $recovery
    Assert-Case ($result.ExitCode -eq 0 -and $result.Joined -match 'journal_recovery=baseline-cleanup') "journal recovery failed output=$($result.Joined)"
    Write-Output '[VX-CODE-STEP-REGRESSION] case=journal-baseline-recovery status=pass'

    $blocked = New-VxCase 'journal-blocked'
    New-Artifact $blocked
    New-Item -ItemType Directory -Path $blocked.State -Force | Out-Null
    Write-JsonNoBom (Join-Path $blocked.State 'commit-journal.json') ([ordered]@{ schema = 'UNKNOWN_JOURNAL'; transaction_id = 'blocked' })
    $result = Invoke-CodeStep $blocked
    Assert-Case ($result.ExitCode -eq 1 -and $result.Joined -match 'code-step-journal-blocked') "journal block failed output=$($result.Joined)"
    Assert-Case (Test-BytesEqual ([IO.File]::ReadAllBytes($blocked.SourceA)) $blocked.InitialA) 'blocked journal changed source_a'
    Assert-Case (-not (Test-Path -LiteralPath $blocked.Created)) 'blocked journal created target'
    Write-Output '[VX-CODE-STEP-REGRESSION] case=journal-hard-block status=pass'
    Write-Output '[VX-CODE-STEP-REGRESSION] status=PASS'
}
finally {
    Remove-Item -LiteralPath $runRoot -Recurse -Force -ErrorAction SilentlyContinue
    if ((Test-Path -LiteralPath $OutDirRoot) -and @((Get-ChildItem -LiteralPath $OutDirRoot -Force -ErrorAction SilentlyContinue)).Count -eq 0) {
        Remove-Item -LiteralPath $OutDirRoot -Force -ErrorAction SilentlyContinue
    }
}