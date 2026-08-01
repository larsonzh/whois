param(
    [AllowEmptyString()][string]$OutDirRoot = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$transactionScript = Join-Path $PSScriptRoot 'task_definition_repair_transaction.ps1'
if ([string]::IsNullOrWhiteSpace($OutDirRoot)) {
    $OutDirRoot = Join-Path $env:TEMP 'whois-task-definition-repair-transaction'
}
$caseRoot = Join-Path $OutDirRoot ([guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $caseRoot -Force | Out-Null

function Write-Utf8Bom {
    param([string]$Path, [AllowEmptyString()][string]$Text)
    $parent = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    [System.IO.File]::WriteAllText($Path, $Text, [System.Text.UTF8Encoding]::new($true))
}

function Write-Utf8NoBom {
    param([string]$Path, [AllowEmptyString()][string]$Text)
    [System.IO.File]::WriteAllText($Path, $Text, [System.Text.UTF8Encoding]::new($false))
}

function New-Fixture {
    param(
        [string]$Name,
        [switch]$IncludeAllRounds
    )
    $root = Join-Path $caseRoot $Name
    New-Item -ItemType Directory -Path $root -Force | Out-Null
    $sourcePath = Join-Path $root 'fixture.c'
    $taskPath = Join-Path $root 'task.json'
    Write-Utf8Bom -Path $sourcePath -Text "static int target(void)`n{`n    return 1;`n}`n"
    $task = [ordered]@{
        schemaVersion = 1
        name = $Name
        targetFile = $sourcePath
        qualityPolicy = [ordered]@{ operationSafetyPolicy = 'enforce' }
        rounds = [ordered]@{
            D1 = [ordered]@{
                type = 'regex-patch'
                idempotentContains = @('return 2;')
                operations = @(
                    [ordered]@{
                        pattern = 'return 1;'
                        replacement = 'return 2;'
                        idempotentContains = @('return 2;')
                    }
                )
                postApplyAssertions = @(
                    [ordered]@{
                        name = 'updated-return'
                        pattern = 'return 2;'
                        expectedCount = 1
                    },
                    [ordered]@{
                        name = 'old-return-removed'
                        pattern = 'return 1;'
                        expectedCount = 0
                    }
                )
            }
        }
    }
    if ($IncludeAllRounds.IsPresent) {
        foreach ($roundNumber in 2..4) {
            $task.rounds["D$roundNumber"] = [ordered]@{
                type = 'noop'
                description = "No source change for D$roundNumber fixture validation."
            }
        }
    }
    Write-Utf8Bom -Path $taskPath -Text (($task | ConvertTo-Json -Depth 16) + "`n")
    return [pscustomobject]@{
        Root = $root
        SourcePath = $sourcePath
        TaskPath = $taskPath
        ArtifactRoot = (Join-Path $root 'artifacts')
    }
}

function Invoke-Transaction {
    param(
        [object]$Fixture,
        [string]$TicketId,
        [string]$Mode,
        [int]$ExpectedExitCode,
        [ValidateRange(0, 256)][int]$OperationIndex = 1,
        [AllowEmptyString()][string]$ValidateThroughRound = '',
        [switch]$ChainRounds,
        [AllowEmptyString()][string]$RoundTag = 'D1'
    )
    $previousErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $arguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $transactionScript, '-Mode', $Mode, '-TaskDefinitionFile', $Fixture.TaskPath, '-TicketId', $TicketId, '-Stage', 'A', '-RoundTag', $RoundTag, '-OperationIndex', [string]$OperationIndex, '-ArtifactRoot', $Fixture.ArtifactRoot)
        if (-not [string]::IsNullOrWhiteSpace($ValidateThroughRound)) {
            $arguments += @('-ValidateThroughRound', $ValidateThroughRound)
        }
        if ($ChainRounds.IsPresent) {
            $arguments += '-ChainRounds'
        }
        $output = @(& powershell.exe @arguments 2>&1 | ForEach-Object { [string]$_ })
        $exitCode = if ($null -eq $LASTEXITCODE) { 0 } else { [int]$LASTEXITCODE }
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    if ($exitCode -ne $ExpectedExitCode) {
        $validationLogTail = @()
        $ticketArtifactDirectory = Join-Path $Fixture.ArtifactRoot $TicketId
        if (Test-Path -LiteralPath $ticketArtifactDirectory -PathType Container) {
            foreach ($validationLog in @(Get-ChildItem -LiteralPath $ticketArtifactDirectory -Filter 'validation-*.log' -File -ErrorAction SilentlyContinue)) {
                $validationLogTail += @((Get-Content -LiteralPath $validationLog.FullName -Tail 8 -ErrorAction SilentlyContinue) | ForEach-Object { [string]$_ })
            }
        }
        throw "mode=$Mode ticket=$TicketId expected_exit=$ExpectedExitCode actual_exit=$exitCode output=$($output -join ' | ') validation_tail=$($validationLogTail -join ' | ')"
    }
    return @($output)
}

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

function Set-CandidateOperation {
    param(
        [string]$CandidatePath,
        [AllowEmptyString()][string]$Pattern,
        [AllowEmptyString()][string]$Replacement
    )
    $candidate = Get-Content -LiteralPath $CandidatePath -Raw -Encoding utf8 | ConvertFrom-Json
    $candidate.rounds.D1.operations[0].pattern = $Pattern
    $candidate.rounds.D1.operations[0].replacement = $Replacement
    Write-Utf8Bom -Path $CandidatePath -Text (($candidate | ConvertTo-Json -Depth 16) + "`n")
}

function Set-ChainedRoundFixture {
    param([object]$Fixture)

    Write-Utf8Bom -Path $Fixture.SourcePath -Text "static int target(void)`n{`n    return 0;`n}`n"
    $task = Get-Content -LiteralPath $Fixture.TaskPath -Raw -Encoding utf8 | ConvertFrom-Json
    $task.rounds = [pscustomobject][ordered]@{}
    foreach ($roundSpec in @(
        [pscustomobject]@{ Tag = 'D1'; Before = 'return 0;'; After = 'return 1;' },
        [pscustomobject]@{ Tag = 'D2'; Before = 'return 1;'; After = 'return 2;' },
        [pscustomobject]@{ Tag = 'D3'; Before = 'return 2;'; After = 'return 3;' },
        [pscustomobject]@{ Tag = 'D4'; Before = 'return 3;'; After = 'return 4;' }
    )) {
        $task.rounds | Add-Member -NotePropertyName $roundSpec.Tag -NotePropertyValue ([pscustomobject][ordered]@{
            type = 'regex-patch'
            idempotentContains = @($roundSpec.After)
            operations = @([pscustomobject][ordered]@{
                pattern = [regex]::Escape($roundSpec.Before)
                replacement = $roundSpec.After
                idempotentContains = @($roundSpec.After)
            })
            postApplyAssertions = @(
                [pscustomobject][ordered]@{ name = 'new-token'; pattern = [regex]::Escape($roundSpec.After); expectedCount = 1 },
                [pscustomobject][ordered]@{ name = 'old-token-removed'; pattern = [regex]::Escape($roundSpec.Before); expectedCount = 0 }
            )
        })
    }
    Write-Utf8Bom -Path $Fixture.TaskPath -Text (($task | ConvertTo-Json -Depth 16) + "`n")
}

try {
    $successFixture = New-Fixture -Name 'success'
    $successTaskText = [System.IO.File]::ReadAllText($successFixture.TaskPath).Replace("`n", "`r`n")
    Write-Utf8NoBom -Path $successFixture.TaskPath -Text $successTaskText
    $successOriginal = [System.IO.File]::ReadAllBytes($successFixture.TaskPath)
    [void](Invoke-Transaction -Fixture $successFixture -TicketId 'T-SUCCESS' -Mode Prepare -ExpectedExitCode 0)
    $successDir = Join-Path $successFixture.ArtifactRoot 'T-SUCCESS'
    $successCandidatePath = Join-Path $successDir 'candidate.json'
    Assert-True -Condition (Test-Path -LiteralPath $successCandidatePath) -Message 'success candidate missing after prepare'
    $successCandidateBytes = [System.IO.File]::ReadAllBytes($successCandidatePath)
    Assert-True -Condition ($successCandidateBytes.Length -ge 3 -and $successCandidateBytes[0] -eq 0xEF -and $successCandidateBytes[1] -eq 0xBB -and $successCandidateBytes[2] -eq 0xBF) -Message 'prepared candidate is missing UTF-8 BOM'
    Assert-True -Condition (-not [System.IO.File]::ReadAllText($successCandidatePath).Contains("`r")) -Message 'prepared candidate is not LF-normalized'
    Assert-True -Condition (Test-Path -LiteralPath (Join-Path $successDir 'operation-preview.json')) -Message 'operation preview json missing after prepare'
    Assert-True -Condition (Test-Path -LiteralPath (Join-Path $successDir 'operation-preview.txt')) -Message 'decoded operation preview missing after prepare'
    Assert-True -Condition (Test-Path -LiteralPath (Join-Path $successDir 'apply-patch-context.txt')) -Message 'apply_patch context missing after prepare'
    $successPreview = Get-Content -LiteralPath (Join-Path $successDir 'operation-preview.json') -Raw -Encoding utf8 | ConvertFrom-Json
    Assert-True -Condition ([int]$successPreview.pattern_match_count -eq 1) -Message 'prepare preview should find one match'
    Assert-True -Condition ([int]$successPreview.post_replacement_pattern_match_count -eq 0) -Message 'prepare preview should show converged replacement'
    Assert-True -Condition ([string]$successPreview.candidate_sha256 -eq (Get-FileHash -LiteralPath (Join-Path $successDir 'candidate.json') -Algorithm SHA256).Hash) -Message 'preview candidate hash binding mismatch'
    Assert-True -Condition ([System.Linq.Enumerable]::SequenceEqual([byte[]]$successOriginal, [byte[]][System.IO.File]::ReadAllBytes($successFixture.TaskPath))) -Message 'official changed during prepare'
    $candidateObject = Get-Content -LiteralPath (Join-Path $successDir 'candidate.json') -Raw -Encoding utf8 | ConvertFrom-Json
    $candidateObject.name = 'success-promoted'
    Write-Utf8Bom -Path (Join-Path $successDir 'candidate.json') -Text (($candidateObject | ConvertTo-Json -Depth 16) + "`n")
    $successValidationOutput = Invoke-Transaction -Fixture $successFixture -TicketId 'T-SUCCESS' -Mode Validate -ExpectedExitCode 0
    Assert-True -Condition (($successValidationOutput -join "`n") -match 'preview_stale=true') -Message 'candidate edit should be reported as stale preview'
    [void](Invoke-Transaction -Fixture $successFixture -TicketId 'T-SUCCESS' -Mode Promote -ExpectedExitCode 0)
    $promotedObject = Get-Content -LiteralPath $successFixture.TaskPath -Raw -Encoding utf8 | ConvertFrom-Json
    Assert-True -Condition ([string]$promotedObject.name -eq 'success-promoted') -Message 'official did not receive validated candidate'
    Assert-True -Condition (-not (Test-Path -LiteralPath (Join-Path $successDir 'candidate.json'))) -Message 'candidate not cleaned after promote'
    Assert-True -Condition (-not (Test-Path -LiteralPath (Join-Path $successDir 'baseline.json'))) -Message 'baseline not cleaned after promote'
    Assert-True -Condition (Test-Path -LiteralPath (Join-Path $successDir 'promotion-receipt.json')) -Message 'promotion receipt missing'
    $successReceipt = Get-Content -LiteralPath (Join-Path $successDir 'promotion-receipt.json') -Raw -Encoding utf8 | ConvertFrom-Json
    Assert-True -Condition ((Get-FileHash -LiteralPath $successFixture.TaskPath -Algorithm SHA256).Hash.ToLowerInvariant() -eq [string]$successReceipt.promoted_sha256) -Message 'canonical promoted hash mismatch'
    Write-Output '[TASK-DEFINITION-TRANSACTION-REGRESSION] case=success-promote-cleanup status=pass'

    $crossRoundFixture = New-Fixture -Name 'cross-round' -IncludeAllRounds
    [void](Invoke-Transaction -Fixture $crossRoundFixture -TicketId 'T-CROSS-ROUND' -Mode Prepare -ExpectedExitCode 0 -ValidateThroughRound D4)
    $crossRoundDir = Join-Path $crossRoundFixture.ArtifactRoot 'T-CROSS-ROUND'
    $crossRoundCandidate = Get-Content -LiteralPath (Join-Path $crossRoundDir 'candidate.json') -Raw -Encoding utf8 | ConvertFrom-Json
    $crossRoundCandidate.name = 'cross-round-promoted'
    Write-Utf8Bom -Path (Join-Path $crossRoundDir 'candidate.json') -Text (($crossRoundCandidate | ConvertTo-Json -Depth 16) + "`n")
    [void](Invoke-Transaction -Fixture $crossRoundFixture -TicketId 'T-CROSS-ROUND' -Mode Validate -ExpectedExitCode 0 -ValidateThroughRound D4)
    $crossRoundManifest = Get-Content -LiteralPath (Join-Path $crossRoundDir 'manifest.json') -Raw -Encoding utf8 | ConvertFrom-Json
    Assert-True -Condition ([string]::Join(',', @($crossRoundManifest.round_sequence)) -eq 'D1,D2,D3,D4') -Message 'cross-round sequence binding mismatch'
    Assert-True -Condition ([string]::Join(',', @($crossRoundManifest.validated_rounds)) -eq 'D1,D2,D3,D4') -Message 'cross-round validation coverage mismatch'
    foreach ($round in @('d1', 'd2', 'd3', 'd4')) {
        Assert-True -Condition (Test-Path -LiteralPath (Join-Path $crossRoundDir "validation-round-$round.log")) -Message "cross-round validation log missing round=$round"
    }
    [void](Invoke-Transaction -Fixture $crossRoundFixture -TicketId 'T-CROSS-ROUND' -Mode Promote -ExpectedExitCode 0)
    $crossRoundReceipt = Get-Content -LiteralPath (Join-Path $crossRoundDir 'promotion-receipt.json') -Raw -Encoding utf8 | ConvertFrom-Json
    Assert-True -Condition ([string]::Join(',', @($crossRoundReceipt.validated_rounds)) -eq 'D1,D2,D3,D4') -Message 'promotion receipt cross-round coverage mismatch'
    Assert-True -Condition ((Get-FileHash -LiteralPath $crossRoundFixture.TaskPath -Algorithm SHA256).Hash.ToLowerInvariant() -eq [string]$crossRoundReceipt.promoted_sha256) -Message 'cross-round promoted hash mismatch'
    Write-Output '[TASK-DEFINITION-TRANSACTION-REGRESSION] case=cross-round-single-promote status=pass'

    $chainFixture = New-Fixture -Name 'chain-rounds'
    Set-ChainedRoundFixture -Fixture $chainFixture
    [void](Invoke-Transaction -Fixture $chainFixture -TicketId 'T-CHAIN' -Mode Prepare -ExpectedExitCode 0 -ValidateThroughRound D4 -ChainRounds)
    $chainDir = Join-Path $chainFixture.ArtifactRoot 'T-CHAIN'
    $chainPreparedManifest = Get-Content -LiteralPath (Join-Path $chainDir 'manifest.json') -Raw -Encoding utf8 | ConvertFrom-Json
    Assert-True -Condition ([bool]$chainPreparedManifest.chain_rounds) -Message 'chain mode was not bound in manifest'
    [void](Invoke-Transaction -Fixture $chainFixture -TicketId 'T-CHAIN' -Mode Validate -ExpectedExitCode 1 -ValidateThroughRound D4)
    $chainFailedManifest = Get-Content -LiteralPath (Join-Path $chainDir 'manifest.json') -Raw -Encoding utf8 | ConvertFrom-Json
    Assert-True -Condition ([string]$chainFailedManifest.state -eq 'validation_failed') -Message 'chain binding mismatch should fail validation'
    $chainFailedManifest.state = 'prepared'
    $chainFailedManifest.detail = ''
    Write-Utf8Bom -Path (Join-Path $chainDir 'manifest.json') -Text (($chainFailedManifest | ConvertTo-Json -Depth 16) + "`n")
    [void](Invoke-Transaction -Fixture $chainFixture -TicketId 'T-CHAIN' -Mode Validate -ExpectedExitCode 0 -ValidateThroughRound D4 -ChainRounds)
    $chainValidatedManifest = Get-Content -LiteralPath (Join-Path $chainDir 'manifest.json') -Raw -Encoding utf8 | ConvertFrom-Json
    Assert-True -Condition ([string]::Join(',', @($chainValidatedManifest.validated_rounds)) -eq 'D1,D2,D3,D4') -Message 'chain validation coverage mismatch'
    Assert-True -Condition (Test-Path -LiteralPath (Join-Path $chainDir 'validation-chain-rounds.log')) -Message 'single chain validation log missing'
    Assert-True -Condition (-not (Test-Path -LiteralPath (Join-Path $chainDir 'validation-round-d2.log'))) -Message 'chain validation must not use isolated later-round logs'
    $chainValidationLog = Get-Content -LiteralPath (Join-Path $chainDir 'validation-chain-rounds.log') -Raw -Encoding utf8
    Assert-True -Condition ($chainValidationLog.Contains('scope=D1-D4:chain')) -Message 'chain validation log missing chain scope'
    Write-Output '[TASK-DEFINITION-TRANSACTION-REGRESSION] case=chain-binding-and-single-check status=pass'

    $incompleteChainFixture = New-Fixture -Name 'incomplete-chain-promotion'
    Set-ChainedRoundFixture -Fixture $incompleteChainFixture
    $incompleteChainOriginalHash = (Get-FileHash -LiteralPath $incompleteChainFixture.TaskPath -Algorithm SHA256).Hash
    [void](Invoke-Transaction -Fixture $incompleteChainFixture -TicketId 'T-INCOMPLETE-CHAIN' -Mode Prepare -ExpectedExitCode 0 -ValidateThroughRound D4 -ChainRounds)
    [void](Invoke-Transaction -Fixture $incompleteChainFixture -TicketId 'T-INCOMPLETE-CHAIN' -Mode Validate -ExpectedExitCode 0 -ValidateThroughRound D4 -ChainRounds)
    $incompleteChainDir = Join-Path $incompleteChainFixture.ArtifactRoot 'T-INCOMPLETE-CHAIN'
    $incompleteChainManifestPath = Join-Path $incompleteChainDir 'manifest.json'
    $incompleteChainManifest = Get-Content -LiteralPath $incompleteChainManifestPath -Raw -Encoding utf8 | ConvertFrom-Json
    $incompleteChainManifest.validated_rounds = @('D1')
    Write-Utf8Bom -Path $incompleteChainManifestPath -Text (($incompleteChainManifest | ConvertTo-Json -Depth 16) + "`n")
    [void](Invoke-Transaction -Fixture $incompleteChainFixture -TicketId 'T-INCOMPLETE-CHAIN' -Mode Promote -ExpectedExitCode 1 -ValidateThroughRound D4 -ChainRounds)
    Assert-True -Condition ((Get-FileHash -LiteralPath $incompleteChainFixture.TaskPath -Algorithm SHA256).Hash -eq $incompleteChainOriginalHash) -Message 'incomplete chain coverage changed official task definition'
    Assert-True -Condition (Test-Path -LiteralPath (Join-Path $incompleteChainDir 'candidate.json')) -Message 'incomplete chain coverage should retain candidate'
    Write-Output '[TASK-DEFINITION-TRANSACTION-REGRESSION] case=incomplete-chain-promotion-blocked status=pass'

    $inspectChainFixture = New-Fixture -Name 'inspect-chain-baseline'
    Set-ChainedRoundFixture -Fixture $inspectChainFixture
    $inspectChainTask = Get-Content -LiteralPath $inspectChainFixture.TaskPath -Raw -Encoding utf8 | ConvertFrom-Json
    $inspectChainTask.rounds.D3.operations[0].pattern = 'return 0;'
    $inspectChainTask.rounds.D3.operations[0].replacement = 'return 3;'
    $inspectChainTask.rounds.D3.operations[0].idempotentContains = @('return 3;')
    Write-Utf8Bom -Path $inspectChainFixture.TaskPath -Text (($inspectChainTask | ConvertTo-Json -Depth 16) + "`n")
    [void](Invoke-Transaction -Fixture $inspectChainFixture -TicketId 'T-INSPECT-CHAIN' -Mode Prepare -ExpectedExitCode 0 -RoundTag D3 -ValidateThroughRound D4 -ChainRounds)
    $inspectChainDir = Join-Path $inspectChainFixture.ArtifactRoot 'T-INSPECT-CHAIN'
    $inspectChainPreview = Get-Content -LiteralPath (Join-Path $inspectChainDir 'operation-preview.json') -Raw -Encoding utf8 | ConvertFrom-Json
    Assert-True -Condition ([int]$inspectChainPreview.pattern_match_count -eq 1) -Message 'chain Inspect must start from current fault-round source without replaying earlier rounds'
    Assert-True -Condition (@($inspectChainPreview.prerequisite_simulation).Count -eq 0) -Message 'chain Inspect must only simulate earlier ops in the fault round'
    Write-Output '[TASK-DEFINITION-TRANSACTION-REGRESSION] case=chain-inspect-current-source-baseline status=pass'

    $invalidFixture = New-Fixture -Name 'invalid-candidate'
    $invalidOfficialHash = (Get-FileHash -LiteralPath $invalidFixture.TaskPath -Algorithm SHA256).Hash
    [void](Invoke-Transaction -Fixture $invalidFixture -TicketId 'T-INVALID' -Mode Prepare -ExpectedExitCode 0)
    $invalidDir = Join-Path $invalidFixture.ArtifactRoot 'T-INVALID'
    Write-Utf8Bom -Path (Join-Path $invalidDir 'candidate.json') -Text '{ invalid json'
    [void](Invoke-Transaction -Fixture $invalidFixture -TicketId 'T-INVALID' -Mode Validate -ExpectedExitCode 1)
    Assert-True -Condition ((Get-FileHash -LiteralPath $invalidFixture.TaskPath -Algorithm SHA256).Hash -eq $invalidOfficialHash) -Message 'official changed after validation failure'
    Assert-True -Condition (Test-Path -LiteralPath (Join-Path $invalidDir 'candidate.json')) -Message 'failed candidate should be retained'
    $invalidManifest = Get-Content -LiteralPath (Join-Path $invalidDir 'manifest.json') -Raw -Encoding utf8 | ConvertFrom-Json
    Assert-True -Condition ([string]$invalidManifest.state -eq 'validation_failed') -Message 'validation failure state missing'
    Write-Output '[TASK-DEFINITION-TRANSACTION-REGRESSION] case=validation-failure-retained status=pass'

    $baselineFixture = New-Fixture -Name 'baseline-drift'
    [void](Invoke-Transaction -Fixture $baselineFixture -TicketId 'T-BASELINE-DRIFT' -Mode Prepare -ExpectedExitCode 0)
    $baselineObject = Get-Content -LiteralPath $baselineFixture.TaskPath -Raw -Encoding utf8 | ConvertFrom-Json
    $baselineObject.name = 'external-change'
    Write-Utf8Bom -Path $baselineFixture.TaskPath -Text (($baselineObject | ConvertTo-Json -Depth 16) + "`n")
    [void](Invoke-Transaction -Fixture $baselineFixture -TicketId 'T-BASELINE-DRIFT' -Mode Validate -ExpectedExitCode 1)
    $baselineAfter = Get-Content -LiteralPath $baselineFixture.TaskPath -Raw -Encoding utf8 | ConvertFrom-Json
    Assert-True -Condition ([string]$baselineAfter.name -eq 'external-change') -Message 'baseline drift was overwritten'
    Write-Output '[TASK-DEFINITION-TRANSACTION-REGRESSION] case=baseline-drift-blocked status=pass'

    $candidateFixture = New-Fixture -Name 'candidate-drift'
    $candidateOfficialHash = (Get-FileHash -LiteralPath $candidateFixture.TaskPath -Algorithm SHA256).Hash
    [void](Invoke-Transaction -Fixture $candidateFixture -TicketId 'T-CANDIDATE-DRIFT' -Mode Prepare -ExpectedExitCode 0)
    [void](Invoke-Transaction -Fixture $candidateFixture -TicketId 'T-CANDIDATE-DRIFT' -Mode Validate -ExpectedExitCode 0)
    $candidateDir = Join-Path $candidateFixture.ArtifactRoot 'T-CANDIDATE-DRIFT'
    Add-Content -LiteralPath (Join-Path $candidateDir 'candidate.json') -Value ' ' -Encoding utf8
    [void](Invoke-Transaction -Fixture $candidateFixture -TicketId 'T-CANDIDATE-DRIFT' -Mode Promote -ExpectedExitCode 1)
    Assert-True -Condition ((Get-FileHash -LiteralPath $candidateFixture.TaskPath -Algorithm SHA256).Hash -eq $candidateOfficialHash) -Message 'official changed after candidate drift'
    Assert-True -Condition (Test-Path -LiteralPath (Join-Path $candidateDir 'candidate.json')) -Message 'drifted candidate should be retained'
    Write-Output '[TASK-DEFINITION-TRANSACTION-REGRESSION] case=candidate-drift-blocked status=pass'

    $quarantineFixture = New-Fixture -Name 'quarantine'
    [void](Invoke-Transaction -Fixture $quarantineFixture -TicketId 'T-QUARANTINE' -Mode Prepare -ExpectedExitCode 0)
    [void](& $transactionScript -Mode Quarantine -TaskDefinitionFile $quarantineFixture.TaskPath -TicketId 'T-QUARANTINE' -Stage A -RoundTag D1 -OperationIndex 1 -ArtifactRoot $quarantineFixture.ArtifactRoot -Reason 'tool-call-parameter-corruption')
    $quarantineManifest = Get-Content -LiteralPath (Join-Path $quarantineFixture.ArtifactRoot 'T-QUARANTINE\manifest.json') -Raw -Encoding utf8 | ConvertFrom-Json
    Assert-True -Condition ([string]$quarantineManifest.state -eq 'quarantined') -Message 'quarantine state missing'
    Assert-True -Condition (Test-Path -LiteralPath (Join-Path $quarantineFixture.ArtifactRoot 'T-QUARANTINE\candidate.json')) -Message 'quarantined candidate should be retained'
    [void](Invoke-Transaction -Fixture $quarantineFixture -TicketId 'T-QUARANTINE' -Mode Validate -ExpectedExitCode 1)
    $quarantineManifestAfterValidate = Get-Content -LiteralPath (Join-Path $quarantineFixture.ArtifactRoot 'T-QUARANTINE\manifest.json') -Raw -Encoding utf8 | ConvertFrom-Json
    Assert-True -Condition ([string]$quarantineManifestAfterValidate.state -eq 'quarantined') -Message 'quarantine terminal state was changed by validate'
    Write-Output '[TASK-DEFINITION-TRANSACTION-REGRESSION] case=quarantine-retained status=pass'

    $inspectFixture = New-Fixture -Name 'inspect-refresh'
    [void](Invoke-Transaction -Fixture $inspectFixture -TicketId 'T-INSPECT' -Mode Prepare -ExpectedExitCode 0)
    $inspectDir = Join-Path $inspectFixture.ArtifactRoot 'T-INSPECT'
    $inspectCandidatePath = Join-Path $inspectDir 'candidate.json'
    Set-CandidateOperation -CandidatePath $inspectCandidatePath -Pattern 'missing token' -Replacement 'return 2;'
    $inspectOutput = Invoke-Transaction -Fixture $inspectFixture -TicketId 'T-INSPECT' -Mode Inspect -ExpectedExitCode 0
    Assert-True -Condition (($inspectOutput -join "`n") -match 'pattern_match_count=0') -Message 'inspect should report zero matches'
    $inspectManifest = Get-Content -LiteralPath (Join-Path $inspectDir 'manifest.json') -Raw -Encoding utf8 | ConvertFrom-Json
    Assert-True -Condition (-not [bool]$inspectManifest.preview_stale) -Message 'inspect should refresh stale preview binding'
    Assert-True -Condition ([string]$inspectManifest.preview_candidate_sha256 -eq (Get-FileHash -LiteralPath $inspectCandidatePath -Algorithm SHA256).Hash) -Message 'inspect did not refresh candidate hash binding'
    Write-Output '[TASK-DEFINITION-TRANSACTION-REGRESSION] case=inspect-zero-match-refresh status=pass'

    $lateBindFixture = New-Fixture -Name 'inspect-late-operation-binding'
    $lateBindPrepareOutput = Invoke-Transaction -Fixture $lateBindFixture -TicketId 'T-INSPECT-LATE-BIND' -Mode Prepare -ExpectedExitCode 0 -OperationIndex 0
    Assert-True -Condition (($lateBindPrepareOutput -join "`n") -match 'preview_unavailable=true') -Message 'unfocused Prepare should report unavailable preview'
    $lateBindDir = Join-Path $lateBindFixture.ArtifactRoot 'T-INSPECT-LATE-BIND'
    Assert-True -Condition (-not (Test-Path -LiteralPath (Join-Path $lateBindDir 'operation-preview.json'))) -Message 'unfocused Prepare unexpectedly generated preview'
    [void](Invoke-Transaction -Fixture $lateBindFixture -TicketId 'T-INSPECT-LATE-BIND' -Mode Inspect -ExpectedExitCode 0 -OperationIndex 1)
    $lateBindManifest = Get-Content -LiteralPath (Join-Path $lateBindDir 'manifest.json') -Raw -Encoding utf8 | ConvertFrom-Json
    Assert-True -Condition ([int]$lateBindManifest.operation_index -eq 1) -Message 'Inspect did not persist late operation binding'
    Assert-True -Condition (Test-Path -LiteralPath (Join-Path $lateBindDir 'operation-preview.json')) -Message 'late-bound Inspect did not generate preview'
    Write-Output '[TASK-DEFINITION-TRANSACTION-REGRESSION] case=inspect-late-operation-binding status=pass'

    $multiFixture = New-Fixture -Name 'multi-match'
    Write-Utf8Bom -Path $multiFixture.SourcePath -Text "static int target(void)`n{`n    return 1;`n    return 1;`n}`n"
    $multiOutput = Invoke-Transaction -Fixture $multiFixture -TicketId 'T-MULTI' -Mode Prepare -ExpectedExitCode 0
    Assert-True -Condition (($multiOutput -join "`n") -match 'pattern_match_count=2') -Message 'prepare should report multiple matches'
    Write-Output '[TASK-DEFINITION-TRANSACTION-REGRESSION] case=multi-match-preview status=pass'

    $remainsFixture = New-Fixture -Name 'remains-matchable'
    [void](Invoke-Transaction -Fixture $remainsFixture -TicketId 'T-REMAINS' -Mode Prepare -ExpectedExitCode 0)
    $remainsCandidatePath = Join-Path $remainsFixture.ArtifactRoot 'T-REMAINS\candidate.json'
    Set-CandidateOperation -CandidatePath $remainsCandidatePath -Pattern 'return\s+\d;' -Replacement 'return 2;'
    [void](Invoke-Transaction -Fixture $remainsFixture -TicketId 'T-REMAINS' -Mode Inspect -ExpectedExitCode 0)
    $remainsPreview = Get-Content -LiteralPath (Join-Path $remainsFixture.ArtifactRoot 'T-REMAINS\operation-preview.json') -Raw -Encoding utf8 | ConvertFrom-Json
    Assert-True -Condition ([int]$remainsPreview.post_replacement_pattern_match_count -eq 1) -Message 'preview should expose pattern remaining matchable'
    Write-Output '[TASK-DEFINITION-TRANSACTION-REGRESSION] case=post-replacement-remains-matchable status=pass'

    $escapeFixture = New-Fixture -Name 'double-escape'
    [void](Invoke-Transaction -Fixture $escapeFixture -TicketId 'T-ESCAPE' -Mode Prepare -ExpectedExitCode 0)
    $escapeCandidatePath = Join-Path $escapeFixture.ArtifactRoot 'T-ESCAPE\candidate.json'
    Set-CandidateOperation -CandidatePath $escapeCandidatePath -Pattern 'return 1;' -Replacement 'return 2;\n'
    [void](Invoke-Transaction -Fixture $escapeFixture -TicketId 'T-ESCAPE' -Mode Inspect -ExpectedExitCode 0)
    $escapePreview = Get-Content -LiteralPath (Join-Path $escapeFixture.ArtifactRoot 'T-ESCAPE\operation-preview.json') -Raw -Encoding utf8 | ConvertFrom-Json
    Assert-True -Condition ([bool]$escapePreview.possible_double_escape) -Message 'preview should flag literal backslash-n risk'
    $escapeDecoded = Get-Content -LiteralPath (Join-Path $escapeFixture.ArtifactRoot 'T-ESCAPE\operation-preview.txt') -Raw -Encoding utf8
    Assert-True -Condition ($escapeDecoded.Contains('possible_double_escape=true')) -Message 'decoded sidecar should expose double escape warning'
    Write-Output '[TASK-DEFINITION-TRANSACTION-REGRESSION] case=double-escape-warning status=pass'

    Write-Output '[TASK-DEFINITION-TRANSACTION-REGRESSION] summary pass=14 fail=0'
}
finally {
    Remove-Item -LiteralPath $caseRoot -Recurse -Force -ErrorAction SilentlyContinue
}