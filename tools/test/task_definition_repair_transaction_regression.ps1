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

function New-Fixture {
    param([string]$Name)
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
        [int]$ExpectedExitCode
    )
    $previousErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = @(& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $transactionScript -Mode $Mode -TaskDefinitionFile $Fixture.TaskPath -TicketId $TicketId -Stage A -RoundTag D1 -OperationIndex 1 -ArtifactRoot $Fixture.ArtifactRoot 2>&1 | ForEach-Object { [string]$_ })
        $exitCode = if ($null -eq $LASTEXITCODE) { 0 } else { [int]$LASTEXITCODE }
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    if ($exitCode -ne $ExpectedExitCode) {
        throw "mode=$Mode ticket=$TicketId expected_exit=$ExpectedExitCode actual_exit=$exitCode output=$($output -join ' | ')"
    }
    return @($output)
}

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

try {
    $successFixture = New-Fixture -Name 'success'
    $successOriginal = [System.IO.File]::ReadAllBytes($successFixture.TaskPath)
    [void](Invoke-Transaction -Fixture $successFixture -TicketId 'T-SUCCESS' -Mode Prepare -ExpectedExitCode 0)
    $successDir = Join-Path $successFixture.ArtifactRoot 'T-SUCCESS'
    Assert-True -Condition (Test-Path -LiteralPath (Join-Path $successDir 'candidate.json')) -Message 'success candidate missing after prepare'
    Assert-True -Condition ([System.Linq.Enumerable]::SequenceEqual([byte[]]$successOriginal, [byte[]][System.IO.File]::ReadAllBytes($successFixture.TaskPath))) -Message 'official changed during prepare'
    $candidateObject = Get-Content -LiteralPath (Join-Path $successDir 'candidate.json') -Raw -Encoding utf8 | ConvertFrom-Json
    $candidateObject.name = 'success-promoted'
    Write-Utf8Bom -Path (Join-Path $successDir 'candidate.json') -Text (($candidateObject | ConvertTo-Json -Depth 16) + "`n")
    [void](Invoke-Transaction -Fixture $successFixture -TicketId 'T-SUCCESS' -Mode Validate -ExpectedExitCode 0)
    [void](Invoke-Transaction -Fixture $successFixture -TicketId 'T-SUCCESS' -Mode Promote -ExpectedExitCode 0)
    $promotedObject = Get-Content -LiteralPath $successFixture.TaskPath -Raw -Encoding utf8 | ConvertFrom-Json
    Assert-True -Condition ([string]$promotedObject.name -eq 'success-promoted') -Message 'official did not receive validated candidate'
    Assert-True -Condition (-not (Test-Path -LiteralPath (Join-Path $successDir 'candidate.json'))) -Message 'candidate not cleaned after promote'
    Assert-True -Condition (-not (Test-Path -LiteralPath (Join-Path $successDir 'baseline.json'))) -Message 'baseline not cleaned after promote'
    Assert-True -Condition (Test-Path -LiteralPath (Join-Path $successDir 'promotion-receipt.json')) -Message 'promotion receipt missing'
    Write-Output '[TASK-DEFINITION-TRANSACTION-REGRESSION] case=success-promote-cleanup status=pass'

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
    Write-Output '[TASK-DEFINITION-TRANSACTION-REGRESSION] case=quarantine-retained status=pass'

    Write-Output '[TASK-DEFINITION-TRANSACTION-REGRESSION] summary pass=5 fail=0'
}
finally {
    Remove-Item -LiteralPath $caseRoot -Recurse -Force -ErrorAction SilentlyContinue
}