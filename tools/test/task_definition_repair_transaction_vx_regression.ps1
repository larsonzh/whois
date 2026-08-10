param([AllowEmptyString()][string]$OutDirRoot = '')

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$transactionScript = Join-Path $PSScriptRoot 'task_definition_repair_transaction.ps1'
if ([string]::IsNullOrWhiteSpace($OutDirRoot)) { $OutDirRoot = Join-Path $repoRoot 'tmp\task-definition-repair-vx-regression' }
$runRoot = Join-Path $OutDirRoot ([guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $runRoot -Force | Out-Null

function Get-TextSha256([string]$Text) {
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha256.ComputeHash([Text.UTF8Encoding]::new($false).GetBytes($Text)))).Replace('-', '').ToLowerInvariant() }
    finally { $sha256.Dispose() }
}

function Write-Json([string]$Path, [object]$Value) {
    [IO.File]::WriteAllText($Path, (($Value | ConvertTo-Json -Depth 30) + "`n"), [Text.UTF8Encoding]::new($true))
}

function New-VxFixture([string]$Name) {
    $root = Join-Path $runRoot $Name
    $fixture = Join-Path $root 'fixture'
    New-Item -ItemType Directory -Path $fixture -Force | Out-Null
    $sourceA = Join-Path $fixture 'a.c'
    $sourceB = Join-Path $fixture 'b.c'
    [IO.File]::WriteAllText($sourceA, "static int alpha(void) { return 1; }`n", [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText($sourceB, "static int beta(void) { return 2; }`n", [Text.UTF8Encoding]::new($false))
    $relativeRoot = $fixture.Substring($repoRoot.Length).TrimStart('\', '/').Replace('\', '/')
    $headerContent = "#define VX_REPAIR_HEADER 1`n"
    $task = [ordered]@{
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
                    [ordered]@{ target = 'source_a'; pattern = 'return 1;'; replacement = 'return 11; /* VX_REPAIR_A1 */'; idempotentContains = @('VX_REPAIR_A1') },
                    [ordered]@{ type = 'create-file'; target = 'created_header'; content = $headerContent; contentSha256 = (Get-TextSha256 $headerContent); existingPolicy = 'skip'; idempotentContains = @('VX_REPAIR_HEADER') },
                    [ordered]@{ target = 'source_a'; pattern = 'return 11; /\* VX_REPAIR_A1 \*/'; replacement = 'return 111; /* VX_REPAIR_A1 VX_REPAIR_A3 */'; idempotentContains = @('VX_REPAIR_A3') }
                )
                idempotentContainsByTarget = [ordered]@{ source_a = @('VX_REPAIR_A3'); created_header = @('VX_REPAIR_HEADER') }
                postApplyAssertions = @(
                    [ordered]@{ name = 'a-final'; target = 'source_a'; pattern = 'VX_REPAIR_A3'; expectedCount = 1 },
                    [ordered]@{ name = 'header-created'; target = 'created_header'; pattern = 'VX_REPAIR_HEADER'; expectedCount = 1 }
                )
            }
            D2 = [ordered]@{ type = 'noop'; description = 'fixture' }
            D3 = [ordered]@{ type = 'noop'; description = 'fixture' }
            D4 = [ordered]@{ type = 'noop'; description = 'fixture' }
        }
    }
    $taskPath = Join-Path $root 'task.json'
    Write-Json $taskPath $task
    return [pscustomobject]@{ Root = $root; Task = $taskPath; ArtifactRoot = (Join-Path $root 'artifacts') }
}

function Invoke-Transaction(
    [object]$Fixture,
    [string]$Ticket,
    [string]$Mode,
    [int]$ExpectedExit,
    [int]$OperationIndex = 3,
    [switch]$ChainRounds,
    [AllowEmptyString()][string]$ValidateThroughRound = ''
) {
    $arguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $transactionScript, '-Mode', $Mode,
        '-TaskDefinitionFile', $Fixture.Task, '-TicketId', $Ticket, '-Stage', 'A', '-RoundTag', 'D1',
        '-OperationIndex', [string]$OperationIndex, '-ArtifactRoot', $Fixture.ArtifactRoot)
    if ($ChainRounds.IsPresent) { $arguments += '-ChainRounds' }
    if (-not [string]::IsNullOrWhiteSpace($ValidateThroughRound)) { $arguments += @('-ValidateThroughRound', $ValidateThroughRound) }
    $oldPreference = $ErrorActionPreference
    try { $ErrorActionPreference = 'Continue'; $output = @(& powershell @arguments 2>&1 | ForEach-Object { [string]$_ }); $exitCode = $LASTEXITCODE }
    finally { $ErrorActionPreference = $oldPreference }
    if ($exitCode -ne $ExpectedExit) { throw "mode=$Mode ticket=$Ticket expected=$ExpectedExit actual=$exitCode output=$($output -join ' | ')" }
    return $output
}

function Assert-True([bool]$Condition, [string]$Message) { if (-not $Condition) { throw $Message } }

try {
    $previewFixture = New-VxFixture 'preview'
    [void](Invoke-Transaction $previewFixture 'VX-PREVIEW' 'Prepare' 0)
    $previewDir = Join-Path $previewFixture.ArtifactRoot 'VX-PREVIEW'
    $manifest = Get-Content -LiteralPath (Join-Path $previewDir 'manifest.json') -Raw -Encoding utf8 | ConvertFrom-Json
    $preview = Get-Content -LiteralPath (Join-Path $previewDir 'operation-preview.json') -Raw -Encoding utf8 | ConvertFrom-Json
    Assert-True ($manifest.schema_version -eq 'vx-draft' -and -not [string]::IsNullOrWhiteSpace([string]$manifest.target_set_sha256)) 'Prepare manifest missing Vx registry binding'
    Assert-True (@($manifest.targets).Count -eq 3 -and @($manifest.targets | Where-Object { $_.id -eq 'created_header' -and -not $_.baseline_exists }).Count -eq 1) 'Prepare target baseline inventory mismatch'
    Assert-True ($preview.schema -eq 'TASK_DEFINITION_OPERATION_PREVIEW_VX1' -and @($preview.prerequisite_simulation).Count -eq 2) 'Vx preview did not simulate all preceding operations'
    Assert-True ($preview.prerequisite_simulation[0].target_id -eq 'source_a' -and $preview.prerequisite_simulation[1].target_id -eq 'created_header') 'Vx preview lost cross-file operation order'
    Assert-True ($preview.prerequisite_simulation[1].status -eq 'created' -and $preview.prerequisite_simulation[1].create_content_sha256_declared -eq $preview.prerequisite_simulation[1].create_content_sha256_calculated) 'Vx create-file preview hash/status mismatch'
    Assert-True ($preview.target_id -eq 'source_a' -and $preview.pattern_match_count -eq 1 -and $preview.target_sha256_before -ne $preview.target_sha256_after) 'Vx target operation before/after binding mismatch'
    Write-Output '[REPAIR-VX-REGRESSION] case=preview-cross-file-and-create status=pass'

    $createPreviewFixture = New-VxFixture 'create-preview'
    [void](Invoke-Transaction $createPreviewFixture 'VX-CREATE-PREVIEW' 'Prepare' 0 2)
    $createPreview = Get-Content -LiteralPath (Join-Path $createPreviewFixture.ArtifactRoot 'VX-CREATE-PREVIEW\operation-preview.json') -Raw -Encoding utf8 | ConvertFrom-Json
    Assert-True ($createPreview.operation_type -eq 'create-file' -and $createPreview.target_id -eq 'created_header') 'create-file target preview identity mismatch'
    Assert-True ($createPreview.create_status -eq 'created' -and $createPreview.create_content_sha256_declared -eq $createPreview.create_content_sha256_calculated) 'create-file target preview hash/status mismatch'
    Assert-True (-not $createPreview.target_exists_before -and $createPreview.target_exists_after) 'create-file target preview existence transition mismatch'
    Write-Output '[REPAIR-VX-REGRESSION] case=create-file-target-preview status=pass'

    $validateDrift = New-VxFixture 'validate-drift'
    [void](Invoke-Transaction $validateDrift 'VX-VALIDATE-DRIFT' 'Prepare' 0)
    $validateDir = Join-Path $validateDrift.ArtifactRoot 'VX-VALIDATE-DRIFT'
    $candidatePath = Join-Path $validateDir 'candidate.json'
    $candidate = Get-Content -LiteralPath $candidatePath -Raw -Encoding utf8 | ConvertFrom-Json
    $candidate.targetFiles[1].kind = 'text'
    Write-Json $candidatePath $candidate
    $validateOutput = Invoke-Transaction $validateDrift 'VX-VALIDATE-DRIFT' 'Validate' 1
    Assert-True (($validateOutput -join "`n") -match 'target registry drift') 'Validate registry drift did not fail closed'
    Write-Output '[REPAIR-VX-REGRESSION] case=validate-registry-drift-blocked status=pass'

    $promoteDrift = New-VxFixture 'promote-drift'
    [void](Invoke-Transaction $promoteDrift 'VX-PROMOTE-DRIFT' 'Prepare' 0)
    [void](Invoke-Transaction $promoteDrift 'VX-PROMOTE-DRIFT' 'Validate' 0)
    $promoteDir = Join-Path $promoteDrift.ArtifactRoot 'VX-PROMOTE-DRIFT'
    $promoteCandidatePath = Join-Path $promoteDir 'candidate.json'
    $promoteCandidate = Get-Content -LiteralPath $promoteCandidatePath -Raw -Encoding utf8 | ConvertFrom-Json
    $promoteCandidate.targetFiles[1].kind = 'text'
    Write-Json $promoteCandidatePath $promoteCandidate
    $promoteManifestPath = Join-Path $promoteDir 'manifest.json'
    $promoteManifest = Get-Content -LiteralPath $promoteManifestPath -Raw -Encoding utf8 | ConvertFrom-Json
    $promoteManifest.validated_candidate_sha256 = (Get-FileHash -LiteralPath $promoteCandidatePath -Algorithm SHA256).Hash.ToLowerInvariant()
    Write-Json $promoteManifestPath $promoteManifest
    $promoteOutput = Invoke-Transaction $promoteDrift 'VX-PROMOTE-DRIFT' 'Promote' 1
    Assert-True (($promoteOutput -join "`n") -match 'target registry drift') 'Promote registry drift did not fail closed'
    Write-Output '[REPAIR-VX-REGRESSION] case=promote-registry-drift-blocked status=pass'

    $receiptFixture = New-VxFixture 'receipt'
    [void](Invoke-Transaction $receiptFixture 'VX-RECEIPT' 'Prepare' 0)
    [void](Invoke-Transaction $receiptFixture 'VX-RECEIPT' 'Validate' 0)
    [void](Invoke-Transaction $receiptFixture 'VX-RECEIPT' 'Promote' 0)
    $receiptDir = Join-Path $receiptFixture.ArtifactRoot 'VX-RECEIPT'
    $receipt = Get-Content -LiteralPath (Join-Path $receiptDir 'promotion-receipt.json') -Raw -Encoding utf8 | ConvertFrom-Json
    $receiptManifest = Get-Content -LiteralPath (Join-Path $receiptDir 'manifest.json') -Raw -Encoding utf8 | ConvertFrom-Json
    Assert-True ($receipt.target_set_sha256 -eq $receiptManifest.target_set_sha256 -and @($receipt.targets).Count -eq 3) 'promotion receipt missing target-set binding'
    Write-Output '[REPAIR-VX-REGRESSION] case=receipt-target-set-binding status=pass'

    $chainFixture = New-VxFixture 'chain'
    [void](Invoke-Transaction $chainFixture 'VX-CHAIN' 'Prepare' 0 3 -ChainRounds -ValidateThroughRound D4)
    [void](Invoke-Transaction $chainFixture 'VX-CHAIN' 'Validate' 0 3 -ChainRounds -ValidateThroughRound D4)
    $chainManifest = Get-Content -LiteralPath (Join-Path $chainFixture.ArtifactRoot 'VX-CHAIN\manifest.json') -Raw -Encoding utf8 | ConvertFrom-Json
    Assert-True ([string]::Join(',', @($chainManifest.validated_rounds)) -eq 'D1,D2,D3,D4') 'Vx ChainRounds validation coverage mismatch'
    Assert-True (Test-Path -LiteralPath (Join-Path $chainFixture.ArtifactRoot 'VX-CHAIN\validation-chain-rounds.log') -PathType Leaf) 'Vx ChainRounds validation log missing'
    Write-Output '[REPAIR-VX-REGRESSION] case=focused-full-chain-validation status=pass'
    Write-Output '[REPAIR-VX-REGRESSION] status=PASS'
}
finally {
    Remove-Item -LiteralPath $runRoot -Recurse -Force -ErrorAction SilentlyContinue
    if ((Test-Path -LiteralPath $OutDirRoot) -and @((Get-ChildItem -LiteralPath $OutDirRoot -Force -ErrorAction SilentlyContinue)).Count -eq 0) {
        Remove-Item -LiteralPath $OutDirRoot -Force -ErrorAction SilentlyContinue
    }
}