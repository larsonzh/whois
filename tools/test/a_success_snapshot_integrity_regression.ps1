param(
    [string]$OutDirRoot = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'a_success_snapshot_integrity.ps1')

if ([string]::IsNullOrWhiteSpace($OutDirRoot)) {
    $repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
    $OutDirRoot = Join-Path $repositoryRoot 'tmp\a-success-snapshot-integrity'
}
$caseRoot = Join-Path $OutDirRoot ([guid]::NewGuid().ToString('N'))
$snapshotDir = Join-Path $caseRoot 'a_success_snapshot'
$sourceDir = Join-Path $snapshotDir 'source'
$destinationDir = Join-Path $caseRoot 'destination'
$targetRelative = 'src/core/fixture.c'
$targetSnapshot = Join-Path $sourceDir $targetRelative.Replace('/', '\')
$targetDestination = Join-Path $destinationDir $targetRelative.Replace('/', '\')
$taskDefinition = Join-Path $caseRoot 'task.json'

function Write-Utf8NoBom {
    param([string]$Path, [string]$Text)

    $parent = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    [System.IO.File]::WriteAllText($Path, $Text, [System.Text.UTF8Encoding]::new($false))
}

function Assert-IntegrityResult {
    param(
        [string]$Name,
        [object]$Result,
        [bool]$ExpectedPass,
        [string]$ExpectedError = ''
    )

    if ([bool]$Result.Pass -ne $ExpectedPass) {
        throw "case=$Name expected_pass=$ExpectedPass actual_pass=$($Result.Pass) errors=$($Result.Errors -join ',')"
    }
    if (-not [string]::IsNullOrWhiteSpace($ExpectedError) -and -not (@($Result.Errors) -match [regex]::Escape($ExpectedError))) {
        throw "case=$Name missing_error=$ExpectedError errors=$($Result.Errors -join ',')"
    }
    Write-Output "[A-SNAPSHOT-INTEGRITY-REGRESSION] case=$Name status=pass"
}

try {
    New-Item -ItemType Directory -Path (Split-Path -Parent $targetSnapshot) -Force | Out-Null
    New-Item -ItemType Directory -Path (Split-Path -Parent $targetDestination) -Force | Out-Null
    Write-Utf8NoBom -Path $targetSnapshot -Text "int fixture(void) { return 1; }`n"
    Copy-Item -LiteralPath $targetSnapshot -Destination $targetDestination -Force
    Write-Utf8NoBom -Path (Join-Path $snapshotDir 'source_files.txt') -Text "$targetRelative`n"
    Write-Utf8NoBom -Path $taskDefinition -Text (@{
        schemaVersion = 1
        targetFile = $targetRelative
        rounds = @{ D1 = @{ type = 'noop'; description = 'fixture' } }
    } | ConvertTo-Json -Depth 6)

    $allowedPaths = @(Get-ASnapshotTaskTargetPaths -TaskDefinitionFile $taskDefinition)
    $null = Write-ASuccessSnapshotManifest -SnapshotDir $snapshotDir
    $valid = Test-ASuccessSnapshotIntegrity -SnapshotDir $snapshotDir -AllowedPaths $allowedPaths -DestinationRoot $destinationDir
    Assert-IntegrityResult -Name 'valid-manifest-and-destination' -Result $valid -ExpectedPass $true

    Write-Utf8NoBom -Path $targetSnapshot -Text "int fixture(void) { return 2; }`n"
    $tampered = Test-ASuccessSnapshotIntegrity -SnapshotDir $snapshotDir -AllowedPaths $allowedPaths
    Assert-IntegrityResult -Name 'snapshot-byte-tamper-blocked' -Result $tampered -ExpectedPass $false -ExpectedError 'snapshot-hash-mismatch'

    Write-Utf8NoBom -Path $targetSnapshot -Text "int fixture(void) { return 1; }`n"
    $unexpectedRelative = 'src/core/unexpected.c'
    Write-Utf8NoBom -Path (Join-Path $sourceDir $unexpectedRelative.Replace('/', '\')) -Text "int unexpected;`n"
    Write-Utf8NoBom -Path (Join-Path $snapshotDir 'source_files.txt') -Text "$targetRelative`n$unexpectedRelative`n"
    $null = Write-ASuccessSnapshotManifest -SnapshotDir $snapshotDir
    $unexpected = Test-ASuccessSnapshotIntegrity -SnapshotDir $snapshotDir -AllowedPaths $allowedPaths
    Assert-IntegrityResult -Name 'task-target-boundary-blocked' -Result $unexpected -ExpectedPass $false -ExpectedError 'path-not-allowed'

    Remove-Item -LiteralPath (Join-Path $sourceDir $unexpectedRelative.Replace('/', '\')) -Force
    Write-Utf8NoBom -Path (Join-Path $snapshotDir 'source_files.txt') -Text "$targetRelative`n"
    $null = Write-ASuccessSnapshotManifest -SnapshotDir $snapshotDir
    Write-Utf8NoBom -Path $targetDestination -Text "int fixture(void) { return 3; }`n"
    $destinationMismatch = Test-ASuccessSnapshotIntegrity -SnapshotDir $snapshotDir -AllowedPaths $allowedPaths -DestinationRoot $destinationDir
    Assert-IntegrityResult -Name 'post-restore-hash-mismatch-blocked' -Result $destinationMismatch -ExpectedPass $false -ExpectedError 'destination-hash-mismatch'

    $vxSnapshotDir = Join-Path $caseRoot 'vx_snapshot'
    $vxSourceDir = Join-Path $vxSnapshotDir 'source'
    $vxDestinationDir = Join-Path $caseRoot 'vx_destination'
    $vxExistingRelative = $caseRoot.Substring((Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path.Length).TrimStart('\').Replace('\', '/') + '/vx-existing.txt'
    $vxMissingRelative = $caseRoot.Substring((Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path.Length).TrimStart('\').Replace('\', '/') + '/vx-missing.txt'
    $vxExistingSource = Join-Path $caseRoot 'vx-existing.txt'
    $vxExistingSnapshot = Join-Path $vxSourceDir $vxExistingRelative.Replace('/', '\')
    $vxExistingDestination = Join-Path $vxDestinationDir $vxExistingRelative.Replace('/', '\')
    $vxMissingSnapshot = Join-Path $vxSourceDir $vxMissingRelative.Replace('/', '\')
    $vxMissingDestination = Join-Path $vxDestinationDir $vxMissingRelative.Replace('/', '\')
    $vxBOnlyRelative = $caseRoot.Substring((Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path.Length).TrimStart('\').Replace('\', '/') + '/vx-b-only.txt'
    $vxBOnlyDestination = Join-Path $vxDestinationDir $vxBOnlyRelative.Replace('/', '\')
    $vxTaskDefinition = Join-Path $caseRoot 'vx-task.json'
    Write-Utf8NoBom -Path $vxExistingSource -Text "VX_EXISTING`n"
    Write-Utf8NoBom -Path $vxExistingSnapshot -Text "VX_EXISTING`n"
    Write-Utf8NoBom -Path $vxExistingDestination -Text "VX_EXISTING`n"
    Write-Utf8NoBom -Path (Join-Path $vxSnapshotDir 'source_files.txt') -Text "$vxExistingRelative`n$vxMissingRelative`n"
    Write-Utf8NoBom -Path $vxTaskDefinition -Text ([ordered]@{
        schemaVersion = 'vx-draft'
        targetFiles = @(
            [ordered]@{ id = 'vx_existing'; file = $vxExistingRelative; kind = 'text'; lifecycle = 'existing' },
            [ordered]@{ id = 'vx_missing'; file = $vxMissingRelative; kind = 'text'; lifecycle = 'create' }
        )
        defaultTarget = 'vx_existing'
        rounds = [ordered]@{
            D1 = [ordered]@{
                type = 'regex-patch'
                operations = @([ordered]@{
                    type = 'create-file'; target = 'vx_missing'; content = "VX_MISSING`n"
                    contentSha256 = '75af71835e6d1a9f2ca0cf8cd71846224264be731ea803275c3e2c2ef2fbeed6'
                    existingPolicy = 'skip'; idempotentContains = @('VX_MISSING')
                })
                postApplyAssertions = @([ordered]@{ name = 'missing'; target = 'vx_missing'; pattern = 'VX_MISSING'; expectedCount = 1 })
            }
            D2 = [ordered]@{ type = 'noop'; description = 'fixture' }
            D3 = [ordered]@{ type = 'noop'; description = 'fixture' }
            D4 = [ordered]@{ type = 'noop'; description = 'fixture' }
        }
    } | ConvertTo-Json -Depth 12)

    $vxRegistry = Get-ASnapshotTaskTargetRegistry -TaskDefinitionFile $vxTaskDefinition
    $vxAllowedPaths = @(Get-ASnapshotTaskTargetPaths -TaskDefinitionFile $vxTaskDefinition)
    $null = Write-ASuccessSnapshotManifest -SnapshotDir $vxSnapshotDir -TaskDefinitionFile $vxTaskDefinition
    $vxManifest = Get-Content -LiteralPath (Join-Path $vxSnapshotDir 'source_manifest.json') -Raw -Encoding utf8 | ConvertFrom-Json
    $vxMissingEntry = @($vxManifest.files | Where-Object { $_.id -eq 'vx_missing' })[0]
    if ([string]$vxManifest.target_set_sha256 -ne [string]$vxRegistry.TargetSetSha256 -or
        [bool]$vxMissingEntry.exists -or $null -ne $vxMissingEntry.length -or $null -ne $vxMissingEntry.sha256 -or
        (Test-Path -LiteralPath $vxMissingSnapshot)) {
        throw 'Vx snapshot target-set or exists=false binding mismatch'
    }
    $vxValid = Test-ASuccessSnapshotIntegrity -SnapshotDir $vxSnapshotDir -AllowedPaths $vxAllowedPaths `
        -DestinationRoot $vxDestinationDir -ExpectedTargetSetSha256 $vxRegistry.TargetSetSha256
    Assert-IntegrityResult -Name 'vx-missing-target-no-placeholder' -Result $vxValid -ExpectedPass $true

    Write-Utf8NoBom -Path $vxMissingDestination -Text "stale destination`n"
    Write-Utf8NoBom -Path $vxBOnlyDestination -Text "stale B-only destination`n"
    $vxAbsentRestore = Restore-ASuccessSnapshotAbsentTargets -SnapshotDir $vxSnapshotDir -DestinationRoot $vxDestinationDir `
        -AllowedPaths $vxAllowedPaths -AdditionalAbsentPaths @($vxBOnlyRelative) -ExpectedTargetSetSha256 $vxRegistry.TargetSetSha256
    if ([int]$vxAbsentRestore.RemovedCount -ne 2 -or (Test-Path -LiteralPath $vxMissingDestination) -or (Test-Path -LiteralPath $vxBOnlyDestination)) {
        throw 'Vx snapshot absent restore did not remove manifest-absent and B-only stale destinations'
    }
    Write-Output '[A-SNAPSHOT-INTEGRITY-REGRESSION] case=vx-missing-and-b-only-target-restore-removes-stale-destinations status=pass'

    $bCreateContent = "B_CREATE_EXACT`n"
    $bCreateExpectedSha256 = ([System.BitConverter]::ToString(
        [System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.UTF8Encoding]::new($false).GetBytes($bCreateContent))
    )).Replace('-', '').ToLowerInvariant()
    Write-Utf8NoBom -Path $vxBOnlyDestination -Text $bCreateContent
    $bCreateActualSha256 = (Get-FileHash -LiteralPath $vxBOnlyDestination -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($bCreateActualSha256 -ne $bCreateExpectedSha256) {
        throw "Vx B-only target recreation hash mismatch expected=$bCreateExpectedSha256 actual=$bCreateActualSha256"
    }
    Write-Output '[A-SNAPSHOT-INTEGRITY-REGRESSION] case=vx-b-only-target-recreates-with-exact-hash status=pass'

    Write-Utf8NoBom -Path $vxMissingSnapshot -Text "unexpected placeholder`n"
    $vxPlaceholder = Test-ASuccessSnapshotIntegrity -SnapshotDir $vxSnapshotDir -AllowedPaths $vxAllowedPaths `
        -ExpectedTargetSetSha256 $vxRegistry.TargetSetSha256
    Assert-IntegrityResult -Name 'vx-missing-target-placeholder-blocked' -Result $vxPlaceholder -ExpectedPass $false -ExpectedError 'snapshot-file-unexpected'
    Remove-Item -LiteralPath $vxMissingSnapshot -Force

    $vxHashMismatch = Test-ASuccessSnapshotIntegrity -SnapshotDir $vxSnapshotDir -AllowedPaths $vxAllowedPaths `
        -ExpectedTargetSetSha256 ('0' * 64)
    Assert-IntegrityResult -Name 'vx-target-set-hash-mismatch-blocked' -Result $vxHashMismatch -ExpectedPass $false -ExpectedError 'manifest-target-set-hash-mismatch'

    Write-Output '[A-SNAPSHOT-INTEGRITY-REGRESSION] result=pass'
}
finally {
    if (Test-Path -LiteralPath $caseRoot) {
        Remove-Item -LiteralPath $caseRoot -Recurse -Force
    }
}
