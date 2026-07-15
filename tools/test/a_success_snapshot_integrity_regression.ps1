param(
    [string]$OutDirRoot = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'a_success_snapshot_integrity.ps1')

if ([string]::IsNullOrWhiteSpace($OutDirRoot)) {
    $OutDirRoot = Join-Path $env:TEMP 'whois-a-success-snapshot-integrity'
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

    Write-Output '[A-SNAPSHOT-INTEGRITY-REGRESSION] result=pass'
}
finally {
    if (Test-Path -LiteralPath $caseRoot) {
        Remove-Item -LiteralPath $caseRoot -Recurse -Force
    }
}
