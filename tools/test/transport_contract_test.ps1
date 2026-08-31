[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$outputDirectory = Join-Path $repoRoot 'tmp\transport_contract'
$outputFile = Join-Path $outputDirectory 'transport_contract_test.exe'
$compiler = Get-Command clang, gcc, cc -ErrorAction SilentlyContinue | Select-Object -First 1

if (-not $compiler) {
    throw 'No C compiler found (tried clang, gcc, cc).'
}

New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
$arguments = @(
    '-std=c11',
    '-Wall',
    '-Wextra',
    '-Werror',
    '-Iinclude',
    'tools/test/transport_contract_test.c',
    'src/core/transport.c',
    '-o',
    $outputFile
)
if ($env:OS -eq 'Windows_NT') {
    $arguments += '-lws2_32'
}

Push-Location $repoRoot
try {
    & $compiler.Source @arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Transport contract compile failed with exit code $LASTEXITCODE."
    }
    & $outputFile
    if ($LASTEXITCODE -ne 0) {
        throw "Transport contract test failed with exit code $LASTEXITCODE."
    }
}
finally {
    Pop-Location
}