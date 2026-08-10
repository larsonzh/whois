param([string]$OutDirRoot = '')

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$checker = Join-Path $PSScriptRoot 'check_task_definition_static.ps1'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
if ([string]::IsNullOrWhiteSpace($OutDirRoot)) {
    $OutDirRoot = Join-Path $repoRoot 'tmp\task-definition-target-registry'
}
$caseRoot = Join-Path $OutDirRoot ([guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $caseRoot -Force | Out-Null

function Write-Utf8NoBom {
    param([string]$Path, [string]$Text)
    [System.IO.File]::WriteAllText($Path, $Text, (New-Object System.Text.UTF8Encoding($false)))
}

function Invoke-SyntaxCase {
    param([string]$Name, [object]$Definition, [int]$ExpectedExit, [string]$ExpectedFragment)

    $taskPath = Join-Path $caseRoot "$Name.json"
    Write-Utf8NoBom -Path $taskPath -Text ($Definition | ConvertTo-Json -Depth 20)
    $previousErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = @(& powershell -NoProfile -ExecutionPolicy Bypass -File $checker `
            -TaskDefinitionFile $taskPath -RepoRoot $repoRoot -Policy enforce -SyntaxOnly 2>&1 | ForEach-Object { [string]$_ })
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    if ($exitCode -ne $ExpectedExit -or -not ($output -match [regex]::Escape($ExpectedFragment))) {
        throw "case=$Name expected_exit=$ExpectedExit actual_exit=$exitCode expected_fragment=$ExpectedFragment output=$($output -join ' | ')"
    }
    Write-Output "[TARGET-REGISTRY-REGRESSION] case=$Name status=pass exit=$exitCode"
}

try {
    $v1 = [ordered]@{
        schemaVersion = 1
        targetFile = 'src/core/preclass.c'
        rounds = [ordered]@{ D1 = [ordered]@{ type = 'noop'; description = 'fixture' } }
    }
    Invoke-SyntaxCase -Name 'v1' -Definition $v1 -ExpectedExit 0 -ExpectedFragment 'schema=1 targets=1'

    $vx = [ordered]@{
        schemaVersion = 'vx-draft'
        targetFile = 'src/core/preclass.c'
        targetFiles = @(
            [ordered]@{ id = 'preclass_source'; file = 'src/core/preclass.c'; kind = 'c-source'; lifecycle = 'existing' },
            [ordered]@{ id = 'query_exec'; file = 'src/core/whois_query_exec.c'; kind = 'c-source'; lifecycle = 'existing' }
        )
        defaultTarget = 'preclass_source'
        rounds = [ordered]@{
            D1 = [ordered]@{
                type = 'regex-patch'
                operations = @([ordered]@{ target = 'query_exec'; pattern = 'x'; replacement = 'y vx-marker-query-exec'; idempotentContains = @('vx-marker-query-exec') })
                postApplyAssertions = @([ordered]@{ name = 'fixture'; target = 'query_exec'; pattern = 'y'; expectedCount = 1 })
            }
        }
    }
    Invoke-SyntaxCase -Name 'vx-valid' -Definition $vx -ExpectedExit 0 -ExpectedFragment 'schema=vx-draft targets=2'

    $duplicate = $vx | ConvertTo-Json -Depth 20 | ConvertFrom-Json
    $duplicate.targetFiles[1].file = 'SRC/CORE/PRECLASS.C'
    Invoke-SyntaxCase -Name 'vx-duplicate-path' -Definition $duplicate -ExpectedExit 1 -ExpectedFragment 'duplicate target'

    $unknown = $vx | ConvertTo-Json -Depth 20 | ConvertFrom-Json
    $unknown.rounds.D1.operations[0].target = 'missing_target'
    Invoke-SyntaxCase -Name 'vx-unknown-target' -Definition $unknown -ExpectedExit 1 -ExpectedFragment 'unknown target'

    $missingAssertionTarget = $vx | ConvertTo-Json -Depth 20 | ConvertFrom-Json
    $missingAssertionTarget.rounds.D1.postApplyAssertions[0].PSObject.Properties.Remove('target')
    Invoke-SyntaxCase -Name 'vx-assertion-target' -Definition $missingAssertionTarget -ExpectedExit 1 -ExpectedFragment 'missing target'

    Write-Output '[TARGET-REGISTRY-REGRESSION] status=PASS'
}
finally {
    Remove-Item -LiteralPath $caseRoot -Recurse -Force -ErrorAction SilentlyContinue
}