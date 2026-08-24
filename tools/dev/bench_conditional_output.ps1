param(
    [Parameter(Mandatory = $true)][string]$RunnerPath,
    [string]$ManifestPath = "testdata/bench/conditional_output/manifest.json",
    [string]$ExpectedPath = "testdata/bench/conditional_output/expected-sha256.json",
    [ValidateRange(5, 1000)][int]$Repetitions = 5,
    [ValidateRange(1, 100)][int]$Warmup = 1,
    [ValidateRange(1, 1000000)][int]$IterationsPerRun = 1000,
    [string]$OutputRoot = "out/artifacts/bench",
    [string]$TargetArchitecture = "unspecified",
    [string]$Compiler = "unspecified",
    [string]$CompilerVersion = "unspecified",
    [string]$CFlags = "unspecified",
    [switch]$UpdateExpected
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2

function Get-Sha256Text {
    param([string]$Text)
    $encoding = New-Object System.Text.UTF8Encoding($false)
    $bytes = $encoding.GetBytes($Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace("-", "").ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
    }
}

function Get-Sha256Files {
    param([string[]]$Paths, [string]$BasePath)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $stream = New-Object System.IO.MemoryStream
        try {
            foreach ($path in $Paths) {
                $relativePath = $path.Substring($BasePath.Length).TrimStart('\', '/')
                $pathBytes = [Text.Encoding]::UTF8.GetBytes(($relativePath -replace "\\", "/") + "`n")
                $stream.Write($pathBytes, 0, $pathBytes.Length)
                $fileBytes = [IO.File]::ReadAllBytes($path)
                $stream.Write($fileBytes, 0, $fileBytes.Length)
            }
            $stream.Position = 0
            return ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace("-", "").ToLowerInvariant()
        }
        finally {
            $stream.Dispose()
        }
    }
    finally {
        $sha.Dispose()
    }
}

function ConvertTo-ProcessArgument {
    param([string]$Value)
    if ($Value -notmatch '[\s"]') {
        return $Value
    }
    return '"' + ($Value -replace '(\\*)"', '$1$1\"' -replace '(\\+)$', '$1$1') + '"'
}

function Invoke-BenchRunner {
    param(
        [string]$Executable,
        [string[]]$RunnerArguments
    )
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Executable
    $psi.Arguments = (($RunnerArguments | ForEach-Object { ConvertTo-ProcessArgument $_ }) -join " ")
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $psi
    $stopwatch = [Diagnostics.Stopwatch]::StartNew()
    if (-not $process.Start()) {
        throw "[bench] failed to start runner"
    }
    $stdout = $process.StandardOutput.ReadToEnd()
    $stderr = $process.StandardError.ReadToEnd()
    $process.WaitForExit()
    $stopwatch.Stop()
    $peakRssKb = [Math]::Ceiling($process.PeakWorkingSet64 / 1KB)
    $exitCode = $process.ExitCode
    $process.Dispose()
    return [pscustomobject]@{
        ExitCode = $exitCode
        Stdout = $stdout
        Stderr = $stderr
        WallTimeMs = $stopwatch.Elapsed.TotalMilliseconds
        PeakRssKb = $peakRssKb
    }
}

function Get-Percentile {
    param([double[]]$Values, [double]$Percentile)
    $sorted = @($Values | Sort-Object)
    $index = [Math]::Ceiling($Percentile * $sorted.Count) - 1
    if ($index -lt 0) { $index = 0 }
    return [double]$sorted[$index]
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "../..")).ProviderPath
$runner = (Resolve-Path (Join-Path $repoRoot $RunnerPath)).ProviderPath
$manifestFull = (Resolve-Path (Join-Path $repoRoot $ManifestPath)).ProviderPath
$manifest = Get-Content -Raw -LiteralPath $manifestFull | ConvertFrom-Json
if ($manifest.schemaVersion -ne 1 -or @($manifest.fixtures).Count -eq 0) {
    throw "[bench] invalid or empty manifest: $ManifestPath"
}
$fixtureRoot = Split-Path $manifestFull -Parent
$fixtures = @()
foreach ($fixture in $manifest.fixtures) {
    $fixturePath = Join-Path $fixtureRoot $fixture.file
    if (-not (Test-Path -LiteralPath $fixturePath -PathType Leaf)) {
        throw "[bench] fixture missing: $fixturePath"
    }
    $fixtures += [pscustomobject]@{
        Id = [string]$fixture.id
        Path = (Resolve-Path -LiteralPath $fixturePath).ProviderPath
        Query = [string]$fixture.query
        Rir = [string]$fixture.rir
        Bytes = (Get-Item -LiteralPath $fixturePath).Length
    }
}

$samplePaths = @($manifestFull) + @($fixtures | ForEach-Object { $_.Path })
$sampleSetSha256 = Get-Sha256Files -Paths $samplePaths -BasePath $repoRoot
$expectedFull = Join-Path $repoRoot $ExpectedPath
$expectedMap = @{}
if (Test-Path -LiteralPath $expectedFull) {
    $expectedDocument = Get-Content -Raw -LiteralPath $expectedFull | ConvertFrom-Json
    if ($expectedDocument.sampleSetSha256 -ne $sampleSetSha256 -and -not $UpdateExpected) {
        throw "[bench] sample-set SHA changed; update expectations explicitly"
    }
    foreach ($property in $expectedDocument.cases.PSObject.Properties) {
        $expectedMap[$property.Name] = [string]$property.Value
    }
}
elseif (-not $UpdateExpected) {
    throw "[bench] expected hashes missing: $ExpectedPath"
}

$cases = @()
foreach ($scenario in @("raw", "title", "grep", "fold", "fold-unique")) {
    foreach ($fixture in $fixtures) {
        $cases += [pscustomobject]@{
            Id = "$scenario/$($fixture.Id)"
            Scenario = $scenario
            Fixtures = @($fixture)
            QueryCount = 1
        }
    }
}
$cases += [pscustomobject]@{
    Id = "batch/all"
    Scenario = "batch"
    Fixtures = @($fixtures)
    QueryCount = $fixtures.Count
}

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$outputDir = Join-Path (Join-Path $repoRoot $OutputRoot) $timestamp
New-Item -ItemType Directory -Force -Path $outputDir | Out-Null
$rawRows = New-Object System.Collections.Generic.List[object]
$summaryRows = New-Object System.Collections.Generic.List[object]
$observedMap = [ordered]@{}

foreach ($case in $cases) {
    $runnerArguments = @("--scenario", $case.Scenario, "--iterations", "$IterationsPerRun")
    foreach ($fixture in $case.Fixtures) {
        $runnerArguments += @("--fixture", $fixture.Path)
    }
    if ($case.QueryCount -eq 1) {
        $runnerArguments += @("--query", $case.Fixtures[0].Query, "--rir", $case.Fixtures[0].Rir)
    }
    $warmupResult = $null
    for ($warmupIndex = 1; $warmupIndex -le $Warmup; ++$warmupIndex) {
        $warmupResult = Invoke-BenchRunner -Executable $runner -RunnerArguments $runnerArguments
        if ($warmupResult.ExitCode -ne 0) {
            throw "[bench] warm-up failed: $($case.Id): $($warmupResult.Stderr.Trim())"
        }
    }
    $expectedHash = Get-Sha256Text -Text $warmupResult.Stdout
    $observedMap[$case.Id] = $expectedHash
    if (-not $UpdateExpected) {
        if (-not $expectedMap.ContainsKey($case.Id) -or $expectedMap[$case.Id] -ne $expectedHash) {
            throw "[bench] frozen output mismatch: $($case.Id)"
        }
    }

    $caseRows = @()
    for ($run = 1; $run -le $Repetitions; ++$run) {
        $result = Invoke-BenchRunner -Executable $runner -RunnerArguments $runnerArguments
        if ($result.ExitCode -ne 0) {
            throw "[bench] measured run failed: $($case.Id): $($result.Stderr.Trim())"
        }
        $outputSha = Get-Sha256Text -Text $result.Stdout
        if ($outputSha -ne $expectedHash) {
            throw "[bench] non-deterministic output: $($case.Id) run=$run"
        }
        $metric = [regex]::Match($result.Stderr,
            '\[BENCH\] scenario=\S+ iterations=\d+ output_bytes=(\d+) reserves=(\d+) grow=(\d+) max_request=(\d+) max_cap=(\d+) max_view=(\d+)')
        if (-not $metric.Success) {
            throw "[bench] metrics missing: $($case.Id) run=$run"
        }
        $scanBytes = [long](($case.Fixtures | Measure-Object -Property Bytes -Sum).Sum)
        $queriesPerRun = [long]$case.QueryCount * $IterationsPerRun
        $row = [pscustomobject]@{
            case_id = $case.Id
            scenario = $case.Scenario
            run = $run
            iterations = $IterationsPerRun
            queries = $queriesPerRun
            wall_time_ms = [Math]::Round($result.WallTimeMs, 3)
            output_bytes = [long]$metric.Groups[1].Value
            peak_rss_kb = [long]$result.PeakRssKb
            reserves = [long]$metric.Groups[2].Value
            grow = [long]$metric.Groups[3].Value
            max_request = [long]$metric.Groups[4].Value
            max_cap = [long]$metric.Groups[5].Value
            max_view = [long]$metric.Groups[6].Value
            throughput_qps = [Math]::Round($queriesPerRun / ($result.WallTimeMs / 1000.0), 3)
            scan_bytes = $scanBytes * $IterationsPerRun
            stdout_sha256 = $outputSha
        }
        $rawRows.Add($row)
        $caseRows += $row
    }
    $wallValues = [double[]]@($caseRows | ForEach-Object { $_.wall_time_ms })
    $qpsValues = [double[]]@($caseRows | ForEach-Object { $_.throughput_qps })
    $summaryRows.Add([pscustomobject]@{
        case_id = $case.Id
        scenario = $case.Scenario
        repetitions = $Repetitions
        iterations_per_run = $IterationsPerRun
        queries_per_run = [long]$case.QueryCount * $IterationsPerRun
        wall_time_median_ms = [Math]::Round((Get-Percentile $wallValues 0.5), 3)
        wall_time_p95_ms = [Math]::Round((Get-Percentile $wallValues 0.95), 3)
        throughput_median_qps = [Math]::Round((Get-Percentile $qpsValues 0.5), 3)
        output_bytes = $caseRows[0].output_bytes
        peak_rss_kb = ($caseRows | Measure-Object -Property peak_rss_kb -Maximum).Maximum
        reserves = $caseRows[0].reserves
        grow = $caseRows[0].grow
        max_request = $caseRows[0].max_request
        max_cap = $caseRows[0].max_cap
        max_view = $caseRows[0].max_view
        scan_bytes = $caseRows[0].scan_bytes
        stdout_sha256 = $expectedHash
    })
    Write-Output "[bench] PASS case=$($case.Id)"
}

if ($UpdateExpected) {
    $expectedDir = Split-Path $expectedFull -Parent
    New-Item -ItemType Directory -Force -Path $expectedDir | Out-Null
    $expectedOutput = [ordered]@{
        schemaVersion = 1
        sampleSetSha256 = $sampleSetSha256
        cases = $observedMap
    } | ConvertTo-Json -Depth 5
    $expectedOutput = $expectedOutput -replace "`r`n", "`n"
    $utf8Bom = New-Object System.Text.UTF8Encoding($true)
    [IO.File]::WriteAllText($expectedFull, $expectedOutput + "`n", $utf8Bom)
}

$rawRows | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $outputDir "raw.csv")
$summaryRows | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $outputDir "summary.csv")
$metadata = [ordered]@{
    schemaVersion = 1
    generatedAt = (Get-Date).ToString("o")
    commit = (& git -C $repoRoot rev-parse HEAD).Trim()
    gitDescribe = (& git -C $repoRoot describe --tags --always --dirty).Trim()
    runner = $runner
    runnerSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $runner).Hash.ToLowerInvariant()
    benchmarkScriptSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $PSCommandPath).Hash.ToLowerInvariant()
    sampleSetSha256 = $sampleSetSha256
    repetitions = $Repetitions
    warmup = $Warmup
    iterationsPerRun = $IterationsPerRun
    targetArchitecture = $TargetArchitecture
    compiler = $Compiler
    compilerVersion = $CompilerVersion
    cflags = $CFlags
    os = [Environment]::OSVersion.VersionString
    processorCount = [Environment]::ProcessorCount
    results = $summaryRows.ToArray()
}
$metadata | ConvertTo-Json -Depth 7 | Set-Content -Encoding UTF8 -Path (Join-Path $outputDir "summary.json")
Write-Output "[bench] PASS cases=$($cases.Count) output=$outputDir"