param(
    [string]$BinaryPath = "d:\LZProjects\whois\release\lzispro\whois\whois-win64.exe",
    [string]$OutDirRoot = ""
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $false

if (-not (Test-Path $BinaryPath)) {
    Write-Error "Binary not found: $BinaryPath"
    exit 2
}

if (-not $OutDirRoot -or $OutDirRoot.Trim().Length -eq 0) {
    $OutDirRoot = Join-Path $PSScriptRoot "..\..\out\artifacts\no_body_contract"
}
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$outDir = Join-Path $OutDirRoot $stamp
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

$script:pass = 0
$script:fail = 0
$script:results = @()

function Invoke-ClientCase {
    param(
        [string]$Name,
        [string[]]$Arguments,
        [string[]]$InputLines = @()
    )

    $stdoutPath = Join-Path $outDir ("{0}.stdout.txt" -f $Name)
    $stderrPath = Join-Path $outDir ("{0}.stderr.txt" -f $Name)
    $startArgs = @{
        FilePath = $BinaryPath
        ArgumentList = $Arguments
        RedirectStandardOutput = $stdoutPath
        RedirectStandardError = $stderrPath
        NoNewWindow = $true
        PassThru = $true
        Wait = $true
    }
    if ($InputLines.Count -gt 0) {
        $stdinPath = Join-Path $outDir ("{0}.stdin.txt" -f $Name)
        [System.IO.File]::WriteAllText(
            $stdinPath,
            ([string]::Join("`n", $InputLines) + "`n"),
            [System.Text.UTF8Encoding]::new($false))
        $startArgs.RedirectStandardInput = $stdinPath
    }
    $process = Start-Process @startArgs
    $stdout = if (Test-Path $stdoutPath) { Get-Content -Raw $stdoutPath } else { "" }
    $stderr = if (Test-Path $stderrPath) { Get-Content -Raw $stderrPath } else { "" }
    $lines = @($stdout -split "`r?`n" | Where-Object { $_.Length -gt 0 })
    return [pscustomobject]@{
        Name = $Name
        ExitCode = $process.ExitCode
        Stdout = $stdout
        Stderr = $stderr
        Lines = $lines
    }
}

function Add-Result {
    param(
        [string]$Name,
        [bool]$Passed,
        [string]$Detail
    )
    if ($Passed) {
        $script:pass++
        Write-Output ("[PASS] {0} {1}" -f $Name, $Detail)
        $script:results += "PASS case=$Name detail=$Detail"
    }
    else {
        $script:fail++
        Write-Output ("[FAIL] {0} {1}" -f $Name, $Detail)
        $script:results += "FAIL case=$Name detail=$Detail"
    }
}

function Test-NoBodyRecord {
    param(
        [pscustomobject]$Run,
        [int]$ExpectedQueries,
        [int]$ExpectedStatuses = 0
    )
    $queries = @($Run.Lines | Where-Object { $_ -match '^=== Query:' })
    $statuses = @($Run.Lines | Where-Object { $_ -match '^=== Address Status:' })
    $tails = @($Run.Lines | Where-Object { $_ -match '^=== Authoritative RIR:' })
    $unexpected = @($Run.Lines | Where-Object {
        $_ -notmatch '^=== (Query:|Address Status:|Authoritative RIR:)'
    })
    return $Run.ExitCode -eq 0 -and
        $queries.Count -eq $ExpectedQueries -and
        $statuses.Count -eq $ExpectedStatuses -and
        $tails.Count -eq $ExpectedQueries -and
        $unexpected.Count -eq 0
}

$online = Invoke-ClientCase -Name "online-success" -Arguments @(
    "--no-body", "--pacing-disable", "-h", "arin", "-Q", "-t", "5", "-r", "0", "8.8.8.8")
Add-Result -Name $online.Name -Passed (Test-NoBodyRecord $online 1 0) `
    -Detail ("exit={0} lines={1}" -f $online.ExitCode, $online.Lines.Count)

$phaseC = Invoke-ClientCase -Name "phasec-status" -Arguments @("--no-body", "255.0.0.0")
Add-Result -Name $phaseC.Name -Passed (Test-NoBodyRecord $phaseC 1 1) `
    -Detail ("exit={0} lines={1}" -f $phaseC.ExitCode, $phaseC.Lines.Count)

$filtered = Invoke-ClientCase -Name "filter-and-selector" -Arguments @(
    "--no-body", "-g", "netname", "--grep", "NET", "--show-non-auth-body",
    "--show-post-marker-body", "--hide-failure-body", "255.0.0.0")
Add-Result -Name $filtered.Name -Passed (Test-NoBodyRecord $filtered 1 1) `
    -Detail ("exit={0} lines={1}" -f $filtered.ExitCode, $filtered.Lines.Count)

$duplicate = Invoke-ClientCase -Name "duplicate-option" -Arguments @(
    "--no-body", "--no-body", "255.0.0.0")
Add-Result -Name $duplicate.Name -Passed (Test-NoBodyRecord $duplicate 1 1) `
    -Detail ("exit={0} lines={1}" -f $duplicate.ExitCode, $duplicate.Lines.Count)

$private = Invoke-ClientCase -Name "private-denied" -Arguments @(
    "--no-body", "--selftest-force-private", "10.0.0.8", "10.0.0.8")
$privatePassed = Test-NoBodyRecord $private 1 0
$privatePassed = $privatePassed -and $private.Stdout -notmatch '(?m)^10\.0\.0\.8 is a private IP address$'
Add-Result -Name $private.Name -Passed $privatePassed `
    -Detail ("exit={0} lines={1}" -f $private.ExitCode, $private.Lines.Count)

$invalid = Invoke-ClientCase -Name "invalid-query" -Arguments @("--no-body", "999.999.999.999")
$invalidPassed = Test-NoBodyRecord $invalid 1 0
$invalidPassed = $invalidPassed -and $invalid.Stdout -notmatch '(?m)^Invalid IP/CIDR query:'
Add-Result -Name $invalid.Name -Passed $invalidPassed `
    -Detail ("exit={0} lines={1}" -f $invalid.ExitCode, $invalid.Lines.Count)

foreach ($batchMode in @("explicit", "auto")) {
    $batchArgs = if ($batchMode -eq "explicit") { @("--no-body", "-B") } else { @("--no-body") }
    $batch = Invoke-ClientCase -Name ("batch-{0}" -f $batchMode) -Arguments $batchArgs `
        -InputLines @("255.0.0.0", "10.0.0.8")
    $queryLines = @($batch.Lines | Where-Object { $_ -match '^=== Query:' })
    $ordered = $queryLines.Count -eq 2 -and
        $queryLines[0] -match '^=== Query: 255\.0\.0\.0 ' -and
        $queryLines[1] -match '^=== Query: 10\.0\.0\.8 '
    Add-Result -Name $batch.Name -Passed ((Test-NoBodyRecord $batch 2 2) -and $ordered) `
        -Detail ("exit={0} lines={1}" -f $batch.ExitCode, $batch.Lines.Count)
}

$conflicts = @(
    @{ Name = "plain-conflict"; Arguments = @("--no-body", "--plain", "255.0.0.0") },
    @{ Name = "fold-conflict"; Arguments = @("--no-body", "--fold", "255.0.0.0") },
    @{ Name = "fold-sep-conflict"; Arguments = @("--no-body", "--fold-sep", "space", "255.0.0.0") },
    @{ Name = "fold-unique-conflict"; Arguments = @("--no-body", "--fold-unique", "255.0.0.0") },
    @{ Name = "fold-upper-conflict"; Arguments = @("--no-body", "--no-fold-upper", "255.0.0.0") }
)
foreach ($conflict in $conflicts) {
    $run = Invoke-ClientCase -Name $conflict.Name -Arguments $conflict.Arguments
    $passed = $run.ExitCode -ne 0 -and
        $run.Stderr -match 'Error: --no-body cannot be combined with' -and
        $run.Stdout -notmatch '(?m)^=== Query:'
    Add-Result -Name $run.Name -Passed $passed -Detail ("exit={0}" -f $run.ExitCode)
}

$reportPath = Join-Path $outDir "summary.txt"
$reportLines = @(
    "binary=$BinaryPath"
    "pass=$script:pass"
    "fail=$script:fail"
    ""
) + $script:results
[System.IO.File]::WriteAllText(
    $reportPath,
    ([string]::Join("`n", $reportLines) + "`n"),
    [System.Text.UTF8Encoding]::new($false))

Write-Output ("Summary: pass={0} fail={1}" -f $script:pass, $script:fail)
Write-Output ("Report: {0}" -f $reportPath)
if ($script:fail -gt 0) {
    exit 1
}
exit 0