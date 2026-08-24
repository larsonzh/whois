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
if (-not $OutDirRoot) {
    $OutDirRoot = Join-Path $PSScriptRoot "..\..\out\artifacts\stats_contract"
}
$outDir = Join-Path $OutDirRoot (Get-Date -Format "yyyyMMdd-HHmmss")
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

$script:pass = 0
$script:fail = 0
$script:results = @()

function Invoke-ClientCase {
    param(
        [string]$Name,
        [string[]]$Arguments,
        [AllowNull()][AllowEmptyString()][string]$InputText = $null
    )
    $stdoutPath = Join-Path $outDir "$Name.stdout.txt"
    $stderrPath = Join-Path $outDir "$Name.stderr.txt"
    $startArgs = @{
        FilePath = $BinaryPath
        ArgumentList = $Arguments
        RedirectStandardOutput = $stdoutPath
        RedirectStandardError = $stderrPath
        NoNewWindow = $true
        PassThru = $true
        Wait = $true
    }
    if ($null -ne $InputText) {
        $stdinPath = Join-Path $outDir "$Name.stdin.txt"
        [System.IO.File]::WriteAllText($stdinPath, $InputText,
            [System.Text.UTF8Encoding]::new($false))
        $startArgs.RedirectStandardInput = $stdinPath
    }
    $process = Start-Process @startArgs
    $stdout = if (Test-Path $stdoutPath) { Get-Content -Raw $stdoutPath } else { "" }
    $stderr = if (Test-Path $stderrPath) { Get-Content -Raw $stderrPath } else { "" }
    $lines = @($stdout -split "`r?`n" | Where-Object { $_.Length -gt 0 })
    [pscustomobject]@{
        Name = $Name
        ExitCode = $process.ExitCode
        Stdout = $stdout
        Stderr = $stderr
        Lines = $lines
    }
}

function Add-Result {
    param([string]$Name, [bool]$Passed, [string]$Detail)
    if ($Passed) {
        $script:pass++
        Write-Output "[PASS] $Name $Detail"
        $script:results += "PASS case=$Name detail=$Detail"
    } else {
        $script:fail++
        Write-Output "[FAIL] $Name $Detail"
        $script:results += "FAIL case=$Name detail=$Detail"
    }
}

function Get-StatsFields {
    param([pscustomobject]$Run)
    $statsLines = @($Run.Lines | Where-Object { $_ -match '^stats_total=' })
    if ($statsLines.Count -ne 1) { return $null }
    $parts = @($statsLines[0] -split "`t")
    if ($parts.Count -ne 18) { return $null }
    $fields = @{}
    foreach ($part in $parts) {
        if ($part -notmatch '^([a-z0-9_]+)=(\d+)$') { return $null }
        $fields[$Matches[1]] = [uint64]$Matches[2]
    }
    return $fields
}

function Test-StatsRun {
    param(
        [pscustomobject]$Run,
        [uint64]$Total,
        [uint64]$Success,
        [uint64]$ExpectedFailures
    )
    $fields = Get-StatsFields $Run
    if ($null -eq $fields) { return $false }
    if ($Run.Lines[-1] -notmatch '^stats_total=') { return $false }
    if ($fields.stats_total -ne $Total -or
        $fields.stats_success -ne $Success -or
        $fields.stats_error -ne $ExpectedFailures) { return $false }
    $failureSum = $fields.stats_error_lookup + $fields.stats_error_rejected +
        $fields.stats_error_internal
    $rirSum = $fields.stats_rir_iana + $fields.stats_rir_arin +
        $fields.stats_rir_ripe + $fields.stats_rir_apnic +
        $fields.stats_rir_lacnic + $fields.stats_rir_afrinic +
        $fields.stats_rir_verisign + $fields.stats_rir_unknown +
        $fields.stats_rir_error + $fields.stats_rir_other
    return $failureSum -eq $ExpectedFailures -and $rirSum -eq $Total
}

$empty = Invoke-ClientCase "empty-batch" @("-B", "--stats") ""
$fields = Get-StatsFields $empty
$ok = Test-StatsRun $empty 0 0 0
$ok = $ok -and $fields.stats_duration_p50_ms -eq 0 -and
    $fields.stats_duration_p95_ms -eq 0
Add-Result $empty.Name ($ok -and $empty.ExitCode -eq 0) "exit=$($empty.ExitCode)"

$comments = Invoke-ClientCase "comments-only" @("-B", "--stats") "`n  # one`n`t# two`n"
Add-Result $comments.Name ((Test-StatsRun $comments 0 0 0) -and
    $comments.ExitCode -eq 0) "exit=$($comments.ExitCode)"

$success = Invoke-ClientCase "local-success" @("-B", "--stats", "--no-body") `
    "255.0.0.0`n999.999.999.999`n10.0.0.8`n"
$fields = Get-StatsFields $success
$ok = Test-StatsRun $success 3 3 0
$ok = $ok -and $fields.stats_rir_unknown -eq 3
Add-Result $success.Name ($ok -and $success.ExitCode -eq 0) "exit=$($success.ExitCode)"

$rejected = Invoke-ClientCase "rejected" @("-B", "--stats") "bad;query`n"
$fields = Get-StatsFields $rejected
$ok = Test-StatsRun $rejected 1 0 1
$ok = $ok -and $fields.stats_error_rejected -eq 1 -and
    $fields.stats_rir_error -eq 1
Add-Result $rejected.Name ($ok -and $rejected.ExitCode -eq 0) "exit=$($rejected.ExitCode)"

$lookup = Invoke-ClientCase "lookup-error" @(
    "-B", "--stats", "--pacing-disable", "-h", "no-such-host.invalid",
    "-t", "1", "-r", "0") "8.8.8.8`n"
$fields = Get-StatsFields $lookup
$ok = Test-StatsRun $lookup 1 0 1
$ok = $ok -and $fields.stats_error_lookup -eq 1
Add-Result $lookup.Name ($ok -and $lookup.ExitCode -eq 0) "exit=$($lookup.ExitCode)"

$combo = Invoke-ClientCase "observation-order" @(
    "-B", "--no-body", "--pick", "netname,country",
    "--print-chain", "--print-meta", "--stats") "255.0.0.0`n"
$ok = Test-StatsRun $combo 1 1 0
$ok = $ok -and $combo.Lines.Count -ge 4 -and
    $combo.Lines[-4] -match '^netname=' -and
    $combo.Lines[-3] -eq 'chain=unknown' -and
    $combo.Lines[-2] -match '^query='
Add-Result $combo.Name ($ok -and $combo.ExitCode -eq 0) "lines=$($combo.Lines.Count)"

$fold = Invoke-ClientCase "fold-order" @("-B", "--fold", "--stats") "255.0.0.0`n"
$ok = Test-StatsRun $fold 1 1 0
$ok = $ok -and $fold.Lines.Count -eq 2 -and $fold.Lines[0] -notmatch '^stats_total='
Add-Result $fold.Name ($ok -and $fold.ExitCode -eq 0) "lines=$($fold.Lines.Count)"

$single = Invoke-ClientCase "single-conflict" @("--stats", "8.8.8.8")
$ok = $single.ExitCode -ne 0 -and $single.Stderr -match '--stats requires batch input' -and
    $single.Stdout -notmatch 'stats_total='
Add-Result $single.Name $ok "exit=$($single.ExitCode)"

$plain = Invoke-ClientCase "plain-conflict" @("-B", "--stats", "--plain") "255.0.0.0`n"
$ok = $plain.ExitCode -ne 0 -and $plain.Stderr -match '--stats cannot be combined with --plain' -and
    $plain.Stdout -notmatch 'stats_total='
Add-Result $plain.Name $ok "exit=$($plain.ExitCode)"

$duplicate = Invoke-ClientCase "duplicate-option" @("-B", "--stats", "--stats") "255.0.0.0`n"
Add-Result $duplicate.Name ((Test-StatsRun $duplicate 1 1 0) -and
    $duplicate.ExitCode -eq 0) "statsLines=$(@($duplicate.Lines | Where-Object { $_ -match '^stats_total=' }).Count)"

$defaultOff = Invoke-ClientCase "default-off" @("-B", "--no-body") "255.0.0.0`n"
$ok = $defaultOff.ExitCode -eq 0 -and $defaultOff.Stdout -notmatch '(?m)^stats_total='
Add-Result $defaultOff.Name $ok "exit=$($defaultOff.ExitCode)"

$auto = Invoke-ClientCase "auto-batch" @("--stats", "--no-body") "255.0.0.0`n"
Add-Result $auto.Name ((Test-StatsRun $auto 1 1 0) -and $auto.ExitCode -eq 0) `
    "exit=$($auto.ExitCode)"

$summaryPath = Join-Path $outDir "summary.txt"
[System.IO.File]::WriteAllLines($summaryPath, $script:results,
    [System.Text.UTF8Encoding]::new($false))
Write-Output "[SUMMARY] pass=$script:pass fail=$script:fail out=$outDir"
if ($script:fail -gt 0) { exit 1 }
exit 0