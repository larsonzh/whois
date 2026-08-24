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
    $OutDirRoot = Join-Path $PSScriptRoot "..\..\out\artifacts\print_chain_contract"
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

function Get-ChainLines {
    param([pscustomobject]$Run)
    return @($Run.Lines | Where-Object { $_ -match '^chain=' })
}

$single = Invoke-ClientCase -Name "single-hop" -Arguments @(
    "--print-chain", "--pacing-disable", "-h", "arin", "-Q", "-t", "5", "-r", "0", "8.8.8.8")
$chains = @(Get-ChainLines $single)
$ok = $single.ExitCode -eq 0 -and $chains.Count -eq 1
$ok = $ok -and $chains[0] -match '^chain=[^>]+$' -and $chains[0] -ne 'chain=unknown'
Add-Result $single.Name $ok ("exit={0} chain={1}" -f $single.ExitCode, ($chains -join ','))

$dnsFailure = Invoke-ClientCase -Name "dns-failure" -Arguments @(
    "--print-chain", "--pacing-disable", "-h", "no-such-host.invalid", "-t", "3", "-r", "0", "8.8.8.8")
$chains = @(Get-ChainLines $dnsFailure)
$ok = $dnsFailure.ExitCode -ne 0 -and $chains.Count -eq 1
$ok = $ok -and $chains[0] -eq 'chain=no-such-host.invalid'
Add-Result $dnsFailure.Name $ok ("exit={0} chain={1}" -f $dnsFailure.ExitCode, ($chains -join ','))

$phaseC = Invoke-ClientCase -Name "phasec-unknown" -Arguments @("--print-chain", "255.0.0.0")
$chains = @(Get-ChainLines $phaseC)
$ok = $phaseC.ExitCode -eq 0 -and $chains.Count -eq 1 -and $chains[0] -eq 'chain=unknown'
Add-Result $phaseC.Name $ok ("exit={0} chain={1}" -f $phaseC.ExitCode, ($chains -join ','))

$invalid = Invoke-ClientCase -Name "invalid-unknown" -Arguments @("--print-chain", "999.999.999.999")
$chains = @(Get-ChainLines $invalid)
$ok = $invalid.ExitCode -eq 0 -and $chains.Count -eq 1 -and $chains[0] -eq 'chain=unknown'
Add-Result $invalid.Name $ok ("exit={0} chain={1}" -f $invalid.ExitCode, ($chains -join ','))

$private = Invoke-ClientCase -Name "private-unknown" -Arguments @("--print-chain", "-h", "arin", "10.0.0.8")
$chains = @(Get-ChainLines $private)
$ok = $private.ExitCode -eq 0 -and $chains.Count -eq 1 -and $chains[0] -eq 'chain=unknown'
Add-Result $private.Name $ok ("exit={0} chain={1}" -f $private.ExitCode, ($chains -join ','))

$suspicious = Invoke-ClientCase -Name "suspicious-unknown" -Arguments @("--print-chain", "bad;query")
$chains = @(Get-ChainLines $suspicious)
$ok = $suspicious.ExitCode -ne 0 -and $suspicious.Lines.Count -eq 1
$ok = $ok -and $chains.Count -eq 1 -and $chains[0] -eq 'chain=unknown'
Add-Result $suspicious.Name $ok ("exit={0} lines={1}" -f $suspicious.ExitCode, $suspicious.Lines.Count)

$foldFailure = Invoke-ClientCase -Name "fold-failure" -Arguments @(
    "--fold", "--print-chain", "--pacing-disable", "-h", "no-such-host.invalid", "-t", "3", "-r", "0", "8.8.8.8")
$ok = $foldFailure.ExitCode -ne 0 -and $foldFailure.Lines.Count -eq 2
$ok = $ok -and $foldFailure.Lines[0] -eq '8.8.8.8 ERROR'
$ok = $ok -and $foldFailure.Lines[1] -eq 'chain=no-such-host.invalid'
Add-Result $foldFailure.Name $ok ("exit={0} lines={1}" -f $foldFailure.ExitCode, $foldFailure.Lines.Count)

$combined = Invoke-ClientCase -Name "chain-meta-order" -Arguments @(
    "--fold", "--print-chain", "--print-meta", "255.0.0.0")
$ok = $combined.ExitCode -eq 0 -and $combined.Lines.Count -eq 3
$ok = $ok -and $combined.Lines[1] -eq 'chain=unknown'
$ok = $ok -and $combined.Lines[2] -match '^query=255\.0\.0\.0\t'
Add-Result $combined.Name $ok ("exit={0} lines={1}" -f $combined.ExitCode, $combined.Lines.Count)

$batch = Invoke-ClientCase -Name "batch-explicit" -Arguments @("-B", "--print-chain") `
    -InputLines @("10.0.0.8", "255.0.0.0")
$chains = @(Get-ChainLines $batch)
$ok = $batch.ExitCode -eq 0 -and $chains.Count -eq 2
$ok = $ok -and $chains[0] -eq 'chain=unknown' -and $chains[1] -eq 'chain=unknown'
Add-Result $batch.Name $ok ("exit={0} chains={1}" -f $batch.ExitCode, $chains.Count)

$batchImplicit = Invoke-ClientCase -Name "batch-implicit" -Arguments @("--print-chain") `
    -InputLines @("10.0.0.8", "255.0.0.0")
$chains = @(Get-ChainLines $batchImplicit)
$ok = $batchImplicit.ExitCode -eq 0 -and $chains.Count -eq 2
$ok = $ok -and $chains[0] -eq 'chain=unknown' -and $chains[1] -eq 'chain=unknown'
Add-Result $batchImplicit.Name $ok ("exit={0} chains={1}" -f $batchImplicit.ExitCode, $chains.Count)

$duplicate = Invoke-ClientCase -Name "duplicate-option" -Arguments @(
    "--print-chain", "--print-chain", "255.0.0.0")
$chains = @(Get-ChainLines $duplicate)
$ok = $duplicate.ExitCode -eq 0 -and $chains.Count -eq 1 -and $chains[0] -eq 'chain=unknown'
Add-Result $duplicate.Name $ok ("exit={0} chains={1}" -f $duplicate.ExitCode, $chains.Count)

$conflict = Invoke-ClientCase -Name "plain-conflict" -Arguments @(
    "--print-chain", "--plain", "8.8.8.8")
$ok = $conflict.ExitCode -ne 0
$ok = $ok -and $conflict.Stderr -match '--print-chain cannot be combined with --plain'
$ok = $ok -and @(Get-ChainLines $conflict).Count -eq 0
$ok = $ok -and @($conflict.Lines | Where-Object { $_ -match '^=== Query:' }).Count -eq 0
Add-Result $conflict.Name $ok ("exit={0} lines={1}" -f $conflict.ExitCode, $conflict.Lines.Count)

$summaryPath = Join-Path $outDir "summary.txt"
$summary = @(
    "print-chain contract smoke summary"
    "artifact=$BinaryPath"
    "run=$outDir"
    "pass=$script:pass fail=$script:fail"
    $script:results
) -join "`n"
[System.IO.File]::WriteAllText($summaryPath, $summary + "`n", [System.Text.UTF8Encoding]::new($false))
Write-Output ("Summary: pass={0} fail={1}" -f $script:pass, $script:fail)
Write-Output ("Report: {0}" -f $summaryPath)
if ($script:fail -gt 0) { exit 1 }
exit 0