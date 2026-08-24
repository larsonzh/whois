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
    $OutDirRoot = Join-Path $PSScriptRoot "..\..\out\artifacts\print_meta_contract"
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

# Validate every metadata line: fixed 6-field TAB-separated k=v record.
function Test-MetaLines {
    param(
        [pscustomobject]$Run,
        [int]$ExpectedMeta
    )
    $meta = @($Run.Lines | Where-Object { $_ -match '^query=' })
    if ($meta.Count -ne $ExpectedMeta) {
        return $false
    }
    foreach ($line in $meta) {
        $fields = @($line -split "`t")
        if ($fields.Count -ne 6) { return $false }
        if ($fields[0] -notmatch '^query=.+$') { return $false }
        if ($fields[1] -notmatch '^rir=.+$') { return $false }
        if ($fields[2] -notmatch '^status=(success|error)$') { return $false }
        if ($fields[3] -notmatch '^duration_ms=\d+$') { return $false }
        if ($fields[4] -notmatch '^attempts=\d+$') { return $false }
        if ($fields[5] -notmatch '^redirects=\d+$') { return $false }
    }
    return $true
}

# Status must agree with the authoritative tail semantics (error @ error => error).
function Test-StatusConsistentWithTail {
    param([pscustomobject]$Run, [int]$ExpectedMeta)
    $meta = @($Run.Lines | Where-Object { $_ -match '^query=' })
    if ($meta.Count -ne $ExpectedMeta) { return $false }
    foreach ($line in $meta) {
        if ($line -match '^.*\tstatus=(success|error)\t') {
            $status = $Matches[1]
            $hasErrorTail = $Run.Lines -match '=== Authoritative RIR: error @ error'
            if ($status -eq 'error' -ne [bool]$hasErrorTail) { return $false }
        }
    }
    return $true
}

# 1. Online success: header + body + tail + one metadata line.
$online = Invoke-ClientCase -Name "single-success" -Arguments @(
    "--print-meta", "--pacing-disable", "-h", "arin", "-Q", "-t", "5", "-r", "0", "8.8.8.8")
$ok = Test-MetaLines $online 1
$ok = $ok -and (Test-StatusConsistentWithTail $online 1)
Add-Result -Name $online.Name -Passed ($ok -and $online.ExitCode -eq 0) `
    -Detail ("exit={0} lines={1}" -f $online.ExitCode, $online.Lines.Count)

# 2. Phase C early converge: status line + unknown tail + metadata.
$phasec = Invoke-ClientCase -Name "single-phasec" -Arguments @("--print-meta", "255.0.0.0")
$ok = Test-MetaLines $phasec 1
$ok = $ok -and (@($phasec.Lines | Where-Object { $_ -match '^=== Address Status:' }).Count -eq 1)
Add-Result -Name $phasec.Name -Passed ($ok -and $phasec.ExitCode -eq 0) `
    -Detail ("exit={0} lines={1}" -f $phasec.ExitCode, $phasec.Lines.Count)

# 3. Private query: two stable boundary lines + metadata.
$private = Invoke-ClientCase -Name "single-private" -Arguments @("--print-meta", "10.0.0.8")
$ok = Test-MetaLines $private 1
$ok = $ok -and (Test-StatusConsistentWithTail $private 1)
Add-Result -Name $private.Name -Passed ($ok -and $private.ExitCode -eq 0) `
    -Detail ("exit={0} lines={1}" -f $private.ExitCode, $private.Lines.Count)

# 4. DNS failure: error tail and status=error; non-zero exit preserved.
$invalid = Invoke-ClientCase -Name "single-invalid" -Arguments @(
    "--print-meta", "--pacing-disable", "-h", "no-such-host.invalid",
    "-t", "3", "-r", "0", "8.8.8.8")
$ok = Test-MetaLines $invalid 1
$ok = $ok -and (Test-StatusConsistentWithTail $invalid 1)
Add-Result -Name $invalid.Name -Passed ($ok -and $invalid.ExitCode -ne 0) `
    -Detail ("exit={0} lines={1}" -f $invalid.ExitCode, $invalid.Lines.Count)

# 5. --no-body combination: no body, metadata still present.
$nobody = Invoke-ClientCase -Name "nobody-combo" -Arguments @(
    "--no-body", "--print-meta", "255.0.0.0")
$ok = Test-MetaLines $nobody 1
$ok = $ok -and (@($nobody.Lines | Where-Object { $_ -notmatch '^=== (Query:|Address Status:|Authoritative RIR:)' -and $_ -notmatch '^query=' }).Count -eq 0)
Add-Result -Name $nobody.Name -Passed ($ok -and $nobody.ExitCode -eq 0) `
    -Detail ("exit={0} lines={1}" -f $nobody.ExitCode, $nobody.Lines.Count)

# 6. --fold combination: folded line then metadata line.
$fold = Invoke-ClientCase -Name "fold-combo" -Arguments @("--print-meta", "--fold", "255.0.0.0")
$ok = Test-MetaLines $fold 1
$ok = $ok -and ($fold.Lines.Count -eq 2)
Add-Result -Name $fold.Name -Passed ($ok -and $fold.ExitCode -eq 0) `
    -Detail ("exit={0} lines={1}" -f $fold.ExitCode, $fold.Lines.Count)

# 7. Explicit batch: one metadata line per input, input order preserved.
$batch = Invoke-ClientCase -Name "batch-explicit" -Arguments @("-B", "--print-meta") `
    -InputLines @("10.0.0.8", "255.0.0.0")
$ok = Test-MetaLines $batch 2
$metaQueries = @($batch.Lines | Where-Object { $_ -match '^query=' })
$orderOk = $metaQueries.Count -eq 2 -and
    $metaQueries[0] -match '^query=10\.0\.0\.8\t' -and
    $metaQueries[1] -match '^query=255\.0\.0\.0\t'
Add-Result -Name $batch.Name -Passed ($ok -and $orderOk -and $batch.ExitCode -eq 0) `
    -Detail ("exit={0} meta={1}" -f $batch.ExitCode, $metaQueries.Count)

# 8. --plain conflict: fail-fast before lookup, non-zero exit, stderr single line.
$conflict = Invoke-ClientCase -Name "plain-conflict" -Arguments @(
    "--print-meta", "--plain", "8.8.8.8")
$ok = $conflict.ExitCode -ne 0 -and
    $conflict.Stderr -match '--print-meta cannot be combined with --plain'
Add-Result -Name $conflict.Name -Passed $ok `
    -Detail ("exit={0} stderrLines={1}" -f $conflict.ExitCode, @($conflict.Stderr -split "`r?`n" | Where-Object { $_ }).Count)

# 9. Duplicate option is idempotent: single metadata line.
$dup = Invoke-ClientCase -Name "duplicate-option" -Arguments @(
    "--print-meta", "--print-meta", "255.0.0.0")
Add-Result -Name $dup.Name -Passed (Test-MetaLines $dup 1 -and $dup.ExitCode -eq 0) `
    -Detail ("exit={0} lines={1}" -f $dup.ExitCode, $dup.Lines.Count)

# 10. Lookup failure under --fold: folded error record then metadata.
$foldFailure = Invoke-ClientCase -Name "fold-failure" -Arguments @(
    "--fold", "--print-meta", "--pacing-disable", "-h", "no-such-host.invalid",
    "-t", "3", "-r", "0", "8.8.8.8")
$ok = Test-MetaLines $foldFailure 1
$ok = $ok -and $foldFailure.Lines.Count -eq 2
$ok = $ok -and $foldFailure.Lines[0] -eq "8.8.8.8 ERROR"
$ok = $ok -and $foldFailure.Lines[1] -match '^query=8\.8\.8\.8\trir=error\tstatus=error\t'
Add-Result -Name $foldFailure.Name -Passed ($ok -and $foldFailure.ExitCode -ne 0) `
    -Detail ("exit={0} lines={1}" -f $foldFailure.ExitCode, $foldFailure.Lines.Count)

# 11. Invalid IP/CIDR: preserve legacy unknown/success boundary and append metadata.
$invalidIp = Invoke-ClientCase -Name "invalid-ip" -Arguments @(
    "--print-meta", "999.999.999.999")
$ok = Test-MetaLines $invalidIp 1
$ok = $ok -and $invalidIp.Stdout -match '(?m)^query=999\.999\.999\.999\trir=unknown\tstatus=success\t'
Add-Result -Name $invalidIp.Name -Passed ($ok -and $invalidIp.ExitCode -eq 0) `
    -Detail ("exit={0} lines={1}" -f $invalidIp.ExitCode, $invalidIp.Lines.Count)

# 12. Invalid IP/CIDR under --fold: folded unknown record then metadata.
$invalidFold = Invoke-ClientCase -Name "invalid-ip-fold" -Arguments @(
    "--fold", "--print-meta", "999.999.999.999")
$ok = Test-MetaLines $invalidFold 1
$ok = $ok -and $invalidFold.Lines.Count -eq 2
$ok = $ok -and $invalidFold.Lines[0] -eq "999.999.999.999 UNKNOWN"
Add-Result -Name $invalidFold.Name -Passed ($ok -and $invalidFold.ExitCode -eq 0) `
    -Detail ("exit={0} lines={1}" -f $invalidFold.ExitCode, $invalidFold.Lines.Count)

# 13. Explicit-host private rejection: append zero-valued unknown/success metadata.
$privateExplicit = Invoke-ClientCase -Name "private-explicit" -Arguments @(
    "--print-meta", "-h", "arin", "10.0.0.8")
$ok = Test-MetaLines $privateExplicit 1
$ok = $ok -and $privateExplicit.Lines -contains "query=10.0.0.8`trir=unknown`tstatus=success`tduration_ms=0`tattempts=0`tredirects=0"
Add-Result -Name $privateExplicit.Name -Passed ($ok -and $privateExplicit.ExitCode -eq 0) `
    -Detail ("exit={0} lines={1}" -f $privateExplicit.ExitCode, $privateExplicit.Lines.Count)

# 14. Security rejection: metadata-only error record without lookup.
$suspicious = Invoke-ClientCase -Name "suspicious-rejection" -Arguments @(
    "--print-meta", "bad;query")
$ok = Test-MetaLines $suspicious 1
$ok = $ok -and $suspicious.Lines.Count -eq 1
$ok = $ok -and $suspicious.Lines[0] -match '^query=bad;query\trir=error\tstatus=error\tduration_ms=0\tattempts=0\tredirects=0$'
Add-Result -Name $suspicious.Name -Passed ($ok -and $suspicious.ExitCode -ne 0) `
    -Detail ("exit={0} lines={1}" -f $suspicious.ExitCode, $suspicious.Lines.Count)

# 15. Metadata normalization removes leading/trailing whitespace.
$normalized = Invoke-ClientCase -Name "value-normalization" -Arguments @(
    "--print-meta", " 255.0.0.0 ")
$ok = Test-MetaLines $normalized 1
$meta = @($normalized.Lines | Where-Object { $_ -match '^query=' })
$ok = $ok -and $meta.Count -eq 1 -and $meta[0] -match '^query=255\.0\.0\.0\t'
Add-Result -Name $normalized.Name -Passed ($ok -and $normalized.ExitCode -eq 0) `
    -Detail ("exit={0} meta={1}" -f $normalized.ExitCode, $meta.Count)

# 16. Redirected stdin without -B: automatic batch mode preserves order.
$batchImplicit = Invoke-ClientCase -Name "batch-implicit" -Arguments @("--print-meta") `
    -InputLines @("10.0.0.8", "255.0.0.0")
$ok = Test-MetaLines $batchImplicit 2
$metaQueries = @($batchImplicit.Lines | Where-Object { $_ -match '^query=' })
$orderOk = $metaQueries.Count -eq 2 -and
    $metaQueries[0] -match '^query=10\.0\.0\.8\t' -and
    $metaQueries[1] -match '^query=255\.0\.0\.0\t'
Add-Result -Name $batchImplicit.Name -Passed ($ok -and $orderOk -and $batchImplicit.ExitCode -eq 0) `
    -Detail ("exit={0} meta={1}" -f $batchImplicit.ExitCode, $metaQueries.Count)

# 17. Grep affects only the body; metadata remains present.
$grepCombo = Invoke-ClientCase -Name "grep-combo" -Arguments @(
    "--print-meta", "--grep", "NetName", "--pacing-disable",
    "-h", "arin", "-Q", "-t", "5", "-r", "0", "8.8.8.8")
$ok = Test-MetaLines $grepCombo 1
$ok = $ok -and (Test-StatusConsistentWithTail $grepCombo 1)
Add-Result -Name $grepCombo.Name -Passed ($ok -and $grepCombo.ExitCode -eq 0) `
    -Detail ("exit={0} lines={1}" -f $grepCombo.ExitCode, $grepCombo.Lines.Count)

# 18. --fold alone preserves the legacy empty stdout on lookup failure.
$foldFailureLegacy = Invoke-ClientCase -Name "fold-failure-without-meta" -Arguments @(
    "--fold", "--pacing-disable", "-h", "no-such-host.invalid",
    "-t", "3", "-r", "0", "8.8.8.8")
$ok = $foldFailureLegacy.ExitCode -ne 0
$ok = $ok -and $foldFailureLegacy.Lines.Count -eq 0
$ok = $ok -and $foldFailureLegacy.Stderr -match 'Error: Query failed for 8\.8\.8\.8'
Add-Result -Name $foldFailureLegacy.Name -Passed $ok `
    -Detail ("exit={0} lines={1}" -f $foldFailureLegacy.ExitCode, $foldFailureLegacy.Lines.Count)

$summaryPath = Join-Path $outDir "summary.txt"
$summary = @(
    "print-meta contract smoke summary"
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
