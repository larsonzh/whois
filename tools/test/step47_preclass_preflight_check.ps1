param(
    [string]$BinaryPath = "d:\LZProjects\whois\release\lzispro\whois\whois-win64.exe",
    [string]$Step47ListFile = "testdata/step47_reserved_list_default.txt",
    [string]$PreclassThresholdFile = "testdata/preclass_p1_group_thresholds_default.txt",
    [string]$OutDirRoot = ""
)

$ErrorActionPreference = "Continue"
$PSNativeCommandUseErrorActionPreference = $false

if (-not (Test-Path $BinaryPath)) {
    Write-Error "Binary not found: $BinaryPath"
    exit 2
}

if (-not (Test-Path $Step47ListFile)) {
    Write-Error "Step47 list file not found: $Step47ListFile"
    exit 2
}

if (-not (Test-Path $PreclassThresholdFile)) {
    Write-Error "Preclass threshold file not found: $PreclassThresholdFile"
    exit 2
}

if (-not $OutDirRoot -or $OutDirRoot.Trim().Length -eq 0) {
    $OutDirRoot = Join-Path $PSScriptRoot "..\..\out\artifacts\step47_preclass_preflight"
}

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$outDir = Join-Path $OutDirRoot $stamp
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

$targetScript = Join-Path $PSScriptRoot "step47_prerelease_check.ps1"
if (-not (Test-Path $targetScript)) {
    Write-Error "Target script not found: $targetScript"
    exit 2
}

function ConvertTo-NormalizedLine {
    param([object[]]$Raw)

    return $Raw | ForEach-Object {
        if ($_ -is [System.Management.Automation.ErrorRecord]) {
            $_.Exception.Message
        }
        else {
            $_
        }
    }
}

function Normalize-WrappedWords {
    param([string]$Text)

    if ($null -eq $Text) {
        return ""
    }

    # Join hard-wrapped lines that break words in the middle.
    return [regex]::Replace($Text, '(?<=[A-Za-z0-9])\r?\n\s*(?=[A-Za-z0-9])', '')
}

function Invoke-Case {
    param(
        [string]$Name,
        [string[]]$CaseArgs,
        [bool]$ExpectPass,
        [string[]]$MustMatchRegex,
        [int]$RetryOnFailCount = 0,
        [string]$RetryIfRegex = ""
    )

    $maxAttempts = 1 + [Math]::Max(0, $RetryOnFailCount)
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        Write-Output ("[STEP47-PREFLIGHT] case={0} status=running attempt={1}/{2}" -f $Name, $attempt, $maxAttempts)

        $raw = & powershell -NoProfile -ExecutionPolicy Bypass -File $targetScript @CaseArgs 2>&1
        $lines = ConvertTo-NormalizedLine -Raw $raw
        $exitCode = $LASTEXITCODE
        if ($null -eq $exitCode) {
            $exitCode = 0
        }

        $attemptSuffix = if ($attempt -eq 1) { "" } else { ".retry{0}" -f ($attempt - 1) }
        $logPath = Join-Path $outDir ("{0}{1}.log" -f $Name, $attemptSuffix)
        $lines | Out-File -FilePath $logPath -Encoding utf8
        $text = ($lines -join "`n")
        $matchText = Normalize-WrappedWords -Text $text

        $exitOk = $false
        if ($ExpectPass) {
            $exitOk = ($exitCode -eq 0)
        }
        else {
            $exitOk = ($exitCode -ne 0)
        }

        $matchOk = $true
        foreach ($rx in $MustMatchRegex) {
            if (-not [regex]::IsMatch($matchText, $rx)) {
                $matchOk = $false
                break
            }
        }

        $pass = ($exitOk -and $matchOk)
        $status = if ($pass) { "pass" } else { "fail" }
        Write-Output ("[STEP47-PREFLIGHT] case={0} status={1} attempt={2}/{3} exit={4} log={5}" -f $Name, $status, $attempt, $maxAttempts, $exitCode, $logPath)

        if ($pass) {
            return [pscustomobject]@{
                Case = $Name
                ExitCode = $exitCode
                ExpectPass = $ExpectPass
                ExitOk = $exitOk
                MatchOk = $matchOk
                Pass = $pass
                Log = $logPath
            }
        }

        if ($attempt -lt $maxAttempts) {
            $retryAllowed = $true
            if ($RetryIfRegex -and $RetryIfRegex.Trim().Length -gt 0) {
                $retryAllowed = [regex]::IsMatch($text, $RetryIfRegex)
            }

            if ($retryAllowed) {
                Write-Output ("[STEP47-PREFLIGHT] case={0} action=retry reason=transient-like-failure next_attempt={1}" -f $Name, ($attempt + 1))
                continue
            }
        }

        return [pscustomobject]@{
            Case = $Name
            ExitCode = $exitCode
            ExpectPass = $ExpectPass
            ExitOk = $exitOk
            MatchOk = $matchOk
            Pass = $pass
            Log = $logPath
        }
    }
}

$common = @(
    "-BinaryPath", $BinaryPath,
    "-Scope", "reserved",
    "-EnableEarlyUnknown",
    "-ListFile", $Step47ListFile
)

$results = @()

$results += (Invoke-Case -Name "baseline-disabled" -CaseArgs $common -ExpectPass $true -MustMatchRegex @(
    '(?m)^\[STEP47-CHECK\] preclass_gate=disabled$',
    '(?m)^\[STEP47-CHECK\] result=pass$'
) | Select-Object -Last 1)

$results += (Invoke-Case -Name "gate-enabled-valid-threshold" -CaseArgs ($common + @(
    "-RunPreclassP1Gate",
    "-PreclassGroupThresholdFile", $PreclassThresholdFile
)) -ExpectPass $true -MustMatchRegex @(
    '(?m)^\[STEP47-CHECK\] preclass_gate=enabled',
    '(?m)^\[STEP47-CHECK\] step=preclass-p1-gate status=pass',
    '(?m)^\[STEP47-CHECK\] result=pass$'
) -RetryOnFailCount 1 -RetryIfRegex '(?m)^\[STEP47-CHECK\] step=rollback status=fail|^\[STEP47-ROLLBACK\] result=fail$' | Select-Object -Last 1)

$results += (Invoke-Case -Name "gate-enabled-missing-threshold" -CaseArgs ($common + @(
    "-RunPreclassP1Gate",
    "-PreclassGroupThresholdFile", "testdata/not_exists_thresholds.txt"
)) -ExpectPass $false -MustMatchRegex @(
    'Preclass group threshold\s*file not found'
) | Select-Object -Last 1)

$results += (Invoke-Case -Name "gate-enabled-missing-case-list" -CaseArgs ($common + @(
    "-RunPreclassP1Gate",
    "-PreclassCaseListFile", "testdata/not_exists_cases.txt",
    "-PreclassGroupThresholdFile", $PreclassThresholdFile
)) -ExpectPass $false -MustMatchRegex @(
    'Preclass case list\s*file not found'
) | Select-Object -Last 1)

$summaryCsv = Join-Path $outDir "summary.csv"
$summaryTxt = Join-Path $outDir "summary.txt"
$results | Export-Csv -Path $summaryCsv -NoTypeInformation -Encoding UTF8
$results | Format-Table -AutoSize | Out-String | Out-File -FilePath $summaryTxt -Encoding utf8

$failCount = @($results | Where-Object { -not $_.Pass }).Count
$passCount = @($results | Where-Object { $_.Pass }).Count

Write-Output ("[STEP47-PREFLIGHT] out_dir={0}" -f $outDir)
Write-Output ("[STEP47-PREFLIGHT] summary_csv={0}" -f $summaryCsv)
Write-Output ("[STEP47-PREFLIGHT] summary_txt={0}" -f $summaryTxt)
Write-Output ("[STEP47-PREFLIGHT] pass={0} fail={1}" -f $passCount, $failCount)

if ($failCount -gt 0) {
    Write-Output "[STEP47-PREFLIGHT] result=fail"
    exit 1
}

Write-Output "[STEP47-PREFLIGHT] result=pass"
exit 0