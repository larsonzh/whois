param(
    [string]$GitBashPath = "C:\Program Files\Git\bin\bash.exe",
    [string]$Version = "3.2.12",
    [string]$BinaryPath = "d:\LZProjects\whois\release\lzispro\whois\whois-win64.exe",
    [string]$RemoteIp = "10.0.0.199",
    [string]$User = "larson",
    [string]$KeyPath = "/c/ssh/id_rsa",
    [string]$Queries = "8.8.8.8 1.1.1.1 10.0.0.8",
    [string]$VerifyRound3Queries = "64.6.64.6 103.53.144.0/22 2620:fe::fe",
    [string]$SyncDir = "/d/LZProjects/lzispro/release/lzispro/whois;/d/LZProjects/whois/release/lzispro/whois",
    [string]$Smoke = "1",
    [string]$Golden = "1",
    [AllowEmptyString()][string]$SmokeArgs = "",
    [AllowEmptyString()][string]$CflagsExtra = "",
    [string]$OptProfile = "lto-auto",
    [string]$Step47ListFile = "testdata/step47_reserved_list_default.txt",
    [string]$PreclassThresholdFile = "testdata/preclass_p1_group_thresholds_default.txt",
    [ValidateRange(0, 2)][int]$NoDeltaRetryMax = 1,
    [ValidateRange(0, 2)][int]$D6RetryMax = 1,
    [ValidateRange(1, 8)][int]$StartRound = 1,
    [ValidateRange(1, 8)][int]$EndRound = 8,
    [switch]$ResetCodeStepState,
    [string]$AutopilotOutDirRoot = "d:\LZProjects\whois\out\artifacts\autopilot_dev_recheck_8round",
    [string]$SessionOutDirRoot = "d:\LZProjects\whois\out\artifacts\dev_verify_multiround",
    [string]$CodeStepScript = "tools\test\autopilot_code_step_rounds.ps1"
)

$ErrorActionPreference = "Stop"

if ($StartRound -gt $EndRound) {
    throw "StartRound must be less than or equal to EndRound"
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
Set-Location $repoRoot

$autopilotScript = Join-Path $repoRoot "tools\test\autopilot_dev_recheck_8round.ps1"
$codeStepScriptPath = if ([System.IO.Path]::IsPathRooted($CodeStepScript)) { $CodeStepScript } else { Join-Path $repoRoot $CodeStepScript }

if (-not (Test-Path -LiteralPath $GitBashPath)) {
    throw "Git Bash not found: $GitBashPath"
}
if (-not (Test-Path -LiteralPath $autopilotScript)) {
    throw "Autopilot script not found: $autopilotScript"
}
if (-not (Test-Path -LiteralPath $codeStepScriptPath)) {
    throw "Code-step script not found: $codeStepScriptPath"
}

if ($ResetCodeStepState.IsPresent) {
    & $codeStepScriptPath -Reset
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to reset code-step state"
    }
}

$sessionStamp = Get-Date -Format "yyyyMMdd-HHmmss"
$sessionOutDir = Join-Path $SessionOutDirRoot $sessionStamp
New-Item -ItemType Directory -Path $sessionOutDir -Force | Out-Null

$rows = @()

for ($round = $StartRound; $round -le $EndRound; $round++) {
    $phase = if ($round -le 4) { "DEV" } else { "VERIFY" }
    $phaseRound = if ($phase -eq "DEV") { $round } else { $round - 4 }
    $roundTag = if ($phase -eq "DEV") { "D$phaseRound" } else { "V$phaseRound" }

    $mode = if ($phase -eq "DEV") { "code-change" } else { "gate-only" }

    Write-Output ("[DEV-VERIFY-MULTI] round_start={0} phase={1} mode={2}" -f $roundTag, $phase, $mode)

    $autopilotParams = @{
        Mode = $mode
        StartRound = $round
        EndRound = $round
        Version = $Version
        BinaryPath = $BinaryPath
        RemoteIp = $RemoteIp
        User = $User
        KeyPath = $KeyPath
        Smoke = $Smoke
        Queries = $Queries
        VerifyRound3Queries = $VerifyRound3Queries
        SyncDir = $SyncDir
        Golden = $Golden
        OptProfile = $OptProfile
        Step47ListFile = $Step47ListFile
        PreclassThresholdFile = $PreclassThresholdFile
        GitBashPath = $GitBashPath
        NoDeltaRetryMax = $NoDeltaRetryMax
        D6RetryMax = $D6RetryMax
        OutDirRoot = $AutopilotOutDirRoot
    }

    if (-not [string]::IsNullOrWhiteSpace($SmokeArgs)) {
        $autopilotParams["SmokeArgs"] = $SmokeArgs
    }
    if (-not [string]::IsNullOrWhiteSpace($CflagsExtra)) {
        $autopilotParams["CflagsExtra"] = $CflagsExtra
    }
    if ($phase -eq "DEV") {
        $autopilotParams["CodeStepCommand"] = "& '$codeStepScriptPath'"
    }

    $raw = & $autopilotScript @autopilotParams 2>&1
    $exitCode = $LASTEXITCODE
    if ($null -eq $exitCode) { $exitCode = 0 }

    $lines = @()
    foreach ($line in $raw) {
        if ($line -is [System.Management.Automation.ErrorRecord]) {
            $lines += $line.Exception.Message
        }
        else {
            $lines += [string]$line
        }
    }

    foreach ($line in $lines) {
        Write-Output $line
    }

    $roundLog = Join-Path $sessionOutDir ("{0}.log" -f $roundTag)
    $lines | Out-File -FilePath $roundLog -Encoding utf8

    $outDir = ""
    $result = ""
    foreach ($line in $lines) {
        if ($line -match '^\[AUTOPILOT-8R\] out_dir=(.+)$') {
            $outDir = $Matches[1].Trim()
        }
        if ($line -match '^\[AUTOPILOT-8R\] result=(pass|fail)$') {
            $result = $Matches[1]
        }
    }

    $roundPass = ($exitCode -eq 0 -and $result -eq "pass")

    $rows += [pscustomobject]@{
        Round = $round
        Phase = $phase
        RoundTag = $roundTag
        Mode = $mode
        ExitCode = $exitCode
        Result = if ($result) { $result } else { "unknown" }
        RoundPass = $roundPass
        AutopilotOutDir = $outDir
        LogFile = $roundLog
    }

    $partialCsv = Join-Path $sessionOutDir "summary_partial.csv"
    $rows | Export-Csv -Path $partialCsv -NoTypeInformation -Encoding UTF8

    if (-not $roundPass) {
        Write-Output ("[DEV-VERIFY-MULTI] round_fail={0}" -f $roundTag)
        break
    }

    Write-Output ("[DEV-VERIFY-MULTI] round_pass={0}" -f $roundTag)
}

$summaryCsv = Join-Path $sessionOutDir "summary.csv"
$summaryTxt = Join-Path $sessionOutDir "summary.txt"
$rows | Export-Csv -Path $summaryCsv -NoTypeInformation -Encoding UTF8
$rows | Format-Table -AutoSize | Out-String | Out-File -FilePath $summaryTxt -Encoding utf8

$expected = $EndRound - $StartRound + 1
$allPass = ($rows.Count -eq $expected) -and (@($rows | Where-Object { -not $_.RoundPass }).Count -eq 0)

Write-Output ("[DEV-VERIFY-MULTI] out_dir={0}" -f $sessionOutDir)
Write-Output ("[DEV-VERIFY-MULTI] summary_csv={0}" -f $summaryCsv)
Write-Output ("[DEV-VERIFY-MULTI] summary_txt={0}" -f $summaryTxt)

if ($allPass) {
    Write-Output "[DEV-VERIFY-MULTI] result=pass"
    exit 0
}

Write-Output "[DEV-VERIFY-MULTI] result=fail"
exit 1
