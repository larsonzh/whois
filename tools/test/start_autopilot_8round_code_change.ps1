param(
    [string]$GitBashPath = "C:\Program Files\Git\bin\bash.exe",
    [string]$Version = "3.2.12",
    [string]$BinaryPath = "d:\LZProjects\whois\release\lzispro\whois\whois-win64.exe",
    [string]$RemoteIp = "10.0.0.199",
    [string]$User = "larson",
    [string]$KeyPath = "/c/Users/妙妙呜/.ssh/id_rsa",
    [string]$Queries = "8.8.8.8 1.1.1.1 10.0.0.8",
    [string]$VerifyRound3Queries = "64.6.64.6 103.53.144.0/22 2620:fe::fe",
    [string]$SyncDir = "/d/LZProjects/lzispro/release/lzispro/whois;/d/LZProjects/whois/release/lzispro/whois",
    [string]$Smoke = "1",
    [string]$Golden = "1",
    [string]$OptProfile = "lto-auto",
    [string]$Step47ListFile = "testdata/step47_reserved_list_default.txt",
    [string]$PreclassThresholdFile = "testdata/preclass_p1_group_thresholds_default.txt",
    [ValidateRange(0, 2)][int]$NoDeltaRetryMax = 1,
    [ValidateRange(0, 2)][int]$D6RetryMax = 1,
    [string]$OutDirRoot = "d:\LZProjects\whois\out\artifacts\autopilot_dev_recheck_8round",
    [string]$SessionOutDirRoot = "d:\LZProjects\whois\out\artifacts\dev_verify_multiround",
    [AllowEmptyString()][string]$TaskDefinitionFile = "testdata/autopilot_code_step_tasks_default.json"
)

$ErrorActionPreference = "Stop"

function Format-ElapsedString {
    param([TimeSpan]$Elapsed)

    $hours = [int][Math]::Floor($Elapsed.TotalHours)
    return ("{0:00}:{1:00}:{2:00}.{3:000}" -f $hours, $Elapsed.Minutes, $Elapsed.Seconds, $Elapsed.Milliseconds)
}

$runStart = Get-Date
Write-Output ("[AUTOPILOT-CODE-CHANGE-8R] started_at={0}" -f $runStart.ToString("yyyy-MM-dd HH:mm:ss"))

if (-not (Test-Path -LiteralPath $GitBashPath)) {
    throw "Git Bash not found: $GitBashPath"
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
Set-Location $repoRoot

$multiRoundScript = Join-Path $repoRoot "tools\test\start_dev_verify_8round_multiround.ps1"

if (-not (Test-Path -LiteralPath $multiRoundScript)) {
    throw "Multi-round script not found: $multiRoundScript"
}

& $multiRoundScript `
    -GitBashPath $GitBashPath `
    -StartRound 1 `
    -EndRound 8 `
    -ResetCodeStepState `
    -Version $Version `
    -BinaryPath $BinaryPath `
    -RemoteIp $RemoteIp `
    -User $User `
    -KeyPath $KeyPath `
    -Smoke $Smoke `
    -Queries $Queries `
    -VerifyRound3Queries $VerifyRound3Queries `
    -SyncDir $SyncDir `
    -Golden $Golden `
    -OptProfile $OptProfile `
    -Step47ListFile $Step47ListFile `
    -PreclassThresholdFile $PreclassThresholdFile `
    -NoDeltaRetryMax $NoDeltaRetryMax `
    -D6RetryMax $D6RetryMax `
    -AutopilotOutDirRoot $OutDirRoot `
    -SessionOutDirRoot $SessionOutDirRoot `
    -TaskDefinitionFile $TaskDefinitionFile

$exitCode = if ($null -eq $LASTEXITCODE) { 0 } else { $LASTEXITCODE }
$runEnd = Get-Date
$elapsed = $runEnd - $runStart
Write-Output ("[AUTOPILOT-CODE-CHANGE-8R] finished_at={0}" -f $runEnd.ToString("yyyy-MM-dd HH:mm:ss"))
Write-Output ("[AUTOPILOT-CODE-CHANGE-8R] elapsed={0} total_seconds={1:N3}" -f (Format-ElapsedString -Elapsed $elapsed), $elapsed.TotalSeconds)

exit $exitCode
