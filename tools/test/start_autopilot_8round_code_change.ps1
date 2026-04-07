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
    [string]$OutDirRoot = "d:\LZProjects\whois\out\artifacts\autopilot_dev_recheck_8round"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $GitBashPath)) {
    throw "Git Bash not found: $GitBashPath"
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
Set-Location $repoRoot

$codeStepScript = Join-Path $repoRoot "tools\test\autopilot_code_step_rounds.ps1"
$autopilotScript = Join-Path $repoRoot "tools\test\autopilot_dev_recheck_8round.ps1"

if (-not (Test-Path -LiteralPath $codeStepScript)) {
    throw "Code-step script not found: $codeStepScript"
}
if (-not (Test-Path -LiteralPath $autopilotScript)) {
    throw "Autopilot script not found: $autopilotScript"
}

# Reset per-run state so D1-D4 placeholders are applied in order.
& $codeStepScript -Reset
if ($LASTEXITCODE -ne 0) {
    throw "Failed to reset code-step state"
}

$codeStepCommand = "& '$codeStepScript'"

& $autopilotScript `
    -Mode code-change `
    -CodeStepCommand $codeStepCommand `
    -StartRound 1 `
    -EndRound 8 `
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
    -GitBashPath $GitBashPath `
    -NoDeltaRetryMax $NoDeltaRetryMax `
    -D6RetryMax $D6RetryMax `
    -OutDirRoot $OutDirRoot

exit $LASTEXITCODE
