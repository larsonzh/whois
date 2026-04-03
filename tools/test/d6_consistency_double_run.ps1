param(
    [string]$BinaryPath = "d:\LZProjects\whois\release\lzispro\whois\whois-win64.exe",
    [string]$RemoteIp = "10.0.0.199",
    [string]$User = "larson",
    [string]$KeyPath = "/c/Users/妙妙呜/.ssh/id_rsa",
    [string]$Smoke = "1",
    [string]$Queries = "8.8.8.8 1.1.1.1 10.0.0.8",
    [string]$SyncDir = "/d/LZProjects/lzispro/release/lzispro/whois;/d/LZProjects/whois/release/lzispro/whois",
    [AllowEmptyString()][string]$SmokeArgs = "",
    [string]$Golden = "1",
    [AllowEmptyString()][string]$CflagsExtra = "",
    [string]$OptProfile = "lto-auto",
    [string]$Step47ListFile = "testdata/step47_reserved_list_default.txt",
    [string]$PreclassThresholdFile = "testdata/preclass_p1_group_thresholds_default.txt",
    [string]$BashPath = "C:\Program Files\Git\bin\bash.exe",
    [string]$OutDirRoot = ""
)

$ErrorActionPreference = "Continue"
$PSNativeCommandUseErrorActionPreference = $false

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

function ConvertTo-GitBashPath {
    param([string]$Path)

    $p = $Path -replace "\\", "/"
    if ($p -match "^[A-Za-z]:(/.*)$") {
        $drive = $p.Substring(0, 1).ToLowerInvariant()
        return "/$drive$($Matches[1])"
    }
    return $p
}

function Get-MatchValue {
    param(
        [string]$Text,
        [string]$Regex,
        [int]$GroupIndex = 1
    )

    $m = [regex]::Match($Text, $Regex)
    if ($m.Success) {
        return $m.Groups[$GroupIndex].Value
    }
    return ""
}

if (-not (Test-Path $BinaryPath)) {
    Write-Error "Binary not found: $BinaryPath"
    exit 2
}
if (-not (Test-Path $BashPath)) {
    Write-Error "Git Bash not found: $BashPath"
    exit 2
}
if (-not (Test-Path $PreclassThresholdFile)) {
    Write-Error "Preclass threshold file not found: $PreclassThresholdFile"
    exit 2
}
if (-not (Test-Path $Step47ListFile)) {
    Write-Error "Step47 list file not found: $Step47ListFile"
    exit 2
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$repoRootUnix = ConvertTo-GitBashPath -Path $repoRoot

if (-not $OutDirRoot -or $OutDirRoot.Trim().Length -eq 0) {
    $OutDirRoot = Join-Path $PSScriptRoot "..\..\out\artifacts\d6_consistency_double_round"
}
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$outDir = Join-Path $OutDirRoot $stamp
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

$smokeArgsNorm = $SmokeArgs
if ($smokeArgsNorm -in @("--", "NONE", "__EMPTY__")) {
    $smokeArgsNorm = ""
}

$smokeArgsPart = ""
if ($smokeArgsNorm -and $smokeArgsNorm.Trim().Length -gt 0) {
    $smokeArgsPart = " -a '$smokeArgsNorm'"
}

$strictBase = "WHOIS_STRICT_VERSION=1 tools/remote/remote_build_and_test.sh -H $RemoteIp -u $User -k '$KeyPath' -r $Smoke -q '$Queries' -s '$SyncDir' -P 1$smokeArgsPart -G $Golden -E '$CflagsExtra' -O '$OptProfile' -K 1 -N 1 -C '$Step47ListFile' -V '$PreclassThresholdFile'"
$strictCmd = "cd $repoRootUnix; $strictBase"

$roundRows = @()

for ($round = 1; $round -le 2; $round++) {
    $strictRaw = & $BashPath -lc $strictCmd 2>&1
    $strictLines = ConvertTo-NormalizedLine -Raw $strictRaw
    $strictExit = $LASTEXITCODE
    if ($null -eq $strictExit) {
        $strictExit = 0
    }

    $strictLog = Join-Path $outDir ("round{0}_strict.log" -f $round)
    $strictLines | Out-File -FilePath $strictLog -Encoding utf8
    $strictText = ($strictLines -join "`n")

    $strictTs = Get-MatchValue -Text $strictText -Regex 'out/artifacts/([0-9]{8}-[0-9]{6})'
    $preflightTs = Get-MatchValue -Text $strictText -Regex 'step47_preclass_preflight[\\/]([0-9]{8}-[0-9]{6})'
    $tableGuardTs = Get-MatchValue -Text $strictText -Regex 'preclass_table_guard[\\/]([0-9]{8}-[0-9]{6})'

    $hashPass = [regex]::IsMatch($strictText, '(?m)^\[remote_build\] Local hash verify: PASS$')
    $goldenPass = [regex]::IsMatch($strictText, '(?m)^\[golden\] PASS$')
    $referralPass = [regex]::IsMatch($strictText, '(?m)^\[remote_build\] referral check: PASS$')
    $preflightPass = [regex]::IsMatch($strictText, '(?m)^\[STEP47-PREFLIGHT\] result=pass$')
    $tableGuardPass = [regex]::IsMatch($strictText, '(?m)^\[PRECLASS-TABLE-GUARD\] result=pass$')

    $p0Raw = & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "preclass_min_matrix.ps1") -BinaryPath $BinaryPath 2>&1
    $p0Lines = ConvertTo-NormalizedLine -Raw $p0Raw
    $p0Exit = $LASTEXITCODE
    if ($null -eq $p0Exit) {
        $p0Exit = 0
    }
    $p0Log = Join-Path $outDir ("round{0}_p0.log" -f $round)
    $p0Lines | Out-File -FilePath $p0Log -Encoding utf8
    $p0Text = ($p0Lines -join "`n")
    $p0OutDir = Get-MatchValue -Text $p0Text -Regex '(?m)^\[PRECLASS-MATRIX\] out_dir=(.+)$'
    $p0Pass = ($p0Exit -eq 0) -and [regex]::IsMatch($p0Text, '(?m)^\[PRECLASS-MATRIX\] result=pass$')

    $p1Raw = & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "preclass_p1_gate_matrix.ps1") -BinaryPath $BinaryPath -GroupPassThresholdFile $PreclassThresholdFile 2>&1
    $p1Lines = ConvertTo-NormalizedLine -Raw $p1Raw
    $p1Exit = $LASTEXITCODE
    if ($null -eq $p1Exit) {
        $p1Exit = 0
    }
    $p1Log = Join-Path $outDir ("round{0}_p1.log" -f $round)
    $p1Lines | Out-File -FilePath $p1Log -Encoding utf8
    $p1Text = ($p1Lines -join "`n")
    $p1OutDir = Get-MatchValue -Text $p1Text -Regex '(?m)^\[PRECLASS-P1\] out_dir=(.+)$'
    $p1Pass = ($p1Exit -eq 0) -and [regex]::IsMatch($p1Text, '(?m)^\[PRECLASS-P1\] result=pass$')

    $roundPass = (
        ($strictExit -eq 0) -and
        $hashPass -and
        $goldenPass -and
        $referralPass -and
        $preflightPass -and
        $tableGuardPass -and
        $p0Pass -and
        $p1Pass
    )

    $roundRows += [pscustomobject]@{
        Round = $round
        StrictExit = $strictExit
        StrictTs = $strictTs
        PreflightTs = $preflightTs
        TableGuardTs = $tableGuardTs
        HashPass = $hashPass
        GoldenPass = $goldenPass
        ReferralPass = $referralPass
        PreflightPass = $preflightPass
        TableGuardPass = $tableGuardPass
        P0Pass = $p0Pass
        P1Pass = $p1Pass
        P0OutDir = $p0OutDir
        P1OutDir = $p1OutDir
        RoundPass = $roundPass
        StrictLog = $strictLog
        P0Log = $p0Log
        P1Log = $p1Log
    }

    Write-Output ("[D6-CONSISTENCY] round={0} status={1} strict_ts={2} preflight_ts={3} table_guard_ts={4}" -f $round, ($(if ($roundPass) { 'pass' } else { 'fail' })), $strictTs, $preflightTs, $tableGuardTs)
}

$summaryCsv = Join-Path $outDir "summary.csv"
$summaryTxt = Join-Path $outDir "summary.txt"
$roundRows | Export-Csv -Path $summaryCsv -NoTypeInformation -Encoding UTF8
$roundRows | Format-Table -AutoSize | Out-String | Out-File -FilePath $summaryTxt -Encoding utf8

$allPass = (@($roundRows | Where-Object { $_.RoundPass }).Count -eq 2)
$strictTsConsistent = ($roundRows[0].StrictTs -ne "" -and $roundRows[1].StrictTs -ne "")

Write-Output ("[D6-CONSISTENCY] out_dir={0}" -f $outDir)
Write-Output ("[D6-CONSISTENCY] summary_csv={0}" -f $summaryCsv)
Write-Output ("[D6-CONSISTENCY] summary_txt={0}" -f $summaryTxt)

if ($allPass -and $strictTsConsistent) {
    Write-Output "[D6-CONSISTENCY] result=pass"
    exit 0
}

Write-Output "[D6-CONSISTENCY] result=fail"
exit 1
