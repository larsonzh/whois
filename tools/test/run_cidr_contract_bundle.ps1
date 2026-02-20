param(
    [string]$BinaryPath = "d:\LZProjects\whois\release\lzispro\whois\whois-win64.exe",
    [string]$BodyOutDir = "",
    [string]$MatrixOutDir = "",
    [string]$SummaryOutDir = "",
    [string]$RirIpPref = "arin=ipv6",
    [string]$PreferIpv4 = "true",
    [string]$SaveLogs = "true",
    [string]$CasesFile = "testdata/cidr_matrix_cases_draft.tsv"
)

$ErrorActionPreference = "Continue"
$PSNativeCommandUseErrorActionPreference = $false

if (-not (Test-Path $BinaryPath)) {
    Write-Error "Binary not found: $BinaryPath"
    exit 2
}

if (-not $BodyOutDir -or $BodyOutDir.Trim().Length -eq 0) {
    $BodyOutDir = Join-Path $PSScriptRoot "..\..\out\artifacts\cidr_body_contract"
}
if (-not $MatrixOutDir -or $MatrixOutDir.Trim().Length -eq 0) {
    $MatrixOutDir = Join-Path $PSScriptRoot "..\..\out\artifacts\redirect_matrix"
}
if (-not $SummaryOutDir -or $SummaryOutDir.Trim().Length -eq 0) {
    $SummaryOutDir = Join-Path $PSScriptRoot "..\..\out\artifacts\cidr_bundle"
}
if (-not (Test-Path $SummaryOutDir)) {
    New-Item -ItemType Directory -Path $SummaryOutDir | Out-Null
}

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$summaryPath = Join-Path $SummaryOutDir ("cidr_bundle_summary_{0}.txt" -f $stamp)

function Get-LatestReport {
    param([string]$BaseDir)

    if (-not (Test-Path $BaseDir)) {
        return ""
    }

    $latest = Get-ChildItem -Path $BaseDir -Recurse -File -Filter "*_report_*.txt" -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1

    if ($null -eq $latest) {
        return ""
    }

    return $latest.FullName
}

function Write-BundleSummary {
    param(
        [string]$Result,
        [string]$BodyStatus,
        [string]$MatrixStatus,
        [string]$BodyReport,
        [string]$MatrixReport,
        [int]$ExitCode
    )

    @(
        "timestamp=$stamp"
        "binary=$BinaryPath"
        "cases_file=$CasesFile"
        "result=$Result"
        "body_status=$BodyStatus"
        "matrix_status=$MatrixStatus"
        "body_report=$BodyReport"
        "matrix_report=$MatrixReport"
        "exit_code=$ExitCode"
    ) | Set-Content -Path $summaryPath -Encoding UTF8
    Write-Output ("[CIDR-BUNDLE] summary={0}" -f $summaryPath)
}

$bodyScript = Join-Path $PSScriptRoot "cidr_body_contract_smoke.ps1"
$matrixScript = Join-Path $PSScriptRoot "redirect_matrix_test.ps1"

$bodyStatus = "not-run"
$matrixStatus = "not-run"
$bodyReport = ""
$matrixReport = ""

Write-Output "[CIDR-BUNDLE] step=body-contract start"
& $bodyScript -BinaryPath $BinaryPath -OutDir $BodyOutDir
if ($LASTEXITCODE -ne 0) {
    $bodyStatus = "fail"
    $bodyReport = Get-LatestReport -BaseDir $BodyOutDir
    Write-Output ("[CIDR-BUNDLE] step=body-contract result=fail exit={0}" -f $LASTEXITCODE)
    Write-BundleSummary -Result "fail" -BodyStatus $bodyStatus -MatrixStatus $matrixStatus -BodyReport $bodyReport -MatrixReport $matrixReport -ExitCode $LASTEXITCODE
    exit $LASTEXITCODE
}
$bodyStatus = "pass"
$bodyReport = Get-LatestReport -BaseDir $BodyOutDir
Write-Output "[CIDR-BUNDLE] step=body-contract result=pass"

Write-Output "[CIDR-BUNDLE] step=matrix start"
& $matrixScript -BinaryPath $BinaryPath -OutDir $MatrixOutDir -RirIpPref $RirIpPref -PreferIpv4 $PreferIpv4 -SaveLogs $SaveLogs -CasesFile $CasesFile
if ($LASTEXITCODE -ne 0) {
    $matrixStatus = "fail"
    $matrixReport = Get-LatestReport -BaseDir $MatrixOutDir
    Write-Output ("[CIDR-BUNDLE] step=matrix result=fail exit={0}" -f $LASTEXITCODE)
    Write-BundleSummary -Result "fail" -BodyStatus $bodyStatus -MatrixStatus $matrixStatus -BodyReport $bodyReport -MatrixReport $matrixReport -ExitCode $LASTEXITCODE
    exit $LASTEXITCODE
}
$matrixStatus = "pass"
$matrixReport = Get-LatestReport -BaseDir $MatrixOutDir
Write-Output "[CIDR-BUNDLE] step=matrix result=pass"

Write-Output "[CIDR-BUNDLE] result=pass"
Write-BundleSummary -Result "pass" -BodyStatus $bodyStatus -MatrixStatus $matrixStatus -BodyReport $bodyReport -MatrixReport $matrixReport -ExitCode 0
exit 0
