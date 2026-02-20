param(
    [string]$BinaryPath = "d:\LZProjects\whois\release\lzispro\whois\whois-win64.exe",
    [string]$BodyOutDir = "",
    [string]$MatrixOutDir = "",
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

$bodyScript = Join-Path $PSScriptRoot "cidr_body_contract_smoke.ps1"
$matrixScript = Join-Path $PSScriptRoot "redirect_matrix_test.ps1"

Write-Output "[CIDR-BUNDLE] step=body-contract start"
& $bodyScript -BinaryPath $BinaryPath -OutDir $BodyOutDir
if ($LASTEXITCODE -ne 0) {
    Write-Output ("[CIDR-BUNDLE] step=body-contract result=fail exit={0}" -f $LASTEXITCODE)
    exit $LASTEXITCODE
}
Write-Output "[CIDR-BUNDLE] step=body-contract result=pass"

Write-Output "[CIDR-BUNDLE] step=matrix start"
& $matrixScript -BinaryPath $BinaryPath -OutDir $MatrixOutDir -RirIpPref $RirIpPref -PreferIpv4 $PreferIpv4 -SaveLogs $SaveLogs -CasesFile $CasesFile
if ($LASTEXITCODE -ne 0) {
    Write-Output ("[CIDR-BUNDLE] step=matrix result=fail exit={0}" -f $LASTEXITCODE)
    exit $LASTEXITCODE
}
Write-Output "[CIDR-BUNDLE] step=matrix result=pass"

Write-Output "[CIDR-BUNDLE] result=pass"
exit 0
