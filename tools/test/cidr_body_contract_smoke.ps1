param(
    [string]$BinaryPath = "d:\LZProjects\whois\release\lzispro\whois\whois-win64.exe",
    [string]$OutDir = ""
)

$ErrorActionPreference = "Continue"
$PSNativeCommandUseErrorActionPreference = $false

if (-not (Test-Path $BinaryPath)) {
    Write-Error "Binary not found: $BinaryPath"
    exit 2
}

if (-not $OutDir -or $OutDir.Trim().Length -eq 0) {
    $OutDir = Join-Path $PSScriptRoot "..\..\out\artifacts\cidr_body_contract"
}
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$OutDir = Join-Path $OutDir $stamp
if (-not (Test-Path $OutDir)) {
    New-Item -ItemType Directory -Path $OutDir | Out-Null
}

$cases = @(
    @{ Name = "first-marker-baseline-suppressed"; Query = "8.8.0.0/16"; StartServer = "apnic"; ExpectActionRegex = "suppress-first-marker-baseline" },
    @{ Name = "post-marker-cidr-body-path"; Query = "45.71.8.0/22"; StartServer = "apnic"; ExpectActionRegex = "(consistency-replace|consistency-suppress|suppress-first-marker-baseline)" }
)

$pass = 0
$fail = 0
$results = @()

foreach ($case in $cases) {
    $name = $case.Name
    $query = $case.Query
    $startServer = $case.StartServer
    $expectActionRegex = $case.ExpectActionRegex

    $stdoutFile = Join-Path $OutDir ("{0}.stdout.txt" -f $name)
    $stderrFile = Join-Path $OutDir ("{0}.stderr.txt" -f $name)

    Write-Output ("Running: {0} -> {1} @ {2}" -f $name, $query, $startServer)
    Start-Process -FilePath $BinaryPath `
        -ArgumentList @("--debug", "--cidr-strip", "--show-non-auth-body", "--show-post-marker-body", "-h", $startServer, $query) `
        -RedirectStandardOutput $stdoutFile `
        -RedirectStandardError $stderrFile `
        -NoNewWindow -Wait | Out-Null

    $stdout = if (Test-Path $stdoutFile) { Get-Content -Raw -Path $stdoutFile } else { "" }
    $stderr = if (Test-Path $stderrFile) { Get-Content -Raw -Path $stderrFile } else { "" }

    $hasHeader = $stdout -match "(?m)^=== Query:"
    $hasTail = $stdout -match "(?m)^=== Authoritative RIR:"
    $hasAction = $stderr -match ("\[CIDR-BODY\]\s+action=({0})(\s|$)" -f $expectActionRegex)

    if ($hasHeader -and $hasTail -and $hasAction) {
        $pass++
        $results += "PASS case=$name query=$query host=$startServer action_regex=$expectActionRegex"
        Write-Output ("[PASS] {0} action_regex={1}" -f $name, $expectActionRegex)
    } else {
        $fail++
        $why = @()
        if (-not $hasHeader) { $why += "missing-header" }
        if (-not $hasTail) { $why += "missing-tail" }
        if (-not $hasAction) { $why += ("missing-action-regex:{0}" -f $expectActionRegex) }
        $results += "FAIL case=$name query=$query host=$startServer reason=$($why -join ',')"
        Write-Output ("[FAIL] {0} -> {1}" -f $name, ($why -join ","))
    }
}

$report = Join-Path $OutDir ("cidr_body_contract_report_{0}.txt" -f $stamp)
@(
    "binary=$BinaryPath"
    "outdir=$OutDir"
    "pass=$pass"
    "fail=$fail"
    ""
    $results
) | Set-Content -Path $report -Encoding UTF8

Write-Output ("Report: {0}" -f $report)
Write-Output ("Summary: pass={0} fail={1}" -f $pass, $fail)

if ($fail -gt 0) {
    exit 1
}

exit 0
