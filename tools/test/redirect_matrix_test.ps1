param(
    [string]$BinaryPath = "d:\LZProjects\whois\release\lzispro\whois\whois-win64.exe",
    [string]$OutDir = "",
    [string]$RirIpPref = "arin=ipv6",
    [string]$PreferIpv4 = "true",
    [string]$SaveLogs = "true",
    [string]$CasesFile = ""
)

$ErrorActionPreference = "Continue"
$PSNativeCommandUseErrorActionPreference = $false

if (-not (Test-Path $BinaryPath)) {
    Write-Error "Binary not found: $BinaryPath"
    exit 2
}

if (-not $OutDir -or $OutDir.Trim().Length -eq 0) {
    $OutDir = Join-Path $PSScriptRoot "..\..\out\artifacts\redirect_matrix"
}
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$OutDir = Join-Path $OutDir $stamp
if (-not (Test-Path $OutDir)) {
    New-Item -ItemType Directory -Path $OutDir | Out-Null
}

# Redirect matrix test: exits with code 1 when any case fails.
$defaultCases = @(
    @{ Query = '143.128.0.0/16'; RirHost = 'iana';    Expect = 'whois.afrinic.net' },
    @{ Query = '143.128.0.0/16'; RirHost = 'apnic';   Expect = 'whois.afrinic.net' },
    @{ Query = '143.128.0.0/16'; RirHost = 'arin';    Expect = 'whois.afrinic.net' },
    @{ Query = '143.128.0.0/16'; RirHost = 'ripe';    Expect = 'whois.afrinic.net' },
    @{ Query = '143.128.0.0/16'; RirHost = 'afrinic'; Expect = 'whois.afrinic.net' },
    @{ Query = '143.128.0.0/16'; RirHost = 'lacnic';  Expect = 'whois.afrinic.net' },

    @{ Query = '171.84.0.0/14'; RirHost = 'iana';    Expect = 'whois.apnic.net' },
    @{ Query = '171.84.0.0/14'; RirHost = 'apnic';   Expect = 'whois.apnic.net' },
    @{ Query = '171.84.0.0/14'; RirHost = 'arin';    Expect = 'whois.apnic.net' },
    @{ Query = '171.84.0.0/14'; RirHost = 'ripe';    Expect = 'whois.apnic.net' },
    @{ Query = '171.84.0.0/14'; RirHost = 'afrinic'; Expect = 'whois.apnic.net' },
    @{ Query = '171.84.0.0/14'; RirHost = 'lacnic';  Expect = 'whois.apnic.net' },

    @{ Query = '1.1.1.0/24'; RirHost = 'iana';    Expect = 'whois.apnic.net' },
    @{ Query = '1.1.1.0/24'; RirHost = 'apnic';   Expect = 'whois.apnic.net' },
    @{ Query = '1.1.1.0/24'; RirHost = 'arin';    Expect = 'whois.apnic.net' },
    @{ Query = '1.1.1.0/24'; RirHost = 'ripe';    Expect = 'whois.apnic.net' },
    @{ Query = '1.1.1.0/24'; RirHost = 'afrinic'; Expect = 'whois.apnic.net' },
    @{ Query = '1.1.1.0/24'; RirHost = 'lacnic';  Expect = 'whois.apnic.net' },

    @{ Query = '1.1.1.1'; RirHost = 'iana';    Expect = 'whois.apnic.net' },
    @{ Query = '1.1.1.1'; RirHost = 'apnic';   Expect = 'whois.apnic.net' },
    @{ Query = '1.1.1.1'; RirHost = 'arin';    Expect = 'whois.apnic.net' },
    @{ Query = '1.1.1.1'; RirHost = 'ripe';    Expect = 'whois.apnic.net' },
    @{ Query = '1.1.1.1'; RirHost = 'afrinic'; Expect = 'whois.apnic.net' },
    @{ Query = '1.1.1.1'; RirHost = 'lacnic';  Expect = 'whois.apnic.net' },

    @{ Query = '8.8.8.0/24'; RirHost = 'iana';    Expect = 'whois.arin.net' },
    @{ Query = '8.8.8.0/24'; RirHost = 'apnic';   Expect = 'whois.arin.net' },
    @{ Query = '8.8.8.0/24'; RirHost = 'arin';    Expect = 'whois.arin.net' },
    @{ Query = '8.8.8.0/24'; RirHost = 'ripe';    Expect = 'whois.arin.net' },
    @{ Query = '8.8.8.0/24'; RirHost = 'afrinic'; Expect = 'whois.arin.net' },
    @{ Query = '8.8.8.0/24'; RirHost = 'lacnic';  Expect = 'whois.arin.net' },

    @{ Query = '8.8.8.8'; RirHost = 'iana';    Expect = 'whois.arin.net' },
    @{ Query = '8.8.8.8'; RirHost = 'apnic';   Expect = 'whois.arin.net' },
    @{ Query = '8.8.8.8'; RirHost = 'arin';    Expect = 'whois.arin.net' },
    @{ Query = '8.8.8.8'; RirHost = 'ripe';    Expect = 'whois.arin.net' },
    @{ Query = '8.8.8.8'; RirHost = 'afrinic'; Expect = 'whois.arin.net' },
    @{ Query = '8.8.8.8'; RirHost = 'lacnic';  Expect = 'whois.arin.net' },

    @{ Query = '8.8.0.0/16'; RirHost = 'iana';    Expect = 'unknown' },
    @{ Query = '8.8.0.0/16'; RirHost = 'apnic';   Expect = 'unknown' },
    @{ Query = '8.8.0.0/16'; RirHost = 'arin';    Expect = 'unknown' },
    @{ Query = '8.8.0.0/16'; RirHost = 'ripe';    Expect = 'unknown' },
    @{ Query = '8.8.0.0/16'; RirHost = 'afrinic'; Expect = 'unknown' },
    @{ Query = '8.8.0.0/16'; RirHost = 'lacnic';  Expect = 'unknown' },

    @{ Query = '0.0.0.0/0'; RirHost = 'iana';    Expect = 'unknown' },
    @{ Query = '0.0.0.0/0'; RirHost = 'apnic';   Expect = 'unknown' },
    @{ Query = '0.0.0.0/0'; RirHost = 'arin';    Expect = 'unknown' },
    @{ Query = '0.0.0.0/0'; RirHost = 'ripe';    Expect = 'unknown' },
    @{ Query = '0.0.0.0/0'; RirHost = 'afrinic'; Expect = 'unknown' },
    @{ Query = '0.0.0.0/0'; RirHost = 'lacnic';  Expect = 'unknown' },

    @{ Query = '0.0.0.0'; RirHost = 'iana';    Expect = 'unknown' },
    @{ Query = '0.0.0.0'; RirHost = 'apnic';   Expect = 'unknown' },
    @{ Query = '0.0.0.0'; RirHost = 'arin';    Expect = 'unknown' },
    @{ Query = '0.0.0.0'; RirHost = 'ripe';    Expect = 'unknown' },
    @{ Query = '0.0.0.0'; RirHost = 'afrinic'; Expect = 'unknown' },
    @{ Query = '0.0.0.0'; RirHost = 'lacnic';  Expect = 'unknown' },

    @{ Query = '888.0.0.0';    RirHost = 'iana';    Expect = 'invalid' },
    @{ Query = '888.0.0.0/16'; RirHost = 'iana';    Expect = 'invalid' },
    @{ Query = '888.0.0.0';    RirHost = 'apnic';   Expect = 'invalid' },
    @{ Query = '888.0.0.0/16'; RirHost = 'apnic';   Expect = 'invalid' },
    @{ Query = '888.0.0.0';    RirHost = 'arin';    Expect = 'invalid' },
    @{ Query = '888.0.0.0/16'; RirHost = 'arin';    Expect = 'invalid' },
    @{ Query = '888.0.0.0';    RirHost = 'ripe';    Expect = 'invalid' },
    @{ Query = '888.0.0.0/16'; RirHost = 'ripe';    Expect = 'invalid' },
    @{ Query = '888.0.0.0';    RirHost = 'afrinic'; Expect = 'invalid' },
    @{ Query = '888.0.0.0/16'; RirHost = 'afrinic'; Expect = 'invalid' },
    @{ Query = '888.0.0.0';    RirHost = 'lacnic';  Expect = 'invalid' },
    @{ Query = '888.0.0.0/16'; RirHost = 'lacnic';  Expect = 'invalid' }
)

function Resolve-CasesFilePath {
    param([string]$PathValue)

    if (-not $PathValue -or $PathValue.Trim().Length -eq 0) {
        return ""
    }

    if (Test-Path $PathValue) {
        return (Resolve-Path $PathValue).Path
    }

    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\.." )).Path
    $candidate = Join-Path $repoRoot $PathValue
    if (Test-Path $candidate) {
        return (Resolve-Path $candidate).Path
    }

    return ""
}

function Get-CaseFieldValue {
    param(
        [object]$Row,
        [string[]]$Names
    )
    foreach ($name in $Names) {
        if ($Row.PSObject.Properties[$name]) {
            $value = [string]$Row.$name
            if ($value -and $value.Trim().Length -gt 0) {
                return $value.Trim()
            }
        }
    }
    return ""
}

$cases = @()
$skippedCases = @()
$resolvedCasesFile = Resolve-CasesFilePath -PathValue $CasesFile

if ($resolvedCasesFile) {
    Write-Output ("Loading cases from file: {0}" -f $resolvedCasesFile)
    $delimiter = "`t"
    if ($resolvedCasesFile.ToLower().EndsWith(".csv")) {
        $delimiter = ","
    }

    $rows = Import-Csv -Path $resolvedCasesFile -Delimiter $delimiter
    foreach ($row in $rows) {
        $caseId = Get-CaseFieldValue -Row $row -Names @("case_id", "CaseId", "id")
        $query = Get-CaseFieldValue -Row $row -Names @("query", "Query")
        $rirHost = Get-CaseFieldValue -Row $row -Names @("start_rir", "RirHost", "rir_host", "host")
        $expectHost = Get-CaseFieldValue -Row $row -Names @("expect_host", "ExpectHost", "expected_host")
        $expectSemantic = Get-CaseFieldValue -Row $row -Names @("expect_authority", "expected_authority", "expect", "Expect")
        $expect = ""

        if ($expectHost -and $expectHost.Trim().Length -gt 0) {
            $expect = $expectHost
        } elseif ($expectSemantic -and $expectSemantic.Trim().Length -gt 0) {
            $expect = $expectSemantic
        }

        if (-not $query -or -not $rirHost) {
            $skippedCases += ("skip(case={0}): missing query/start_rir" -f $caseId)
            continue
        }

        # For draft semantic values like first_marker_rir/next_hit_rir, explicit host expectation is required.
        $semanticExpectation = @("first_marker_rir", "next_hit_rir")
        if ($semanticExpectation -contains $expect) {
            $skippedCases += ("skip(case={0}): unresolved semantic expect='{1}', provide expect_host/Expect for executable assertion" -f $caseId, $expect)
            continue
        }

        if (-not $expect) {
            $skippedCases += ("skip(case={0}): missing expect/expect_host" -f $caseId)
            continue
        }

        $cases += @{
            CaseId = $caseId
            Query = $query
            RirHost = $rirHost
            Expect = $expect
        }
    }

    if ($cases.Count -eq 0) {
        Write-Error "No executable cases loaded from CasesFile."
        if ($skippedCases.Count -gt 0) {
            $skippedCases | ForEach-Object { Write-Warning $_ }
        }
        exit 2
    }

    if ($skippedCases.Count -gt 0) {
        $skippedCases | ForEach-Object { Write-Warning $_ }
    }
} else {
    if ($CasesFile -and $CasesFile.Trim().Length -gt 0) {
        Write-Error ("CasesFile not found: {0}" -f $CasesFile)
        exit 2
    }
    $cases = $defaultCases
}

$reportPath = Join-Path $OutDir ("redirect_matrix_report_{0}.txt" -f $stamp)
$logDir = Join-Path -Path $OutDir -ChildPath "cases"
$saveLogsEnabled = [string]::Equals($SaveLogs, "true", [System.StringComparison]::OrdinalIgnoreCase)
$preferIpv4Enabled = [string]::Equals($PreferIpv4, "true", [System.StringComparison]::OrdinalIgnoreCase)
$rirIpPrefEnabled = -not [string]::Equals($RirIpPref, "none", [System.StringComparison]::OrdinalIgnoreCase)
if ($saveLogsEnabled) {
    if (-not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir | Out-Null
    }
}

$results = @()
$pass = 0
$fail = 0

foreach ($case in $cases) {
    $caseId = ""
    if ($case.ContainsKey("CaseId")) { $caseId = [string]$case.CaseId }
    $query = $case.Query
    $targetHost = $case.RirHost
    $expect = $case.Expect
    if ($caseId -and $caseId.Trim().Length -gt 0) {
        Write-Output ("Running: {0} -> {1} @ {2}" -f $caseId, $query, $targetHost)
    } else {
        Write-Output ("Running: {0} @ {1}" -f $query, $targetHost)
    }

    $cliArgList = @()
    if ($preferIpv4Enabled) { $cliArgList += "--prefer-ipv4" }
    if ($RirIpPref -and $rirIpPrefEnabled) { $cliArgList += @("--rir-ip-pref", $RirIpPref) }
    $cliArgList += @($query, "-h", $targetHost)

    $tmpOut = [System.IO.Path]::GetTempFileName()
    $tmpErr = [System.IO.Path]::GetTempFileName()
    $procStartInfo = @{
        FilePath = $BinaryPath
        ArgumentList = $cliArgList
        NoNewWindow = $true
        Wait = $true
        PassThru = $true
        RedirectStandardOutput = $tmpOut
        RedirectStandardError = $tmpErr
    }
    $null = Start-Process @procStartInfo
    $output = ""
    if (Test-Path $tmpOut) { $output += (Get-Content -Raw $tmpOut) }
    if (Test-Path $tmpErr) { $output += (Get-Content -Raw $tmpErr) }
    Remove-Item -Force -ErrorAction SilentlyContinue $tmpOut, $tmpErr
    if ($saveLogsEnabled) {
        $safeQuery = ($query -replace '[^A-Za-z0-9._-]', '_')
        $safeHost = ($targetHost -replace '[^A-Za-z0-9._-]', '_')
        $casePath = Join-Path $logDir ("case_{0}_{1}.log" -f $safeQuery, $safeHost)
        $output | Set-Content -Encoding UTF8 $casePath
    }
    $authLine = $output | Select-String "Authoritative RIR:" -SimpleMatch | Select-Object -First 1
    $invalidLine = $output | Select-String "Invalid IP/CIDR query" -SimpleMatch | Select-Object -First 1

    $found = ""
    if ($invalidLine) {
        $found = "invalid"
    } elseif ($authLine) {
        $m = [regex]::Match($authLine.Line, "Authoritative RIR:\s+([^\s]+)")
        if ($m.Success) {
            $found = $m.Groups[1].Value
        }
    }

    $ok = $false
    if ($expect -eq "invalid") {
        $ok = ($found -eq "invalid")
    } elseif ($expect -eq "unknown") {
        $ok = ($found -eq "unknown")
    } else {
        $ok = ($found -eq $expect)
    }

    if ($ok) { $pass++ } else { $fail++ }

    $foundDisplay = "(none)"
    if ($found -ne "") { $foundDisplay = $found }
    $statusLabel = "FAIL"
    if ($ok) { $statusLabel = "PASS" }

    $results += [pscustomobject]@{
        CaseId = $caseId
        Query = $query
        RirHost = $targetHost
        Expect = $expect
        Found = $foundDisplay
        Status = $statusLabel
    }
    if ($caseId -and $caseId.Trim().Length -gt 0) {
        Write-Output ("[{0}] {1} {2} @ {3} expect={4} found={5}" -f $statusLabel, $caseId, $query, $targetHost, $expect, $foundDisplay)
    } else {
        Write-Output ("[{0}] {1} @ {2} expect={3} found={4}" -f $statusLabel, $query, $targetHost, $expect, $foundDisplay)
    }
}

$results | ForEach-Object {
    if ($_.CaseId -and $_.CaseId.Trim().Length -gt 0) {
        "[{0}] {1} {2} @ {3} expect={4} found={5}" -f $_.Status, $_.CaseId, $_.Query, $_.RirHost, $_.Expect, $_.Found
    } else {
        "[{0}] {1} @ {2} expect={3} found={4}" -f $_.Status, $_.Query, $_.RirHost, $_.Expect, $_.Found
    }
} | Set-Content -Encoding UTF8 $reportPath

Add-Content -Encoding UTF8 $reportPath ""
Add-Content -Encoding UTF8 $reportPath ("Summary: pass={0} fail={1}" -f $pass, $fail)
if ($skippedCases.Count -gt 0) {
    Add-Content -Encoding UTF8 $reportPath ""
    Add-Content -Encoding UTF8 $reportPath ("Skipped cases: {0}" -f $skippedCases.Count)
    $skippedCases | ForEach-Object { Add-Content -Encoding UTF8 $reportPath ("- {0}" -f $_) }
}

Write-Output "Report: $reportPath"
Write-Output ("Summary: pass={0} fail={1}" -f $pass, $fail)

if ($fail -gt 0) { exit 1 }
exit 0
