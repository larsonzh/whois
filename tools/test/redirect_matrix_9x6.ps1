param(
    [string]$BinaryPath = "d:\LZProjects\whois\release\lzispro\whois\whois-win64.exe",
    [string]$OutDirRoot = "",
    [string]$RirIpPref = "arin=ipv6",
    [string]$PreferIpv4 = "true",
    [string]$ShowExtraBodies = "false",
    [string]$ShowNonAuthBody = "false",
    [string]$HideFailureBody = "false"
)

$ErrorActionPreference = "Continue"
$PSNativeCommandUseErrorActionPreference = $false

if (-not (Test-Path $BinaryPath)) {
    Write-Error "Binary not found: $BinaryPath"
    exit 2
}

if (-not $OutDirRoot -or $OutDirRoot.Trim().Length -eq 0) {
    $OutDirRoot = Join-Path $PSScriptRoot "..\..\out\artifacts\redirect_matrix_9x6"
}

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$OutDir = Join-Path $OutDirRoot $stamp
if (-not (Test-Path $OutDir)) {
    New-Item -ItemType Directory -Path $OutDir | Out-Null
}

$starts = @("iana", "apnic", "arin", "ripe", "afrinic", "lacnic")
$ips = @(
    "47.96.0.0/11",
    "45.121.52.0/22",
    "139.159.0.0/16",
    "158.60.0.0/16",
    "171.84.0.0/14",
    "69.10.0.0/20",
    "5.199.160.0/20",
    "143.128.0.0/16",
    "45.71.8.0/22"
)

function Test-Truthy([string]$value) {
    if (-not $value) { return $false }
    switch ($value.Trim().ToLowerInvariant()) {
        "1" { return $true }
        "true" { return $true }
        "yes" { return $true }
        "on" { return $true }
        "enable" { return $true }
        "enabled" { return $true }
        default { return $false }
    }
}

$preferIpv4Enabled = Test-Truthy $PreferIpv4
$rirIpPrefEnabled = -not [string]::Equals($RirIpPref, "none", [System.StringComparison]::OrdinalIgnoreCase)
$showNonAuthBodyEnabled = Test-Truthy $ShowNonAuthBody
$showPostMarkerBodyEnabled = Test-Truthy $ShowExtraBodies
if ($showPostMarkerBodyEnabled) { $showNonAuthBodyEnabled = $true }
$hideFailureBodyEnabled = Test-Truthy $HideFailureBody

Write-Output ("Flags: PreferIpv4={0} RirIpPref={1} ShowExtraBodies={2} ShowNonAuthBody={3}" -f `
    $preferIpv4Enabled, $RirIpPref, $showPostMarkerBodyEnabled, $showNonAuthBodyEnabled)
Write-Output ("Flags: HideFailureBody={0}" -f $hideFailureBodyEnabled)

Write-Output "Starting 9x6 redirect matrix... (this may take a while)"
Write-Output ("Output dir: {0}" -f $OutDir)

foreach ($start in $starts) {
    foreach ($ip in $ips) {
        $key = $ip -replace "/", "_"
        $outPath = Join-Path $OutDir ("{0}_{1}.txt" -f $start, $key)

        $cliArgList = @()
        if ($preferIpv4Enabled) { $cliArgList += "--prefer-ipv4" }
        if ($RirIpPref -and $rirIpPrefEnabled) { $cliArgList += @("--rir-ip-pref", $RirIpPref) }
        if ($showNonAuthBodyEnabled) { $cliArgList += "--show-non-auth-body" }
        if ($showPostMarkerBodyEnabled) { $cliArgList += "--show-post-marker-body" }
        if ($hideFailureBodyEnabled) { $cliArgList += "--hide-failure-body" }
        $cliArgList += @($ip, "-h", $start)

        Write-Output ("Running: {0} @ {1}" -f $ip, $start)
        $output = & $BinaryPath @cliArgList 2>&1
        $output | ForEach-Object {
            if ($_ -is [System.Management.Automation.ErrorRecord]) {
                $_.Exception.Message
            } else {
                $_
            }
        } | Out-File -FilePath $outPath -Encoding utf8
    }
}

$markerPattern = 'ERX-NETBLOCK|IANA-NETBLOCK'
$rirHost = @{
    apnic = "whois.apnic.net"
    arin = "whois.arin.net"
    ripe = "whois.ripe.net"
    afrinic = "whois.afrinic.net"
    lacnic = "whois.lacnic.net"
    iana = "whois.iana.org"
}

$expect = @{
    "47.96.0.0_11" = "apnic"
    "45.121.52.0_22" = "apnic"
    "139.159.0.0_16" = "apnic"
    "158.60.0.0_16" = "apnic"
    "171.84.0.0_14" = "apnic"
    "69.10.0.0_20" = "arin"
    "5.199.160.0_20" = "ripe"
    "143.128.0.0_16" = "afrinic"
    "45.71.8.0_22" = "lacnic"
}

$analysisPath = Join-Path $OutDir ("analysis_{0}.txt" -f $stamp)
$errorsPath = Join-Path $OutDir ("errors_{0}.txt" -f $stamp)
$authPath = Join-Path $OutDir ("authority_{0}.txt" -f $stamp)

$analysisRows = @()
$authRows = @()
$errorRows = @()

Get-ChildItem -Path $OutDir -Filter *.txt | ForEach-Object {
    $lines = Get-Content -Path $_.FullName

    $headers = @()
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match '^=== (Query|Additional/Redirected query|Redirected query):') {
            $headers += [pscustomobject]@{ Index = $i; Line = $lines[$i] }
        }
    }
    $headers += [pscustomobject]@{ Index = $lines.Count; Line = '__END__' }

    $authLine = ($lines | Select-String -Pattern '^=== Authoritative RIR:' | Select-Object -Last 1)
    $tailIsError = $false
    $authRir = ''
    if ($authLine) {
        if ($authLine.Line -eq '=== Authoritative RIR: error @ error ===') {
            $tailIsError = $true
        }
        if ($authLine.Line -match 'Authoritative RIR: ([^ ]+)') {
            $authRir = ($Matches[1] -replace '^whois\.' -replace '\..*$','')
        }
    }

    $hops = @()
    for ($h = 0; $h -lt ($headers.Count - 1); $h++) {
        $start = $headers[$h].Index
        $end = $headers[$h + 1].Index
        $headerLine = $lines[$start]
        $bodyLines = @()
        for ($j = $start + 1; $j -lt $end; $j++) {
            if ($lines[$j] -match '^=== Authoritative RIR:') { break }
            $bodyLines += $lines[$j]
        }
        $bodyNonEmpty = ($bodyLines | Where-Object { $_ -and ($_ -notmatch '^\s*$') }).Count
        $hasMarker = ($bodyLines | Select-String -Pattern $markerPattern -Quiet)
        $viaHost = ''
        if ($headerLine -match ' via ([^ ]+)') { $viaHost = $Matches[1] }
        $hopRir = ''
        foreach ($k in $rirHost.Keys) {
            if ($viaHost -eq $rirHost[$k]) { $hopRir = $k; break }
        }
        $hops += [pscustomobject]@{ BodyNonEmpty = $bodyNonEmpty; HasMarker = $hasMarker; HopRir = $hopRir }
    }

    $markerIdx = -1
    for ($h = 0; $h -lt $hops.Count; $h++) {
        if ($hops[$h].HasMarker) { $markerIdx = $h; break }
    }

    $authIdx = -1
    if ($authRir) {
        for ($h = ($hops.Count - 1); $h -ge 0; $h--) {
            if ($hops[$h].HopRir -eq $authRir) { $authIdx = $h; break }
        }
    }

    $clearAfterIdx = if ($markerIdx -ge 0) {
        if ($authIdx -ge 0) { [Math]::Max($markerIdx, $authIdx) } else { $markerIdx }
    } else {
        if ($authIdx -ge 0) { $authIdx } else { -1 }
    }

    $preMissing = @()
    if ($clearAfterIdx -gt 0) {
        for ($h = 0; $h -lt $clearAfterIdx; $h++) {
            if ($hops[$h].BodyNonEmpty -eq 0) { $preMissing += $h }
        }
    }

    $postHas = @()
    if ($clearAfterIdx -ge 0) {
        for ($h = $clearAfterIdx + 1; $h -lt $hops.Count; $h++) {
            if ($hops[$h].BodyNonEmpty -gt 0) { $postHas += $h }
        }
    }

    $parts = $_.BaseName.Split('_', 2)
    $start = if ($parts.Count -ge 1) { $parts[0] } else { "" }
    $ipkey = if ($parts.Count -ge 2) { $parts[1] } else { $null }
    $expected = $null
    if ($ipkey -and $expect.ContainsKey($ipkey)) { $expected = $expect[$ipkey] }
    $analysisRows += [pscustomobject]@{
        File = $_.Name
        MarkerHop = $markerIdx
        AuthRIR = $authRir
        ExpectedAuth = $expected
        AuthHop = $authIdx
        ClearAfter = $clearAfterIdx
        PreMissing = $preMissing.Count
        PostHasBody = $postHas.Count
    }
    $ok = ($expected -and $authRir -eq $expected)
    $authRows += [pscustomobject]@{
        File = $_.Name
        Start = $start
        IP = $ipkey
        AuthRIR = $authRir
        Expected = $expected
        OK = $ok
    }

    if ($tailIsError) {
        $errPrimary = Select-String -Path $_.FullName -Pattern '^Error: Query failed for '
        if ($errPrimary) {
            $errorRows += [pscustomobject]@{ File = $_.Name; FirstLine = $errPrimary[0].Line }
        } else {
            $errHits = Select-String -Path $_.FullName -Pattern 'ERROR|error|timed out|timeout|failed|refused|denied|No response|connection|unreachable|reset by peer'
            if ($errHits) {
                $line = $errHits[0].Line
                $errorRows += [pscustomobject]@{ File = $_.Name; FirstLine = $line }
            } else {
                $errorRows += [pscustomobject]@{ File = $_.Name; FirstLine = 'MISSING_FAILURE_LINE (tail=error @ error)' }
            }
        }
    }
}

$analysisText = ($analysisRows | Sort-Object File | Format-Table -AutoSize | Out-String)
$analysisText | Set-Content -Encoding UTF8 $analysisPath
$authMismatches = $authRows | Where-Object { -not $_.OK }
$authText = ($authMismatches | Sort-Object File | Format-Table -AutoSize | Out-String)
$authText | Set-Content -Encoding UTF8 $authPath
if ($errorRows.Count -gt 0) {
    $errorText = ($errorRows | Sort-Object File | Format-Table -AutoSize | Out-String)
    $errorText | Set-Content -Encoding UTF8 $errorsPath
} else {
    $errorText = "(no errors found)"
    $errorText | Set-Content -Encoding UTF8 $errorsPath
}

$preMissingCount = ($analysisRows | Where-Object { $_.PreMissing -gt 0 }).Count
$postHasCount = ($analysisRows | Where-Object { $_.PostHasBody -gt 0 }).Count
$authMismatchCount = ($authRows | Where-Object { -not $_.OK }).Count
$errorCount = $errorRows.Count

Write-Output "Logs: $OutDir"
Write-Output "Analysis: $analysisPath"
Write-Output "Authority mismatches: $authPath"
Write-Output "Errors: $errorsPath"
Write-Output ("Summary: preMissingFiles={0} postHasBodyFiles={1} authMismatchFiles={2} errorFiles={3}" -f $preMissingCount, $postHasCount, $authMismatchCount, $errorCount)
Write-Output ""
Write-Output "Analysis (table):"
Write-Output $analysisText
Write-Output "Authority mismatches (table):"
Write-Output $authText
Write-Output "Errors (table):"
Write-Output $errorText
