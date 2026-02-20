Param(
    [string[]]$InputRoots = @('tmp/logs', 'out/artifacts'),
    [string]$OutputPath = '',
    [int]$MaxExamplesPerRir = 40,
    [string]$DocPath = 'docs/IPv4_&_IPv6_address_whois_lookup_rules.txt'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Resolve-RirFromHost {
    Param([string]$HostName)

    if ([string]::IsNullOrWhiteSpace($HostName)) { return 'UNKNOWN' }
    $h = $HostName.ToLowerInvariant()
    if ($h -match 'iana') { return 'IANA' }
    if ($h -match 'apnic') { return 'APNIC' }
    if ($h -match 'arin') { return 'ARIN' }
    if ($h -match 'ripe') { return 'RIPE' }
    if ($h -match 'afrinic') { return 'AFRINIC' }
    if ($h -match 'lacnic') { return 'LACNIC' }
    if ($h -match 'verisign') { return 'VERISIGN' }
    return 'UNKNOWN'
}

function Normalize-DocLine {
    Param([string]$Line)

    $normalized = $Line.Trim()
    $normalized = $normalized -replace '<客户端公网 IP 地址>', '<CLIENT_PUBLIC_IP>'
    $normalized = [regex]::Replace($normalized, 'for\s+<[^>]+>', 'for <CLIENT_PUBLIC_IP>', 'IgnoreCase')
    $normalized = [regex]::Replace($normalized, 'for\s+\d{1,3}(?:\.\d{1,3}){3}', 'for <CLIENT_PUBLIC_IP>', 'IgnoreCase')
    $normalized = [regex]::Replace($normalized, 'for\s+[0-9a-f:]{2,}', 'for <CLIENT_PUBLIC_IP>', 'IgnoreCase')
    return $normalized
}

function Is-FailureRawLine {
    Param([string]$Line)

    $s = $Line.Trim()
    if ([string]::IsNullOrWhiteSpace($s)) { return $false }

    return (
        $s -match '^%ERROR:201:\s*access denied for .+' -or
        $s -match '^(?i:query rate limit exceeded)$' -or
        $s -match '^(?i:rate limit exceeded)$' -or
        $s -match '^(?i:temporary denied)$' -or
        $s -match '^(?i:permanently denied)$' -or
        $s -match '^(?i:access denied)$' -or
        $s -match '^%\s*Access from your host has been temporarily denied\.$' -or
        $s -match '^%\s*Sorry, access from your host has been permanently$' -or
        $s -match '^%\s*denied because of a repeated excessive querying\.$' -or
        $s -match '^%\s*Queries from your IP address have passed the daily limit of controlled objects\.$'
    )
}

function Ensure-OutputPath {
    Param([string]$Out)

    if (-not [string]::IsNullOrWhiteSpace($Out)) {
        $dir = Split-Path -Parent $Out
        if (-not [string]::IsNullOrWhiteSpace($dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
        return $Out
    }

    $ts = Get-Date -Format 'yyyyMMdd-HHmmss'
    $dirOut = Join-Path 'tmp/logs/rir_failure_extract' $ts
    New-Item -ItemType Directory -Path $dirOut -Force | Out-Null
    return (Join-Path $dirOut 'rir_failure_raw_extract.md')
}

function Read-DocFailureLinesByRir {
    Param([string]$Path)

    $map = @{}
    $rirOrder = @('IANA', 'APNIC', 'ARIN', 'RIPE', 'AFRINIC', 'LACNIC', 'VERISIGN', 'UNKNOWN')
    foreach ($r in $rirOrder) {
        $map[$r] = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    }

    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) {
        return $map
    }

    $lines = @(Get-Content -LiteralPath $Path -ErrorAction SilentlyContinue)
    if ($lines.Count -eq 0) { return $map }

    $inSection = $false
    $currentRir = 'UNKNOWN'

    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = ([string]$lines[$i]).TrimEnd("`r", "`n")
        $trim = $line.Trim()

        if ($trim -match '^3\.\s') {
            $inSection = $true
            $currentRir = 'UNKNOWN'
            continue
        }
        if ($trim -match '^4\.\s') {
            break
        }
        if (-not $inSection) { continue }

        $fullWidthColon = [string][char]0xFF1A
        $headingNorm = $trim.Replace($fullWidthColon, ':')
        if ($headingNorm -match '^(IANA|APNIC|ARIN|RIPE|AFRINIC|LACNIC|VERISIGN):\s*$') {
            $currentRir = $Matches[1].ToUpperInvariant()
            continue
        }

        if (Is-FailureRawLine -Line $trim) {
            [void]$map[$currentRir].Add((Normalize-DocLine -Line $trim))
        }
    }

    return $map
}

function Flatten-DocSets {
    Param([hashtable]$Map)

    $all = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($k in $Map.Keys) {
        foreach ($v in $Map[$k]) {
            [void]$all.Add($v)
        }
    }
    return $all
}

function Build-DocNormalizedText {
    Param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) {
        return ''
    }

    $lines = @(Get-Content -LiteralPath $Path -ErrorAction SilentlyContinue)
    if ($lines.Count -eq 0) { return '' }

    $normalized = $lines | ForEach-Object { Normalize-DocLine -Line ([string]$_) }
    return (($normalized -join "`n").ToLowerInvariant())
}

$outputFile = Ensure-OutputPath -Out $OutputPath
$docMap = Read-DocFailureLinesByRir -Path $DocPath
$docAll = Flatten-DocSets -Map $docMap
$docText = Build-DocNormalizedText -Path $DocPath

$roots = @()
foreach ($root in $InputRoots) {
    if (-not [string]::IsNullOrWhiteSpace($root) -and (Test-Path -LiteralPath $root)) {
        $roots += $root
    }
}

if ($roots.Count -eq 0) {
    throw 'No valid input roots found. Please pass -InputRoots with existing paths.'
}

$files = @()
foreach ($root in $roots) {
    $files += Get-ChildItem -LiteralPath $root -Recurse -File -ErrorAction SilentlyContinue
}

$records = New-Object System.Collections.Generic.List[object]

foreach ($f in $files) {
    $rawLines = Get-Content -LiteralPath $f.FullName -ErrorAction SilentlyContinue
    if ($null -eq $rawLines) { continue }
    $lines = @($rawLines)

    $currentHost = ''
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $lineRaw = [string]$lines[$i]
        $line = $lineRaw.TrimEnd("`r", "`n")

        if ($line -match '^=== Query: .* via ([^ ]+) @') {
            $currentHost = $Matches[1]
        }
        elseif ($line -match '^=== (?:Additional|Redirected) query to ([^ ]+) ===') {
            $currentHost = $Matches[1]
        }
        elseif ($line -match '^\s*%\s*This is the RIPE Database query service\.') {
            $currentHost = 'whois.ripe.net'
        }
        elseif ($line -match '^\s*%\s*This is the AfriNIC Whois server\.') {
            $currentHost = 'whois.afrinic.net'
        }
        elseif ($line -match '^\s*%\s*Joint Whois - whois\.lacnic\.net') {
            $currentHost = 'whois.lacnic.net'
        }
        elseif ($line -match '^\s*%\s*\[whois\.apnic\.net\]') {
            $currentHost = 'whois.apnic.net'
        }
        elseif ($line -match '^\s*#\s*ARIN WHOIS data and services are subject to the Terms of Use') {
            $currentHost = 'whois.arin.net'
        }
        elseif ($line -match '^\s*%\s*IANA WHOIS server') {
            $currentHost = 'whois.iana.org'
        }

        if (-not (Is-FailureRawLine -Line $line)) { continue }

        $rir = Resolve-RirFromHost -HostName $currentHost
        $records.Add([pscustomobject]@{
            Rir       = $rir
            Host      = $currentHost
            Raw       = $line.Trim()
            Normalized = Normalize-DocLine -Line $line
            File      = $f.FullName
            Line      = ($i + 1)
        })
    }
}

$sb = New-Object System.Text.StringBuilder
[void]$sb.AppendLine('# RIR Failure Raw Extract')
[void]$sb.AppendLine('')
[void]$sb.AppendLine("- Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
[void]$sb.AppendLine("- Input roots: $($roots -join ', ')")
[void]$sb.AppendLine("- Scanned files: $($files.Count)")
[void]$sb.AppendLine("- Matched lines: $($records.Count)")
[void]$sb.AppendLine("- Doc compare: $DocPath")
[void]$sb.AppendLine('')

if ($records.Count -eq 0) {
    [void]$sb.AppendLine('No failure raw lines found.')
}
else {
    [void]$sb.AppendLine('## Suggested lines for docs section 3 (normalized)')
    [void]$sb.AppendLine('')

    $rirOrder = @('IANA', 'APNIC', 'ARIN', 'RIPE', 'AFRINIC', 'LACNIC', 'VERISIGN', 'UNKNOWN')
    $missingMap = @{}
    foreach ($rir in $rirOrder) {
        $rows = @($records | Where-Object { $_.Rir -eq $rir })
        if ($rows.Count -eq 0) { continue }

        $norm = $rows | Select-Object -ExpandProperty Normalized | Sort-Object -Unique
        $docSet = $docMap[$rir]
        $missing = @()
        foreach ($n in $norm) {
            $nLower = $n.ToLowerInvariant()
            $docTextHas = (-not [string]::IsNullOrEmpty($docText)) -and $docText.Contains($nLower)
            if ((-not $docSet.Contains($n)) -and (-not $docAll.Contains($n)) -and (-not $docTextHas)) {
                $missing += $n
            }
        }
        $missingMap[$rir] = $missing

        [void]$sb.AppendLine("### $rir")
        foreach ($n in $norm) {
            [void]$sb.AppendLine("- $n")
        }
        [void]$sb.AppendLine('')
    }

    [void]$sb.AppendLine('## Missing candidate lines vs current doc section 3')
    [void]$sb.AppendLine('')

    $missingTotal = 0
    foreach ($rir in $rirOrder) {
        if (-not $missingMap.ContainsKey($rir)) { continue }
        $missing = @($missingMap[$rir])
        if ($missing.Count -eq 0) { continue }

        $missingTotal += $missing.Count
        [void]$sb.AppendLine("### $rir")
        foreach ($m in $missing) {
            [void]$sb.AppendLine("- $m")
        }
        [void]$sb.AppendLine('')
    }

    if ($missingTotal -eq 0) {
        [void]$sb.AppendLine('- No missing lines. Current doc section 3 already covers all extracted normalized candidates.')
        [void]$sb.AppendLine('')
    }

    [void]$sb.AppendLine('## Evidence samples by RIR')
    [void]$sb.AppendLine('')

    foreach ($rir in $rirOrder) {
        $rows = @($records | Where-Object { $_.Rir -eq $rir })
        if ($rows.Count -eq 0) { continue }

        [void]$sb.AppendLine("### $rir")
        [void]$sb.AppendLine("- Hits: $($rows.Count)")

        $grouped = $rows | Group-Object Raw | Sort-Object Count -Descending
        $shown = 0
        foreach ($g in $grouped) {
            if ($shown -ge $MaxExamplesPerRir) { break }
            [void]$sb.AppendLine("- Raw: $($g.Name) (hits=$($g.Count))")

            $sample = $g.Group | Select-Object -First 3
            foreach ($s in $sample) {
                [void]$sb.AppendLine("  - $($s.File):$($s.Line) (host=$($s.Host))")
            }
            $shown++
        }

        [void]$sb.AppendLine('')
    }
}

$sb.ToString() | Out-File -LiteralPath $outputFile -Encoding utf8
Write-Output "Output: $outputFile"
