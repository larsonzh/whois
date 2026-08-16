param(
    [string]$BinaryPath = "d:\LZProjects\whois\release\lzispro\whois\whois-win64.exe",
    [string]$OutDirRoot = "",
    [switch]$RunExplicitHosts,
    [string[]]$ExplicitHosts = @("iana", "apnic", "arin", "ripe", "afrinic", "lacnic", "verisign")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $false

if (-not (Test-Path -LiteralPath $BinaryPath -PathType Leaf)) {
    throw "Binary not found: $BinaryPath"
}
if ([string]::IsNullOrWhiteSpace($OutDirRoot)) {
    $OutDirRoot = Join-Path $PSScriptRoot "..\..\out\artifacts\preclass_special_registry"
}
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$outDir = Join-Path $OutDirRoot $stamp
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

$cases = @(
    [pscustomobject]@{ Query = "192.0.2.1"; Class = "special"; Purpose = "documentation"; CoveringRir = "arin" },
    [pscustomobject]@{ Query = "198.51.100.1"; Class = "special"; Purpose = "documentation"; CoveringRir = "arin" },
    [pscustomobject]@{ Query = "203.0.113.1"; Class = "special"; Purpose = "documentation"; CoveringRir = "apnic" },
    [pscustomobject]@{ Query = "10.0.0.1"; Class = "special"; Purpose = "private-use"; CoveringRir = "none" },
    [pscustomobject]@{ Query = "198.18.0.1"; Class = "special"; Purpose = "benchmarking"; CoveringRir = "arin" },
    [pscustomobject]@{ Query = "127.0.0.1"; Class = "special"; Purpose = "loopback"; CoveringRir = "none" },
    [pscustomobject]@{ Query = "240.0.0.1"; Class = "reserved"; Purpose = "reserved"; CoveringRir = "none" },
    [pscustomobject]@{ Query = "2001:db8::1"; Class = "special"; Purpose = "documentation"; CoveringRir = "unknown" },
    [pscustomobject]@{ Query = "fc00::1"; Class = "special"; Purpose = "unique-local"; CoveringRir = "none" },
    [pscustomobject]@{ Query = "fe80::1"; Class = "special"; Purpose = "link-local-unicast"; CoveringRir = "none" }
)

function ConvertTo-NativeText {
    param([object[]]$InputObject)

    return @($InputObject | ForEach-Object {
        if ($_ -is [System.Management.Automation.ErrorRecord]) {
            $_.Exception.Message
        }
        else {
            [string]$_
        }
    })
}

function Get-PreclassField {
    param([string]$Text, [string]$Name)

    $match = [regex]::Match($Text,
        '(?m)^\[PRECLASS\][^\r\n]*\b' + [regex]::Escape($Name) + '=(?<value>[^\s]+)')
    return $(if ($match.Success) { $match.Groups["value"].Value } else { "" })
}

function Get-AddressStatus {
    param([string]$Text)

    $match = [regex]::Match($Text,
        '(?m)^=== Address Status: (?<class>reserved|special) purpose=(?<purpose>[^\s]+) registry=(?<registry>[^\s]+) covering-rir=(?<covering>[^\s]+) ===$')
    if (-not $match.Success) {
        return $null
    }
    return [pscustomobject]@{
        Class = $match.Groups["class"].Value
        Purpose = $match.Groups["purpose"].Value
        Registry = $match.Groups["registry"].Value
        CoveringRir = $match.Groups["covering"].Value
    }
}

function Invoke-SpecialCase {
    param(
        [string]$Name,
        [string]$Query,
        [string]$ExpectedClass,
        [string]$ExpectedPurpose,
        [string]$ExpectedCoveringRir,
        [string]$ExplicitHost = ""
    )

    $cliOptions = @("--enable-preclass-early-converge", "--debug", "-t", "3")
    if (-not [string]::IsNullOrWhiteSpace($ExplicitHost)) {
        $cliOptions += @("-h", $ExplicitHost)
    }
    $cliOptions += $Query
    $previousErrorAction = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        $raw = & $BinaryPath @cliOptions 2>&1
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousErrorAction
    }
    $lines = ConvertTo-NativeText -InputObject $raw
    $text = $lines -join "`n"
    $safeName = ($Name -replace '[^A-Za-z0-9._-]', '_')
    $logPath = Join-Path $outDir "$safeName.log"
    [System.IO.File]::WriteAllLines($logPath, $lines, [System.Text.UTF8Encoding]::new($false))

    $status = Get-AddressStatus -Text $text
    $authorityUnknown = $text -match '(?m)^=== Authoritative RIR: unknown @ unknown ===$'
    $preclassClass = Get-PreclassField -Text $text -Name "class"
    $preclassRir = Get-PreclassField -Text $text -Name "rir"
    $preclassCovering = Get-PreclassField -Text $text -Name "covering_rir"
    $preclassRegistry = Get-PreclassField -Text $text -Name "registry"
    $preclassPurpose = Get-PreclassField -Text $text -Name "purpose"
    $pass = $exitCode -eq 0 -and $null -ne $status -and $authorityUnknown -and
        $status.Class -eq $ExpectedClass -and
        $status.Purpose -eq $ExpectedPurpose -and
        $status.Registry -eq "iana" -and
        $status.CoveringRir -eq $ExpectedCoveringRir -and
        $preclassClass -eq $ExpectedClass -and
        $preclassRir -eq "none" -and
        $preclassCovering -eq $ExpectedCoveringRir -and
        $preclassRegistry -eq "iana" -and
        $preclassPurpose -eq $ExpectedPurpose

    return [pscustomobject]@{
        Name = $Name
        Query = $Query
        ExplicitHost = $ExplicitHost
        ExitCode = $exitCode
        Class = $(if ($null -ne $status) { $status.Class } else { "" })
        Purpose = $(if ($null -ne $status) { $status.Purpose } else { "" })
        Registry = $(if ($null -ne $status) { $status.Registry } else { "" })
        CoveringRir = $(if ($null -ne $status) { $status.CoveringRir } else { "" })
        AuthorityUnknown = $authorityUnknown
        Pass = $pass
        Log = $logPath
    }
}

$results = @()
foreach ($case in $cases) {
    $results += Invoke-SpecialCase -Name ("implicit-{0}" -f $case.Query) `
        -Query $case.Query -ExpectedClass $case.Class -ExpectedPurpose $case.Purpose `
        -ExpectedCoveringRir $case.CoveringRir
}

if ($RunExplicitHosts) {
    foreach ($hostName in $ExplicitHosts) {
        $results += Invoke-SpecialCase -Name "explicit-test-net-3-$hostName" `
            -Query "203.0.113.0/24" -ExpectedClass "special" `
            -ExpectedPurpose "documentation" -ExpectedCoveringRir "apnic" `
            -ExplicitHost $hostName
    }
}

$summaryCsv = Join-Path $outDir "summary.csv"
$summaryTxt = Join-Path $outDir "summary.txt"
$results | Export-Csv -Path $summaryCsv -NoTypeInformation -Encoding UTF8
$failed = @($results | Where-Object { -not $_.Pass })
$summary = @(
    "result=$(if ($failed.Count -eq 0) { 'pass' } else { 'fail' })"
    "cases=$($results.Count)"
    "passed=$(@($results | Where-Object { $_.Pass }).Count)"
    "failed=$($failed.Count)"
    "explicit_hosts=$([int]$RunExplicitHosts.IsPresent)"
)
[System.IO.File]::WriteAllLines($summaryTxt, $summary, [System.Text.UTF8Encoding]::new($false))

foreach ($result in $results) {
    Write-Output ("[PRECLASS-SPECIAL] case={0} result={1} class={2} purpose={3} covering_rir={4}" -f
        $result.Name, $(if ($result.Pass) { "pass" } else { "fail" }),
        $result.Class, $result.Purpose, $result.CoveringRir)
}
Write-Output ("[PRECLASS-SPECIAL] summary={0} result={1} passed={2} failed={3}" -f
    $summaryTxt, $(if ($failed.Count -eq 0) { "pass" } else { "fail" }),
    @($results | Where-Object { $_.Pass }).Count, $failed.Count)

if ($failed.Count -gt 0) {
    exit 1
}
exit 0