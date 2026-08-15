param(
    [string]$OutputDirectory = "",
    [ValidateRange(5, 300)][int]$TimeoutSec = 60
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $repositoryRoot "docs\registry-snapshots"
}
elseif (-not [System.IO.Path]::IsPathRooted($OutputDirectory)) {
    $OutputDirectory = Join-Path $repositoryRoot $OutputDirectory
}
$OutputDirectory = [System.IO.Path]::GetFullPath($OutputDirectory)

$snapshotDefinitions = @(
    [pscustomobject]@{
        Name = "iana-ipv4-address-space.csv"
        Url = "https://www.iana.org/assignments/ipv4-address-space/ipv4-address-space.csv"
        RequiredColumns = @("Prefix", "Designation", "Date", "WHOIS", "RDAP", "Status [1]", "Note")
    },
    [pscustomobject]@{
        Name = "iana-ipv6-address-space.csv"
        Url = "https://www.iana.org/assignments/ipv6-address-space/ipv6-address-space-1.csv"
        RequiredColumns = @("IPv6 Prefix", "Allocation", "Reference", "Notes")
    },
    [pscustomobject]@{
        Name = "iana-ipv4-special-registry.csv"
        Url = "https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry-1.csv"
        RequiredColumns = @("Address Block", "Name", "RFC", "Allocation Date", "Termination Date", "Source", "Destination", "Forwardable", "Globally Reachable", "Reserved-by-Protocol")
    },
    [pscustomobject]@{
        Name = "iana-ipv6-special-registry.csv"
        Url = "https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry-1.csv"
        RequiredColumns = @("Address Block", "Name", "RFC", "Allocation Date", "Termination Date", "Source", "Destination", "Forwardable", "Globally Reachable", "Reserved-by-Protocol")
    }
)

function Get-ByteSha256 {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([System.BitConverter]::ToString($sha256.ComputeHash($Bytes))).Replace("-", "").ToLowerInvariant()
    }
    finally {
        $sha256.Dispose()
    }
}

function ConvertTo-CanonicalCsvContent {
    param([Parameter(Mandatory = $true)][byte[]]$SourceBytes)

    $strictUtf8 = [System.Text.UTF8Encoding]::new($false, $true)
    $text = $strictUtf8.GetString($SourceBytes)
    if ($text.Length -gt 0 -and $text[0] -eq [char]0xFEFF) {
        $text = $text.Substring(1)
    }
    $text = $text.Replace("`r`n", "`n").Replace("`r", "`n")
    if (-not $text.EndsWith("`n", [System.StringComparison]::Ordinal)) {
        $text += "`n"
    }
    $encoding = [System.Text.UTF8Encoding]::new($true)
    $preamble = $encoding.GetPreamble()
    $payload = $encoding.GetBytes($text)
    $result = New-Object byte[] ($preamble.Length + $payload.Length)
    [System.Array]::Copy($preamble, 0, $result, 0, $preamble.Length)
    [System.Array]::Copy($payload, 0, $result, $preamble.Length, $payload.Length)
    return $result
}

function Assert-CsvContract {
    param(
        [Parameter(Mandatory = $true)][byte[]]$CanonicalBytes,
        [Parameter(Mandatory = $true)][string[]]$RequiredColumns,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $text = [System.Text.Encoding]::UTF8.GetString($CanonicalBytes).TrimStart([char]0xFEFF)
    $rows = @($text | ConvertFrom-Csv)
    if ($rows.Count -eq 0) {
        throw "CSV contains no data rows: $Name"
    }
    $columns = @($rows[0].PSObject.Properties.Name)
    foreach ($requiredColumn in $RequiredColumns) {
        if ($columns -notcontains $requiredColumn) {
            throw "CSV column missing: file=$Name column=$requiredColumn actual=$($columns -join ',')"
        }
    }
    return $rows.Count
}

if ([Net.ServicePointManager]::SecurityProtocol -band [Net.SecurityProtocolType]::Tls12) {
    $null = $true
}
else {
    [Net.ServicePointManager]::SecurityProtocol =
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
}

$stagingRoot = Join-Path $repositoryRoot ("tmp\iana-registry-snapshot-update\{0}" -f [guid]::NewGuid().ToString("N"))
$backupRoot = Join-Path $stagingRoot "backup"
$stagedFiles = Join-Path $stagingRoot "staged"
$promotedNames = New-Object "System.Collections.Generic.List[string]"

try {
    New-Item -ItemType Directory -Path $stagedFiles -Force | Out-Null
    $retrievedAt = [DateTimeOffset]::UtcNow.ToString("o")
    $entries = @()

    foreach ($definition in $snapshotDefinitions) {
        Write-Output ("[IANA-SNAPSHOT] action=download file={0} url={1}" -f $definition.Name, $definition.Url)
        $response = Invoke-WebRequest -Uri $definition.Url -UseBasicParsing -TimeoutSec $TimeoutSec -ErrorAction Stop
        if ([int]$response.StatusCode -ne 200) {
            throw "Unexpected HTTP status: file=$($definition.Name) status=$($response.StatusCode)"
        }
        $contentType = [string]$response.Headers["Content-Type"]
        if ($contentType -notmatch "(?i)^text/csv(?:;|$)") {
            throw "Unexpected content type: file=$($definition.Name) content_type=$contentType"
        }

        $sourceBytes = $response.RawContentStream.ToArray()
        if ($sourceBytes.Length -eq 0) {
            throw "Downloaded file is empty: $($definition.Name)"
        }
        $canonicalBytes = ConvertTo-CanonicalCsvContent -SourceBytes $sourceBytes
        $rowCount = Assert-CsvContract -CanonicalBytes $canonicalBytes -RequiredColumns $definition.RequiredColumns -Name $definition.Name
        $stagedPath = Join-Path $stagedFiles $definition.Name
        [System.IO.File]::WriteAllBytes($stagedPath, $canonicalBytes)

        $entries += [ordered]@{
            file = $definition.Name
            url = $definition.Url
            retrieved_at_utc = $retrievedAt
            content_type = $contentType
            row_count = [int]$rowCount
            source_length = [long]$sourceBytes.Length
            source_sha256 = Get-ByteSha256 -Bytes $sourceBytes
            stored_length = [long]$canonicalBytes.Length
            stored_sha256 = Get-ByteSha256 -Bytes $canonicalBytes
        }
        Write-Output ("[IANA-SNAPSHOT] action=validated file={0} rows={1}" -f $definition.Name, $rowCount)
    }

    $manifest = [ordered]@{
        schema = "IANA_REGISTRY_SNAPSHOT_MANIFEST_V1"
        generated_at_utc = $retrievedAt
        normalization = "UTF-8 BOM + LF"
        file_count = [int]$entries.Count
        files = @($entries)
    }
    $manifestText = ($manifest | ConvertTo-Json -Depth 8) + "`n"
    $manifestText = $manifestText.Replace("`r`n", "`n").Replace("`r", "`n")
    [System.IO.File]::WriteAllText(
        (Join-Path $stagedFiles "manifest.json"),
        $manifestText,
        [System.Text.UTF8Encoding]::new($true))

    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    New-Item -ItemType Directory -Path $backupRoot -Force | Out-Null
    $namesToPromote = @($snapshotDefinitions | ForEach-Object { $_.Name }) + "manifest.json"
    foreach ($name in $namesToPromote) {
        $destination = Join-Path $OutputDirectory $name
        if (Test-Path -LiteralPath $destination -PathType Leaf) {
            Copy-Item -LiteralPath $destination -Destination (Join-Path $backupRoot $name) -Force
        }
        Copy-Item -LiteralPath (Join-Path $stagedFiles $name) -Destination $destination -Force
        [void]$promotedNames.Add($name)
    }

    Write-Output ("[IANA-SNAPSHOT] result=pass output={0} files={1}" -f $OutputDirectory, $entries.Count)
}
catch {
    foreach ($name in @($promotedNames)) {
        $destination = Join-Path $OutputDirectory $name
        $backup = Join-Path $backupRoot $name
        if (Test-Path -LiteralPath $backup -PathType Leaf) {
            Copy-Item -LiteralPath $backup -Destination $destination -Force
        }
        elseif (Test-Path -LiteralPath $destination -PathType Leaf) {
            Remove-Item -LiteralPath $destination -Force
        }
    }
    Write-Error ("[IANA-SNAPSHOT] result=fail error={0}" -f $_.Exception.Message)
    exit 1
}
finally {
    Remove-Item -LiteralPath $stagingRoot -Recurse -Force -ErrorAction SilentlyContinue
}