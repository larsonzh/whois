param(
    [string]$ManifestPath = "out/generated/preclass_manifest.json",
    [string]$ReasonMapPath = "tools/preclass/reason_code_map.json",
    [string]$TableSourcePath = "src/core/preclass_table.c",
    [string]$PreclassCoreSourcePath = "src/core/preclass.c",
    [string]$OutDirRoot = ""
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $false

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path

function Resolve-RepoPath {
    param(
        [string]$PathValue
    )

    if ([string]::IsNullOrWhiteSpace($PathValue)) {
        return ""
    }
    if ([System.IO.Path]::IsPathRooted($PathValue)) {
        return (Resolve-Path $PathValue).Path
    }
    return (Resolve-Path (Join-Path $repoRoot $PathValue)).Path
}

function Get-Sha256Lower {
    param(
        [string]$PathValue
    )

    return (Get-FileHash -Algorithm SHA256 -Path $PathValue).Hash.ToLowerInvariant()
}

$manifestFullPath = Resolve-RepoPath -PathValue $ManifestPath
$reasonMapFullPath = Resolve-RepoPath -PathValue $ReasonMapPath
$tableSourceFullPath = Resolve-RepoPath -PathValue $TableSourcePath
$preclassCoreSourceFullPath = Resolve-RepoPath -PathValue $PreclassCoreSourcePath

function Get-FunctionText {
    param(
        [string]$SourceText,
        [string]$FunctionName
    )

    if (-not $SourceText -or -not $FunctionName) {
        return ""
    }

    $startPattern = "(?m)^static\s+const\s+char\*\s+{0}\s*\(" -f [regex]::Escape($FunctionName)
    $startMatch = [regex]::Match($SourceText, $startPattern)
    if (-not $startMatch.Success) {
        return ""
    }

    $rest = $SourceText.Substring($startMatch.Index)
    if ($rest.Length -le 1) {
        return $rest
    }

    $nextMatch = [regex]::Match($rest.Substring(1), "(?m)^static\s+")
    if ($nextMatch.Success) {
        $length = $nextMatch.Index + 1
        return $rest.Substring(0, $length)
    }

    return $rest
}

function Get-SwitchCaseIds {
    param(
        [string]$FunctionText
    )

    $ids = @()
    if (-not $FunctionText) {
        return $ids
    }

    $matches = [regex]::Matches($FunctionText, '(?m)^\s*case\s+(?<id>\d+)u:\s*return\s+"[^"]+";')
    foreach ($m in $matches) {
        $ids += [int]$m.Groups['id'].Value
    }
    return @($ids | Sort-Object -Unique)
}

if (-not $OutDirRoot -or $OutDirRoot.Trim().Length -eq 0) {
    $OutDirRoot = Join-Path $repoRoot "out/artifacts/preclass_table_guard"
}
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$outDir = Join-Path $OutDirRoot $stamp
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

$manifest = Get-Content -Raw -Path $manifestFullPath | ConvertFrom-Json
$reasonObj = Get-Content -Raw -Path $reasonMapFullPath | ConvertFrom-Json

$manifestIpv4Path = Resolve-RepoPath -PathValue $manifest.source_ipv4
$manifestIpv6Path = Resolve-RepoPath -PathValue $manifest.source_ipv6

$hashIpv4Actual = Get-Sha256Lower -PathValue $manifestIpv4Path
$hashIpv6Actual = Get-Sha256Lower -PathValue $manifestIpv6Path
$hashIpv4Expected = ([string]$manifest.source_ipv4_sha256).ToLowerInvariant()
$hashIpv6Expected = ([string]$manifest.source_ipv6_sha256).ToLowerInvariant()

$reasonMap = @{}
$allowedOrphanIds = @()
foreach ($prop in $reasonObj.PSObject.Properties) {
    $id = [int]$prop.Value
    $reasonMap[$prop.Name] = $id
    if ($prop.Name -match "_UNKNOWN_") {
        $allowedOrphanIds += $id
    }
}

$tableText = Get-Content -Raw -Path $tableSourceFullPath
$rowPattern = '\{(?<family>\d+)u,\s*\d+u,\s*\d+u,\s*\d+u,\s*(?<confidence>\d+)u,\s*(?<reason>\d+)u,\s*0x[0-9A-Fa-f]+ULL,\s*0x[0-9A-Fa-f]+ULL\}'
$rowMatches = [regex]::Matches($tableText, $rowPattern)

$rowsTotal = $rowMatches.Count
$rowsV4 = 0
$rowsV6 = 0
$usedReasonIds = @{}
$usedConfidenceIds = @{}

foreach ($m in $rowMatches) {
    $family = [int]$m.Groups["family"].Value
    $reason = [int]$m.Groups["reason"].Value
    $confidence = [int]$m.Groups["confidence"].Value
    if ($family -eq 4) {
        $rowsV4++
    }
    elseif ($family -eq 6) {
        $rowsV6++
    }
    $usedReasonIds[$reason] = $true
    $usedConfidenceIds[$confidence] = $true
}

$preclassCoreText = Get-Content -Raw -Path $preclassCoreSourceFullPath
$reasonFunctionText = Get-FunctionText -SourceText $preclassCoreText -FunctionName "wc_preclass_reason_name"
$confidenceFunctionText = Get-FunctionText -SourceText $preclassCoreText -FunctionName "wc_preclass_confidence_name"

$reasonReverseIds = Get-SwitchCaseIds -FunctionText $reasonFunctionText
$confidenceReverseIds = Get-SwitchCaseIds -FunctionText $confidenceFunctionText

$mapIds = @($reasonMap.Values | Sort-Object -Unique)
$usedIds = @($usedReasonIds.Keys | ForEach-Object { [int]$_ } | Sort-Object -Unique)
$usedConfidenceIdList = @($usedConfidenceIds.Keys | ForEach-Object { [int]$_ } | Sort-Object -Unique)
$allowedOrphanIds = @($allowedOrphanIds | Sort-Object -Unique)

$missingReasonIds = @($usedIds | Where-Object { $mapIds -notcontains $_ })
$orphanReasonIds = @($mapIds | Where-Object { ($usedIds -notcontains $_) -and ($allowedOrphanIds -notcontains $_) })
$missingReverseReasonIds = @($usedIds | Where-Object { $reasonReverseIds -notcontains $_ })
$missingReverseConfidenceIds = @($usedConfidenceIdList | Where-Object { $confidenceReverseIds -notcontains $_ })

$checkHashV4 = ($hashIpv4Actual -eq $hashIpv4Expected)
$checkHashV6 = ($hashIpv6Actual -eq $hashIpv6Expected)
$checkCountV4 = ($rowsV4 -eq [int]$manifest.record_count_v4)
$checkCountV6 = ($rowsV6 -eq [int]$manifest.record_count_v6)
$checkCountTotal = ($rowsTotal -eq [int]$manifest.record_count_total)
$checkReasonMissing = ($missingReasonIds.Count -eq 0)
$checkReasonOrphan = ($orphanReasonIds.Count -eq 0)
$checkReasonReverse = ($missingReverseReasonIds.Count -eq 0)
$checkConfidenceReverse = ($missingReverseConfidenceIds.Count -eq 0)

$allPass = @(
    $checkHashV4,
    $checkHashV6,
    $checkCountV4,
    $checkCountV6,
    $checkCountTotal,
    $checkReasonMissing,
    $checkReasonReverse,
    $checkConfidenceReverse
) -notcontains $false

$summaryObj = [ordered]@{
    result = $(if ($allPass) { "pass" } else { "fail" })
    manifest = $ManifestPath
    generatedAt = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
    checks = [ordered]@{
        hash_ipv4_match = $checkHashV4
        hash_ipv6_match = $checkHashV6
        row_count_v4_match = $checkCountV4
        row_count_v6_match = $checkCountV6
        row_count_total_match = $checkCountTotal
        reason_missing_none = $checkReasonMissing
        reason_reverse_lookup_complete = $checkReasonReverse
        confidence_reverse_lookup_complete = $checkConfidenceReverse
        reason_orphan_none = $checkReasonOrphan
        reason_orphan_non_blocking = $true
    }
    counts = [ordered]@{
        rows_v4 = $rowsV4
        rows_v6 = $rowsV6
        rows_total = $rowsTotal
        manifest_v4 = [int]$manifest.record_count_v4
        manifest_v6 = [int]$manifest.record_count_v6
        manifest_total = [int]$manifest.record_count_total
    }
    reason = [ordered]@{
        used_ids = $usedIds
        map_ids = $mapIds
        allowed_orphan_ids = $allowedOrphanIds
        missing_ids = $missingReasonIds
        orphan_ids = $orphanReasonIds
        reverse_lookup_ids = $reasonReverseIds
        missing_reverse_lookup_ids = $missingReverseReasonIds
    }
    confidence = [ordered]@{
        used_ids = $usedConfidenceIdList
        reverse_lookup_ids = $confidenceReverseIds
        missing_reverse_lookup_ids = $missingReverseConfidenceIds
    }
    sources = [ordered]@{
        ipv4 = $manifest.source_ipv4
        ipv6 = $manifest.source_ipv6
        ipv4_sha256_expected = $hashIpv4Expected
        ipv4_sha256_actual = $hashIpv4Actual
        ipv6_sha256_expected = $hashIpv6Expected
        ipv6_sha256_actual = $hashIpv6Actual
        table_source = $TableSourcePath
        preclass_core_source = $PreclassCoreSourcePath
        reason_map = $ReasonMapPath
    }
}

$summaryJsonPath = Join-Path $outDir "summary.json"
$summaryTxtPath = Join-Path $outDir "summary.txt"

$summaryObj | ConvertTo-Json -Depth 8 | Out-File -FilePath $summaryJsonPath -Encoding utf8

$summaryLines = @(
    "[PRECLASS-TABLE-GUARD] out_dir=$outDir",
    "[PRECLASS-TABLE-GUARD] manifest=$ManifestPath",
    "[PRECLASS-TABLE-GUARD] hash_ipv4_match=$checkHashV4 hash_ipv6_match=$checkHashV6",
    "[PRECLASS-TABLE-GUARD] count_v4=$rowsV4/$($manifest.record_count_v4) count_v6=$rowsV6/$($manifest.record_count_v6) count_total=$rowsTotal/$($manifest.record_count_total)",
    "[PRECLASS-TABLE-GUARD] missing_reason_ids=$($missingReasonIds -join ',')",
    "[PRECLASS-TABLE-GUARD] missing_reverse_reason_ids=$($missingReverseReasonIds -join ',')",
    "[PRECLASS-TABLE-GUARD] missing_reverse_confidence_ids=$($missingReverseConfidenceIds -join ',')",
    "[PRECLASS-TABLE-GUARD] orphan_reason_ids=$($orphanReasonIds -join ',')",
    "[PRECLASS-TABLE-GUARD] orphan_reason_ids_non_blocking=True",
    "[PRECLASS-TABLE-GUARD] summary_json=$summaryJsonPath",
    "[PRECLASS-TABLE-GUARD] result=$($summaryObj.result)"
)
$summaryLines | Out-File -FilePath $summaryTxtPath -Encoding utf8
$summaryLines | ForEach-Object { Write-Output $_ }

if (-not $allPass) {
    exit 1
}

exit 0
