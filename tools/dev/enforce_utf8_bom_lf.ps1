param(
    [AllowEmptyString()][string]$RepoRoot = '',
    [ValidateSet('check', 'fix')][string]$Mode = 'check',
    [ValidateSet('off', 'warn', 'enforce')][string]$Policy = 'enforce',
    [ValidateSet('tracked', 'all')][string]$Scope = 'tracked',
    [int]$MaxReport = 120,
    [string[]]$Extensions = @('.ps1', '.json', '.md'),
    [string[]]$ExcludePaths = @()
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($RepoRoot)) {
    $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
}

function Convert-ToRepoRelativePath {
    param(
        [string]$Root,
        [string]$Path
    )

    $rootFull = [System.IO.Path]::GetFullPath($Root)
    $pathFull = [System.IO.Path]::GetFullPath($Path)
    if ($pathFull.StartsWith($rootFull, [System.StringComparison]::OrdinalIgnoreCase)) {
        $rel = $pathFull.Substring($rootFull.Length).TrimStart([char]92, [char]47)
        return $rel.Replace('\', '/')
    }

    return $pathFull.Replace('\', '/')
}

function Test-ExcludedPath {
    param(
        [string]$RelativePath,
        [string[]]$Excluded
    )

    if ($null -eq $Excluded -or $Excluded.Count -eq 0) {
        return $false
    }

    foreach ($prefix in $Excluded) {
        if ([string]::IsNullOrWhiteSpace($prefix)) {
            continue
        }

        $normalizedPrefix = $prefix.Replace('\\', '/').Trim()
        if ($RelativePath.StartsWith($normalizedPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }

    return $false
}

function Get-TrackedCandidateFiles {
    param(
        [string]$Root,
        [string[]]$Exts
    )

    $patterns = New-Object 'System.Collections.Generic.List[string]'
    foreach ($ext in $Exts) {
        [void]$patterns.Add(('*' + $ext))
    }

    $gitArgs = @('-C', $Root, 'ls-files', '--') + @($patterns)
    $output = & git @gitArgs
    if ($LASTEXITCODE -ne 0) {
        throw 'git ls-files failed; cannot enumerate tracked files.'
    }

    $list = New-Object 'System.Collections.Generic.List[string]'
    foreach ($line in @($output)) {
        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }

        $normalized = [string]$line
        $normalized = $normalized.Replace('\\', '/')
        [void]$list.Add($normalized)
    }

    return @($list)
}

function Get-RecursiveCandidateFiles {
    param(
        [string]$Root,
        [string[]]$Exts
    )

    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $paths = New-Object 'System.Collections.Generic.List[string]'
    $files = Get-ChildItem -LiteralPath $Root -Recurse -File

    foreach ($f in $files) {
        if ($Exts -notcontains $f.Extension.ToLowerInvariant()) {
            continue
        }

        $rel = Convert-ToRepoRelativePath -Root $Root -Path $f.FullName
        if ($set.Add($rel)) {
            [void]$paths.Add($rel)
        }
    }

    return @($paths)
}

function Get-EncodingStatus {
    param([string]$FilePath)

    $bytes = [System.IO.File]::ReadAllBytes($FilePath)
    $hasBom = ($bytes.Length -ge 3 -and $bytes[0] -eq 239 -and $bytes[1] -eq 187 -and $bytes[2] -eq 191)
    $hasCr = ([Array]::IndexOf($bytes, [byte]13) -ge 0)
    $hasLf = ([Array]::IndexOf($bytes, [byte]10) -ge 0)

    $eol = if (-not $hasCr -and $hasLf) {
        'LF'
    }
    elseif (-not $hasCr -and -not $hasLf) {
        'None'
    }
    elseif ($hasCr -and $hasLf) {
        'CRLF-or-Mixed'
    }
    else {
        'CR-only'
    }

    [PSCustomObject]@{
        HasBom      = $hasBom
        HasCr       = $hasCr
        HasLf       = $hasLf
        Eol         = $eol
        IsCompliant = ($hasBom -and -not $hasCr)
    }
}

function Convert-ToUtf8BomLf {
    param([string]$FilePath)

    $text = [System.IO.File]::ReadAllText($FilePath)
    $text = ($text -replace "`r`n", "`n") -replace "`r", "`n"
    if (-not [string]::IsNullOrEmpty($text) -and -not $text.EndsWith("`n", [System.StringComparison]::Ordinal)) {
        $text += "`n"
    }

    $utf8Bom = New-Object System.Text.UTF8Encoding $true
    [System.IO.File]::WriteAllText($FilePath, $text, $utf8Bom)
}

if ($Policy -eq 'off') {
    Write-Output '[ENCODING-POLICY] policy=off action=skip'
    exit 0
}

$candidates = if ($Scope -eq 'tracked') {
    Get-TrackedCandidateFiles -Root $RepoRoot -Exts $Extensions
}
else {
    Get-RecursiveCandidateFiles -Root $RepoRoot -Exts $Extensions
}

$scanned = 0
$nonCompliant = 0
$fixed = 0
$remaining = 0
$failedFixes = New-Object 'System.Collections.Generic.List[string]'
$nonCompliantFiles = New-Object 'System.Collections.Generic.List[string]'
$reported = 0

foreach ($rel in $candidates) {
    if (Test-ExcludedPath -RelativePath $rel -Excluded $ExcludePaths) {
        continue
    }

    $full = Join-Path $RepoRoot ($rel.Replace('/', '\\'))
    if (-not (Test-Path -LiteralPath $full)) {
        continue
    }

    $scanned++
    $status = Get-EncodingStatus -FilePath $full
    if ($status.IsCompliant) {
        continue
    }

    $nonCompliant++
    [void]$nonCompliantFiles.Add($rel)
    if ($reported -lt $MaxReport) {
        Write-Output ("[ENCODING-POLICY] noncompliant path={0} bom={1} eol={2}" -f $rel, $status.HasBom, $status.Eol)
        $reported++
    }

    if ($Mode -eq 'fix') {
        try {
            Convert-ToUtf8BomLf -FilePath $full
            $after = Get-EncodingStatus -FilePath $full
            if ($after.IsCompliant) {
                $fixed++
                if ($reported -lt $MaxReport) {
                    Write-Output ("[ENCODING-POLICY] fixed path={0}" -f $rel)
                    $reported++
                }
            }
            else {
                $remaining++
                [void]$failedFixes.Add($rel)
            }
        }
        catch {
            $remaining++
            [void]$failedFixes.Add($rel)
            Write-Warning ("[ENCODING-POLICY] fix_failed path={0} detail={1}" -f $rel, $_.Exception.Message)
        }
    }
}

if ($Mode -eq 'check') {
    $remaining = $nonCompliant
}

Write-Output ("[ENCODING-POLICY] summary mode={0} policy={1} scope={2} scanned={3} non_compliant={4} fixed={5} remaining={6}" -f $Mode, $Policy, $Scope, $scanned, $nonCompliant, $fixed, $remaining)

if ($nonCompliantFiles.Count -gt 0) {
    $preview = @($nonCompliantFiles | Select-Object -First 20)
    Write-Output ("[ENCODING-POLICY] noncompliant_preview count={0} files={1}" -f $nonCompliantFiles.Count, ($preview -join ';'))
}

if ($failedFixes.Count -gt 0) {
    $preview = @($failedFixes | Select-Object -First 20)
    Write-Warning ("[ENCODING-POLICY] failed_preview count={0} files={1}" -f $failedFixes.Count, ($preview -join ';'))
}

if ($Policy -eq 'warn' -and $remaining -gt 0) {
    Write-Warning ("[ENCODING-POLICY] policy=warn remaining={0}" -f $remaining)
    exit 0
}

if ($Policy -eq 'enforce' -and $remaining -gt 0) {
    Write-Output ("[ENCODING-POLICY] policy=enforce remaining={0} exit_code=1" -f $remaining)
    exit 1
}

exit 0
