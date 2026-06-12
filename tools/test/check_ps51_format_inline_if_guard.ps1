param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [ValidateSet('tracked', 'all')][string]$Scope = 'tracked'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-TargetFiles {
    param(
        [string]$Root,
        [ValidateSet('tracked', 'all')][string]$FileScope
    )

    if ($FileScope -eq 'all') {
        return @(
            Get-ChildItem -Path $Root -Recurse -File -Filter '*.ps1' -ErrorAction Stop |
                ForEach-Object { $_.FullName }
        )
    }

    $files = @((& git -C $Root ls-files '*.ps1' 2>$null) | ForEach-Object { [string]$_ })
    $resolved = New-Object 'System.Collections.Generic.List[string]'
    foreach ($rel in $files) {
        if ([string]::IsNullOrWhiteSpace($rel)) {
            continue
        }

        $full = [System.IO.Path]::GetFullPath((Join-Path $Root $rel))
        if (Test-Path -LiteralPath $full) {
            [void]$resolved.Add($full)
        }
    }

    return @($resolved)
}

function Get-RepoRelativePath {
    param(
        [string]$Root,
        [string]$Path
    )

    $root = [System.IO.Path]::GetFullPath($Root)
    $full = [System.IO.Path]::GetFullPath($Path)
    if ($full.StartsWith($root, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $full.Substring($root.Length).TrimStart('\\').Replace('\\', '/')
    }

    return $full.Replace('\\', '/')
}

$targetFiles = @(Get-TargetFiles -Root $RepoRoot -FileScope $Scope)
if ($targetFiles.Count -lt 1) {
    Write-Output ('[PS51-FMT-CHECK] result=PASS scope={0} files=0 detail=no-ps1-files' -f $Scope)
    exit 0
}

$violations = New-Object 'System.Collections.Generic.List[object]'

# Detect inline conditional subexpressions used as format arguments.
# Use line-based checks to avoid heavy regex backtracking in large files.
$linePattern = [regex]'(?i)-f.*\$\(\s*if\s*\('
$continuationPattern = [regex]'(?i)^\s*\$\(\s*if\s*\('

foreach ($file in $targetFiles) {
    $content = ''
    try {
        $content = Get-Content -LiteralPath $file -Raw -Encoding utf8 -ErrorAction Stop
    }
    catch {
        continue
    }

    $lines = @($content -split "`r?`n")
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $lineText = [string]$lines[$i]
        $hit = $false

        if ($linePattern.IsMatch($lineText)) {
            $hit = $true
        }
        elseif ($i -gt 0) {
            $prev = [string]$lines[$i - 1]
            if ($prev -match '(?i)-f\s*$' -and $continuationPattern.IsMatch($lineText)) {
                $hit = $true
            }
        }

        if (-not $hit) {
            continue
        }

        $snippet = $lineText.Trim()
        if ($snippet.Length -gt 180) {
            $snippet = $snippet.Substring(0, 180) + '...'
        }

        [void]$violations.Add([pscustomobject]@{
            file = (Get-RepoRelativePath -Root $RepoRoot -Path $file)
            line = ($i + 1)
            snippet = $snippet
        })
    }
}

if ($violations.Count -gt 0) {
    Write-Output ('[PS51-FMT-CHECK] result=FAIL scope={0} files={1} violations={2}' -f $Scope, $targetFiles.Count, $violations.Count)
    foreach ($v in $violations) {
        Write-Output ('[PS51-FMT-CHECK] severity=error file={0} line={1} detail=inline-$(if) used in -f arguments snippet={2}' -f [string]$v.file, [int]$v.line, [string]$v.snippet)
    }
    exit 1
}

Write-Output ('[PS51-FMT-CHECK] result=PASS scope={0} files={1} violations=0' -f $Scope, $targetFiles.Count)
exit 0
