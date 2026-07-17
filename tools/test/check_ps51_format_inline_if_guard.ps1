param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [ValidateSet('tracked', 'all')][string]$Scope = 'tracked'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'unattended_exit_result.ps1')
$script:UnhandledExitTag = 'CHECK-PS51-FORMAT-INLINE-IF-GUARD'

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

foreach ($file in $targetFiles) {
    $tokens = $null
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($file, [ref]$tokens, [ref]$parseErrors)
    $formatExpressions = @($ast.FindAll({
        param($node)
        return (
            $node -is [System.Management.Automation.Language.BinaryExpressionAst] -and
            $node.Operator -eq [System.Management.Automation.Language.TokenKind]::Format
        )
    }, $true))

    foreach ($formatExpression in $formatExpressions) {
        $inlineIfNodes = @($formatExpression.Right.FindAll({
            param($node)
            return $node -is [System.Management.Automation.Language.IfStatementAst]
        }, $true))
        if ($inlineIfNodes.Count -lt 1) {
            continue
        }

        $snippet = $formatExpression.Extent.Text.Trim()
        if ($snippet.Length -gt 180) {
            $snippet = $snippet.Substring(0, 180) + '...'
        }

        [void]$violations.Add([pscustomobject]@{
            file = (Get-RepoRelativePath -Root $RepoRoot -Path $file)
            line = [int]$formatExpression.Extent.StartLineNumber
            snippet = $snippet
        })
    }
}

if ($violations.Count -gt 0) {
    Write-Output ('[PS51-FMT-CHECK] result=FAIL scope={0} files={1} violations={2}' -f $Scope, $targetFiles.Count, $violations.Count)
    foreach ($v in $violations) {
        Write-Output ('[PS51-FMT-CHECK] severity=error file={0} line={1} detail=inline-$(if) used in -f arguments snippet={2}' -f [string]$v.file, [int]$v.line, [string]$v.snippet)
    }
    Exit-UnattendedFailure -Tag $script:UnhandledExitTag -Reason ("inline-if format violations={0}" -f $violations.Count) -ExitCode 1
}

Write-Output ('[PS51-FMT-CHECK] result=PASS scope={0} files={1} violations=0' -f $Scope, $targetFiles.Count)
exit 0
