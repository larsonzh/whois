Set-StrictMode -Version Latest

function Convert-ToGuardRepoRelativePath {
    param(
        [string]$RepoRoot,
        [string]$Path
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return ''
    }

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $repoRootFull = [System.IO.Path]::GetFullPath($RepoRoot)
    if ($fullPath.StartsWith($repoRootFull, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $fullPath.Substring($repoRootFull.Length).TrimStart('\').Replace('\', '/')
    }

    return $fullPath.Replace('\', '/')
}

function Assert-GuardRepoPathUnderRoots {
    param(
        [string]$RepoRoot,
        [string]$Path,
        [string[]]$AllowedRelativeRoots,
        [string]$Label
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw ("{0} path must not be empty." -f $Label)
    }

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $repoRootFull = [System.IO.Path]::GetFullPath($RepoRoot)
    if (-not $fullPath.StartsWith($repoRootFull, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw ("{0} must stay inside the repository: {1}" -f $Label, $fullPath)
    }

    $relativePath = Convert-ToGuardRepoRelativePath -RepoRoot $RepoRoot -Path $fullPath
    $normalizedRelativePath = $relativePath.Replace('\', '/').TrimStart('/')
    foreach ($allowedRoot in @($AllowedRelativeRoots)) {
        if ([string]::IsNullOrWhiteSpace($allowedRoot)) {
            continue
        }

        $normalizedRoot = $allowedRoot.Trim().Replace('\', '/').Trim('/')
        if ($normalizedRelativePath.Equals($normalizedRoot, [System.StringComparison]::OrdinalIgnoreCase) -or
            $normalizedRelativePath.StartsWith($normalizedRoot + '/', [System.StringComparison]::OrdinalIgnoreCase)) {
            return $fullPath
        }
    }

    throw ("{0} must stay under one of [{1}]. path={2}" -f $Label, (($AllowedRelativeRoots | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join ', '), $normalizedRelativePath)
}

function Assert-GuardRepoPathMatchesPattern {
    param(
        [string]$RepoRoot,
        [string]$Path,
        [string]$RelativePathPattern,
        [string]$Label
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw ("{0} path must not be empty." -f $Label)
    }

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $repoRootFull = [System.IO.Path]::GetFullPath($RepoRoot)
    if (-not $fullPath.StartsWith($repoRootFull, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw ("{0} must stay inside the repository: {1}" -f $Label, $fullPath)
    }

    $relativePath = Convert-ToGuardRepoRelativePath -RepoRoot $RepoRoot -Path $fullPath
    if ($relativePath -notmatch $RelativePathPattern) {
        throw ("{0} must match repo-relative pattern {1}: {2}" -f $Label, $RelativePathPattern, $relativePath)
    }

    return $fullPath
}

function Assert-GuardUnattendedStartFileOutputPath {
    param(
        [string]$RepoRoot,
        [string]$Path
    )

    return Assert-GuardRepoPathMatchesPattern -RepoRoot $RepoRoot -Path $Path -RelativePathPattern '^testdata/unattended_start/(active|smoke)/.+\.md$' -Label 'Output file'
}

function Assert-GuardTaskDefinitionMutationPath {
    param(
        [string]$RepoRoot,
        [string]$Path
    )

    return Assert-GuardRepoPathMatchesPattern -RepoRoot $RepoRoot -Path $Path -RelativePathPattern '^testdata/.+\.json$' -Label 'Task definition mutation path'
}
