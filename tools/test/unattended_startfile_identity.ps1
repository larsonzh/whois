Set-StrictMode -Version Latest

function Get-StableStartFileToken {
    param([string]$StartFilePath)

    if ([string]::IsNullOrWhiteSpace($StartFilePath)) {
        return 'sf_unknown'
    }

    $fullPath = [System.IO.Path]::GetFullPath($StartFilePath).ToLowerInvariant()
    $sha1 = [System.Security.Cryptography.SHA1]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($fullPath)
        $hashBytes = $sha1.ComputeHash($bytes)
        $hash = ([System.BitConverter]::ToString($hashBytes)).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sha1.Dispose()
    }

    return ('sf_{0}' -f $hash)
}

function Get-LegacyStartFileToken {
    param(
        [string]$StartFilePath,
        [switch]$PreserveCase,
        [switch]$NoSanitize,
        [string]$EmptyFallback = 'default'
    )

    $leaf = [System.IO.Path]::GetFileNameWithoutExtension($StartFilePath)
    if (-not $PreserveCase.IsPresent) {
        $leaf = $leaf.ToLowerInvariant()
    }

    if ($NoSanitize.IsPresent) {
        if ([string]::IsNullOrWhiteSpace($leaf)) {
            return $EmptyFallback
        }

        return $leaf
    }

    $safe = ([regex]::Replace($leaf, '[^A-Za-z0-9._-]', '_')).Trim('_')
    if ([string]::IsNullOrWhiteSpace($safe)) {
        return $EmptyFallback
    }

    return $safe
}