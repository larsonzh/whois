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

function Resolve-PreferredDefaultPath {
    param(
        [AllowEmptyString()][string]$PreferredPath,
        [AllowEmptyString()][string]$LegacyPath
    )

    if (-not [string]::IsNullOrWhiteSpace($PreferredPath) -and (Test-Path -LiteralPath $PreferredPath)) {
        return $PreferredPath
    }

    if (-not [string]::IsNullOrWhiteSpace($LegacyPath) -and (Test-Path -LiteralPath $LegacyPath)) {
        return $LegacyPath
    }

    if (-not [string]::IsNullOrWhiteSpace($PreferredPath)) {
        return $PreferredPath
    }

    return $LegacyPath
}

function Get-UnattendedRepoRoot {
    if (Get-Variable -Name RepoRoot -Scope Script -ErrorAction SilentlyContinue) {
        $value = [string](Get-Variable -Name RepoRoot -Scope Script -ValueOnly)
        if (-not [string]::IsNullOrWhiteSpace($value)) {
            return [System.IO.Path]::GetFullPath($value)
        }
    }

    return [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
}

function Convert-ToBooleanSetting {
    param(
        [AllowEmptyString()][string]$Value,
        [bool]$Default = $false
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $Default
    }

    return $Value.Trim().ToLowerInvariant() -in @('1', 'true', 'yes', 'on')
}

function Convert-ToSingleLineText {
    param([AllowNull()][AllowEmptyString()][string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return ''
    }

    $singleLine = (($Text -split "`r?`n") -join ' ')
    return ([regex]::Replace($singleLine, '\s+', ' ')).Trim()
}

function Convert-MsysPathToWindowsPath {
    param([AllowNull()][AllowEmptyString()][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return ''
    }

    if ($Path -match '^/([a-zA-Z])/(.*)$') {
        $drive = $Matches[1].ToUpperInvariant()
        $rest = $Matches[2] -replace '/', '\'
        return ("{0}:\\{1}" -f $drive, $rest)
    }

    return $Path
}

function ConvertTo-PathLikeValue {
    param([AllowEmptyString()][string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return ''
    }

    $normalized = $Value.Trim()
    if ($normalized.Length -ge 2) {
        if (($normalized.StartsWith('"') -and $normalized.EndsWith('"')) -or
            ($normalized.StartsWith("'") -and $normalized.EndsWith("'"))) {
            $normalized = $normalized.Substring(1, $normalized.Length - 2).Trim()
        }
    }

    return $normalized
}

function Resolve-RepoPath {
    param(
        [AllowEmptyString()][string]$Path,
        [bool]$MustExist = $true,
        [AllowEmptyString()][string]$RepoRoot = ''
    )

    $Path = ConvertTo-PathLikeValue -Value $Path
    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw 'Path must not be empty.'
    }

    $fullPath = if ([System.IO.Path]::IsPathRooted($Path)) {
        [System.IO.Path]::GetFullPath($Path)
    }
    else {
        if ([string]::IsNullOrWhiteSpace($RepoRoot)) {
            $RepoRoot = Get-UnattendedRepoRoot
        }
        [System.IO.Path]::GetFullPath((Join-Path $RepoRoot $Path))
    }

    if ($MustExist -and -not (Test-Path -LiteralPath $fullPath)) {
        throw ("Path not found: {0}" -f $fullPath)
    }

    return $fullPath
}

function Resolve-RepoPathAllowMissing {
    param(
        [AllowEmptyString()][string]$Path,
        [AllowEmptyString()][string]$RepoRoot = ''
    )

    $Path = ConvertTo-PathLikeValue -Value $Path
    if ([string]::IsNullOrWhiteSpace($Path)) {
        return ''
    }

    try {
        return Resolve-RepoPath -Path $Path -MustExist $false -RepoRoot $RepoRoot
    }
    catch {
        return ''
    }
}

function Convert-ToRepoRelativePath {
    param(
        [Alias('AbsolutePath')]
        [AllowEmptyString()][string]$Path,
        [AllowEmptyString()][string]$RepoRoot = ''
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return ''
    }

    try {
        $fullPath = [System.IO.Path]::GetFullPath($Path)
        if ([string]::IsNullOrWhiteSpace($RepoRoot)) {
            $RepoRoot = Get-UnattendedRepoRoot
        }
        $repoRootFull = [System.IO.Path]::GetFullPath($RepoRoot)
        if ($fullPath.StartsWith($repoRootFull, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $fullPath.Substring($repoRootFull.Length).TrimStart('\').Replace('\', '/')
        }

        return $fullPath.Replace('\', '/')
    }
    catch {
        return $Path.Replace('\', '/')
    }
}

function Resolve-TaskDefinitionRelativePath {
    param(
        [AllowEmptyString()][string]$InputName,
        [AllowEmptyString()][string]$SettingKey = ''
    )

    $effectiveKey = 'TaskDefinitionFileName'
    if (-not [string]::IsNullOrWhiteSpace($SettingKey)) {
        $effectiveKey = $SettingKey
    }

    if ([string]::IsNullOrWhiteSpace($InputName)) {
        if ([string]::IsNullOrWhiteSpace($SettingKey)) {
            throw "TaskDefinitionFileName is required."
        }
        throw ("{0} is missing in start file." -f $effectiveKey)
    }

    $normalized = $InputName.Trim().Replace('\', '/')
    if ($normalized.StartsWith('./')) {
        $normalized = $normalized.Substring(2)
    }

    if ($normalized -match '^(?:[A-Za-z]:|/|\\\\)') {
        throw ("{0} must be a repository-relative path under testdata/." -f $effectiveKey)
    }

    if (-not $normalized.StartsWith('testdata/')) {
        $normalized = 'testdata/' + $normalized
    }

    return $normalized
}

function Read-KeyValueFile {
    param(
        [AllowEmptyString()][string]$Path,
        [switch]$AllowMissing
    )

    $keyLineMap = @{}
    $map = [ordered]@{}
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) {
        if ($AllowMissing.IsPresent) {
            return $map
        }

        throw ("Path not found: {0}" -f $Path)
    }

    $lineNo = 0
    foreach ($line in @(Get-Content -LiteralPath $Path -Encoding utf8 -ErrorAction Stop)) {
        $lineNo++
        if ($line -match '^([^=]+)=(.*)$') {
            $key = $Matches[1].Trim()
            if ($map.Contains($key)) {
                $firstLine = [int]$keyLineMap[$key]
                throw ("Duplicate key '{0}' detected in {1} at line {2} and line {3}." -f $key, $Path, $firstLine, $lineNo)
            }

            $keyLineMap[$key] = $lineNo
            $map[$key] = $Matches[2]
        }
    }

    return $map
}

function Read-KeyValueFileWithRetry {
    param(
        [AllowEmptyString()][string]$Path,
        [ValidateRange(1, 20)][int]$MaxAttempts = 8
    )

    $lines = @()
    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            $lines = @(Get-Content -LiteralPath $Path -Encoding utf8 -ErrorAction Stop)
            break
        }
        catch {
            if ($attempt -eq $MaxAttempts) {
                throw
            }

            $delayMs = switch ($attempt) {
                1 { 50 }
                2 { 100 }
                3 { 200 }
                4 { 400 }
                default { 800 }
            }
            Start-Sleep -Milliseconds $delayMs
        }
    }

    $keyLineMap = @{}
    $map = [ordered]@{}
    $lineNo = 0
    foreach ($line in $lines) {
        $lineNo++
        if ($line -match '^([^=]+)=(.*)$') {
            $key = $Matches[1].Trim()
            if ($map.Contains($key)) {
                $firstLine = [int]$keyLineMap[$key]
                throw ("Duplicate key '{0}' detected in {1} at line {2} and line {3}." -f $key, $Path, $firstLine, $lineNo)
            }

            $keyLineMap[$key] = $lineNo
            $map[$key] = $Matches[2]
        }
    }

    return $map
}

function Read-KeyValueFileLastWins {
    param(
        [AllowEmptyString()][string]$Path,
        [switch]$AllowMissing
    )

    $map = [ordered]@{}
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) {
        if ($AllowMissing.IsPresent) {
            return $map
        }

        throw ("Path not found: {0}" -f $Path)
    }

    foreach ($line in @(Get-Content -LiteralPath $Path -Encoding utf8 -ErrorAction Stop)) {
        if ($line -match '^([^=]+)=(.*)$') {
            $map[$Matches[1].Trim()] = $Matches[2]
        }
    }

    return $map
}

function Get-StartFileMutexName {
    param([string]$StartFilePath)

    $fullPath = [System.IO.Path]::GetFullPath($StartFilePath).ToLowerInvariant()
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($fullPath)
    $sha1 = [System.Security.Cryptography.SHA1]::Create()
    try {
        $hashBytes = $sha1.ComputeHash($bytes)
    }
    finally {
        $sha1.Dispose()
    }

    $hash = [System.BitConverter]::ToString($hashBytes).Replace('-', '')
    return "Local\whois-unattended-startfile-write-$hash"
}

function Get-StartFileRoleMutexName {
    param(
        [string]$Role,
        [string]$StartFilePath
    )

    $fullPath = [System.IO.Path]::GetFullPath($StartFilePath).ToLowerInvariant()
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($fullPath)
    $sha1 = [System.Security.Cryptography.SHA1]::Create()
    try {
        $hashBytes = $sha1.ComputeHash($bytes)
    }
    finally {
        $sha1.Dispose()
    }

    $hash = [System.BitConverter]::ToString($hashBytes).Replace('-', '')
    return "Local\whois-unattended-{0}-{1}" -f $Role, $hash
}