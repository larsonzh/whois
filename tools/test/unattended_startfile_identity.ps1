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

function Convert-ToBoundedSingleLineText {
    param(
        [AllowEmptyString()][string]$Text,
        [ValidateRange(32, 4000)][int]$MaxChars = 800
    )

    $singleLine = Convert-ToSingleLineText -Text $Text
    if ([string]::IsNullOrWhiteSpace($singleLine)) {
        return ''
    }

    if ($singleLine.Length -le $MaxChars) {
        return $singleLine
    }

    return ($singleLine.Substring(0, $MaxChars).TrimEnd() + '...')
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

function Resolve-RemoteKeyPath {
    param(
        [Alias('InputPath', 'KeyPath')]
        [AllowEmptyString()][string]$Path,
        [switch]$UseDefaultSshKeyFallback,
        [string]$Purpose = 'SSH private key path'
    )

    if (-not [string]::IsNullOrWhiteSpace($Path) -and (Test-Path -LiteralPath $Path)) {
        return (Resolve-Path -LiteralPath $Path).Path
    }

    $converted = Convert-MsysPathToWindowsPath -Path $Path
    if (-not [string]::IsNullOrWhiteSpace($converted) -and (Test-Path -LiteralPath $converted)) {
        return (Resolve-Path -LiteralPath $converted).Path
    }

    if ($UseDefaultSshKeyFallback.IsPresent) {
        $fallback = Join-Path ([Environment]::GetFolderPath('UserProfile')) '.ssh\id_rsa'
        if (Test-Path -LiteralPath $fallback) {
            return (Resolve-Path -LiteralPath $fallback).Path
        }
    }

    throw ("Unable to resolve {0}. input={1}" -f $Purpose, $Path)
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

function Get-NormalizedPathIdentity {
    param(
        [AllowEmptyString()][string]$Path,
        [string]$RepoRoot
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return ''
    }

    try {
        $resolved = if ([System.IO.Path]::IsPathRooted($Path)) {
            [System.IO.Path]::GetFullPath($Path)
        }
        else {
            [System.IO.Path]::GetFullPath((Join-Path $RepoRoot $Path))
        }

        return $resolved.ToLowerInvariant()
    }
    catch {
        return ''
    }
}

function Get-StartFilePathFromCommandLine {
    param(
        [AllowEmptyString()][string]$CommandLine,
        [string]$RepoRoot
    )

    if ([string]::IsNullOrWhiteSpace($CommandLine)) {
        return ''
    }

    $match = [regex]::Match($CommandLine, '(?i)(?:^|\s)-StartFile\s+("([^"]+)"|''([^'']+)''|([^\s]+))')
    if (-not $match.Success) {
        return ''
    }

    $rawPath = if ($match.Groups[2].Success) {
        $match.Groups[2].Value
    }
    elseif ($match.Groups[3].Success) {
        $match.Groups[3].Value
    }
    else {
        $match.Groups[4].Value
    }

    return Get-NormalizedPathIdentity -Path $rawPath -RepoRoot $RepoRoot
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

function Get-RemoteLockField {
    param(
        [string[]]$Lines,
        [string]$Key
    )

    $escapedKey = [regex]::Escape($Key)
    foreach ($record in @($Lines)) {
        if ($null -eq $record) {
            continue
        }

        foreach ($rawLine in @(([string]$record) -split "`r?`n")) {
            if ([string]::IsNullOrWhiteSpace($rawLine)) {
                continue
            }

            $line = $rawLine.Trim().TrimStart([char]0xFEFF)
            if ($line -match ('^\[CHECK-REMOTE-LOCK\]\s+' + $escapedKey + '=(.*)$')) {
                return $Matches[1].Trim()
            }

            if ($line -match ('(?:^|\s)' + $escapedKey + '=(.*)$')) {
                return $Matches[1].Trim()
            }
        }
    }

    return ''
}

function Save-RemoteLockScene {
    param(
        [string]$RepoRoot,
        [string]$RoleTag,
        [string]$StageTag,
        [string]$RemoteIp,
        [string]$RemoteUser,
        [string]$KeyPath,
        [string]$LockScope,
        [string]$ConflictAction,
        [string[]]$ObservedCheckLines,
        [switch]$IncludeRuntimeLogPath
    )

    try {
        $sceneRoot = Join-Path $RepoRoot 'out\artifacts\ab_remote_lock_scene'
        if (-not (Test-Path -LiteralPath $sceneRoot)) {
            New-Item -ItemType Directory -Path $sceneRoot -Force | Out-Null
        }

        $stageLower = if ([string]::IsNullOrWhiteSpace($StageTag)) { 'x' } else { $StageTag.Trim().ToLowerInvariant() }
        $timestamp = (Get-Date).ToString('yyyyMMdd-HHmmss-fff')
        $sceneDir = Join-Path $sceneRoot ("{0}_{1}_pid{2}" -f $timestamp, $stageLower, $PID)
        New-Item -ItemType Directory -Path $sceneDir -Force | Out-Null

        $observedPath = Join-Path $sceneDir 'remote_lock_check_observed.txt'
        @($ObservedCheckLines | ForEach-Object { [string]$_ }) | Out-File -FilePath $observedPath -Encoding utf8

        $checkScript = Join-Path $RepoRoot 'tools\dev\check_remote_lock.ps1'
        $checkNowPath = Join-Path $sceneDir 'remote_lock_check_now.txt'
        if (Test-Path -LiteralPath $checkScript) {
            try {
                $checkNowLines = @((& $checkScript -RemoteIp $RemoteIp -RemoteUser $RemoteUser -KeyPath $KeyPath -TimeoutSec 20 2>&1) | ForEach-Object { [string]$_ })
                @($checkNowLines) | Out-File -FilePath $checkNowPath -Encoding utf8
            }
            catch {
                (Convert-ToSingleLineText -Text $_.Exception.Message) | Out-File -FilePath $checkNowPath -Encoding utf8
            }
        }

        $clearScript = Join-Path $RepoRoot 'tools\dev\clear_remote_lock.ps1'
        $clearDryRunPath = Join-Path $sceneDir 'remote_lock_dryrun.txt'
        if (Test-Path -LiteralPath $clearScript) {
            try {
                $clearLines = @((& $clearScript -RemoteIp $RemoteIp -RemoteUser $RemoteUser -KeyPath $KeyPath -TimeoutSec 20 -DryRun 2>&1) | ForEach-Object { [string]$_ })
                @($clearLines) | Out-File -FilePath $clearDryRunPath -Encoding utf8
            }
            catch {
                (Convert-ToSingleLineText -Text $_.Exception.Message) | Out-File -FilePath $clearDryRunPath -Encoding utf8
            }
        }

        $startFilePath = ''
        if (-not [string]::IsNullOrWhiteSpace([string]$env:AUTO_START_FILE_PATH)) {
            try {
                $startFilePath = [System.IO.Path]::GetFullPath([string]$env:AUTO_START_FILE_PATH)
            }
            catch {
                $startFilePath = [string]$env:AUTO_START_FILE_PATH
            }
        }

        $metadata = [ordered]@{
            schema = 'AB_REMOTE_LOCK_SCENE_V1'
            generated_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
            role_tag = $RoleTag
            stage = if ([string]::IsNullOrWhiteSpace($StageTag)) { '' } else { $StageTag.Trim().ToUpperInvariant() }
            process_id = [int]$PID
            remote_ip = $RemoteIp
            remote_user = $RemoteUser
            key_path = $KeyPath
            lock_scope = $LockScope
            conflict_action = $ConflictAction
            observed_state = (Get-RemoteLockField -Lines $ObservedCheckLines -Key 'state')
            observed_stale = (Get-RemoteLockField -Lines $ObservedCheckLines -Key 'stale')
            observed_age_sec = (Get-RemoteLockField -Lines $ObservedCheckLines -Key 'age_sec')
            observed_token = (Get-RemoteLockField -Lines $ObservedCheckLines -Key 'token')
            start_file_path = $startFilePath
            observed_file = 'remote_lock_check_observed.txt'
            check_now_file = if (Test-Path -LiteralPath $checkNowPath) { 'remote_lock_check_now.txt' } else { '' }
            dryrun_file = if (Test-Path -LiteralPath $clearDryRunPath) { 'remote_lock_dryrun.txt' } else { '' }
        }

        if ($IncludeRuntimeLogPath.IsPresent) {
            $runtimeLogPath = ''
            if (-not [string]::IsNullOrWhiteSpace([string]$env:AUTO_STAGE_RUNTIME_LOG_PATH)) {
                try {
                    $runtimeLogPath = [System.IO.Path]::GetFullPath([string]$env:AUTO_STAGE_RUNTIME_LOG_PATH)
                }
                catch {
                    $runtimeLogPath = [string]$env:AUTO_STAGE_RUNTIME_LOG_PATH
                }
            }
            $metadata['runtime_log_path'] = $runtimeLogPath
        }

        ($metadata | ConvertTo-Json -Depth 8) | Out-File -FilePath (Join-Path $sceneDir 'metadata.json') -Encoding utf8

        return [pscustomobject]@{
            SceneDir = $sceneDir
            ErrorDetail = ''
        }
    }
    catch {
        return [pscustomobject]@{
            SceneDir = ''
            ErrorDetail = (Convert-ToSingleLineText -Text $_.Exception.Message)
        }
    }
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