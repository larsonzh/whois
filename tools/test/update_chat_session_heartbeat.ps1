param(
    [Parameter(Mandatory = $true)][string]$StartFile,
    [AllowEmptyString()][string]$HeartbeatPath = '',
    [AllowEmptyString()][string]$QueuePath = '',
    [AllowEmptyString()][string]$StatePath = '',
    [AllowEmptyString()][string]$Source = 'chat-session-keepalive',
    [switch]$AsJson
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Convert-ToSingleLineText {
    param([AllowEmptyString()][string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return ''
    }

    return ([regex]::Replace($Text.Trim(), '\s+', ' '))
}

function Get-Utf8BomEncoding {
    return [System.Text.UTF8Encoding]::new($true)
}

function Write-Utf8BomFileText {
    param(
        [string]$Path,
        [AllowEmptyString()][string]$Text
    )

    $parent = Split-Path -Parent $Path
    if (-not [string]::IsNullOrWhiteSpace($parent) -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }

    [System.IO.File]::WriteAllText($Path, [string]$Text, (Get-Utf8BomEncoding))
}

function Test-TextContainsNonAscii {
    param([AllowEmptyString()][string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return $false
    }

    return ($Text -match '[^\u0000-\u007F]')
}

function Test-FileHasUtf8Bom {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) {
        return $false
    }

    $bytes = [System.IO.File]::ReadAllBytes($Path)
    return ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF)
}

function Assert-Ps51Utf8BomCompatibility {
    param(
        [string]$ScriptPath,
        [string]$ScriptRole
    )

    if ([string]::IsNullOrWhiteSpace($ScriptPath) -or -not (Test-Path -LiteralPath $ScriptPath)) {
        return
    }

    try {
        $raw = Get-Content -LiteralPath $ScriptPath -Raw -Encoding utf8 -ErrorAction Stop
    }
    catch {
        return
    }

    if ((Test-TextContainsNonAscii -Text $raw) -and -not (Test-FileHasUtf8Bom -Path $ScriptPath)) {
        Write-Warning ("[CHAT-HEARTBEAT] ps51_utf8_bom_recommended role={0} path={1}" -f $ScriptRole, $ScriptPath)
    }
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
        [string]$Path,
        [bool]$MustExist = $true
    )

    $Path = ConvertTo-PathLikeValue -Value $Path
    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw 'Path must not be empty.'
    }

    $fullPath = ''
    if ([System.IO.Path]::IsPathRooted($Path)) {
        $fullPath = [System.IO.Path]::GetFullPath($Path)
    }
    else {
        $fullPath = [System.IO.Path]::GetFullPath((Join-Path $script:RepoRoot $Path))
    }

    if ($MustExist -and -not (Test-Path -LiteralPath $fullPath)) {
        throw "Path not found: $fullPath"
    }

    return $fullPath
}

function Resolve-RepoPathAllowMissing {
    param([string]$Path)

    return Resolve-RepoPath -Path $Path -MustExist $false
}

function Convert-ToRepoRelativePath {
    param([AllowEmptyString()][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return ''
    }

    $fullPath = Resolve-RepoPathAllowMissing -Path $Path
    if ($fullPath.StartsWith($script:RepoRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $fullPath.Substring($script:RepoRoot.Length).TrimStart('\\')
    }

    return $fullPath
}

function Read-KeyValueFile {
    param([string]$Path)

    $map = [ordered]@{}
    foreach ($line in @(Get-Content -LiteralPath $Path -Encoding utf8 -ErrorAction Stop)) {
        if ($line -match '^([^=]+)=(.*)$') {
            $map[$Matches[1].Trim()] = $Matches[2]
        }
    }

    return $map
}

function Convert-ToBooleanValue {
    param(
        [AllowNull()][object]$Value,
        [bool]$Default = $false
    )

    if ($null -eq $Value) {
        return $Default
    }

    if ($Value -is [bool]) {
        return [bool]$Value
    }

    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) {
        return $Default
    }

    return $text.Trim().ToLowerInvariant() -in @('1', 'true', 'yes', 'on')
}

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
    param([string]$StartFilePath)

    return [System.IO.Path]::GetFileNameWithoutExtension($StartFilePath)
}

function Resolve-PreferredDefaultPath {
    param(
        [string]$PreferredPath,
        [string]$LegacyPath
    )

    if (-not [string]::IsNullOrWhiteSpace($LegacyPath) -and -not (Test-Path -LiteralPath $PreferredPath) -and (Test-Path -LiteralPath $LegacyPath)) {
        return $LegacyPath
    }

    return $PreferredPath
}

function Write-JsonFileSafely {
    param(
        [string]$Path,
        $Value
    )

    $parent = Split-Path -Parent $Path
    if (-not [string]::IsNullOrWhiteSpace($parent) -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }

    $json = $Value | ConvertTo-Json -Depth 10
    Write-Utf8BomFileText -Path $Path -Text $json
}

function Get-NowText {
    return (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
}

$script:RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\\..')).Path
Assert-Ps51Utf8BomCompatibility -ScriptPath $MyInvocation.MyCommand.Path -ScriptRole 'update_chat_session_heartbeat.ps1'
$startFilePath = Resolve-RepoPath -Path $StartFile
$startFileRel = Convert-ToRepoRelativePath -Path $startFilePath
$settings = Read-KeyValueFile -Path $startFilePath
$startToken = Get-StableStartFileToken -StartFilePath $startFilePath
$legacyStartToken = Get-LegacyStartFileToken -StartFilePath $startFilePath

$heartbeatEnabled = $true
if ($settings.Contains('AI_CHAT_HEARTBEAT_ENABLED')) {
    $heartbeatEnabled = Convert-ToBooleanValue -Value ([string]$settings.AI_CHAT_HEARTBEAT_ENABLED) -Default $true
}

$heartbeatPathValue = ConvertTo-PathLikeValue -Value $HeartbeatPath
if ([string]::IsNullOrWhiteSpace($heartbeatPathValue) -and $settings.Contains('AI_CHAT_HEARTBEAT_PATH')) {
    $heartbeatPathValue = ConvertTo-PathLikeValue -Value ([string]$settings.AI_CHAT_HEARTBEAT_PATH)
}
if ([string]::IsNullOrWhiteSpace($heartbeatPathValue)) {
    $heartbeatPathValue = Resolve-PreferredDefaultPath -PreferredPath (Resolve-RepoPathAllowMissing -Path (Join-Path 'out\\artifacts\\ab_agent_queue' ("chat_session_heartbeat_{0}.json" -f $startToken))) -LegacyPath (Resolve-RepoPathAllowMissing -Path (Join-Path 'out\\artifacts\\ab_agent_queue' ("chat_session_heartbeat_{0}.json" -f $legacyStartToken)))
}
$heartbeatFilePath = Resolve-RepoPathAllowMissing -Path $heartbeatPathValue

$queuePathValue = ConvertTo-PathLikeValue -Value $QueuePath
if ([string]::IsNullOrWhiteSpace($queuePathValue) -and $settings.Contains('LOCAL_GUARD_AGENT_QUEUE_PATH')) {
    $queuePathValue = ConvertTo-PathLikeValue -Value ([string]$settings.LOCAL_GUARD_AGENT_QUEUE_PATH)
}
if ([string]::IsNullOrWhiteSpace($queuePathValue)) {
    $queuePathValue = 'out\\artifacts\\ab_agent_queue\\agent_tickets.jsonl'
}
$queueFilePath = Resolve-RepoPathAllowMissing -Path $queuePathValue

$statePathValue = ConvertTo-PathLikeValue -Value $StatePath
if ([string]::IsNullOrWhiteSpace($statePathValue)) {
    $statePathValue = Resolve-PreferredDefaultPath -PreferredPath (Resolve-RepoPathAllowMissing -Path (Join-Path 'out\\artifacts\\ab_agent_queue' ("ai_ticket_poll_state_{0}.json" -f $startToken))) -LegacyPath (Resolve-RepoPathAllowMissing -Path (Join-Path 'out\\artifacts\\ab_agent_queue' ("ai_ticket_poll_state_{0}.json" -f $legacyStartToken)))
}
$stateFilePath = Resolve-RepoPathAllowMissing -Path $statePathValue

if (-not $heartbeatEnabled) {
    $disabled = [ordered]@{
        schema = 'AB_CHAT_SESSION_HEARTBEAT_UPDATE_V1'
        updated_at = ''
        start_file = $startFileRel
        heartbeat_path = (Convert-ToRepoRelativePath -Path $heartbeatFilePath)
        write_ok = $false
        reason = 'disabled'
    }

    if ($AsJson.IsPresent) {
        $disabled | ConvertTo-Json -Depth 6
    }
    else {
        Write-Output ('[CHAT-HEARTBEAT] write_ok={0} reason={1} start_file={2} heartbeat_path={3}' -f [bool]$disabled.write_ok, [string]$disabled.reason, [string]$disabled.start_file, [string]$disabled.heartbeat_path)
    }

    return
}

$sourceText = Convert-ToSingleLineText -Text $Source
if ([string]::IsNullOrWhiteSpace($sourceText)) {
    $sourceText = 'chat-session-keepalive'
}

$nowText = Get-NowText
$payload = [ordered]@{
    schema = 'AB_CHAT_SESSION_HEARTBEAT_V1'
    updated_at = $nowText
    start_file = $startFileRel
    queue_path = (Convert-ToRepoRelativePath -Path $queueFilePath)
    state_path = (Convert-ToRepoRelativePath -Path $stateFilePath)
    source = $sourceText
    pid = [int]$PID
    host = [string]$env:COMPUTERNAME
    user = [string]$env:USERNAME
}

$writeOk = $true
$reason = 'ok'
try {
    Write-JsonFileSafely -Path $heartbeatFilePath -Value $payload
}
catch {
    $writeOk = $false
    $reason = Convert-ToSingleLineText -Text $_.Exception.Message
}

$result = [ordered]@{
    schema = 'AB_CHAT_SESSION_HEARTBEAT_UPDATE_V1'
    updated_at = $nowText
    start_file = $startFileRel
    heartbeat_path = (Convert-ToRepoRelativePath -Path $heartbeatFilePath)
    source = $sourceText
    write_ok = [bool]$writeOk
    reason = $reason
}

if ($AsJson.IsPresent) {
    $result | ConvertTo-Json -Depth 6
}
else {
    Write-Output ('[CHAT-HEARTBEAT] write_ok={0} reason={1} updated_at={2} source={3} start_file={4} heartbeat_path={5}' -f [bool]$result.write_ok, [string]$result.reason, [string]$result.updated_at, [string]$result.source, [string]$result.start_file, [string]$result.heartbeat_path)
}
