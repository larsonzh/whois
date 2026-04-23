param(
    [ValidateSet('A', 'B')][string]$Stage,
    [string]$StartFile = 'tmp\unattended_ab_start_20260418-2200.md',
    [switch]$StartMonitors,
    [switch]$SkipMonitorRestart,
    [switch]$EnableBMonitorRestart
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Resolve-RepoPath {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw 'Path must not be empty.'
    }

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return (Resolve-Path -LiteralPath $Path).Path
    }

    return (Resolve-Path -LiteralPath (Join-Path $repoRoot $Path)).Path
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

function Set-KeyValueFileValues {
    param(
        [string]$Path,
        [hashtable]$Values
    )

    $lines = @()
    if (Test-Path -LiteralPath $Path) {
        $lines = @(Get-Content -LiteralPath $Path -Encoding utf8 -ErrorAction Stop)
    }

    $buffer = New-Object 'System.Collections.Generic.List[string]'
    foreach ($line in $lines) {
        [void]$buffer.Add([string]$line)
    }

    foreach ($key in $Values.Keys) {
        $prefix = "$key="
        $found = $false
        for ($index = 0; $index -lt $buffer.Count; $index++) {
            if ($buffer[$index].StartsWith($prefix, [System.StringComparison]::Ordinal)) {
                $buffer[$index] = $prefix + [string]$Values[$key]
                $found = $true
                break
            }
        }

        if (-not $found) {
            [void]$buffer.Add($prefix + [string]$Values[$key])
        }
    }

    Set-Content -LiteralPath $Path -Value @($buffer) -Encoding utf8
}

function Get-LatestAnchorValueFromNotes {
    param(
        [AllowEmptyString()][string]$Notes,
        [string]$Key
    )

    if ([string]::IsNullOrWhiteSpace($Notes) -or [string]::IsNullOrWhiteSpace($Key)) {
        return ''
    }

    $parts = @($Notes -split ';')
    for ($index = $parts.Count - 1; $index -ge 0; $index--) {
        $segment = [string]$parts[$index]
        if ([string]::IsNullOrWhiteSpace($segment)) {
            continue
        }

        if ($segment -match ('^\s*' + [regex]::Escape($Key) + '=(.+)$')) {
            return $Matches[1].Trim()
        }
    }

    return ''
}

function Convert-ToAnchorPath {
    param([AllowEmptyString()][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return ''
    }

    $normalized = $Path.Trim().Replace('/', '\\')
    if (-not [System.IO.Path]::IsPathRooted($normalized)) {
        return $normalized
    }

    $fullPath = [System.IO.Path]::GetFullPath($normalized)
    $repoRootFull = [System.IO.Path]::GetFullPath($repoRoot)
    if ($fullPath.StartsWith($repoRootFull, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $fullPath.Substring($repoRootFull.Length).TrimStart('\\')
    }

    return $fullPath
}

function Update-SessionAnchorsInStartFile {
    param(
        [string]$Path,
        [System.Collections.IDictionary]$Anchors
    )

    $settingsMap = Read-KeyValueFile -Path $Path
    $existingNotes = if ($settingsMap.Contains('SESSION_FINAL_NOTES')) { [string]$settingsMap.SESSION_FINAL_NOTES } else { '' }
    $segments = New-Object 'System.Collections.Generic.List[string]'

    foreach ($part in @($existingNotes -split ';')) {
        $segment = [string]$part
        if ([string]::IsNullOrWhiteSpace($segment)) {
            continue
        }

        $trimmed = $segment.Trim()
        if ($trimmed -match '^(run_dir|supervisor_log|companion_log|live_status)=') {
            continue
        }

        [void]$segments.Add($trimmed)
    }

    foreach ($anchorKey in @('run_dir', 'supervisor_log', 'companion_log', 'live_status')) {
        if (-not $Anchors.ContainsKey($anchorKey)) {
            continue
        }

        $value = [string]$Anchors[$anchorKey]
        if ([string]::IsNullOrWhiteSpace($value)) {
            continue
        }

        [void]$segments.Add("$anchorKey=$value")
    }

    $newNotes = ($segments -join '; ')
    Set-KeyValueFileValues -Path $Path -Values @{ SESSION_FINAL_NOTES = $newNotes }
    return $newNotes
}

function Resolve-CurrentStageRunDir {
    param(
        [datetime]$LaunchTime,
        [System.Collections.IDictionary]$Settings,
        [string]$SessionOutDirRoot
    )

    $currentRunDir = ''
    for ($attempt = 0; $attempt -lt 24; $attempt++) {
        $candidate = Get-LatestTimestampedDirectory -Root $SessionOutDirRoot -After $LaunchTime
        if ($null -ne $candidate) {
            $currentRunDir = $candidate.FullName
            break
        }

        Start-Sleep -Seconds 5
    }

    if (-not [string]::IsNullOrWhiteSpace($currentRunDir)) {
        return $currentRunDir
    }

    if ($null -ne $Settings -and $Settings.Contains('SESSION_FINAL_NOTES')) {
        $hintRunDir = Get-LatestAnchorValueFromNotes -Notes ([string]$Settings.SESSION_FINAL_NOTES) -Key 'run_dir'
        if (-not [string]::IsNullOrWhiteSpace($hintRunDir)) {
            try {
                return (Resolve-RepoPath -Path $hintRunDir)
            }
            catch {
                return ''
            }
        }
    }

    return ''
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

function Convert-MsysPathToWindowsPath {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return ''
    }

    if ($Path -match '^/([a-zA-Z])/(.*)$') {
        $drive = $Matches[1].ToUpperInvariant()
        $rest = $Matches[2] -replace '/', '\\'
        return ("{0}:\\{1}" -f $drive, $rest)
    }

    return $Path
}

function Resolve-RemoteKeyPathForNetworkPrecheck {
    param([string]$InputPath)

    if (-not [string]::IsNullOrWhiteSpace($InputPath) -and (Test-Path -LiteralPath $InputPath)) {
        return (Resolve-Path -LiteralPath $InputPath).Path
    }

    $converted = Convert-MsysPathToWindowsPath -Path $InputPath
    if (-not [string]::IsNullOrWhiteSpace($converted) -and (Test-Path -LiteralPath $converted)) {
        return (Resolve-Path -LiteralPath $converted).Path
    }

    throw "Unable to resolve SSH private key for network precheck. input=$InputPath"
}

function Assert-PrecheckGateReady {
    param(
        [System.Collections.IDictionary]$Settings,
        [string]$StartFilePath,
        [string]$ScriptTag
    )

    if ($null -eq $Settings) {
        throw "[$ScriptTag] start file settings map is null"
    }

    $precheckRequired = if ($Settings.Contains('PRECHECK_REQUIRED')) {
        Convert-ToBooleanSetting -Value ([string]$Settings.PRECHECK_REQUIRED) -Default $true
    }
    else {
        $true
    }

    if (-not $precheckRequired) {
        Write-Output ("[{0}] precheck_gate required=false action=skip" -f $ScriptTag)
        return
    }

    $statusRaw = if ($Settings.Contains('PRECHECK_STATUS')) { [string]$Settings.PRECHECK_STATUS } else { '' }
    $startGateRaw = if ($Settings.Contains('PRECHECK_START_GATE')) { [string]$Settings.PRECHECK_START_GATE } else { '' }
    $remoteLockRaw = if ($Settings.Contains('PRECHECK_REMOTE_LOCK')) { [string]$Settings.PRECHECK_REMOTE_LOCK } else { '' }

    $status = $statusRaw.Trim().ToUpperInvariant()
    $startGate = $startGateRaw.Trim().ToUpperInvariant()
    $remoteLock = $remoteLockRaw.Trim().ToUpperInvariant()
    $allowedRemoteLockStates = @('ABSENT', 'HELD-BY-SELF')

    $reasons = New-Object 'System.Collections.Generic.List[string]'
    if ($status -ne 'PASS') {
        [void]$reasons.Add(("PRECHECK_STATUS={0}" -f $statusRaw))
    }
    if ($startGate -ne 'READY') {
        [void]$reasons.Add(("PRECHECK_START_GATE={0}" -f $startGateRaw))
    }
    if (-not ($allowedRemoteLockStates -contains $remoteLock)) {
        [void]$reasons.Add(("PRECHECK_REMOTE_LOCK={0}" -f $remoteLockRaw))
    }

    if ($reasons.Count -gt 0) {
        $reasonText = ($reasons -join '; ')
        Set-KeyValueFileValues -Path $StartFilePath -Values @{
            PRECHECK_START_GATE = 'BLOCKED'
            PRECHECK_START_BLOCKER = $reasonText
            PRECHECK_FAILURE_REASON = $reasonText
        }
        throw ("[{0}] precheck gate blocked: {1}" -f $ScriptTag, $reasonText)
    }

    Write-Output ("[{0}] precheck_gate status=PASS gate=READY remote_lock={1}" -f $ScriptTag, $remoteLockRaw)
}

function Assert-NetworkPrecheckReady {
    param(
        [System.Collections.IDictionary]$Settings,
        [string]$StartFilePath,
        [string]$ScriptTag,
        [string]$RepoRoot
    )

    if ($null -eq $Settings) {
        throw "[$ScriptTag] start file settings map is null for network precheck"
    }

    $networkPrecheckRequired = if ($Settings.Contains('NETWORK_PRECHECK_REQUIRED')) {
        Convert-ToBooleanSetting -Value ([string]$Settings.NETWORK_PRECHECK_REQUIRED) -Default $true
    }
    else {
        $true
    }

    if (-not $networkPrecheckRequired) {
        Write-Output ("[{0}] network_precheck required=false action=skip" -f $ScriptTag)
        return
    }

    $checkLocal = if ($Settings.Contains('NETWORK_PRECHECK_LOCAL_REQUIRED')) {
        Convert-ToBooleanSetting -Value ([string]$Settings.NETWORK_PRECHECK_LOCAL_REQUIRED) -Default $true
    }
    else {
        $true
    }

    $checkRemote = if ($Settings.Contains('NETWORK_PRECHECK_REMOTE_REQUIRED')) {
        Convert-ToBooleanSetting -Value ([string]$Settings.NETWORK_PRECHECK_REMOTE_REQUIRED) -Default $true
    }
    else {
        $true
    }

    $checkIPv4 = if ($Settings.Contains('NETWORK_PRECHECK_CHECK_IPV4')) {
        Convert-ToBooleanSetting -Value ([string]$Settings.NETWORK_PRECHECK_CHECK_IPV4) -Default $true
    }
    else {
        $true
    }

    $checkIPv6 = if ($Settings.Contains('NETWORK_PRECHECK_CHECK_IPV6')) {
        Convert-ToBooleanSetting -Value ([string]$Settings.NETWORK_PRECHECK_CHECK_IPV6) -Default $true
    }
    else {
        $true
    }

    $requireIPv4 = if ($Settings.Contains('NETWORK_PRECHECK_REQUIRE_IPV4')) {
        Convert-ToBooleanSetting -Value ([string]$Settings.NETWORK_PRECHECK_REQUIRE_IPV4) -Default $false
    }
    else {
        $false
    }

    $requireIPv6 = if ($Settings.Contains('NETWORK_PRECHECK_REQUIRE_IPV6')) {
        Convert-ToBooleanSetting -Value ([string]$Settings.NETWORK_PRECHECK_REQUIRE_IPV6) -Default $true
    }
    else {
        $true
    }

    if (-not $checkLocal -and -not $checkRemote) {
        throw "[$ScriptTag] network precheck misconfigured: both local and remote checks are disabled"
    }

    if (-not $checkIPv4 -and -not $checkIPv6) {
        throw "[$ScriptTag] network precheck misconfigured: both IPv4 and IPv6 checks are disabled"
    }

    if ($requireIPv4 -and -not $checkIPv4) {
        $checkIPv4 = $true
    }
    if ($requireIPv6 -and -not $checkIPv6) {
        $checkIPv6 = $true
    }

    $targets = if ($Settings.Contains('NETWORK_PRECHECK_TARGETS') -and -not [string]::IsNullOrWhiteSpace([string]$Settings.NETWORK_PRECHECK_TARGETS)) {
        [string]$Settings.NETWORK_PRECHECK_TARGETS
    }
    else {
        'whois.iana.org;whois.arin.net'
    }

    $timeoutSec = 8
    if ($Settings.Contains('NETWORK_PRECHECK_TIMEOUT_SEC')) {
        $parsedTimeout = 0
        if ([int]::TryParse(([string]$Settings.NETWORK_PRECHECK_TIMEOUT_SEC), [ref]$parsedTimeout)) {
            if ($parsedTimeout -ge 1 -and $parsedTimeout -le 30) {
                $timeoutSec = $parsedTimeout
            }
        }
    }

    $remoteIp = if ($Settings.Contains('REMOTE_IP') -and -not [string]::IsNullOrWhiteSpace([string]$Settings.REMOTE_IP)) {
        [string]$Settings.REMOTE_IP
    }
    else {
        '10.0.0.199'
    }

    $remoteUser = if ($Settings.Contains('REMOTE_USER') -and -not [string]::IsNullOrWhiteSpace([string]$Settings.REMOTE_USER)) {
        [string]$Settings.REMOTE_USER
    }
    else {
        'larson'
    }

    $remoteKeyRaw = if ($Settings.Contains('REMOTE_KEYPATH') -and -not [string]::IsNullOrWhiteSpace([string]$Settings.REMOTE_KEYPATH)) {
        [string]$Settings.REMOTE_KEYPATH
    }
    else {
        "/c/Users/$env:USERNAME/.ssh/id_rsa"
    }

    $precheckScript = Join-Path $RepoRoot 'tools\dev\check_dualstack_whois_connectivity.ps1'
    if (-not (Test-Path -LiteralPath $precheckScript)) {
        throw "[$ScriptTag] network precheck script not found: $precheckScript"
    }

    $resolvedKeyPath = ''
    if ($checkRemote) {
        $resolvedKeyPath = Resolve-RemoteKeyPathForNetworkPrecheck -InputPath $remoteKeyRaw
    }

    $outputLines = @()
    $exitCode = 1
    try {
        $outputLines = @((& $precheckScript `
            -Targets $targets `
            -TimeoutSec $timeoutSec `
            -CheckLocal:$checkLocal `
            -CheckRemote:$checkRemote `
            -CheckIPv4:$checkIPv4 `
            -CheckIPv6:$checkIPv6 `
            -RequireIPv4:$requireIPv4 `
            -RequireIPv6:$requireIPv6 `
            -RemoteIp $remoteIp `
            -RemoteUser $remoteUser `
            -KeyPath $resolvedKeyPath 2>&1) | ForEach-Object { [string]$_ })
        $exitCode = if ($null -eq $LASTEXITCODE) { 0 } else { [int]$LASTEXITCODE }
    }
    catch {
        $exitCode = 1
        $outputLines = @($_.Exception.Message)
    }

    foreach ($line in @($outputLines)) {
        if (-not [string]::IsNullOrWhiteSpace($line)) {
            Write-Output $line
        }
    }

    $nowText = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    if ($exitCode -ne 0) {
        $reason = "NETWORK_PRECHECK_FAIL exit=$exitCode targets=$targets local=$checkLocal remote=$checkRemote check_ipv4=$checkIPv4 check_ipv6=$checkIPv6 require_ipv4=$requireIPv4 require_ipv6=$requireIPv6"
        Set-KeyValueFileValues -Path $StartFilePath -Values @{
            PRECHECK_START_GATE = 'BLOCKED'
            PRECHECK_START_BLOCKER = $reason
            PRECHECK_FAILURE_REASON = $reason
            NETWORK_PRECHECK_LAST_RESULT = 'FAIL'
            NETWORK_PRECHECK_LAST_AT = $nowText
            NETWORK_PRECHECK_LAST_REASON = $reason
        }
        throw ("[{0}] network precheck blocked: {1}" -f $ScriptTag, $reason)
    }

    Set-KeyValueFileValues -Path $StartFilePath -Values @{
        NETWORK_PRECHECK_LAST_RESULT = 'PASS'
        NETWORK_PRECHECK_LAST_AT = $nowText
        NETWORK_PRECHECK_LAST_REASON = ''
    }
    Write-Output ("[{0}] network_precheck status=PASS targets={1} local={2} remote={3} check_ipv4={4} check_ipv6={5} require_ipv4={6} require_ipv6={7}" -f $ScriptTag, $targets, $checkLocal, $checkRemote, $checkIPv4, $checkIPv6, $requireIPv4, $requireIPv6)
}

function Set-EnvFromSetting {
    param(
        [string]$EnvName,
        [System.Collections.IDictionary]$Settings,
        [string]$Key
    )

    if ($null -eq $Settings -or -not $Settings.Contains($Key)) {
        return
    }

    $value = [string]$Settings[$Key]
    if ([string]::IsNullOrWhiteSpace($value)) {
        return
    }

    Set-Item -Path ("Env:{0}" -f $EnvName) -Value $value
}

function Get-LatestTimestampedDirectory {
    param(
        [string]$Root,
        [Nullable[datetime]]$After = $null
    )

    if (-not (Test-Path -LiteralPath $Root)) {
        return $null
    }

    $dirs = Get-ChildItem -LiteralPath $Root -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^[0-9]{8}-[0-9]{6}$' }

    if ($null -ne $After) {
        $dirs = @($dirs | Where-Object { $_.CreationTime -ge $After.AddSeconds(-2) -or $_.LastWriteTime -ge $After.AddSeconds(-2) })
    }

    $candidates = @($dirs | Sort-Object CreationTime, LastWriteTime -Descending | Select-Object -First 1)
    if ($candidates.Count -lt 1) {
        return $null
    }

    return $candidates[0]
}

function Stop-MonitorProcessesForStartFile {
    param([string]$StartFilePath)

    $startFileLeaf = [System.IO.Path]::GetFileName($StartFilePath).ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($startFileLeaf)) {
        return @()
    }

    $targetPids = @(
        Get-CimInstance Win32_Process |
            Where-Object {
                $commandLine = [string]$_.CommandLine
                if ([string]::IsNullOrWhiteSpace($commandLine)) {
                    return $false
                }

                $line = $commandLine.ToLowerInvariant()
                ($line -match 'unattended_ab_supervisor\.ps1|unattended_ab_companion\.ps1') -and $line.Contains($startFileLeaf)
            } |
            Select-Object -ExpandProperty ProcessId -Unique
    )

    foreach ($targetPid in $targetPids) {
        Stop-Process -Id ([int]$targetPid) -Force -ErrorAction SilentlyContinue
    }

    return @($targetPids)
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$startFilePath = Resolve-RepoPath -Path $StartFile
$settings = Read-KeyValueFile -Path $startFilePath
Assert-PrecheckGateReady -Settings $settings -StartFilePath $startFilePath -ScriptTag 'OPEN-AB-STAGE'
Assert-NetworkPrecheckReady -Settings $settings -StartFilePath $startFilePath -ScriptTag 'OPEN-AB-STAGE' -RepoRoot $repoRoot
$settings = Read-KeyValueFile -Path $startFilePath

$entryScriptKey = if ($Stage -eq 'A') { 'ENTRY_SCRIPT_A' } else { 'ENTRY_SCRIPT_B' }
$taskKey = if ($Stage -eq 'A') { 'A_TASK_DEFINITION' } else { 'B_TASK_DEFINITION' }

$entryScriptPath = Resolve-RepoPath -Path ([string]$settings[$entryScriptKey])
$taskLeaf = [System.IO.Path]::GetFileName([string]$settings[$taskKey])

$powershellPath = Join-Path $PSHOME 'powershell.exe'
if (-not (Test-Path -LiteralPath $powershellPath)) {
    $powershellPath = 'powershell.exe'
}

Set-EnvFromSetting -EnvName 'AUTO_REMOTE_IP' -Settings $settings -Key 'REMOTE_IP'
Set-EnvFromSetting -EnvName 'AUTO_REMOTE_USER' -Settings $settings -Key 'REMOTE_USER'
Set-EnvFromSetting -EnvName 'AUTO_REMOTE_KEYPATH' -Settings $settings -Key 'REMOTE_KEYPATH'
Set-EnvFromSetting -EnvName 'AUTO_QUERIES' -Settings $settings -Key 'QUERIES'
Set-EnvFromSetting -EnvName 'AUTO_TERMINAL_WATCHDOG_MODE' -Settings $settings -Key 'TERMINAL_WATCHDOG_MODE'
Set-EnvFromSetting -EnvName 'AUTO_TERMINAL_WATCHDOG_INTERVAL_SEC' -Settings $settings -Key 'TERMINAL_WATCHDOG_INTERVAL_SEC'
Set-EnvFromSetting -EnvName 'AUTO_TERMINAL_WATCHDOG_MIN_AGE_SEC' -Settings $settings -Key 'TERMINAL_WATCHDOG_MIN_AGE_SEC'
Set-EnvFromSetting -EnvName 'AUTO_REMOTE_BUILD_LOCK_REQUIRED' -Settings $settings -Key 'REMOTE_BUILD_LOCK_REQUIRED'
Set-EnvFromSetting -EnvName 'AUTO_REMOTE_BUILD_LOCK_SCOPE' -Settings $settings -Key 'REMOTE_BUILD_LOCK_SCOPE'
Set-EnvFromSetting -EnvName 'AUTO_REMOTE_BUILD_LOCK_CONFLICT_ACTION' -Settings $settings -Key 'REMOTE_BUILD_LOCK_CONFLICT_ACTION'
Set-EnvFromSetting -EnvName 'AUTO_NETWORK_PRECHECK_REQUIRED' -Settings $settings -Key 'NETWORK_PRECHECK_REQUIRED'
Set-EnvFromSetting -EnvName 'AUTO_NETWORK_PRECHECK_LOCAL_REQUIRED' -Settings $settings -Key 'NETWORK_PRECHECK_LOCAL_REQUIRED'
Set-EnvFromSetting -EnvName 'AUTO_NETWORK_PRECHECK_REMOTE_REQUIRED' -Settings $settings -Key 'NETWORK_PRECHECK_REMOTE_REQUIRED'
Set-EnvFromSetting -EnvName 'AUTO_NETWORK_PRECHECK_CHECK_IPV4' -Settings $settings -Key 'NETWORK_PRECHECK_CHECK_IPV4'
Set-EnvFromSetting -EnvName 'AUTO_NETWORK_PRECHECK_CHECK_IPV6' -Settings $settings -Key 'NETWORK_PRECHECK_CHECK_IPV6'
Set-EnvFromSetting -EnvName 'AUTO_NETWORK_PRECHECK_REQUIRE_IPV4' -Settings $settings -Key 'NETWORK_PRECHECK_REQUIRE_IPV4'
Set-EnvFromSetting -EnvName 'AUTO_NETWORK_PRECHECK_REQUIRE_IPV6' -Settings $settings -Key 'NETWORK_PRECHECK_REQUIRE_IPV6'
Set-EnvFromSetting -EnvName 'AUTO_NETWORK_PRECHECK_TARGETS' -Settings $settings -Key 'NETWORK_PRECHECK_TARGETS'
Set-EnvFromSetting -EnvName 'AUTO_NETWORK_PRECHECK_TIMEOUT_SEC' -Settings $settings -Key 'NETWORK_PRECHECK_TIMEOUT_SEC'
Set-EnvFromSetting -EnvName 'AUTO_ROUND_RUNTIME_GATE_ENABLED' -Settings $settings -Key 'ROUND_RUNTIME_GATE_ENABLED'
Set-EnvFromSetting -EnvName 'AUTO_ROUND_RUNTIME_GATE_START_ROUND' -Settings $settings -Key 'ROUND_RUNTIME_GATE_START_ROUND'
Set-EnvFromSetting -EnvName 'AUTO_ROUND_RUNTIME_GATE_MAX_ATTEMPTS' -Settings $settings -Key 'ROUND_RUNTIME_GATE_MAX_ATTEMPTS'
Set-EnvFromSetting -EnvName 'AUTO_ROUND_RUNTIME_GATE_RETRY_DELAY_SEC' -Settings $settings -Key 'ROUND_RUNTIME_GATE_RETRY_DELAY_SEC'
Set-EnvFromSetting -EnvName 'AUTO_ROUND_RUNTIME_GATE_MIN_FREE_DISK_MB' -Settings $settings -Key 'ROUND_RUNTIME_GATE_MIN_FREE_DISK_MB'
Set-EnvFromSetting -EnvName 'AUTO_ROUND_RUNTIME_GATE_CHECK_REMOTE_LOCK' -Settings $settings -Key 'ROUND_RUNTIME_GATE_CHECK_REMOTE_LOCK'
Set-EnvFromSetting -EnvName 'AUTO_ROUND_RUNTIME_GATE_CHECK_NETWORK' -Settings $settings -Key 'ROUND_RUNTIME_GATE_CHECK_NETWORK'
Set-EnvFromSetting -EnvName 'AUTO_ROUND_RUNTIME_GATE_CHECK_PROCESS_CONFLICT' -Settings $settings -Key 'ROUND_RUNTIME_GATE_CHECK_PROCESS_CONFLICT'
Set-EnvFromSetting -EnvName 'AUTO_TASK_STATIC_PRECHECK_POLICY' -Settings $settings -Key 'TASK_STATIC_PRECHECK_POLICY'

$stageLaunchTime = Get-Date
$processInfo = Start-Process -FilePath $powershellPath -WorkingDirectory $repoRoot -ArgumentList @(
    '-NoExit',
    '-NoProfile',
    '-ExecutionPolicy', 'Bypass',
    '-File', $entryScriptPath,
    $taskLeaf
) -PassThru

Write-Output ("[OPEN-AB-STAGE] stage={0} pid={1} launcher_pid={2} entry={3} task={4}" -f $Stage, $processInfo.Id, $PID, $entryScriptPath, $taskLeaf)

$statusUpdates = @{
    SESSION_FINAL_STATUS = 'RUNNING'
}
if ($Stage -eq 'A') {
    $statusUpdates['A_FINAL_STATUS'] = 'RUNNING'
}
else {
    $statusUpdates['B_FINAL_STATUS'] = 'RUNNING'
}
Set-KeyValueFileValues -Path $startFilePath -Values $statusUpdates
$settings = Read-KeyValueFile -Path $startFilePath
Write-Output ("[OPEN-AB-STAGE] stage_status_update stage={0} session_status=RUNNING" -f $Stage)

$sessionOutDirRoot = Join-Path $repoRoot 'out\artifacts\dev_verify_multiround'
$currentStageRunDir = Resolve-CurrentStageRunDir -LaunchTime $stageLaunchTime -Settings $settings -SessionOutDirRoot $sessionOutDirRoot
if (-not [string]::IsNullOrWhiteSpace($currentStageRunDir)) {
    $updatedNotes = Update-SessionAnchorsInStartFile -Path $startFilePath -Anchors @{ run_dir = (Convert-ToAnchorPath -Path $currentStageRunDir) }
    Write-Output ("[OPEN-AB-STAGE] anchor_update run_dir={0}" -f (Convert-ToAnchorPath -Path $currentStageRunDir))
    $settings = Read-KeyValueFile -Path $startFilePath
}
else {
    Write-Output '[OPEN-AB-STAGE] anchor_update run_dir=unknown'
}

$autoStartMonitors = $false
if ($Stage -eq 'A') {
    $autoStartMonitors = if ($StartMonitors.IsPresent) {
        $true
    }
    elseif ($settings.Contains('AUTO_START_MONITORS')) {
        Convert-ToBooleanSetting -Value ([string]$settings.AUTO_START_MONITORS) -Default $false
    }
    else {
        $false
    }
}
elseif ($EnableBMonitorRestart.IsPresent) {
    $autoStartMonitors = $true
}

if (-not $autoStartMonitors) {
    return
}

$restartMonitors = if ($settings.Contains('RESTART_MONITORS_ON_STAGE_RESTART')) {
    Convert-ToBooleanSetting -Value ([string]$settings.RESTART_MONITORS_ON_STAGE_RESTART) -Default $true
}
else {
    $true
}

if ($SkipMonitorRestart.IsPresent) {
    $restartMonitors = $false
}

if ($restartMonitors) {
    $stoppedPids = @(Stop-MonitorProcessesForStartFile -StartFilePath $startFilePath)
    Write-Output ("[OPEN-AB-STAGE] monitor_restart stopped_count={0} stopped_pids={1}" -f $stoppedPids.Count, ($stoppedPids -join ','))
}

$supervisorLauncherRelative = if ($settings.Contains('MONITOR_ENTRY_SCRIPT_SUPERVISOR') -and -not [string]::IsNullOrWhiteSpace([string]$settings.MONITOR_ENTRY_SCRIPT_SUPERVISOR)) {
    [string]$settings.MONITOR_ENTRY_SCRIPT_SUPERVISOR
}
else {
    'tools/test/open_unattended_ab_supervisor_window.ps1'
}

$companionLauncherRelative = if ($settings.Contains('MONITOR_ENTRY_SCRIPT_COMPANION') -and -not [string]::IsNullOrWhiteSpace([string]$settings.MONITOR_ENTRY_SCRIPT_COMPANION)) {
    [string]$settings.MONITOR_ENTRY_SCRIPT_COMPANION
}
else {
    'tools/test/open_unattended_ab_companion_window.ps1'
}

$supervisorLauncherPath = Resolve-RepoPath -Path $supervisorLauncherRelative
$companionLauncherPath = Resolve-RepoPath -Path $companionLauncherRelative

$supervisorOutput = @()
if ($Stage -eq 'A') {
    if ([string]::IsNullOrWhiteSpace($currentStageRunDir)) {
        $supervisorOutput = & $supervisorLauncherPath -StartFile $StartFile -CurrentAStartRound 1
    }
    else {
        $supervisorOutput = & $supervisorLauncherPath -StartFile $StartFile -CurrentAStartRound 1 -CurrentARunDir $currentStageRunDir
    }
}
else {
    $currentBRunDir = $currentStageRunDir

    if ([string]::IsNullOrWhiteSpace($currentBRunDir) -and $settings.Contains('SESSION_FINAL_NOTES')) {
        $hintRunDir = Get-LatestAnchorValueFromNotes -Notes ([string]$settings.SESSION_FINAL_NOTES) -Key 'run_dir'
        if (-not [string]::IsNullOrWhiteSpace($hintRunDir)) {
            try {
                $currentBRunDir = Resolve-RepoPath -Path $hintRunDir
            }
            catch {
                $currentBRunDir = ''
            }
        }
    }

    if ([string]::IsNullOrWhiteSpace($currentBRunDir)) {
        Write-Output '[OPEN-AB-STAGE] monitor_attach_b run_dir=unknown source=fallback-auto'
        $supervisorOutput = & $supervisorLauncherPath -StartFile $StartFile -StartFromStage B
    }
    else {
        Write-Output ("[OPEN-AB-STAGE] monitor_attach_b run_dir={0}" -f $currentBRunDir)
        $supervisorOutput = & $supervisorLauncherPath -StartFile $StartFile -StartFromStage B -CurrentBRunDir $currentBRunDir
    }
}

$supervisorLog = ''
$liveStatus = ''
foreach ($line in @($supervisorOutput | ForEach-Object { [string]$_ })) {
    Write-Output $line
    if ($line -match 'supervisor_log=([^\s]+)') {
        $supervisorLog = $Matches[1]
    }
    if ($line -match 'live_status=([^\s]+)') {
        $liveStatus = $Matches[1]
    }
}

$companionOutput = if ([string]::IsNullOrWhiteSpace($supervisorLog)) {
    & $companionLauncherPath -StartFile $StartFile
}
else {
    & $companionLauncherPath -StartFile $StartFile -SupervisorLog $supervisorLog
}

$companionLog = ''
foreach ($line in @($companionOutput | ForEach-Object { [string]$_ })) {
    Write-Output $line
    if ($line -match 'companion_log=([^\s]+)$') {
        $companionLog = $Matches[1]
    }
}

$anchorUpdates = @{}
if (-not [string]::IsNullOrWhiteSpace($currentStageRunDir)) {
    $anchorUpdates.run_dir = Convert-ToAnchorPath -Path $currentStageRunDir
}
if (-not [string]::IsNullOrWhiteSpace($supervisorLog)) {
    $anchorUpdates.supervisor_log = Convert-ToAnchorPath -Path $supervisorLog
}
if (-not [string]::IsNullOrWhiteSpace($companionLog)) {
    $anchorUpdates.companion_log = Convert-ToAnchorPath -Path $companionLog
}
if (-not [string]::IsNullOrWhiteSpace($liveStatus)) {
    $anchorUpdates.live_status = Convert-ToAnchorPath -Path $liveStatus
}

if ($anchorUpdates.Count -gt 0) {
    $updatedNotes = Update-SessionAnchorsInStartFile -Path $startFilePath -Anchors $anchorUpdates
    Write-Output ("[OPEN-AB-STAGE] anchor_update notes={0}" -f $updatedNotes)
}
