param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$TaskDefinitionFileName
)

$ErrorActionPreference = "Stop"

function Get-RepoScopedMutexName {
    param(
        [string]$Role,
        [string]$RepoRoot
    )

    $fullPath = [System.IO.Path]::GetFullPath($RepoRoot).ToLowerInvariant()
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($fullPath)
    $sha1 = [System.Security.Cryptography.SHA1]::Create()
    try {
        $hashBytes = $sha1.ComputeHash($bytes)
    }
    finally {
        $sha1.Dispose()
    }

    $hash = [System.BitConverter]::ToString($hashBytes).Replace('-', '')
    return "Local\whois-fastmode-$Role-$hash"
}

function Enter-RunMutex {
    param(
        [string]$Role,
        [string]$RepoRoot
    )

    $name = Get-RepoScopedMutexName -Role $Role -RepoRoot $RepoRoot
    $mutex = New-Object System.Threading.Mutex($false, $name)
    $acquired = $false
    try {
        try {
            $acquired = $mutex.WaitOne(0)
        }
        catch [System.Threading.AbandonedMutexException] {
            $acquired = $true
        }

        if (-not $acquired) {
            $mutex.Dispose()
            throw "Another $Role fastmode run is already active in this repository."
        }
    }
    catch {
        if (-not $acquired -and $null -ne $mutex) {
            try {
                $mutex.Dispose()
            }
            catch {
            }
        }
        throw
    }

    return [pscustomobject]@{
        Name = $name
        Mutex = $mutex
    }
}

function Get-RunningFastmodeProcessIds {
    param(
        [string]$Role,
        [string]$RepoRoot,
        [int]$ExcludePid
    )

    $scriptLeaf = ("start_dev_verify_fastmode_{0}.ps1" -f $Role).ToLowerInvariant()
    $scriptPath = (Join-Path $PSScriptRoot ("start_dev_verify_fastmode_{0}.ps1" -f $Role)).ToLowerInvariant()
    $scriptPathSlash = $scriptPath.Replace('\', '/')
    $repoRootWindows = $RepoRoot.ToLowerInvariant()
    $repoRootSlash = $repoRootWindows.Replace('\', '/')

    $ids = @(
        Get-CimInstance Win32_Process |
            Where-Object {
                $processId = [int]$_.ProcessId
                if ($processId -eq $ExcludePid) {
                    return $false
                }

                $commandLine = [string]$_.CommandLine
                if ([string]::IsNullOrWhiteSpace($commandLine)) {
                    return $false
                }

                $line = $commandLine.ToLowerInvariant()
                if (-not $line.Contains($scriptLeaf)) {
                    return $false
                }

                return $line.Contains($scriptPath) -or $line.Contains($scriptPathSlash) -or $line.Contains($repoRootWindows) -or $line.Contains($repoRootSlash)
            } |
            Select-Object -ExpandProperty ProcessId -Unique
    )

    return @($ids)
}

function Stop-RunningFastmodeProcesses {
    param([int[]]$ProcessIds)

    $stopped = New-Object 'System.Collections.Generic.List[int]'
    foreach ($targetPid in @($ProcessIds | Sort-Object -Unique)) {
        if ($targetPid -le 0) {
            continue
        }

        try {
            Stop-Process -Id $targetPid -Force -ErrorAction Stop
            Wait-Process -Id $targetPid -Timeout 30 -ErrorAction SilentlyContinue
            [void]$stopped.Add([int]$targetPid)
        }
        catch {
        }
    }

    return @($stopped)
}

function Resolve-TaskDefinitionRelativePath {
    param([string]$InputName)

    if ([string]::IsNullOrWhiteSpace($InputName)) {
        throw "TaskDefinitionFileName is required."
    }

    $normalized = $InputName.Trim().Replace("\\", "/")
    if ($normalized.StartsWith("./")) {
        $normalized = $normalized.Substring(2)
    }

    if ($normalized -match "^(?:[A-Za-z]:|/|\\\\)") {
        throw "TaskDefinitionFileName must be a repository-relative path under testdata/."
    }

    if (-not $normalized.StartsWith("testdata/")) {
        $normalized = "testdata/$normalized"
    }

    return $normalized
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

function Resolve-RemoteKeyPathForLock {
    param([string]$KeyPath)

    if (-not [string]::IsNullOrWhiteSpace($KeyPath) -and (Test-Path -LiteralPath $KeyPath)) {
        return (Resolve-Path -LiteralPath $KeyPath).Path
    }

    $converted = Convert-MsysPathToWindowsPath -Path $KeyPath
    if (-not [string]::IsNullOrWhiteSpace($converted) -and (Test-Path -LiteralPath $converted)) {
        return (Resolve-Path -LiteralPath $converted).Path
    }

    $fallback = Join-Path ([Environment]::GetFolderPath('UserProfile')) '.ssh\id_rsa'
    if (Test-Path -LiteralPath $fallback) {
        return (Resolve-Path -LiteralPath $fallback).Path
    }

    throw "Unable to resolve SSH private key for remote lock check. input=$KeyPath"
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

            # Fallback for aggregated/mixed output lines.
            if ($line -match ('(?:^|\s)' + $escapedKey + '=(.*)$')) {
                return $Matches[1].Trim()
            }
        }
    }

    return ''
}

function Assert-RemoteBuildLockReady {
    param(
        [string]$RepoRoot,
        [string]$RoleTag,
        [string]$RemoteIp,
        [string]$RemoteUser,
        [string]$KeyPath,
        [string]$LockScope,
        [string]$ConflictAction
    )

    $checkScript = Join-Path $RepoRoot 'tools\dev\check_remote_lock.ps1'
    if (-not (Test-Path -LiteralPath $checkScript)) {
        throw "[$RoleTag] remote lock check script not found: $checkScript"
    }

    $lines = @()
    try {
        $lines = @((& $checkScript -RemoteIp $RemoteIp -RemoteUser $RemoteUser -KeyPath $KeyPath -TimeoutSec 20 2>&1) | ForEach-Object { [string]$_ })
    }
    catch {
        throw "[$RoleTag] remote lock check failed: $($_.Exception.Message)"
    }

    $state = (Get-RemoteLockField -Lines $lines -Key 'state').ToLowerInvariant()
    $stale = Get-RemoteLockField -Lines $lines -Key 'stale'
    $ageSec = Get-RemoteLockField -Lines $lines -Key 'age_sec'
    $token = Get-RemoteLockField -Lines $lines -Key 'token'

    Write-Output ("[{0}] remote_lock_check state={1} stale={2} age_sec={3} token={4} scope={5}" -f $RoleTag, $state, $stale, $ageSec, $token, $LockScope)

    if ($state -eq 'absent') {
        return
    }

    if ($state -eq 'present') {
        throw ("[{0}] remote lock is present (stale={1}, age_sec={2}, token={3}, action={4}, scope={5})" -f $RoleTag, $stale, $ageSec, $token, $ConflictAction, $LockScope)
    }

    throw ("[{0}] remote lock check returned unexpected state='{1}'" -f $RoleTag, $state)
}

function Assert-NetworkPrecheckReady {
    param(
        [string]$RepoRoot,
        [string]$RoleTag,
        [string]$RemoteIp,
        [string]$RemoteUser,
        [string]$KeyPath
    )

    $networkPrecheckRequired = Convert-ToBooleanSetting -Value ([string]$env:AUTO_NETWORK_PRECHECK_REQUIRED) -Default $true
    if (-not $networkPrecheckRequired) {
        Write-Output ("[{0}] network_precheck required=false action=skip" -f $RoleTag)
        return
    }

    $checkLocal = Convert-ToBooleanSetting -Value ([string]$env:AUTO_NETWORK_PRECHECK_LOCAL_REQUIRED) -Default $true
    $checkRemote = Convert-ToBooleanSetting -Value ([string]$env:AUTO_NETWORK_PRECHECK_REMOTE_REQUIRED) -Default $true
    $checkIPv4 = Convert-ToBooleanSetting -Value ([string]$env:AUTO_NETWORK_PRECHECK_CHECK_IPV4) -Default $true
    $checkIPv6 = Convert-ToBooleanSetting -Value ([string]$env:AUTO_NETWORK_PRECHECK_CHECK_IPV6) -Default $true
    $requireIPv4 = Convert-ToBooleanSetting -Value ([string]$env:AUTO_NETWORK_PRECHECK_REQUIRE_IPV4) -Default $false
    $requireIPv6 = Convert-ToBooleanSetting -Value ([string]$env:AUTO_NETWORK_PRECHECK_REQUIRE_IPV6) -Default $true

    if (-not $checkLocal -and -not $checkRemote) {
        throw ("[{0}] network precheck misconfigured: both local and remote checks are disabled" -f $RoleTag)
    }
    if (-not $checkIPv4 -and -not $checkIPv6) {
        throw ("[{0}] network precheck misconfigured: both IPv4 and IPv6 checks are disabled" -f $RoleTag)
    }
    if ($requireIPv4 -and -not $checkIPv4) {
        $checkIPv4 = $true
    }
    if ($requireIPv6 -and -not $checkIPv6) {
        $checkIPv6 = $true
    }

    $targets = if ([string]::IsNullOrWhiteSpace([string]$env:AUTO_NETWORK_PRECHECK_TARGETS)) {
        'whois.iana.org;whois.arin.net'
    }
    else {
        [string]$env:AUTO_NETWORK_PRECHECK_TARGETS
    }

    $timeoutSec = 8
    if (-not [string]::IsNullOrWhiteSpace([string]$env:AUTO_NETWORK_PRECHECK_TIMEOUT_SEC)) {
        $parsedTimeout = 0
        if ([int]::TryParse(([string]$env:AUTO_NETWORK_PRECHECK_TIMEOUT_SEC), [ref]$parsedTimeout)) {
            if ($parsedTimeout -ge 1 -and $parsedTimeout -le 30) {
                $timeoutSec = $parsedTimeout
            }
        }
    }

    $precheckScript = Join-Path $RepoRoot 'tools\dev\check_dualstack_whois_connectivity.ps1'
    if (-not (Test-Path -LiteralPath $precheckScript)) {
        throw ("[{0}] network precheck script not found: {1}" -f $RoleTag, $precheckScript)
    }

    $resolvedKeyPath = ''
    if ($checkRemote) {
        $resolvedKeyPath = Resolve-RemoteKeyPathForLock -KeyPath $KeyPath
    }

    $lines = @()
    try {
        $lines = @((& $precheckScript -Targets $targets -TimeoutSec $timeoutSec -CheckLocal:$checkLocal -CheckRemote:$checkRemote -CheckIPv4:$checkIPv4 -CheckIPv6:$checkIPv6 -RequireIPv4:$requireIPv4 -RequireIPv6:$requireIPv6 -RemoteIp $RemoteIp -RemoteUser $RemoteUser -KeyPath $resolvedKeyPath 2>&1) | ForEach-Object { [string]$_ })
    }
    catch {
        throw ("[{0}] network precheck execution failed: {1}" -f $RoleTag, $_.Exception.Message)
    }

    $exitCode = if ($null -eq $LASTEXITCODE) { 0 } else { [int]$LASTEXITCODE }
    foreach ($line in $lines) {
        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }
        Write-Output $line
    }

    if ($exitCode -ne 0) {
        throw ("[{0}] network precheck failed (exit={1}) targets={2} local={3} remote={4} check_ipv4={5} check_ipv6={6} require_ipv4={7} require_ipv6={8}" -f $RoleTag, $exitCode, $targets, $checkLocal, $checkRemote, $checkIPv4, $checkIPv6, $requireIPv4, $requireIPv6)
    }

    Write-Output ("[{0}] network_precheck status=PASS targets={1} local={2} remote={3} check_ipv4={4} check_ipv6={5} require_ipv4={6} require_ipv6={7}" -f $RoleTag, $targets, $checkLocal, $checkRemote, $checkIPv4, $checkIPv6, $requireIPv4, $requireIPv6)
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
Set-Location $repoRoot

$existingRunPids = @(Get-RunningFastmodeProcessIds -Role 'A' -RepoRoot $repoRoot -ExcludePid $PID)
if ($existingRunPids.Count -gt 0) {
    Write-Output ("[FASTMODE-A] restart_precheck existing_count={0} existing_pids={1}" -f $existingRunPids.Count, ($existingRunPids -join ','))
    $stoppedRunPids = @(Stop-RunningFastmodeProcesses -ProcessIds $existingRunPids)
    Write-Output ("[FASTMODE-A] restart_precheck stopped_count={0} stopped_pids={1}" -f $stoppedRunPids.Count, ($stoppedRunPids -join ','))
}
else {
    Write-Output '[FASTMODE-A] restart_precheck existing_count=0'
}

$runMutexContext = Enter-RunMutex -Role 'A' -RepoRoot $repoRoot
Write-Output ("[FASTMODE-A] run_mutex={0}" -f [string]$runMutexContext.Name)

$taskDefinitionRelative = Resolve-TaskDefinitionRelativePath -InputName $TaskDefinitionFileName
$taskDefinitionAbsolute = Join-Path $repoRoot ($taskDefinitionRelative -replace "/", [System.IO.Path]::DirectorySeparatorChar)

if (-not (Test-Path -LiteralPath $taskDefinitionAbsolute)) {
    throw "Task definition file not found: $taskDefinitionRelative"
}

if (Select-String -Path $taskDefinitionAbsolute -Pattern "TODO_" -Quiet) {
    throw "Task definition still contains TODO placeholders: $taskDefinitionRelative"
}

$remoteIp = if ([string]::IsNullOrWhiteSpace($env:AUTO_REMOTE_IP)) { "10.0.0.199" } else { $env:AUTO_REMOTE_IP }
$remoteUser = if ([string]::IsNullOrWhiteSpace($env:AUTO_REMOTE_USER)) { "larson" } else { $env:AUTO_REMOTE_USER }
$keyPath = if ([string]::IsNullOrWhiteSpace($env:AUTO_REMOTE_KEYPATH)) { "/c/Users/$env:USERNAME/.ssh/id_rsa" } else { $env:AUTO_REMOTE_KEYPATH }
$queries = if ([string]::IsNullOrWhiteSpace($env:AUTO_QUERIES)) { "8.8.8.8 1.1.1.1 10.0.0.8" } else { $env:AUTO_QUERIES }
$terminalWatchdogMode = if ([string]::IsNullOrWhiteSpace($env:AUTO_TERMINAL_WATCHDOG_MODE)) { "safe" } else { $env:AUTO_TERMINAL_WATCHDOG_MODE }
$terminalWatchdogIntervalSec = if ([string]::IsNullOrWhiteSpace($env:AUTO_TERMINAL_WATCHDOG_INTERVAL_SEC)) { 120 } else { [int]$env:AUTO_TERMINAL_WATCHDOG_INTERVAL_SEC }
$terminalWatchdogMinAgeSec = if ([string]::IsNullOrWhiteSpace($env:AUTO_TERMINAL_WATCHDOG_MIN_AGE_SEC)) { 600 } else { [int]$env:AUTO_TERMINAL_WATCHDOG_MIN_AGE_SEC }
$taskStaticPrecheckPolicy = if ([string]::IsNullOrWhiteSpace($env:AUTO_TASK_STATIC_PRECHECK_POLICY)) { "enforce" } else { [string]$env:AUTO_TASK_STATIC_PRECHECK_POLICY }

$taskStaticPrecheckPolicy = $taskStaticPrecheckPolicy.Trim().ToLowerInvariant()
if ($taskStaticPrecheckPolicy -notin @('off', 'warn', 'enforce')) {
    throw "Invalid AUTO_TASK_STATIC_PRECHECK_POLICY value: $taskStaticPrecheckPolicy"
}

$remoteBuildLockRequired = Convert-ToBooleanSetting -Value ([string]$env:AUTO_REMOTE_BUILD_LOCK_REQUIRED) -Default $true
$remoteBuildLockScope = if ([string]::IsNullOrWhiteSpace($env:AUTO_REMOTE_BUILD_LOCK_SCOPE)) { 'remote-base' } else { [string]$env:AUTO_REMOTE_BUILD_LOCK_SCOPE }
$remoteBuildLockConflictAction = if ([string]::IsNullOrWhiteSpace($env:AUTO_REMOTE_BUILD_LOCK_CONFLICT_ACTION)) { 'stop-before-build' } else { [string]$env:AUTO_REMOTE_BUILD_LOCK_CONFLICT_ACTION }

if ($remoteBuildLockRequired) {
    $lockCheckKeyPath = Resolve-RemoteKeyPathForLock -KeyPath $keyPath
    Assert-RemoteBuildLockReady -RepoRoot $repoRoot -RoleTag 'FASTMODE-A' -RemoteIp $remoteIp -RemoteUser $remoteUser -KeyPath $lockCheckKeyPath -LockScope $remoteBuildLockScope -ConflictAction $remoteBuildLockConflictAction
}
else {
    Write-Output ("[FASTMODE-A] remote_lock_check required=false action=skip scope={0}" -f $remoteBuildLockScope)
}

Assert-NetworkPrecheckReady -RepoRoot $repoRoot -RoleTag 'FASTMODE-A' -RemoteIp $remoteIp -RemoteUser $remoteUser -KeyPath $keyPath

$entryScript = Join-Path $PSScriptRoot "start_dev_verify_8round_multiround.ps1"
if (-not (Test-Path -LiteralPath $entryScript)) {
    throw "Entry script not found: $entryScript"
}

Write-Output ("[FASTMODE-A] task_definition={0}" -f $taskDefinitionRelative)

$exitCode = 1
try {
    & $entryScript `
        -ResetCodeStepState `
        -CodeStepResetPolicy restore-source `
        -TaskDefinitionFile $taskDefinitionRelative `
        -StartRound 1 -EndRound 8 `
        -DevVerifyStride 2 `
        -VerifyExecutionProfile d6-only `
        -EnableGuardedFastMode $true `
        -EnableGateOnlySourceDrivenSkip $true `
        -RbPreflight 1 -RbPreclassTableGuard 1 `
        -QuietTerminalOutput true `
        -TerminalWatchdogMode $terminalWatchdogMode `
        -TerminalWatchdogIntervalSec $terminalWatchdogIntervalSec `
        -TerminalWatchdogMinAgeSec $terminalWatchdogMinAgeSec `
        -QuietRemoteBuildLogs false `
        -TaskStaticPrecheckPolicy $taskStaticPrecheckPolicy `
        -TaskDesignQualityPolicy enforce `
        -UnknownNoOpBudget 1 -UnknownNoOpConsecutiveLimit 2 `
        -DisableUnknownNoOpBudgetGate:$false `
        -KeyPath $keyPath -RemoteIp $remoteIp -User $remoteUser -Queries $queries

    $exitCode = if ($null -eq $LASTEXITCODE) { 0 } else { [int]$LASTEXITCODE }
}
finally {
    if ($null -ne $runMutexContext -and $null -ne $runMutexContext.Mutex) {
        try {
            $runMutexContext.Mutex.ReleaseMutex() | Out-Null
        }
        catch {
        }
        finally {
            $runMutexContext.Mutex.Dispose()
        }
    }
}

Write-Output ("A_EXIT={0}" -f $exitCode)
exit $exitCode
