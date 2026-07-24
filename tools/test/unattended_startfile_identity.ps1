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
            catch { Write-Verbose ("Suppressed exception: {0}" -f $_.Exception.Message) }
        }
        throw
    }

    return [pscustomobject]@{
        Name = $name
        Mutex = $mutex
    }
}

function Get-RepoScopedMainMutexName {
    param([string]$RepoRoot)

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
    return "Local\whois-fastmode-main-$hash"
}

function Enter-MainRunMutex {
    param([string]$RepoRoot)

    $name = Get-RepoScopedMainMutexName -RepoRoot $RepoRoot
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
            throw "Another AB main run is already active in this repository."
        }
    }
    catch {
        if (-not $acquired -and $null -ne $mutex) {
            try {
                $mutex.Dispose()
            }
            catch { Write-Verbose ("Suppressed exception: {0}" -f $_.Exception.Message) }
        }
        throw
    }

    return [pscustomobject]@{
        Name = $name
        Mutex = $mutex
    }
}

function Get-RunningFastmodeProcessIdList {
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

function Invoke-RunningFastmodeProcessStop {
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
        catch { Write-Verbose ("Suppressed exception: {0}" -f $_.Exception.Message) }
    }

    return @($stopped)
}

function Resolve-StartFilePathFromEnv {
    if ([string]::IsNullOrWhiteSpace([string]$env:AUTO_START_FILE_PATH)) {
        return ''
    }

    try {
        return [System.IO.Path]::GetFullPath([string]$env:AUTO_START_FILE_PATH)
    }
    catch {
        return [string]$env:AUTO_START_FILE_PATH
    }
}

function Assert-StageWindowInvocation {
    param(
        [string]$Stage,
        [string]$TaskDefinitionRelative
    )

    $startFilePath = Resolve-StartFilePathFromEnv
    if ([string]::IsNullOrWhiteSpace($startFilePath)) {
        throw ("Fastmode {0} must be launched via tools/test/open_unattended_ab_stage_window.ps1; AUTO_START_FILE_PATH is not set." -f $Stage)
    }

    $settings = Read-KeyValueFile -Path $startFilePath
    $taskKey = '{0}_TASK_DEFINITION' -f $Stage
    if (-not $settings.Contains($taskKey)) {
        throw ("Fastmode {0} requires {1} in start file: {2}" -f $Stage, $taskKey, $startFilePath)
    }

    $expectedTaskDefinition = Resolve-TaskDefinitionRelativePath -InputName ([string]$settings[$taskKey])
    if ($expectedTaskDefinition -ne $TaskDefinitionRelative) {
        throw ("Fastmode {0} task mismatch: start-file {1}={2}, invocation={3}. Use tools/test/open_unattended_ab_stage_window.ps1." -f $Stage, $taskKey, $expectedTaskDefinition, $TaskDefinitionRelative)
    }

    Write-Output ("[FASTMODE-{0}] [{1}] stage_window_guard start_file={2} task={3}" -f $Stage, (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $startFilePath, $TaskDefinitionRelative)
}

function Invoke-StartFieldSyncStrictGate {
    param(
        [string]$RepoRoot,
        [string]$RoleTag,
        [string]$StartFilePath
    )

    $checkScript = Join-Path $RepoRoot 'tools\test\check_unattended_start_field_sync.ps1'
    if (-not (Test-Path -LiteralPath $checkScript)) {
        throw ("[{0}] start-field-sync script not found: {1}" -f $RoleTag, $checkScript)
    }

    $lines = @()
    $exitCode = 1
    try {
        $lines = @((& $checkScript -StartFile $StartFilePath -EnforceRunningStatusMessageTemplateMatch 2>&1) | ForEach-Object { [string]$_ })
        $exitCode = if ($null -eq $LASTEXITCODE) { 0 } else { [int]$LASTEXITCODE }
    }
    catch {
        $errorText = Convert-ToSingleLineText -Text $_.Exception.Message
        if (-not [string]::IsNullOrWhiteSpace($errorText)) {
            $lines = @($errorText)
        }
        $exitCode = if ($null -eq $LASTEXITCODE) { 1 } else { [int]$LASTEXITCODE }
    }

    foreach ($line in @($lines)) {
        if (-not [string]::IsNullOrWhiteSpace($line)) {
            Write-Output $line
        }
    }

    if ($exitCode -ne 0) {
        $detailLines = @($lines | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
        $detail = if ($detailLines.Count -gt 0) {
            Convert-ToSingleLineText -Text ($detailLines -join ' | ')
        }
        else {
            'no-output'
        }

        throw ("[{0}] start-field-sync strict gate failed (exit={1}) start_file={2} detail={3}" -f $RoleTag, $exitCode, $StartFilePath, $detail)
    }

    Write-Output ("[{0}] start-field-sync strict_gate=PASS start_file={1}" -f $RoleTag, $StartFilePath)
}

function Invoke-StatusTicketMiniRegressionGate {
    param(
        [string]$RepoRoot,
        [string]$RoleTag
    )

    $checkScript = Join-Path $RepoRoot 'tools\test\status_ticket_mini_regression.ps1'
    if (-not (Test-Path -LiteralPath $checkScript)) {
        throw ("[{0}] status-ticket-mini script not found: {1}" -f $RoleTag, $checkScript)
    }

    $lines = @()
    $exitCode = 1
    try {
        $lines = @((& $checkScript 2>&1) | ForEach-Object { [string]$_ })
        $exitCode = if ($null -eq $LASTEXITCODE) { 0 } else { [int]$LASTEXITCODE }
    }
    catch {
        $errorText = Convert-ToSingleLineText -Text $_.Exception.Message
        if (-not [string]::IsNullOrWhiteSpace($errorText)) {
            $lines = @($errorText)
        }
        $exitCode = if ($null -eq $LASTEXITCODE) { 1 } else { [int]$LASTEXITCODE }
    }

    foreach ($line in @($lines)) {
        if (-not [string]::IsNullOrWhiteSpace($line)) {
            Write-Output $line
        }
    }

    if ($exitCode -ne 0) {
        $detailLines = @($lines | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
        $detail = if ($detailLines.Count -gt 0) {
            Convert-ToSingleLineText -Text ($detailLines -join ' | ')
        }
        else {
            'no-output'
        }

        throw ("[{0}] status-ticket-mini gate failed (exit={1}) detail={2}" -f $RoleTag, $exitCode, $detail)
    }

    Write-Output ("[{0}] status-ticket-mini gate=PASS" -f $RoleTag)
}

function Invoke-IncrementalEncodingFixGate {
    param(
        [string]$RepoRoot,
        [string]$RoleTag
    )

    $checkScript = Join-Path $RepoRoot 'tools\dev\enforce_utf8_bom_lf_changed.ps1'
    if (-not (Test-Path -LiteralPath $checkScript)) {
        throw ("[{0}] incremental encoding script not found: {1}" -f $RoleTag, $checkScript)
    }

    $lines = @()
    $exitCode = 1
    try {
        $lines = @((& $checkScript -Mode fix -Policy enforce -IncludeUntracked 2>&1) | ForEach-Object { [string]$_ })
        $exitCode = if ($null -eq $LASTEXITCODE) { 0 } else { [int]$LASTEXITCODE }
    }
    catch {
        $errorText = Convert-ToSingleLineText -Text $_.Exception.Message
        if (-not [string]::IsNullOrWhiteSpace($errorText)) {
            $lines = @($errorText)
        }
        $exitCode = if ($null -eq $LASTEXITCODE) { 1 } else { [int]$LASTEXITCODE }
    }

    foreach ($line in @($lines)) {
        if (-not [string]::IsNullOrWhiteSpace($line)) {
            Write-Output $line
        }
    }

    if ($exitCode -ne 0) {
        $detailLines = @($lines | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
        $detail = if ($detailLines.Count -gt 0) {
            Convert-ToSingleLineText -Text ($detailLines -join ' | ')
        }
        else {
            'no-output'
        }

        throw ("[{0}] incremental encoding gate failed (exit={1}) detail={2}" -f $RoleTag, $exitCode, $detail)
    }

    Write-Output ("[{0}] incremental encoding gate=PASS mode=fix policy=enforce" -f $RoleTag)
}

function Invoke-SrcCodeEncodingFixGate {
    param(
        [string]$RepoRoot,
        [string]$RoleTag
    )

    $checkScript = Join-Path $RepoRoot 'tools\dev\enforce_utf8_lf_src_changed.ps1'
    if (-not (Test-Path -LiteralPath $checkScript)) {
        throw ("[{0}] src encoding script not found: {1}" -f $RoleTag, $checkScript)
    }

    $lines = @()
    $exitCode = 1
    try {
        $lines = @((& $checkScript -Mode fix -Policy enforce -IncludeUntracked 2>&1) | ForEach-Object { [string]$_ })
        $exitCode = if ($null -eq $LASTEXITCODE) { 0 } else { [int]$LASTEXITCODE }
    }
    catch {
        $errorText = Convert-ToSingleLineText -Text $_.Exception.Message
        if (-not [string]::IsNullOrWhiteSpace($errorText)) {
            $lines = @($errorText)
        }
        $exitCode = if ($null -eq $LASTEXITCODE) { 1 } else { [int]$LASTEXITCODE }
    }

    foreach ($line in @($lines)) {
        if (-not [string]::IsNullOrWhiteSpace($line)) {
            Write-Output $line
        }
    }

    if ($exitCode -ne 0) {
        $detailLines = @($lines | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
        $detail = if ($detailLines.Count -gt 0) {
            Convert-ToSingleLineText -Text ($detailLines -join ' | ')
        }
        else {
            'no-output'
        }

        throw ("[{0}] src encoding gate failed (exit={1}) detail={2}" -f $RoleTag, $exitCode, $detail)
    }

    Write-Output ("[{0}] src encoding gate=PASS mode=fix policy=enforce" -f $RoleTag)
}

function Assert-RemoteBuildLockReady {
    param(
        [string]$RepoRoot,
        [string]$RoleTag,
        [string]$RemoteIp,
        [string]$RemoteUser,
        [string]$KeyPath,
        [string]$LockScope,
        [string]$ConflictAction,
        [switch]$IncludeRuntimeLogPath
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
        $stageTag = ''
        if ($RoleTag -match 'FASTMODE-([A-Za-z0-9]+)') {
            $stageTag = $Matches[1]
        }

        $sceneCapture = if ($IncludeRuntimeLogPath.IsPresent) {
            Save-RemoteLockScene -RepoRoot $RepoRoot -RoleTag $RoleTag -StageTag $stageTag -RemoteIp $RemoteIp -RemoteUser $RemoteUser -KeyPath $KeyPath -LockScope $LockScope -ConflictAction $ConflictAction -ObservedCheckLines $lines -IncludeRuntimeLogPath
        }
        else {
            Save-RemoteLockScene -RepoRoot $RepoRoot -RoleTag $RoleTag -StageTag $stageTag -RemoteIp $RemoteIp -RemoteUser $RemoteUser -KeyPath $KeyPath -LockScope $LockScope -ConflictAction $ConflictAction -ObservedCheckLines $lines
        }
        $sceneDir = [string]$sceneCapture.SceneDir
        $sceneErrorDetail = [string]$sceneCapture.ErrorDetail

        if (-not [string]::IsNullOrWhiteSpace($sceneErrorDetail)) {
            Write-Output ("[{0}] remote_lock_scene_failed detail={1}" -f $RoleTag, $sceneErrorDetail)
        }

        $sceneRel = Convert-ToRepoRelativePath -Path $sceneDir -RepoRoot $RepoRoot
        if (-not [string]::IsNullOrWhiteSpace($sceneRel)) {
            Write-Output ("[{0}] remote_lock_scene={1}" -f $RoleTag, $sceneRel)
        }

        $message = ("[{0}] remote lock is present (stale={1}, age_sec={2}, token={3}, action={4}, scope={5})" -f $RoleTag, $stale, $ageSec, $token, $ConflictAction, $LockScope)
        if (-not [string]::IsNullOrWhiteSpace($sceneRel)) {
            $message = $message + ", scene=" + $sceneRel
        }

        throw $message
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

    $executionMaxAttempts = if ($checkRemote) { 2 } else { 1 }
    if (-not [string]::IsNullOrWhiteSpace([string]$env:AUTO_NETWORK_PRECHECK_EXEC_MAX_ATTEMPTS)) {
        $parsedAttemptCount = 0
        if ([int]::TryParse(([string]$env:AUTO_NETWORK_PRECHECK_EXEC_MAX_ATTEMPTS), [ref]$parsedAttemptCount)) {
            if ($parsedAttemptCount -ge 1 -and $parsedAttemptCount -le 3) {
                $executionMaxAttempts = $parsedAttemptCount
            }
        }
    }

    $executionRetryDelaySec = 3
    if (-not [string]::IsNullOrWhiteSpace([string]$env:AUTO_NETWORK_PRECHECK_EXEC_RETRY_DELAY_SEC)) {
        $parsedRetryDelay = 0
        if ([int]::TryParse(([string]$env:AUTO_NETWORK_PRECHECK_EXEC_RETRY_DELAY_SEC), [ref]$parsedRetryDelay)) {
            if ($parsedRetryDelay -ge 1 -and $parsedRetryDelay -le 30) {
                $executionRetryDelaySec = $parsedRetryDelay
            }
        }
    }

    $precheckScript = Join-Path $RepoRoot 'tools\dev\check_dualstack_whois_connectivity.ps1'
    if (-not (Test-Path -LiteralPath $precheckScript)) {
        throw ("[{0}] network precheck script not found: {1}" -f $RoleTag, $precheckScript)
    }

    $resolvedKeyPath = ''
    if ($checkRemote) {
        $resolvedKeyPath = Resolve-RemoteKeyPath -KeyPath $KeyPath -UseDefaultSshKeyFallback -Purpose 'SSH private key for remote lock check'
    }

    $lines = @()
    $exitCode = 1
    $lastExecutionError = ''
    for ($attempt = 1; $attempt -le $executionMaxAttempts; $attempt++) {
        $lines = @()
        $exitCode = 1
        $lastExecutionError = ''

        try {
            $lines = @((& $precheckScript -Targets $targets -TimeoutSec $timeoutSec -CheckLocal:$checkLocal -CheckRemote:$checkRemote -CheckIPv4:$checkIPv4 -CheckIPv6:$checkIPv6 -RequireIPv4:$requireIPv4 -RequireIPv6:$requireIPv6 -RemoteIp $RemoteIp -RemoteUser $RemoteUser -KeyPath $resolvedKeyPath 2>&1) | ForEach-Object { [string]$_ })
            $exitCode = if ($null -eq $LASTEXITCODE) { 0 } else { [int]$LASTEXITCODE }
            break
        }
        catch {
            $lastExecutionError = $_.Exception.Message
            if ($attempt -lt $executionMaxAttempts) {
                Write-Output ("[{0}] network_precheck execution_retry attempt={1}/{2} wait_sec={3} reason={4}" -f $RoleTag, $attempt, $executionMaxAttempts, $executionRetryDelaySec, $lastExecutionError)
                Start-Sleep -Seconds $executionRetryDelaySec
                continue
            }
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($lastExecutionError) -and $exitCode -ne 0 -and $lines.Count -eq 0) {
        throw ("[{0}] network precheck execution failed: {1}" -f $RoleTag, $lastExecutionError)
    }

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

function Write-Utf8NoBomTextFileAtomically {
    param(
        [string]$Path,
        [AllowEmptyString()][string]$Text
    )

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $parent = Split-Path -Parent $fullPath
    $commitToken = ([guid]::NewGuid().ToString('N'))
    $tempPath = Join-Path $parent ('.{0}.{1}.{2}.tmp' -f (Split-Path -Leaf $fullPath), $PID, $commitToken)
    $backupPath = Join-Path $parent ('.{0}.{1}.{2}.bak' -f (Split-Path -Leaf $fullPath), $PID, $commitToken)
    try {
        [System.IO.File]::WriteAllText($tempPath, $Text, [System.Text.UTF8Encoding]::new($false))
        if ([System.IO.File]::Exists($fullPath)) {
            [System.IO.File]::Replace($tempPath, $fullPath, $backupPath)
        }
        else {
            [System.IO.File]::Move($tempPath, $fullPath)
        }
    }
    finally {
        if ([System.IO.File]::Exists($tempPath)) {
            [System.IO.File]::Delete($tempPath)
        }
        if ([System.IO.File]::Exists($backupPath)) {
            [System.IO.File]::Delete($backupPath)
        }
    }
}

function Write-StageExitReasonArtifact {
    param(
        [string]$RepoRoot,
        [string]$Stage,
        [string]$ScriptTag,
        [string]$TaskDefinitionFile,
        [string]$Result,
        [int]$ExitCode,
        [AllowEmptyString()][string]$FailureCategory,
        [AllowEmptyString()][string]$FailureReason,
        [AllowEmptyString()][string]$SourceScriptName,
        [switch]$IncludeRuntimeLogPath
    )

    $artifactDir = Join-Path $RepoRoot 'out\artifacts\ab_stage_exit'
    try {
        if (-not (Test-Path -LiteralPath $artifactDir)) {
            New-Item -ItemType Directory -Path $artifactDir -Force | Out-Null
        }

        $now = Get-Date
        $pidText = [string]$PID
        $stageLower = $Stage.Trim().ToLowerInvariant()
        $timestamp = $now.ToString('yyyyMMdd-HHmmss')
        $historyFile = Join-Path $artifactDir ("{0}_{1}_pid{2}.json" -f $timestamp, $stageLower, $pidText)
        $latestFile = Join-Path $artifactDir ("latest_{0}_exit.json" -f $stageLower)

        $startFilePath = ''
        if (-not [string]::IsNullOrWhiteSpace([string]$env:AUTO_START_FILE_PATH)) {
            try {
                $startFilePath = [System.IO.Path]::GetFullPath([string]$env:AUTO_START_FILE_PATH)
            }
            catch {
                $startFilePath = [string]$env:AUTO_START_FILE_PATH
            }
        }

        $record = [ordered]@{
            schema = 'AB_STAGE_EXIT_REASON_V1'
            generated_at = $now.ToString('yyyy-MM-dd HH:mm:ss')
            stage = $Stage.Trim().ToUpperInvariant()
            process_id = [int]$PID
            result = $Result.Trim().ToLowerInvariant()
            exit_code = [int]$ExitCode
            fail_category = (Convert-ToSingleLineText -Text $FailureCategory)
            fail_reason = (Convert-ToSingleLineText -Text $FailureReason)
            task_definition = (Convert-ToSingleLineText -Text $TaskDefinitionFile)
            source_script = if ([string]::IsNullOrWhiteSpace($SourceScriptName)) { (Split-Path -Leaf $PSCommandPath) } else { (Convert-ToSingleLineText -Text $SourceScriptName) }
            start_file_path = $startFilePath
            launch_token = (Convert-ToSingleLineText -Text ([string]$env:AUTO_STAGE_LAUNCH_TOKEN))
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

            $record['runtime_log_path'] = $runtimeLogPath
        }

        $json = (($record | ConvertTo-Json -Depth 8) -replace "`r`n", "`n")
        Write-Utf8NoBomTextFileAtomically -Path $historyFile -Text $json
        Write-Utf8NoBomTextFileAtomically -Path $latestFile -Text $json

        Write-Output ("[{0}] exit_reason_file={1}" -f $ScriptTag, (Convert-ToRepoRelativePath -Path $historyFile -RepoRoot $RepoRoot))
        Write-Output ("[{0}] exit_reason_latest={1}" -f $ScriptTag, (Convert-ToRepoRelativePath -Path $latestFile -RepoRoot $RepoRoot))
    }
    catch {
        Write-Output ("[{0}] exit_reason_write_failed detail={1}" -f $ScriptTag, (Convert-ToSingleLineText -Text $_.Exception.Message))
    }
}

function Get-FastmodeFailureCategory {
    param(
        [AllowEmptyString()][string]$Message,
        [switch]$IncludeSnapshotRestore
    )

    $line = (Convert-ToSingleLineText -Text $Message).ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($line)) {
        return 'unknown-gate'
    }

    if ($line -match 'remote lock') {
        return 'remote-lock-gate'
    }
    if ($line -match 'network precheck') {
        return 'network-gate'
    }
    if ($line -match 'task definition|todo placeholders') {
        return 'task-definition-gate'
    }
    if ($line -match 'already active in this repository') {
        return 'single-instance-gate'
    }
    if ($line -match 'entry script not found|unable to resolve ssh private key|invalid auto_task_static_precheck_policy|invalid auto_task_static_precheck_fail_on_warnings') {
        return 'config-gate'
    }
    if ($line -match 'start-field-sync strict gate failed|start-field-sync script not found') {
        return 'start-field-gate'
    }
    if ($line -match 'status-ticket-mini gate failed|status-ticket-mini script not found') {
        return 'status-ticket-mini-gate'
    }
    if ($line -match 'incremental encoding gate failed|incremental encoding script not found') {
        return 'encoding-gate'
    }
    if ($line -match 'src encoding gate failed|src encoding script not found') {
        return 'src-encoding-gate'
    }
    if ($IncludeSnapshotRestore.IsPresent -and $line -match 'snapshot restore|a_success_snapshot|a snapshot') {
        return 'snapshot-restore-gate'
    }

    return 'runtime-fail'
}

function Exit-FastmodeProcess {
    param(
        [int]$Code,
        [string]$ScriptName,
        [string]$ScriptTag,
        [switch]$StopRuntimeTranscript
    )

    if ($StopRuntimeTranscript.IsPresent) {
        Invoke-StageRuntimeTranscriptStop
    }

    $commandLine = ''
    try {
        $proc = Get-CimInstance Win32_Process -Filter ("ProcessId={0}" -f $PID)
        if ($null -ne $proc) {
            $commandLine = [string]$proc.CommandLine
        }
    }
    catch { Write-Verbose ("Suppressed exception: {0}" -f $_.Exception.Message) }

    $line = $commandLine.ToLowerInvariant()
    $keepWindowOnExit = Convert-ToBooleanSetting -Value ([string]$env:AUTO_KEEP_WINDOW_ON_EXIT) -Default $true
    if ($keepWindowOnExit -and -not [string]::IsNullOrWhiteSpace($line) -and $line.Contains('-noexit') -and $line.Contains($ScriptName.ToLowerInvariant())) {
        $global:LASTEXITCODE = $Code
        Write-Output ("[{0}] keep_window_on_exit=true exit_code={1} action=return_to_prompt" -f $ScriptTag, $Code)
        return
    }

    if (-not [string]::IsNullOrWhiteSpace($line) -and $line.Contains('-noexit') -and $line.Contains($ScriptName.ToLowerInvariant())) {
        [System.Environment]::Exit($Code)
    }

    exit $Code
}

function Invoke-DispatchDeliveryToggle {
    param(
        [string]$Path,
        [System.Collections.IDictionary]$Settings,
        [string]$ScriptTag
    )

    $defaultTriggerCommand = 'powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/dispatch_takeover_to_chat.ps1 -TicketId "%TICKET_ID%" -TicketEvent "%EVENT%" -StartFile "%START_FILE%" -QueuePath "%QUEUE_PATH%" -BriefPath "%BRIEF_PATH%" -NoOpenEditor -SkipClipboard'
    $policyPlan = Get-ChatDispatchPolicyPlan -Settings $Settings -DefaultTriggerCommand $defaultTriggerCommand
    $updates = if ($null -ne $policyPlan) { [hashtable]$policyPlan.Updates } else { @{} }
    $changes = if ($null -ne $policyPlan) { @($policyPlan.Changes) } else { @() }

    if ($updates.Count -gt 0) {
        Invoke-KeyValueFileValueUpdateCore -Path $Path -Values $updates
        Write-Host ("[{0}] dispatch_policy_autofix applied={1}" -f $ScriptTag, ($changes -join ','))
        return (Read-KeyValueFile -Path $Path)
    }

    $resolvedPolicy = if ($null -ne $policyPlan) { $policyPlan.ResolvedPolicy } else { $null }
    $policySummary = ''
    if ($null -ne $resolvedPolicy) {
        $policySummary = ('work_mode={0} primary={1} fallback={2} final_stop_gate={3}' -f [string]$resolvedPolicy.work_mode, [string]$resolvedPolicy.delivery_primary, [string]$resolvedPolicy.delivery_fallback, [string]$resolvedPolicy.final_stop_gate)
    }
    Write-Host ("[{0}] dispatch_policy_guard status=PASS {1}" -f $ScriptTag, (Convert-ToSingleLineText -Text $policySummary))
    return $Settings
}

function Clear-MonitorChainShutdownRequest {
    param(
        [string]$Path,
        [System.Collections.IDictionary]$Settings,
        [string]$ScriptTag
    )

    $requested = $false
    if ($null -ne $Settings -and $Settings.Contains('MONITOR_CHAIN_SHUTDOWN_REQUESTED')) {
        $requested = Convert-ToBooleanSetting -Value ([string]$Settings.MONITOR_CHAIN_SHUTDOWN_REQUESTED) -Default $false
    }

    $reason = if ($null -ne $Settings -and $Settings.Contains('MONITOR_CHAIN_SHUTDOWN_REASON')) { [string]$Settings.MONITOR_CHAIN_SHUTDOWN_REASON } else { '' }
    $source = if ($null -ne $Settings -and $Settings.Contains('MONITOR_CHAIN_SHUTDOWN_SOURCE')) { [string]$Settings.MONITOR_CHAIN_SHUTDOWN_SOURCE } else { '' }
    $requestedAt = if ($null -ne $Settings -and $Settings.Contains('MONITOR_CHAIN_SHUTDOWN_AT')) { [string]$Settings.MONITOR_CHAIN_SHUTDOWN_AT } else { '' }
    $detail = if ($null -ne $Settings -and $Settings.Contains('MONITOR_CHAIN_SHUTDOWN_DETAIL')) { [string]$Settings.MONITOR_CHAIN_SHUTDOWN_DETAIL } else { '' }

    if (-not $requested -and [string]::IsNullOrWhiteSpace($reason) -and [string]::IsNullOrWhiteSpace($source) -and [string]::IsNullOrWhiteSpace($requestedAt) -and [string]::IsNullOrWhiteSpace($detail)) {
        Write-Host ("[{0}] monitor_chain_shutdown_reset status=PASS" -f $ScriptTag)
        return $Settings
    }

    Invoke-KeyValueFileValueUpdateCore -Path $Path -Values @{
        MONITOR_CHAIN_SHUTDOWN_REQUESTED = 'false'
        MONITOR_CHAIN_SHUTDOWN_REASON = ''
        MONITOR_CHAIN_SHUTDOWN_SOURCE = ''
        MONITOR_CHAIN_SHUTDOWN_AT = ''
        MONITOR_CHAIN_SHUTDOWN_DETAIL = ''
    }
    Write-Host ("[{0}] monitor_chain_shutdown_reset applied=true" -f $ScriptTag)
    return (Read-KeyValueFile -Path $Path)
}

function Get-NormalizedFinalStatus {
    param(
        [System.Collections.IDictionary]$Settings,
        [string]$Key
    )

    if ($null -eq $Settings -or [string]::IsNullOrWhiteSpace($Key) -or -not $Settings.Contains($Key)) {
        return ''
    }

    $raw = [string]$Settings[$Key]
    if ([string]::IsNullOrWhiteSpace($raw)) {
        return ''
    }

    return $raw.Trim().ToUpperInvariant()
}

function Get-NormalizedStatusToken {
    param(
        [AllowEmptyString()][string]$Value,
        [AllowEmptyString()][string]$Default = ''
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $Default
    }

    return $Value.Trim().ToUpperInvariant()
}

function Resolve-RoundFromConfig {
    param(
        [System.Collections.IDictionary]$Settings,
        [string]$Key,
        [int]$DefaultValue
    )

    if ($null -eq $Settings -or -not $Settings.Contains($Key)) {
        return $DefaultValue
    }

    $raw = [string]$Settings[$Key]
    if ([string]::IsNullOrWhiteSpace($raw)) {
        return $DefaultValue
    }

    $parsed = 0
    if (-not [int]::TryParse($raw.Trim(), [ref]$parsed) -or $parsed -lt 1 -or $parsed -gt 8) {
        throw ("{0} in start file must be an integer within [1,8], actual value='{1}'" -f $Key, $raw)
    }

    return $parsed
}

function Update-KeyValueLineList {
    param(
        [string[]]$Lines,
        [System.Collections.IDictionary]$Values,
        [string]$Path
    )

    $seenKeys = @{}
    $lineNo = 0
    foreach ($line in @($Lines)) {
        $lineNo++
        if ($line -match '^([^=]+)=(.*)$') {
            $key = $Matches[1].Trim()
            if ($seenKeys.ContainsKey($key)) {
                throw ("Duplicate key '{0}' detected in {1} at line {2} and line {3}." -f $key, $Path, [int]$seenKeys[$key], $lineNo)
            }

            $seenKeys[$key] = $lineNo
        }
    }

    $buffer = New-Object 'System.Collections.Generic.List[string]'
    foreach ($line in @($Lines)) {
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

    return @($buffer | ForEach-Object { [string]$_ })
}

function Get-AgentTicketQueuePath {
    param(
        [System.Collections.IDictionary]$Settings,
        [AllowEmptyString()][string]$RepoRoot = ''
    )

    $rawPath = ''
    if ($null -ne $Settings -and $Settings.Contains('LOCAL_GUARD_AGENT_QUEUE_PATH')) {
        $rawPath = [string]$Settings.LOCAL_GUARD_AGENT_QUEUE_PATH
    }

    if ([string]::IsNullOrWhiteSpace($rawPath)) {
        $rawPath = 'out\artifacts\ab_agent_queue\agent_tickets.jsonl'
    }

    return (Resolve-RepoPathAllowMissing -Path $rawPath -RepoRoot $RepoRoot)
}

function Test-AgentTicketQueueContainsDedupSuffix {
    param(
        [AllowEmptyString()][string]$QueuePath,
        [AllowEmptyString()][string]$StartFilePath,
        [AllowEmptyString()][string]$EventName,
        [AllowEmptyString()][string]$Signature,
        [ValidateRange(1, 10000)][int]$Tail = 2000
    )

    $signatureCompact = Convert-ToSingleLineText -Text $Signature
    $eventCompact = (Convert-ToSingleLineText -Text $EventName).ToLowerInvariant()
    $resolvedQueuePath = Resolve-RepoPathAllowMissing -Path $QueuePath
    if ([string]::IsNullOrWhiteSpace($signatureCompact) -or
        [string]::IsNullOrWhiteSpace($eventCompact) -or
        [string]::IsNullOrWhiteSpace($resolvedQueuePath) -or
        -not (Test-Path -LiteralPath $resolvedQueuePath)) {
        return $false
    }

    $startFileRelative = (Convert-ToRepoRelativePath -Path $StartFilePath).Replace('\', '/').ToLowerInvariant()
    foreach ($line in @(Get-Content -LiteralPath $resolvedQueuePath -Encoding utf8 -Tail $Tail -ErrorAction SilentlyContinue)) {
        try {
            $ticket = $line | ConvertFrom-Json -ErrorAction Stop
            $ticketEvent = (Convert-ToSingleLineText -Text ([string]$ticket.event)).ToLowerInvariant()
            $ticketStartFile = (Convert-ToSingleLineText -Text ([string]$ticket.start_file)).Replace('\', '/').ToLowerInvariant()
            $ticketDedupSignature = Convert-ToSingleLineText -Text ([string]$ticket.dedup_signature)
            if ($ticketEvent -eq $eventCompact -and
                $ticketStartFile -eq $startFileRelative -and
                $ticketDedupSignature.EndsWith(('|' + $signatureCompact), [System.StringComparison]::Ordinal)) {
                return $true
            }
        }
        catch {
            continue
        }
    }

    return $false
}

function Write-JsonLineWithRetry {
    param(
        [string]$Path,
        [string]$Line
    )

    if ([string]::IsNullOrWhiteSpace($Path) -or [string]::IsNullOrWhiteSpace($Line)) {
        return $false
    }

    $parent = Split-Path -Parent $Path
    if (-not [string]::IsNullOrWhiteSpace($parent) -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }

    $maxAttempts = 6
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        try {
            Add-Content -LiteralPath $Path -Value $Line -Encoding utf8 -ErrorAction Stop
            return $true
        }
        catch {
            if ($attempt -eq $maxAttempts) {
                return $false
            }

            $delayMs = switch ($attempt) {
                1 { 30 }
                2 { 60 }
                3 { 120 }
                4 { 200 }
                default { 300 }
            }
            Start-Sleep -Milliseconds $delayMs
        }
    }

    return $false
}

function Convert-LineListToLfText {
    param(
        [string[]]$Lines,
        [switch]$EnsureTrailingLf
    )

    $normalizedLines = @(@($Lines) | ForEach-Object { [string]$_ })
    $text = [string]::Join("`n", $normalizedLines)
    if ($EnsureTrailingLf.IsPresent -and $normalizedLines.Count -gt 0) {
        $text += "`n"
    }

    return $text
}

function Write-Utf8BomTextFile {
    param(
        [string]$Path,
        [AllowEmptyString()][string]$Text
    )

    [System.IO.File]::WriteAllText($Path, $Text, [System.Text.UTF8Encoding]::new($true))
}

function Invoke-KeyValueFileValueUpdateCore {
    param(
        [string]$Path,
        [System.Collections.IDictionary]$Values,
        [ValidateSet('Copy', 'Move')][string]$CommitMode = 'Move',
        [ValidateRange(1, 64)][int]$ReadMaxAttempts = 1,
        [ValidateRange(1, 64)][int]$WriteMaxAttempts = 1,
        [int[]]$RetryDelayMs = @(50, 100, 200, 400, 800),
        [bool]$RequireExistingFile = $false
    )

    $mutex = New-Object System.Threading.Mutex($false, (Get-StartFileMutexName -StartFilePath $Path))
    $locked = $false
    $tempPath = ''
    try {
        try {
            $locked = $mutex.WaitOne([TimeSpan]::FromSeconds(30))
        }
        catch [System.Threading.AbandonedMutexException] {
            $locked = $true
        }

        if (-not $locked) {
            throw "Failed to acquire start-file write lock within timeout: $Path"
        }

        $sourceLines = @()
        if ($RequireExistingFile -or (Test-Path -LiteralPath $Path)) {
            for ($attempt = 1; $attempt -le $ReadMaxAttempts; $attempt++) {
                try {
                    $sourceLines = @(Get-Content -LiteralPath $Path -Encoding utf8 -ErrorAction Stop)
                    break
                }
                catch {
                    if ($attempt -eq $ReadMaxAttempts) {
                        throw
                    }

                    $delayIndex = [Math]::Min(($attempt - 1), ($RetryDelayMs.Count - 1))
                    $delayMs = if ($RetryDelayMs.Count -gt 0) { [int]$RetryDelayMs[$delayIndex] } else { 200 }
                    Start-Sleep -Milliseconds $delayMs
                }
            }
        }

        $updatedLines = @(Update-KeyValueLineList -Lines $sourceLines -Values $Values -Path $Path)

        for ($attempt = 1; $attempt -le $WriteMaxAttempts; $attempt++) {
            try {
                $tempPath = "$Path.tmp.$PID.$([guid]::NewGuid().ToString('N'))"
                $text = Convert-LineListToLfText -Lines $updatedLines -EnsureTrailingLf
                Write-Utf8BomTextFile -Path $tempPath -Text $text
                if ($CommitMode -eq 'Copy') {
                    Copy-Item -LiteralPath $tempPath -Destination $Path -Force
                    Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue
                }
                else {
                    Move-Item -LiteralPath $tempPath -Destination $Path -Force
                }
                $tempPath = ''
                break
            }
            catch {
                if (-not [string]::IsNullOrWhiteSpace($tempPath) -and (Test-Path -LiteralPath $tempPath)) {
                    Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue
                    $tempPath = ''
                }

                if ($attempt -eq $WriteMaxAttempts) {
                    throw
                }

                $delayIndex = [Math]::Min(($attempt - 1), ($RetryDelayMs.Count - 1))
                $delayMs = if ($RetryDelayMs.Count -gt 0) { [int]$RetryDelayMs[$delayIndex] } else { 200 }
                Start-Sleep -Milliseconds $delayMs
            }
        }
    }
    finally {
        if (-not [string]::IsNullOrWhiteSpace($tempPath) -and (Test-Path -LiteralPath $tempPath)) {
            Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue
        }

        if ($locked) {
            try { $mutex.ReleaseMutex() } catch { Write-Verbose ("Suppressed exception: {0}" -f $_.Exception.Message) }
        }
        $mutex.Dispose()
    }
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
    $repoRootFull = [System.IO.Path]::GetFullPath((Get-UnattendedRepoRoot))
    if ($fullPath.StartsWith($repoRootFull, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $fullPath.Substring($repoRootFull.Length).TrimStart('\\')
    }

    return $fullPath
}

function Test-ProcessAlive {
    param([int]$ProcessId)

    if ($ProcessId -le 0) {
        return $false
    }

    return ($null -ne (Get-Process -Id $ProcessId -ErrorAction SilentlyContinue))
}

function Get-ParsedPositiveInt {
    param([AllowEmptyString()][string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return 0
    }

    $parsed = 0
    if ([int]::TryParse($Value.Trim(), [ref]$parsed) -and $parsed -gt 0) {
        return $parsed
    }

    return 0
}

function Get-LatestAnchorValueFromNoteText {
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

function Get-StartFileLaunchMutexName {
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
    return "Local\whois-monitor-launch-{0}-{1}" -f $Role, $hash
}

function Enter-LaunchMutex {
    param(
        [string]$Role,
        [string]$StartFilePath
    )

    $name = Get-StartFileLaunchMutexName -Role $Role -StartFilePath $StartFilePath
    $mutex = New-Object System.Threading.Mutex($false, $name)
    $acquired = $false
    try {
        try {
            $acquired = $mutex.WaitOne([TimeSpan]::FromSeconds(30))
        }
        catch [System.Threading.AbandonedMutexException] {
            $acquired = $true
        }

        if (-not $acquired) {
            $mutex.Dispose()
            throw "Timed out waiting for monitor launch mutex: $name"
        }
    }
    catch {
        if ($null -ne $mutex) {
            try { $mutex.Dispose() } catch { Write-Verbose ("Suppressed exception: {0}" -f $_.Exception.Message) }
        }
        throw
    }

    return [pscustomobject]@{
        Name = $name
        Mutex = $mutex
        Acquired = $acquired
    }
}

function Exit-LaunchMutex {
    param($Context)

    if ($null -eq $Context -or $null -eq $Context.Mutex) {
        return
    }

    if ([bool]$Context.Acquired) {
        try { $Context.Mutex.ReleaseMutex() | Out-Null } catch { Write-Verbose ("Suppressed exception: {0}" -f $_.Exception.Message) }
    }

    try { $Context.Mutex.Dispose() } catch { Write-Verbose ("Suppressed exception: {0}" -f $_.Exception.Message) }
}

function Get-RunningStartFileProcessIdList {
    param(
        [string]$ScriptLeaf,
        [string]$StartFileIdentity,
        [string]$RepoRoot,
        [int]$CurrentProcessId = 0,
        [AllowEmptyString()][string]$ExcludeCommandLinePattern = ''
    )

    $ids = @(
        Get-CimInstance Win32_Process |
            Where-Object {
                if ($CurrentProcessId -gt 0 -and [int]$_.ProcessId -eq $CurrentProcessId) {
                    return $false
                }

                $commandLine = [string]$_.CommandLine
                if ([string]::IsNullOrWhiteSpace($commandLine)) {
                    return $false
                }

                $line = $commandLine.ToLowerInvariant()
                if (-not $line.Contains($ScriptLeaf)) {
                    return $false
                }

                if (-not [string]::IsNullOrWhiteSpace($ExcludeCommandLinePattern) -and $commandLine -match $ExcludeCommandLinePattern) {
                    return $false
                }

                if ([string]::IsNullOrWhiteSpace($StartFileIdentity)) {
                    return $true
                }

                $processStartFileIdentity = Get-StartFilePathFromCommandLine -CommandLine $commandLine -RepoRoot $RepoRoot
                if ([string]::IsNullOrWhiteSpace($processStartFileIdentity)) {
                    return $false
                }

                return ($processStartFileIdentity -eq $StartFileIdentity)
            } |
            Select-Object -ExpandProperty ProcessId -Unique
    )

    if ($ScriptLeaf -eq 'unattended_ab_session_guard.ps1' -and -not [string]::IsNullOrWhiteSpace([string]$env:AUTO_PARENT_GUARD_PID)) {
        $envParentPid = 0
        if ([int]::TryParse([string]$env:AUTO_PARENT_GUARD_PID, [ref]$envParentPid) -and $envParentPid -gt 0) {
            $envStartFileIdentity = Get-NormalizedPathIdentity -Path ([string]$env:AUTO_PARENT_GUARD_START_FILE) -RepoRoot $RepoRoot
            if (([string]::IsNullOrWhiteSpace($StartFileIdentity) -or $envStartFileIdentity -eq $StartFileIdentity) -and
                    $null -ne (Get-Process -Id $envParentPid -ErrorAction SilentlyContinue) -and
                    ($ids -notcontains $envParentPid)) {
                $ids += $envParentPid
            }
        }
    }

    return @($ids)
}

function Invoke-RunningProcessStop {
    param(
        [int[]]$ProcessIds,
        [switch]$UseTaskkill,
        [ValidateRange(0, 30000)][int]$TaskkillGraceMs = 1500,
        [ValidateRange(1, 120)][int]$WaitTimeoutSec = 15
    )

    $stopped = New-Object 'System.Collections.Generic.List[int]'
    foreach ($targetPid in @($ProcessIds | Sort-Object -Unique)) {
        if ($targetPid -le 0) {
            continue
        }

        try {
            if ($UseTaskkill.IsPresent) {
                $null = & 'taskkill.exe' '/PID', ([string]$targetPid) 2>&1
                if ($TaskkillGraceMs -gt 0) {
                    Start-Sleep -Milliseconds $TaskkillGraceMs
                }
            }

            if ($null -ne (Get-Process -Id $targetPid -ErrorAction SilentlyContinue)) {
                Stop-Process -Id $targetPid -Force -ErrorAction Stop
            }
            Wait-Process -Id $targetPid -Timeout $WaitTimeoutSec -ErrorAction SilentlyContinue
            [void]$stopped.Add([int]$targetPid)
        }
        catch { Write-Verbose ("Suppressed exception: {0}" -f $_.Exception.Message) }
    }

    return @($stopped)
}

function Get-LatestAnchorValueFromNoteLog {
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

function Get-AnchorValueFromConfig {
    param(
        [System.Collections.IDictionary]$Settings,
        [string]$Key
    )

    if ($null -eq $Settings -or [string]::IsNullOrWhiteSpace($Key)) {
        return ''
    }

    if (-not $Settings.Contains('SESSION_FINAL_NOTES')) {
        return ''
    }

    return Get-LatestAnchorValueFromNoteLog -Notes ([string]$Settings.SESSION_FINAL_NOTES) -Key $Key
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
        $afterValue = [datetime]$After
        $threshold = if ($afterValue -le [datetime]::MinValue.AddSeconds(2)) {
            [datetime]::MinValue
        }
        else {
            $afterValue.AddSeconds(-2)
        }

        $dirs = @($dirs | Where-Object { $_.CreationTime -ge $threshold -or $_.LastWriteTime -ge $threshold })
    }

    $candidates = @($dirs | Sort-Object CreationTime, LastWriteTime -Descending | Select-Object -First 1)
    if ($candidates.Count -lt 1) {
        return $null
    }

    return $candidates[0]
}

function Get-LatestDevVerifyMultiroundFinalStatus {
    param(
        [string]$RepoRoot,
        [Nullable[datetime]]$After = $null
    )

    $result = [ordered]@{
        Available = $false
        OutDir = ''
        FinalStatusPath = ''
        Result = ''
        ExitCode = -1
        FailurePhase = ''
        FailureKind = ''
        FailureCategory = ''
        FailureSourceLog = ''
        FailedRoundTags = ''
        FailedRoundDecision = ''
        FailedRoundReason = ''
        EffectiveFailureCategory = ''
        EffectiveFailureReason = ''
        Error = ''
    }

    $root = Join-Path $RepoRoot 'out\artifacts\dev_verify_multiround'
    $latestDir = Get-LatestTimestampedDirectory -Root $root -After $After
    if ($null -eq $latestDir) {
        $result.Error = 'latest-run-dir-missing'
        return [pscustomobject]$result
    }

    $finalStatusPath = Join-Path $latestDir.FullName 'final_status.json'
    $result.OutDir = Convert-ToRepoRelativePath -Path $latestDir.FullName -RepoRoot $RepoRoot
    $result.FinalStatusPath = Convert-ToRepoRelativePath -Path $finalStatusPath -RepoRoot $RepoRoot
    if (-not (Test-Path -LiteralPath $finalStatusPath)) {
        $result.Error = 'final-status-missing'
        return [pscustomobject]$result
    }

    try {
        $payload = Get-Content -LiteralPath $finalStatusPath -Raw -Encoding utf8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        if ($null -eq $payload) {
            $result.Error = 'final-status-empty'
            return [pscustomobject]$result
        }

        $result.Available = $true
        $result.Result = (Convert-ToSingleLineText -Text ([string]$payload.Result)).ToLowerInvariant()
        $exitCode = -1
        if ([int]::TryParse(([string]$payload.ExitCode), [ref]$exitCode)) {
            $result.ExitCode = [int]$exitCode
        }
        $result.FailurePhase = (Convert-ToSingleLineText -Text ([string]$payload.FailurePhase)).ToLowerInvariant()
        $result.FailureKind = (Convert-ToSingleLineText -Text ([string]$payload.FailureKind)).ToLowerInvariant()
        $result.FailureCategory = (Convert-ToSingleLineText -Text ([string]$payload.FailureCategory)).ToLowerInvariant()
        $result.FailureSourceLog = Convert-ToSingleLineText -Text ([string]$payload.FailureSourceLog)
        $result.FailedRoundDecision = Convert-ToSingleLineText -Text ([string]$payload.FailedRoundDecision)
        $result.FailedRoundReason = Convert-ToSingleLineText -Text ([string]$payload.FailedRoundReason)

        $roundTags = @()
        if ($payload.PSObject.Properties.Name -contains 'FailedRoundTags' -and $null -ne $payload.FailedRoundTags) {
            $roundTags = @($payload.FailedRoundTags | ForEach-Object { Convert-ToSingleLineText -Text ([string]$_) } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        }
        $result.FailedRoundTags = ($roundTags -join ',')

        $effectiveCategory = [string]$result.FailureCategory
        if ([string]::IsNullOrWhiteSpace($effectiveCategory)) {
            switch ([string]$result.FailureKind) {
                'task-definition-mismatch' { $effectiveCategory = 'task-definition-mismatch' }
                'environment-transient' { $effectiveCategory = 'noncode-transient' }
                'verify-failure' { $effectiveCategory = 'code-or-unknown' }
                'compile-failure' { $effectiveCategory = 'code-or-unknown' }
                'compile-warning' { $effectiveCategory = 'code-or-unknown' }
                'compile-or-test-failure' { $effectiveCategory = 'code-or-unknown' }
                default {
                    if ([string]$result.FailurePhase -eq 'code-step') {
                        $effectiveCategory = 'noncode-transient'
                    }
                    elseif ([string]$result.FailurePhase -eq 'round-gate') {
                        $effectiveCategory = 'noncode-transient'
                    }
                    else {
                        $effectiveCategory = 'runner-fail'
                    }
                }
            }
        }
        $result.EffectiveFailureCategory = $effectiveCategory

        $reasonParts = New-Object 'System.Collections.Generic.List[string]'
        [void]$reasonParts.Add(('multiround_result={0}' -f [string]$result.Result))
        [void]$reasonParts.Add(('multiround_exit={0}' -f [int]$result.ExitCode))
        if (-not [string]::IsNullOrWhiteSpace([string]$result.FailurePhase)) { [void]$reasonParts.Add(('failure_phase={0}' -f [string]$result.FailurePhase)) }
        if (-not [string]::IsNullOrWhiteSpace([string]$result.FailureKind)) { [void]$reasonParts.Add(('failure_kind={0}' -f [string]$result.FailureKind)) }
        if (-not [string]::IsNullOrWhiteSpace([string]$result.EffectiveFailureCategory)) { [void]$reasonParts.Add(('failure_category={0}' -f [string]$result.EffectiveFailureCategory)) }
        if (-not [string]::IsNullOrWhiteSpace([string]$result.FailedRoundTags)) { [void]$reasonParts.Add(('failed_rounds={0}' -f [string]$result.FailedRoundTags)) }
        if (-not [string]::IsNullOrWhiteSpace([string]$result.FailureSourceLog)) { [void]$reasonParts.Add(('source={0}' -f [string]$result.FailureSourceLog)) }
        [void]$reasonParts.Add(('final_status={0}' -f [string]$result.FinalStatusPath))
        $result.EffectiveFailureReason = ($reasonParts -join ' ')
    }
    catch {
        $result.Error = Convert-ToSingleLineText -Text $_.Exception.Message
    }

    return [pscustomobject]$result
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