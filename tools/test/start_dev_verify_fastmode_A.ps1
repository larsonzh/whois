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

function Read-KeyValueFile {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw 'Start file path is empty.'
    }
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Start file not found: $Path"
    }

    $keyLineMap = @{}
    $map = [ordered]@{}
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

    Write-Output ("[FASTMODE-{0}] stage_window_guard start_file={1} task={2}" -f $Stage, $startFilePath, $TaskDefinitionRelative)
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
        [string[]]$ObservedCheckLines
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
        $stageTag = ''
        if ($RoleTag -match 'FASTMODE-([A-Za-z0-9]+)') {
            $stageTag = $Matches[1]
        }

        $sceneCapture = Save-RemoteLockScene -RepoRoot $RepoRoot -RoleTag $RoleTag -StageTag $stageTag -RemoteIp $RemoteIp -RemoteUser $RemoteUser -KeyPath $KeyPath -LockScope $LockScope -ConflictAction $ConflictAction -ObservedCheckLines $lines
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
        $resolvedKeyPath = Resolve-RemoteKeyPathForLock -KeyPath $KeyPath
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

function Convert-ToSingleLineText {
    param([AllowEmptyString()][string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return ''
    }

    $singleLine = (($Text -split "`r?`n") -join ' ')
    return ([regex]::Replace($singleLine, '\s+', ' ')).Trim()
}

function Convert-ToRepoRelativePath {
    param(
        [AllowEmptyString()][string]$Path,
        [string]$RepoRoot
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return ''
    }

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $repoRootFull = [System.IO.Path]::GetFullPath($RepoRoot)
    if ($fullPath.StartsWith($repoRootFull, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $fullPath.Substring($repoRootFull.Length).TrimStart('\\').Replace('\\', '/')
    }

    return $fullPath.Replace('\\', '/')
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
        [AllowEmptyString()][string]$FailureReason
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
            source_script = (Split-Path -Leaf $PSCommandPath)
            start_file_path = $startFilePath
        }

        $json = $record | ConvertTo-Json -Depth 8
        $json | Set-Content -LiteralPath $historyFile -Encoding utf8
        $json | Set-Content -LiteralPath $latestFile -Encoding utf8

        Write-Output ("[{0}] exit_reason_file={1}" -f $ScriptTag, (Convert-ToRepoRelativePath -Path $historyFile -RepoRoot $RepoRoot))
        Write-Output ("[{0}] exit_reason_latest={1}" -f $ScriptTag, (Convert-ToRepoRelativePath -Path $latestFile -RepoRoot $RepoRoot))
    }
    catch {
        Write-Output ("[{0}] exit_reason_write_failed detail={1}" -f $ScriptTag, (Convert-ToSingleLineText -Text $_.Exception.Message))
    }
}

function Get-FastmodeFailureCategory {
    param([AllowEmptyString()][string]$Message)

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

    return 'runtime-fail'
}

function Exit-FastmodeProcess {
    param([int]$Code)

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
    if ($keepWindowOnExit -and -not [string]::IsNullOrWhiteSpace($line) -and $line.Contains('-noexit') -and $line.Contains('start_dev_verify_fastmode_a.ps1')) {
        $global:LASTEXITCODE = $Code
        Write-Output ("[FASTMODE-A] keep_window_on_exit=true exit_code={0} action=return_to_prompt" -f $Code)
        return
    }

    if (-not [string]::IsNullOrWhiteSpace($line) -and $line.Contains('-noexit') -and $line.Contains('start_dev_verify_fastmode_a.ps1')) {
        [System.Environment]::Exit($Code)
    }

    exit $Code
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
Set-Location $repoRoot

$runMutexContext = $null
$mainRunMutexContext = $null
$exitCode = 1
$failureCategory = ''
$failureReason = ''

try {
    $taskDefinitionRelative = Resolve-TaskDefinitionRelativePath -InputName $TaskDefinitionFileName
    Assert-StageWindowInvocation -Stage 'A' -TaskDefinitionRelative $taskDefinitionRelative
    $startFilePathForGate = Resolve-StartFilePathFromEnv
    Invoke-StartFieldSyncStrictGate -RepoRoot $repoRoot -RoleTag 'FASTMODE-A' -StartFilePath $startFilePathForGate
    Invoke-StatusTicketMiniRegressionGate -RepoRoot $repoRoot -RoleTag 'FASTMODE-A'
    Invoke-IncrementalEncodingFixGate -RepoRoot $repoRoot -RoleTag 'FASTMODE-A'
    Invoke-SrcCodeEncodingFixGate -RepoRoot $repoRoot -RoleTag 'FASTMODE-A'

    $existingRunPids = @(Get-RunningFastmodeProcessIdList -Role 'A' -RepoRoot $repoRoot -ExcludePid $PID)
    if ($existingRunPids.Count -gt 0) {
        Write-Output ("[FASTMODE-A] restart_precheck existing_count={0} existing_pids={1}" -f $existingRunPids.Count, ($existingRunPids -join ','))
        $stoppedRunPids = @(Invoke-RunningFastmodeProcessStop -ProcessIds $existingRunPids)
        Write-Output ("[FASTMODE-A] restart_precheck stopped_count={0} stopped_pids={1}" -f $stoppedRunPids.Count, ($stoppedRunPids -join ','))
    }
    else {
        Write-Output '[FASTMODE-A] restart_precheck existing_count=0'
    }

    $mainRunMutexContext = Enter-MainRunMutex -RepoRoot $repoRoot
    Write-Output ("[FASTMODE-A] main_run_mutex={0}" -f [string]$mainRunMutexContext.Name)

    $runMutexContext = Enter-RunMutex -Role 'A' -RepoRoot $repoRoot
    Write-Output ("[FASTMODE-A] run_mutex={0}" -f [string]$runMutexContext.Name)
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
    $taskStaticPrecheckFailOnWarnings = Convert-ToBooleanSetting -Value ([string]$env:AUTO_TASK_STATIC_PRECHECK_FAIL_ON_WARNINGS) -Default $true

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

    Write-Output '[FASTMODE-A] stage_banner stage=A reset_policy=restore-source restart_baseline=repo-baseline stage_window_only=true'
    Write-Output ("[FASTMODE-A] task_definition={0}" -f $taskDefinitionRelative)

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
        -TaskStaticPrecheckFailOnWarnings $taskStaticPrecheckFailOnWarnings `
        -TaskDesignQualityPolicy enforce `
        -UnknownNoOpBudget 1 -UnknownNoOpConsecutiveLimit 2 `
        -DisableUnknownNoOpBudgetGate:$false `
        -KeyPath $keyPath -RemoteIp $remoteIp -User $remoteUser -Queries $queries

    $exitCode = if ($null -eq $LASTEXITCODE) { 0 } else { [int]$LASTEXITCODE }
    if ($exitCode -ne 0) {
        $failureCategory = 'runner-fail'
        $failureReason = "start_dev_verify_8round_multiround exited with code=$exitCode"
    }
}
catch {
    $failureReason = Convert-ToSingleLineText -Text $_.Exception.Message
    $failureCategory = Get-FastmodeFailureCategory -Message $failureReason

    $exitCode = 1
    Write-Output ("[FASTMODE-A] gate_fail category={0} reason={1}" -f $failureCategory, $failureReason)
}
finally {
    if ($null -ne $runMutexContext -and $null -ne $runMutexContext.Mutex) {
        try {
            $runMutexContext.Mutex.ReleaseMutex() | Out-Null
        }
        catch { Write-Verbose ("Suppressed exception: {0}" -f $_.Exception.Message) }
        finally {
            $runMutexContext.Mutex.Dispose()
        }
    }

    if ($null -ne $mainRunMutexContext -and $null -ne $mainRunMutexContext.Mutex) {
        try {
            $mainRunMutexContext.Mutex.ReleaseMutex() | Out-Null
        }
        catch { Write-Verbose ("Suppressed exception: {0}" -f $_.Exception.Message) }
        finally {
            $mainRunMutexContext.Mutex.Dispose()
        }
    }
}

if ($exitCode -ne 0) {
    if ([string]::IsNullOrWhiteSpace($failureCategory)) {
        $failureCategory = 'runtime-fail'
    }
    if ([string]::IsNullOrWhiteSpace($failureReason)) {
        $failureReason = 'fastmode-a failed without explicit reason'
    }

    Write-Output ("[FASTMODE-A] fail_reason category={0} detail={1}" -f $failureCategory, $failureReason)
    Write-Output ("A_FAIL_CATEGORY={0}" -f $failureCategory)
    Write-Output ("A_FAIL_REASON={0}" -f $failureReason)
}

$exitResult = if ($exitCode -eq 0) { 'pass' } else { 'fail' }
Write-StageExitReasonArtifact -RepoRoot $repoRoot -Stage 'A' -ScriptTag 'FASTMODE-A' -TaskDefinitionFile $TaskDefinitionFileName -Result $exitResult -ExitCode $exitCode -FailureCategory $failureCategory -FailureReason $failureReason

Write-Output ("A_EXIT={0}" -f $exitCode)
Exit-FastmodeProcess -Code $exitCode
