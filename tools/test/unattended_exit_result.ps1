Set-StrictMode -Version Latest

. (Join-Path $PSScriptRoot 'unattended_startfile_identity.ps1')

function Convert-ToSingleLineTextForMonitorChain {
    param([AllowEmptyString()][string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return ''
    }

    $singleLine = (($Text -split "`r?`n") -join ' ')
    return ([regex]::Replace($singleLine, '\s+', ' ')).Trim()
}

function Get-TriggerRestartRequestFromStartFile {
    param([string]$StartFilePath)

    $result = [ordered]@{
        Requested = $false
        Reason = ''
        Source = ''
        RequestedAt = ''
    }

    if ([string]::IsNullOrWhiteSpace($StartFilePath) -or -not (Test-Path -LiteralPath $StartFilePath)) {
        return [pscustomobject]$result
    }

    try {
        $settings = Read-KeyValueFile -Path $StartFilePath
        if ($null -ne $settings -and $settings.Contains('TRIGGER_RESTART_REQUESTED')) {
            $requestedRaw = [string]$settings.TRIGGER_RESTART_REQUESTED
            $result.Requested = Convert-ToBooleanSetting -Value $requestedRaw -Default $false
        }
        if ($null -ne $settings -and $settings.Contains('TRIGGER_RESTART_REQUEST_REASON')) {
            $result.Reason = Convert-ToSingleLineTextForMonitorChain -Text ([string]$settings.TRIGGER_RESTART_REQUEST_REASON)
        }
        if ($null -ne $settings -and $settings.Contains('TRIGGER_RESTART_REQUEST_SOURCE')) {
            $result.Source = Convert-ToSingleLineTextForMonitorChain -Text ([string]$settings.TRIGGER_RESTART_REQUEST_SOURCE)
        }
        if ($null -ne $settings -and $settings.Contains('TRIGGER_RESTART_REQUEST_AT')) {
            $result.RequestedAt = Convert-ToSingleLineTextForMonitorChain -Text ([string]$settings.TRIGGER_RESTART_REQUEST_AT)
        }
    }
    catch {
        return [pscustomobject]$result
    }

    return [pscustomobject]$result
}

function Request-TriggerRestartInStartFile {
    param(
        [string]$StartFilePath,
        [AllowEmptyString()][string]$Reason,
        [AllowEmptyString()][string]$Source
    )

    if ([string]::IsNullOrWhiteSpace($StartFilePath) -or -not (Test-Path -LiteralPath $StartFilePath)) {
        return $false
    }

    $reasonText = Convert-ToSingleLineTextForMonitorChain -Text $Reason
    if ([string]::IsNullOrWhiteSpace($reasonText)) {
        $reasonText = 'trigger-healthcheck-missing'
    }

    $sourceText = Convert-ToSingleLineTextForMonitorChain -Text $Source
    if ([string]::IsNullOrWhiteSpace($sourceText)) {
        $sourceText = 'monitor-chain-healthcheck'
    }

    try {
        Invoke-KeyValueFileValueUpdateCore -Path $StartFilePath -Values @{
            TRIGGER_RESTART_REQUESTED = 'true'
            TRIGGER_RESTART_REQUEST_REASON = $reasonText
            TRIGGER_RESTART_REQUEST_SOURCE = $sourceText
            TRIGGER_RESTART_REQUEST_AT = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        }
        return $true
    }
    catch {
        return $false
    }
}

function Write-TriggerLastActionInStartFile {
    param(
        [string]$StartFilePath,
        [AllowEmptyString()][string]$Action,
        [AllowEmptyString()][string]$ActionBy,
        [AllowEmptyString()][string]$Detail,
        [bool]$ClearRequest = $false
    )

    if ([string]::IsNullOrWhiteSpace($StartFilePath) -or -not (Test-Path -LiteralPath $StartFilePath)) {
        return $false
    }

    $actionText = Convert-ToSingleLineTextForMonitorChain -Text $Action
    if ([string]::IsNullOrWhiteSpace($actionText)) {
        $actionText = 'unknown'
    }

    $actionByText = Convert-ToSingleLineTextForMonitorChain -Text $ActionBy
    if ([string]::IsNullOrWhiteSpace($actionByText)) {
        $actionByText = 'monitor-chain'
    }

    $detailText = Convert-ToSingleLineTextForMonitorChain -Text $Detail

    $updates = @{
        TRIGGER_LAST_ACTION = $actionText
        TRIGGER_LAST_ACTION_AT = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        TRIGGER_LAST_ACTION_BY = $actionByText
        TRIGGER_LAST_ACTION_DETAIL = $detailText
    }

    if ($ClearRequest) {
        $updates['TRIGGER_RESTART_REQUESTED'] = 'false'
        $updates['TRIGGER_RESTART_REQUEST_REASON'] = ''
        $updates['TRIGGER_RESTART_REQUEST_SOURCE'] = ''
        $updates['TRIGGER_RESTART_REQUEST_AT'] = ''
    }

    try {
        Invoke-KeyValueFileValueUpdateCore -Path $StartFilePath -Values $updates
        return $true
    }
    catch {
        return $false
    }
}

function Test-IsGuardArbitratorContext {
    $tag = ''
    try {
        $tag = [string]$script:UnhandledExitTag
    }
    catch {
        $tag = ''
    }

    return ($tag -eq 'UNATTENDED-AB-SESSION-GUARD')
}

function Test-RoleProcessTrulyAlive {
    param(
        [string]$Role,
        [object[]]$Processes,
        [string]$RepoRoot
    )

    foreach ($proc in @($Processes)) {
        $cmdLine = [string]$proc.CommandLine
        if ([string]::IsNullOrWhiteSpace($cmdLine)) { continue }

        $procStartTime = $null
        try {
            if ($null -ne $proc.PSObject.Properties['CreationDate'] -and -not [string]::IsNullOrWhiteSpace([string]$proc.CreationDate)) {
                $procStartTime = [System.Management.ManagementDateTimeConverter]::ToDateTime([string]$proc.CreationDate)
            }
        }
        catch {
            $procStartTime = $null
        }

        # Derive state file path from role and start-file
        $roleStateRoot = switch ($Role) {
            'guard'      { Join-Path $RepoRoot 'out\artifacts\ab_session_guard' }
            'trigger'    { Join-Path $RepoRoot 'out\artifacts\ab_agent_queue' }
            default      { '' }
        }
        if ([string]::IsNullOrWhiteSpace($roleStateRoot)) { return $true }  # unknown role: assume alive

        # Find the state file by scanning for the latest timestamped directory
        $stateFileName = switch ($Role) {
            'guard'      { 'guard_state.json' }
            'trigger'    { $null }  # handled separately below
        }

        $statePath = ''
        $pollSecDetected = 30
        if ($Role -eq 'trigger') {
            # Trigger: extract start-file hash from any matching process command line
            $sfMatch = [regex]::Match($cmdLine, '-StartFile\s+"([^"]+)"')
            if (-not $sfMatch.Success) { $sfMatch = [regex]::Match($cmdLine, '-StartFile\s+(\S+)') }
            if ($sfMatch.Success) {
                $triggerStartFile = $sfMatch.Groups[1].Value.Trim('"')
                $fullPath = if ([System.IO.Path]::IsPathRooted($triggerStartFile)) {
                    [System.IO.Path]::GetFullPath($triggerStartFile)
                }
                else {
                    [System.IO.Path]::GetFullPath((Join-Path $RepoRoot $triggerStartFile))
                }
                $stableToken = Get-StableStartFileToken -StartFilePath $fullPath
                $legacyToken = Get-LegacyStartFileToken -StartFilePath $fullPath

                foreach ($candidateStatePath in @(
                    (Join-Path $roleStateRoot ("takeover_trigger_state_{0}.json" -f $stableToken)),
                    (Join-Path $roleStateRoot ("takeover_trigger_state_{0}.json" -f $legacyToken))
                )) {
                    if (Test-Path -LiteralPath $candidateStatePath) {
                        $statePath = $candidateStatePath
                        break
                    }
                }

                $pollMatch = [regex]::Match($cmdLine, '-PollSec\s+(\d+)')
                if ($pollMatch.Success) {
                    $parsedPoll = 0
                    if ([int]::TryParse($pollMatch.Groups[1].Value, [ref]$parsedPoll) -and $parsedPoll -gt 0) {
                        $pollSecDetected = $parsedPoll
                    }
                }
            }
            if ([string]::IsNullOrWhiteSpace($statePath) -or -not (Test-Path -LiteralPath $statePath)) {
                return $true  # Can't find state file, assume alive
            }
        }
        else {
            # Guard: scan for the latest timestamped subdirectory
            if (Test-Path -LiteralPath $roleStateRoot) {
                $dirs = @(Get-ChildItem -LiteralPath $roleStateRoot -Directory -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -match '^\d{8}-\d{6}$' } |
                    Sort-Object LastWriteTime -Descending)
                foreach ($dir in $dirs) {
                    $candidate = Join-Path $dir.FullName $stateFileName
                    if (Test-Path -LiteralPath $candidate) {
                        $statePath = $candidate
                        break
                    }
                }
            }
            if ([string]::IsNullOrWhiteSpace($statePath)) {
                return $true  # No state file found, assume alive
            }
        }

        $stateLastWriteTime = $null
        try {
            if (Test-Path -LiteralPath $statePath) {
                $stateLastWriteTime = (Get-Item -LiteralPath $statePath -ErrorAction SilentlyContinue).LastWriteTime
            }
        }
        catch {
            $stateLastWriteTime = $null
        }

        $statePredatesProcessStart = $false
        if ($null -ne $procStartTime -and $null -ne $stateLastWriteTime) {
            # Small tolerance to avoid clock jitter false positives.
            $statePredatesProcessStart = (($procStartTime - $stateLastWriteTime).TotalSeconds -gt 2)
        }

        # Read state file and check for terminal markers
        try {
            $rawState = Get-Content -LiteralPath $statePath -Raw -Encoding utf8 -ErrorAction SilentlyContinue
            if (-not [string]::IsNullOrWhiteSpace($rawState)) {
                $lowerState = $rawState.ToLowerInvariant()

                # JSON state file terminal markers (guard/trigger)
                if ($lowerState -match '"status":\s*"stopped"' -or
                    $lowerState -match '"status":\s*"shutdown"' -or
                    $lowerState -match '"status":\s*"fail"' -or
                    $lowerState -match '"event":\s*"shutdown"') {
                    if ($statePredatesProcessStart) {
                        # The state file still contains the previous instance terminal marker.
                        # Give the newly spawned process a short warm-up grace window to refresh state.
                        $warmupWindowSec = switch ($Role) {
                            'trigger' { [Math]::Max(45, $pollSecDetected + 15) }
                            'guard' { 45 }
                            default { 30 }
                        }
                        if ($null -ne $procStartTime) {
                            $procAgeSec = (Get-Date - $procStartTime).TotalSeconds
                            if ($procAgeSec -le $warmupWindowSec) {
                                return $true
                            }
                        }
                    }
                    continue  # This instance terminated, check next process
                }


            }
        }
        catch { $null = $_ }

        # Staleness check: if the state/log file hasn't been updated within the
        # threshold, the script has likely terminated (empty -NoExit shell).
        # This catch-all covers killed/crashed processes that couldn't write
        # terminal markers.
        $staleThreshold = switch ($Role) {
            'guard'      { 300 }
            # For trigger, align with launcher rule: 3x poll interval + 10s margin.
            # This keeps healthy idle loops reusable while classifying empty shells
            # as zombies for cleanup/restart.
            'trigger'    { (3 * $pollSecDetected) + 10 }
            default      { 0 }
        }
        if ($staleThreshold -gt 0) {
            $now = Get-Date
            $fileAge = ($now - (Get-Item -LiteralPath $statePath -ErrorAction SilentlyContinue).LastWriteTime).TotalSeconds

            if ($statePredatesProcessStart -and $null -ne $procStartTime) {
                $warmupWindowSec = switch ($Role) {
                    'trigger' { [Math]::Max(45, $pollSecDetected + 15) }
                    'guard' { 45 }
                    default { 30 }
                }
                $procAgeSec = ($now - $procStartTime).TotalSeconds
                if ($procAgeSec -le $warmupWindowSec) {
                    return $true
                }
            }

            if ($fileAge -gt $staleThreshold) {
                continue  # State file stale -> script terminated, treat as zombie
            }
        }

        # Found an alive process
        return $true
    }

    return $false  # All matching processes appear to be zombies
}

function Invoke-MonitorChainHealthCheck {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Roles,
        [Parameter(Mandatory = $true)]
        [string]$RepoRoot,
        [Parameter(Mandatory = $true)]
        [string]$StartFilePath,
        [string]$LogPrefix = 'health_check',
        [bool]$GuardArbitratedTrigger = $true,
        [bool]$ForceTriggerRestartOnRequest = $false
    )

    $roleMap = @(
        @{ n = 'guard';      p = 'tools/test/open_unattended_ab_session_guard_window.ps1'; s = 'unattended_ab_session_guard.ps1' }
        @{ n = 'trigger';    p = 'tools/test/open_unattended_ab_takeover_trigger_window.ps1'; s = 'unattended_ab_takeover_trigger.ps1' }
    )

    # Normalize start file identity for single-instance matching
    $startFileIdentity = try {
        $resolved = if ([System.IO.Path]::IsPathRooted($StartFilePath)) {
            [System.IO.Path]::GetFullPath($StartFilePath)
        }
        else {
            [System.IO.Path]::GetFullPath((Join-Path $RepoRoot $StartFilePath))
        }
        $resolved.ToLowerInvariant()
    } catch { '' }

    foreach ($role in $Roles) {
        $rn = $role.Trim().ToLowerInvariant()
        $entry = $roleMap | Where-Object { $_.n -eq $rn } | Select-Object -First 1
        if ($null -eq $entry) { continue }

        $isGuardContext = Test-IsGuardArbitratorContext

        $scriptLeaf = [string]$entry.s
        $found = @(Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -ErrorAction SilentlyContinue | Where-Object {
            $procCmdLine = [string]$_.CommandLine
            if ([string]::IsNullOrWhiteSpace($procCmdLine)) { return $false }
            if (-not $procCmdLine.ToLowerInvariant().Contains($scriptLeaf)) { return $false }
            if ([string]::IsNullOrWhiteSpace($startFileIdentity)) { return $true }

            # Single-instance check: filter by start file identity
            $sfMatch = [regex]::Match($procCmdLine, '-StartFile\s+"([^"]+)"')
            if (-not $sfMatch.Success) { $sfMatch = [regex]::Match($procCmdLine, '-StartFile\s+(\S+)') }
            if (-not $sfMatch.Success) { return $false }

            $procStartFile = $sfMatch.Groups[1].Value
            $procStartFileNormalized = try {
                $candidateStartFile = if ([System.IO.Path]::IsPathRooted($procStartFile)) {
                    [System.IO.Path]::GetFullPath($procStartFile)
                }
                else {
                    [System.IO.Path]::GetFullPath((Join-Path $RepoRoot $procStartFile))
                }
                $candidateStartFile.ToLowerInvariant()
            } catch { return $false }
            return ($procStartFileNormalized -eq $startFileIdentity)
        })

        if (@($found).Count -gt 0) {
            # PID found — verify it's not a zombie (script terminated but -NoExit shell alive).
            # Check known state files for terminal markers.
            $trulyAlive = Test-RoleProcessTrulyAlive -Role $rn -Processes $found -RepoRoot $RepoRoot
            if (-not $trulyAlive) {
                Write-Output ("[{0}] timestamp={1} role={2} action=zombie-detected count={3}" -f $LogPrefix, (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'), $rn, @($found).Count)
                # Kill zombie processes before clearing, preventing empty-shell accumulation
                foreach ($zombieProc in @($found)) {
                    $zpid = [int]$zombieProc.ProcessId
                    try {
                        Stop-Process -Id $zpid -Force -ErrorAction SilentlyContinue
                        Write-Output ("[{0}] timestamp={1} role={2} action=zombie-killed pid={3}" -f $LogPrefix, (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'), $rn, $zpid)
                    }
                    catch {
                        Write-Output ("[{0}] timestamp={1} role={2} action=zombie-kill-failed pid={3}" -f $LogPrefix, (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'), $rn, $zpid)
                    }
                }
                $found = @()  # Force restart below
            }
        }

        if (@($found).Count -eq 0) {
            $preferDirectTriggerRestart = (
                $rn -eq 'trigger' -and
                -not $isGuardContext -and
                [string]$LogPrefix -eq 'DEV-VERIFY-MULTI'
            )

            if ($rn -eq 'trigger' -and $isGuardContext) {
                # Guard-side relaxed reuse probe: strict start-file binding can miss in transient
                # command-line normalization windows; if any trigger instance is alive, reuse it.
                $guardRelaxedCandidates = @(Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -ErrorAction SilentlyContinue | Where-Object {
                    $probeCmdLine = [string]$_.CommandLine
                    if ([string]::IsNullOrWhiteSpace($probeCmdLine)) { return $false }
                    $probeCmdLine.ToLowerInvariant().Contains('unattended_ab_takeover_trigger.ps1')
                })

                $guardRelaxedAlive = Test-RoleProcessTrulyAlive -Role $rn -Processes $guardRelaxedCandidates -RepoRoot $RepoRoot
                if ($guardRelaxedAlive) {
                    $requestState = Get-TriggerRestartRequestFromStartFile -StartFilePath $StartFilePath
                    if ([bool]$requestState.Requested) {
                        $requestDetail = ('request_source={0} request_reason={1} fallback=guard-relaxed-reuse' -f [string]$requestState.Source, [string]$requestState.Reason)
                        $null = Write-TriggerLastActionInStartFile -StartFilePath $StartFilePath -Action 'trigger-alive-request-cleared' -ActionBy 'guard' -Detail $requestDetail -ClearRequest $true
                    }
                    Write-Output ("[{0}] timestamp={1} role={2} action=request-cleared-no-restart reason=guard-relaxed-reuse" -f $LogPrefix, (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'), $rn)
                    continue
                }
            }

            if ($rn -eq 'trigger' -and $isGuardContext -and $ForceTriggerRestartOnRequest) {
                $requestState = Get-TriggerRestartRequestFromStartFile -StartFilePath $StartFilePath
                $isStageBootstrapRequest = (
                    [bool]$requestState.Requested -and
                    ([string]$requestState.Source -eq 'open_unattended_ab_stage_window.ps1') -and
                    ([string]$requestState.Reason -like '*monitor_chain_bootstrap*')
                )

                if ($isStageBootstrapRequest) {
                    # Fallback reuse probe: if strict start-file matching misses but any trigger instance
                    # is still alive, treat this bootstrap request as stale and clear it without restart.
                    $relaxedCandidates = @(Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -ErrorAction SilentlyContinue | Where-Object {
                        $probeCmdLine = [string]$_.CommandLine
                        if ([string]::IsNullOrWhiteSpace($probeCmdLine)) { return $false }
                        $probeCmdLine.ToLowerInvariant().Contains('unattended_ab_takeover_trigger.ps1')
                    })

                    $relaxedAlive = Test-RoleProcessTrulyAlive -Role $rn -Processes $relaxedCandidates -RepoRoot $RepoRoot
                    if ($relaxedAlive) {
                        $requestDetail = ('request_source={0} request_reason={1} fallback=relaxed-probe' -f [string]$requestState.Source, [string]$requestState.Reason)
                        $null = Write-TriggerLastActionInStartFile -StartFilePath $StartFilePath -Action 'trigger-alive-bootstrap-request-cleared' -ActionBy 'guard' -Detail $requestDetail -ClearRequest $true
                        Write-Output ("[{0}] timestamp={1} role={2} action=request-cleared-no-restart reason=bootstrap-request-while-alive-relaxed" -f $LogPrefix, (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'), $rn)
                        continue
                    }
                }
            }

            if ($GuardArbitratedTrigger -and $rn -eq 'trigger' -and -not $isGuardContext -and -not $preferDirectTriggerRestart) {
                $requestSource = $LogPrefix
                $requestReason = ('role=trigger missing_process start_file={0}' -f $StartFilePath)
                $requested = Request-TriggerRestartInStartFile -StartFilePath $StartFilePath -Reason $requestReason -Source $requestSource
                if ($requested) {
                    Write-Output ("[{0}] timestamp={1} role={2} action=requested-via-guard source={3}" -f $LogPrefix, (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'), $rn, $requestSource)
                }
                else {
                    Write-Output ("[{0}] timestamp={1} role={2} action=request-failed source={3}" -f $LogPrefix, (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'), $rn, $requestSource)
                }
                continue
            }

            if ($preferDirectTriggerRestart) {
                Write-Output ("[{0}] timestamp={1} role={2} action=restart-direct source=DEV-VERIFY-MULTI" -f $LogPrefix, (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'), $rn)
            }

            $launcherPath = Join-Path $RepoRoot ([string]$entry.p)
            if (Test-Path -LiteralPath $launcherPath) {
                try {
                    Start-Process -WindowStyle Hidden -FilePath 'powershell' -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$launcherPath`" -StartFile `"$StartFilePath`" -NoRestartIfRunning"
                    Write-Output ("[{0}] timestamp={1} role={2} action=restart" -f $LogPrefix, (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'), $rn)
                    if ($preferDirectTriggerRestart) {
                        $null = Write-TriggerLastActionInStartFile -StartFilePath $StartFilePath -Action 'restart-trigger-direct' -ActionBy 'dev-verify-multi' -Detail ('source={0}' -f $LogPrefix) -ClearRequest $true
                    }
                    if ($rn -eq 'trigger' -and $isGuardContext) {
                        $null = Write-TriggerLastActionInStartFile -StartFilePath $StartFilePath -Action 'restart-trigger' -ActionBy 'guard' -Detail ('source={0}' -f $LogPrefix) -ClearRequest $true
                    }
                }
                catch {
                    Write-Output ("[{0}] timestamp={1} role={2} action=restart_failed detail={3}" -f $LogPrefix, (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'), $rn, $_.Exception.Message)
                    if ($preferDirectTriggerRestart) {
                        $null = Write-TriggerLastActionInStartFile -StartFilePath $StartFilePath -Action 'restart-trigger-direct-failed' -ActionBy 'dev-verify-multi' -Detail (Convert-ToSingleLineTextForMonitorChain -Text $_.Exception.Message) -ClearRequest $false
                    }
                    if ($rn -eq 'trigger' -and $isGuardContext) {
                        $null = Write-TriggerLastActionInStartFile -StartFilePath $StartFilePath -Action 'restart-trigger-failed' -ActionBy 'guard' -Detail (Convert-ToSingleLineTextForMonitorChain -Text $_.Exception.Message) -ClearRequest $false
                    }
                }
            }
        }
        elseif ($GuardArbitratedTrigger -and $rn -eq 'trigger' -and $isGuardContext) {
            $requestState = Get-TriggerRestartRequestFromStartFile -StartFilePath $StartFilePath
            if ([bool]$requestState.Requested) {
                $isStageBootstrapRequest = (
                    ([string]$requestState.Source -eq 'open_unattended_ab_stage_window.ps1') -and
                    ([string]$requestState.Reason -like '*monitor_chain_bootstrap*')
                )

                if ($ForceTriggerRestartOnRequest -and $isStageBootstrapRequest) {
                    $requestDetail = ('request_source={0} request_reason={1}' -f [string]$requestState.Source, [string]$requestState.Reason)
                    $null = Write-TriggerLastActionInStartFile -StartFilePath $StartFilePath -Action 'trigger-alive-bootstrap-request-cleared' -ActionBy 'guard' -Detail $requestDetail -ClearRequest $true
                    Write-Output ("[{0}] timestamp={1} role={2} action=request-cleared-no-restart reason=bootstrap-request-while-alive" -f $LogPrefix, (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'), $rn)
                    continue
                }

                if ($ForceTriggerRestartOnRequest) {
                    foreach ($liveProc in @($found)) {
                        $livePid = [int]$liveProc.ProcessId
                        try {
                            Stop-Process -Id $livePid -Force -ErrorAction SilentlyContinue
                            Write-Output ("[{0}] timestamp={1} role={2} action=force-restart-kill pid={3}" -f $LogPrefix, (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'), $rn, $livePid)
                        }
                        catch {
                            Write-Output ("[{0}] timestamp={1} role={2} action=force-restart-kill-failed pid={3}" -f $LogPrefix, (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'), $rn, $livePid)
                        }
                    }

                    $launcherPath = Join-Path $RepoRoot ([string]$entry.p)
                    if (Test-Path -LiteralPath $launcherPath) {
                        try {
                            Start-Process -WindowStyle Hidden -FilePath 'powershell' -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$launcherPath`" -StartFile `"$StartFilePath`" -NoRestartIfRunning"
                            Write-Output ("[{0}] timestamp={1} role={2} action=force-restart" -f $LogPrefix, (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'), $rn)
                            $requestDetail = ('request_source={0} request_reason={1}' -f [string]$requestState.Source, [string]$requestState.Reason)
                            $null = Write-TriggerLastActionInStartFile -StartFilePath $StartFilePath -Action 'restart-trigger-forced-by-request' -ActionBy 'guard' -Detail $requestDetail -ClearRequest $true
                        }
                        catch {
                            Write-Output ("[{0}] timestamp={1} role={2} action=force-restart-failed detail={3}" -f $LogPrefix, (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'), $rn, $_.Exception.Message)
                            $null = Write-TriggerLastActionInStartFile -StartFilePath $StartFilePath -Action 'restart-trigger-forced-failed' -ActionBy 'guard' -Detail (Convert-ToSingleLineTextForMonitorChain -Text $_.Exception.Message) -ClearRequest $false
                        }
                    }
                }
                else {
                    $requestDetail = ('request_source={0} request_reason={1}' -f [string]$requestState.Source, [string]$requestState.Reason)
                    $null = Write-TriggerLastActionInStartFile -StartFilePath $StartFilePath -Action 'trigger-alive-no-restart' -ActionBy 'guard' -Detail $requestDetail -ClearRequest $true
                    Write-Output ("[{0}] timestamp={1} role={2} action=request-cleared-no-restart" -f $LogPrefix, (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'), $rn)
                }
            }
        }
    }
}

function Invoke-KillOldRoleInstances {
    param(
        [string]$Role,
        [string]$StartFilePath,
        [string]$LogPrefix = '[AB-MONITOR]'
    )

    $scriptName = switch ($Role) {
        'guard'      { 'unattended_ab_session_guard.ps1' }
        'trigger'    { 'unattended_ab_takeover_trigger.ps1' }
        default      { '' }
    }

    if ([string]::IsNullOrWhiteSpace($scriptName)) {
        Write-Output ("${LogPrefix} kill_old_instances role={0} script_name=unknown skipped" -f $Role)
        return
    }

    $killedCount = 0
    try {
        $candidates = @(Get-Process -Name 'powershell' -ErrorAction SilentlyContinue | Where-Object { -not $_.HasExited })
        foreach ($candidate in $candidates) {
            if ($candidate.Id -eq $PID) { continue }
            try {
                $cmdLine = (Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $($candidate.Id)" -ErrorAction SilentlyContinue).CommandLine
                if ($cmdLine -match [regex]::Escape($scriptName)) {
                    $consolePid = $candidate.Id
                    try {
                        $processInfo = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $consolePid" -ErrorAction SilentlyContinue
                        if ($processInfo) {
                            $parentPid = [int]$processInfo.ParentProcessId
                            try {
                                $parentProcess = Get-Process -Id $parentPid -ErrorAction SilentlyContinue
                                if ($parentProcess -and $parentProcess.ProcessName -eq 'powershell' -and -not $parentProcess.HasExited) {
                                    Stop-Process -Id $parentPid -Force -ErrorAction SilentlyContinue
                                    Write-Output ("${LogPrefix} kill_old_instances role={0} old_pid={1} console_pid={2} action=killed-console" -f $Role, $candidate.Id, $parentPid)
                                }
                            }
                            catch { $null = $_ }
                        }
                    }
                    catch { $null = $_ }
                    Stop-Process -Id $candidate.Id -Force -ErrorAction SilentlyContinue
                    $killedCount++
                    Write-Output ("${LogPrefix} kill_old_instances role={0} old_pid={1} action=killed-process" -f $Role, $candidate.Id)
                }
            }
            catch { $null = $_ }
        }
    }
    catch { $null = $_ }

    if ($killedCount -gt 0) {
        Start-Sleep -Seconds 2
    }

    Write-Output ("${LogPrefix} kill_old_instances role={0} killed_count={1}" -f $Role, $killedCount)
}

function Get-UnattendedExitCodeFromRecord {
    param(
        [string]$Tag,
        [System.Management.Automation.ErrorRecord]$Record,
        [int]$DefaultExitCode = 1
    )

    $exitCode = if ($DefaultExitCode -gt 0) { [int]$DefaultExitCode } else { 1 }
    $detail = ''
    if ($null -ne $Record -and $null -ne $Record.Exception) {
        $detail = [string]$Record.Exception.Message
    }

    $normalized = $detail.Trim().ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($normalized)) {
        return $exitCode
    }

    if ($normalized -match 'path must not be empty|must be an integer within|missing script|not found|cannot find path|because it does not exist|is missing in start file') {
        return 2
    }

    if ($normalized -match 'a_only_guard blocked|precheck gate blocked|launch-ready gate blocked|start gate blocked|task static precheck failed') {
        return 3
    }

    if ($normalized -match 'stage_delegate_failed') {
        return 4
    }

    return $exitCode
}

function Write-UnattendedUnhandledResult {
    param(
        [string]$Tag,
        [System.Management.Automation.ErrorRecord]$Record,
        [int]$ExitCode = 1
    )

    if ([string]::IsNullOrWhiteSpace($Tag)) {
        $Tag = 'UNATTENDED-SCRIPT'
    }

    $detail = if ($null -ne $Record -and $null -ne $Record.Exception) {
        [string]$Record.Exception.Message
    }
    else {
        'unknown-error'
    }

    $detail = ([regex]::Replace($detail, '\s+', ' ')).Trim()
    if ([string]::IsNullOrWhiteSpace($detail)) {
        $detail = 'unknown-error'
    }

    if ($ExitCode -le 0) {
        $ExitCode = 1
    }

    Write-Output ("[AB-UNATTENDED-RESULT] schema=AB_UNATTENDED_SCRIPT_RESULT_V1 script={0} result=FAIL final_result=FAIL exit_code={1} error={2}" -f $Tag, $ExitCode, $detail)
}

function Exit-UnattendedFailure {
    param(
        [string]$Tag,
        [string]$Reason,
        [int]$ExitCode = 1
    )

    if ([string]::IsNullOrWhiteSpace($Tag)) {
        $Tag = 'UNATTENDED-SCRIPT'
    }

    $detail = ([regex]::Replace([string]$Reason, '\s+', ' ')).Trim()
    if ([string]::IsNullOrWhiteSpace($detail)) {
        $detail = 'script-failed'
    }

    if ($ExitCode -le 0) {
        $ExitCode = 1
    }

    Write-Output ("[AB-UNATTENDED-RESULT] schema=AB_UNATTENDED_SCRIPT_RESULT_V1 script={0} result=FAIL final_result=FAIL exit_code={1} error={2}" -f $Tag, $ExitCode, $detail)
    exit $ExitCode
}
