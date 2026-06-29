param(
    [string]$StartFile = 'testdata\unattended_start\active\unattended_ab_start_20260504-1123.md',
    [AllowEmptyString()][string]$SupervisorLog = '',
    [ValidateRange(15, 300)][int]$PollSec = 60,
    [ValidateRange(5, 120)][int]$SupervisorQuietMinutes = 5,
    [ValidateRange(10, 180)][int]$UnknownStageStallMinutes = 20,
    [switch]$NoRestartIfRunning
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'unattended_exit_result.ps1')
$script:UnhandledExitTag = 'OPEN-AB-COMPANION'

trap {
    $exitCode = Get-UnattendedExitCodeFromRecord -Tag $script:UnhandledExitTag -Record $_ -DefaultExitCode 1
    Write-UnattendedUnhandledResult -Tag $script:UnhandledExitTag -Record $_ -ExitCode $exitCode
    exit $exitCode
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

    return [pscustomobject]@{ Name = $name; Mutex = $mutex; Acquired = $acquired }
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

function Get-RunningMonitorProcessIdList {
    param(
        [string]$ScriptLeaf,
        [string]$StartFileIdentity,
        [string]$RepoRoot
    )

    $ids = @(
        Get-CimInstance Win32_Process |
            Where-Object {
                $commandLine = [string]$_.CommandLine
                if ([string]::IsNullOrWhiteSpace($commandLine)) {
                    return $false
                }

                $line = $commandLine.ToLowerInvariant()
                if (-not $line.Contains($ScriptLeaf)) {
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

    return @($ids)
}

function Invoke-RunningMonitorProcessStop {
    param([int[]]$ProcessIds)

    $stopped = New-Object 'System.Collections.Generic.List[int]'
    foreach ($targetPid in @($ProcessIds | Sort-Object -Unique)) {
        if ($targetPid -le 0) {
            continue
        }

        try {
            # Graceful shutdown via taskkill to avoid exit code -1
            $null = & 'taskkill.exe' '/PID', ([string]$targetPid) 2>&1
            Start-Sleep -Milliseconds 1500
            if ($null -ne (Get-Process -Id $targetPid -ErrorAction SilentlyContinue)) {
                Stop-Process -Id $targetPid -Force -ErrorAction Stop
            }
            Wait-Process -Id $targetPid -Timeout 15 -ErrorAction SilentlyContinue
            [void]$stopped.Add([int]$targetPid)
        }
        catch { Write-Verbose ("Suppressed exception: {0}" -f $_.Exception.Message) }
    }

    return @($stopped)
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

function Test-ExistingMonitorProcessAlive {
    param(
        [int[]]$ProcessIds,
        [string[]]$EvidencePaths,
        [int]$MaxStaleMinutes = 15
    )

    $thresholdMinutes = if ($MaxStaleMinutes -gt 0) { $MaxStaleMinutes } else { 15 }
    $alivePidCount = 0
    foreach ($candidatePid in @($ProcessIds | Sort-Object -Unique)) {
        if ($candidatePid -le 0) {
            continue
        }

        if ($null -ne (Get-Process -Id $candidatePid -ErrorAction SilentlyContinue)) {
            $alivePidCount++
        }
    }

    if ($alivePidCount -le 0) {
        return $false
    }

    $now = Get-Date
    foreach ($path in @($EvidencePaths)) {
        if ([string]::IsNullOrWhiteSpace($path) -or -not (Test-Path -LiteralPath $path)) {
            continue
        }

        $item = Get-Item -LiteralPath $path -ErrorAction SilentlyContinue
        if ($null -eq $item) {
            continue
        }

        $ageMinutes = (New-TimeSpan -Start $item.LastWriteTime -End $now).TotalMinutes
        if ($ageMinutes -le $thresholdMinutes) {
            # Avoid PID-alive-but-script-terminated: check JSON state files for terminal markers
            if ($path -like '*.json') {
                try {
                    $rawTerminal = Get-Content -LiteralPath $path -Raw -Encoding utf8 -ErrorAction SilentlyContinue
                    if (-not [string]::IsNullOrWhiteSpace($rawTerminal)) {
                        $lowerTerminal = $rawTerminal.ToLowerInvariant()
                        $terminalPatterns = @('"status": "stopped"', '"status": "shutdown"', '"event": "shutdown"')
                        $hasTerminal = $false
                        foreach ($tp in $terminalPatterns) {
                            if ($lowerTerminal.Contains($tp)) {
                                $hasTerminal = $true
                                break
                            }
                        }
                        if ($hasTerminal) {
                            continue
                        }
                    }
                }
                catch { }
            }
            return $true
        }
    }

    return $false
}

function Clear-OrphanedMonitorConsole {
    param(
        [string]$Role,
        [string]$StartFilePath,
        [string]$RepoRoot
    )

    try {
        $fullPath = [System.IO.Path]::GetFullPath($StartFilePath).ToLowerInvariant()
        $sha1 = [System.Security.Cryptography.SHA1]::Create()
        try {
            $hashBytes = $sha1.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($fullPath))
            $hash = ([System.BitConverter]::ToString($hashBytes)).Replace('-', '').Substring(0, 12).ToLowerInvariant()
        }
        finally { $sha1.Dispose() }
        $titlePattern = "whois-mon-$Role-$hash*"

        $orphanedConhostPids = New-Object 'System.Collections.Generic.List[int]'
        $allConhost = @(Get-CimInstance Win32_Process -Filter "Name='conhost.exe'" -ErrorAction SilentlyContinue)
        foreach ($ch in $allConhost) {
            $chPid = [int]$ch.ProcessId
            $children = @(Get-CimInstance Win32_Process -Filter "ParentProcessId=$chPid" -ErrorAction SilentlyContinue)
            $hasMatchingAlive = $false
            $hasMatchingExited = $false
            foreach ($child in $children) {
                if ($child.Name -eq 'powershell.exe') {
                    $cmdLine = [string]$child.CommandLine
                    if ($cmdLine -match [regex]::Escape("-$Role")) {
                        try {
                            $null = Get-Process -Id ([int]$child.ProcessId) -ErrorAction Stop
                            $hasMatchingAlive = $true
                        }
                        catch {
                            $hasMatchingExited = $true
                        }
                    }
                }
            }
            if ($hasMatchingExited -and -not $hasMatchingAlive) {
                $orphanedConhostPids.Add($chPid)
            }
        }

        $null = & 'taskkill.exe' '/F', '/FI', ("WINDOWTITLE eq $titlePattern") 2>&1

        foreach ($targetPid in $orphanedConhostPids) {
            $null = & 'taskkill.exe' '/F', '/PID', ([string]$targetPid) 2>&1
        }
    }
    catch { }
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$startFilePath = if ([System.IO.Path]::IsPathRooted($StartFile)) {
    (Resolve-Path -LiteralPath $StartFile).Path
}
else {
    (Resolve-Path -LiteralPath (Join-Path $repoRoot $StartFile)).Path
}
$settings = Read-KeyValueFile -Path $startFilePath
$startFileIdentity = Get-NormalizedPathIdentity -Path $startFilePath -RepoRoot $repoRoot
$scriptPath = Join-Path $repoRoot 'tools\test\unattended_ab_companion.ps1'
$powershellPath = Join-Path $PSHOME 'powershell.exe'
if (-not (Test-Path -LiteralPath $powershellPath)) {
    $powershellPath = 'powershell.exe'
}

$launchMutexContext = Enter-LaunchMutex -Role 'companion' -StartFilePath $startFilePath
try {
    $existingPids = @(Get-RunningMonitorProcessIdList -ScriptLeaf 'unattended_ab_companion.ps1' -StartFileIdentity $startFileIdentity -RepoRoot $repoRoot)
    $reuseExisting = $false
    $processId = 0

    if ($existingPids.Count -gt 0) {
        $evidencePaths = @()
        $cpLog = Get-AnchorValueFromConfig -Settings $settings -Key 'companion_log'
        if (-not [string]::IsNullOrWhiteSpace($cpLog)) { $evidencePaths += (Join-Path $repoRoot $cpLog) }
        if ($evidencePaths.Count -eq 0) {
            Write-Output ("[OPEN-AB-COMPANION] restart_precheck existing_count={0} existing_pids={1} mode=no-evidence-clean" -f $existingPids.Count, ($existingPids -join ','))
            Invoke-RunningMonitorProcessStop -ProcessIds $existingPids
            Clear-OrphanedMonitorConsole -Role 'companion' -StartFilePath $startFilePath -RepoRoot $repoRoot
            $reuseExisting = $false
        }
        else {
            $isTrulyAlive = Test-ExistingMonitorProcessAlive -ProcessIds $existingPids -EvidencePaths $evidencePaths -MaxStaleMinutes 15
            if ($isTrulyAlive) {
                Write-Output ("[OPEN-AB-COMPANION] restart_precheck existing_count={0} existing_pids={1} mode=reuse-alive" -f $existingPids.Count, ($existingPids -join ','))
                $reuseExisting = $true
                $processId = [int]$existingPids[0]
            }
            else {
                Write-Output ("[OPEN-AB-COMPANION] restart_precheck existing_count={0} existing_pids={1} mode=stale-kill" -f $existingPids.Count, ($existingPids -join ','))
                Invoke-RunningMonitorProcessStop -ProcessIds $existingPids
                Clear-OrphanedMonitorConsole -Role 'companion' -StartFilePath $startFilePath -RepoRoot $repoRoot
                $reuseExisting = $false
            }
        }
    }
    else {
        Write-Output '[OPEN-AB-COMPANION] restart_precheck existing_count=0'
    }

    if (-not $reuseExisting) {
        Clear-OrphanedMonitorConsole -Role 'companion' -StartFilePath $startFilePath -RepoRoot $repoRoot
        $launchTime = Get-Date

        $argumentList = @(
            '-NoExit',
            '-NoProfile',
            '-ExecutionPolicy', 'Bypass',
            '-File', $scriptPath,
            '-StartFile', $StartFile,
            '-PollSec', [string]$PollSec,
            '-SupervisorQuietMinutes', [string]$SupervisorQuietMinutes,
            '-UnknownStageStallMinutes', [string]$UnknownStageStallMinutes
        )

        if (-not [string]::IsNullOrWhiteSpace($SupervisorLog)) {
            $argumentList += @('-SupervisorLog', $SupervisorLog)
        }

        $processInfo = Start-Process -FilePath $powershellPath -WorkingDirectory $repoRoot -ArgumentList $argumentList -PassThru
        $processId = [int]$processInfo.Id
    }

    $companionLog = ''
    if ($reuseExisting) {
        $companionLog = Get-AnchorValueFromConfig -Settings $settings -Key 'companion_log'
    }

    if ([string]::IsNullOrWhiteSpace($companionLog)) {
        $companionRoot = Join-Path $repoRoot 'out\artifacts\ab_companion'
        $companionDir = $null
        for ($attempt = 0; $attempt -lt 24; $attempt++) {
            if ($reuseExisting) {
                $companionDir = Get-LatestTimestampedDirectory -Root $companionRoot
            }
            else {
                $companionDir = Get-LatestTimestampedDirectory -Root $companionRoot -After $launchTime
            }
            if ($null -ne $companionDir) {
                break
            }

            Start-Sleep -Seconds 5
        }

        if ($null -ne $companionDir) {
            $companionLog = Join-Path $companionDir.FullName 'companion.log'
        }
    }

    Write-Output ("[OPEN-AB-COMPANION] pid={0} launcher_pid={1} script={2} start_file={3} companion_log={4} reuse_existing={5}" -f $processId, $PID, $scriptPath, $StartFile, $companionLog, [string]$reuseExisting)
}
finally {
    Exit-LaunchMutex -Context $launchMutexContext
}

exit 0
