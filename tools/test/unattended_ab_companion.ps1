param(
    [Parameter(Mandatory = $true)][string]$StartFile,
    [AllowEmptyString()][string]$SupervisorLog = "",
    [ValidateRange(15, 300)][int]$PollSec = 60,
    [ValidateRange(5, 120)][int]$SupervisorQuietMinutes = 5,
    [ValidateRange(10, 180)][int]$UnknownStageStallMinutes = 20
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Resolve-RepoPath {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return ""
    }

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return (Resolve-Path -LiteralPath $Path).Path
    }

    return (Resolve-Path -LiteralPath (Join-Path $script:RepoRoot $Path)).Path
}

function Convert-ToRepoRelativePath {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return ""
    }

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $repoRootFull = [System.IO.Path]::GetFullPath($script:RepoRoot)
    if ($fullPath.StartsWith($repoRootFull, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $fullPath.Substring($repoRootFull.Length).TrimStart('\\').Replace('\\', '/')
    }

    return $Path.Replace('\\', '/')
}

function Convert-MsysPathToWindowsPath {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return ""
    }

    if ($Path -match '^/([a-zA-Z])/(.*)$') {
        $drive = $Matches[1].ToUpperInvariant()
        $rest = $Matches[2] -replace '/', '\\'
        return "${drive}:\\$rest"
    }

    return $Path
}

function Get-StartFileMutexName {
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

function Acquire-InstanceMutex {
    param(
        [string]$Role,
        [string]$StartFilePath
    )

    $name = Get-StartFileMutexName -Role $Role -StartFilePath $StartFilePath
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
            Write-Output "[AB-COMPANION] single_instance_conflict mutex=$name start_file=$StartFilePath"
            $mutex.Dispose()
            throw "Another unattended_ab_companion instance is already active for this start file"
        }
    }
    catch {
        if (-not $acquired -and $null -ne $mutex) {
            try { $mutex.Dispose() } catch {}
        }
        throw
    }

    return $mutex
}

function Read-KeyValueFile {
    param([string]$Path)

    $maxAttempts = 8
    $lines = @()
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        try {
            $lines = @(Get-Content -LiteralPath $Path -Encoding utf8 -ErrorAction Stop)
            break
        }
        catch {
            if ($attempt -eq $maxAttempts) {
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

    $map = [ordered]@{}
    foreach ($line in $lines) {
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

    $maxAttempts = 8
    $sourceLines = @()
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        try {
            $sourceLines = @(Get-Content -LiteralPath $Path -Encoding utf8 -ErrorAction Stop)
            break
        }
        catch {
            if ($attempt -eq $maxAttempts) {
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

    $lines = New-Object 'System.Collections.Generic.List[string]'
    foreach ($line in $sourceLines) {
        [void]$lines.Add([string]$line)
    }

    foreach ($key in $Values.Keys) {
        $prefix = "$key="
        $found = $false
        for ($index = 0; $index -lt $lines.Count; $index++) {
            if ($lines[$index].StartsWith($prefix, [System.StringComparison]::Ordinal)) {
                $lines[$index] = $prefix + [string]$Values[$key]
                $found = $true
                break
            }
        }

        if (-not $found) {
            [void]$lines.Add($prefix + [string]$Values[$key])
        }
    }

    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        try {
            Set-Content -LiteralPath $Path -Value @($lines) -Encoding utf8 -ErrorAction Stop
            break
        }
        catch {
            if ($attempt -eq $maxAttempts) {
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
}

function Append-DelimitedNote {
    param(
        [string]$Existing,
        [string]$Append
    )

    if ([string]::IsNullOrWhiteSpace($Existing)) {
        return $Append
    }

    return "$Existing; $Append"
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

function Get-FileAgeMinutes {
    param([AllowEmptyString()][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return [double]::PositiveInfinity
    }

    if (-not (Test-Path -LiteralPath $Path)) {
        return [double]::PositiveInfinity
    }

    try {
        return ((Get-Date) - (Get-Item -LiteralPath $Path).LastWriteTime).TotalMinutes
    }
    catch {
        return [double]::PositiveInfinity
    }
}

function Get-StageLaunchPid {
    param(
        [hashtable]$Settings,
        [string]$Stage
    )

    if ($null -eq $Settings -or [string]::IsNullOrWhiteSpace($Stage)) {
        return 0
    }

    $pidKey = if ($Stage -eq 'A') {
        'A_LAUNCH_PID'
    }
    elseif ($Stage -eq 'B') {
        'B_LAUNCH_PID'
    }
    else {
        ''
    }

    if ([string]::IsNullOrWhiteSpace($pidKey) -or -not $Settings.Contains($pidKey)) {
        return 0
    }

    $pidValue = 0
    if ([int]::TryParse(([string]$Settings[$pidKey]).Trim(), [ref]$pidValue) -and $pidValue -gt 0) {
        return $pidValue
    }

    return 0
}

function Test-StageProcessAlive {
    param(
        [int]$ProcessId,
        [string]$Stage
    )

    if ($ProcessId -le 0 -or [string]::IsNullOrWhiteSpace($Stage)) {
        return $false
    }

    $proc = $null
    try {
        $proc = Get-CimInstance Win32_Process -Filter ("ProcessId={0}" -f $ProcessId) -ErrorAction SilentlyContinue
    }
    catch {
        return $false
    }

    if ($null -eq $proc) {
        return $false
    }

    $commandLine = [string]$proc.CommandLine
    if ([string]::IsNullOrWhiteSpace($commandLine)) {
        return $true
    }

    $line = $commandLine.ToLowerInvariant()
    if ($Stage -eq 'A') {
        return $line.Contains('start_dev_verify_fastmode_a.ps1')
    }
    if ($Stage -eq 'B') {
        return $line.Contains('start_dev_verify_fastmode_b.ps1')
    }

    return $true
}

function Write-CompanionLog {
    param([string]$Message)

    $timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $line = "[AB-COMPANION] timestamp=$timestamp $Message"

    $maxAttempts = 5
    $written = $false
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        $stream = $null
        $writer = $null
        try {
            $stream = New-Object System.IO.FileStream($script:CompanionLog, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite)
            $writer = New-Object System.IO.StreamWriter($stream, [System.Text.Encoding]::UTF8)
            $writer.WriteLine($line)
            $writer.Flush()
            $written = $true
            break
        }
        catch {
            if ($attempt -lt $maxAttempts) {
                Start-Sleep -Milliseconds (120 * $attempt)
            }
        }
        finally {
            if ($null -ne $writer) {
                $writer.Dispose()
            }
            if ($null -ne $stream) {
                $stream.Dispose()
            }
        }
    }

    if (-not $written) {
        Write-Warning ("[AB-COMPANION] log_write_failed path={0}" -f $script:CompanionLog)
    }

    Write-Output $line
}

function Get-CsvRowCount {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return 0
    }

    if (-not (Test-Path -LiteralPath $Path)) {
        return 0
    }

    try {
        return @((Import-Csv -LiteralPath $Path)).Count
    }
    catch {
        return 0
    }
}

function Get-ArtifactState {
    param([string[]]$Paths)

    $files = @()
    foreach ($path in @($Paths | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })) {
        if (-not (Test-Path -LiteralPath $path)) {
            continue
        }

        $files += @(Get-ChildItem -LiteralPath $path -File -Recurse -Force -ErrorAction SilentlyContinue)
    }

    if ($files.Count -eq 0) {
        return [pscustomobject]@{
            FileCount = 0
            LatestWriteTime = [datetime]'2000-01-01 00:00:00'
            LatestPath = ''
        }
    }

    $latest = $files | Sort-Object LastWriteTime, FullName | Select-Object -Last 1
    return [pscustomobject]@{
        FileCount = $files.Count
        LatestWriteTime = $latest.LastWriteTime
        LatestPath = $latest.FullName
    }
}

function Get-RemoteChainCount {
    param([hashtable]$Settings)

    $remoteIp = if ($null -ne $Settings -and $Settings.Contains('REMOTE_IP')) { [string]$Settings.REMOTE_IP } else { '' }
    $remoteUser = if ($null -ne $Settings -and $Settings.Contains('REMOTE_USER')) { [string]$Settings.REMOTE_USER } else { '' }

    $count = 0
    foreach ($processInfo in @(Get-CimInstance Win32_Process)) {
        $commandLineRaw = [string]$processInfo.CommandLine
        if ([string]::IsNullOrWhiteSpace($commandLineRaw)) {
            continue
        }

        $commandLine = $commandLineRaw.ToLowerInvariant()
        $processName = ([string]$processInfo.Name).ToLowerInvariant()

        if ($processName -eq 'ssh-agent.exe' -or $commandLine -match '(^|\s)ssh-agent(?:\.exe)?(\s|$)') {
            continue
        }

        $isRemoteMatch = $false
        if ($commandLine -match 'remote_build_and_test\.sh|whois-win64\.exe|whois-x86_64') {
            $isRemoteMatch = $true
        }
        elseif ($processName -eq 'ssh.exe' -or $commandLine -match '(^|\s)ssh(?:\.exe)?(\s|$)') {
            $hasTargetEndpoint = $false
            if (-not [string]::IsNullOrWhiteSpace($remoteIp) -and $commandLine.Contains($remoteIp.ToLowerInvariant())) {
                $hasTargetEndpoint = $true
            }
            elseif (-not [string]::IsNullOrWhiteSpace($remoteUser) -and $commandLine.Contains(($remoteUser.ToLowerInvariant() + '@'))) {
                $hasTargetEndpoint = $true
            }

            $hasRemoteBuildIntent = ($commandLine -match 'remote_build_and_test\.sh|check_remote_lock\.ps1|clear_remote_lock\.ps1')
            if ($hasTargetEndpoint -or $hasRemoteBuildIntent) {
                $isRemoteMatch = $true
            }
        }

        if ($isRemoteMatch) {
            $count++
        }
    }

    return $count
}

function Copy-PathIfExists {
    param(
        [string]$SourcePath,
        [string]$DestinationDir
    )

    if ([string]::IsNullOrWhiteSpace($SourcePath) -or -not (Test-Path -LiteralPath $SourcePath)) {
        return
    }

    $destinationPath = Join-Path $DestinationDir ([System.IO.Path]::GetFileName($SourcePath))
    Copy-Item -LiteralPath $SourcePath -Destination $destinationPath -Force
}

function Capture-BlockedPackage {
    param(
        [string]$Reason,
        [string]$Detail,
        [string]$Stage,
        [string]$StageRunDir,
        [string]$InnerRunDir,
        [string]$SupervisorLogPath
    )

    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $packageDir = Join-Path $script:CompanionOutDir ("blocked_package_" + $stamp)
    New-Item -ItemType Directory -Path $packageDir -Force | Out-Null

    @(Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, Name, CommandLine) |
        Format-List | Out-File -FilePath (Join-Path $packageDir 'local_process_snapshot.txt') -Encoding utf8

    if (-not [string]::IsNullOrWhiteSpace($StageRunDir) -and (Test-Path -LiteralPath $StageRunDir)) {
        @(Get-ChildItem -LiteralPath $StageRunDir -Recurse -Force | Select-Object FullName, LastWriteTime, Length) |
            Format-Table -AutoSize | Out-String | Out-File -FilePath (Join-Path $packageDir 'stage_run_tree.txt') -Encoding utf8
    }

    if (-not [string]::IsNullOrWhiteSpace($InnerRunDir) -and (Test-Path -LiteralPath $InnerRunDir)) {
        @(Get-ChildItem -LiteralPath $InnerRunDir -Recurse -Force | Select-Object FullName, LastWriteTime, Length) |
            Format-Table -AutoSize | Out-String | Out-File -FilePath (Join-Path $packageDir 'inner_run_tree.txt') -Encoding utf8
    }

    Copy-PathIfExists -SourcePath $script:StartFilePath -DestinationDir $packageDir
    Copy-PathIfExists -SourcePath $SupervisorLogPath -DestinationDir $packageDir
    Copy-PathIfExists -SourcePath $script:CompanionLog -DestinationDir $packageDir
    $candidatePaths = @()
    if (-not [string]::IsNullOrWhiteSpace($StageRunDir)) {
        $candidatePaths += @(
            (Join-Path $StageRunDir 'summary_partial.csv'),
            (Join-Path $StageRunDir 'summary.csv'),
            (Join-Path $StageRunDir 'final_status.json'),
            (Join-Path $StageRunDir 'final_status.txt')
        )
    }
    if (-not [string]::IsNullOrWhiteSpace($InnerRunDir)) {
        $candidatePaths += @(
            (Join-Path $InnerRunDir 'summary_partial.csv'),
            (Join-Path $InnerRunDir 'summary.csv'),
            (Join-Path $InnerRunDir 'final_status.json'),
            (Join-Path $InnerRunDir 'final_status.txt')
        )
    }

    foreach ($candidate in $candidatePaths) {
        Copy-PathIfExists -SourcePath $candidate -DestinationDir $packageDir
    }

    $metadata = [ordered]@{
        Reason = $Reason
        Detail = $Detail
        Stage = $Stage
        StageRunDir = (Convert-ToRepoRelativePath -Path $StageRunDir)
        InnerRunDir = (Convert-ToRepoRelativePath -Path $InnerRunDir)
        StartFile = (Convert-ToRepoRelativePath -Path $script:StartFilePath)
        SupervisorLog = (Convert-ToRepoRelativePath -Path $SupervisorLogPath)
        CompanionLog = (Convert-ToRepoRelativePath -Path $script:CompanionLog)
        GeneratedAt = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    }
    ($metadata | ConvertTo-Json -Depth 4) | Out-File -FilePath (Join-Path $packageDir 'metadata.json') -Encoding utf8

    return $packageDir
}

function Get-LatestSupervisorLog {
    if (-not (Test-Path -LiteralPath $script:SupervisorRoot)) {
        return ''
    }

    $latest = @(Get-ChildItem -LiteralPath $script:SupervisorRoot -Directory | Sort-Object LastWriteTime, Name | Select-Object -Last 1)
    if ($latest.Count -eq 0) {
        return ''
    }

    $candidate = Join-Path $latest[0].FullName 'supervisor.log'
    if (Test-Path -LiteralPath $candidate) {
        return $candidate
    }

    return ''
}

function Get-CurrentStageContext {
    param([hashtable]$Settings)

    $sessionNotes = [string]$Settings.SESSION_FINAL_NOTES
    $runDir = Get-LatestAnchorValueFromNotes -Notes $sessionNotes -Key 'run_dir'

    $stage = ''
    if ([string]$Settings.B_FINAL_STATUS -eq 'RUNNING') {
        $stage = 'B'
    }
    elseif ([string]$Settings.A_FINAL_STATUS -eq 'RUNNING') {
        $stage = 'A'
    }

    $resolvedRunDir = if ([string]::IsNullOrWhiteSpace($runDir)) { '' } else { Resolve-RepoPath -Path $runDir }
    return [pscustomobject]@{
        Stage = $stage
        RunDir = $resolvedRunDir
    }
}

$script:RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$script:StartFilePath = Resolve-RepoPath -Path $StartFile
$script:InstanceMutex = Acquire-InstanceMutex -Role 'companion' -StartFilePath $script:StartFilePath
$script:SupervisorRoot = Join-Path $script:RepoRoot 'out\artifacts\ab_supervisor'

$companionStamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$script:CompanionOutDir = Join-Path $script:RepoRoot (Join-Path 'out\artifacts\ab_companion' $companionStamp)
New-Item -ItemType Directory -Path $script:CompanionOutDir -Force | Out-Null
$script:CompanionLog = Join-Path $script:CompanionOutDir 'companion.log'

$lastState = $null
$stallSince = $null
$lastQuietAliveAlertAt = $null
$d1NoProgressLimitMinutes = [Math]::Min([int]$UnknownStageStallMinutes, 10)
$supervisorLogPath = ''
$liveStatusPath = ''
if (-not [string]::IsNullOrWhiteSpace($SupervisorLog)) {
    try {
        $supervisorLogPath = Resolve-RepoPath -Path $SupervisorLog
    }
    catch {
        $supervisorLogPath = ''
    }
}
if ([string]::IsNullOrWhiteSpace($supervisorLogPath)) {
    $supervisorLogPath = Get-LatestSupervisorLog
}

$startupSettings = Read-KeyValueFile -Path $script:StartFilePath
$startupNotes = if ($startupSettings.Contains('SESSION_FINAL_NOTES')) { [string]$startupSettings.SESSION_FINAL_NOTES } else { '' }
$startupLiveStatusAnchor = Get-LatestAnchorValueFromNotes -Notes $startupNotes -Key 'live_status'
if (-not [string]::IsNullOrWhiteSpace($startupLiveStatusAnchor)) {
    try {
        $liveStatusPath = Resolve-RepoPath -Path $startupLiveStatusAnchor
    }
    catch {
        $liveStatusPath = ''
    }
}

Write-CompanionLog ("startup start_file={0} supervisor_log={1} live_status={2}" -f (Convert-ToRepoRelativePath -Path $script:StartFilePath), (Convert-ToRepoRelativePath -Path $supervisorLogPath), (Convert-ToRepoRelativePath -Path $liveStatusPath))
Write-CompanionLog ("startup_pid pid={0}" -f $PID)

while ($true) {
    $settings = Read-KeyValueFile -Path $script:StartFilePath
    $sessionNotes = if ($settings.Contains('SESSION_FINAL_NOTES')) { [string]$settings.SESSION_FINAL_NOTES } else { '' }
    $stageContext = Get-CurrentStageContext -Settings $settings
    $stage = [string]$stageContext.Stage
    $stageRunDir = [string]$stageContext.RunDir
    $stageLaunchPid = Get-StageLaunchPid -Settings $settings -Stage $stage
    $stageProcessAlive = Test-StageProcessAlive -ProcessId $stageLaunchPid -Stage $stage

    if ([string]$settings.SESSION_FINAL_STATUS -in @('PASS', 'FAIL', 'BLOCKED') -and [string]$settings.A_FINAL_STATUS -ne 'RUNNING' -and [string]$settings.B_FINAL_STATUS -ne 'RUNNING') {
        Write-CompanionLog ("complete session_status={0} a={1} b={2}" -f [string]$settings.SESSION_FINAL_STATUS, [string]$settings.A_FINAL_STATUS, [string]$settings.B_FINAL_STATUS)
        break
    }

    if ([string]::IsNullOrWhiteSpace($supervisorLogPath) -or -not (Test-Path -LiteralPath $supervisorLogPath)) {
        $supervisorLogPath = Get-LatestSupervisorLog
    }

    $liveStatusAnchor = Get-LatestAnchorValueFromNotes -Notes $sessionNotes -Key 'live_status'
    if (-not [string]::IsNullOrWhiteSpace($liveStatusAnchor)) {
        try {
            $liveStatusPath = Resolve-RepoPath -Path $liveStatusAnchor
        }
        catch {
            $liveStatusPath = ''
        }
    }
    if ([string]::IsNullOrWhiteSpace($liveStatusPath) -and -not [string]::IsNullOrWhiteSpace($supervisorLogPath)) {
        $candidateLiveStatus = Join-Path (Split-Path -Parent $supervisorLogPath) 'live_status.json'
        if (Test-Path -LiteralPath $candidateLiveStatus) {
            $liveStatusPath = $candidateLiveStatus
        }
    }

    $supervisorAgeMinutes = Get-FileAgeMinutes -Path $supervisorLogPath
    $supervisorQuiet = ($supervisorAgeMinutes -ge $SupervisorQuietMinutes)

    $liveStatusAgeMinutes = Get-FileAgeMinutes -Path $liveStatusPath
    $liveStatusQuiet = ($liveStatusAgeMinutes -ge $SupervisorQuietMinutes)

    $summaryPartial = if ([string]::IsNullOrWhiteSpace($stageRunDir)) { '' } else { Join-Path $stageRunDir 'summary_partial.csv' }
    $rowCount = Get-CsvRowCount -Path $summaryPartial

    $innerRunDir = ''
    if ($stage -eq 'A') {
        $autoDir = Join-Path $script:RepoRoot 'out\artifacts\autopilot_dev_recheck_8round'
        if (Test-Path -LiteralPath $autoDir) {
            $latestInner = @(Get-ChildItem -LiteralPath $autoDir -Directory | Where-Object { $_.Name -notlike '_*' } | Sort-Object LastWriteTime, Name | Select-Object -Last 1)
            if ($latestInner.Count -gt 0) {
                $innerRunDir = $latestInner[0].FullName
            }
        }
    }

    $artifactState = Get-ArtifactState -Paths @($stageRunDir, $innerRunDir)
    $remoteChainCount = Get-RemoteChainCount -Settings $settings
    $currentState = [pscustomobject]@{
        Stage = $stage
        RunDir = $stageRunDir
        InnerRunDir = $innerRunDir
        RowCount = $rowCount
        FileCount = $artifactState.FileCount
        LatestWriteTime = $artifactState.LatestWriteTime
        LatestPath = $artifactState.LatestPath
        RemoteChainCount = $remoteChainCount
    }

    $stageRunAgeMinutes = 0.0
    if (-not [string]::IsNullOrWhiteSpace($currentState.RunDir) -and (Test-Path -LiteralPath $currentState.RunDir)) {
        $stageRunAgeMinutes = ((Get-Date) - (Get-Item -LiteralPath $currentState.RunDir).CreationTime).TotalMinutes
    }

    $hasProgress = $false
    if ($null -eq $lastState) {
        $hasProgress = $true
    }
    elseif ($currentState.Stage -ne $lastState.Stage -or $currentState.RowCount -gt $lastState.RowCount -or $currentState.FileCount -gt $lastState.FileCount -or $currentState.LatestWriteTime -gt $lastState.LatestWriteTime) {
        $hasProgress = $true
    }

    if ($hasProgress -or $currentState.RemoteChainCount -gt 0) {
        $stallSince = $null
    }
    elseif ($null -eq $stallSince) {
        if ([int]$currentState.RowCount -lt 1 -and $stageRunAgeMinutes -ge $d1NoProgressLimitMinutes) {
            $stallSince = (Get-Date).AddMinutes(-1 * $d1NoProgressLimitMinutes)
        }
        else {
            $stallSince = Get-Date
        }
    }

    $noProgressMinutes = if ($null -eq $stallSince) { 0.0 } else { ((Get-Date) - $stallSince).TotalMinutes }
    $quietNoProgress = ($noProgressMinutes -ge $SupervisorQuietMinutes)

    Write-CompanionLog ("heartbeat stage={0} stage_pid={1} stage_alive={2} row_count={3} file_count={4} latest_path={5} remote_chain_count={6} supervisor_quiet={7} live_status_quiet={8} no_progress_min={9:N1}" -f $currentState.Stage, $stageLaunchPid, $stageProcessAlive, $currentState.RowCount, $currentState.FileCount, (Convert-ToRepoRelativePath -Path $currentState.LatestPath), $currentState.RemoteChainCount, $supervisorQuiet, $liveStatusQuiet, $noProgressMinutes)

    $blockedReason = ''
    $blockedDetail = ''
    if (-not [string]::IsNullOrWhiteSpace($currentState.Stage) -and $supervisorQuiet -and $liveStatusQuiet -and $currentState.RemoteChainCount -eq 0 -and $quietNoProgress) {
        if ($stageProcessAlive) {
            $now = Get-Date
            if ($null -eq $lastQuietAliveAlertAt -or (($now - $lastQuietAliveAlertAt).TotalMinutes -ge 5.0)) {
                Write-CompanionLog ("quiet_alert reason=supervisor-quiet action=defer-block stage={0} stage_pid={1} stage_alive={2} supervisor_age_min={3:N1} live_status_age_min={4:N1} no_progress_min={5:N1}" -f $currentState.Stage, $stageLaunchPid, $stageProcessAlive, $supervisorAgeMinutes, $liveStatusAgeMinutes, $noProgressMinutes)
                $lastQuietAliveAlertAt = $now
            }
        }
        else {
            $blockedReason = 'supervisor-quiet'
            $blockedDetail = ("Supervisor and live_status quiet beyond threshold with no progress and no remote chain (supervisor_age_min={0:N1}, live_status_age_min={1:N1}, no_progress_min={2:N1}, stage_pid={3}, stage_alive={4})" -f $supervisorAgeMinutes, $liveStatusAgeMinutes, $noProgressMinutes, $stageLaunchPid, $stageProcessAlive)
        }
    }
    elseif (-not [string]::IsNullOrWhiteSpace($currentState.Stage) -and [int]$currentState.RowCount -lt 1 -and $null -ne $stallSince -and (((Get-Date) - $stallSince).TotalMinutes -ge $d1NoProgressLimitMinutes)) {
        $blockedReason = 'd1-no-progress-no-remote'
        $blockedDetail = ("D1 no progress with no remote chain beyond threshold ({0} min)" -f $d1NoProgressLimitMinutes)
    }
    elseif (-not [string]::IsNullOrWhiteSpace($currentState.Stage) -and $null -ne $stallSince -and (((Get-Date) - $stallSince).TotalMinutes -ge $UnknownStageStallMinutes)) {
        $blockedReason = 'unknown-stage-stall'
        $blockedDetail = 'No artifact progress and no remote chain activity beyond threshold'
    }

    if (-not [string]::IsNullOrWhiteSpace($blockedReason)) {
        $blockedDir = Capture-BlockedPackage -Reason $blockedReason -Detail $blockedDetail -Stage $currentState.Stage -StageRunDir $currentState.RunDir -InnerRunDir $currentState.InnerRunDir -SupervisorLogPath $supervisorLogPath
        $blockedRel = Convert-ToRepoRelativePath -Path $blockedDir

        $updates = @{
            SESSION_FINAL_STATUS = 'BLOCKED'
            SESSION_FINAL_NOTES = (Append-DelimitedNote -Existing ([string]$settings.SESSION_FINAL_NOTES) -Append ("companion_blocked reason=$blockedReason evidence=$blockedRel"))
        }
        if ($currentState.Stage -eq 'A' -and [string]$settings.A_FINAL_STATUS -eq 'RUNNING') {
            $updates['A_FINAL_STATUS'] = 'BLOCKED'
            if ([string]$settings.B_FINAL_STATUS -eq 'NOT_RUN') {
                $updates['B_FINAL_STATUS'] = 'BLOCKED'
            }
        }
        elseif ($currentState.Stage -eq 'B' -and [string]$settings.B_FINAL_STATUS -eq 'RUNNING') {
            $updates['B_FINAL_STATUS'] = 'BLOCKED'
        }

        Set-KeyValueFileValues -Path $script:StartFilePath -Values $updates
        Write-CompanionLog ("blocked reason={0} evidence={1}" -f $blockedReason, $blockedRel)
        break
    }

    $lastState = $currentState
    Start-Sleep -Seconds $PollSec
}

Write-CompanionLog ("shutdown_pid pid={0}" -f $PID)
if ($null -ne $script:InstanceMutex) {
    try {
        $script:InstanceMutex.ReleaseMutex() | Out-Null
    }
    catch {
    }
    finally {
        $script:InstanceMutex.Dispose()
    }
}