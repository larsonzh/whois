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
            $lines = @(Get-Content -LiteralPath $Path -ErrorAction Stop)
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
            $sourceLines = @(Get-Content -LiteralPath $Path -ErrorAction Stop)
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
    $count = 0
    foreach ($processInfo in @(Get-CimInstance Win32_Process)) {
        $commandLine = [string]$processInfo.CommandLine
        if ([string]::IsNullOrWhiteSpace($commandLine)) {
            continue
        }

        if ($commandLine -match 'remote_build_and_test\.sh|ssh(?:\.exe)?|whois-win64\.exe|whois-x86_64') {
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
    $runDir = ''
    if ($sessionNotes -match 'run_dir=([^;]+)') {
        $runDir = $Matches[1].Trim()
    }

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
$supervisorLogPath = if ([string]::IsNullOrWhiteSpace($SupervisorLog)) { '' } else { Resolve-RepoPath -Path $SupervisorLog }
if ([string]::IsNullOrWhiteSpace($supervisorLogPath)) {
    $supervisorLogPath = Get-LatestSupervisorLog
}

Write-CompanionLog ("startup start_file={0} supervisor_log={1}" -f (Convert-ToRepoRelativePath -Path $script:StartFilePath), (Convert-ToRepoRelativePath -Path $supervisorLogPath))
Write-CompanionLog ("startup_pid pid={0}" -f $PID)

while ($true) {
    $settings = Read-KeyValueFile -Path $script:StartFilePath
    $stageContext = Get-CurrentStageContext -Settings $settings
    $stage = [string]$stageContext.Stage
    $stageRunDir = [string]$stageContext.RunDir

    if ([string]$settings.SESSION_FINAL_STATUS -in @('PASS', 'FAIL', 'BLOCKED') -and [string]$settings.A_FINAL_STATUS -ne 'RUNNING' -and [string]$settings.B_FINAL_STATUS -ne 'RUNNING') {
        Write-CompanionLog ("complete session_status={0} a={1} b={2}" -f [string]$settings.SESSION_FINAL_STATUS, [string]$settings.A_FINAL_STATUS, [string]$settings.B_FINAL_STATUS)
        break
    }

    if ([string]::IsNullOrWhiteSpace($supervisorLogPath) -or -not (Test-Path -LiteralPath $supervisorLogPath)) {
        $supervisorLogPath = Get-LatestSupervisorLog
    }

    $supervisorQuiet = $false
    if (-not [string]::IsNullOrWhiteSpace($supervisorLogPath) -and (Test-Path -LiteralPath $supervisorLogPath)) {
        $supervisorAgeMinutes = ((Get-Date) - (Get-Item -LiteralPath $supervisorLogPath).LastWriteTime).TotalMinutes
        if ($supervisorAgeMinutes -ge $SupervisorQuietMinutes) {
            $supervisorQuiet = $true
        }
    }
    else {
        $supervisorQuiet = $true
    }

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
    $remoteChainCount = Get-RemoteChainCount
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
        $stallSince = Get-Date
    }

    Write-CompanionLog ("heartbeat stage={0} row_count={1} file_count={2} latest_path={3} remote_chain_count={4} supervisor_quiet={5}" -f $currentState.Stage, $currentState.RowCount, $currentState.FileCount, (Convert-ToRepoRelativePath -Path $currentState.LatestPath), $currentState.RemoteChainCount, $supervisorQuiet)

    $blockedReason = ''
    $blockedDetail = ''
    if ($supervisorQuiet) {
        $blockedReason = 'supervisor-quiet'
        $blockedDetail = 'Supervisor heartbeat missing beyond threshold'
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