param(
    [Parameter(Mandatory = $true)][string]$StartFile,
    [AllowEmptyString()][string]$CurrentARunDir = "",
    [AllowEmptyString()][string]$CurrentBRunDir = "",
    [ValidateSet('A', 'B')][string]$StartFromStage = 'A',
    [ValidateRange(1, 8)][int]$CurrentAStartRound = 1,
    [ValidateRange(15, 300)][int]$PollSec = 60,
    [ValidateRange(0, 3)][int]$MaxStageRestarts = 2
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

function Convert-WindowsPathToMsysPath {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return ""
    }

    if ($Path -match '^([a-zA-Z]):\\(.*)$') {
        $drive = $Matches[1].ToLowerInvariant()
        $rest = $Matches[2] -replace '\\', '/'
        return "/$drive/$rest"
    }

    return $Path.Replace('\\', '/')
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
            Write-Output "[AB-SUPERVISOR] single_instance_conflict mutex=$name start_file=$StartFilePath"
            $mutex.Dispose()
            throw "Another unattended_ab_supervisor instance is already active for this start file"
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

function Write-SupervisorLog {
    param([string]$Message)

    $timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $line = "[AB-SUPERVISOR] timestamp=$timestamp $Message"

    $maxAttempts = 5
    $written = $false
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        $stream = $null
        $writer = $null
        try {
            $stream = New-Object System.IO.FileStream($script:SupervisorLog, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite)
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
        Write-Warning ("[AB-SUPERVISOR] log_write_failed path={0}" -f $script:SupervisorLog)
    }

    Write-Host $line
}

function Get-ProcessMap {
    $map = @{}
    foreach ($processInfo in @(Get-CimInstance Win32_Process)) {
        $map[[int]$processInfo.ProcessId] = $processInfo
    }

    return $map
}

function Get-ChildMap {
    param([hashtable]$ProcessMap)

    $childMap = @{}
    foreach ($processInfo in $ProcessMap.Values) {
        $parentPid = [int]$processInfo.ParentProcessId
        if (-not $childMap.ContainsKey($parentPid)) {
            $childMap[$parentPid] = @()
        }
        $childMap[$parentPid] += [int]$processInfo.ProcessId
    }

    return $childMap
}

function Get-DescendantIds {
    param(
        [int]$RootPid,
        [hashtable]$ChildMap
    )

    $queue = New-Object 'System.Collections.Generic.Queue[int]'
    $seen = New-Object 'System.Collections.Generic.HashSet[int]'
    $queue.Enqueue($RootPid)
    [void]$seen.Add($RootPid)

    while ($queue.Count -gt 0) {
        $targetPid = $queue.Dequeue()
        if (-not $ChildMap.ContainsKey($targetPid)) {
            continue
        }

        foreach ($childPid in @($ChildMap[$targetPid])) {
            $resolvedChildPid = [int]$childPid
            if ($seen.Add($resolvedChildPid)) {
                $queue.Enqueue($resolvedChildPid)
            }
        }
    }

    return @($seen)
}

function Get-DepthFromParentMap {
    param(
        [int]$TargetPid,
        [hashtable]$ProcessMap
    )

    $depth = 0
    $cursorPid = $TargetPid
    while ($ProcessMap.ContainsKey($cursorPid)) {
        $parentPid = [int]$ProcessMap[$cursorPid].ParentProcessId
        if ($parentPid -le 0 -or $parentPid -eq $cursorPid) {
            break
        }
        $depth++
        $cursorPid = $parentPid
    }

    return $depth
}

function Get-LatestTimestampedDirectory {
    param(
        [string]$Root,
        [Nullable[datetime]]$After = $null
    )

    if (-not (Test-Path -LiteralPath $Root)) {
        return $null
    }

    $dirs = @(Get-ChildItem -LiteralPath $Root -Directory | Where-Object { $_.Name -notlike '_*' })
    if ($null -ne $After) {
        $dirs = @($dirs | Where-Object { $_.CreationTime -ge $After -or $_.LastWriteTime -ge $After })
    }

    if ($dirs.Count -eq 0) {
        return $null
    }

    return ($dirs | Sort-Object LastWriteTime, CreationTime, Name | Select-Object -Last 1)
}

function Get-CsvRowCount {
    param([string]$Path)

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

function Get-StageFinalStatus {
    param([string]$RunDir)

    $statusPath = Join-Path $RunDir 'final_status.json'
    if (-not (Test-Path -LiteralPath $statusPath)) {
        return [pscustomobject]@{
            Exists = $false
            Result = ''
            ExitCode = -1
            SummaryCsv = ''
            OutDir = $RunDir
        }
    }

    try {
        $statusObject = (Get-Content -LiteralPath $statusPath -Raw | ConvertFrom-Json)
        return [pscustomobject]@{
            Exists = $true
            Result = [string]$statusObject.Result
            ExitCode = [int]$statusObject.ExitCode
            SummaryCsv = [string]$statusObject.SummaryCsv
            OutDir = [string]$statusObject.OutDir
        }
    }
    catch {
        return [pscustomobject]@{
            Exists = $false
            Result = ''
            ExitCode = -1
            SummaryCsv = ''
            OutDir = $RunDir
        }
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

function Get-RemoteChainSnapshot {
    $remoteMatches = @()
    foreach ($processInfo in @(Get-CimInstance Win32_Process)) {
        $commandLine = [string]$processInfo.CommandLine
        if ([string]::IsNullOrWhiteSpace($commandLine)) {
            continue
        }

        if ($commandLine -match 'remote_build_and_test\.sh|ssh(?:\.exe)?|whois-win64\.exe|whois-x86_64') {
            $remoteMatches += [pscustomobject]@{
                ProcessId = [int]$processInfo.ProcessId
                Name = [string]$processInfo.Name
                CommandLine = $commandLine
            }
        }
    }

    return @($remoteMatches)
}

function Capture-RestartEvidence {
    param([hashtable]$Stage)

    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $evidenceDir = Join-Path $Stage.RunDir (Join-Path 'restart_evidence' $stamp)
    New-Item -ItemType Directory -Path $evidenceDir -Force | Out-Null

    @(Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, Name, CommandLine) |
        Format-List | Out-File -FilePath (Join-Path $evidenceDir 'local_process_snapshot.txt') -Encoding utf8

    @(Get-ChildItem -LiteralPath $Stage.RunDir -Recurse -Force | Select-Object FullName, LastWriteTime, Length) |
        Format-Table -AutoSize | Out-String | Out-File -FilePath (Join-Path $evidenceDir 'stage_run_tree.txt') -Encoding utf8

    $stageInnerRunDir = [string]($Stage.InnerRunDir)
    if (-not [string]::IsNullOrWhiteSpace($stageInnerRunDir) -and (Test-Path -LiteralPath $stageInnerRunDir)) {
        @(Get-ChildItem -LiteralPath $stageInnerRunDir -Recurse -Force | Select-Object FullName, LastWriteTime, Length) |
            Format-Table -AutoSize | Out-String | Out-File -FilePath (Join-Path $evidenceDir 'inner_run_tree.txt') -Encoding utf8
    }

    $candidatePaths = @(
        (Join-Path ([string]($Stage.RunDir)) 'summary_partial.csv'),
        (Join-Path ([string]($Stage.RunDir)) 'summary.csv')
    )
    if (-not [string]::IsNullOrWhiteSpace($stageInnerRunDir)) {
        $candidatePaths += (Join-Path $stageInnerRunDir 'summary_partial.csv')
    }

    foreach ($candidate in $candidatePaths) {
        if (Test-Path -LiteralPath $candidate) {
            Copy-Item -LiteralPath $candidate -Destination (Join-Path $evidenceDir ([System.IO.Path]::GetFileName($candidate))) -Force
        }
    }

    try {
        $clearLines = (& $script:ClearRemoteLockScript -RemoteIp $script:Settings.REMOTE_IP -RemoteUser $script:Settings.REMOTE_USER -KeyPath $script:RemoteKeyPathWindows -DryRun 2>&1)
        @($clearLines | ForEach-Object { [string]$_ }) | Out-File -FilePath (Join-Path $evidenceDir 'remote_lock_dryrun.txt') -Encoding utf8
    }
    catch {
        $_.Exception.Message | Out-File -FilePath (Join-Path $evidenceDir 'remote_lock_dryrun.txt') -Encoding utf8
    }

    return $evidenceDir
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
        [AllowNull()][hashtable]$Stage
    )

    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $packageDir = Join-Path $script:SupervisorOutDir ("blocked_package_" + $stamp)
    New-Item -ItemType Directory -Path $packageDir -Force | Out-Null

    $stageName = if ($null -eq $Stage) { '' } else { [string]$Stage.Name }
    $stageRunDir = if ($null -eq $Stage) { '' } else { [string]$Stage.RunDir }
    $stageInnerRunDir = if ($null -eq $Stage) { '' } else { [string]$Stage.InnerRunDir }

    @(Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, Name, CommandLine) |
        Format-List | Out-File -FilePath (Join-Path $packageDir 'local_process_snapshot.txt') -Encoding utf8

    if (-not [string]::IsNullOrWhiteSpace($stageRunDir) -and (Test-Path -LiteralPath $stageRunDir)) {
        @(Get-ChildItem -LiteralPath $stageRunDir -Recurse -Force | Select-Object FullName, LastWriteTime, Length) |
            Format-Table -AutoSize | Out-String | Out-File -FilePath (Join-Path $packageDir 'stage_run_tree.txt') -Encoding utf8
    }

    if (-not [string]::IsNullOrWhiteSpace($stageInnerRunDir) -and (Test-Path -LiteralPath $stageInnerRunDir)) {
        @(Get-ChildItem -LiteralPath $stageInnerRunDir -Recurse -Force | Select-Object FullName, LastWriteTime, Length) |
            Format-Table -AutoSize | Out-String | Out-File -FilePath (Join-Path $packageDir 'inner_run_tree.txt') -Encoding utf8
    }

    Copy-PathIfExists -SourcePath $script:StartFilePath -DestinationDir $packageDir
    Copy-PathIfExists -SourcePath $script:SupervisorLog -DestinationDir $packageDir
    $candidatePaths = @()
    if (-not [string]::IsNullOrWhiteSpace($stageRunDir)) {
        $candidatePaths += @(
            (Join-Path $stageRunDir 'summary_partial.csv'),
            (Join-Path $stageRunDir 'summary.csv'),
            (Join-Path $stageRunDir 'final_status.json'),
            (Join-Path $stageRunDir 'final_status.txt')
        )
    }
    if (-not [string]::IsNullOrWhiteSpace($stageInnerRunDir)) {
        $candidatePaths += @(
            (Join-Path $stageInnerRunDir 'summary_partial.csv'),
            (Join-Path $stageInnerRunDir 'summary.csv'),
            (Join-Path $stageInnerRunDir 'final_status.json'),
            (Join-Path $stageInnerRunDir 'final_status.txt')
        )
    }

    foreach ($candidate in $candidatePaths) {
        Copy-PathIfExists -SourcePath $candidate -DestinationDir $packageDir
    }

    if (-not [string]::IsNullOrWhiteSpace($stageRunDir) -and (Test-Path -LiteralPath $stageRunDir)) {
        foreach ($logFile in @(Get-ChildItem -LiteralPath $stageRunDir -Filter '*.log' -File -ErrorAction SilentlyContinue)) {
            Copy-PathIfExists -SourcePath $logFile.FullName -DestinationDir $packageDir
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($stageInnerRunDir) -and (Test-Path -LiteralPath $stageInnerRunDir)) {
        foreach ($logFile in @(Get-ChildItem -LiteralPath $stageInnerRunDir -Filter '*.log' -File -ErrorAction SilentlyContinue)) {
            Copy-PathIfExists -SourcePath $logFile.FullName -DestinationDir $packageDir
        }
    }

    try {
        $clearLines = (& $script:ClearRemoteLockScript -RemoteIp $script:Settings.REMOTE_IP -RemoteUser $script:Settings.REMOTE_USER -KeyPath $script:RemoteKeyPathWindows -DryRun 2>&1)
        @($clearLines | ForEach-Object { [string]$_ }) | Out-File -FilePath (Join-Path $packageDir 'remote_lock_dryrun.txt') -Encoding utf8
    }
    catch {
        $_.Exception.Message | Out-File -FilePath (Join-Path $packageDir 'remote_lock_dryrun.txt') -Encoding utf8
    }

    $metadata = [ordered]@{
        Reason = $Reason
        Detail = $Detail
        Stage = $stageName
        StageRunDir = (Convert-ToRepoRelativePath -Path $stageRunDir)
        StageInnerRunDir = (Convert-ToRepoRelativePath -Path $stageInnerRunDir)
        StartFile = (Convert-ToRepoRelativePath -Path $script:StartFilePath)
        SupervisorLog = (Convert-ToRepoRelativePath -Path $script:SupervisorLog)
        GeneratedAt = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    }
    ($metadata | ConvertTo-Json -Depth 4) | Out-File -FilePath (Join-Path $packageDir 'metadata.json') -Encoding utf8
    @(
        "reason=$Reason"
        "detail=$Detail"
        "stage=$stageName"
        "stage_run_dir=$((Convert-ToRepoRelativePath -Path $stageRunDir))"
        "stage_inner_run_dir=$((Convert-ToRepoRelativePath -Path $stageInnerRunDir))"
        "start_file=$((Convert-ToRepoRelativePath -Path $script:StartFilePath))"
        "supervisor_log=$((Convert-ToRepoRelativePath -Path $script:SupervisorLog))"
        "generated_at=$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))"
    ) | Out-File -FilePath (Join-Path $packageDir 'metadata.txt') -Encoding utf8

    return $packageDir
}

function Stop-StageProcessTree {
    param([hashtable]$Stage)

    $processMap = Get-ProcessMap
    $childMap = Get-ChildMap -ProcessMap $processMap
    $rootSet = New-Object 'System.Collections.Generic.HashSet[int]'
    $taskLeaf = ([System.IO.Path]::GetFileName([string]$Stage.TaskDefinition)).ToLowerInvariant()
    $entryLeaf = ([System.IO.Path]::GetFileName([string]$Stage.EntryScript)).ToLowerInvariant()

    foreach ($processInfo in $processMap.Values) {
        $commandLine = ([string]$processInfo.CommandLine).ToLowerInvariant()
        if ([string]::IsNullOrWhiteSpace($commandLine)) {
            continue
        }

        if ($commandLine.Contains($taskLeaf) -or $commandLine.Contains($entryLeaf)) {
            [void]$rootSet.Add([int]$processInfo.ProcessId)
            continue
        }

        if ($commandLine.Contains('start_dev_verify_8round_multiround.ps1') -and $commandLine.Contains($taskLeaf)) {
            [void]$rootSet.Add([int]$processInfo.ProcessId)
        }
    }

    if ([int]$Stage.LaunchProcessId -gt 0 -and $processMap.ContainsKey([int]$Stage.LaunchProcessId)) {
        [void]$rootSet.Add([int]$Stage.LaunchProcessId)
    }

    $killSet = New-Object 'System.Collections.Generic.HashSet[int]'
    foreach ($rootPid in @($rootSet)) {
        foreach ($targetPid in @(Get-DescendantIds -RootPid ([int]$rootPid) -ChildMap $childMap)) {
            [void]$killSet.Add([int]$targetPid)
        }
    }

    $killed = @()
    $orderedTargets = @($killSet | Sort-Object { Get-DepthFromParentMap -TargetPid ([int]$_) -ProcessMap $processMap } -Descending)
    foreach ($targetPid in $orderedTargets) {
        try {
            Stop-Process -Id ([int]$targetPid) -Force -ErrorAction Stop
            $killed += [int]$targetPid
        }
        catch {
        }
    }

    return @($killed)
}

function Invoke-SafeRemoteLockCleanup {
    try {
        $lines = (& $script:ClearRemoteLockScript -RemoteIp $script:Settings.REMOTE_IP -RemoteUser $script:Settings.REMOTE_USER -KeyPath $script:RemoteKeyPathWindows 2>&1)
        $text = (@($lines | ForEach-Object { [string]$_ }) -join ' | ')
        Write-SupervisorLog "remote_lock_cleanup result=$text"
    }
    catch {
        Write-SupervisorLog "remote_lock_cleanup result=error detail=$($_.Exception.Message)"
    }
}

function Start-StageRun {
    param([hashtable]$Stage)

    $env:AUTO_REMOTE_IP = [string]$script:Settings.REMOTE_IP
    $env:AUTO_REMOTE_USER = [string]$script:Settings.REMOTE_USER
    $env:AUTO_REMOTE_KEYPATH = [string]$script:RemoteKeyPathForEnv
    $env:AUTO_QUERIES = [string]$script:Settings.QUERIES
    $env:AUTO_TERMINAL_WATCHDOG_MODE = [string]$script:Settings.TERMINAL_WATCHDOG_MODE
    $env:AUTO_TERMINAL_WATCHDOG_INTERVAL_SEC = [string]$script:Settings.TERMINAL_WATCHDOG_INTERVAL_SEC
    $env:AUTO_TERMINAL_WATCHDOG_MIN_AGE_SEC = [string]$script:Settings.TERMINAL_WATCHDOG_MIN_AGE_SEC

    $powershellPath = Join-Path $PSHOME 'powershell.exe'
    if (-not (Test-Path -LiteralPath $powershellPath)) {
        $powershellPath = 'powershell.exe'
    }

    $entryScriptPath = Resolve-RepoPath -Path ([string]$Stage.EntryScript)
    $taskLeaf = [System.IO.Path]::GetFileName([string]$Stage.TaskDefinition)
    $launchStamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $stdoutLog = Join-Path $script:SupervisorOutDir ("{0}_launch_{1}.stdout.log" -f [string]$Stage.Name, $launchStamp)
    $stderrLog = Join-Path $script:SupervisorOutDir ("{0}_launch_{1}.stderr.log" -f [string]$Stage.Name, $launchStamp)
    $launchTime = Get-Date
    $previousRunDir = [string]$Stage.RunDir
    $launchMode = if ([string]$script:Settings.RUN_MODE -eq 'foreground-visible') { 'visible-noexit' } else { 'hidden-redirect' }

    if ($launchMode -eq 'visible-noexit') {
        $processInfo = Start-Process -FilePath $powershellPath -WorkingDirectory $script:RepoRoot -ArgumentList @(
            '-NoExit',
            '-NoProfile',
            '-ExecutionPolicy', 'Bypass',
            '-File', $entryScriptPath,
            $taskLeaf
        ) -PassThru
    }
    else {
        $processInfo = Start-Process -FilePath $powershellPath -WorkingDirectory $script:RepoRoot -ArgumentList @(
            '-NoProfile',
            '-ExecutionPolicy', 'Bypass',
            '-File', $entryScriptPath,
            $taskLeaf
        ) -WindowStyle Hidden -RedirectStandardOutput $stdoutLog -RedirectStandardError $stderrLog -PassThru
    }

    $detectedRunDir = ''
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        $candidate = Get-LatestTimestampedDirectory -Root $script:SessionOutDirRoot -After $launchTime.AddSeconds(-2)
        if ($null -ne $candidate) {
            $candidatePath = $candidate.FullName
            if ([string]::IsNullOrWhiteSpace($previousRunDir) -or ([System.IO.Path]::GetFullPath($candidatePath) -ne [System.IO.Path]::GetFullPath($previousRunDir))) {
                $detectedRunDir = $candidatePath
                break
            }
        }

        Start-Sleep -Seconds 5
    }

    if ([string]::IsNullOrWhiteSpace($detectedRunDir)) {
        throw "Failed to detect $([string]$Stage.Name) session directory after launch"
    }

    $Stage.LaunchProcessId = [int]$processInfo.Id
    $Stage.RunDir = $detectedRunDir
    $Stage.StartTime = (Get-Item -LiteralPath $detectedRunDir).CreationTime
    $Stage.InnerRunDir = ''

    $stdoutRel = if ($launchMode -eq 'hidden-redirect') { Convert-ToRepoRelativePath -Path $stdoutLog } else { '(visible-noexit-window)' }
    Write-SupervisorLog ("stage_start stage={0} pid={1} launch_mode={2} run_dir={3} stdout={4}" -f [string]$Stage.Name, $processInfo.Id, $launchMode, (Convert-ToRepoRelativePath -Path $detectedRunDir), $stdoutRel)
    return $Stage
}

function Capture-ASuccessSnapshot {
    param([string]$RunDir)

    $snapshotDir = Join-Path $RunDir 'a_success_snapshot'
    $sourceDir = Join-Path $snapshotDir 'source'
    New-Item -ItemType Directory -Path $sourceDir -Force | Out-Null

    $statusRel = Convert-ToRepoRelativePath -Path (Join-Path $RunDir 'final_status.json')
    $summaryRel = Convert-ToRepoRelativePath -Path (Join-Path $RunDir 'summary.csv')

    $statusRaw = @((& git -C $script:RepoRoot status --short 2>&1) | ForEach-Object { [string]$_ })
    $statusFiltered = @($statusRaw | Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and $_ -notmatch '^warning:' })
    $sourceState = if ($statusFiltered.Count -eq 0) { 'CLEAN' } else { ($statusFiltered -join ' | ') }
    $sourceState | Out-File -FilePath (Join-Path $snapshotDir 'source_state.txt') -Encoding utf8

    $diffNamesRaw = @((& git -C $script:RepoRoot diff --name-only -- src include 2>&1) | ForEach-Object { [string]$_ })
    $diffNames = @($diffNamesRaw | Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and $_ -notmatch '^warning:' })
    $diffNames | Out-File -FilePath (Join-Path $snapshotDir 'source_files.txt') -Encoding utf8

    foreach ($relativePath in $diffNames) {
        $sourcePath = Join-Path $script:RepoRoot $relativePath
        if (-not (Test-Path -LiteralPath $sourcePath)) {
            continue
        }

        $destinationPath = Join-Path $sourceDir ($relativePath -replace '/', '\\')
        $destinationParent = Split-Path -Parent $destinationPath
        if (-not (Test-Path -LiteralPath $destinationParent)) {
            New-Item -ItemType Directory -Path $destinationParent -Force | Out-Null
        }

        Copy-Item -LiteralPath $sourcePath -Destination $destinationPath -Force
    }

    $patchPath = Join-Path $snapshotDir 'source.patch'
    $patchRaw = @((& git -C $script:RepoRoot diff --binary -- src include 2>&1) | ForEach-Object { [string]$_ })
    $patchRaw | Out-File -FilePath $patchPath -Encoding utf8

    return [pscustomobject]@{
        FinalStatus = $statusRel
        Summary = $summaryRel
        SourceState = $sourceState
        SnapshotDir = (Convert-ToRepoRelativePath -Path $snapshotDir)
    }
}

function Monitor-StageUntilFinal {
    param([hashtable]$Stage)

    $policyBaseline = $null
    $lastPolicyCheckAt = $null
    $stallSince = $null
    $d1CompletedLogged = $false

    while ($true) {
        $finalStatus = Get-StageFinalStatus -RunDir ([string]$Stage.RunDir)
        if ($finalStatus.Exists) {
            Write-SupervisorLog ("stage_final stage={0} result={1} exit_code={2} run_dir={3}" -f [string]$Stage.Name, $finalStatus.Result, $finalStatus.ExitCode, (Convert-ToRepoRelativePath -Path ([string]$Stage.RunDir)))
            return $finalStatus
        }

        $innerCandidate = Get-LatestTimestampedDirectory -Root $script:AutopilotOutDirRoot -After ([datetime]$Stage.StartTime).AddSeconds(-5)
        if ($null -ne $innerCandidate) {
            $Stage.InnerRunDir = $innerCandidate.FullName
        }

        $summaryPartialPath = Join-Path ([string]$Stage.RunDir) 'summary_partial.csv'
        $rowCount = Get-CsvRowCount -Path $summaryPartialPath
        $isD1Active = ($rowCount -lt 1 -and [int]$Stage.StartRound -eq 1)
        $artifactState = Get-ArtifactState -Paths @([string]$Stage.RunDir, [string]$Stage.InnerRunDir)
        $remoteChain = Get-RemoteChainSnapshot
        $now = Get-Date

        if ($isD1Active) {
            if ($null -eq $policyBaseline) {
                $policyBaseline = $artifactState
                $lastPolicyCheckAt = $now
                Write-SupervisorLog ("d1_monitor stage={0} age_min=0 file_count={1} latest_path={2}" -f [string]$Stage.Name, $artifactState.FileCount, (Convert-ToRepoRelativePath -Path $artifactState.LatestPath))
            }

            $ageMin = ($now - [datetime]$Stage.StartTime).TotalMinutes
            if ($ageMin -ge 30 -and (($now - $lastPolicyCheckAt).TotalMinutes -ge 10)) {
                $noArtifactProgress = ($artifactState.LatestWriteTime -le $policyBaseline.LatestWriteTime)
                $noFileGrowth = ($artifactState.FileCount -le $policyBaseline.FileCount)
                $noRemoteChain = (@($remoteChain).Count -eq 0)
                Write-SupervisorLog ("d1_check stage={0} age_min={1:N1} no_artifact_progress={2} no_file_growth={3} remote_chain_count={4} inner_run={5}" -f [string]$Stage.Name, $ageMin, $noArtifactProgress, $noFileGrowth, @($remoteChain).Count, (Convert-ToRepoRelativePath -Path ([string]$Stage.InnerRunDir)))

                if ($noArtifactProgress -and $noFileGrowth -and $noRemoteChain) {
                    if ($null -eq $stallSince) {
                        $stallSince = $now
                    }

                    $stallMinutes = ($now - $stallSince).TotalMinutes
                    if ($stallMinutes -ge 20) {
                        if ([int]$Stage.RestartCount -ge [int]$Stage.MaxRestarts) {
                            throw "Stage $([string]$Stage.Name) exceeded max restarts after D1 stall"
                        }

                        $evidenceDir = Capture-RestartEvidence -Stage $Stage
                        $evidenceRel = Convert-ToRepoRelativePath -Path $evidenceDir
                        $restartNote = "stage=$([string]$Stage.Name) reason=d1-stall evidence=$evidenceRel"
                        $newRestartNotes = Append-DelimitedNote -Existing ([string]$script:Settings.RESTART_EVIDENCE_NOTES) -Append $restartNote
                        $script:Settings.RESTART_EVIDENCE_NOTES = $newRestartNotes
                        Set-KeyValueFileValues -Path $script:StartFilePath -Values @{
                            RESTART_EVIDENCE_NOTES = $newRestartNotes
                            SESSION_FINAL_NOTES = (Append-DelimitedNote -Existing ([string]$script:Settings.SESSION_FINAL_NOTES) -Append ("{0} restart evidence={1}" -f [string]$Stage.Name, $evidenceRel))
                        }

                        $killed = Stop-StageProcessTree -Stage $Stage
                        Write-SupervisorLog ("stage_cleanup stage={0} killed_count={1} killed_pids={2}" -f [string]$Stage.Name, @($killed).Count, ((@($killed) -join ',')))
                        Invoke-SafeRemoteLockCleanup

                        $Stage.RestartCount = [int]$Stage.RestartCount + 1
                        $Stage = Start-StageRun -Stage $Stage
                        $script:Settings.SESSION_FINAL_NOTES = "{0} restarted at {1}; run_dir={2}; supervisor_log={3}" -f [string]$Stage.Name, (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'), (Convert-ToRepoRelativePath -Path ([string]$Stage.RunDir)), (Convert-ToRepoRelativePath -Path $script:SupervisorLog)
                        if ([string]$Stage.Name -eq 'A') {
                            Set-KeyValueFileValues -Path $script:StartFilePath -Values @{
                                A_FINAL_STATUS = 'RUNNING'
                                SESSION_FINAL_STATUS = 'RUNNING'
                                SESSION_FINAL_NOTES = [string]$script:Settings.SESSION_FINAL_NOTES
                            }
                        }
                        else {
                            Set-KeyValueFileValues -Path $script:StartFilePath -Values @{
                                B_FINAL_STATUS = 'RUNNING'
                                SESSION_FINAL_STATUS = 'RUNNING'
                                SESSION_FINAL_NOTES = [string]$script:Settings.SESSION_FINAL_NOTES
                            }
                        }

                        $policyBaseline = $null
                        $lastPolicyCheckAt = $null
                        $stallSince = $null
                        $d1CompletedLogged = $false
                        continue
                    }
                }
                else {
                    $stallSince = $null
                }

                $policyBaseline = $artifactState
                $lastPolicyCheckAt = $now
            }
        }
        elseif ([int]$Stage.StartRound -eq 1 -and -not $d1CompletedLogged) {
            Write-SupervisorLog ("d1_complete stage={0} row_count={1} run_dir={2}" -f [string]$Stage.Name, $rowCount, (Convert-ToRepoRelativePath -Path ([string]$Stage.RunDir)))
            $d1CompletedLogged = $true
            $stallSince = $null
        }

        Write-SupervisorLog ("heartbeat stage={0} row_count={1} file_count={2} latest_path={3} remote_chain_count={4}" -f [string]$Stage.Name, $rowCount, $artifactState.FileCount, (Convert-ToRepoRelativePath -Path $artifactState.LatestPath), @($remoteChain).Count)
        Start-Sleep -Seconds $PollSec
    }
}

$script:RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$script:StartFilePath = Resolve-RepoPath -Path $StartFile
$script:InstanceMutex = Acquire-InstanceMutex -Role 'supervisor' -StartFilePath $script:StartFilePath
$script:SessionOutDirRoot = Join-Path $script:RepoRoot 'out\artifacts\dev_verify_multiround'
$script:AutopilotOutDirRoot = Join-Path $script:RepoRoot 'out\artifacts\autopilot_dev_recheck_8round'
$script:ClearRemoteLockScript = Join-Path $script:RepoRoot 'tools\dev\clear_remote_lock.ps1'
$script:Settings = Read-KeyValueFile -Path $script:StartFilePath
$settingsRemoteKeyRaw = [string]$script:Settings.REMOTE_KEYPATH
$settingsRemoteKeyWindows = Convert-MsysPathToWindowsPath -Path $settingsRemoteKeyRaw
if (-not [string]::IsNullOrWhiteSpace($settingsRemoteKeyWindows) -and (Test-Path -LiteralPath $settingsRemoteKeyWindows)) {
    $script:RemoteKeyPathWindows = $settingsRemoteKeyWindows
    $script:RemoteKeyPathForEnv = if ([string]::IsNullOrWhiteSpace($settingsRemoteKeyRaw)) {
        Convert-WindowsPathToMsysPath -Path $settingsRemoteKeyWindows
    }
    else {
        $settingsRemoteKeyRaw
    }
}
else {
    $fallbackRemoteKeyWindows = Join-Path ([Environment]::GetFolderPath('UserProfile')) '.ssh\id_rsa'
    if (-not (Test-Path -LiteralPath $fallbackRemoteKeyWindows)) {
        throw "SSH private key not found for supervisor fallback: $fallbackRemoteKeyWindows"
    }

    $script:RemoteKeyPathWindows = $fallbackRemoteKeyWindows
    $script:RemoteKeyPathForEnv = Convert-WindowsPathToMsysPath -Path $fallbackRemoteKeyWindows
}

$supervisorStamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$script:SupervisorOutDir = Join-Path $script:RepoRoot (Join-Path 'out\artifacts\ab_supervisor' $supervisorStamp)
New-Item -ItemType Directory -Path $script:SupervisorOutDir -Force | Out-Null
$script:SupervisorLog = Join-Path $script:SupervisorOutDir 'supervisor.log'

$stageA = $null
$stageB = $null

if ([string]$StartFromStage -eq 'B') {
    $currentRunDir = $CurrentBRunDir
    if ([string]::IsNullOrWhiteSpace($currentRunDir) -and [string]$script:Settings.SESSION_FINAL_NOTES -match 'run_dir=([^;]+)') {
        $currentRunDir = $Matches[1].Trim()
    }
    if ([string]::IsNullOrWhiteSpace($currentRunDir)) {
        $latestSessionDir = Get-LatestTimestampedDirectory -Root $script:SessionOutDirRoot -After $null
        if ($null -ne $latestSessionDir) {
            $currentRunDir = $latestSessionDir.FullName
        }
    }

    if ([string]::IsNullOrWhiteSpace($currentRunDir)) {
        throw 'Unable to resolve current B run directory'
    }

    $currentRunDirResolved = Resolve-RepoPath -Path $currentRunDir
    Write-SupervisorLog ("startup start_file={0} current_b_run_dir={1}" -f (Convert-ToRepoRelativePath -Path $script:StartFilePath), (Convert-ToRepoRelativePath -Path $currentRunDirResolved))
    Write-SupervisorLog ("startup_pid pid={0}" -f $PID)

    if ([string]$script:Settings.A_FINAL_STATUS -ne 'PASS') {
        Write-SupervisorLog ("b_attach_warning a_final_status={0}" -f [string]$script:Settings.A_FINAL_STATUS)
    }

    $script:Settings.SESSION_FINAL_NOTES = Append-DelimitedNote -Existing ([string]$script:Settings.SESSION_FINAL_NOTES) -Append ("run_dir=" + (Convert-ToRepoRelativePath -Path $currentRunDirResolved))
    $script:Settings.SESSION_FINAL_NOTES = Append-DelimitedNote -Existing ([string]$script:Settings.SESSION_FINAL_NOTES) -Append ("supervisor_log=" + (Convert-ToRepoRelativePath -Path $script:SupervisorLog))
    Set-KeyValueFileValues -Path $script:StartFilePath -Values @{
        SESSION_FINAL_NOTES = [string]$script:Settings.SESSION_FINAL_NOTES
    }

    $stageB = [ordered]@{
        Name = 'B'
        TaskDefinition = [string]$script:Settings.B_TASK_DEFINITION
        EntryScript = [string]$script:Settings.ENTRY_SCRIPT_B
        RunDir = $currentRunDirResolved
        StartRound = 1
        StartTime = (Get-Item -LiteralPath $currentRunDirResolved).CreationTime
        InnerRunDir = ''
        LaunchProcessId = 0
        RestartCount = 0
        MaxRestarts = $MaxStageRestarts
    }
}
else {
    $currentRunDir = $CurrentARunDir
    if ([string]::IsNullOrWhiteSpace($currentRunDir) -and [string]$script:Settings.SESSION_FINAL_NOTES -match 'run_dir=([^;]+)') {
        $currentRunDir = $Matches[1].Trim()
    }
    if ([string]::IsNullOrWhiteSpace($currentRunDir)) {
        $latestSessionDir = Get-LatestTimestampedDirectory -Root $script:SessionOutDirRoot -After $null
        if ($null -ne $latestSessionDir) {
            $currentRunDir = $latestSessionDir.FullName
        }
    }

    if ([string]::IsNullOrWhiteSpace($currentRunDir)) {
        throw 'Unable to resolve current A run directory'
    }

    $currentRunDirResolved = Resolve-RepoPath -Path $currentRunDir
    Write-SupervisorLog ("startup start_file={0} current_a_run_dir={1}" -f (Convert-ToRepoRelativePath -Path $script:StartFilePath), (Convert-ToRepoRelativePath -Path $currentRunDirResolved))
    Write-SupervisorLog ("startup_pid pid={0}" -f $PID)

    $script:Settings.SESSION_FINAL_NOTES = Append-DelimitedNote -Existing ([string]$script:Settings.SESSION_FINAL_NOTES) -Append ("run_dir=" + (Convert-ToRepoRelativePath -Path $currentRunDirResolved))
    $script:Settings.SESSION_FINAL_NOTES = Append-DelimitedNote -Existing ([string]$script:Settings.SESSION_FINAL_NOTES) -Append ("supervisor_log=" + (Convert-ToRepoRelativePath -Path $script:SupervisorLog))
    Set-KeyValueFileValues -Path $script:StartFilePath -Values @{
        SESSION_FINAL_NOTES = [string]$script:Settings.SESSION_FINAL_NOTES
    }

    $stageA = [ordered]@{
        Name = 'A'
        TaskDefinition = [string]$script:Settings.A_TASK_DEFINITION
        EntryScript = [string]$script:Settings.ENTRY_SCRIPT_A
        RunDir = $currentRunDirResolved
        StartRound = $CurrentAStartRound
        StartTime = (Get-Item -LiteralPath $currentRunDirResolved).CreationTime
        InnerRunDir = ''
        LaunchProcessId = 0
        RestartCount = 0
        MaxRestarts = $MaxStageRestarts
    }

    $stageB = [ordered]@{
        Name = 'B'
        TaskDefinition = [string]$script:Settings.B_TASK_DEFINITION
        EntryScript = [string]$script:Settings.ENTRY_SCRIPT_B
        RunDir = ''
        StartRound = 1
        StartTime = Get-Date
        InnerRunDir = ''
        LaunchProcessId = 0
        RestartCount = 0
        MaxRestarts = $MaxStageRestarts
    }
}

try {
    if ([string]$StartFromStage -eq 'B') {
        $script:Settings.SESSION_FINAL_NOTES = "B monitor attached at $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss')); run_dir=$((Convert-ToRepoRelativePath -Path ([string]$stageB.RunDir))); supervisor_log=$((Convert-ToRepoRelativePath -Path $script:SupervisorLog))"
        Set-KeyValueFileValues -Path $script:StartFilePath -Values @{
            B_FINAL_STATUS = 'RUNNING'
            SESSION_FINAL_STATUS = 'RUNNING'
            SESSION_FINAL_NOTES = [string]$script:Settings.SESSION_FINAL_NOTES
        }
        Write-SupervisorLog ("b_attach run_dir={0}" -f (Convert-ToRepoRelativePath -Path ([string]$stageB.RunDir)))

        $bFinal = Monitor-StageUntilFinal -Stage $stageB
        if ($bFinal.Result -eq 'pass') {
            $script:Settings.SESSION_FINAL_NOTES = "B PASS after attach; b_run_dir=$((Convert-ToRepoRelativePath -Path ([string]$stageB.RunDir))); supervisor_log=$((Convert-ToRepoRelativePath -Path $script:SupervisorLog))"
            Set-KeyValueFileValues -Path $script:StartFilePath -Values @{
                B_FINAL_STATUS = 'PASS'
                SESSION_FINAL_STATUS = 'PASS'
                SESSION_FINAL_NOTES = [string]$script:Settings.SESSION_FINAL_NOTES
            }
            Write-SupervisorLog 'complete result=pass mode=b-attach'
            exit 0
        }

        $blockedDir = Capture-BlockedPackage -Reason 'b-fail' -Detail 'B final status reported fail in attach mode' -Stage $stageB
        $blockedRel = Convert-ToRepoRelativePath -Path $blockedDir
        $script:Settings.SESSION_FINAL_NOTES = Append-DelimitedNote -Existing ([string]$script:Settings.SESSION_FINAL_NOTES) -Append ("B failed in attach mode; evidence=$blockedRel")
        Set-KeyValueFileValues -Path $script:StartFilePath -Values @{
            B_FINAL_STATUS = 'FAIL'
            SESSION_FINAL_STATUS = 'FAIL'
            SESSION_FINAL_NOTES = [string]$script:Settings.SESSION_FINAL_NOTES
        }
        Write-SupervisorLog ("stop reason=b-fail mode=b-attach evidence={0}" -f $blockedRel)
        exit 1
    }

    $aFinal = Monitor-StageUntilFinal -Stage $stageA
    if ($aFinal.Result -ne 'pass') {
        $blockedDir = Capture-BlockedPackage -Reason 'a-fail' -Detail 'A final status reported fail' -Stage $stageA
        $blockedRel = Convert-ToRepoRelativePath -Path $blockedDir
        $script:Settings.SESSION_FINAL_NOTES = Append-DelimitedNote -Existing ([string]$script:Settings.SESSION_FINAL_NOTES) -Append ("A failed; B blocked; evidence=$blockedRel")
        Set-KeyValueFileValues -Path $script:StartFilePath -Values @{
            A_FINAL_STATUS = 'FAIL'
            B_FINAL_STATUS = 'BLOCKED'
            SESSION_FINAL_STATUS = 'FAIL'
            SESSION_FINAL_NOTES = [string]$script:Settings.SESSION_FINAL_NOTES
        }
        Write-SupervisorLog ("stop reason=a-fail b=blocked evidence={0}" -f $blockedRel)
        exit 1
    }

    $aSnapshot = Capture-ASuccessSnapshot -RunDir ([string]$stageA.RunDir)
    $script:Settings.A_SUCCESS_SNAPSHOT_FINAL_STATUS = [string]$aSnapshot.FinalStatus
    $script:Settings.A_SUCCESS_SNAPSHOT_SUMMARY = [string]$aSnapshot.Summary
    $script:Settings.A_SUCCESS_SNAPSHOT_SOURCE_STATE = [string]$aSnapshot.SourceState
    $script:Settings.SESSION_FINAL_NOTES = "A PASS; a_snapshot_dir=$([string]$aSnapshot.SnapshotDir); launching B; supervisor_log=$((Convert-ToRepoRelativePath -Path $script:SupervisorLog))"
    Set-KeyValueFileValues -Path $script:StartFilePath -Values @{
        A_FINAL_STATUS = 'PASS'
        A_SUCCESS_SNAPSHOT_FINAL_STATUS = [string]$aSnapshot.FinalStatus
        A_SUCCESS_SNAPSHOT_SUMMARY = [string]$aSnapshot.Summary
        A_SUCCESS_SNAPSHOT_SOURCE_STATE = [string]$aSnapshot.SourceState
        SESSION_FINAL_STATUS = 'RUNNING'
        SESSION_FINAL_NOTES = [string]$script:Settings.SESSION_FINAL_NOTES
    }
    Write-SupervisorLog ("a_snapshot final_status={0} summary={1} source_state={2} snapshot_dir={3}" -f [string]$aSnapshot.FinalStatus, [string]$aSnapshot.Summary, [string]$aSnapshot.SourceState, [string]$aSnapshot.SnapshotDir)

    $stageB = Start-StageRun -Stage $stageB
    $script:Settings.SESSION_FINAL_NOTES = "B started at $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss')); run_dir=$((Convert-ToRepoRelativePath -Path ([string]$stageB.RunDir))); supervisor_log=$((Convert-ToRepoRelativePath -Path $script:SupervisorLog))"
    Set-KeyValueFileValues -Path $script:StartFilePath -Values @{
        B_FINAL_STATUS = 'RUNNING'
        SESSION_FINAL_STATUS = 'RUNNING'
        SESSION_FINAL_NOTES = [string]$script:Settings.SESSION_FINAL_NOTES
    }

    $bFinal = Monitor-StageUntilFinal -Stage $stageB
    if ($bFinal.Result -eq 'pass') {
        $script:Settings.SESSION_FINAL_NOTES = "A/B PASS; a_run_dir=$((Convert-ToRepoRelativePath -Path ([string]$stageA.RunDir))); b_run_dir=$((Convert-ToRepoRelativePath -Path ([string]$stageB.RunDir))); supervisor_log=$((Convert-ToRepoRelativePath -Path $script:SupervisorLog))"
        Set-KeyValueFileValues -Path $script:StartFilePath -Values @{
            B_FINAL_STATUS = 'PASS'
            SESSION_FINAL_STATUS = 'PASS'
            SESSION_FINAL_NOTES = [string]$script:Settings.SESSION_FINAL_NOTES
        }
        Write-SupervisorLog 'complete result=pass'
        exit 0
    }

    $blockedDir = Capture-BlockedPackage -Reason 'b-fail' -Detail 'B final status reported fail after A snapshot captured' -Stage $stageB
    $blockedRel = Convert-ToRepoRelativePath -Path $blockedDir
    $script:Settings.SESSION_FINAL_NOTES = Append-DelimitedNote -Existing ([string]$script:Settings.SESSION_FINAL_NOTES) -Append ("B failed after A snapshot captured; evidence=$blockedRel")
    Set-KeyValueFileValues -Path $script:StartFilePath -Values @{
        B_FINAL_STATUS = 'FAIL'
        SESSION_FINAL_STATUS = 'FAIL'
        SESSION_FINAL_NOTES = [string]$script:Settings.SESSION_FINAL_NOTES
    }
    Write-SupervisorLog ("stop reason=b-fail evidence={0}" -f $blockedRel)
    exit 1
}
catch {
    $failureMessage = $_.Exception.Message.Replace("`r", ' ').Replace("`n", ' ')
    $activeStage = $null
    if ($null -ne $stageB -and -not [string]::IsNullOrWhiteSpace([string]$stageB.RunDir)) {
        $activeStage = $stageB
    }
    elseif ($null -ne $stageA -and -not [string]::IsNullOrWhiteSpace([string]$stageA.RunDir)) {
        $activeStage = $stageA
    }
    $blockedDir = Capture-BlockedPackage -Reason 'supervisor-error' -Detail $failureMessage -Stage $activeStage
    $blockedRel = Convert-ToRepoRelativePath -Path $blockedDir
    $script:Settings.SESSION_FINAL_NOTES = Append-DelimitedNote -Existing ([string]$script:Settings.SESSION_FINAL_NOTES) -Append ("supervisor_error=$failureMessage evidence=$blockedRel")
    Set-KeyValueFileValues -Path $script:StartFilePath -Values @{
        SESSION_FINAL_STATUS = 'BLOCKED'
        SESSION_FINAL_NOTES = [string]$script:Settings.SESSION_FINAL_NOTES
    }
    Write-SupervisorLog ("stop reason=supervisor-error detail={0} evidence={1}" -f $failureMessage, $blockedRel)
    throw
}
finally {
    Write-SupervisorLog ("shutdown_pid pid={0}" -f $PID)
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
}