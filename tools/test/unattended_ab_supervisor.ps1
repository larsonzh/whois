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

function Upsert-SessionAnchorNotes {
    param(
        [AllowEmptyString()][string]$Existing,
        [System.Collections.IDictionary]$Anchors
    )

    $segments = New-Object 'System.Collections.Generic.List[string]'
    foreach ($part in @($Existing -split ';')) {
        $segment = [string]$part
        if ([string]::IsNullOrWhiteSpace($segment)) {
            continue
        }

        $trimmed = $segment.Trim()
        if ($trimmed -match '^(run_dir|supervisor_log|live_status)=') {
            continue
        }

        [void]$segments.Add($trimmed)
    }

    foreach ($anchorKey in @('run_dir', 'supervisor_log', 'live_status')) {
        if (-not $Anchors.Contains($anchorKey)) {
            continue
        }

        $value = [string]$Anchors[$anchorKey]
        if ([string]::IsNullOrWhiteSpace($value)) {
            continue
        }

        [void]$segments.Add("$anchorKey=$value")
    }

    return ($segments -join '; ')
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

function Convert-ToIntSetting {
    param(
        [AllowEmptyString()][string]$Value,
        [int]$Default,
        [int]$Min,
        [int]$Max
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $Default
    }

    $parsed = 0
    if (-not [int]::TryParse($Value.Trim(), [ref]$parsed)) {
        return $Default
    }

    if ($parsed -lt $Min) {
        return $Min
    }
    if ($parsed -gt $Max) {
        return $Max
    }

    return $parsed
}

function Convert-ToNullablePositiveInt {
    param([AllowEmptyString()][string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $null
    }

    $parsed = 0
    if (-not [int]::TryParse($Value.Trim(), [ref]$parsed)) {
        return $null
    }

    if ($parsed -le 0) {
        return $null
    }

    return [int]$parsed
}

function Resolve-StageLaunchProcessId {
    param(
        [System.Collections.IDictionary]$Settings,
        [hashtable]$Stage
    )

    if ($null -eq $Settings -or $null -eq $Stage) {
        return 0
    }

    $key = if ([string]$Stage.Name -eq 'A') { 'A_LAUNCH_PID' } else { 'B_LAUNCH_PID' }
    if (-not $Settings.Contains($key)) {
        return 0
    }

    $pidValue = Convert-ToNullablePositiveInt -Value ([string]$Settings[$key])
    if ($null -eq $pidValue) {
        return 0
    }

    return [int]$pidValue
}

function Get-SessionWatchSettings {
    param([System.Collections.IDictionary]$Settings)

    $required = if ($null -ne $Settings -and $Settings.Contains('AI_SESSION_BLOCKING_WATCH_REQUIRED')) {
        Convert-ToBooleanSetting -Value ([string]$Settings.AI_SESSION_BLOCKING_WATCH_REQUIRED) -Default $false
    }
    else {
        $false
    }

    $reportIntervalMin = if ($null -ne $Settings -and $Settings.Contains('AI_SESSION_BLOCKING_WATCH_REPORT_INTERVAL_MIN')) {
        Convert-ToIntSetting -Value ([string]$Settings.AI_SESSION_BLOCKING_WATCH_REPORT_INTERVAL_MIN) -Default 10 -Min 1 -Max 120
    }
    else {
        10
    }

    $scopes = if ($null -ne $Settings -and $Settings.Contains('AI_SESSION_BLOCKING_WATCH_SCOPES') -and -not [string]::IsNullOrWhiteSpace([string]$Settings.AI_SESSION_BLOCKING_WATCH_SCOPES)) {
        [string]$Settings.AI_SESSION_BLOCKING_WATCH_SCOPES
    }
    else {
        'artifacts;supervisor_log;companion_log;compile-step'
    }

    return [pscustomobject]@{
        Required = $required
        ReportIntervalMin = $reportIntervalMin
        Scopes = $scopes
    }
}

function Get-RestartBudgetSettings {
    param(
        [System.Collections.IDictionary]$Settings,
        [int]$DefaultMaxStageRestarts
    )

    $source = 'param'
    $globalMax = $DefaultMaxStageRestarts
    if ($null -ne $Settings -and $Settings.Contains('MAX_STAGE_RESTARTS') -and -not [string]::IsNullOrWhiteSpace([string]$Settings.MAX_STAGE_RESTARTS)) {
        $globalMax = Convert-ToIntSetting -Value ([string]$Settings.MAX_STAGE_RESTARTS) -Default $DefaultMaxStageRestarts -Min 0 -Max 6
        $source = 'start_file'
    }

    $aMax = $globalMax
    if ($null -ne $Settings -and $Settings.Contains('A_MAX_STAGE_RESTARTS') -and -not [string]::IsNullOrWhiteSpace([string]$Settings.A_MAX_STAGE_RESTARTS)) {
        $aMax = Convert-ToIntSetting -Value ([string]$Settings.A_MAX_STAGE_RESTARTS) -Default $globalMax -Min 0 -Max 6
        $source = 'start_file'
    }

    $bMax = $globalMax
    if ($null -ne $Settings -and $Settings.Contains('B_MAX_STAGE_RESTARTS') -and -not [string]::IsNullOrWhiteSpace([string]$Settings.B_MAX_STAGE_RESTARTS)) {
        $bMax = Convert-ToIntSetting -Value ([string]$Settings.B_MAX_STAGE_RESTARTS) -Default $globalMax -Min 0 -Max 6
        $source = 'start_file'
    }

    return [pscustomobject]@{
        Source = $source
        Global = $globalMax
        A = $aMax
        B = $bMax
    }
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

function Write-LiveStatus {
    param([hashtable]$Values)

    if ([string]::IsNullOrWhiteSpace($script:LiveStatusPath)) {
        return
    }

    if ($null -eq $script:LiveStatusState) {
        $script:LiveStatusState = [ordered]@{}
    }

    foreach ($key in $Values.Keys) {
        $script:LiveStatusState[$key] = $Values[$key]
    }
    $script:LiveStatusState.updated_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')

    $json = $script:LiveStatusState | ConvertTo-Json -Depth 8
    $written = $false
    $lastError = ''

    for ($attempt = 1; $attempt -le 4; $attempt++) {
        $stream = $null
        $writer = $null
        try {
            $stream = [System.IO.File]::Open(
                $script:LiveStatusPath,
                [System.IO.FileMode]::Create,
                [System.IO.FileAccess]::Write,
                [System.IO.FileShare]::ReadWrite)
            $writer = New-Object System.IO.StreamWriter($stream, [System.Text.UTF8Encoding]::new($false))
            $writer.Write($json)
            $writer.Flush()
            $written = $true
            break
        }
        catch {
            $lastError = $_.Exception.Message
            if ($attempt -lt 4) {
                Start-Sleep -Milliseconds (80 * $attempt)
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
        Write-Warning ("[AB-SUPERVISOR] live_status_write_failed path={0} detail={1}" -f $script:LiveStatusPath, $lastError)
    }
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

function Resolve-CurrentRunDirWithWait {
    param(
        [string]$StageName,
        [AllowEmptyString()][string]$ProvidedRunDir,
        [string]$SessionOutDirRoot,
        [AllowEmptyString()][string]$SessionNotes,
        [ValidateRange(0, 1800)][int]$WaitTimeoutSec = 180,
        [ValidateRange(1, 60)][int]$PollSec = 5
    )

    $deadline = (Get-Date).AddSeconds($WaitTimeoutSec)
    $loggedWait = $false

    while ($true) {
        $candidateRunDir = $ProvidedRunDir
        if ([string]::IsNullOrWhiteSpace($candidateRunDir)) {
            $candidateRunDir = Get-LatestAnchorValueFromNotes -Notes $SessionNotes -Key 'run_dir'
        }
        if ([string]::IsNullOrWhiteSpace($candidateRunDir)) {
            $latestSessionDir = Get-LatestTimestampedDirectory -Root $SessionOutDirRoot -After $null
            if ($null -ne $latestSessionDir) {
                $candidateRunDir = $latestSessionDir.FullName
            }
        }

        if (-not [string]::IsNullOrWhiteSpace($candidateRunDir)) {
            try {
                return (Resolve-RepoPath -Path $candidateRunDir)
            }
            catch {
                $candidateRunDir = ''
            }
        }

        if ((Get-Date) -ge $deadline) {
            return ''
        }

        if (-not $loggedWait) {
            Write-SupervisorLog ("attach_wait stage={0} reason=run_dir_missing timeout_sec={1} poll_sec={2}" -f $StageName, $WaitTimeoutSec, $PollSec)
            $loggedWait = $true
        }

        Start-Sleep -Seconds $PollSec
    }
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

function Get-StageLaunchProcessSnapshot {
    param([hashtable]$Stage)

    $launchPid = [int]$Stage.LaunchProcessId
    if ($launchPid -le 0) {
        return [pscustomobject]@{
            Alive = $false
            Matched = $false
            ProcessId = $launchPid
            Name = ''
            CommandLine = ''
        }
    }

    $matches = @(Get-CimInstance Win32_Process -Filter ("ProcessId = {0}" -f $launchPid) -ErrorAction SilentlyContinue)
    if ($matches.Count -lt 1) {
        return [pscustomobject]@{
            Alive = $false
            Matched = $false
            ProcessId = $launchPid
            Name = ''
            CommandLine = ''
        }
    }

    $processInfo = $matches[0]
    $commandLine = [string]$processInfo.CommandLine
    $commandLineLower = $commandLine.ToLowerInvariant()
    $entryLeaf = ([System.IO.Path]::GetFileName([string]$Stage.EntryScript)).ToLowerInvariant()
    $taskLeaf = ([System.IO.Path]::GetFileName([string]$Stage.TaskDefinition)).ToLowerInvariant()

    $matched = $true
    if (-not [string]::IsNullOrWhiteSpace($commandLine)) {
        $matched = (
            $commandLineLower.Contains($entryLeaf) -or
            $commandLineLower.Contains($taskLeaf) -or
            $commandLineLower.Contains('start_dev_verify_fastmode_')
        )
    }

    return [pscustomobject]@{
        Alive = $true
        Matched = $matched
        ProcessId = $launchPid
        Name = [string]$processInfo.Name
        CommandLine = $commandLine
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

function New-EmptyArtifactState {
    return [pscustomobject]@{
        FileCount = 0
        LatestWriteTime = [datetime]'2000-01-01 00:00:00'
        LatestPath = ''
    }
}

function Get-RemoteChainSnapshot {
    $remoteIp = [string]$script:Settings.REMOTE_IP
    $remoteUser = [string]$script:Settings.REMOTE_USER

    $remoteMatches = @()
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
            $remoteMatches += [pscustomobject]@{
                ProcessId = [int]$processInfo.ProcessId
                Name = [string]$processInfo.Name
                CommandLine = $commandLineRaw
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
        LiveStatus = (Convert-ToRepoRelativePath -Path $script:LiveStatusPath)
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
        "live_status=$((Convert-ToRepoRelativePath -Path $script:LiveStatusPath))"
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
    $env:AUTO_TASK_STATIC_PRECHECK_POLICY = [string]$script:Settings.TASK_STATIC_PRECHECK_POLICY
    $keepWindowOnExit = Convert-ToBooleanSetting -Value ([string]$script:Settings.KEEP_WINDOW_ON_EXIT) -Default $false
    if ($keepWindowOnExit) {
        $env:AUTO_KEEP_WINDOW_ON_EXIT = 'true'
    }
    else {
        Remove-Item -Path 'Env:AUTO_KEEP_WINDOW_ON_EXIT' -ErrorAction SilentlyContinue
    }

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

    $launchPidKey = if ([string]$Stage.Name -eq 'A') { 'A_LAUNCH_PID' } else { 'B_LAUNCH_PID' }
    Set-KeyValueFileValues -Path $script:StartFilePath -Values @{
        $launchPidKey = [string]$Stage.LaunchProcessId
    }

    $stdoutRel = if ($launchMode -eq 'hidden-redirect') { Convert-ToRepoRelativePath -Path $stdoutLog } else { '(visible-noexit-window)' }
    Write-SupervisorLog ("stage_start stage={0} pid={1} launch_mode={2} run_dir={3} stdout={4}" -f [string]$Stage.Name, $processInfo.Id, $launchMode, (Convert-ToRepoRelativePath -Path $detectedRunDir), $stdoutRel)
    Write-LiveStatus -Values @{
        status = 'running'
        event = 'stage_start'
        current_stage = [string]$Stage.Name
        current_stage_run_dir = (Convert-ToRepoRelativePath -Path $detectedRunDir)
        current_stage_start_round = [int]$Stage.StartRound
        current_stage_restart_count = [int]$Stage.RestartCount
    }
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
    $d1NoProgressMarker = $null
    $d1NoProgressSince = $null
    $d1NoProgressLastReportAt = $null
    $d1NoProgressFailMin = 8
    $d1NoProgressReportIntervalMin = 2
    $lastWatchHeartbeatAt = $null
    $postD1ProgressMarker = $null
    $postD1NoProgressSince = $null
    $postD1LastReportAt = $null
    $postD1StallThresholdMin = 30
    $postD1ReportIntervalMin = 5
    $stagePidMissingSince = $null
    $stagePidMissingGraceSec = 20
    $cachedArtifactState = New-EmptyArtifactState
    $cachedRemoteChain = @()
    $lastHeavyScanAt = [datetime]::MinValue
    $lastHeavyScanDurationMs = -1

    while ($true) {
        $now = Get-Date
        $finalStatus = Get-StageFinalStatus -RunDir ([string]$Stage.RunDir)
        if ($finalStatus.Exists) {
            Write-SupervisorLog ("stage_final stage={0} result={1} exit_code={2} run_dir={3}" -f [string]$Stage.Name, $finalStatus.Result, $finalStatus.ExitCode, (Convert-ToRepoRelativePath -Path ([string]$Stage.RunDir)))
            Write-LiveStatus -Values @{
                status = 'running'
                event = 'stage_final'
                current_stage = [string]$Stage.Name
                current_stage_run_dir = (Convert-ToRepoRelativePath -Path ([string]$Stage.RunDir))
                current_stage_result = [string]$finalStatus.Result
                current_stage_exit_code = [int]$finalStatus.ExitCode
                current_stage_restart_count = [int]$Stage.RestartCount
            }
            return $finalStatus
        }

        if ([int]$Stage.LaunchProcessId -gt 0) {
            $launchSnapshot = Get-StageLaunchProcessSnapshot -Stage $Stage
            $stagePidMissing = (-not [bool]$launchSnapshot.Alive) -or (-not [bool]$launchSnapshot.Matched)

            if ($stagePidMissing) {
                if ($null -eq $stagePidMissingSince) {
                    $stagePidMissingSince = $now
                    $missingReason = if (-not [bool]$launchSnapshot.Alive) { 'not-found' } else { 'pid-mismatch' }
                    Write-SupervisorLog ("stage_pid_missing stage={0} pid={1} reason={2} grace_sec={3}" -f [string]$Stage.Name, [int]$Stage.LaunchProcessId, $missingReason, $stagePidMissingGraceSec)
                }

                $missingAgeSec = ($now - $stagePidMissingSince).TotalSeconds
                if ($missingAgeSec -ge $stagePidMissingGraceSec) {
                    $detail = ("Stage {0} process missing before final status (pid={1}, run_dir={2}, missing_sec={3:N1})" -f [string]$Stage.Name, [int]$Stage.LaunchProcessId, (Convert-ToRepoRelativePath -Path ([string]$Stage.RunDir)), $missingAgeSec)
                    $blockedDir = Capture-BlockedPackage -Reason 'stage-process-exited-no-final' -Detail $detail -Stage $Stage
                    $blockedRel = Convert-ToRepoRelativePath -Path $blockedDir
                    Write-LiveStatus -Values @{
                        status = 'fail'
                        event = 'stage_process_exit_no_final'
                        current_stage = [string]$Stage.Name
                        current_stage_run_dir = (Convert-ToRepoRelativePath -Path ([string]$Stage.RunDir))
                        current_stage_result = 'fail'
                        current_stage_exit_code = 96
                        blocked_evidence = $blockedRel
                    }
                    Write-SupervisorLog ("stage_pid_fail stage={0} pid={1} evidence={2}" -f [string]$Stage.Name, [int]$Stage.LaunchProcessId, $blockedRel)
                    return [pscustomobject]@{
                        Exists = $true
                        Path = ''
                        Result = 'fail'
                        ExitCode = 96
                    }
                }
            }
            else {
                $stagePidMissingSince = $null
            }
        }

        $innerCandidate = Get-LatestTimestampedDirectory -Root $script:AutopilotOutDirRoot -After ([datetime]$Stage.StartTime).AddSeconds(-5)
        if ($null -ne $innerCandidate) {
            $Stage.InnerRunDir = $innerCandidate.FullName
        }

        $summaryPartialPath = Join-Path ([string]$Stage.RunDir) 'summary_partial.csv'
        $rowCount = Get-CsvRowCount -Path $summaryPartialPath
        $isD1Active = ($rowCount -lt 1 -and [int]$Stage.StartRound -eq 1)

        $scanAgeSecLite = if ($lastHeavyScanAt -eq [datetime]::MinValue) {
            -1
        }
        else {
            [int][Math]::Max(0, [Math]::Round(($now - $lastHeavyScanAt).TotalSeconds))
        }

        Write-SupervisorLog (
            "heartbeat mode=lite stage={0} row_count={1} file_count={2} latest_path={3} remote_chain_count={4} scan_age_sec={5} scan_duration_ms={6}" -f
            [string]$Stage.Name,
            $rowCount,
            [int]$cachedArtifactState.FileCount,
            (Convert-ToRepoRelativePath -Path ([string]$cachedArtifactState.LatestPath)),
            @($cachedRemoteChain).Count,
            $scanAgeSecLite,
            $lastHeavyScanDurationMs)

        $scanStartedAt = Get-Date
        $artifactState = Get-ArtifactState -Paths @([string]$Stage.RunDir, [string]$Stage.InnerRunDir)
        $remoteChain = Get-RemoteChainSnapshot
        $scanFinishedAt = Get-Date
        $lastHeavyScanAt = $scanFinishedAt
        $lastHeavyScanDurationMs = [int][Math]::Round(($scanFinishedAt - $scanStartedAt).TotalMilliseconds)
        $cachedArtifactState = $artifactState
        $cachedRemoteChain = @($remoteChain)
        $now = $scanFinishedAt

        if ($isD1Active) {
            if ($null -eq $policyBaseline) {
                $policyBaseline = $artifactState
                $lastPolicyCheckAt = $now
                Write-SupervisorLog ("d1_monitor stage={0} age_min=0 file_count={1} latest_path={2}" -f [string]$Stage.Name, $artifactState.FileCount, (Convert-ToRepoRelativePath -Path $artifactState.LatestPath))
            }

            $ageMin = ($now - [datetime]$Stage.StartTime).TotalMinutes
            $previousD1Marker = $d1NoProgressMarker
            if ($null -eq $previousD1Marker) {
                $d1NoProgressMarker = [pscustomobject]@{
                    FileCount = [int]$artifactState.FileCount
                    LatestWriteTime = [datetime]$artifactState.LatestWriteTime
                    LatestPath = [string]$artifactState.LatestPath
                }
            }

            $hasD1Progress = $false
            if ($null -eq $previousD1Marker) {
                $hasD1Progress = $true
                if ($ageMin -ge $d1NoProgressFailMin -and @($remoteChain).Count -eq 0) {
                    $hasD1Progress = $false
                }
            }
            else {
                $hasD1Progress = (
                    ([int]$artifactState.FileCount -gt [int]$previousD1Marker.FileCount) -or
                    ([datetime]$artifactState.LatestWriteTime -gt [datetime]$previousD1Marker.LatestWriteTime)
                )
                if ($hasD1Progress) {
                    $d1NoProgressMarker = [pscustomobject]@{
                        FileCount = [int]$artifactState.FileCount
                        LatestWriteTime = [datetime]$artifactState.LatestWriteTime
                        LatestPath = [string]$artifactState.LatestPath
                    }
                }
            }

            if ($hasD1Progress) {
                $d1NoProgressSince = $null
                $d1NoProgressLastReportAt = $now
            }
            elseif (@($remoteChain).Count -eq 0) {
                if ($null -eq $d1NoProgressSince) {
                    if ($ageMin -ge $d1NoProgressFailMin) {
                        $d1NoProgressSince = [datetime]$Stage.StartTime
                    }
                    else {
                        $d1NoProgressSince = $now
                    }
                    $d1NoProgressLastReportAt = $now
                }

                $d1NoProgressMin = ($now - $d1NoProgressSince).TotalMinutes
                $shouldReportD1NoProgress = ($null -eq $d1NoProgressLastReportAt) -or (($now - $d1NoProgressLastReportAt).TotalMinutes -ge $d1NoProgressReportIntervalMin)
                if ($shouldReportD1NoProgress) {
                    Write-SupervisorLog ("d1_no_progress stage={0} no_progress_min={1:N1} row_count={2} file_count={3} latest_path={4}" -f [string]$Stage.Name, $d1NoProgressMin, $rowCount, $artifactState.FileCount, (Convert-ToRepoRelativePath -Path $artifactState.LatestPath))
                    $d1NoProgressLastReportAt = $now
                }

                if ($d1NoProgressMin -ge $d1NoProgressFailMin) {
                    $detail = ("Stage {0} no progress for {1:N1} minutes in D1 with no remote chain (row_count={2}, file_count={3}, latest_path={4})" -f [string]$Stage.Name, $d1NoProgressMin, $rowCount, $artifactState.FileCount, (Convert-ToRepoRelativePath -Path $artifactState.LatestPath))
                    $blockedDir = Capture-BlockedPackage -Reason 'd1-no-progress-no-remote' -Detail $detail -Stage $Stage
                    $blockedRel = Convert-ToRepoRelativePath -Path $blockedDir
                    Write-LiveStatus -Values @{
                        status = 'fail'
                        event = 'd1_no_progress'
                        current_stage = [string]$Stage.Name
                        current_stage_run_dir = (Convert-ToRepoRelativePath -Path ([string]$Stage.RunDir))
                        current_stage_result = 'fail'
                        current_stage_exit_code = 97
                        blocked_evidence = $blockedRel
                    }
                    Write-SupervisorLog ("d1_no_progress_fail stage={0} no_progress_min={1:N1} evidence={2}" -f [string]$Stage.Name, $d1NoProgressMin, $blockedRel)
                    return [pscustomobject]@{
                        Exists = $true
                        Path = ''
                        Result = 'fail'
                        ExitCode = 97
                    }
                }
            }
            else {
                $d1NoProgressSince = $null
            }

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
                            Write-LiveStatus -Values @{
                                status = 'blocked'
                                event = 'restart_budget_exhausted'
                                current_stage = [string]$Stage.Name
                                current_stage_run_dir = (Convert-ToRepoRelativePath -Path ([string]$Stage.RunDir))
                                current_stage_restart_count = [int]$Stage.RestartCount
                                current_stage_max_restarts = [int]$Stage.MaxRestarts
                            }
                            throw "Stage $([string]$Stage.Name) exceeded max restarts after D1 stall"
                        }

                        $evidenceDir = Capture-RestartEvidence -Stage $Stage
                        $evidenceRel = Convert-ToRepoRelativePath -Path $evidenceDir
                        Write-LiveStatus -Values @{
                            status = 'running'
                            event = 'restart_triggered'
                            current_stage = [string]$Stage.Name
                            current_stage_run_dir = (Convert-ToRepoRelativePath -Path ([string]$Stage.RunDir))
                            current_stage_restart_count = ([int]$Stage.RestartCount + 1)
                            last_restart_evidence = $evidenceRel
                        }
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
                        $script:Settings.SESSION_FINAL_NOTES = "{0} restarted at {1}; run_dir={2}; supervisor_log={3}; live_status={4}" -f [string]$Stage.Name, (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'), (Convert-ToRepoRelativePath -Path ([string]$Stage.RunDir)), (Convert-ToRepoRelativePath -Path $script:SupervisorLog), (Convert-ToRepoRelativePath -Path $script:LiveStatusPath)
                        if ([string]$Stage.Name -eq 'A') {
                            Set-KeyValueFileValues -Path $script:StartFilePath -Values @{
                                A_FINAL_STATUS = 'RUNNING'
                                A_LAUNCH_PID = [string]$Stage.LaunchProcessId
                                SESSION_FINAL_STATUS = 'RUNNING'
                                SESSION_FINAL_NOTES = [string]$script:Settings.SESSION_FINAL_NOTES
                            }
                        }
                        else {
                            Set-KeyValueFileValues -Path $script:StartFilePath -Values @{
                                B_FINAL_STATUS = 'RUNNING'
                                B_LAUNCH_PID = [string]$Stage.LaunchProcessId
                                SESSION_FINAL_STATUS = 'RUNNING'
                                SESSION_FINAL_NOTES = [string]$script:Settings.SESSION_FINAL_NOTES
                            }
                        }

                        $policyBaseline = $null
                        $lastPolicyCheckAt = $null
                        $stallSince = $null
                        $d1CompletedLogged = $false
                        $d1NoProgressMarker = $null
                        $d1NoProgressSince = $null
                        $d1NoProgressLastReportAt = $null
                        $postD1ProgressMarker = $null
                        $postD1NoProgressSince = $null
                        $postD1LastReportAt = $null
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
            $d1NoProgressSince = $null
            $d1NoProgressLastReportAt = $null
        }

        if ($rowCount -ge 1) {
            $hasPostD1Progress = $false
            if ($null -eq $postD1ProgressMarker) {
                $hasPostD1Progress = $true
            }
            else {
                $hasPostD1Progress = (
                    ([int]$rowCount -gt [int]$postD1ProgressMarker.RowCount) -or
                    ([int]$artifactState.FileCount -gt [int]$postD1ProgressMarker.FileCount) -or
                    ([datetime]$artifactState.LatestWriteTime -gt [datetime]$postD1ProgressMarker.LatestWriteTime)
                )
            }

            if ($hasPostD1Progress) {
                $postD1ProgressMarker = [pscustomobject]@{
                    RowCount = [int]$rowCount
                    FileCount = [int]$artifactState.FileCount
                    LatestWriteTime = [datetime]$artifactState.LatestWriteTime
                    LatestPath = [string]$artifactState.LatestPath
                }
                $postD1NoProgressSince = $null
                $postD1LastReportAt = $now
            }
            else {
                if ($null -eq $postD1NoProgressSince) {
                    $postD1NoProgressSince = $now
                    $postD1LastReportAt = $now
                }

                $noProgressMin = ($now - $postD1NoProgressSince).TotalMinutes
                $shouldReportNoProgress = ($null -eq $postD1LastReportAt) -or (($now - $postD1LastReportAt).TotalMinutes -ge $postD1ReportIntervalMin)
                if ($shouldReportNoProgress) {
                    Write-SupervisorLog ("post_d1_no_progress stage={0} no_progress_min={1:N1} row_count={2} file_count={3} latest_path={4}" -f [string]$Stage.Name, $noProgressMin, $rowCount, $artifactState.FileCount, (Convert-ToRepoRelativePath -Path $artifactState.LatestPath))
                    $postD1LastReportAt = $now
                }

                if ($noProgressMin -ge $postD1StallThresholdMin) {
                    $detail = ("Stage {0} no progress for {1:N1} minutes after D1 (row_count={2}, file_count={3}, latest_path={4})" -f [string]$Stage.Name, $noProgressMin, $rowCount, $artifactState.FileCount, (Convert-ToRepoRelativePath -Path $artifactState.LatestPath))
                    $blockedDir = Capture-BlockedPackage -Reason 'post-d1-no-progress' -Detail $detail -Stage $Stage
                    $blockedRel = Convert-ToRepoRelativePath -Path $blockedDir
                    Write-LiveStatus -Values @{
                        status = 'fail'
                        event = 'post_d1_no_progress'
                        current_stage = [string]$Stage.Name
                        current_stage_run_dir = (Convert-ToRepoRelativePath -Path ([string]$Stage.RunDir))
                        current_stage_result = 'fail'
                        current_stage_exit_code = 98
                        blocked_evidence = $blockedRel
                    }
                    Write-SupervisorLog ("post_d1_stall stage={0} no_progress_min={1:N1} evidence={2}" -f [string]$Stage.Name, $noProgressMin, $blockedRel)
                    return [pscustomobject]@{
                        Exists = $true
                        Path = ''
                        Result = 'fail'
                        ExitCode = 98
                    }
                }
            }
        }

        Write-SupervisorLog ("heartbeat mode=full stage={0} row_count={1} file_count={2} latest_path={3} remote_chain_count={4} scan_age_sec=0 scan_duration_ms={5}" -f [string]$Stage.Name, $rowCount, $artifactState.FileCount, (Convert-ToRepoRelativePath -Path $artifactState.LatestPath), @($remoteChain).Count, $lastHeavyScanDurationMs)
        Write-LiveStatus -Values @{
            status = 'running'
            event = 'heartbeat'
            heartbeat_mode = 'full'
            current_stage = [string]$Stage.Name
            current_stage_run_dir = (Convert-ToRepoRelativePath -Path ([string]$Stage.RunDir))
            current_stage_inner_run_dir = (Convert-ToRepoRelativePath -Path ([string]$Stage.InnerRunDir))
            current_stage_start_round = [int]$Stage.StartRound
            current_stage_restart_count = [int]$Stage.RestartCount
            current_stage_result = 'running'
            current_stage_exit_code = -1
            row_count = [int]$rowCount
            artifact_file_count = [int]$artifactState.FileCount
            artifact_latest_path = (Convert-ToRepoRelativePath -Path $artifactState.LatestPath)
            remote_chain_count = @($remoteChain).Count
            scan_age_sec = 0
            scan_duration_ms = [int]$lastHeavyScanDurationMs
        }

        if ($null -ne $script:WatchSettings -and [bool]$script:WatchSettings.Required) {
            $watchIntervalMin = [int]$script:WatchSettings.ReportIntervalMin
            $needWatchHeartbeat = ($null -eq $lastWatchHeartbeatAt)
            if (-not $needWatchHeartbeat) {
                $needWatchHeartbeat = (($now - $lastWatchHeartbeatAt).TotalMinutes -ge $watchIntervalMin)
            }

            if ($needWatchHeartbeat) {
                Write-SupervisorLog ("watch_heartbeat required=true interval_min={0} scopes={1} stage={2} row_count={3} file_count={4} latest_path={5} remote_chain_count={6} mode=full scan_age_sec=0 scan_duration_ms={7}" -f $watchIntervalMin, [string]$script:WatchSettings.Scopes, [string]$Stage.Name, $rowCount, $artifactState.FileCount, (Convert-ToRepoRelativePath -Path $artifactState.LatestPath), @($remoteChain).Count, $lastHeavyScanDurationMs)
                $lastWatchHeartbeatAt = $now
            }
        }

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
$script:WatchSettings = Get-SessionWatchSettings -Settings $script:Settings
if (-not $script:Settings.Contains('TASK_STATIC_PRECHECK_POLICY') -or [string]::IsNullOrWhiteSpace([string]$script:Settings.TASK_STATIC_PRECHECK_POLICY)) {
    $script:Settings.TASK_STATIC_PRECHECK_POLICY = 'enforce'
}
$script:RestartBudgetSettings = Get-RestartBudgetSettings -Settings $script:Settings -DefaultMaxStageRestarts $MaxStageRestarts
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
$script:LiveStatusPath = Join-Path $script:SupervisorOutDir 'live_status.json'
$script:LiveStatusState = [ordered]@{
    schema = 'AB_SUPERVISOR_LIVE_STATUS_V1'
    status = 'starting'
    event = 'startup'
    start_file = (Convert-ToRepoRelativePath -Path $script:StartFilePath)
    supervisor_log = (Convert-ToRepoRelativePath -Path $script:SupervisorLog)
    live_status = (Convert-ToRepoRelativePath -Path $script:LiveStatusPath)
    watch_required = [bool]$script:WatchSettings.Required
    watch_interval_min = [int]$script:WatchSettings.ReportIntervalMin
    watch_scopes = [string]$script:WatchSettings.Scopes
    task_static_precheck_policy = [string]$script:Settings.TASK_STATIC_PRECHECK_POLICY
    restart_budget_source = [string]$script:RestartBudgetSettings.Source
    restart_budget_global = [int]$script:RestartBudgetSettings.Global
    restart_budget_a = [int]$script:RestartBudgetSettings.A
    restart_budget_b = [int]$script:RestartBudgetSettings.B
}
Write-LiveStatus -Values @{}

Write-SupervisorLog ("watch_policy required={0} interval_min={1} scopes={2}" -f [bool]$script:WatchSettings.Required, [int]$script:WatchSettings.ReportIntervalMin, [string]$script:WatchSettings.Scopes)
Write-SupervisorLog ("restart_budget source={0} global={1} a={2} b={3}" -f [string]$script:RestartBudgetSettings.Source, [int]$script:RestartBudgetSettings.Global, [int]$script:RestartBudgetSettings.A, [int]$script:RestartBudgetSettings.B)
if ([bool]$script:WatchSettings.Required) {
    $watchNotes = "supervisor_watch_active at {0}; interval_min={1}; scopes={2}" -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'), [int]$script:WatchSettings.ReportIntervalMin, [string]$script:WatchSettings.Scopes
    $script:Settings.AI_SESSION_BLOCKING_WATCH_NOTES = $watchNotes
    Set-KeyValueFileValues -Path $script:StartFilePath -Values @{
        AI_SESSION_BLOCKING_WATCH_NOTES = $watchNotes
    }
}

$stageA = $null
$stageB = $null

if ([string]$StartFromStage -eq 'B') {
    $currentRunDirResolved = Resolve-CurrentRunDirWithWait -StageName 'B' -ProvidedRunDir $CurrentBRunDir -SessionOutDirRoot $script:SessionOutDirRoot -SessionNotes ([string]$script:Settings.SESSION_FINAL_NOTES) -WaitTimeoutSec 180 -PollSec 5
    if ([string]::IsNullOrWhiteSpace($currentRunDirResolved)) {
        throw 'Unable to resolve current B run directory'
    }
    Write-SupervisorLog ("startup start_file={0} current_b_run_dir={1}" -f (Convert-ToRepoRelativePath -Path $script:StartFilePath), (Convert-ToRepoRelativePath -Path $currentRunDirResolved))
    Write-SupervisorLog ("startup_pid pid={0}" -f $PID)

    if ([string]$script:Settings.A_FINAL_STATUS -ne 'PASS') {
        Write-SupervisorLog ("b_attach_warning a_final_status={0}" -f [string]$script:Settings.A_FINAL_STATUS)
    }

    $script:Settings.SESSION_FINAL_NOTES = Upsert-SessionAnchorNotes -Existing ([string]$script:Settings.SESSION_FINAL_NOTES) -Anchors @{
        run_dir = (Convert-ToRepoRelativePath -Path $currentRunDirResolved)
        supervisor_log = (Convert-ToRepoRelativePath -Path $script:SupervisorLog)
        live_status = (Convert-ToRepoRelativePath -Path $script:LiveStatusPath)
    }
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
        MaxRestarts = [int]$script:RestartBudgetSettings.B
    }

    $stageB.LaunchProcessId = Resolve-StageLaunchProcessId -Settings $script:Settings -Stage $stageB
    if ([int]$stageB.LaunchProcessId -gt 0) {
        Write-SupervisorLog ("b_attach_pid pid={0}" -f [int]$stageB.LaunchProcessId)
    }
}
else {
    $currentRunDirResolved = Resolve-CurrentRunDirWithWait -StageName 'A' -ProvidedRunDir $CurrentARunDir -SessionOutDirRoot $script:SessionOutDirRoot -SessionNotes ([string]$script:Settings.SESSION_FINAL_NOTES) -WaitTimeoutSec 180 -PollSec 5
    if ([string]::IsNullOrWhiteSpace($currentRunDirResolved)) {
        throw 'Unable to resolve current A run directory'
    }
    Write-SupervisorLog ("startup start_file={0} current_a_run_dir={1}" -f (Convert-ToRepoRelativePath -Path $script:StartFilePath), (Convert-ToRepoRelativePath -Path $currentRunDirResolved))
    Write-SupervisorLog ("startup_pid pid={0}" -f $PID)

    $script:Settings.SESSION_FINAL_NOTES = Upsert-SessionAnchorNotes -Existing ([string]$script:Settings.SESSION_FINAL_NOTES) -Anchors @{
        run_dir = (Convert-ToRepoRelativePath -Path $currentRunDirResolved)
        supervisor_log = (Convert-ToRepoRelativePath -Path $script:SupervisorLog)
        live_status = (Convert-ToRepoRelativePath -Path $script:LiveStatusPath)
    }
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
        MaxRestarts = [int]$script:RestartBudgetSettings.A
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
        MaxRestarts = [int]$script:RestartBudgetSettings.B
    }
}

try {
    if ([string]$StartFromStage -eq 'B') {
        Write-LiveStatus -Values @{
            status = 'running'
            event = 'b_attach_start'
            current_stage = 'B'
            current_stage_run_dir = (Convert-ToRepoRelativePath -Path ([string]$stageB.RunDir))
        }
        $script:Settings.SESSION_FINAL_NOTES = "B monitor attached at $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss')); run_dir=$((Convert-ToRepoRelativePath -Path ([string]$stageB.RunDir))); supervisor_log=$((Convert-ToRepoRelativePath -Path $script:SupervisorLog)); live_status=$((Convert-ToRepoRelativePath -Path $script:LiveStatusPath))"
        Set-KeyValueFileValues -Path $script:StartFilePath -Values @{
            B_FINAL_STATUS = 'RUNNING'
            B_LAUNCH_PID = [string]$stageB.LaunchProcessId
            SESSION_FINAL_STATUS = 'RUNNING'
            SESSION_FINAL_NOTES = [string]$script:Settings.SESSION_FINAL_NOTES
        }
        Write-SupervisorLog ("b_attach run_dir={0}" -f (Convert-ToRepoRelativePath -Path ([string]$stageB.RunDir)))

        $bFinal = Monitor-StageUntilFinal -Stage $stageB
        if ($bFinal.Result -eq 'pass') {
            $script:Settings.SESSION_FINAL_NOTES = "B PASS after attach; b_run_dir=$((Convert-ToRepoRelativePath -Path ([string]$stageB.RunDir))); supervisor_log=$((Convert-ToRepoRelativePath -Path $script:SupervisorLog)); live_status=$((Convert-ToRepoRelativePath -Path $script:LiveStatusPath))"
            Set-KeyValueFileValues -Path $script:StartFilePath -Values @{
                B_FINAL_STATUS = 'PASS'
                B_LAUNCH_PID = '0'
                SESSION_FINAL_STATUS = 'PASS'
                SESSION_FINAL_NOTES = [string]$script:Settings.SESSION_FINAL_NOTES
            }
            Write-LiveStatus -Values @{
                status = 'pass'
                event = 'complete'
                current_stage = 'B'
                current_stage_result = 'pass'
                session_final_status = 'PASS'
            }
            Write-SupervisorLog 'complete result=pass mode=b-attach'
            exit 0
        }

        $blockedDir = Capture-BlockedPackage -Reason 'b-fail' -Detail 'B final status reported fail in attach mode' -Stage $stageB
        $blockedRel = Convert-ToRepoRelativePath -Path $blockedDir
        $script:Settings.SESSION_FINAL_NOTES = Append-DelimitedNote -Existing ([string]$script:Settings.SESSION_FINAL_NOTES) -Append ("B failed in attach mode; evidence=$blockedRel")
        Set-KeyValueFileValues -Path $script:StartFilePath -Values @{
            B_FINAL_STATUS = 'FAIL'
            B_LAUNCH_PID = '0'
            SESSION_FINAL_STATUS = 'FAIL'
            SESSION_FINAL_NOTES = [string]$script:Settings.SESSION_FINAL_NOTES
        }
        Write-LiveStatus -Values @{
            status = 'fail'
            event = 'blocked_package'
            current_stage = 'B'
            current_stage_result = 'fail'
            session_final_status = 'FAIL'
            blocked_evidence = $blockedRel
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
            A_LAUNCH_PID = '0'
            B_FINAL_STATUS = 'BLOCKED'
            B_LAUNCH_PID = '0'
            SESSION_FINAL_STATUS = 'FAIL'
            SESSION_FINAL_NOTES = [string]$script:Settings.SESSION_FINAL_NOTES
        }
        Write-LiveStatus -Values @{
            status = 'fail'
            event = 'blocked_package'
            current_stage = 'A'
            current_stage_result = 'fail'
            session_final_status = 'FAIL'
            blocked_evidence = $blockedRel
        }
        Write-SupervisorLog ("stop reason=a-fail b=blocked evidence={0}" -f $blockedRel)
        exit 1
    }

    $aSnapshot = Capture-ASuccessSnapshot -RunDir ([string]$stageA.RunDir)
    $script:Settings.A_SUCCESS_SNAPSHOT_FINAL_STATUS = [string]$aSnapshot.FinalStatus
    $script:Settings.A_SUCCESS_SNAPSHOT_SUMMARY = [string]$aSnapshot.Summary
    $script:Settings.A_SUCCESS_SNAPSHOT_SOURCE_STATE = [string]$aSnapshot.SourceState
    $script:Settings.SESSION_FINAL_NOTES = "A PASS; a_snapshot_dir=$([string]$aSnapshot.SnapshotDir); launching B; supervisor_log=$((Convert-ToRepoRelativePath -Path $script:SupervisorLog)); live_status=$((Convert-ToRepoRelativePath -Path $script:LiveStatusPath))"
    Set-KeyValueFileValues -Path $script:StartFilePath -Values @{
        A_FINAL_STATUS = 'PASS'
        A_LAUNCH_PID = '0'
        A_SUCCESS_SNAPSHOT_FINAL_STATUS = [string]$aSnapshot.FinalStatus
        A_SUCCESS_SNAPSHOT_SUMMARY = [string]$aSnapshot.Summary
        A_SUCCESS_SNAPSHOT_SOURCE_STATE = [string]$aSnapshot.SourceState
        SESSION_FINAL_STATUS = 'RUNNING'
        SESSION_FINAL_NOTES = [string]$script:Settings.SESSION_FINAL_NOTES
    }
    Write-LiveStatus -Values @{
        status = 'running'
        event = 'a_pass_snapshot_ready'
        current_stage = 'A'
        current_stage_result = 'pass'
        a_snapshot_dir = [string]$aSnapshot.SnapshotDir
    }
    Write-SupervisorLog ("a_snapshot final_status={0} summary={1} source_state={2} snapshot_dir={3}" -f [string]$aSnapshot.FinalStatus, [string]$aSnapshot.Summary, [string]$aSnapshot.SourceState, [string]$aSnapshot.SnapshotDir)

    $stageB = Start-StageRun -Stage $stageB
    $script:Settings.SESSION_FINAL_NOTES = "B started at $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss')); run_dir=$((Convert-ToRepoRelativePath -Path ([string]$stageB.RunDir))); supervisor_log=$((Convert-ToRepoRelativePath -Path $script:SupervisorLog)); live_status=$((Convert-ToRepoRelativePath -Path $script:LiveStatusPath))"
    Set-KeyValueFileValues -Path $script:StartFilePath -Values @{
        B_FINAL_STATUS = 'RUNNING'
        B_LAUNCH_PID = [string]$stageB.LaunchProcessId
        SESSION_FINAL_STATUS = 'RUNNING'
        SESSION_FINAL_NOTES = [string]$script:Settings.SESSION_FINAL_NOTES
    }
    Write-LiveStatus -Values @{
        status = 'running'
        event = 'b_started'
        current_stage = 'B'
        current_stage_run_dir = (Convert-ToRepoRelativePath -Path ([string]$stageB.RunDir))
    }

    $bFinal = Monitor-StageUntilFinal -Stage $stageB
    if ($bFinal.Result -eq 'pass') {
        $script:Settings.SESSION_FINAL_NOTES = "A/B PASS; a_run_dir=$((Convert-ToRepoRelativePath -Path ([string]$stageA.RunDir))); b_run_dir=$((Convert-ToRepoRelativePath -Path ([string]$stageB.RunDir))); supervisor_log=$((Convert-ToRepoRelativePath -Path $script:SupervisorLog)); live_status=$((Convert-ToRepoRelativePath -Path $script:LiveStatusPath))"
        Set-KeyValueFileValues -Path $script:StartFilePath -Values @{
            B_FINAL_STATUS = 'PASS'
            B_LAUNCH_PID = '0'
            SESSION_FINAL_STATUS = 'PASS'
            SESSION_FINAL_NOTES = [string]$script:Settings.SESSION_FINAL_NOTES
        }
        Write-LiveStatus -Values @{
            status = 'pass'
            event = 'complete'
            current_stage = 'B'
            current_stage_result = 'pass'
            session_final_status = 'PASS'
        }
        Write-SupervisorLog 'complete result=pass'
        exit 0
    }

    $blockedDir = Capture-BlockedPackage -Reason 'b-fail' -Detail 'B final status reported fail after A snapshot captured' -Stage $stageB
    $blockedRel = Convert-ToRepoRelativePath -Path $blockedDir
    $script:Settings.SESSION_FINAL_NOTES = Append-DelimitedNote -Existing ([string]$script:Settings.SESSION_FINAL_NOTES) -Append ("B failed after A snapshot captured; evidence=$blockedRel")
    Set-KeyValueFileValues -Path $script:StartFilePath -Values @{
        B_FINAL_STATUS = 'FAIL'
        B_LAUNCH_PID = '0'
        SESSION_FINAL_STATUS = 'FAIL'
        SESSION_FINAL_NOTES = [string]$script:Settings.SESSION_FINAL_NOTES
    }
    Write-LiveStatus -Values @{
        status = 'fail'
        event = 'blocked_package'
        current_stage = 'B'
        current_stage_result = 'fail'
        session_final_status = 'FAIL'
        blocked_evidence = $blockedRel
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
    Write-LiveStatus -Values @{
        status = 'blocked'
        event = 'supervisor_error'
        session_final_status = 'BLOCKED'
        error_detail = $failureMessage
        blocked_evidence = $blockedRel
    }
    Write-SupervisorLog ("stop reason=supervisor-error detail={0} evidence={1}" -f $failureMessage, $blockedRel)
    throw
}
finally {
    Write-LiveStatus -Values @{
        event = 'shutdown'
    }
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