param(
    [Parameter(Mandatory = $true)][string]$StartFile,
    [AllowEmptyString()][string]$SupervisorLog = "",
    [ValidateRange(15, 300)][int]$PollSec = 60,
    [ValidateRange(5, 120)][int]$SupervisorQuietMinutes = 5,
    [ValidateRange(10, 180)][int]$UnknownStageStallMinutes = 20
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot 'unattended_exit_result.ps1')
$script:UnhandledExitTag = 'UNATTENDED-AB-COMPANION'

trap {
    $exitCode = Get-UnattendedExitCodeFromRecord -Tag $script:UnhandledExitTag -Record $_ -DefaultExitCode 1
    Write-UnattendedUnhandledResult -Tag $script:UnhandledExitTag -Record $_ -ExitCode $exitCode
    exit $exitCode
}

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

function Enter-InstanceMutex {
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
            try { $mutex.Dispose() } catch { Write-Verbose ("Suppressed exception: {0}" -f $_.Exception.Message) }
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

function Invoke-KeyValueFileValueUpdate {
    param(
        [string]$Path,
        [hashtable]$Values
    )

    $mutex = New-Object System.Threading.Mutex($false, (Get-StartFileMutexName -Role 'startfile-write' -StartFilePath $Path))
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

        $seenKeys = @{}
        $lineNo = 0
        foreach ($line in $sourceLines) {
            $lineNo++
            if ($line -match '^([^=]+)=(.*)$') {
                $key = $Matches[1].Trim()
                if ($seenKeys.ContainsKey($key)) {
                    throw ("Duplicate key '{0}' detected in {1} at line {2} and line {3}." -f $key, $Path, [int]$seenKeys[$key], $lineNo)
                }

                $seenKeys[$key] = $lineNo
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
                $tempPath = "$Path.tmp.$PID.$([guid]::NewGuid().ToString('N'))"
                $normalizedLines = @($lines | ForEach-Object { [string]$_ })
                $text = [string]::Join("`n", $normalizedLines)
                if ($normalizedLines.Count -gt 0) {
                    $text += "`n"
                }
                [System.IO.File]::WriteAllText($tempPath, $text, [System.Text.UTF8Encoding]::new($true))
                Move-Item -LiteralPath $tempPath -Destination $Path -Force
                $tempPath = ''
                break
            }
            catch {
                if (-not [string]::IsNullOrWhiteSpace($tempPath) -and (Test-Path -LiteralPath $tempPath)) {
                    Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue
                    $tempPath = ''
                }

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

function Add-DelimitedNote {
    param(
        [string]$Existing,
        [string]$Append
    )

    if ([string]::IsNullOrWhiteSpace($Existing)) {
        return $Append
    }

    return "$Existing; $Append"
}

function Get-SettingValue {
    param(
        [hashtable]$Settings,
        [string]$Key,
        [AllowEmptyString()][string]$Default = ''
    )

    if ($null -eq $Settings -or [string]::IsNullOrWhiteSpace($Key) -or -not $Settings.Contains($Key)) {
        return $Default
    }

    return [string]$Settings[$Key]
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

function Get-FileAgeMinuteValue {
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
        return ($line.Contains('start_dev_verify_fastmode_a.ps1') -or $line.Contains('start_dev_verify_8round_multiround.ps1'))
    }
    if ($Stage -eq 'B') {
        return $line.Contains('start_dev_verify_fastmode_b.ps1')
    }

    return $true
}

function Get-DateTimeUtcOrNull {
    param([AllowEmptyString()][string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return $null
    }

    $parsed = [datetimeoffset]::MinValue
    if ([datetimeoffset]::TryParse($Text, [ref]$parsed)) {
        return $parsed.UtcDateTime
    }

    return $null
}

function Get-NormalizedStatusValue {
    param([AllowEmptyString()][string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return 'NOT_RUN'
    }

    return $Value.Trim().ToUpperInvariant()
}

function Get-BPassFailConflictEvidence {
    param(
        [hashtable]$Settings,
        [AllowEmptyString()][string]$SessionNotes,
        [AllowEmptyString()][string]$SessionStatus,
        [AllowEmptyString()][string]$AStatus,
        [AllowEmptyString()][string]$BStatus
    )

    $artifactPath = Join-Path $script:RepoRoot 'out\artifacts\ab_stage_exit\latest_b_exit.json'
    $result = [ordered]@{
        Conflict = $false
        Reason = 'status-not-pass'
        ArtifactPath = (Convert-ToRepoRelativePath -Path $artifactPath)
        Stage = ''
        ExitResult = ''
        ExitCode = -1
        ProcessId = 0
        ProcessIdMatch = $true
        StartFileMatch = $true
        GeneratedAt = ''
        Fresh = $false
        FailCategory = ''
        FailReason = ''
    }

    $sessionNorm = Get-NormalizedStatusValue -Value $SessionStatus
    $aNorm = Get-NormalizedStatusValue -Value $AStatus
    $bNorm = Get-NormalizedStatusValue -Value $BStatus
    if ($sessionNorm -ne 'PASS' -or $aNorm -ne 'PASS' -or $bNorm -ne 'PASS') {
        return [pscustomobject]$result
    }

    if (-not (Test-Path -LiteralPath $artifactPath)) {
        $result.Reason = 'artifact-missing'
        return [pscustomobject]$result
    }

    $payload = $null
    try {
        $payload = Get-Content -LiteralPath $artifactPath -Raw -Encoding utf8 | ConvertFrom-Json
    }
    catch {
        $result.Reason = 'artifact-parse-failed'
        return [pscustomobject]$result
    }

    if ($null -eq $payload) {
        $result.Reason = 'artifact-empty'
        return [pscustomobject]$result
    }

    $result.Stage = ([string]$payload.stage).Trim().ToUpperInvariant()
    if ($result.Stage -ne 'B') {
        $result.Reason = 'stage-mismatch'
        return [pscustomobject]$result
    }

    $result.ExitResult = ([string]$payload.result).Trim().ToLowerInvariant()
    if ($result.ExitResult -ne 'fail') {
        $result.Reason = 'result-not-fail'
        return [pscustomobject]$result
    }

    $parsedExitCode = -1
    if ([int]::TryParse(([string]$payload.exit_code), [ref]$parsedExitCode)) {
        $result.ExitCode = [int]$parsedExitCode
    }

    $parsedProcessId = 0
    if ([int]::TryParse(([string]$payload.process_id), [ref]$parsedProcessId) -and $parsedProcessId -gt 0) {
        $result.ProcessId = [int]$parsedProcessId
    }

    $expectedBLaunchPid = Get-StageLaunchPid -Settings $Settings -Stage 'B'
    if ($expectedBLaunchPid -gt 0) {
        $result.ProcessIdMatch = ([int]$result.ProcessId -eq [int]$expectedBLaunchPid)
    }
    if (-not [bool]$result.ProcessIdMatch) {
        $result.Reason = 'pid-mismatch'
        return [pscustomobject]$result
    }

    $artifactStartFilePath = [string]$payload.start_file_path
    if (-not [string]::IsNullOrWhiteSpace($artifactStartFilePath)) {
        try {
            $expectedStart = [System.IO.Path]::GetFullPath($script:StartFilePath)
            $artifactStart = [System.IO.Path]::GetFullPath($artifactStartFilePath)
            $result.StartFileMatch = $artifactStart.Equals($expectedStart, [System.StringComparison]::OrdinalIgnoreCase)
        }
        catch {
            $result.StartFileMatch = $false
        }
    }

    if (-not [bool]$result.StartFileMatch) {
        $result.Reason = 'start-file-mismatch'
        return [pscustomobject]$result
    }

    $result.GeneratedAt = [string]$payload.generated_at
    $generatedUtc = Get-DateTimeUtcOrNull -Text $result.GeneratedAt
    if ($null -eq $generatedUtc) {
        $result.Reason = 'generated-at-invalid'
        return [pscustomobject]$result
    }

    $runDir = Get-LatestAnchorValueFromNoteText -Notes $SessionNotes -Key 'b_run_dir'
    if ([string]::IsNullOrWhiteSpace($runDir)) {
        $runDir = Get-LatestAnchorValueFromNoteText -Notes $SessionNotes -Key 'run_dir'
    }
    $runDirResolved = ''
    if (-not [string]::IsNullOrWhiteSpace($runDir)) {
        try {
            $runDirResolved = Resolve-RepoPath -Path $runDir
        }
        catch {
            $runDirResolved = ''
        }
    }

    $freshByRunDir = $false
    if (-not [string]::IsNullOrWhiteSpace($runDirResolved) -and (Test-Path -LiteralPath $runDirResolved)) {
        $runDirCreatedUtc = (Get-Item -LiteralPath $runDirResolved).CreationTimeUtc
        $freshByRunDir = ([datetime]$generatedUtc -ge [datetime]$runDirCreatedUtc.AddMinutes(-2))
    }
    else {
        $ageMinutes = ((Get-Date).ToUniversalTime() - [datetime]$generatedUtc).TotalMinutes
        $freshByRunDir = ($ageMinutes -ge 0 -and $ageMinutes -le 240)
    }

    $result.Fresh = [bool]$freshByRunDir
    if (-not [bool]$result.Fresh) {
        $result.Reason = 'artifact-not-fresh'
        return [pscustomobject]$result
    }

    $result.FailCategory = [string]$payload.fail_category
    $result.FailReason = [string]$payload.fail_reason
    $result.Conflict = $true
    $result.Reason = 'conflict-detected'
    return [pscustomobject]$result
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

    $remoteIp = Get-SettingValue -Settings $Settings -Key 'REMOTE_IP' -Default ''
    $remoteUser = Get-SettingValue -Settings $Settings -Key 'REMOTE_USER' -Default ''

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

function Copy-PathIfPresent {
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

function Save-BlockedPackage {
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

    Copy-PathIfPresent -SourcePath $script:StartFilePath -DestinationDir $packageDir
    Copy-PathIfPresent -SourcePath $SupervisorLogPath -DestinationDir $packageDir
    Copy-PathIfPresent -SourcePath $script:CompanionLog -DestinationDir $packageDir
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
        Copy-PathIfPresent -SourcePath $candidate -DestinationDir $packageDir
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

    $sessionNotes = Get-SettingValue -Settings $Settings -Key 'SESSION_FINAL_NOTES' -Default ''
    $runDir = Get-LatestAnchorValueFromNoteText -Notes $sessionNotes -Key 'run_dir'
    if ([string]::IsNullOrWhiteSpace($runDir)) {
        $runDir = Get-LatestAnchorValueFromNoteText -Notes $sessionNotes -Key 'b_run_dir'
    }
    if ([string]::IsNullOrWhiteSpace($runDir)) {
        $runDir = Get-LatestAnchorValueFromNoteText -Notes $sessionNotes -Key 'current_stage_run_dir'
    }
    $aStatus = Get-SettingValue -Settings $Settings -Key 'A_FINAL_STATUS' -Default 'NOT_RUN'
    $bStatus = Get-SettingValue -Settings $Settings -Key 'B_FINAL_STATUS' -Default 'NOT_RUN'

    $stage = ''
    if ($bStatus -eq 'RUNNING') {
        $stage = 'B'
    }
    elseif ($aStatus -eq 'RUNNING') {
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
$script:InstanceMutex = Enter-InstanceMutex -Role 'companion' -StartFilePath $script:StartFilePath
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
$script:CompanionGraceStartedAt = $null
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
$startupNotes = Get-SettingValue -Settings $startupSettings -Key 'SESSION_FINAL_NOTES' -Default ''
$startupSupervisorLogAnchor = Get-LatestAnchorValueFromNoteText -Notes $startupNotes -Key 'supervisor_log'
if (-not [string]::IsNullOrWhiteSpace($startupSupervisorLogAnchor)) {
    try {
        $supervisorLogPath = Resolve-RepoPath -Path $startupSupervisorLogAnchor
    }
    catch {
        $supervisorLogPath = ''
    }
}
$startupLiveStatusAnchor = Get-LatestAnchorValueFromNoteText -Notes $startupNotes -Key 'live_status'
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
    $sessionNotes = Get-SettingValue -Settings $settings -Key 'SESSION_FINAL_NOTES' -Default ''
    $sessionStatus = Get-SettingValue -Settings $settings -Key 'SESSION_FINAL_STATUS' -Default 'NOT_RUN'
    $aStatus = Get-SettingValue -Settings $settings -Key 'A_FINAL_STATUS' -Default 'NOT_RUN'
    $bStatus = Get-SettingValue -Settings $settings -Key 'B_FINAL_STATUS' -Default 'NOT_RUN'

    $monitorChainShutdownRequested = Convert-ToBooleanSetting -Value (Get-SettingValue -Settings $settings -Key 'MONITOR_CHAIN_SHUTDOWN_REQUESTED' -Default 'false') -Default $false
    if ($monitorChainShutdownRequested) {
        $monitorChainShutdownReason = Get-SettingValue -Settings $settings -Key 'MONITOR_CHAIN_SHUTDOWN_REASON' -Default ''
        $monitorChainShutdownSource = Get-SettingValue -Settings $settings -Key 'MONITOR_CHAIN_SHUTDOWN_SOURCE' -Default ''
        $monitorChainShutdownAt = Get-SettingValue -Settings $settings -Key 'MONITOR_CHAIN_SHUTDOWN_AT' -Default ''
        Write-CompanionLog ("stop reason=monitor-chain-shutdown-request source={0} request_reason={1} request_at={2}" -f $monitorChainShutdownSource, $monitorChainShutdownReason, $monitorChainShutdownAt)
        break
    }

    $stageContext = Get-CurrentStageContext -Settings $settings
    $stage = [string]$stageContext.Stage
    $stageRunDir = [string]$stageContext.RunDir
    $stageLaunchPid = Get-StageLaunchPid -Settings $settings -Stage $stage
    $stageProcessAlive = Test-StageProcessAlive -ProcessId $stageLaunchPid -Stage $stage

    $bPassFailConflict = Get-BPassFailConflictEvidence -Settings $settings -SessionNotes $sessionNotes -SessionStatus $sessionStatus -AStatus $aStatus -BStatus $bStatus
    if ([bool]$bPassFailConflict.Conflict) {
        Write-CompanionLog (
            "status_conflict_detected reason={0} session={1} a={2} b={3} exit_result={4} exit_code={5} fail_category={6} fail_reason={7} artifact={8}" -f
            [string]$bPassFailConflict.Reason,
            $sessionStatus,
            $aStatus,
            $bStatus,
            [string]$bPassFailConflict.ExitResult,
            [int]$bPassFailConflict.ExitCode,
            [string]$bPassFailConflict.FailCategory,
            [string]$bPassFailConflict.FailReason,
            [string]$bPassFailConflict.ArtifactPath)

        $conflictNote = "companion_pass_conflict b_exit_fail artifact={0} exit_code={1} fail_category={2}" -f [string]$bPassFailConflict.ArtifactPath, [int]$bPassFailConflict.ExitCode, [string]$bPassFailConflict.FailCategory
        $updatedNotes = Add-DelimitedNote -Existing $sessionNotes -Append $conflictNote
        try {
            Invoke-KeyValueFileValueUpdate -Path $script:StartFilePath -Values @{
                B_FINAL_STATUS = 'FAIL'
                B_LAUNCH_PID = '0'
                SESSION_FINAL_STATUS = 'FAIL'
                SESSION_CLOSED = 'false'
                SESSION_CLOSED_AT = ''
                SESSION_CLOSED_REASON = 'b-exit-fail-conflict'
                SESSION_FINAL_NOTES = $updatedNotes
            }
            Write-CompanionLog ("status_conflict_reconciled action=write_fail_status artifact={0}" -f [string]$bPassFailConflict.ArtifactPath)
            $settings = Read-KeyValueFile -Path $script:StartFilePath
            $sessionNotes = Get-SettingValue -Settings $settings -Key 'SESSION_FINAL_NOTES' -Default ''
            $sessionStatus = Get-SettingValue -Settings $settings -Key 'SESSION_FINAL_STATUS' -Default 'NOT_RUN'
            $aStatus = Get-SettingValue -Settings $settings -Key 'A_FINAL_STATUS' -Default 'NOT_RUN'
            $bStatus = Get-SettingValue -Settings $settings -Key 'B_FINAL_STATUS' -Default 'NOT_RUN'
        }
        catch {
            Write-CompanionLog ("status_conflict_reconcile_failed detail={0}" -f $_.Exception.Message)
        }
    }

    if ($sessionStatus -in @('PASS', 'FAIL', 'BLOCKED') -and $aStatus -ne 'RUNNING' -and $bStatus -ne 'RUNNING') {
        if ($monitorChainShutdownRequested) {
            Write-CompanionLog ("complete session_status={0} a={1} b={2}" -f $sessionStatus, $aStatus, $bStatus)
            break
        }
        if (-not $script:CompanionGraceStartedAt) {
            $script:CompanionGraceStartedAt = Get-Date
        }
        $graceElapsedMinutes = ((Get-Date) - $script:CompanionGraceStartedAt).TotalMinutes
        $monitorChainGraceMinutes = 15
        if ($settings.Contains('MONITOR_CHAIN_GRACE_MINUTES')) {
            $parsedGrace = 0
            if ([int]::TryParse(([string]$settings.MONITOR_CHAIN_GRACE_MINUTES), [ref]$parsedGrace)) {
                if ($parsedGrace -ge 1 -and $parsedGrace -le 120) {
                    $monitorChainGraceMinutes = [int]$parsedGrace
                }
            }
        }
        if ($graceElapsedMinutes -ge $monitorChainGraceMinutes) {
            Write-CompanionLog ("complete session_status={0} a={1} b={2} reason=grace-expired elapsed_min={3:N1}" -f $sessionStatus, $aStatus, $bStatus, $graceElapsedMinutes)
            break
        }
        Write-CompanionLog ("grace_wait session_status={0} a={1} b={2} elapsed_min={3:N1} remaining_min={4:N1}" -f $sessionStatus, $aStatus, $bStatus, $graceElapsedMinutes, ($monitorChainGraceMinutes - $graceElapsedMinutes))
        Start-Sleep -Seconds 30
        continue
    }

    $supervisorLogAnchor = Get-LatestAnchorValueFromNoteText -Notes $sessionNotes -Key 'supervisor_log'
    if (-not [string]::IsNullOrWhiteSpace($supervisorLogAnchor)) {
        try {
            $supervisorLogPath = Resolve-RepoPath -Path $supervisorLogAnchor
        }
        catch {
            $supervisorLogPath = ''
        }
    }

    if ([string]::IsNullOrWhiteSpace($supervisorLogPath) -or -not (Test-Path -LiteralPath $supervisorLogPath)) {
        $supervisorLogPath = Get-LatestSupervisorLog
    }

    $liveStatusAnchor = Get-LatestAnchorValueFromNoteText -Notes $sessionNotes -Key 'live_status'
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

    $supervisorAgeMinutes = Get-FileAgeMinuteValue -Path $supervisorLogPath
    $supervisorQuiet = ($supervisorAgeMinutes -ge $SupervisorQuietMinutes)

    $liveStatusAgeMinutes = Get-FileAgeMinuteValue -Path $liveStatusPath
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
        if ($stageProcessAlive) {
            $now = Get-Date
            if ($null -eq $lastQuietAliveAlertAt -or (($now - $lastQuietAliveAlertAt).TotalMinutes -ge 5.0)) {
                Write-CompanionLog ("quiet_alert reason=d1-no-progress-no-remote action=defer-block stage={0} stage_pid={1} stage_alive={2} no_progress_min={3:N1} threshold_min={4}" -f $currentState.Stage, $stageLaunchPid, $stageProcessAlive, $noProgressMinutes, $d1NoProgressLimitMinutes)
                $lastQuietAliveAlertAt = $now
            }
        }
        else {
            $blockedReason = 'd1-no-progress-no-remote'
            $blockedDetail = ("D1 no progress with no remote chain beyond threshold ({0} min)" -f $d1NoProgressLimitMinutes)
        }
    }
    elseif (-not [string]::IsNullOrWhiteSpace($currentState.Stage) -and $null -ne $stallSince -and (((Get-Date) - $stallSince).TotalMinutes -ge $UnknownStageStallMinutes)) {
        if ($stageProcessAlive) {
            $now = Get-Date
            if ($null -eq $lastQuietAliveAlertAt -or (($now - $lastQuietAliveAlertAt).TotalMinutes -ge 5.0)) {
                Write-CompanionLog ("quiet_alert reason=unknown-stage-stall action=defer-block stage={0} stage_pid={1} stage_alive={2} no_progress_min={3:N1} threshold_min={4}" -f $currentState.Stage, $stageLaunchPid, $stageProcessAlive, $noProgressMinutes, $UnknownStageStallMinutes)
                $lastQuietAliveAlertAt = $now
            }
        }
        else {
            $blockedReason = 'unknown-stage-stall'
            $blockedDetail = 'No artifact progress and no remote chain activity beyond threshold'
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($blockedReason)) {
        $blockedDir = Save-BlockedPackage -Reason $blockedReason -Detail $blockedDetail -Stage $currentState.Stage -StageRunDir $currentState.RunDir -InnerRunDir $currentState.InnerRunDir -SupervisorLogPath $supervisorLogPath
        $blockedRel = Convert-ToRepoRelativePath -Path $blockedDir

        $updates = @{
            SESSION_FINAL_STATUS = 'BLOCKED'
            SESSION_FINAL_NOTES = (Add-DelimitedNote -Existing (Get-SettingValue -Settings $settings -Key 'SESSION_FINAL_NOTES' -Default '') -Append ("companion_blocked reason=$blockedReason evidence=$blockedRel"))
        }
        if ($currentState.Stage -eq 'A' -and $aStatus -eq 'RUNNING') {
            $updates['A_FINAL_STATUS'] = 'BLOCKED'
            if ($bStatus -eq 'NOT_RUN') {
                $updates['B_FINAL_STATUS'] = 'BLOCKED'
            }
        }
        elseif ($currentState.Stage -eq 'B' -and $bStatus -eq 'RUNNING') {
            $updates['B_FINAL_STATUS'] = 'BLOCKED'
        }

        Invoke-KeyValueFileValueUpdate -Path $script:StartFilePath -Values $updates
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
    catch { Write-Verbose ("Suppressed exception: {0}" -f $_.Exception.Message) }
    finally {
        $script:InstanceMutex.Dispose()
    }
}
