[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Logging helper intentionally writes host and log file for unattended observability.')]
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Internal script helper functions are not exposed as interactive cmdlets.')]
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Existing helper names are kept for compatibility and readability in unattended flow scripts.')]
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseBOMForUnicodeEncodedFile', '', Justification = 'Repository policy uses UTF-8 without BOM for script files.')]
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '', Justification = 'Stale editor diagnostics may reference pre-rename symbols; actual helper names already use approved verbs where applicable.')]
param(
    [Parameter(Mandatory = $true)][string]$StartFile,
    [ValidateRange(5, 300)][int]$PollSec = 30,
    [switch]$Once,
    [switch]$NoAutoStopOnFinal,
    [switch]$ExitShellOnFinal,
    [AllowEmptyString()][string]$QueuePath = '',
    [AllowEmptyString()][string]$TriggerCommand = '',
    [switch]$ExecuteTriggerCommand,
    [ValidateRange(0, 200000)][int]$MaxProcessedIds = 0
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:TriggerLogWriteFailureKey = ''
$script:TriggerLogWriteFailureLastAt = [datetime]::MinValue

function Resolve-RepoPath {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw 'Path must not be empty.'
    }

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return (Resolve-Path -LiteralPath $Path).Path
    }

    return (Resolve-Path -LiteralPath (Join-Path $script:RepoRoot $Path)).Path
}

function Resolve-RepoPathAllowMissing {
    param([AllowEmptyString()][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return ''
    }

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return [System.IO.Path]::GetFullPath($Path)
    }

    return [System.IO.Path]::GetFullPath((Join-Path $script:RepoRoot $Path))
}

function Convert-ToRepoRelativePath {
    param([AllowEmptyString()][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return ''
    }

    try {
        $fullPath = [System.IO.Path]::GetFullPath($Path)
        $repoRootFull = [System.IO.Path]::GetFullPath($script:RepoRoot)
        if ($fullPath.StartsWith($repoRootFull, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $fullPath.Substring($repoRootFull.Length).TrimStart('\\').Replace('\\', '/')
        }

        return $fullPath.Replace('\\', '/')
    }
    catch {
        return $Path.Replace('\\', '/')
    }
}

function Convert-ToSingleLineText {
    param([AllowEmptyString()][string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return ''
    }

    $singleLine = (($Text -split "`r?`n") -join ' ')
    return ([regex]::Replace($singleLine, '\s+', ' ')).Trim()
}

function Get-StartFileMutexName {
    param(
        [AllowEmptyString()][string]$Role,
        [string]$StartFilePath
    )

    $roleToken = Convert-ToSingleLineText -Text $Role
    if ([string]::IsNullOrWhiteSpace($roleToken)) {
        $roleToken = 'takeover-trigger'
    }
    $roleToken = ([regex]::Replace($roleToken, '[^A-Za-z0-9._-]', '_')).Trim('_')
    if ([string]::IsNullOrWhiteSpace($roleToken)) {
        $roleToken = 'takeover-trigger'
    }

    $fullPath = [System.IO.Path]::GetFullPath($StartFilePath).ToLowerInvariant()
    $sha1 = [System.Security.Cryptography.SHA1]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($fullPath)
        $hashBytes = $sha1.ComputeHash($bytes)
        $hash = ([System.BitConverter]::ToString($hashBytes)).Replace('-', '').ToLowerInvariant()
    }
    finally {
        if ($null -ne $sha1) {
            $sha1.Dispose()
        }
    }

    return ("Local\wc_ab_{0}_{1}" -f $roleToken, $hash)
}

function Enter-InstanceMutex {
    param(
        [AllowEmptyString()][string]$Role,
        [string]$StartFilePath
    )

    $name = Get-StartFileMutexName -Role $Role -StartFilePath $StartFilePath
    $createdNew = $false
    $mutex = New-Object System.Threading.Mutex($false, $name, [ref]$createdNew)

    $acquired = $false
    try {
        $acquired = $mutex.WaitOne(0, $false)
    }
    catch [System.Threading.AbandonedMutexException] {
        $acquired = $true
    }

    if (-not $acquired) {
        Write-Host ("[AB-TAKEOVER-TRIGGER] single_instance_conflict mutex={0} start_file={1}" -f $name, $StartFilePath)
        $mutex.Dispose()
        return $null
    }

    return $mutex
}

function Get-ObjectPropertyString {
    param(
        [object]$InputObject,
        [string]$Name
    )

    if ($null -eq $InputObject -or [string]::IsNullOrWhiteSpace($Name)) {
        return ''
    }

    if ($InputObject -is [System.Collections.IDictionary]) {
        if ($InputObject.Contains($Name)) {
            return [string]$InputObject[$Name]
        }
        return ''
    }

    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return ''
    }

    return [string]$property.Value
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

function Get-DateTimeOrNull {
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

function Get-StatusValue {
    param([AllowEmptyString()][string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return 'NOT_RUN'
    }

    return $Value.Trim().ToUpperInvariant()
}

function Test-IsTerminalFinalStatus {
    param([AllowEmptyString()][string]$Status)

    $normalized = Get-StatusValue -Value $Status
    return $normalized -in @('PASS', 'FAIL', 'BLOCKED', 'STOPPED', 'ERROR', 'ABORTED', 'CANCELLED', 'TIMEOUT')
}

function Test-CurrentHostNoExitMode {
    try {
        $self = Get-CimInstance Win32_Process -Filter ("ProcessId={0}" -f $PID) -ErrorAction Stop
        $commandLine = [string]$self.CommandLine
        if (-not [string]::IsNullOrWhiteSpace($commandLine)) {
            $line = $commandLine.ToLowerInvariant()
            if ($line -match '(?:^|\s)-noexit(?:\s|$)') {
                return $true
            }
        }
    }
    catch {
        $null = $_
    }

    foreach ($arg in @([Environment]::GetCommandLineArgs())) {
        if ([string]::IsNullOrWhiteSpace($arg)) {
            continue
        }

        $normalized = $arg.Trim().ToLowerInvariant()
        if ($normalized -eq '-noexit' -or $normalized -eq '/noexit') {
            return $true
        }
    }

    return $false
}

function Get-IntSetting {
    param(
        [System.Collections.IDictionary]$Settings,
        [string]$Key,
        [int]$Default,
        [int]$Min,
        [int]$Max
    )

    if ($null -eq $Settings -or [string]::IsNullOrWhiteSpace($Key) -or -not $Settings.Contains($Key)) {
        return $Default
    }

    $raw = Convert-ToSingleLineText -Text ([string]$Settings[$Key])
    if ([string]::IsNullOrWhiteSpace($raw)) {
        return $Default
    }

    $parsed = 0
    if (-not [int]::TryParse($raw, [ref]$parsed)) {
        return $Default
    }

    if ($parsed -lt $Min -or $parsed -gt $Max) {
        return $Default
    }

    return $parsed
}

function Get-ChatHeartbeatPath {
    param(
        [System.Collections.IDictionary]$Settings,
        [string]$StartToken
    )

    $pathValue = ''
    if ($null -ne $Settings -and $Settings.Contains('AI_CHAT_HEARTBEAT_PATH')) {
        $pathValue = Convert-ToSingleLineText -Text ([string]$Settings.AI_CHAT_HEARTBEAT_PATH)
    }

    if ([string]::IsNullOrWhiteSpace($pathValue)) {
        $pathValue = Join-Path 'out\artifacts\ab_agent_queue' ("chat_session_heartbeat_{0}.json" -f $StartToken)
    }

    return Resolve-RepoPathAllowMissing -Path $pathValue
}

function Get-ChatHeartbeatState {
    param(
        [string]$Path,
        [datetime]$NowUtc,
        [int]$TtlMinutes,
        [int]$MissingGraceMinutes,
        [datetime]$ScriptStartUtc
    )

    $pathRel = Convert-ToRepoRelativePath -Path $Path
    $base = [ordered]@{
        path = $pathRel
        exists = $false
        updated_at = ''
        age_seconds = -1
        stale = $false
        reason = 'disabled'
    }

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return [pscustomobject]$base
    }

    if (-not (Test-Path -LiteralPath $Path)) {
        $uptimeMinutes = [Math]::Floor(([timespan]($NowUtc - $ScriptStartUtc)).TotalMinutes)
        if ($uptimeMinutes -lt $MissingGraceMinutes) {
            $base.reason = 'missing-grace'
            return [pscustomobject]$base
        }

        $base.stale = $true
        $base.reason = 'missing'
        return [pscustomobject]$base
    }

    $base.exists = $true
    $raw = Read-JsonFileSafely -Path $Path
    if ($null -eq $raw) {
        $base.stale = $true
        $base.reason = 'invalid-json'
        return [pscustomobject]$base
    }

    $updatedAt = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $raw -Name 'updated_at')
    $base.updated_at = $updatedAt
    if ([string]::IsNullOrWhiteSpace($updatedAt)) {
        $base.stale = $true
        $base.reason = 'missing-updated-at'
        return [pscustomobject]$base
    }

    $updatedUtc = Get-DateTimeOrNull -Text $updatedAt
    if ($null -eq $updatedUtc) {
        $base.stale = $true
        $base.reason = 'invalid-updated-at'
        return [pscustomobject]$base
    }

    $ageSeconds = [int][Math]::Floor(([timespan]($NowUtc - $updatedUtc)).TotalSeconds)
    if ($ageSeconds -lt 0) {
        $ageSeconds = 0
    }

    $base.age_seconds = $ageSeconds
    $ttlSeconds = [int]([Math]::Max(1, $TtlMinutes) * 60)
    if ($ageSeconds -gt $ttlSeconds) {
        $base.stale = $true
        $base.reason = 'heartbeat-timeout'
    }
    else {
        $base.stale = $false
        $base.reason = 'fresh'
    }

    return [pscustomobject]$base
}

function Test-SessionWatchExpected {
    param([System.Collections.IDictionary]$Settings)

    $sessionStatus = 'NOT_RUN'
    if ($null -ne $Settings -and $Settings.Contains('SESSION_FINAL_STATUS')) {
        $sessionStatus = Get-StatusValue -Value ([string]$Settings.SESSION_FINAL_STATUS)
    }

    $aStatus = 'NOT_RUN'
    if ($null -ne $Settings -and $Settings.Contains('A_FINAL_STATUS')) {
        $aStatus = Get-StatusValue -Value ([string]$Settings.A_FINAL_STATUS)
    }

    $bStatus = 'NOT_RUN'
    if ($null -ne $Settings -and $Settings.Contains('B_FINAL_STATUS')) {
        $bStatus = Get-StatusValue -Value ([string]$Settings.B_FINAL_STATUS)
    }

    $watchExpected = ($sessionStatus -eq 'RUNNING' -or $aStatus -eq 'RUNNING' -or $bStatus -eq 'RUNNING')
    return [pscustomobject]@{
        watch_expected = [bool]$watchExpected
        session_status = $sessionStatus
        a_status = $aStatus
        b_status = $bStatus
    }
}

function Get-SessionCloseGateState {
    param([System.Collections.IDictionary]$Settings)

    $sessionStatus = 'NOT_RUN'
    if ($null -ne $Settings -and $Settings.Contains('SESSION_FINAL_STATUS')) {
        $sessionStatus = Get-StatusValue -Value ([string]$Settings.SESSION_FINAL_STATUS)
    }

    $aStatus = 'NOT_RUN'
    if ($null -ne $Settings -and $Settings.Contains('A_FINAL_STATUS')) {
        $aStatus = Get-StatusValue -Value ([string]$Settings.A_FINAL_STATUS)
    }

    $bStatus = 'NOT_RUN'
    if ($null -ne $Settings -and $Settings.Contains('B_FINAL_STATUS')) {
        $bStatus = Get-StatusValue -Value ([string]$Settings.B_FINAL_STATUS)
    }

    $closedByFlagRaw = $false
    if ($null -ne $Settings -and $Settings.Contains('SESSION_CLOSED')) {
        $closedByFlagRaw = Convert-ToBooleanSetting -Value ([string]$Settings.SESSION_CLOSED) -Default $false
    }

    $closedByPassFinal = ($sessionStatus -eq 'PASS') -or ($aStatus -eq 'PASS' -and $bStatus -eq 'PASS')
    $closedByFlag = $closedByFlagRaw -and $closedByPassFinal
    $closed = $closedByFlag -or $closedByPassFinal

    $reason = 'none'
    if ($closedByFlag) {
        $reason = 'session-closed-flag'
    }
    elseif ($closedByPassFinal) {
        $reason = 'pass-final-status'
    }

    return [pscustomobject]@{
        closed = [bool]$closed
        reason = $reason
        closed_by_flag = [bool]$closedByFlag
        closed_by_pass_final = [bool]$closedByPassFinal
        session_status = $sessionStatus
        a_status = $aStatus
        b_status = $bStatus
    }
}

function Read-KeyValueFile {
    param([string]$Path)

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

function Get-StartFileWriteMutexName {
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

function Set-KeyValueFileValues {
    param(
        [string]$Path,
        [hashtable]$Values
    )

    if ([string]::IsNullOrWhiteSpace($Path) -or $null -eq $Values -or $Values.Count -lt 1) {
        return $false
    }

    $mutex = New-Object System.Threading.Mutex($false, (Get-StartFileWriteMutexName -StartFilePath $Path))
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

        $lines = @()
        if (Test-Path -LiteralPath $Path) {
            $lines = @(Get-Content -LiteralPath $Path -Encoding utf8 -ErrorAction Stop)
        }

        $seenKeys = @{}
        $lineNo = 0
        foreach ($line in $lines) {
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
        foreach ($line in $lines) {
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

        $tempPath = "$Path.tmp.$PID.$([guid]::NewGuid().ToString('N'))"
        Set-Content -LiteralPath $tempPath -Value @($buffer) -Encoding utf8 -ErrorAction Stop
        Move-Item -LiteralPath $tempPath -Destination $Path -Force
        $tempPath = ''
        return $true
    }
    finally {
        if (-not [string]::IsNullOrWhiteSpace($tempPath) -and (Test-Path -LiteralPath $tempPath)) {
            Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue
        }

        if ($locked) {
            try { $mutex.ReleaseMutex() } catch { $null = $_ }
        }
        $mutex.Dispose()
    }
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

function Get-SafeToken {
    param([string]$Text)

    $normalized = Convert-ToSingleLineText -Text $Text
    if ([string]::IsNullOrWhiteSpace($normalized)) {
        return 'default'
    }

    return ([regex]::Replace($normalized, '[^A-Za-z0-9._-]', '_')).Trim('_')
}

function Write-TriggerLog {
    param([string]$Message)

    $line = "[AB-TAKEOVER-TRIGGER] timestamp={0} {1}" -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'), (Convert-ToSingleLineText -Text $Message)
    Write-Host $line
    $maxAttempts = 5
    $written = $false
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        $stream = $null
        $writer = $null
        try {
            $stream = New-Object System.IO.FileStream($script:TriggerLogPath, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite)
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

    if ($written) {
        if ($script:TriggerLogWriteFailureKey -eq $script:TriggerLogPath) {
            $script:TriggerLogWriteFailureKey = ''
            $script:TriggerLogWriteFailureLastAt = [datetime]::MinValue
        }
        return
    }

    $now = Get-Date
    $shouldWarn = $false
    if ($script:TriggerLogWriteFailureKey -ne $script:TriggerLogPath) {
        $shouldWarn = $true
    }
    elseif (($now - $script:TriggerLogWriteFailureLastAt).TotalSeconds -ge 60) {
        $shouldWarn = $true
    }

    if ($shouldWarn) {
        $script:TriggerLogWriteFailureKey = $script:TriggerLogPath
        $script:TriggerLogWriteFailureLastAt = $now
        Write-Warning ("[AB-TAKEOVER-TRIGGER] log_write_failed path={0}" -f $script:TriggerLogPath)
    }
}

function Read-JsonFileSafely {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) {
        return $null
    }

    try {
        $raw = Get-Content -LiteralPath $Path -Raw -Encoding utf8 -ErrorAction Stop
        return ($raw | ConvertFrom-Json -ErrorAction Stop)
    }
    catch {
        return $null
    }
}

function Test-IsRetryableStateWriteError {
    param([System.Exception]$Exception)

    if ($null -eq $Exception) {
        return $false
    }

    if ($Exception -is [System.IO.IOException]) {
        return $true
    }

    $message = Convert-ToSingleLineText -Text $Exception.Message
    if ([string]::IsNullOrWhiteSpace($message)) {
        return $false
    }

    return ($message -match '(?i)(another process|being used by another process|cannot access the file|sharing violation|access.*denied|另一个进程|正在使用|无法访问此文件|访问被拒绝)')
}

function Write-JsonFileSafely {
    param(
        [string]$Path,
        $Value
    )

    $parent = Split-Path -Parent $Path
    if (-not [string]::IsNullOrWhiteSpace($parent) -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }

    $json = $Value | ConvertTo-Json -Depth 10
    $maxAttempts = 4
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        try {
            Set-Content -LiteralPath $Path -Value $json -Encoding utf8 -ErrorAction Stop
            return $true
        }
        catch {
            $isRetryable = Test-IsRetryableStateWriteError -Exception $_.Exception
            if (-not $isRetryable) {
                throw
            }

            if ($attempt -lt $maxAttempts) {
                Start-Sleep -Milliseconds (75 * $attempt)
                continue
            }

            return $false
        }
    }

    return $false
}

function Test-LogTailContainsFragment {
    param(
        [AllowEmptyString()][string]$Path,
        [AllowEmptyString()][string]$Fragment,
        [ValidateRange(20, 5000)][int]$TailLines = 1200
    )

    if ([string]::IsNullOrWhiteSpace($Path) -or [string]::IsNullOrWhiteSpace($Fragment)) {
        return $false
    }

    if (-not (Test-Path -LiteralPath $Path)) {
        return $false
    }

    try {
        foreach ($line in @(Get-Content -LiteralPath $Path -Tail $TailLines -Encoding utf8 -ErrorAction SilentlyContinue)) {
            if (-not [string]::IsNullOrWhiteSpace($line) -and $line.Contains($Fragment)) {
                return $true
            }
        }
    }
    catch {
        return $false
    }

    return $false
}

function Get-TicketsFromQueue {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) {
        return @()
    }

    $tickets = New-Object 'System.Collections.Generic.List[object]'
    $lineNo = 0
    foreach ($line in @(Get-Content -LiteralPath $Path -Encoding utf8 -ErrorAction SilentlyContinue)) {
        $lineNo++
        $jsonLine = Convert-ToSingleLineText -Text ([string]$line)
        if ([string]::IsNullOrWhiteSpace($jsonLine)) {
            continue
        }

        try {
            $ticket = $jsonLine | ConvertFrom-Json -ErrorAction Stop
            [void]$tickets.Add($ticket)
        }
        catch {
            Write-TriggerLog ("queue_parse_skip line={0} detail={1}" -f $lineNo, (Convert-ToSingleLineText -Text $_.Exception.Message))
        }
    }

    return $tickets.ToArray()
}

function Add-TicketToQueue {
    param(
        [object]$Ticket,
        [string]$QueueFilePath
    )

    $targetPath = Resolve-RepoPathAllowMissing -Path $QueueFilePath
    if ([string]::IsNullOrWhiteSpace($targetPath)) {
        return [pscustomobject]@{
            Success = $false
            Reason = 'queue-path-empty'
            Path = ''
        }
    }

    $parent = Split-Path -Parent $targetPath
    if (-not [string]::IsNullOrWhiteSpace($parent) -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }

    try {
        $line = $Ticket | ConvertTo-Json -Compress -Depth 8
        Add-Content -LiteralPath $targetPath -Value $line -Encoding utf8 -ErrorAction Stop
        return [pscustomobject]@{
            Success = $true
            Reason = 'queued'
            Path = $targetPath
        }
    }
    catch {
        return [pscustomobject]@{
            Success = $false
            Reason = (Convert-ToSingleLineText -Text $_.Exception.Message)
            Path = $targetPath
        }
    }
}

function Wait-QueueSignalOrTimeout {
    param(
        [AllowEmptyString()][string]$QueueFilePath,
        [ValidateRange(1, 600)][int]$TimeoutSec,
        [bool]$EnableEventDriven = $true
    )

    if ($TimeoutSec -le 0) {
        return 'immediate'
    }

    if (-not $EnableEventDriven) {
        Start-Sleep -Seconds $TimeoutSec
        return 'timer'
    }

    $path = Resolve-RepoPathAllowMissing -Path $QueueFilePath
    if ([string]::IsNullOrWhiteSpace($path)) {
        Start-Sleep -Seconds $TimeoutSec
        return 'timer'
    }

    $parent = Split-Path -Parent $path
    $leaf = Split-Path -Leaf $path
    if ([string]::IsNullOrWhiteSpace($parent) -or [string]::IsNullOrWhiteSpace($leaf) -or -not (Test-Path -LiteralPath $parent)) {
        Start-Sleep -Seconds $TimeoutSec
        return 'timer'
    }

    $watcher = $null
    try {
        $watcher = New-Object System.IO.FileSystemWatcher
        $watcher.Path = $parent
        $watcher.Filter = $leaf
        $watcher.NotifyFilter = [System.IO.NotifyFilters]'FileName,LastWrite,Size,CreationTime'
        $watcher.IncludeSubdirectories = $false
        $watcher.EnableRaisingEvents = $true

        $timeoutMs = [int]([Math]::Min([int]::MaxValue, $TimeoutSec * 1000))
        $change = $watcher.WaitForChanged([System.IO.WatcherChangeTypes]::All, $timeoutMs)
        if ($change.TimedOut) {
            return 'timer'
        }

        $changeType = (Convert-ToSingleLineText -Text ([string]$change.ChangeType)).ToLowerInvariant()
        if ([string]::IsNullOrWhiteSpace($changeType)) {
            return 'event'
        }

        return ('event-{0}' -f $changeType)
    }
    catch {
        Start-Sleep -Seconds $TimeoutSec
        return 'timer'
    }
    finally {
        if ($null -ne $watcher) {
            $watcher.Dispose()
        }
    }
}

function Resolve-ExternalTriggerExecutionPlan {
    param(
        [string]$Template,
        [string]$TicketId,
        [string]$EventName,
        [string]$StartFilePath,
        [string]$QueueFilePath,
        [string]$BriefPath
    )

    if ([string]::IsNullOrWhiteSpace($Template)) {
        return [pscustomobject]@{
            Valid = $false
            Reason = 'command-empty'
            FilePath = ''
            ArgumentList = @()
            Summary = ''
        }
    }

    $normalized = Convert-ToSingleLineText -Text $Template
    $dispatchPattern = '^(?i)powershell(?:\.exe)?\b.*\s-File\s+(["'']?)tools[\\/]test[\\/]dispatch_takeover_to_chat\.ps1\1(?:\s|$)'
    if ($normalized -notmatch $dispatchPattern) {
        return [pscustomobject]@{
            Valid = $false
            Reason = 'unsupported-command-template'
            FilePath = ''
            ArgumentList = @()
            Summary = $normalized
        }
    }

    if ($normalized -match '[`;&|<>]') {
        return [pscustomobject]@{
            Valid = $false
            Reason = 'unsafe-command-template'
            FilePath = ''
            ArgumentList = @()
            Summary = $normalized
        }
    }

    $dispatchScript = Join-Path $script:RepoRoot 'tools\test\dispatch_takeover_to_chat.ps1'
    if (-not (Test-Path -LiteralPath $dispatchScript)) {
        return [pscustomobject]@{
            Valid = $false
            Reason = 'dispatch-script-missing'
            FilePath = ''
            ArgumentList = @()
            Summary = $dispatchScript
        }
    }

    $powershellPath = Join-Path $PSHOME 'powershell.exe'
    if (-not (Test-Path -LiteralPath $powershellPath)) {
        $powershellPath = 'powershell.exe'
    }

    $argumentList = @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', $dispatchScript,
        '-TicketId', $TicketId,
        '-TicketEvent', $EventName,
        '-StartFile', $StartFilePath,
        '-QueuePath', $QueueFilePath,
        '-BriefPath', $BriefPath
    )

    if ($normalized -imatch '(?:^|\s)-NoOpenEditor(?:\s|$)') {
        $argumentList += '-NoOpenEditor'
    }
    if ($normalized -imatch '(?:^|\s)-SkipClipboard(?:\s|$)') {
        $argumentList += '-SkipClipboard'
    }

    return [pscustomobject]@{
        Valid = $true
        Reason = 'ready'
        FilePath = $powershellPath
        ArgumentList = $argumentList
        Summary = $normalized
    }
}

function Invoke-ExternalTriggerCommand {
    param([pscustomobject]$Plan)

    if ($null -eq $Plan -or -not [bool]$Plan.Valid) {
        return [pscustomobject]@{
            Started = $false
            ProcessId = 0
            Reason = if ($null -eq $Plan) { 'plan-empty' } else { [string]$Plan.Reason }
        }
    }

    try {
        $process = Start-Process -FilePath ([string]$Plan.FilePath) -ArgumentList @($Plan.ArgumentList) -WindowStyle Hidden -PassThru
        return [pscustomobject]@{
            Started = $true
            ProcessId = [int]$process.Id
            Reason = 'started'
        }
    }
    catch {
        return [pscustomobject]@{
            Started = $false
            ProcessId = 0
            Reason = (Convert-ToSingleLineText -Text $_.Exception.Message)
        }
    }
}

function New-TakeoverBrief {
    param(
        [object]$Ticket,
        [System.Collections.IDictionary]$Settings,
        [string]$OutputRoot,
        [string]$QueueFilePath,
        [string]$StartFilePath
    )

    if (-not (Test-Path -LiteralPath $OutputRoot)) {
        New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null
    }

    $ticketId = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $Ticket -Name 'ticket_id')
    $eventName = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $Ticket -Name 'event')
    $eventNameNormalized = $eventName.ToLowerInvariant()
    $fileName = ('takeover_{0}_{1}.md' -f (Get-SafeToken -Text $ticketId), (Get-Date).ToString('yyyyMMdd-HHmmss'))
    $briefPath = Join-Path $OutputRoot $fileName

    $sessionCloseGate = Get-SessionCloseGateState -Settings $Settings
    $suppressResumeInBrief = [bool]$sessionCloseGate.closed -or $eventNameNormalized -eq 'running-status-report' -or $eventNameNormalized -eq 'chat-session-final-status'
    $resumeCommand = ''
    $guardCommand = 'powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/open_unattended_ab_session_guard_window.ps1 -StartFile "{0}" -NoRestartIfRunning' -f (Convert-ToRepoRelativePath -Path $StartFilePath)
    if (-not $suppressResumeInBrief) {
        $resumeCommand = 'powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/open_unattended_ab_resume_window.ps1 -StartFile "{0}" -StartMonitors' -f (Convert-ToRepoRelativePath -Path $StartFilePath)
        $guardCommand = 'powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/open_unattended_ab_session_guard_window.ps1 -StartFile "{0}"' -f (Convert-ToRepoRelativePath -Path $StartFilePath)
    }

    $nextCommands = New-Object 'System.Collections.Generic.List[string]'
    if (-not [string]::IsNullOrWhiteSpace($resumeCommand)) {
        [void]$nextCommands.Add($resumeCommand)
    }
    if (-not [string]::IsNullOrWhiteSpace($guardCommand)) {
        [void]$nextCommands.Add($guardCommand)
    }
    if ($nextCommands.Count -lt 1) {
        [void]$nextCommands.Add('# no next command')
    }

    $notes = if ($Settings.Contains('SESSION_FINAL_NOTES')) { [string]$Settings.SESSION_FINAL_NOTES } else { '' }
    $runDir = Get-LatestAnchorValueFromNotes -Notes $notes -Key 'run_dir'
    $supervisorLog = Get-LatestAnchorValueFromNotes -Notes $notes -Key 'supervisor_log'
    $companionLog = Get-LatestAnchorValueFromNotes -Notes $notes -Key 'companion_log'
    $liveStatus = Get-LatestAnchorValueFromNotes -Notes $notes -Key 'live_status'

    $lines = @(
        '# AB Takeover Brief',
        '',
        ('generated_at={0}' -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')),
        ('ticket_id={0}' -f $ticketId),
        ('event={0}' -f $eventName),
        ('severity={0}' -f (Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $Ticket -Name 'severity'))),
        ('requires_confirmation={0}' -f (Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $Ticket -Name 'requires_confirmation'))),
        ('start_file={0}' -f (Convert-ToRepoRelativePath -Path $StartFilePath)),
        ('queue_path={0}' -f (Convert-ToRepoRelativePath -Path $QueueFilePath)),
        ('guard_state={0}' -f (Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $Ticket -Name 'guard_state'))),
        ('guard_log={0}' -f (Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $Ticket -Name 'guard_log'))),
        ('incident_dir={0}' -f (Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $Ticket -Name 'incident_dir'))),
        ('session_final_status={0}' -f (Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $Ticket -Name 'session_final_status'))),
        ('a_final_status={0}' -f (Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $Ticket -Name 'a_final_status'))),
        ('b_final_status={0}' -f (Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $Ticket -Name 'b_final_status'))),
        ('run_dir={0}' -f $runDir),
        ('supervisor_log={0}' -f $supervisorLog),
        ('companion_log={0}' -f $companionLog),
        ('live_status={0}' -f $liveStatus),
        ('detail={0}' -f (Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $Ticket -Name 'detail'))),
        ('recommended_action={0}' -f (Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $Ticket -Name 'recommended_action'))),
        '',
        'next_commands:'
    )
    $lines += @($nextCommands.ToArray())

    Set-Content -LiteralPath $briefPath -Value $lines -Encoding utf8
    return $briefPath
}

$script:RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$startFilePath = Resolve-RepoPath -Path $StartFile
$startFileToken = Get-SafeToken -Text ([System.IO.Path]::GetFileNameWithoutExtension($startFilePath).ToLowerInvariant())

$queueRoot = Resolve-RepoPathAllowMissing -Path 'out\artifacts\ab_agent_queue'
if (-not (Test-Path -LiteralPath $queueRoot)) {
    New-Item -ItemType Directory -Path $queueRoot -Force | Out-Null
}

$script:TriggerLogPath = Join-Path $queueRoot ("takeover_trigger_{0}.log" -f $startFileToken)
$statePath = Join-Path $queueRoot ("takeover_trigger_state_{0}.json" -f $startFileToken)
$takeoverRoot = Join-Path $queueRoot 'takeover_requests'
$script:InstanceMutex = Enter-InstanceMutex -Role 'takeover-trigger' -StartFilePath $startFilePath
if ($script:InstanceMutex -isnot [System.Threading.Mutex]) {
    return
}

$stateRaw = Read-JsonFileSafely -Path $statePath
$processedIds = New-Object 'System.Collections.Generic.List[string]'
$processedSet = @{}
if ($null -ne $stateRaw -and $stateRaw.PSObject.Properties.Name -contains 'processed_ids') {
    foreach ($id in @($stateRaw.processed_ids)) {
        $ticketId = Convert-ToSingleLineText -Text ([string]$id)
        if ([string]::IsNullOrWhiteSpace($ticketId)) {
            continue
        }

        if (-not $processedSet.Contains($ticketId)) {
            $processedSet[$ticketId] = $true
            [void]$processedIds.Add($ticketId)
        }
    }
}

$scriptStartUtc = (Get-Date).ToUniversalTime()
$chatRecoveryLastTriggerAt = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $stateRaw -Name 'chat_recovery_last_trigger_at')
$chatRecoveryLastSignature = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $stateRaw -Name 'chat_recovery_last_signature')
$chatRecoveryTriggerCount = 0
$chatRecoveryTriggerCountRaw = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $stateRaw -Name 'chat_recovery_trigger_count')
if (-not [string]::IsNullOrWhiteSpace($chatRecoveryTriggerCountRaw)) {
    $parsedCount = 0
    if ([int]::TryParse($chatRecoveryTriggerCountRaw, [ref]$parsedCount) -and $parsedCount -ge 0) {
        $chatRecoveryTriggerCount = $parsedCount
    }
}

$chatRecoveryLastFastRetrySignature = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $stateRaw -Name 'chat_recovery_last_fast_retry_signature')
$chatRecoveryLastFastRetryAt = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $stateRaw -Name 'chat_recovery_last_fast_retry_at')
$chatRecoveryFastRetryCount = 0
$chatRecoveryFastRetryCountRaw = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $stateRaw -Name 'chat_recovery_fast_retry_count')
if (-not [string]::IsNullOrWhiteSpace($chatRecoveryFastRetryCountRaw)) {
    $parsedFastRetryCount = 0
    if ([int]::TryParse($chatRecoveryFastRetryCountRaw, [ref]$parsedFastRetryCount) -and $parsedFastRetryCount -ge 0) {
        $chatRecoveryFastRetryCount = $parsedFastRetryCount
    }
}

Write-TriggerLog ("startup start_file={0} poll_sec={1} once={2} state={3}" -f (Convert-ToRepoRelativePath -Path $startFilePath), $PollSec, [bool]$Once.IsPresent, (Convert-ToRepoRelativePath -Path $statePath))
$triggerParentPid = 0
try {
    $triggerSelfProcess = Get-CimInstance Win32_Process -Filter ("ProcessId={0}" -f $PID) -ErrorAction Stop
    if ($null -ne $triggerSelfProcess) {
        $triggerParentPid = [int]$triggerSelfProcess.ParentProcessId
    }
}
catch {
    $triggerParentPid = 0
}
Write-TriggerLog ("startup_pid pid={0} parent_pid={1}" -f $PID, $triggerParentPid)

$waitQueuePath = Resolve-RepoPathAllowMissing -Path 'out\artifacts\ab_agent_queue\agent_tickets.jsonl'
$eventDrivenQueue = $true

while ($true) {
    try {
        if (-not (Test-Path -LiteralPath $startFilePath)) {
            Write-TriggerLog ("stop reason=start-file-missing start_file={0}" -f (Convert-ToRepoRelativePath -Path $startFilePath))
            break
        }

        $settings = Read-KeyValueFile -Path $startFilePath

        $queueEnabled = $true
        if ($settings.Contains('LOCAL_GUARD_AGENT_QUEUE_ENABLED')) {
            $queueEnabled = Convert-ToBooleanSetting -Value ([string]$settings.LOCAL_GUARD_AGENT_QUEUE_ENABLED) -Default $true
        }

        $queuePathValue = $QueuePath
        if ([string]::IsNullOrWhiteSpace($queuePathValue)) {
            if ($settings.Contains('LOCAL_GUARD_AGENT_QUEUE_PATH')) {
                $queuePathValue = [string]$settings.LOCAL_GUARD_AGENT_QUEUE_PATH
            }
        }
        if ([string]::IsNullOrWhiteSpace($queuePathValue)) {
            $queuePathValue = 'out\artifacts\ab_agent_queue\agent_tickets.jsonl'
        }

        $queueFilePath = Resolve-RepoPathAllowMissing -Path $queuePathValue
        $waitQueuePath = $queueFilePath

        $triggerCommandValue = $TriggerCommand
        if ([string]::IsNullOrWhiteSpace($triggerCommandValue) -and $settings.Contains('EXTERNAL_TRIGGER_COMMAND')) {
            $triggerCommandValue = [string]$settings.EXTERNAL_TRIGGER_COMMAND
        }

        $executeCommand = $ExecuteTriggerCommand.IsPresent
        if (-not $executeCommand -and $settings.Contains('EXTERNAL_TRIGGER_EXECUTE')) {
            $executeCommand = Convert-ToBooleanSetting -Value ([string]$settings.EXTERNAL_TRIGGER_EXECUTE) -Default $false
        }

        if (-not $queueEnabled) {
            Write-TriggerLog 'queue_disabled action=skip'
            if ($Once.IsPresent) {
                break
            }

            $wakeReason = Wait-QueueSignalOrTimeout -QueueFilePath $queueFilePath -TimeoutSec $PollSec -EnableEventDriven $eventDrivenQueue
            if ($wakeReason -ne 'timer') {
                Write-TriggerLog ("wake reason={0} queue={1}" -f $wakeReason, (Convert-ToRepoRelativePath -Path $queueFilePath))
            }
            continue
        }

        $chatHeartbeatEnabled = $true
        if ($settings.Contains('AI_CHAT_HEARTBEAT_ENABLED')) {
            $chatHeartbeatEnabled = Convert-ToBooleanSetting -Value ([string]$settings.AI_CHAT_HEARTBEAT_ENABLED) -Default $true
        }
        $chatAutoRecoverEnabled = $false
        if ($settings.Contains('AI_CHAT_AUTO_RECOVER_ENABLED')) {
            $chatAutoRecoverEnabled = Convert-ToBooleanSetting -Value ([string]$settings.AI_CHAT_AUTO_RECOVER_ENABLED) -Default $false
        }
        $dispatchStatusReports = $false
        if ($settings.Contains('AI_CHAT_TRIGGER_DISPATCH_STATUS_REPORTS')) {
            $dispatchStatusReports = Convert-ToBooleanSetting -Value ([string]$settings.AI_CHAT_TRIGGER_DISPATCH_STATUS_REPORTS) -Default $false
        }
        $eventDrivenQueue = $true
        if ($settings.Contains('AI_CHAT_TRIGGER_EVENT_DRIVEN_QUEUE')) {
            $eventDrivenQueue = Convert-ToBooleanSetting -Value ([string]$settings.AI_CHAT_TRIGGER_EVENT_DRIVEN_QUEUE) -Default $true
        }
        $chatHeartbeatTtlMinutes = Get-IntSetting -Settings $settings -Key 'AI_CHAT_HEARTBEAT_TTL_MINUTES' -Default 12 -Min 2 -Max 180
        $chatHeartbeatMissingGraceMinutes = Get-IntSetting -Settings $settings -Key 'AI_CHAT_HEARTBEAT_MISSING_GRACE_MINUTES' -Default 20 -Min 1 -Max 180
        $chatRecoveryCooldownMinutes = Get-IntSetting -Settings $settings -Key 'AI_CHAT_AUTO_RECOVER_COOLDOWN_MINUTES' -Default 10 -Min 1 -Max 240
        $chatRecoveryFastRetryEnabled = $true
        if ($settings.Contains('AI_CHAT_AUTO_RECOVER_FAST_RETRY_ENABLED')) {
            $chatRecoveryFastRetryEnabled = Convert-ToBooleanSetting -Value ([string]$settings.AI_CHAT_AUTO_RECOVER_FAST_RETRY_ENABLED) -Default $true
        }
        $chatRecoveryFastRetrySeconds = Get-IntSetting -Settings $settings -Key 'AI_CHAT_AUTO_RECOVER_FAST_RETRY_SECONDS' -Default 90 -Min 30 -Max 900
        $chatRecoveryEventRaw = ''
        if ($settings.Contains('AI_CHAT_AUTO_RECOVER_EVENT')) {
            $chatRecoveryEventRaw = [string]$settings.AI_CHAT_AUTO_RECOVER_EVENT
        }
        $chatRecoveryEvent = Convert-ToSingleLineText -Text $chatRecoveryEventRaw
        if ([string]::IsNullOrWhiteSpace($chatRecoveryEvent)) {
            $chatRecoveryEvent = 'chat-session-heartbeat-timeout'
        }

        $watchExpectation = Test-SessionWatchExpected -Settings $settings
        $sessionCloseGate = Get-SessionCloseGateState -Settings $settings
        $autoStopOnFinal = -not $NoAutoStopOnFinal.IsPresent
        if ($autoStopOnFinal -and (Test-IsTerminalFinalStatus -Status $watchExpectation.session_status) -and -not [bool]$watchExpectation.watch_expected) {
            if ([string]$watchExpectation.session_status -eq 'PASS') {
                $closeUpdates = @{
                    SESSION_CLOSED = 'true'
                    SESSION_CLOSED_AT = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
                    SESSION_CLOSED_REASON = 'chat-session-final-status-pass'
                }
                try {
                    $closeApplied = Set-KeyValueFileValues -Path $startFilePath -Values $closeUpdates
                    Write-TriggerLog ('session_closed_set applied={0} reason={1}' -f [bool]$closeApplied, [string]$closeUpdates.SESSION_CLOSED_REASON)
                }
                catch {
                    Write-TriggerLog ('session_closed_set_failed detail={0}' -f (Convert-ToSingleLineText -Text $_.Exception.Message))
                }
            }

            $finalEventName = 'chat-session-final-status'
            $finalSignature = ('session={0};a={1};b={2}' -f [string]$watchExpectation.session_status, [string]$watchExpectation.a_status, [string]$watchExpectation.b_status)
            $finalDispatchMarker = ('final_status_trigger_started signature={0}' -f $finalSignature)
            $alreadyFinalDispatched = Test-LogTailContainsFragment -Path $script:TriggerLogPath -Fragment $finalDispatchMarker

            if (-not $alreadyFinalDispatched) {
                $finalTicketId = ('chat-final-{0}' -f (Get-Date).ToString('yyyyMMdd-HHmmss'))
                $finalDetail = ('session reached terminal status; session={0}; a={1}; b={2}' -f [string]$watchExpectation.session_status, [string]$watchExpectation.a_status, [string]$watchExpectation.b_status)
                $finalTicket = [pscustomobject]@{
                    ticket_id = $finalTicketId
                    event = $finalEventName
                    severity = 'info'
                    requires_confirmation = $false
                    guard_state = 'session-final'
                    guard_log = ''
                    incident_dir = ''
                    session_final_status = [string]$watchExpectation.session_status
                    a_final_status = [string]$watchExpectation.a_status
                    b_final_status = [string]$watchExpectation.b_status
                    detail = $finalDetail
                    recommended_action = 'confirm completion and close monitor windows.'
                }

                $finalBriefPath = New-TakeoverBrief -Ticket $finalTicket -Settings $settings -OutputRoot $takeoverRoot -QueueFilePath $queueFilePath -StartFilePath $startFilePath
                $finalBriefRel = Convert-ToRepoRelativePath -Path $finalBriefPath
                Write-TriggerLog ('final_status_dispatch signature={0} id={1} event={2} brief={3}' -f $finalSignature, $finalTicketId, $finalEventName, $finalBriefRel)

                if (-not [string]::IsNullOrWhiteSpace($triggerCommandValue) -and $executeCommand) {
                    $finalPlan = Resolve-ExternalTriggerExecutionPlan -Template $triggerCommandValue -TicketId $finalTicketId -EventName $finalEventName -StartFilePath $startFilePath -QueueFilePath $queueFilePath -BriefPath $finalBriefPath
                    $finalResult = Invoke-ExternalTriggerCommand -Plan $finalPlan
                    if ([bool]$finalResult.Started) {
                        Write-TriggerLog ('final_status_trigger_started signature={0} id={1} pid={2}' -f $finalSignature, $finalTicketId, [int]$finalResult.ProcessId)
                    }
                    else {
                        Write-TriggerLog ('final_status_trigger_failed id={0} detail={1}' -f $finalTicketId, [string]$finalResult.Reason)
                    }
                }
                elseif (-not [string]::IsNullOrWhiteSpace($triggerCommandValue)) {
                    Write-TriggerLog ('final_status_trigger_skipped id={0} reason=execution-disabled' -f $finalTicketId)
                }
                else {
                    Write-TriggerLog ('final_status_trigger_skipped id={0} reason=command-empty' -f $finalTicketId)
                }
            }
            else {
                Write-TriggerLog ('final_status_skip reason=already-dispatched signature={0}' -f $finalSignature)
            }

            Write-TriggerLog ('auto_stop reason=session-final session={0} a={1} b={2}' -f [string]$watchExpectation.session_status, [string]$watchExpectation.a_status, [string]$watchExpectation.b_status)
            if ($ExitShellOnFinal.IsPresent -or (Test-CurrentHostNoExitMode)) {
                [Environment]::Exit(0)
            }

            break
        }

        $nowUtc = (Get-Date).ToUniversalTime()
        $chatHeartbeatPath = ''
        $chatHeartbeatState = [pscustomobject]@{
            path = ''
            exists = $false
            updated_at = ''
            age_seconds = -1
            stale = $false
            reason = 'disabled'
        }
        if ($chatHeartbeatEnabled) {
            $chatHeartbeatPath = Get-ChatHeartbeatPath -Settings $settings -StartToken $startFileToken
            $chatHeartbeatState = Get-ChatHeartbeatState -Path $chatHeartbeatPath -NowUtc $nowUtc -TtlMinutes $chatHeartbeatTtlMinutes -MissingGraceMinutes $chatHeartbeatMissingGraceMinutes -ScriptStartUtc $scriptStartUtc
        }

        $chatRecoveryRunReason = ''
        if ($chatAutoRecoverEnabled -and $chatHeartbeatEnabled -and [bool]$watchExpectation.watch_expected -and [bool]$chatHeartbeatState.stale) {
            $heartbeatSignature = if (-not [string]::IsNullOrWhiteSpace([string]$chatHeartbeatState.updated_at)) {
                ('updated_at:{0}' -f [string]$chatHeartbeatState.updated_at)
            }
            else {
                ('reason:{0}' -f [string]$chatHeartbeatState.reason)
            }

            $cooldownReady = $true
            $lastTriggerUtc = Get-DateTimeOrNull -Text $chatRecoveryLastTriggerAt
            $elapsedSinceLastTriggerSeconds = -1
            if ($null -ne $lastTriggerUtc) {
                $elapsedMinutes = ([timespan]($nowUtc - $lastTriggerUtc)).TotalMinutes
                $elapsedSinceLastTriggerSeconds = [int][Math]::Floor(([timespan]($nowUtc - $lastTriggerUtc)).TotalSeconds)
                if ($elapsedMinutes -lt $chatRecoveryCooldownMinutes) {
                    $cooldownReady = $false
                }
            }

            $signatureChanged = ([string]$chatRecoveryLastSignature -ne [string]$heartbeatSignature)
            $fastRetryReady = $false
            if ($chatRecoveryFastRetryEnabled -and -not $cooldownReady -and -not $signatureChanged -and $elapsedSinceLastTriggerSeconds -ge 0) {
                $alreadyFastRetriedForSignature = ([string]$chatRecoveryLastFastRetrySignature -eq [string]$heartbeatSignature)
                if (-not $alreadyFastRetriedForSignature -and $elapsedSinceLastTriggerSeconds -ge $chatRecoveryFastRetrySeconds) {
                    $fastRetryReady = $true
                }
            }

            if ($cooldownReady -or $signatureChanged -or $fastRetryReady) {
                $triggerMode = 'regular'
                if ($fastRetryReady) {
                    $triggerMode = 'fast-retry'
                }

                $ticketId = ('chat-recover-{0}' -f (Get-Date).ToString('yyyyMMdd-HHmmss'))
                $detail = ('chat session heartbeat stale; reason={0}; updated_at={1}; age_seconds={2}; ttl_minutes={3}; heartbeat_path={4}' -f
                    [string]$chatHeartbeatState.reason,
                    [string]$chatHeartbeatState.updated_at,
                    [int]$chatHeartbeatState.age_seconds,
                    [int]$chatHeartbeatTtlMinutes,
                    [string]$chatHeartbeatState.path)

                $ticket = [pscustomobject]@{
                    ticket_id = $ticketId
                    event = $chatRecoveryEvent
                    severity = 'high'
                    requires_confirmation = $false
                    guard_state = 'chat-session-stale'
                    guard_log = ''
                    incident_dir = ''
                    session_final_status = [string]$watchExpectation.session_status
                    a_final_status = [string]$watchExpectation.a_status
                    b_final_status = [string]$watchExpectation.b_status
                    detail = $detail
                    recommended_action = 'reopen chat channel and continue blocking watch; then execute business and continue_watch commands from latest poll output.'
                }

                $enqueueResult = Add-TicketToQueue -Ticket $ticket -QueueFilePath $queueFilePath
                if ([bool]$enqueueResult.Success) {
                    $chatRecoveryLastTriggerAt = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
                    $chatRecoveryLastSignature = $heartbeatSignature
                    $chatRecoveryTriggerCount = [int]$chatRecoveryTriggerCount + 1
                    if ($fastRetryReady) {
                        $chatRecoveryLastFastRetrySignature = $heartbeatSignature
                        $chatRecoveryLastFastRetryAt = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
                        $chatRecoveryFastRetryCount = [int]$chatRecoveryFastRetryCount + 1
                        $chatRecoveryRunReason = 'ticket-enqueued-fast-retry'
                    }
                    else {
                        $chatRecoveryRunReason = 'ticket-enqueued'
                    }

                    Write-TriggerLog ('chat_recovery_ticket_enqueued id={0} event={1} queue={2} signature={3} mode={4}' -f $ticketId, $chatRecoveryEvent, (Convert-ToRepoRelativePath -Path ([string]$enqueueResult.Path)), $heartbeatSignature, $triggerMode)
                }
                else {
                    $chatRecoveryRunReason = ('ticket-enqueue-failed:{0}' -f [string]$enqueueResult.Reason)
                    Write-TriggerLog ('chat_recovery_ticket_enqueue_failed id={0} detail={1} queue={2} mode={3}' -f $ticketId, [string]$enqueueResult.Reason, (Convert-ToRepoRelativePath -Path ([string]$enqueueResult.Path)), $triggerMode)
                }
            }
            else {
                $chatRecoveryRunReason = ('cooldown-active minutes={0} fast_retry_seconds={1}' -f $chatRecoveryCooldownMinutes, $chatRecoveryFastRetrySeconds)
                Write-TriggerLog ('chat_recovery_skip reason=cooldown signature={0} fast_retry_enabled={1} fast_retry_seconds={2}' -f $heartbeatSignature, $chatRecoveryFastRetryEnabled, $chatRecoveryFastRetrySeconds)
            }
        }

        $tickets = @(Get-TicketsFromQueue -Path $queueFilePath)
        $newCount = 0

        foreach ($ticket in $tickets) {
            $ticketId = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $ticket -Name 'ticket_id')
            if ([string]::IsNullOrWhiteSpace($ticketId)) {
                continue
            }

            if ($processedSet.Contains($ticketId)) {
                continue
            }

            $eventName = (Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $ticket -Name 'event')).ToLowerInvariant()
            if ([bool]$sessionCloseGate.closed -and $eventName -ne 'chat-session-final-status') {
                Write-TriggerLog ("ticket_skip id={0} event={1} reason=session-closed-lock" -f $ticketId, $eventName)
                if (-not $processedSet.Contains($ticketId)) {
                    $processedSet[$ticketId] = $true
                    [void]$processedIds.Add($ticketId)
                }
                $newCount++
                continue
            }

            if (-not $dispatchStatusReports -and $eventName -eq 'running-status-report') {
                Write-TriggerLog ("ticket_skip id={0} event={1} reason=status-report-dispatch-disabled" -f $ticketId, $eventName)
                if (-not $processedSet.Contains($ticketId)) {
                    $processedSet[$ticketId] = $true
                    [void]$processedIds.Add($ticketId)
                }
                $newCount++
                continue
            }

            $briefPath = New-TakeoverBrief -Ticket $ticket -Settings $settings -OutputRoot $takeoverRoot -QueueFilePath $queueFilePath -StartFilePath $startFilePath
            $briefRel = Convert-ToRepoRelativePath -Path $briefPath
            $eventName = Convert-ToSingleLineText -Text (Get-ObjectPropertyString -InputObject $ticket -Name 'event')

            Write-TriggerLog ("ticket_dispatch id={0} event={1} brief={2}" -f $ticketId, $eventName, $briefRel)

            if (-not [string]::IsNullOrWhiteSpace($triggerCommandValue)) {
                if ($executeCommand) {
                    $plan = Resolve-ExternalTriggerExecutionPlan -Template $triggerCommandValue -TicketId $ticketId -EventName $eventName -StartFilePath $startFilePath -QueueFilePath $queueFilePath -BriefPath $briefPath
                    $commandResult = Invoke-ExternalTriggerCommand -Plan $plan
                    if ([bool]$commandResult.Started) {
                        Write-TriggerLog ("external_trigger_started id={0} pid={1}" -f $ticketId, [int]$commandResult.ProcessId)
                    }
                    else {
                        Write-TriggerLog ("external_trigger_failed id={0} detail={1} template={2}" -f $ticketId, [string]$commandResult.Reason, (Convert-ToSingleLineText -Text ([string]$plan.Summary)))
                    }
                }
                else {
                    Write-TriggerLog ("external_trigger_skipped id={0} reason=execution-disabled" -f $ticketId)
                }
            }

            $processedSet[$ticketId] = $true
            [void]$processedIds.Add($ticketId)
            $newCount++
        }

        if ($MaxProcessedIds -gt 0) {
            while ($processedIds.Count -gt $MaxProcessedIds) {
                $oldId = [string]$processedIds[0]
                $processedIds.RemoveAt(0)
                if ($processedSet.Contains($oldId)) {
                    $processedSet.Remove($oldId) | Out-Null
                }
            }
        }

        $state = [ordered]@{
            schema = 'AB_TAKEOVER_TRIGGER_STATE_V2'
            updated_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
            start_file = (Convert-ToRepoRelativePath -Path $startFilePath)
            queue_path = (Convert-ToRepoRelativePath -Path $queueFilePath)
            processed_ids = @($processedIds)
            chat_recovery_last_trigger_at = $chatRecoveryLastTriggerAt
            chat_recovery_last_signature = $chatRecoveryLastSignature
            chat_recovery_trigger_count = [int]$chatRecoveryTriggerCount
            chat_recovery_last_fast_retry_signature = $chatRecoveryLastFastRetrySignature
            chat_recovery_last_fast_retry_at = $chatRecoveryLastFastRetryAt
            chat_recovery_fast_retry_count = [int]$chatRecoveryFastRetryCount
            chat_recovery_last_run_reason = $chatRecoveryRunReason
            chat_recovery_enabled = [bool]$chatAutoRecoverEnabled
            chat_recovery_fast_retry_enabled = [bool]$chatRecoveryFastRetryEnabled
            chat_recovery_fast_retry_seconds = [int]$chatRecoveryFastRetrySeconds
            chat_recovery_watch_expected = [bool]$watchExpectation.watch_expected
            chat_heartbeat_enabled = [bool]$chatHeartbeatEnabled
            chat_heartbeat_path = (Convert-ToRepoRelativePath -Path $chatHeartbeatPath)
            chat_heartbeat_updated_at = [string]$chatHeartbeatState.updated_at
            chat_heartbeat_age_seconds = [int]$chatHeartbeatState.age_seconds
            chat_heartbeat_stale = [bool]$chatHeartbeatState.stale
            chat_heartbeat_reason = [string]$chatHeartbeatState.reason
            trigger_event_driven_queue = [bool]$eventDrivenQueue
        }
        $stateWriteOk = Write-JsonFileSafely -Path $statePath -Value $state
        if (-not $stateWriteOk) {
            Write-TriggerLog ("state_write_skip reason=state-file-in-use path={0}" -f (Convert-ToRepoRelativePath -Path $statePath))
        }
        $stateRaw = $state

        if ($Once.IsPresent) {
            break
        }

        $wakeReason = Wait-QueueSignalOrTimeout -QueueFilePath $waitQueuePath -TimeoutSec $PollSec -EnableEventDriven $eventDrivenQueue
        if ($wakeReason -ne 'timer') {
            Write-TriggerLog ("wake reason={0} queue={1}" -f $wakeReason, (Convert-ToRepoRelativePath -Path $waitQueuePath))
        }

        continue
    }
    catch {
        $errorDetail = Convert-ToSingleLineText -Text $_.Exception.Message
        $errorType = if ($null -ne $_.Exception) { [string]$_.Exception.GetType().FullName } else { 'unknown' }
        $errorPos = Convert-ToSingleLineText -Text $_.InvocationInfo.PositionMessage
        Write-TriggerLog ("loop_error type={0} detail={1} pos={2}" -f $errorType, $errorDetail, $errorPos)
        if ($Once.IsPresent) {
            break
        }
    }

    $wakeReason = Wait-QueueSignalOrTimeout -QueueFilePath $waitQueuePath -TimeoutSec $PollSec -EnableEventDriven $eventDrivenQueue
    if ($wakeReason -ne 'timer') {
        Write-TriggerLog ("wake reason={0} queue={1}" -f $wakeReason, (Convert-ToRepoRelativePath -Path $waitQueuePath))
    }
}

Write-TriggerLog 'shutdown'
Write-TriggerLog ("shutdown_pid pid={0}" -f $PID)
if ($script:InstanceMutex -is [System.Threading.Mutex]) {
    try {
        $script:InstanceMutex.ReleaseMutex() | Out-Null
    }
    catch {
        $null = $_
    }
    finally {
        $script:InstanceMutex.Dispose()
    }
}
