param(
    [Parameter(Mandatory = $true)][string]$StartFile,
    [ValidateRange(15, 300)][int]$PollSec = 60,
    [ValidateRange(0, 10)][int]$MaxBRecoveryAttempts = 2,
    [ValidateRange(1, 180)][int]$RecoveryCooldownMinutes = 10,
    [bool]$StopOnBudgetExhausted = $true
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

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

function Convert-ToRepoRelativePath {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return ''
    }

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $repoRootFull = [System.IO.Path]::GetFullPath($script:RepoRoot)
    if ($fullPath.StartsWith($repoRootFull, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $fullPath.Substring($repoRootFull.Length).TrimStart('\\').Replace('\\', '/')
    }

    return $Path.Replace('\\', '/')
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
    param([AllowEmptyString()][string]$Text)

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

function Get-FilteredRuntimeTailLines {
    param([string[]]$Lines)

    $filtered = New-Object 'System.Collections.Generic.List[string]'
    foreach ($record in @($Lines)) {
        $line = Convert-ToSingleLineText -Text ([string]$record)
        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }

        if ($line -match '^\*{8,}') {
            continue
        }

        if ($line -imatch '^windows powershell transcript (start|end)$' -or
            $line -imatch '^start time:' -or
            $line -imatch '^end time:' -or
            $line -imatch '^username:' -or
            $line -imatch '^runas user:' -or
            $line -imatch '^machine:' -or
            $line -imatch '^host application:' -or
            $line -imatch '^process id:' -or
            $line -imatch '^psversion:' -or
            $line -imatch '^serializationversion:' -or
            $line -imatch '^wsman stack version:') {
            continue
        }

        [void]$filtered.Add($line)
    }

    return @($filtered)
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
            Write-Output "[AB-SESSION-GUARD] single_instance_conflict mutex=$name start_file=$StartFilePath"
            $mutex.Dispose()
            throw 'Another unattended_ab_session_guard instance is already active for this start file'
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
        [AllowEmptyString()][string]$Existing,
        [AllowEmptyString()][string]$Append
    )

    if ([string]::IsNullOrWhiteSpace($Append)) {
        return $Existing
    }

    if ([string]::IsNullOrWhiteSpace($Existing)) {
        return $Append.Trim()
    }

    return ($Existing.TrimEnd() + '; ' + $Append.Trim())
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

function Resolve-AnchorPath {
    param([AllowEmptyString()][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return ''
    }

    try {
        return Resolve-RepoPath -Path $Path
    }
    catch {
        return ''
    }
}

function Copy-FileIfExists {
    param(
        [AllowEmptyString()][string]$Source,
        [string]$Destination
    )

    if ([string]::IsNullOrWhiteSpace($Source)) {
        return
    }

    if (-not (Test-Path -LiteralPath $Source)) {
        return
    }

    $parent = Split-Path -Parent $Destination
    if (-not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }

    Copy-Item -LiteralPath $Source -Destination $Destination -Force
}

function Export-FileTail {
    param(
        [AllowEmptyString()][string]$Source,
        [string]$Destination,
        [ValidateRange(1, 2000)][int]$Tail = 400
    )

    if ([string]::IsNullOrWhiteSpace($Source)) {
        return
    }

    if (-not (Test-Path -LiteralPath $Source)) {
        return
    }

    $parent = Split-Path -Parent $Destination
    if (-not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }

    @(Get-Content -LiteralPath $Source -Tail $Tail -ErrorAction SilentlyContinue) | Set-Content -LiteralPath $Destination -Encoding utf8
}

function Write-GuardLog {
    param([string]$Message)

    $line = "[AB-SESSION-GUARD] timestamp={0} {1}" -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'), $Message
    Write-Host $line
    try {
        Add-Content -LiteralPath $script:GuardLogPath -Value $line -Encoding utf8
    }
    catch {
        Write-Warning ("[AB-SESSION-GUARD] log_write_failed path={0}" -f $script:GuardLogPath)
    }
}

function Write-GuardPastedBlock {
    param(
        [string]$Tag,
        [string[]]$Lines,
        [ValidateRange(12, 160)][int]$SeparatorWidth = 72
    )

    if ([string]::IsNullOrWhiteSpace($Tag)) {
        $Tag = 'guard_paste_block'
    }

    $normalized = @(
        @($Lines) |
            ForEach-Object { Convert-ToSingleLineText -Text ([string]$_) } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    )
    if ($normalized.Count -lt 1) {
        return
    }

    $separator = ('-' * $SeparatorWidth)
    Write-GuardLog ("{0}_begin {1}" -f $Tag, $separator)
    foreach ($entry in $normalized) {
        Write-GuardLog ("{0} {1}" -f $Tag, $entry)
    }
    Write-GuardLog ("{0}_end {1}" -f $Tag, $separator)
}

function Write-GuardState {
    param([hashtable]$Values)

    foreach ($key in $Values.Keys) {
        $script:GuardState[$key] = $Values[$key]
    }
    $script:GuardState.updated_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')

    $json = $script:GuardState | ConvertTo-Json -Depth 8
    try {
        $json | Set-Content -LiteralPath $script:GuardStatePath -Encoding utf8
    }
    catch {
        Write-Warning ("[AB-SESSION-GUARD] state_write_failed path={0} detail={1}" -f $script:GuardStatePath, $_.Exception.Message)
    }
}

function Get-StatusValue {
    param([AllowEmptyString()][string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return 'NOT_RUN'
    }

    return $Value.Trim().ToUpperInvariant()
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

function Test-ProcessAlive {
    param([int]$ProcessId)

    if ($ProcessId -le 0) {
        return $false
    }

    try {
        Get-Process -Id $ProcessId -ErrorAction Stop | Out-Null
        return $true
    }
    catch {
        return $false
    }
}

function Get-BStageProcessCandidates {
    $startFileLeaf = [string]$script:StartFileLeaf
    $candidates = @(
        Get-CimInstance Win32_Process |
            Where-Object {
                $line = [string]$_.CommandLine
                if ([string]::IsNullOrWhiteSpace($line)) {
                    return $false
                }

                $lineLower = $line.ToLowerInvariant()
                if (-not [string]::IsNullOrWhiteSpace($startFileLeaf) -and -not $lineLower.Contains($startFileLeaf)) {
                    return $false
                }

                if ($lineLower.Contains('unattended_ab_supervisor.ps1') -or
                    $lineLower.Contains('unattended_ab_companion.ps1') -or
                    $lineLower.Contains('unattended_ab_session_guard.ps1') -or
                    $lineLower.Contains('open_unattended_ab_stage_window.ps1')) {
                    return $false
                }

                return ($lineLower -match 'start_dev_verify_fastmode_b\.ps1|start_dev_verify_8round_multiround\.ps1')
            } |
            Select-Object ProcessId, Name, CreationDate, CommandLine |
            Sort-Object CreationDate, ProcessId -Descending
    )

    return @($candidates)
}

function Get-BStageProcessSnapshot {
    param([int]$ExpectedProcessId)

    $expectedAlive = Test-ProcessAlive -ProcessId $ExpectedProcessId
    $candidates = @(Get-BStageProcessCandidates)
    $candidateIds = @($candidates | Select-Object -ExpandProperty ProcessId -Unique)

    $resolvedProcessId = 0
    $resolvedSource = 'none'

    if ($expectedAlive -and $ExpectedProcessId -gt 0) {
        $resolvedProcessId = [int]$ExpectedProcessId
        $resolvedSource = 'expected'
    }
    elseif ($candidateIds.Count -eq 1) {
        $resolvedProcessId = [int]$candidateIds[0]
        $resolvedSource = 'single-candidate'
    }
    elseif ($candidateIds.Count -gt 1) {
        $resolvedSource = 'ambiguous-candidates'
    }

    $hasAliveProcess = $expectedAlive -or ($candidateIds.Count -gt 0)
    $anchorUpdateRequired = ($resolvedProcessId -gt 0 -and $resolvedProcessId -ne $ExpectedProcessId)

    return [pscustomobject]@{
        ExpectedProcessId = [int]$ExpectedProcessId
        ExpectedAlive = [bool]$expectedAlive
        CandidateCount = [int]$candidateIds.Count
        CandidateIds = @($candidateIds)
        ResolvedProcessId = [int]$resolvedProcessId
        ResolvedSource = [string]$resolvedSource
        HasAliveProcess = [bool]$hasAliveProcess
        AnchorUpdateRequired = [bool]$anchorUpdateRequired
    }
}

function Get-StageExitReasonArtifactPath {
    param([string]$Stage)

    $stageLower = $Stage.Trim().ToLowerInvariant()
    return (Join-Path $script:RepoRoot (Join-Path 'out\artifacts\ab_stage_exit' ("latest_{0}_exit.json" -f $stageLower)))
}

function Get-BStageExitReasonEvidence {
    param([int]$ExpectedProcessId)

    $artifactPath = Get-StageExitReasonArtifactPath -Stage 'B'
    $result = [ordered]@{
        Available = $false
        ArtifactPath = (Convert-ToRepoRelativePath -Path $artifactPath)
        Stage = 'B'
        ProcessId = 0
        ExitCode = 0
        Result = ''
        FailCategory = ''
        FailReason = ''
        GeneratedAt = ''
        StartFilePath = ''
        RuntimeLogPath = ''
        StartFileMatch = $false
        ProcessIdMatch = $false
        ParseError = ''
    }

    if (-not (Test-Path -LiteralPath $artifactPath)) {
        return [pscustomobject]$result
    }

    $payload = $null
    try {
        $payloadRaw = Get-Content -LiteralPath $artifactPath -Raw -Encoding utf8 -ErrorAction Stop
        $payload = $payloadRaw | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        $result.ParseError = Convert-ToSingleLineText -Text $_.Exception.Message
        return [pscustomobject]$result
    }

    $result.Available = $true

    if ($payload.PSObject.Properties.Name -contains 'stage') {
        $result.Stage = (Convert-ToSingleLineText -Text ([string]$payload.stage)).ToUpperInvariant()
    }

    if ($payload.PSObject.Properties.Name -contains 'process_id') {
        $parsedPid = Convert-ToNullablePositiveInt -Value ([string]$payload.process_id)
        if ($null -ne $parsedPid) {
            $result.ProcessId = [int]$parsedPid
        }
    }

    if ($payload.PSObject.Properties.Name -contains 'exit_code') {
        $parsedExitCode = 0
        if ([int]::TryParse(([string]$payload.exit_code), [ref]$parsedExitCode)) {
            $result.ExitCode = [int]$parsedExitCode
        }
    }

    if ($payload.PSObject.Properties.Name -contains 'result') {
        $result.Result = (Convert-ToSingleLineText -Text ([string]$payload.result)).ToLowerInvariant()
    }

    if ($payload.PSObject.Properties.Name -contains 'fail_category') {
        $result.FailCategory = Convert-ToSingleLineText -Text ([string]$payload.fail_category)
    }

    if ($payload.PSObject.Properties.Name -contains 'fail_reason') {
        $result.FailReason = Convert-ToSingleLineText -Text ([string]$payload.fail_reason)
    }

    if ($payload.PSObject.Properties.Name -contains 'generated_at') {
        $result.GeneratedAt = Convert-ToSingleLineText -Text ([string]$payload.generated_at)
    }

    $artifactStartFilePath = ''
    if ($payload.PSObject.Properties.Name -contains 'start_file_path') {
        $artifactStartFilePath = Convert-ToSingleLineText -Text ([string]$payload.start_file_path)
        $result.StartFilePath = $artifactStartFilePath
    }

    if ($payload.PSObject.Properties.Name -contains 'runtime_log_path') {
        $result.RuntimeLogPath = Convert-ToSingleLineText -Text ([string]$payload.runtime_log_path)
    }

    if ([string]::IsNullOrWhiteSpace($artifactStartFilePath)) {
        $result.StartFileMatch = $true
    }
    else {
        try {
            $expectedStartFile = [System.IO.Path]::GetFullPath($script:StartFilePath)
            $artifactStartFile = [System.IO.Path]::GetFullPath($artifactStartFilePath)
            $result.StartFileMatch = $artifactStartFile.Equals($expectedStartFile, [System.StringComparison]::OrdinalIgnoreCase)
        }
        catch {
            $result.StartFileMatch = $false
        }
    }

    $result.ProcessIdMatch = ($ExpectedProcessId -gt 0 -and [int]$result.ProcessId -eq $ExpectedProcessId)
    return [pscustomobject]$result
}

function Get-BRuntimeLogHint {
    param(
        [System.Collections.IDictionary]$Settings,
        [AllowEmptyString()][string]$ArtifactRuntimeLogPath
    )

    if (-not [string]::IsNullOrWhiteSpace($ArtifactRuntimeLogPath)) {
        return $ArtifactRuntimeLogPath
    }

    if ($null -ne $Settings -and $Settings.Contains('B_RUNTIME_LOG')) {
        $value = Convert-ToSingleLineText -Text ([string]$Settings.B_RUNTIME_LOG)
        if (-not [string]::IsNullOrWhiteSpace($value)) {
            return $value
        }
    }

    $notes = ''
    if ($null -ne $Settings -and $Settings.Contains('SESSION_FINAL_NOTES')) {
        $notes = [string]$Settings.SESSION_FINAL_NOTES
    }

    $anchor = Get-LatestAnchorValueFromNotes -Notes $notes -Key 'b_runtime_log'
    if (-not [string]::IsNullOrWhiteSpace($anchor)) {
        return $anchor
    }

    return ''
}

function Get-BRuntimeTailEvidence {
    param(
        [AllowEmptyString()][string]$RuntimeLogPath,
        [ValidateRange(5, 200)][int]$PrimaryTail = 10,
        [ValidateRange(10, 400)][int]$ExpandedTail = 30,
        [ValidateRange(20, 1000)][int]$MaxTail = 80,
        [ValidateRange(1, 50)][int]$MinimumUsefulLines = 6
    )

    $result = [ordered]@{
        Available = $false
        RuntimeLogPath = ''
        UsedTail = 0
        Escalated = $false
        Lines = @()
        Error = ''
    }

    if ([string]::IsNullOrWhiteSpace($RuntimeLogPath)) {
        return [pscustomobject]$result
    }

    $resolvedPath = Resolve-AnchorPath -Path $RuntimeLogPath
    if ([string]::IsNullOrWhiteSpace($resolvedPath)) {
        $result.Error = 'resolve-log-path-failed'
        return [pscustomobject]$result
    }

    $result.RuntimeLogPath = Convert-ToRepoRelativePath -Path $resolvedPath
    if (-not (Test-Path -LiteralPath $resolvedPath)) {
        $result.Error = 'runtime-log-not-found'
        return [pscustomobject]$result
    }

    $tailCandidates = @($PrimaryTail, $ExpandedTail, $MaxTail)
    $bestLines = @()
    $usedTail = $PrimaryTail

    foreach ($tail in $tailCandidates) {
        if ($tail -le 0) {
            continue
        }

        try {
            $rawTail = @(Get-Content -LiteralPath $resolvedPath -Tail $tail -ErrorAction Stop)
            $filteredTail = @(Get-FilteredRuntimeTailLines -Lines $rawTail)
            if ($filteredTail.Count -eq 0) {
                $filteredTail = @($rawTail | ForEach-Object { Convert-ToSingleLineText -Text ([string]$_) } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
            }

            $bestLines = @($filteredTail)
            $usedTail = $tail

            if ($bestLines.Count -ge $MinimumUsefulLines) {
                break
            }
        }
        catch {
            $result.Error = Convert-ToSingleLineText -Text $_.Exception.Message
            return [pscustomobject]$result
        }
    }

    $result.UsedTail = [int]$usedTail
    $result.Escalated = ([int]$usedTail -gt [int]$PrimaryTail)
    $result.Lines = @($bestLines)
    $result.Available = ($bestLines.Count -gt 0)
    return [pscustomobject]$result
}

function Format-AgeMinutesForLog {
    param([double]$AgeMinutes)

    if ([double]::IsNaN($AgeMinutes) -or [double]::IsInfinity($AgeMinutes) -or $AgeMinutes -lt 0) {
        return 'n/a'
    }

    return ([Math]::Round($AgeMinutes, 1).ToString('0.0'))
}

function Get-PathFreshnessEvidence {
    param(
        [AllowEmptyString()][string]$Path,
        [ValidateRange(1, 180)][int]$WindowMinutes = 6
    )

    $result = [ordered]@{
        Exists = $false
        Fresh = $false
        AgeMinutes = -1.0
        Path = ''
        ResolvedPath = ''
    }

    $resolvedPath = Resolve-AnchorPath -Path $Path
    if ([string]::IsNullOrWhiteSpace($resolvedPath)) {
        return [pscustomobject]$result
    }

    $result.ResolvedPath = $resolvedPath
    $result.Path = Convert-ToRepoRelativePath -Path $resolvedPath

    if (-not (Test-Path -LiteralPath $resolvedPath)) {
        return [pscustomobject]$result
    }

    try {
        $item = Get-Item -LiteralPath $resolvedPath -ErrorAction Stop
        $ageMinutes = ((Get-Date) - $item.LastWriteTime).TotalMinutes
        $result.Exists = $true
        $result.AgeMinutes = [double]$ageMinutes
        $result.Fresh = ($ageMinutes -le $WindowMinutes)
    }
    catch {
    }

    return [pscustomobject]$result
}

function Get-RunDirFreshnessEvidence {
    param(
        [AllowEmptyString()][string]$RunDirPath,
        [ValidateRange(1, 180)][int]$WindowMinutes = 6
    )

    $result = [ordered]@{
        Exists = $false
        Fresh = $false
        AgeMinutes = -1.0
        Path = ''
        ResolvedPath = ''
    }

    $resolvedPath = Resolve-AnchorPath -Path $RunDirPath
    if ([string]::IsNullOrWhiteSpace($resolvedPath)) {
        return [pscustomobject]$result
    }

    $result.ResolvedPath = $resolvedPath
    $result.Path = Convert-ToRepoRelativePath -Path $resolvedPath

    if (-not (Test-Path -LiteralPath $resolvedPath)) {
        return [pscustomobject]$result
    }

    try {
        $latestWriteTime = (Get-Item -LiteralPath $resolvedPath -ErrorAction Stop).LastWriteTime
        $latestFile = $null
        foreach ($file in @(Get-ChildItem -LiteralPath $resolvedPath -File -Recurse -Force -ErrorAction SilentlyContinue)) {
            if ($null -eq $latestFile -or $file.LastWriteTime -gt $latestFile.LastWriteTime) {
                $latestFile = $file
            }
        }

        if ($null -ne $latestFile -and $latestFile.LastWriteTime -gt $latestWriteTime) {
            $latestWriteTime = $latestFile.LastWriteTime
        }

        $ageMinutes = ((Get-Date) - $latestWriteTime).TotalMinutes
        $result.Exists = $true
        $result.AgeMinutes = [double]$ageMinutes
        $result.Fresh = ($ageMinutes -le $WindowMinutes)
    }
    catch {
    }

    return [pscustomobject]$result
}

function Get-BudgetExhaustedLivenessEvidence {
    param(
        [System.Collections.IDictionary]$Settings,
        [ValidateRange(2, 180)][int]$WindowMinutes = 6,
        [int]$FallbackProcessId = 0
    )

    $notes = ''
    if ($null -ne $Settings -and $Settings.Contains('SESSION_FINAL_NOTES')) {
        $notes = [string]$Settings.SESSION_FINAL_NOTES
    }

    $bLaunchPid = $FallbackProcessId
    if ($null -ne $Settings -and $Settings.Contains('B_LAUNCH_PID')) {
        $parsedPid = Convert-ToNullablePositiveInt -Value ([string]$Settings.B_LAUNCH_PID)
        if ($null -ne $parsedPid) {
            $bLaunchPid = [int]$parsedPid
        }
    }

    $supervisorLogAnchor = Get-LatestAnchorValueFromNotes -Notes $notes -Key 'supervisor_log'
    $liveStatusAnchor = Get-LatestAnchorValueFromNotes -Notes $notes -Key 'live_status'
    $runDirAnchor = Get-LatestAnchorValueFromNotes -Notes $notes -Key 'run_dir'
    $runtimeLogHint = Get-BRuntimeLogHint -Settings $Settings -ArtifactRuntimeLogPath ''

    $pidAlive = Test-ProcessAlive -ProcessId $bLaunchPid
    $supervisorFreshness = Get-PathFreshnessEvidence -Path $supervisorLogAnchor -WindowMinutes $WindowMinutes
    $liveStatusFreshness = Get-PathFreshnessEvidence -Path $liveStatusAnchor -WindowMinutes $WindowMinutes
    $runtimeFreshness = Get-PathFreshnessEvidence -Path $runtimeLogHint -WindowMinutes $WindowMinutes
    $runDirFreshness = Get-RunDirFreshnessEvidence -RunDirPath $runDirAnchor -WindowMinutes $WindowMinutes

    $hostFresh = ([bool]$supervisorFreshness.Fresh -or [bool]$liveStatusFreshness.Fresh)
    $artifactFresh = ([bool]$runtimeFreshness.Fresh -or [bool]$runDirFreshness.Fresh)
    $active = ($pidAlive -or ($hostFresh -and $artifactFresh))

    $detail = ("pid={0} pid_alive={1} window_min={2} supervisor_age_min={3} live_status_age_min={4} runtime_age_min={5} run_dir_age_min={6}" -f
        $bLaunchPid,
        $pidAlive,
        $WindowMinutes,
        (Format-AgeMinutesForLog -AgeMinutes [double]$supervisorFreshness.AgeMinutes),
        (Format-AgeMinutesForLog -AgeMinutes [double]$liveStatusFreshness.AgeMinutes),
        (Format-AgeMinutesForLog -AgeMinutes [double]$runtimeFreshness.AgeMinutes),
        (Format-AgeMinutesForLog -AgeMinutes [double]$runDirFreshness.AgeMinutes))

    return [pscustomobject]@{
        Active = [bool]$active
        BLaunchPid = [int]$bLaunchPid
        ProcessAlive = [bool]$pidAlive
        Detail = $detail
    }
}

function Capture-IncidentPackage {
    param(
        [System.Collections.IDictionary]$Settings,
        [string]$SessionStatus,
        [string]$AStatus,
        [string]$BStatus
    )

    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $incidentDir = Join-Path $script:GuardOutDir ("incident_" + $stamp)
    New-Item -ItemType Directory -Path $incidentDir -Force | Out-Null

    $notes = if ($Settings.Contains('SESSION_FINAL_NOTES')) { [string]$Settings.SESSION_FINAL_NOTES } else { '' }
    $runDirAnchor = Get-LatestAnchorValueFromNotes -Notes $notes -Key 'run_dir'
    $supervisorLogAnchor = Get-LatestAnchorValueFromNotes -Notes $notes -Key 'supervisor_log'
    $companionLogAnchor = Get-LatestAnchorValueFromNotes -Notes $notes -Key 'companion_log'
    $liveStatusAnchor = Get-LatestAnchorValueFromNotes -Notes $notes -Key 'live_status'

    $runDir = Resolve-AnchorPath -Path $runDirAnchor
    $supervisorLog = Resolve-AnchorPath -Path $supervisorLogAnchor
    $companionLog = Resolve-AnchorPath -Path $companionLogAnchor
    $liveStatus = Resolve-AnchorPath -Path $liveStatusAnchor

    Copy-FileIfExists -Source $script:StartFilePath -Destination (Join-Path $incidentDir 'start_file_snapshot.md')
    Copy-FileIfExists -Source $liveStatus -Destination (Join-Path $incidentDir 'live_status.json')
    Export-FileTail -Source $supervisorLog -Destination (Join-Path $incidentDir 'supervisor_tail.log') -Tail 500
    Export-FileTail -Source $companionLog -Destination (Join-Path $incidentDir 'companion_tail.log') -Tail 500

    if (-not [string]::IsNullOrWhiteSpace($runDir) -and (Test-Path -LiteralPath $runDir)) {
        Copy-FileIfExists -Source (Join-Path $runDir 'final_status.json') -Destination (Join-Path $incidentDir 'run_final_status.json')
        Copy-FileIfExists -Source (Join-Path $runDir 'final_status.txt') -Destination (Join-Path $incidentDir 'run_final_status.txt')
        Copy-FileIfExists -Source (Join-Path $runDir 'summary.csv') -Destination (Join-Path $incidentDir 'summary.csv')
        Copy-FileIfExists -Source (Join-Path $runDir 'summary_partial.csv') -Destination (Join-Path $incidentDir 'summary_partial.csv')
    }

    $startFileLeaf = [System.IO.Path]::GetFileName($script:StartFilePath).ToLowerInvariant()
    $processSnapshot = @(
        Get-CimInstance Win32_Process |
            Where-Object {
                $line = [string]$_.CommandLine
                if ([string]::IsNullOrWhiteSpace($line)) {
                    return $false
                }

                $lineLower = $line.ToLowerInvariant()
                if (-not [string]::IsNullOrWhiteSpace($startFileLeaf) -and -not $lineLower.Contains($startFileLeaf)) {
                    return $false
                }

                return ($lineLower -match 'unattended_ab_|start_dev_verify_fastmode_|start_dev_verify_8round_multiround')
            } |
            Select-Object ProcessId, Name, CreationDate, CommandLine |
            Sort-Object ProcessId
    )
    $processSnapshot | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $incidentDir 'process_snapshot.json') -Encoding utf8

    $gitStatus = @((& git -C $script:RepoRoot status --short 2>&1) | ForEach-Object { [string]$_ })
    $gitStatus | Set-Content -LiteralPath (Join-Path $incidentDir 'git_status_short.txt') -Encoding utf8

    $summary = @(
        "captured_at=$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))",
        "session_status=$SessionStatus",
        "a_status=$AStatus",
        "b_status=$BStatus",
        "run_dir_anchor=$runDirAnchor",
        "supervisor_log_anchor=$supervisorLogAnchor",
        "companion_log_anchor=$companionLogAnchor",
        "live_status_anchor=$liveStatusAnchor"
    )
    $summary | Set-Content -LiteralPath (Join-Path $incidentDir 'summary.txt') -Encoding utf8

    return $incidentDir
}

function Invoke-BStageRestart {
    param([int]$Attempt)

    $stageLauncher = Join-Path $script:RepoRoot 'tools\test\open_unattended_ab_stage_window.ps1'
    $powershellPath = Join-Path $PSHOME 'powershell.exe'
    if (-not (Test-Path -LiteralPath $powershellPath)) {
        $powershellPath = 'powershell.exe'
    }

    Write-GuardLog ("restart_begin stage=B attempt={0} launcher={1}" -f $Attempt, (Convert-ToRepoRelativePath -Path $stageLauncher))
    $output = @(& $powershellPath -NoProfile -ExecutionPolicy Bypass -File $stageLauncher -Stage B -StartFile $script:StartFilePath -EnableBMonitorRestart 2>&1 | ForEach-Object { [string]$_ })
    $exitCode = $LASTEXITCODE

    $outputLines = @(
        @($output) |
            ForEach-Object { Convert-ToSingleLineText -Text ([string]$_) } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    )
    if ($outputLines.Count -gt 0) {
        Write-GuardLog ("restart_output_summary attempt={0} lines={1}" -f $Attempt, $outputLines.Count)
        $outputBlockLines = New-Object 'System.Collections.Generic.List[string]'
        [void]$outputBlockLines.Add(("attempt={0}" -f $Attempt))
        foreach ($line in $outputLines) {
            [void]$outputBlockLines.Add(("line={0}" -f $line))
        }
        Write-GuardPastedBlock -Tag 'restart_output_block' -Lines @($outputBlockLines)
    }

    return [pscustomobject]@{
        ExitCode = [int]$exitCode
        Succeeded = ([int]$exitCode -eq 0)
    }
}

$script:RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$script:StartFilePath = Resolve-RepoPath -Path $StartFile
$script:StartFileLeaf = [System.IO.Path]::GetFileName($script:StartFilePath).ToLowerInvariant()
$script:InstanceMutex = Acquire-InstanceMutex -Role 'session-guard' -StartFilePath $script:StartFilePath

$guardStamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$script:GuardOutDir = Join-Path $script:RepoRoot (Join-Path 'out\artifacts\ab_session_guard' $guardStamp)
New-Item -ItemType Directory -Path $script:GuardOutDir -Force | Out-Null
$script:GuardLogPath = Join-Path $script:GuardOutDir 'guard.log'
$script:GuardStatePath = Join-Path $script:GuardOutDir 'guard_state.json'
$script:GuardState = [ordered]@{
    schema = 'AB_SESSION_GUARD_STATE_V1'
    status = 'starting'
    start_file = (Convert-ToRepoRelativePath -Path $script:StartFilePath)
    guard_log = (Convert-ToRepoRelativePath -Path $script:GuardLogPath)
    guard_state = (Convert-ToRepoRelativePath -Path $script:GuardStatePath)
    poll_sec = [int]$PollSec
    max_b_recovery_attempts = [int]$MaxBRecoveryAttempts
    recovery_cooldown_minutes = [int]$RecoveryCooldownMinutes
    stop_on_budget_exhausted = [bool]$StopOnBudgetExhausted
    auto_recover_b = $true
    b_recovery_attempts = 0
    last_recovery_at = ''
}

Write-GuardState -Values @{}
Write-GuardLog ("startup start_file={0} poll_sec={1} max_b_recovery_attempts={2} recovery_cooldown_minutes={3} stop_on_budget_exhausted={4} guard_log={5} guard_state={6}" -f (Convert-ToRepoRelativePath -Path $script:StartFilePath), $PollSec, $MaxBRecoveryAttempts, $RecoveryCooldownMinutes, $StopOnBudgetExhausted, (Convert-ToRepoRelativePath -Path $script:GuardLogPath), (Convert-ToRepoRelativePath -Path $script:GuardStatePath))

$bRecoveryAttempts = 0
$lastRecoveryAt = [datetime]::MinValue
$lastIncidentSignature = ''
$lastHeartbeatAt = [datetime]::MinValue
$lastBudgetExhaustedSignature = ''
$bRunningNoProcessSince = $null
$lastMissingBProcessReportAt = $null
$lastBMissingExitReasonEvidence = $null
$lastBMissingRuntimeTailEvidence = $null

try {
    while ($true) {
        try {
            if (-not (Test-Path -LiteralPath $script:StartFilePath)) {
                $missingStartFile = Convert-ToRepoRelativePath -Path $script:StartFilePath
                Write-GuardState -Values @{
                    status = 'stopped'
                    event = 'start-file-missing'
                    stop_reason = 'start-file-missing'
                    missing_start_file = $missingStartFile
                }
                Write-GuardLog ("complete reason=start_file_missing start_file={0}" -f $missingStartFile)
                break
            }

            $settings = Read-KeyValueFile -Path $script:StartFilePath

            $sessionStatusRaw = 'NOT_RUN'
            if ($settings.Contains('SESSION_FINAL_STATUS')) {
                $sessionStatusRaw = [string]$settings.SESSION_FINAL_STATUS
            }

            $aStatusRaw = 'NOT_RUN'
            if ($settings.Contains('A_FINAL_STATUS')) {
                $aStatusRaw = [string]$settings.A_FINAL_STATUS
            }

            $bStatusRaw = 'NOT_RUN'
            if ($settings.Contains('B_FINAL_STATUS')) {
                $bStatusRaw = [string]$settings.B_FINAL_STATUS
            }

            $sessionStatus = Get-StatusValue -Value $sessionStatusRaw
            $aStatus = Get-StatusValue -Value $aStatusRaw
            $bStatus = Get-StatusValue -Value $bStatusRaw

            $autoRecoverB = $true
            if ($settings.Contains('LOCAL_GUARD_AUTO_RECOVER_B')) {
                $autoRecoverB = Convert-ToBooleanSetting -Value ([string]$settings.LOCAL_GUARD_AUTO_RECOVER_B) -Default $true
            }

            if ($settings.Contains('LOCAL_GUARD_MAX_B_RECOVERY_ATTEMPTS')) {
                $parsedAttempts = 0
                if ([int]::TryParse(([string]$settings.LOCAL_GUARD_MAX_B_RECOVERY_ATTEMPTS), [ref]$parsedAttempts)) {
                    if ($parsedAttempts -ge 0 -and $parsedAttempts -le 10) {
                        $MaxBRecoveryAttempts = $parsedAttempts
                    }
                }
            }

            if ($settings.Contains('LOCAL_GUARD_RECOVERY_COOLDOWN_MINUTES')) {
                $parsedCooldown = 0
                if ([int]::TryParse(([string]$settings.LOCAL_GUARD_RECOVERY_COOLDOWN_MINUTES), [ref]$parsedCooldown)) {
                    if ($parsedCooldown -ge 1 -and $parsedCooldown -le 180) {
                        $RecoveryCooldownMinutes = $parsedCooldown
                    }
                }
            }

            if ($settings.Contains('LOCAL_GUARD_POLL_SEC')) {
                $parsedPoll = 0
                if ([int]::TryParse(([string]$settings.LOCAL_GUARD_POLL_SEC), [ref]$parsedPoll)) {
                    if ($parsedPoll -ge 15 -and $parsedPoll -le 300) {
                        $PollSec = $parsedPoll
                    }
                }
            }

            if ($settings.Contains('LOCAL_GUARD_STOP_ON_BUDGET_EXHAUSTED')) {
                $StopOnBudgetExhausted = Convert-ToBooleanSetting -Value ([string]$settings.LOCAL_GUARD_STOP_ON_BUDGET_EXHAUSTED) -Default $true
            }

            $bRunningNoProcessGraceSec = [Math]::Max(([int]$PollSec * 3), 180)
            if ($settings.Contains('LOCAL_GUARD_B_RUNNING_NO_PROCESS_GRACE_SEC')) {
                $parsedGrace = 0
                if ([int]::TryParse(([string]$settings.LOCAL_GUARD_B_RUNNING_NO_PROCESS_GRACE_SEC), [ref]$parsedGrace)) {
                    if ($parsedGrace -ge 30 -and $parsedGrace -le 1800) {
                        $bRunningNoProcessGraceSec = [int]$parsedGrace
                    }
                }
            }

            $bLaunchPid = 0
            if ($settings.Contains('B_LAUNCH_PID')) {
                $parsedLaunchPid = Convert-ToNullablePositiveInt -Value ([string]$settings.B_LAUNCH_PID)
                if ($null -ne $parsedLaunchPid) {
                    $bLaunchPid = [int]$parsedLaunchPid
                }
            }

            $running = ($aStatus -eq 'RUNNING' -or $bStatus -eq 'RUNNING')
            $notes = if ($settings.Contains('SESSION_FINAL_NOTES')) { [string]$settings.SESSION_FINAL_NOTES } else { '' }
            $runDirAnchor = Get-LatestAnchorValueFromNotes -Notes $notes -Key 'run_dir'

            $bProcessSnapshot = $null
            if ($bStatus -eq 'RUNNING') {
                $bProcessSnapshot = Get-BStageProcessSnapshot -ExpectedProcessId $bLaunchPid
                if ([bool]$bProcessSnapshot.AnchorUpdateRequired) {
                    $newBLaunchPid = [int]$bProcessSnapshot.ResolvedProcessId
                    Set-KeyValueFileValues -Path $script:StartFilePath -Values @{
                        B_LAUNCH_PID = [string]$newBLaunchPid
                    }
                    Write-GuardLog ("b_anchor_refresh old_pid={0} new_pid={1} source={2} candidate_count={3}" -f $bLaunchPid, $newBLaunchPid, $bProcessSnapshot.ResolvedSource, $bProcessSnapshot.CandidateCount)
                    $bLaunchPid = $newBLaunchPid
                }

                if ([bool]$bProcessSnapshot.HasAliveProcess) {
                    $bRunningNoProcessSince = $null
                    $lastMissingBProcessReportAt = $null
                    $lastBMissingExitReasonEvidence = $null
                    $lastBMissingRuntimeTailEvidence = $null
                }
                else {
                    $now = Get-Date
                    if ($null -eq $bRunningNoProcessSince) {
                        $bRunningNoProcessSince = $now
                        $lastMissingBProcessReportAt = $now
                        Write-GuardLog ("b_process_missing_start expected_pid={0} candidate_count={1} grace_sec={2}" -f $bLaunchPid, $bProcessSnapshot.CandidateCount, $bRunningNoProcessGraceSec)

                        $lastBMissingExitReasonEvidence = Get-BStageExitReasonEvidence -ExpectedProcessId $bLaunchPid
                        $reasonMatched = $false
                        if ($null -ne $lastBMissingExitReasonEvidence) {
                            $reasonMatched = (
                                [bool]$lastBMissingExitReasonEvidence.Available -and
                                ([string]$lastBMissingExitReasonEvidence.Stage -eq 'B') -and
                                [bool]$lastBMissingExitReasonEvidence.StartFileMatch -and
                                [bool]$lastBMissingExitReasonEvidence.ProcessIdMatch
                            )

                            if ($reasonMatched) {
                                Write-GuardLog ("b_process_missing_reason expected_pid={0} artifact_pid={1} result={2} exit_code={3} category={4} detail={5} artifact={6}" -f
                                    $bLaunchPid,
                                    [int]$lastBMissingExitReasonEvidence.ProcessId,
                                    [string]$lastBMissingExitReasonEvidence.Result,
                                    [int]$lastBMissingExitReasonEvidence.ExitCode,
                                    [string]$lastBMissingExitReasonEvidence.FailCategory,
                                    [string]$lastBMissingExitReasonEvidence.FailReason,
                                    [string]$lastBMissingExitReasonEvidence.ArtifactPath)
                            }
                            elseif ([bool]$lastBMissingExitReasonEvidence.Available) {
                                Write-GuardLog ("b_process_missing_reason_unmatched expected_pid={0} artifact_pid={1} stage={2} start_file_match={3} pid_match={4} artifact={5}" -f
                                    $bLaunchPid,
                                    [int]$lastBMissingExitReasonEvidence.ProcessId,
                                    [string]$lastBMissingExitReasonEvidence.Stage,
                                    [bool]$lastBMissingExitReasonEvidence.StartFileMatch,
                                    [bool]$lastBMissingExitReasonEvidence.ProcessIdMatch,
                                    [string]$lastBMissingExitReasonEvidence.ArtifactPath)
                            }
                            elseif (-not [string]::IsNullOrWhiteSpace([string]$lastBMissingExitReasonEvidence.ParseError)) {
                                Write-GuardLog ("b_process_missing_reason_parse_error expected_pid={0} artifact={1} detail={2}" -f
                                    $bLaunchPid,
                                    [string]$lastBMissingExitReasonEvidence.ArtifactPath,
                                    [string]$lastBMissingExitReasonEvidence.ParseError)
                            }
                            else {
                                Write-GuardLog ("b_process_missing_reason_unavailable expected_pid={0} artifact={1}" -f
                                    $bLaunchPid,
                                    [string]$lastBMissingExitReasonEvidence.ArtifactPath)
                            }
                        }

                        if (-not $reasonMatched) {
                            $artifactRuntimeLogPath = ''
                            if ($null -ne $lastBMissingExitReasonEvidence) {
                                $artifactRuntimeLogPath = [string]$lastBMissingExitReasonEvidence.RuntimeLogPath
                            }

                            $runtimeLogHint = Get-BRuntimeLogHint -Settings $settings -ArtifactRuntimeLogPath $artifactRuntimeLogPath
                            $lastBMissingRuntimeTailEvidence = Get-BRuntimeTailEvidence -RuntimeLogPath $runtimeLogHint -PrimaryTail 10 -ExpandedTail 30 -MaxTail 80 -MinimumUsefulLines 6
                            if ($null -ne $lastBMissingRuntimeTailEvidence -and [bool]$lastBMissingRuntimeTailEvidence.Available) {
                                $tailLines = @($lastBMissingRuntimeTailEvidence.Lines)
                                $tailPreview = Convert-ToBoundedSingleLineText -Text ($tailLines -join ' || ') -MaxChars 240
                                Write-GuardLog ("b_process_missing_tail expected_pid={0} log={1} used_tail={2} escalated={3} lines={4} detail_preview={5}" -f
                                    $bLaunchPid,
                                    [string]$lastBMissingRuntimeTailEvidence.RuntimeLogPath,
                                    [int]$lastBMissingRuntimeTailEvidence.UsedTail,
                                    [bool]$lastBMissingRuntimeTailEvidence.Escalated,
                                    $tailLines.Count,
                                    $tailPreview)

                                $tailBlockLines = New-Object 'System.Collections.Generic.List[string]'
                                [void]$tailBlockLines.Add(("expected_pid={0} log={1} used_tail={2} escalated={3} lines={4}" -f
                                        $bLaunchPid,
                                        [string]$lastBMissingRuntimeTailEvidence.RuntimeLogPath,
                                        [int]$lastBMissingRuntimeTailEvidence.UsedTail,
                                        [bool]$lastBMissingRuntimeTailEvidence.Escalated,
                                        $tailLines.Count))
                                foreach ($tailLine in $tailLines) {
                                    [void]$tailBlockLines.Add(("line={0}" -f [string]$tailLine))
                                }
                                Write-GuardPastedBlock -Tag 'b_process_missing_tail_block' -Lines @($tailBlockLines)
                            }
                            elseif ($null -ne $lastBMissingRuntimeTailEvidence -and -not [string]::IsNullOrWhiteSpace([string]$lastBMissingRuntimeTailEvidence.Error)) {
                                Write-GuardLog ("b_process_missing_tail_error expected_pid={0} log={1} detail={2}" -f
                                    $bLaunchPid,
                                    [string]$runtimeLogHint,
                                    [string]$lastBMissingRuntimeTailEvidence.Error)
                            }
                            else {
                                Write-GuardLog ("b_process_missing_tail_unavailable expected_pid={0} log={1}" -f
                                    $bLaunchPid,
                                    [string]$runtimeLogHint)
                            }
                        }
                        else {
                            $lastBMissingRuntimeTailEvidence = $null
                        }
                    }
                    elseif ($null -eq $lastMissingBProcessReportAt -or (($now - $lastMissingBProcessReportAt).TotalMinutes -ge 5)) {
                        $missingSecReport = [Math]::Max(0, [int][Math]::Round(($now - $bRunningNoProcessSince).TotalSeconds))
                        Write-GuardLog ("b_process_missing_wait expected_pid={0} elapsed_sec={1} grace_sec={2}" -f $bLaunchPid, $missingSecReport, $bRunningNoProcessGraceSec)
                        $lastMissingBProcessReportAt = $now
                    }

                    $missingSec = [Math]::Max(0, [int][Math]::Round(((Get-Date) - $bRunningNoProcessSince).TotalSeconds))
                    if ($missingSec -ge $bRunningNoProcessGraceSec) {
                        $sessionStatusToWrite = if ($aStatus -eq 'RUNNING') { $sessionStatus } else { 'FAIL' }
                        $failureNote = "guard_detected b_process_missing expected_pid={0} elapsed_sec={1} grace_sec={2}" -f $bLaunchPid, $missingSec, $bRunningNoProcessGraceSec

                        $reasonMatchedForNotes = (
                            $null -ne $lastBMissingExitReasonEvidence -and
                            [bool]$lastBMissingExitReasonEvidence.Available -and
                            ([string]$lastBMissingExitReasonEvidence.Stage -eq 'B') -and
                            [bool]$lastBMissingExitReasonEvidence.StartFileMatch -and
                            [bool]$lastBMissingExitReasonEvidence.ProcessIdMatch
                        )
                        if ($reasonMatchedForNotes) {
                            $failureNote = $failureNote + (" exit_category={0} exit_code={1} exit_reason={2}" -f
                                [string]$lastBMissingExitReasonEvidence.FailCategory,
                                [int]$lastBMissingExitReasonEvidence.ExitCode,
                                [string]$lastBMissingExitReasonEvidence.FailReason)
                        }
                        elseif ($null -ne $lastBMissingRuntimeTailEvidence -and [bool]$lastBMissingRuntimeTailEvidence.Available) {
                            $tailLinesForNote = @($lastBMissingRuntimeTailEvidence.Lines)
                            $tailExcerptForNote = Convert-ToBoundedSingleLineText -Text ($tailLinesForNote -join ' || ') -MaxChars 360
                            if (-not [string]::IsNullOrWhiteSpace($tailExcerptForNote)) {
                                $failureNote = $failureNote + (" tail_log={0} tail_lines={1} tail_used={2} tail_excerpt={3}" -f
                                    [string]$lastBMissingRuntimeTailEvidence.RuntimeLogPath,
                                    $tailLinesForNote.Count,
                                    [int]$lastBMissingRuntimeTailEvidence.UsedTail,
                                    $tailExcerptForNote)
                            }
                        }

                        $newNotes = Append-DelimitedNote -Existing $notes -Append $failureNote
                        Set-KeyValueFileValues -Path $script:StartFilePath -Values @{
                            B_FINAL_STATUS = 'FAIL'
                            SESSION_FINAL_STATUS = $sessionStatusToWrite
                            B_LAUNCH_PID = '0'
                            SESSION_FINAL_NOTES = $newNotes
                        }
                        Write-GuardLog ("b_process_missing_fail expected_pid={0} elapsed_sec={1} grace_sec={2} session_status={3}" -f $bLaunchPid, $missingSec, $bRunningNoProcessGraceSec, $sessionStatusToWrite)

                        $settings = Read-KeyValueFile -Path $script:StartFilePath
                        $sessionStatusRawAfter = 'NOT_RUN'
                        if ($settings.Contains('SESSION_FINAL_STATUS')) {
                            $sessionStatusRawAfter = [string]$settings.SESSION_FINAL_STATUS
                        }
                        $aStatusRawAfter = 'NOT_RUN'
                        if ($settings.Contains('A_FINAL_STATUS')) {
                            $aStatusRawAfter = [string]$settings.A_FINAL_STATUS
                        }
                        $bStatusRawAfter = 'NOT_RUN'
                        if ($settings.Contains('B_FINAL_STATUS')) {
                            $bStatusRawAfter = [string]$settings.B_FINAL_STATUS
                        }
                        $sessionStatus = Get-StatusValue -Value $sessionStatusRawAfter
                        $aStatus = Get-StatusValue -Value $aStatusRawAfter
                        $bStatus = Get-StatusValue -Value $bStatusRawAfter
                        $running = ($aStatus -eq 'RUNNING' -or $bStatus -eq 'RUNNING')
                        $notes = if ($settings.Contains('SESSION_FINAL_NOTES')) { [string]$settings.SESSION_FINAL_NOTES } else { '' }
                        $runDirAnchor = Get-LatestAnchorValueFromNotes -Notes $notes -Key 'run_dir'
                        $bLaunchPid = 0
                        $bRunningNoProcessSince = $null
                        $lastMissingBProcessReportAt = $null
                        $lastBMissingExitReasonEvidence = $null
                        $lastBMissingRuntimeTailEvidence = $null
                    }
                }
            }
            else {
                $bRunningNoProcessSince = $null
                $lastMissingBProcessReportAt = $null
                $lastBMissingExitReasonEvidence = $null
                $lastBMissingRuntimeTailEvidence = $null
            }

            $running = ($aStatus -eq 'RUNNING' -or $bStatus -eq 'RUNNING')

            $guardLoopStatus = 'idle'
            if ($running) {
                $guardLoopStatus = 'running'
            }

            $lastRecoveryAtText = ''
            if ($lastRecoveryAt -ne [datetime]::MinValue) {
                $lastRecoveryAtText = $lastRecoveryAt.ToString('yyyy-MM-dd HH:mm:ss')
            }

            Write-GuardState -Values @{
                status = $guardLoopStatus
                session_final_status = $sessionStatus
                a_final_status = $aStatus
                b_final_status = $bStatus
                run_dir = $runDirAnchor
                b_launch_pid = [int]$bLaunchPid
                b_stage_process_alive = if ($null -ne $bProcessSnapshot) { [bool]$bProcessSnapshot.HasAliveProcess } else { $null }
                b_stage_process_candidates = if ($null -ne $bProcessSnapshot) { [int]$bProcessSnapshot.CandidateCount } else { 0 }
                b_running_no_process_grace_sec = [int]$bRunningNoProcessGraceSec
                poll_sec = [int]$PollSec
                max_b_recovery_attempts = [int]$MaxBRecoveryAttempts
                recovery_cooldown_minutes = [int]$RecoveryCooldownMinutes
                stop_on_budget_exhausted = [bool]$StopOnBudgetExhausted
                auto_recover_b = [bool]$autoRecoverB
                b_recovery_attempts = [int]$bRecoveryAttempts
                last_recovery_at = $lastRecoveryAtText
            }

            if ($sessionStatus -eq 'PASS' -and -not $running) {
                Write-GuardLog ("complete session_status=PASS a={0} b={1}" -f $aStatus, $bStatus)
                break
            }

            if (($sessionStatus -in @('FAIL', 'BLOCKED')) -and -not $running) {
                $statusSignature = "{0}|{1}|{2}|{3}" -f $sessionStatus, $aStatus, $bStatus, $runDirAnchor
                if ($statusSignature -ne $lastIncidentSignature) {
                    $incidentDir = Capture-IncidentPackage -Settings $settings -SessionStatus $sessionStatus -AStatus $aStatus -BStatus $bStatus
                    $incidentRel = Convert-ToRepoRelativePath -Path $incidentDir
                    $lastIncidentSignature = $statusSignature
                    Write-GuardLog ("incident status={0} a={1} b={2} evidence={3}" -f $sessionStatus, $aStatus, $bStatus, $incidentRel)

                    $newNotes = Append-DelimitedNote -Existing $notes -Append ("guard_incident status={0} a={1} b={2} evidence={3}" -f $sessionStatus, $aStatus, $bStatus, $incidentRel)
                    Set-KeyValueFileValues -Path $script:StartFilePath -Values @{
                        SESSION_FINAL_NOTES = $newNotes
                    }
                }

                $canRecoverB = ($aStatus -eq 'PASS' -and $bStatus -in @('FAIL', 'BLOCKED'))
                if ($autoRecoverB -and $canRecoverB) {
                    if ($bRecoveryAttempts -ge $MaxBRecoveryAttempts) {
                        $budgetSignature = "{0}|{1}|{2}|{3}" -f $sessionStatus, $aStatus, $bStatus, $runDirAnchor
                        if ($StopOnBudgetExhausted) {
                            $activityWindowMinutes = [Math]::Max(6, [int][Math]::Ceiling(([double]$PollSec * 4.0) / 60.0))
                            $livenessEvidence = Get-BudgetExhaustedLivenessEvidence -Settings $settings -WindowMinutes $activityWindowMinutes -FallbackProcessId $bLaunchPid
                            if ([bool]$livenessEvidence.Active) {
                                $deferSignature = ($budgetSignature + '|active')
                                if ($deferSignature -ne $lastBudgetExhaustedSignature) {
                                    Write-GuardLog ("recovery_skip reason=budget_exhausted_defer_active attempts={0} max={1} detail={2}" -f $bRecoveryAttempts, $MaxBRecoveryAttempts, [string]$livenessEvidence.Detail)
                                    $lastBudgetExhaustedSignature = $deferSignature
                                }

                                Write-GuardState -Values @{
                                    status = 'running'
                                    event = 'budget-exhausted-defer-active'
                                    stop_reason = ''
                                    b_recovery_attempts = [int]$bRecoveryAttempts
                                    b_liveness_detail = [string]$livenessEvidence.Detail
                                }
                                continue
                            }

                            if ($budgetSignature -ne $lastBudgetExhaustedSignature) {
                                Write-GuardLog ("recovery_skip reason=budget_exhausted attempts={0} max={1}" -f $bRecoveryAttempts, $MaxBRecoveryAttempts)
                                $lastBudgetExhaustedSignature = $budgetSignature
                            }

                            Write-GuardState -Values @{
                                status = 'stopped'
                                event = 'budget-exhausted'
                                stop_reason = 'budget-exhausted'
                                b_recovery_attempts = [int]$bRecoveryAttempts
                            }
                            Write-GuardLog ("complete reason=budget_exhausted attempts={0} max={1} stop_on_budget_exhausted={2}" -f $bRecoveryAttempts, $MaxBRecoveryAttempts, $StopOnBudgetExhausted)
                            break
                        }

                        if ($budgetSignature -ne $lastBudgetExhaustedSignature) {
                            Write-GuardLog ("recovery_skip reason=budget_exhausted attempts={0} max={1}" -f $bRecoveryAttempts, $MaxBRecoveryAttempts)
                            $lastBudgetExhaustedSignature = $budgetSignature
                        }
                    }
                    elseif ($lastRecoveryAt -ne [datetime]::MinValue -and ((Get-Date) -lt $lastRecoveryAt.AddMinutes($RecoveryCooldownMinutes))) {
                        $lastBudgetExhaustedSignature = ''
                        $nextAt = $lastRecoveryAt.AddMinutes($RecoveryCooldownMinutes).ToString('yyyy-MM-dd HH:mm:ss')
                        Write-GuardLog ("recovery_skip reason=cooldown next_at={0}" -f $nextAt)
                    }
                    else {
                        $lastBudgetExhaustedSignature = ''
                        $attempt = $bRecoveryAttempts + 1
                        $restartResult = Invoke-BStageRestart -Attempt $attempt
                        if ($restartResult.Succeeded) {
                            $bRecoveryAttempts = $attempt
                            $lastRecoveryAt = Get-Date
                            $lastIncidentSignature = ''
                            $lastBudgetExhaustedSignature = ''
                            Write-GuardState -Values @{
                                status = 'running'
                                last_action = 'restart-triggered'
                                b_recovery_attempts = [int]$bRecoveryAttempts
                                last_recovery_at = $lastRecoveryAt.ToString('yyyy-MM-dd HH:mm:ss')
                            }
                            $restartNote = "guard_recovery action=restart-b attempt={0} at={1}" -f $attempt, $lastRecoveryAt.ToString('yyyy-MM-dd HH:mm:ss')
                            $newNotes = Append-DelimitedNote -Existing ([string](Read-KeyValueFile -Path $script:StartFilePath).SESSION_FINAL_NOTES) -Append $restartNote
                            Set-KeyValueFileValues -Path $script:StartFilePath -Values @{ SESSION_FINAL_NOTES = $newNotes }
                            Write-GuardLog ("recovery_triggered stage=B attempt={0}" -f $attempt)
                            Start-Sleep -Seconds 5
                            continue
                        }

                        Write-GuardLog ("recovery_failed stage=B attempt={0} exit_code={1}" -f $attempt, $restartResult.ExitCode)
                    }
                }
                else {
                    $lastBudgetExhaustedSignature = ''
                    Write-GuardLog ("manual_action_required status={0} a={1} b={2} auto_recover_b={3}" -f $sessionStatus, $aStatus, $bStatus, $autoRecoverB)
                }
            }
            else {
                $lastBudgetExhaustedSignature = ''
                $now = Get-Date
                if ($lastHeartbeatAt -eq [datetime]::MinValue -or (($now - $lastHeartbeatAt).TotalMinutes -ge 5)) {
                    Write-GuardLog ("heartbeat session={0} a={1} b={2} running={3} run_dir={4}" -f $sessionStatus, $aStatus, $bStatus, $running, $runDirAnchor)
                    $lastHeartbeatAt = $now
                }
            }
        }
        catch {
            Write-GuardLog ("loop_error detail={0}" -f $_.Exception.Message.Replace("`r", ' ').Replace("`n", ' '))
        }

        Start-Sleep -Seconds $PollSec
    }
}
finally {
    Write-GuardState -Values @{
        status = 'stopped'
        event = 'shutdown'
    }
    Write-GuardLog ("shutdown_pid pid={0}" -f $PID)
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