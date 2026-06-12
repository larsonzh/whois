param(
    [Parameter(Mandatory = $true)][string]$StartFile,
    [switch]$AutoHeal,
    [switch]$EscalateMonitorChainDegraded,
    [ValidateRange(1, 20)][int]$EscalateMonitorChainDegradedThreshold = 3,
    [switch]$AsJson
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'unattended_exit_result.ps1')
$script:UnhandledExitTag = 'CHECK-UNATTENDED-MAIN-PROCESS-HEALTH'

trap {
    Write-UnattendedUnhandledResult -Tag $script:UnhandledExitTag -Record $_
    exit 1
}

function Convert-ToSingleLineText {
    param([AllowEmptyString()][string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return ''
    }

    $singleLine = (($Text -split "`r?`n") -join ' ')
    return ([regex]::Replace($singleLine, '\s+', ' ')).Trim()
}

function Resolve-RepoPath {
    param(
        [string]$RepoRoot,
        [string]$Path,
        [bool]$MustExist = $true
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw 'Path must not be empty.'
    }

    $fullPath = if ([System.IO.Path]::IsPathRooted($Path)) {
        [System.IO.Path]::GetFullPath($Path)
    }
    else {
        [System.IO.Path]::GetFullPath((Join-Path $RepoRoot $Path))
    }

    if ($MustExist -and -not (Test-Path -LiteralPath $fullPath)) {
        throw ('Path not found: {0}' -f $fullPath)
    }

    return $fullPath
}

function Convert-ToRepoRelativePath {
    param(
        [string]$RepoRoot,
        [AllowEmptyString()][string]$Path
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return ''
    }

    try {
        $fullPath = [System.IO.Path]::GetFullPath($Path)
        $repoRootFull = [System.IO.Path]::GetFullPath($RepoRoot)
        if ($fullPath.StartsWith($repoRootFull, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $fullPath.Substring($repoRootFull.Length).TrimStart('\\').Replace('\\', '/')
        }

        return $fullPath.Replace('\\', '/')
    }
    catch {
        return $Path.Replace('\\', '/')
    }
}

function Get-StatusValue {
    param([AllowEmptyString()][string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return 'NOT_RUN'
    }

    return $Value.Trim().ToUpperInvariant()
}

function Convert-ToBooleanValue {
    param(
        [AllowNull()][object]$Value,
        [bool]$Default = $false
    )

    if ($null -eq $Value) {
        return $Default
    }

    if ($Value -is [bool]) {
        return [bool]$Value
    }

    $raw = Convert-ToSingleLineText -Text ([string]$Value)
    if ([string]::IsNullOrWhiteSpace($raw)) {
        return $Default
    }

    return $raw.Trim().ToLowerInvariant() -in @('1', 'true', 'yes', 'on')
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

function Read-KeyValueFile {
    param([string]$Path)

    $map = [ordered]@{}
    $lineMap = @{}
    $lineNo = 0
    foreach ($line in @(Get-Content -LiteralPath $Path -Encoding utf8 -ErrorAction Stop)) {
        $lineNo++
        if ($line -match '^([^=]+)=(.*)$') {
            $key = $Matches[1].Trim()
            if ($map.Contains($key)) {
                $firstLine = [int]$lineMap[$key]
                throw ("Duplicate key '{0}' detected in {1} at line {2} and line {3}." -f $key, $Path, $firstLine, $lineNo)
            }

            $lineMap[$key] = $lineNo
            $map[$key] = $Matches[2]
        }
    }

    return $map
}

function Get-StartFileMutexName {
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

function Set-KeyValueFileValue {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [string]$Path,
        [hashtable]$Values
    )

    $mutex = New-Object System.Threading.Mutex($false, (Get-StartFileMutexName -StartFilePath $Path))
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

        if ($PSCmdlet.ShouldProcess($Path, 'Update start-file values')) {
            $tempPath = "$Path.tmp.$PID.$([guid]::NewGuid().ToString('N'))"
            $normalizedLines = @($buffer | ForEach-Object { [string]$_ })
            $text = [string]::Join("`n", $normalizedLines)
            if ($normalizedLines.Count -gt 0) {
                $text += "`n"
            }
            [System.IO.File]::WriteAllText($tempPath, $text, [System.Text.UTF8Encoding]::new($true))
            Move-Item -LiteralPath $tempPath -Destination $Path -Force
            $tempPath = ''
        }
    }
    finally {
        if (-not [string]::IsNullOrWhiteSpace($tempPath) -and (Test-Path -LiteralPath $tempPath)) {
            Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue
        }
        if ($locked) {
            try { $mutex.ReleaseMutex() } catch { Write-Verbose (("ReleaseMutex failed: {0}") -f $_.Exception.Message) }
        }
        $mutex.Dispose()
    }
}

function Add-DelimitedNote {
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

function Write-JsonFileSafely {
    param(
        [string]$Path,
        [AllowNull()][object]$Value
    )

    try {
        $parent = Split-Path -Parent $Path
        if (-not [string]::IsNullOrWhiteSpace($parent) -and -not (Test-Path -LiteralPath $parent)) {
            New-Item -ItemType Directory -Path $parent -Force | Out-Null
        }

        $json = $Value | ConvertTo-Json -Depth 12
        [System.IO.File]::WriteAllText($Path, $json + "`n", [System.Text.UTF8Encoding]::new($true))
        return $true
    }
    catch {
        return $false
    }
}

function Write-JsonLineWithRetry {
    param(
        [string]$Path,
        [string]$Line
    )

    if ([string]::IsNullOrWhiteSpace($Path) -or [string]::IsNullOrWhiteSpace($Line)) {
        return $false
    }

    try {
        $parent = Split-Path -Parent $Path
        if (-not [string]::IsNullOrWhiteSpace($parent) -and -not (Test-Path -LiteralPath $parent)) {
            New-Item -ItemType Directory -Path $parent -Force | Out-Null
        }

        Add-Content -LiteralPath $Path -Value $Line -Encoding utf8 -ErrorAction Stop
        return $true
    }
    catch {
        return $false
    }
}

function Get-StartFileToken {
    param([string]$StartFilePath)

    try {
        $fullPath = [System.IO.Path]::GetFullPath($StartFilePath).ToLowerInvariant()
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($fullPath)
        $sha1 = [System.Security.Cryptography.SHA1]::Create()
        try {
            $hashBytes = $sha1.ComputeHash($bytes)
        }
        finally {
            $sha1.Dispose()
        }

        $hash = [System.BitConverter]::ToString($hashBytes).Replace('-', '').ToLowerInvariant()
        return $hash.Substring(0, 16)
    }
    catch {
        return 'default'
    }
}

function Get-AgentTicketQueuePath {
    param(
        [System.Collections.IDictionary]$Settings,
        [string]$RepoRoot
    )

    $rawPath = ''
    if ($null -ne $Settings -and $Settings.Contains('LOCAL_GUARD_AGENT_QUEUE_PATH')) {
        $rawPath = [string]$Settings.LOCAL_GUARD_AGENT_QUEUE_PATH
    }

    if ([string]::IsNullOrWhiteSpace($rawPath)) {
        $rawPath = 'out\artifacts\ab_agent_queue\agent_tickets.jsonl'
    }

    return (Resolve-RepoPath -RepoRoot $RepoRoot -Path $rawPath -MustExist $false)
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

    try {
        if ([System.IO.Path]::IsPathRooted($rawPath)) {
            return [System.IO.Path]::GetFullPath($rawPath).ToLowerInvariant()
        }

        return [System.IO.Path]::GetFullPath((Join-Path $RepoRoot $rawPath)).ToLowerInvariant()
    }
    catch {
        return ''
    }
}

function Get-RunningProcessIdsByScriptLeaf {
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
                if (-not $line.Contains($ScriptLeaf.ToLowerInvariant())) {
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

function Get-BStageProcessCandidate {
    param(
        [string]$StartFileLeaf
    )

    $candidates = @(
        Get-CimInstance Win32_Process |
            Where-Object {
                $line = [string]$_.CommandLine
                if ([string]::IsNullOrWhiteSpace($line)) {
                    return $false
                }

                $lineLower = $line.ToLowerInvariant()
                if (-not [string]::IsNullOrWhiteSpace($StartFileLeaf) -and -not $lineLower.Contains($StartFileLeaf.ToLowerInvariant())) {
                    return $false
                }

                if ($lineLower.Contains('unattended_ab_supervisor.ps1') -or
                    $lineLower.Contains('unattended_ab_companion.ps1') -or
                    $lineLower.Contains('unattended_ab_session_guard.ps1') -or
                    $lineLower.Contains('unattended_ab_takeover_trigger.ps1') -or
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

function Get-BStageExitReasonEvidence {
    param(
        [string]$RepoRoot,
        [string]$StartFilePath,
        [int]$ExpectedProcessId
    )

    $artifactPath = Join-Path $RepoRoot 'out\artifacts\ab_stage_exit\latest_b_exit.json'
    $result = [ordered]@{
        Available = $false
        ArtifactPath = $artifactPath
        Stage = ''
        ProcessId = 0
        ExitCode = 0
        Result = ''
        FailCategory = ''
        FailReason = ''
        StartFileMatch = $false
        ProcessIdMatch = $false
    }

    $payload = Read-JsonFileSafely -Path $artifactPath
    if ($null -eq $payload) {
        return [pscustomobject]$result
    }

    $result.Available = $true
    $result.Stage = (Convert-ToSingleLineText -Text ([string]$payload.stage)).ToUpperInvariant()
    $procValue = Convert-ToNullablePositiveInt -Value ([string]$payload.process_id)
    if ($null -ne $procValue) {
        $result.ProcessId = [int]$procValue
    }

    $exitCode = 0
    if ([int]::TryParse(([string]$payload.exit_code), [ref]$exitCode)) {
        $result.ExitCode = [int]$exitCode
    }

    $result.Result = (Convert-ToSingleLineText -Text ([string]$payload.result)).ToLowerInvariant()
    $result.FailCategory = Convert-ToSingleLineText -Text ([string]$payload.fail_category)
    $result.FailReason = Convert-ToSingleLineText -Text ([string]$payload.fail_reason)

    $artifactStartFile = Convert-ToSingleLineText -Text ([string]$payload.start_file_path)
    if ([string]::IsNullOrWhiteSpace($artifactStartFile)) {
        $result.StartFileMatch = $true
    }
    else {
        try {
            $expectedStart = [System.IO.Path]::GetFullPath($StartFilePath)
            $artifactStart = [System.IO.Path]::GetFullPath($artifactStartFile)
            $result.StartFileMatch = $artifactStart.Equals($expectedStart, [System.StringComparison]::OrdinalIgnoreCase)
        }
        catch {
            $result.StartFileMatch = $false
        }
    }

    if ($ExpectedProcessId -gt 0) {
        $result.ProcessIdMatch = ($ExpectedProcessId -eq [int]$result.ProcessId)
    }
    else {
        # When there is no active expected B PID, a historical exit artifact must not be treated as matched evidence.
        $result.ProcessIdMatch = $false
    }

    return [pscustomobject]$result
}

function Invoke-Launcher {
    param(
        [string]$RepoRoot,
        [string]$ScriptPath,
        [string[]]$LauncherParams
    )

    $powershellPath = Join-Path $PSHOME 'powershell.exe'
    if (-not (Test-Path -LiteralPath $powershellPath)) {
        $powershellPath = 'powershell.exe'
    }

    if (-not [System.IO.Path]::IsPathRooted($ScriptPath)) {
        $ScriptPath = Join-Path $RepoRoot $ScriptPath
    }

    $launcherInvocation = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $ScriptPath) + @($LauncherParams)
    $output = @(& $powershellPath @launcherInvocation 2>&1 | ForEach-Object { [string]$_ })
    $exitCode = if ($null -eq $LASTEXITCODE) { 0 } else { [int]$LASTEXITCODE }

    return [pscustomobject]@{
        Succeeded = ($exitCode -eq 0)
        ExitCode = $exitCode
        Output = Convert-ToSingleLineText -Text (($output | Out-String).Trim())
    }
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$startFilePath = Resolve-RepoPath -RepoRoot $repoRoot -Path $StartFile -MustExist $true
$startFileRel = Convert-ToRepoRelativePath -RepoRoot $repoRoot -Path $startFilePath
$startFileIdentity = [System.IO.Path]::GetFullPath($startFilePath).ToLowerInvariant()
$startFileLeaf = [System.IO.Path]::GetFileName($startFilePath).ToLowerInvariant()

$settings = Read-KeyValueFile -Path $startFilePath

$policyWorkMode = ''
if ($settings.Contains('AI_CHAT_POLICY_WORK_MODE')) {
    $policyWorkMode = (Convert-ToSingleLineText -Text ([string]$settings.AI_CHAT_POLICY_WORK_MODE)).ToLowerInvariant()
}
$eventOnlyMode = ($policyWorkMode -eq 'event-only')

$sessionStatus = if ($settings.Contains('SESSION_FINAL_STATUS')) { Get-StatusValue -Value ([string]$settings.SESSION_FINAL_STATUS) } else { 'NOT_RUN' }
$aStatus = if ($settings.Contains('A_FINAL_STATUS')) { Get-StatusValue -Value ([string]$settings.A_FINAL_STATUS) } else { 'NOT_RUN' }
$bStatus = if ($settings.Contains('B_FINAL_STATUS')) { Get-StatusValue -Value ([string]$settings.B_FINAL_STATUS) } else { 'NOT_RUN' }

$aLaunchProcessId = if ($settings.Contains('A_LAUNCH_PID')) { Convert-ToNullablePositiveInt -Value ([string]$settings.A_LAUNCH_PID) } else { $null }
$bLaunchProcessId = if ($settings.Contains('B_LAUNCH_PID')) { Convert-ToNullablePositiveInt -Value ([string]$settings.B_LAUNCH_PID) } else { $null }

$aAlive = if ($null -ne $aLaunchProcessId) { Test-ProcessAlive -ProcessId ([int]$aLaunchProcessId) } else { $false }
$bExpectedAlive = if ($null -ne $bLaunchProcessId) { Test-ProcessAlive -ProcessId ([int]$bLaunchProcessId) } else { $false }
$bCandidates = @()
if ($bStatus -eq 'RUNNING' -and -not $bExpectedAlive) {
    $bCandidates = @(Get-BStageProcessCandidate -StartFileLeaf $startFileLeaf)
}
$bHasAliveProcess = $bExpectedAlive -or ($bCandidates.Count -gt 0)

$expectedProcessIdForExitEvidence = if ($null -eq $bLaunchProcessId) { 0 } else { [int]$bLaunchProcessId }
$bExitEvidence = Get-BStageExitReasonEvidence -RepoRoot $repoRoot -StartFilePath $startFilePath -ExpectedProcessId $expectedProcessIdForExitEvidence
$reasonMatched = (
    [bool]$bExitEvidence.Available -and
    ([string]$bExitEvidence.Stage -eq 'B') -and
    [bool]$bExitEvidence.StartFileMatch -and
    [bool]$bExitEvidence.ProcessIdMatch
)

$shellAliveAfterExit = ($bStatus -eq 'RUNNING' -and $bExpectedAlive -and $reasonMatched -and ([string]$bExitEvidence.Result -in @('pass', 'fail')))
if ($shellAliveAfterExit) {
    # The launch shell can stay alive under -NoExit even after B stage has already exited.
    $bExpectedAlive = $false
    $bHasAliveProcess = ($bCandidates.Count -gt 0)
}

$abnormalNoExit = ($bStatus -eq 'RUNNING' -and -not $bHasAliveProcess -and -not $reasonMatched)

$updatedStartFile = $false
if ($abnormalNoExit) {
    $sessionStatusToWrite = if ($aStatus -eq 'RUNNING') { $sessionStatus } else { 'FAIL' }
    $notes = if ($settings.Contains('SESSION_FINAL_NOTES')) { [string]$settings.SESSION_FINAL_NOTES } else { '' }
    $expectedProcessIdForMarker = if ($null -eq $bLaunchProcessId) { 0 } else { [int]$bLaunchProcessId }
    $marker = ('health_guard_detected b_process_missing_no_exit expected_pid={0} candidate_count={1} at={2}' -f $expectedProcessIdForMarker, $bCandidates.Count, (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))
    $newNotes = Add-DelimitedNote -Existing $notes -Append $marker

    Set-KeyValueFileValue -Path $startFilePath -Values @{
        B_FINAL_STATUS = 'FAIL'
        B_LAUNCH_PID = '0'
        SESSION_FINAL_STATUS = $sessionStatusToWrite
        SESSION_FINAL_NOTES = $newNotes
    }
    $updatedStartFile = $true

    $settings = Read-KeyValueFile -Path $startFilePath
    $sessionStatus = if ($settings.Contains('SESSION_FINAL_STATUS')) { Get-StatusValue -Value ([string]$settings.SESSION_FINAL_STATUS) } else { 'NOT_RUN' }
    $aStatus = if ($settings.Contains('A_FINAL_STATUS')) { Get-StatusValue -Value ([string]$settings.A_FINAL_STATUS) } else { 'NOT_RUN' }
    $bStatus = if ($settings.Contains('B_FINAL_STATUS')) { Get-StatusValue -Value ([string]$settings.B_FINAL_STATUS) } else { 'NOT_RUN' }
}

$monitorShouldRun = ($sessionStatus -eq 'RUNNING' -or $aStatus -eq 'RUNNING' -or $bStatus -eq 'RUNNING')
$monitorShouldRunOrAbnormal = ($monitorShouldRun -or $abnormalNoExit)
$autoStartTrigger = if ($settings.Contains('AUTO_START_TAKEOVER_TRIGGER')) {
    Convert-ToBooleanValue -Value ([string]$settings.AUTO_START_TAKEOVER_TRIGGER) -Default $false
}
elseif ($settings.Contains('EXTERNAL_TRIGGER_EXECUTE')) {
    Convert-ToBooleanValue -Value ([string]$settings.EXTERNAL_TRIGGER_EXECUTE) -Default $false
}
else {
    $false
}

$supervisorPids = @(Get-RunningProcessIdsByScriptLeaf -ScriptLeaf 'unattended_ab_supervisor.ps1' -StartFileIdentity $startFileIdentity -RepoRoot $repoRoot)
$companionPids = @(Get-RunningProcessIdsByScriptLeaf -ScriptLeaf 'unattended_ab_companion.ps1' -StartFileIdentity $startFileIdentity -RepoRoot $repoRoot)
$guardPids = @(Get-RunningProcessIdsByScriptLeaf -ScriptLeaf 'unattended_ab_session_guard.ps1' -StartFileIdentity $startFileIdentity -RepoRoot $repoRoot)
$triggerPids = @(Get-RunningProcessIdsByScriptLeaf -ScriptLeaf 'unattended_ab_takeover_trigger.ps1' -StartFileIdentity $startFileIdentity -RepoRoot $repoRoot)

$monitorChainMissingComponents = New-Object 'System.Collections.Generic.List[string]'
if ($monitorShouldRun -and $supervisorPids.Count -lt 1) {
    [void]$monitorChainMissingComponents.Add('supervisor')
}
if ($monitorShouldRun -and $companionPids.Count -lt 1) {
    [void]$monitorChainMissingComponents.Add('companion')
}
if ($monitorShouldRun -and $guardPids.Count -lt 1) {
    [void]$monitorChainMissingComponents.Add('guard')
}
if ($monitorShouldRun -and $autoStartTrigger -and $triggerPids.Count -lt 1) {
    [void]$monitorChainMissingComponents.Add('trigger')
}
$monitorChainDegraded = ($monitorChainMissingComponents.Count -gt 0)

$healActions = New-Object 'System.Collections.Generic.List[object]'
if ($AutoHeal.IsPresent -and $monitorShouldRunOrAbnormal) {
    $startFromStage = if ($bStatus -eq 'RUNNING') { 'B' } else { 'A' }

    if ($supervisorPids.Count -lt 1) {
        $supervisorLauncher = Join-Path $repoRoot 'tools/test/open_unattended_ab_supervisor_window.ps1'
        $result = Invoke-Launcher -RepoRoot $repoRoot -ScriptPath $supervisorLauncher -LauncherParams @('-StartFile', $startFileRel, '-StartFromStage', $startFromStage)
        $healActions.Add([pscustomobject]@{ name = 'restart-supervisor'; succeeded = [bool]$result.Succeeded; exit_code = [int]$result.ExitCode; output = [string]$result.Output }) | Out-Null
    }

    if ($companionPids.Count -lt 1) {
        $companionLauncher = Join-Path $repoRoot 'tools/test/open_unattended_ab_companion_window.ps1'
        $result = Invoke-Launcher -RepoRoot $repoRoot -ScriptPath $companionLauncher -LauncherParams @('-StartFile', $startFileRel)
        $healActions.Add([pscustomobject]@{ name = 'restart-companion'; succeeded = [bool]$result.Succeeded; exit_code = [int]$result.ExitCode; output = [string]$result.Output }) | Out-Null
    }

    if ($guardPids.Count -lt 1 -or $abnormalNoExit) {
        $guardLauncher = Join-Path $repoRoot 'tools/test/open_unattended_ab_session_guard_window.ps1'
        $result = Invoke-Launcher -RepoRoot $repoRoot -ScriptPath $guardLauncher -LauncherParams @('-StartFile', $startFileRel, '-NoRestartIfRunning')
        $healActions.Add([pscustomobject]@{ name = 'ensure-guard'; succeeded = [bool]$result.Succeeded; exit_code = [int]$result.ExitCode; output = [string]$result.Output }) | Out-Null
    }

    if ($autoStartTrigger -and $triggerPids.Count -lt 1) {
        $triggerLauncher = Join-Path $repoRoot 'tools/test/open_unattended_ab_takeover_trigger_window.ps1'
        $result = Invoke-Launcher -RepoRoot $repoRoot -ScriptPath $triggerLauncher -LauncherParams @('-StartFile', $startFileRel)
        $healActions.Add([pscustomobject]@{ name = 'restart-trigger'; succeeded = [bool]$result.Succeeded; exit_code = [int]$result.ExitCode; output = [string]$result.Output }) | Out-Null
    }
}

$allHealSucceeded = $true
if ($healActions.Count -gt 0) {
    foreach ($action in @($healActions.ToArray())) {
        if (-not [bool]$action.succeeded) {
            $allHealSucceeded = $false
            break
        }
    }
}

$staleExitEvidence = ([bool]$bExitEvidence.Available -and (-not [bool]$reasonMatched))
$healthClassification = 'inspection-required'
$recommendedAction = 'inspect-health-result'
$statusSummary = 'Health check needs operator review.'
$restartStageRecommended = $false

if ($abnormalNoExit) {
    $healthClassification = 'main-process-missing'
    $recommendedAction = 'investigate-main-process-exit'
    $statusSummary = 'Expected running stage process is missing without matched exit evidence; investigate before any stage restart.'
    $restartStageRecommended = $true
}
elseif ($sessionStatus -in @('PASS', 'FAIL', 'BLOCKED')) {
    $healthClassification = 'terminal-state'
    $recommendedAction = 'no-running-state-restart'
    $statusSummary = 'Session is already in a terminal state; do not restart a stage from a routine status ticket.'
}
elseif ($monitorShouldRun -and $monitorChainDegraded) {
    if ($healActions.Count -gt 0 -and $allHealSucceeded) {
        $healthClassification = 'monitor-chain-self-heal-dispatched'
        $recommendedAction = 'recheck-monitor-chain'
        $statusSummary = ('Monitor-chain heal actions were dispatched; re-check liveness. missing_components={0}' -f (($monitorChainMissingComponents.ToArray()) -join ','))
    }
    else {
        $healthClassification = 'monitor-chain-degraded'
        $recommendedAction = 'ensure-guard-and-continue-watch'
        $statusSummary = ('Monitor-chain is degraded while session expects monitoring. missing_components={0}' -f (($monitorChainMissingComponents.ToArray()) -join ','))
    }
}
elseif ($bStatus -eq 'RUNNING' -and $bHasAliveProcess) {
    if ($healActions.Count -gt 0 -and $allHealSucceeded) {
        $healthClassification = 'running-normal-after-self-heal'
        $recommendedAction = 'continue-watch-only'
        $statusSummary = 'B main process is alive and monitor-chain self-heal succeeded; continue watch only, do not infer a B restart from stale history.'
    }
    else {
        $healthClassification = 'running-normal'
        $recommendedAction = 'continue-watch-only'
        $statusSummary = 'B main process is alive; treat this status ticket as normal monitoring and do not infer a B restart from stale history.'
    }
}
elseif ($aStatus -eq 'RUNNING' -and $bStatus -eq 'NOT_RUN') {
    $healthClassification = 'running-normal'
    $recommendedAction = 'continue-watch-only'
    if ($staleExitEvidence) {
        $statusSummary = 'A stage is running and B is not running; historical B exit evidence is stale for this status ticket and should be ignored.'
    }
    else {
        $statusSummary = 'A stage is running and B is not running; treat this status ticket as normal monitoring.'
    }
}
elseif ($healActions.Count -gt 0 -and $allHealSucceeded) {
    $healthClassification = 'monitor-chain-self-healed'
    $recommendedAction = 'continue-watch-only'
    $statusSummary = 'Monitor-chain self-heal succeeded; continue watch only.'
}
elseif ($healActions.Count -gt 0) {
    $healthClassification = 'monitor-chain-heal-failed'
    $recommendedAction = 'investigate-monitor-chain'
    $statusSummary = 'Monitor-chain self-heal was attempted but did not fully succeed; investigate monitor-chain state.'
}

$output = [ordered]@{
    schema = 'AB_MAIN_PROCESS_HEALTH_CHECK_V1'
    generated_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    start_file = $startFileRel
    monitor_should_run = [bool]$monitorShouldRun
    verdict = [ordered]@{
        classification = $healthClassification
        recommended_action = $recommendedAction
        restart_stage_recommended = [bool]$restartStageRecommended
        stale_exit_evidence = [bool]$staleExitEvidence
        monitor_chain_degraded = [bool]$monitorChainDegraded
        monitor_chain_missing_components = @($monitorChainMissingComponents.ToArray())
        status_summary = $statusSummary
    }
    statuses = [ordered]@{
        session = $sessionStatus
        a = $aStatus
        b = $bStatus
    }
    process_health = [ordered]@{
        a_launch_pid = if ($null -eq $aLaunchProcessId) { 0 } else { [int]$aLaunchProcessId }
        a_launch_alive = [bool]$aAlive
        b_launch_pid = if ($null -eq $bLaunchProcessId) { 0 } else { [int]$bLaunchProcessId }
        b_launch_alive = [bool]$bExpectedAlive
        b_shell_alive_after_exit = [bool]$shellAliveAfterExit
        b_candidate_count = $bCandidates.Count
        b_candidate_pids = @($bCandidates | Select-Object -ExpandProperty ProcessId -Unique)
        b_has_alive_process = [bool]$bHasAliveProcess
        abnormal_no_exit = [bool]$abnormalNoExit
    }
    b_exit_evidence = [ordered]@{
        available = [bool]$bExitEvidence.Available
        stage = [string]$bExitEvidence.Stage
        process_id = [int]$bExitEvidence.ProcessId
        exit_code = [int]$bExitEvidence.ExitCode
        result = [string]$bExitEvidence.Result
        fail_category = [string]$bExitEvidence.FailCategory
        fail_reason = [string]$bExitEvidence.FailReason
        start_file_match = [bool]$bExitEvidence.StartFileMatch
        process_id_match = [bool]$bExitEvidence.ProcessIdMatch
        artifact_path = (Convert-ToRepoRelativePath -RepoRoot $repoRoot -Path ([string]$bExitEvidence.ArtifactPath))
        matched = [bool]$reasonMatched
    }
    monitor_chain = [ordered]@{
        supervisor = [ordered]@{ count = $supervisorPids.Count; pids = @($supervisorPids) }
        companion = [ordered]@{ count = $companionPids.Count; pids = @($companionPids) }
        guard = [ordered]@{ count = $guardPids.Count; pids = @($guardPids) }
        trigger = [ordered]@{ count = $triggerPids.Count; pids = @($triggerPids); enabled = [bool]$autoStartTrigger }
        degraded = [bool]$monitorChainDegraded
        missing_components = @($monitorChainMissingComponents.ToArray())
    }
    auto_heal = [ordered]@{
        enabled = [bool]$AutoHeal.IsPresent
        actions = @($healActions.ToArray())
        all_succeeded = [bool]$allHealSucceeded
    }
    start_file_updated = [bool]$updatedStartFile
}

$escalationStatePath = Join-Path $repoRoot (Join-Path 'out\artifacts\ab_main_health' ('monitor_chain_escalation_{0}.json' -f (Get-StartFileToken -StartFilePath $startFilePath)))
$escalationInfo = [ordered]@{
    enabled = [bool]$EscalateMonitorChainDegraded.IsPresent
    threshold = [int]$EscalateMonitorChainDegradedThreshold
    streak = 0
    incident_emitted = $false
    incident_ticket_id = ''
    queue_path = ''
    state_path = (Convert-ToRepoRelativePath -RepoRoot $repoRoot -Path $escalationStatePath)
    reason = 'disabled'
}

if ($EscalateMonitorChainDegraded.IsPresent) {
    $queuePath = Get-AgentTicketQueuePath -Settings $settings -RepoRoot $repoRoot
    $queuePathRel = Convert-ToRepoRelativePath -RepoRoot $repoRoot -Path $queuePath
    $escalationInfo.queue_path = $queuePathRel

    $stateRaw = Read-JsonFileSafely -Path $escalationStatePath
    $previousStreak = 0
    if ($null -ne $stateRaw) {
        $streakParsed = 0
        if ([int]::TryParse(([string]$stateRaw.streak), [ref]$streakParsed)) {
            $previousStreak = [Math]::Max(0, $streakParsed)
        }
    }

    $currentStreak = 0
    $incidentEmitted = $false
    $incidentTicketId = ''
    $reason = 'no-degraded-state'

    if ($monitorShouldRun -and $healthClassification -eq 'monitor-chain-degraded') {
        $currentStreak = $previousStreak + 1
        $reason = 'degraded-streak-incremented'

        $alreadyEmittedForActiveStreak = $false
        if ($null -ne $stateRaw) {
            $alreadyEmittedForActiveStreak = Convert-ToBooleanValue -Value $stateRaw.incident_emitted -Default $false
        }

        if ($alreadyEmittedForActiveStreak) {
            $incidentEmitted = $true
            $incidentTicketId = Convert-ToSingleLineText -Text ([string]$stateRaw.incident_ticket_id)
            $reason = 'incident-already-emitted-for-active-streak'
        }
        elseif ($currentStreak -ge $EscalateMonitorChainDegradedThreshold) {
            $preferredStage = if ($bStatus -eq 'RUNNING') { 'B' } else { 'A' }
            $missingComponents = ($monitorChainMissingComponents.ToArray()) -join ','
            $ticketId = ('T{0}-{1}' -f (Get-Date).ToString('yyyyMMdd-HHmmssfff'), ([System.Guid]::NewGuid().ToString('N').Substring(0, 8)))
            $ticket = [ordered]@{
                schema = 'AB_AGENT_TICKET_V1'
                ticket_id = $ticketId
                created_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
                source = 'check_unattended_main_process_health'
                event = 'incident-captured'
                severity = 'high'
                requires_confirmation = $false
                confirmation_key = ''
                start_file = $startFileRel
                queue_path = $queuePathRel
                session_final_status = $sessionStatus
                a_final_status = $aStatus
                b_final_status = $bStatus
                run_dir = ''
                incident_dir = ''
                detail = ('monitor-chain degraded streak={0}/{1} missing_components={2} start_file={3}' -f $currentStreak, $EscalateMonitorChainDegradedThreshold, $missingComponents, $startFileRel)
                recommended_action = 'Monitor-chain degraded repeatedly. Report root cause and remediation path, then trigger business_resume workflow if eligible to restore stable monitoring.'
                preferred_stage = $preferredStage
                main_round = ''
                failure_kind = 'monitor-chain-degraded'
                failure_category = 'monitor-chain'
                failure_source = 'tools/test/check_unattended_main_process_health.ps1'
                failure_evidence = ('missing_components={0}' -f $missingComponents)
                self_healable = $true
                non_recoverable_env = $false
                dedup_signature = ('monitor-chain-degraded|{0}|{1}|{2}' -f $startFileRel, $missingComponents, $EscalateMonitorChainDegradedThreshold)
            }

            $line = $ticket | ConvertTo-Json -Compress -Depth 8
            if (Write-JsonLineWithRetry -Path $queuePath -Line $line) {
                $incidentEmitted = $true
                $incidentTicketId = $ticketId
                $reason = 'incident-enqueued-threshold-reached'
            }
            else {
                $reason = 'incident-enqueue-failed'
            }
        }
    }
    else {
        $reason = 'degraded-streak-reset'
    }

    $stateToWrite = [ordered]@{
        schema = 'AB_MONITOR_CHAIN_ESCALATION_STATE_V1'
        updated_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        start_file = $startFileRel
        streak = $currentStreak
        incident_emitted = [bool]$incidentEmitted
        incident_ticket_id = $incidentTicketId
        last_classification = $healthClassification
        last_missing_components = @($monitorChainMissingComponents.ToArray())
    }

    if (-not (Write-JsonFileSafely -Path $escalationStatePath -Value $stateToWrite)) {
        if ($reason -eq 'degraded-streak-incremented') {
            $reason = 'state-write-failed'
        }
        elseif ($reason -eq 'degraded-streak-reset') {
            $reason = 'state-write-failed'
        }
    }

    $escalationInfo.streak = $currentStreak
    $escalationInfo.incident_emitted = [bool]$incidentEmitted
    $escalationInfo.incident_ticket_id = $incidentTicketId
    $escalationInfo.reason = $reason
}

$output.escalation = $escalationInfo

$mainProcessMissingEscalationStatePath = Join-Path $repoRoot (Join-Path 'out\artifacts\ab_main_health' ('main_process_missing_escalation_{0}.json' -f (Get-StartFileToken -StartFilePath $startFilePath)))
$mainProcessMissingEscalationInfo = [ordered]@{
    enabled = [bool]($AutoHeal.IsPresent -and $monitorShouldRunOrAbnormal)
    incident_emitted = $false
    incident_ticket_id = ''
    queue_path = ''
    state_path = (Convert-ToRepoRelativePath -RepoRoot $repoRoot -Path $mainProcessMissingEscalationStatePath)
    reason = 'disabled'
}

if ($AutoHeal.IsPresent -and $monitorShouldRunOrAbnormal) {
    if ($eventOnlyMode) {
        $mainProcessMissingEscalationInfo.reason = 'event-only-mode-skip'
    }
    elseif (-not $abnormalNoExit) {
        $mainProcessMissingEscalationInfo.reason = 'no-abnormal-main-process-missing'
    }
    else {
        $queuePath = Get-AgentTicketQueuePath -Settings $settings -RepoRoot $repoRoot
        $queuePathRel = Convert-ToRepoRelativePath -RepoRoot $repoRoot -Path $queuePath
        $mainProcessMissingEscalationInfo.queue_path = $queuePathRel

        $stateRaw = Read-JsonFileSafely -Path $mainProcessMissingEscalationStatePath
        $previousSignature = ''
        if ($null -ne $stateRaw) {
            $previousSignature = Convert-ToSingleLineText -Text ([string]$stateRaw.last_signature)
        }

        $expectedPid = if ($null -eq $bLaunchProcessId) { 0 } else { [int]$bLaunchProcessId }
        $currentSignature = ('main-process-missing|{0}|{1}|{2}|{3}|{4}|{5}' -f $startFileRel, $sessionStatus, $aStatus, $bStatus, $expectedPid, $bCandidates.Count)

        $incidentEmitted = $false
        $incidentTicketId = ''
        $reason = 'signature-unchanged'

        if ($currentSignature -ne $previousSignature) {
            $preferredStage = if ($bStatus -eq 'RUNNING') { 'B' } else { 'A' }
            $ticketId = ('T{0}-{1}' -f (Get-Date).ToString('yyyyMMdd-HHmmssfff'), ([System.Guid]::NewGuid().ToString('N').Substring(0, 8)))
            $detail = ('main process missing without matched exit evidence expected_pid={0} candidate_count={1} start_file={2}' -f $expectedPid, $bCandidates.Count, $startFileRel)
            $ticket = [ordered]@{
                schema = 'AB_AGENT_TICKET_V1'
                ticket_id = $ticketId
                created_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
                source = 'check_unattended_main_process_health'
                event = 'incident-captured'
                severity = 'high'
                requires_confirmation = $false
                confirmation_key = ''
                start_file = $startFileRel
                queue_path = $queuePathRel
                session_final_status = $sessionStatus
                a_final_status = $aStatus
                b_final_status = $bStatus
                run_dir = ''
                incident_dir = ''
                detail = $detail
                recommended_action = 'Main process is missing unexpectedly. Investigate root cause first, then apply script/code self-heal fixes and continue watch via business_resume workflow if eligible.'
                preferred_stage = $preferredStage
                main_round = ''
                failure_kind = 'main-process-exit'
                failure_category = 'script-fault'
                failure_source = 'tools/test/check_unattended_main_process_health.ps1'
                failure_evidence = ('expected_pid={0};candidate_count={1}' -f $expectedPid, $bCandidates.Count)
                self_healable = $true
                non_recoverable_env = $false
                dedup_signature = $currentSignature
            }

            $line = $ticket | ConvertTo-Json -Compress -Depth 8
            if (Write-JsonLineWithRetry -Path $queuePath -Line $line) {
                $incidentEmitted = $true
                $incidentTicketId = $ticketId
                $reason = 'incident-enqueued'
            }
            else {
                $reason = 'incident-enqueue-failed'
            }
        }

        $stateToWrite = [ordered]@{
            schema = 'AB_MAIN_PROCESS_MISSING_ESCALATION_STATE_V1'
            updated_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
            start_file = $startFileRel
            last_signature = $currentSignature
            incident_emitted = [bool]$incidentEmitted
            incident_ticket_id = $incidentTicketId
            classification = $healthClassification
        }
        if (-not (Write-JsonFileSafely -Path $mainProcessMissingEscalationStatePath -Value $stateToWrite) -and $reason -eq 'incident-enqueued') {
            $reason = 'state-write-failed-after-enqueue'
        }

        $mainProcessMissingEscalationInfo.incident_emitted = [bool]$incidentEmitted
        $mainProcessMissingEscalationInfo.incident_ticket_id = $incidentTicketId
        $mainProcessMissingEscalationInfo.reason = $reason
    }
}

$output.main_process_missing_escalation = $mainProcessMissingEscalationInfo

if ($AsJson.IsPresent) {
    $output | ConvertTo-Json -Depth 12
}
else {
    Write-Output ('[AB-MAIN-HEALTH] session={0} a={1} b={2} monitor_should_run={3}' -f [string]$output.statuses.session, [string]$output.statuses.a, [string]$output.statuses.b, [bool]$output.monitor_should_run)
    Write-Output ('[AB-MAIN-HEALTH] verdict={0} recommended_action={1} restart_stage_recommended={2} stale_exit_evidence={3}' -f [string]$output.verdict.classification, [string]$output.verdict.recommended_action, [bool]$output.verdict.restart_stage_recommended, [bool]$output.verdict.stale_exit_evidence)
    Write-Output ('[AB-MAIN-HEALTH] b_launch_pid={0} b_launch_alive={1} b_shell_alive_after_exit={2} b_candidates={3} abnormal_no_exit={4}' -f [int]$output.process_health.b_launch_pid, [bool]$output.process_health.b_launch_alive, [bool]$output.process_health.b_shell_alive_after_exit, [int]$output.process_health.b_candidate_count, [bool]$output.process_health.abnormal_no_exit)
    Write-Output ('[AB-MAIN-HEALTH] monitor_chain supervisor={0} companion={1} guard={2} trigger={3}' -f [int]$output.monitor_chain.supervisor.count, [int]$output.monitor_chain.companion.count, [int]$output.monitor_chain.guard.count, [int]$output.monitor_chain.trigger.count)
    Write-Output ('[AB-MAIN-HEALTH] escalation enabled={0} threshold={1} streak={2} incident_emitted={3} ticket={4} reason={5}' -f [bool]$output.escalation.enabled, [int]$output.escalation.threshold, [int]$output.escalation.streak, [bool]$output.escalation.incident_emitted, [string]$output.escalation.incident_ticket_id, [string]$output.escalation.reason)
    Write-Output ('[AB-MAIN-HEALTH] main_process_missing_escalation enabled={0} incident_emitted={1} ticket={2} reason={3}' -f [bool]$output.main_process_missing_escalation.enabled, [bool]$output.main_process_missing_escalation.incident_emitted, [string]$output.main_process_missing_escalation.incident_ticket_id, [string]$output.main_process_missing_escalation.reason)

    if ([bool]$output.b_exit_evidence.available) {
        Write-Output ('[AB-MAIN-HEALTH] b_exit stage={0} result={1} exit_code={2} category={3} matched={4}' -f [string]$output.b_exit_evidence.stage, [string]$output.b_exit_evidence.result, [int]$output.b_exit_evidence.exit_code, [string]$output.b_exit_evidence.fail_category, [bool]$output.b_exit_evidence.matched)
    }

    foreach ($action in @($output.auto_heal.actions)) {
        Write-Output ('[AB-MAIN-HEALTH] heal_action={0} ok={1} exit={2}' -f [string]$action.name, [bool]$action.succeeded, [int]$action.exit_code)
    }
}
