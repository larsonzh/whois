param(
    [Parameter(Mandatory = $true)][string]$StartFile,
    [switch]$AutoHeal,
    [switch]$AsJson
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

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
            Set-Content -LiteralPath $tempPath -Value @($buffer) -Encoding utf8 -ErrorAction Stop
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
        $result.ProcessIdMatch = ($result.ProcessId -gt 0)
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

$bExitEvidence = Get-BStageExitReasonEvidence -RepoRoot $repoRoot -StartFilePath $startFilePath -ExpectedProcessId $(if ($null -eq $bLaunchProcessId) { 0 } else { [int]$bLaunchProcessId })
$reasonMatched = (
    [bool]$bExitEvidence.Available -and
    ([string]$bExitEvidence.Stage -eq 'B') -and
    [bool]$bExitEvidence.StartFileMatch -and
    [bool]$bExitEvidence.ProcessIdMatch
)

$abnormalNoExit = ($bStatus -eq 'RUNNING' -and -not $bHasAliveProcess -and -not $reasonMatched)

$updatedStartFile = $false
if ($abnormalNoExit) {
    $sessionStatusToWrite = if ($aStatus -eq 'RUNNING') { $sessionStatus } else { 'FAIL' }
    $notes = if ($settings.Contains('SESSION_FINAL_NOTES')) { [string]$settings.SESSION_FINAL_NOTES } else { '' }
    $marker = ('health_guard_detected b_process_missing_no_exit expected_pid={0} candidate_count={1} at={2}' -f $(if ($null -eq $bLaunchProcessId) { 0 } else { [int]$bLaunchProcessId }), $bCandidates.Count, (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))
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

$healActions = New-Object 'System.Collections.Generic.List[object]'
if ($AutoHeal.IsPresent -and $monitorShouldRun) {
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

$output = [ordered]@{
    schema = 'AB_MAIN_PROCESS_HEALTH_CHECK_V1'
    generated_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    start_file = $startFileRel
    monitor_should_run = [bool]$monitorShouldRun
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
    }
    auto_heal = [ordered]@{
        enabled = [bool]$AutoHeal.IsPresent
        actions = @($healActions.ToArray())
        all_succeeded = [bool]$allHealSucceeded
    }
    start_file_updated = [bool]$updatedStartFile
}

if ($AsJson.IsPresent) {
    $output | ConvertTo-Json -Depth 12
}
else {
    Write-Output ('[AB-MAIN-HEALTH] session={0} a={1} b={2} monitor_should_run={3}' -f [string]$output.statuses.session, [string]$output.statuses.a, [string]$output.statuses.b, [bool]$output.monitor_should_run)
    Write-Output ('[AB-MAIN-HEALTH] b_launch_pid={0} b_launch_alive={1} b_candidates={2} abnormal_no_exit={3}' -f [int]$output.process_health.b_launch_pid, [bool]$output.process_health.b_launch_alive, [int]$output.process_health.b_candidate_count, [bool]$output.process_health.abnormal_no_exit)
    Write-Output ('[AB-MAIN-HEALTH] monitor_chain supervisor={0} companion={1} guard={2} trigger={3}' -f [int]$output.monitor_chain.supervisor.count, [int]$output.monitor_chain.companion.count, [int]$output.monitor_chain.guard.count, [int]$output.monitor_chain.trigger.count)

    if ([bool]$output.b_exit_evidence.available) {
        Write-Output ('[AB-MAIN-HEALTH] b_exit stage={0} result={1} exit_code={2} category={3} matched={4}' -f [string]$output.b_exit_evidence.stage, [string]$output.b_exit_evidence.result, [int]$output.b_exit_evidence.exit_code, [string]$output.b_exit_evidence.fail_category, [bool]$output.b_exit_evidence.matched)
    }

    foreach ($action in @($output.auto_heal.actions)) {
        Write-Output ('[AB-MAIN-HEALTH] heal_action={0} ok={1} exit={2}' -f [string]$action.name, [bool]$action.succeeded, [int]$action.exit_code)
    }
}
