param(
    [Parameter(Mandatory = $true)]
    [string]$StartFile,
    [string]$Operator = 'Copilot',
    [switch]$RequireCleanWorkspace,
    [string]$ExpectedRunMode = 'foreground-visible',
    [string]$ExpectedEntryMode = 'single-param-fastmode',
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'unattended_exit_result.ps1')
. (Join-Path $PSScriptRoot 'unattended_startfile_identity.ps1')
$script:UnhandledExitTag = 'PRECHECK-UNATTENDED-AB-START-FILE'

trap {
    $exitCode = Get-UnattendedExitCodeFromRecord -Tag $script:UnhandledExitTag -Record $_ -DefaultExitCode 1
    Write-UnattendedUnhandledResult -Tag $script:UnhandledExitTag -Record $_ -ExitCode $exitCode
    exit $exitCode
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

        $sourceLines = @()
        if (Test-Path -LiteralPath $Path) {
            $sourceLines = @(Get-Content -LiteralPath $Path -Encoding utf8 -ErrorAction Stop)
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

        if ($PSCmdlet.ShouldProcess($Path, 'Update start-file values')) {
            $tempPath = "$Path.tmp.$PID.$([guid]::NewGuid().ToString('N'))"
            $normalizedLines = @($lines | ForEach-Object { [string]$_ })
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
            try { $mutex.ReleaseMutex() } catch { Write-Verbose ("ReleaseMutex failed: {0}" -f $_.Exception.Message) }
        }
        $mutex.Dispose()
    }
}

function Get-CommandPreview {
    param(
        [AllowEmptyString()][string]$CommandLine,
        [int]$MaxLength = 120
    )

    if ([string]::IsNullOrWhiteSpace($CommandLine)) {
        return ''
    }

    $single = (($CommandLine -split "`r?`n") -join ' ').Trim()
    if ($single.Length -le $MaxLength) {
        return $single
    }

    return $single.Substring(0, $MaxLength) + '...'
}

function Get-TaskDefinitionPathFromCommandLine {
    param(
        [AllowEmptyString()][string]$CommandLine,
        [string]$RepoRoot,
        [string]$Role
    )

    if ([string]::IsNullOrWhiteSpace($CommandLine)) {
        return ''
    }

    $scriptPattern = switch ($Role) {
        'launcher-fastmode-a' { 'start_dev_verify_fastmode_a\.ps1' }
        'launcher-fastmode-b' { 'start_dev_verify_fastmode_b\.ps1' }
        default { '' }
    }

    if ([string]::IsNullOrWhiteSpace($scriptPattern)) {
        return ''
    }

    $match = [regex]::Match($CommandLine, ('(?i){0}\s+("([^"]+)"|''([^'']+)''|([^\s]+))' -f $scriptPattern))
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

function Get-LocalRelatedProcessRole {
    param([string]$CommandLine)

    $line = ([string]$CommandLine).ToLowerInvariant()
    if ($line -match 'unattended_ab_session_guard\.ps1') { return 'monitor-guard' }
    if ($line -match 'unattended_ab_takeover_trigger\.ps1') { return 'monitor-trigger' }
    if ($line -match 'open_unattended_ab_stage_window\.ps1') { return 'launcher-stage-window' }
    if ($line -match 'open_unattended_ab_resume_window\.ps1') { return 'launcher-resume-window' }
    if ($line -match 'start_dev_verify_fastmode_a\.ps1') { return 'launcher-fastmode-a' }
    if ($line -match 'start_dev_verify_fastmode_b\.ps1') { return 'launcher-fastmode-b' }
    if ($line -match 'start_dev_verify_8round_multiround\.ps1') { return 'launcher-multiround' }
    if ($line -match 'autopilot_dev_recheck_8round\.ps1') { return 'launcher-recheck' }
    if ($line -match 'remote_build_and_test\.sh') { return 'launcher-remote-build' }
    return 'related-unknown'
}

function Read-JsonFileSafely {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) {
        return $null
    }

    try {
        return (Get-Content -LiteralPath $Path -Raw -Encoding utf8 | ConvertFrom-Json)
    }
    catch {
        return $null
    }
}

function Test-StaleFailedStageLauncher {
    param(
        [string]$Role,
        [int]$ProcessId,
        [string]$RepoRoot,
        [string]$StartFilePath,
        [System.Collections.IDictionary]$Settings
    )

    $stage = ''
    $pidKey = ''
    $artifactPath = ''
    switch ($Role) {
        'launcher-fastmode-a' {
            $stage = 'A'
            $pidKey = 'A_LAUNCH_PID'
            $artifactPath = Join-Path $RepoRoot 'out\artifacts\ab_stage_exit\latest_a_exit.json'
            break
        }
        'launcher-fastmode-b' {
            $stage = 'B'
            $pidKey = 'B_LAUNCH_PID'
            $artifactPath = Join-Path $RepoRoot 'out\artifacts\ab_stage_exit\latest_b_exit.json'
            break
        }
        default {
            return $false
        }
    }

    if ($null -eq $Settings -or -not $Settings.Contains($pidKey)) {
        return $false
    }

    $launchPidValue = 0
    if (-not [int]::TryParse(([string]$Settings[$pidKey]), [ref]$launchPidValue)) {
        return $false
    }

    if ($launchPidValue -ne 0) {
        return $false
    }

    $payload = Read-JsonFileSafely -Path $artifactPath
    if ($null -eq $payload) {
        return $false
    }

    $artifactStage = (Convert-ToBooleanSetting -Value 'false') > $null
    $artifactStage = ([string]$payload.stage).Trim().ToUpperInvariant()
    if ($artifactStage -ne $stage) {
        return $false
    }

    $artifactResult = ([string]$payload.result).Trim().ToLowerInvariant()
    if ($artifactResult -ne 'fail') {
        return $false
    }

    $artifactPidValue = 0
    if (-not [int]::TryParse(([string]$payload.process_id), [ref]$artifactPidValue) -or $artifactPidValue -ne $ProcessId) {
        return $false
    }

    $expectedStartFileIdentity = Get-NormalizedPathIdentity -Path $StartFilePath -RepoRoot $RepoRoot
    $artifactStartFileIdentity = Get-NormalizedPathIdentity -Path ([string]$payload.start_file_path) -RepoRoot $RepoRoot
    if ([string]::IsNullOrWhiteSpace($expectedStartFileIdentity) -or $artifactStartFileIdentity -ne $expectedStartFileIdentity) {
        return $false
    }

    return $true
}

function Test-CompletedLauncherShell {
    param(
        [string]$Role,
        [System.Collections.IDictionary]$Settings,
        [bool]$SameStartFile
    )

    if (-not $SameStartFile -or $null -eq $Settings) {
        return $false
    }

    $pidKey = ''
    $finalStatusKey = ''
    switch ($Role) {
        'launcher-fastmode-a' {
            $pidKey = 'A_LAUNCH_PID'
            $finalStatusKey = 'A_FINAL_STATUS'
            break
        }
        'launcher-fastmode-b' {
            $pidKey = 'B_LAUNCH_PID'
            $finalStatusKey = 'B_FINAL_STATUS'
            break
        }
        default {
            return $false
        }
    }

    if (-not $Settings.Contains($pidKey) -or -not $Settings.Contains($finalStatusKey)) {
        return $false
    }

    $launchPidValue = 0
    if (-not [int]::TryParse(([string]$Settings[$pidKey]), [ref]$launchPidValue)) {
        return $false
    }

    if ($launchPidValue -ne 0) {
        return $false
    }

    $finalStatus = ([string]$Settings[$finalStatusKey]).Trim()
    return (-not [string]::IsNullOrWhiteSpace($finalStatus))
}

function Get-LocalRelatedProcess {
    param(
        [string]$RepoRoot,
        [int]$SelfPid,
        [string]$StartFilePath,
        [System.Collections.IDictionary]$Settings
    )

    $repoRootLower = $RepoRoot.ToLowerInvariant()
    $repoRootSlash = $repoRootLower.Replace('\\', '/')
    $keywordPattern = 'unattended_ab_session_guard\.ps1|open_unattended_ab_stage_window\.ps1|open_unattended_ab_resume_window\.ps1|start_dev_verify_fastmode_a\.ps1|start_dev_verify_fastmode_b\.ps1|start_dev_verify_8round_multiround\.ps1|autopilot_dev_recheck_8round\.ps1|remote_build_and_test\.sh'
    $ancestorExcludePattern = 'open_unattended_ab_stage_window\.ps1|check_unattended_ab_launch_ready\.ps1'
    $startFileIdentity = Get-NormalizedPathIdentity -Path $StartFilePath -RepoRoot $RepoRoot
    $reusableRoles = @('monitor-guard', 'monitor-trigger')
    $excludePids = New-Object 'System.Collections.Generic.HashSet[int]'
    [void]$excludePids.Add([int]$SelfPid)

    try {
        $cursorPid = [int]$SelfPid
        for ($depth = 0; $depth -lt 6; $depth++) {
            $cursorRow = Get-CimInstance Win32_Process -Filter ("ProcessId = {0}" -f $cursorPid) -ErrorAction Stop | Select-Object -First 1
            if ($null -eq $cursorRow) {
                break
            }

            $parentPid = [int]$cursorRow.ParentProcessId
            if ($parentPid -le 0) {
                break
            }

            $parentRow = Get-CimInstance Win32_Process -Filter ("ProcessId = {0}" -f $parentPid) -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($null -eq $parentRow) {
                $cursorPid = $parentPid
                continue
            }

            $parentCmd = [string]$parentRow.CommandLine
            if (-not [string]::IsNullOrWhiteSpace($parentCmd)) {
                $parentLine = $parentCmd.ToLowerInvariant()
                if ($parentLine -match $ancestorExcludePattern) {
                    [void]$excludePids.Add($parentPid)
                }
            }

            $cursorPid = $parentPid
        }
    }
    catch {
        Write-Verbose ("Suppress ancestor process traversal failure: {0}" -f $_.Exception.Message)
    }

    $rows = @(
        Get-CimInstance Win32_Process -ErrorAction Stop |
            Where-Object {
                $processId = [int]$_.ProcessId
                if ($excludePids.Contains($processId)) {
                    return $false
                }

                $cmd = [string]$_.CommandLine
                if ([string]::IsNullOrWhiteSpace($cmd)) {
                    return $false
                }

                $line = $cmd.ToLowerInvariant()
                if ($line.Contains('precheck_unattended_ab_start_file.ps1') -or $line.Contains('check_unattended_ab_launch_ready.ps1')) {
                    return $false
                }

                if (-not ($line.Contains($repoRootLower) -or $line.Contains($repoRootSlash))) {
                    return $false
                }

                if ($line -notmatch $keywordPattern) {
                    return $false
                }

                return $true
            } |
            Select-Object ProcessId, Name, CommandLine
    )

    $classifiedRows = foreach ($row in $rows) {
        $commandLine = [string]$row.CommandLine
        $role = Get-LocalRelatedProcessRole -CommandLine $commandLine
        $processStartFileIdentity = Get-StartFilePathFromCommandLine -CommandLine $commandLine -RepoRoot $RepoRoot
        $processTaskDefinitionIdentity = Get-TaskDefinitionPathFromCommandLine -CommandLine $commandLine -RepoRoot $RepoRoot -Role $role
        $expectedTaskDefinitionIdentity = ''
        switch ($role) {
            'launcher-fastmode-a' {
                if ($Settings.Contains('A_TASK_DEFINITION')) {
                    $expectedTaskDefinitionIdentity = Get-NormalizedPathIdentity -Path ([string]$Settings.A_TASK_DEFINITION) -RepoRoot $RepoRoot
                }
                break
            }
            'launcher-fastmode-b' {
                if ($Settings.Contains('B_TASK_DEFINITION')) {
                    $expectedTaskDefinitionIdentity = Get-NormalizedPathIdentity -Path ([string]$Settings.B_TASK_DEFINITION) -RepoRoot $RepoRoot
                }
                break
            }
        }

        $sameStartFile = ((-not [string]::IsNullOrWhiteSpace($startFileIdentity)) -and ($processStartFileIdentity -eq $startFileIdentity)) -or ((-not [string]::IsNullOrWhiteSpace($expectedTaskDefinitionIdentity)) -and ($processTaskDefinitionIdentity -eq $expectedTaskDefinitionIdentity))
        $reusable = $sameStartFile -and ($reusableRoles -contains $role)
        $staleFailedLauncher = Test-StaleFailedStageLauncher -Role $role -ProcessId ([int]$row.ProcessId) -RepoRoot $RepoRoot -StartFilePath $StartFilePath -Settings $Settings
        $completedLauncherShell = Test-CompletedLauncherShell -Role $role -Settings $Settings -SameStartFile $sameStartFile

        $blockReason = ''
        if (-not $reusable -and -not $staleFailedLauncher -and -not $completedLauncherShell) {
            if ($sameStartFile) {
                $blockReason = 'same-start conflicting launcher still running'
            }
            elseif ([string]::IsNullOrWhiteSpace($processStartFileIdentity)) {
                $blockReason = 'unbound related process still running'
            }
            else {
                $blockReason = 'different-start related process still running'
            }
        }

        [pscustomobject]@{
            ProcessId = [int]$row.ProcessId
            Name = [string]$row.Name
            CommandLine = $commandLine
            Role = $role
            StartFileIdentity = $processStartFileIdentity
            TaskDefinitionIdentity = $processTaskDefinitionIdentity
            SameStartFile = [bool]$sameStartFile
            ReusableForSameStart = [bool]$reusable
            StaleFailedLauncher = [bool]$staleFailedLauncher
            CompletedLauncherShell = [bool]$completedLauncherShell
            Blocking = (-not $reusable -and -not $staleFailedLauncher -and -not $completedLauncherShell)
            BlockingReason = $blockReason
        }
    }

    return @($classifiedRows)
}

function Get-WorkspaceStatus {
    param([string]$RepoRoot)

    $lines = @((& git -C $RepoRoot status --short 2>&1) | ForEach-Object { [string]$_ })
    $exitCode = if ($null -eq $LASTEXITCODE) { 0 } else { [int]$LASTEXITCODE }

    return [pscustomobject]@{
        ExitCode = $exitCode
        Lines = @($lines)
    }
}

function Get-WorkspaceSummary {
    param([string[]]$Lines)

    if ($null -eq $Lines -or $Lines.Count -eq 0) {
        return 'CLEAN'
    }

    $previewLimit = 4
    $preview = @($Lines | Select-Object -First $previewLimit)
    $summary = ($preview -join ' | ')
    if ($Lines.Count -gt $previewLimit) {
        $summary = "$summary | ... (+$($Lines.Count - $previewLimit) more)"
    }

    return $summary
}

function Test-TaskDefinition {
    param(
        [string]$RepoRoot,
        [AllowEmptyString()][string]$TaskValue,
        [string]$Label
    )

    if ([string]::IsNullOrWhiteSpace($TaskValue)) {
        return [pscustomobject]@{
            Exists = $false
            TodoFree = $false
            ExistsDetail = "$Label missing"
            TodoDetail = "$Label missing"
        }
    }

    $taskPath = ''
    try {
        $taskPath = Resolve-RepoPath -Path $TaskValue -MustExist $false
    }
    catch {
        return [pscustomobject]@{
            Exists = $false
            TodoFree = $false
            ExistsDetail = "$Label invalid path: $($_.Exception.Message)"
            TodoDetail = "$Label invalid path"
        }
    }

    if (-not (Test-Path -LiteralPath $taskPath)) {
        return [pscustomobject]@{
            Exists = $false
            TodoFree = $false
            ExistsDetail = "$Label not found: $taskPath"
            TodoDetail = "$Label not found"
        }
    }

    $content = ''
    try {
        $content = Get-Content -LiteralPath $taskPath -Raw -Encoding utf8 -ErrorAction Stop
    }
    catch {
        return [pscustomobject]@{
            Exists = $true
            TodoFree = $false
            ExistsDetail = "$Label exists"
            TodoDetail = "$Label unreadable: $($_.Exception.Message)"
        }
    }

    $hasTodo = ($content -match 'TODO_')
    return [pscustomobject]@{
        Exists = $true
        TodoFree = (-not $hasTodo)
        ExistsDetail = "$Label exists"
        TodoDetail = if ($hasTodo) { "$Label contains TODO_ placeholder" } else { "$Label todo-free" }
    }
}

function Test-EntryScript {
    param(
        [string]$RepoRoot,
        [AllowEmptyString()][string]$ScriptValue,
        [string]$Label
    )

    if ([string]::IsNullOrWhiteSpace($ScriptValue)) {
        return [pscustomobject]@{
            Pass = $false
            Detail = "$Label missing"
        }
    }

    $scriptPath = ''
    try {
        $scriptPath = Resolve-RepoPath -Path $ScriptValue -MustExist $false
    }
    catch {
        return [pscustomobject]@{
            Pass = $false
            Detail = "$Label invalid path: $($_.Exception.Message)"
        }
    }

    if (-not (Test-Path -LiteralPath $scriptPath)) {
        return [pscustomobject]@{
            Pass = $false
            Detail = "$Label not found: $scriptPath"
        }
    }

    return [pscustomobject]@{
        Pass = $true
        Detail = "$Label exists"
    }
}

function Format-RemoteLockStateForStartFile {
    param([string]$State)

    switch ($State.ToLowerInvariant()) {
        'absent' { return 'absent' }
        'held-by-self' { return 'held-by-self' }
        'present' { return 'blocked' }
        default { return 'unknown' }
    }
}

function Join-Detail {
    param([System.Collections.Generic.List[string]]$List)

    $parts = @($List | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($parts.Count -lt 1) {
        return ''
    }

    return ($parts -join '; ')
}

function Write-CheckLine {
    param(
        [string]$Name,
        [bool]$Pass,
        [string]$Detail
    )

    $status = if ($Pass) { 'PASS' } else { 'FAIL' }
    Write-Output ("[AB-PRECHECK] check={0} status={1} detail={2}" -f $Name, $status, $Detail)
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$startFilePath = Resolve-RepoPath -Path $StartFile -MustExist $true
$settings = Read-KeyValueFile -Path $startFilePath
$nowText = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')

$failReasons = New-Object 'System.Collections.Generic.List[string]'
$notes = New-Object 'System.Collections.Generic.List[string]'

$updates = @{
    PRECHECK_OPERATOR = $Operator
    PRECHECK_AT = $nowText
}

$localRelatedPass = $false
$localRelatedDetail = ''
try {
    $localRows = @(Get-LocalRelatedProcess -RepoRoot $repoRoot -SelfPid $PID -StartFilePath $startFilePath -Settings $settings)
    $blockingLocalRows = @($localRows | Where-Object { [bool]$_.Blocking })
    $reusableLocalRows = @($localRows | Where-Object { [bool]$_.ReusableForSameStart })
    $staleFailedLauncherRows = @($localRows | Where-Object { [bool]$_.StaleFailedLauncher })
    $completedLauncherShellRows = @($localRows | Where-Object { [bool]$_.CompletedLauncherShell })
    if ($blockingLocalRows.Count -eq 0) {
        $localRelatedPass = $true
        if ($reusableLocalRows.Count -eq 0 -and $staleFailedLauncherRows.Count -eq 0 -and $completedLauncherShellRows.Count -eq 0) {
            $localRelatedDetail = 'local related blocking count=0'
        }
        else {
            $previewRows = @($reusableLocalRows + $staleFailedLauncherRows + $completedLauncherShellRows | Select-Object -First 5)
            $preview = @($previewRows | ForEach-Object {
                $kind = if ([bool]$_.ReusableForSameStart) { 'reusable-same-start' } elseif ([bool]$_.StaleFailedLauncher) { 'stale-failed-launcher' } else { 'completed-launcher-shell' }
                "pid=$($_.ProcessId),role=$($_.Role),kind=$kind,cmd=$((Get-CommandPreview -CommandLine ([string]$_.CommandLine)))"
            })
            $localRelatedDetail = "local related blocking count=0; reusable_same_start_count=$($reusableLocalRows.Count); stale_failed_launcher_count=$($staleFailedLauncherRows.Count); completed_launcher_shell_count=$($completedLauncherShellRows.Count); " + ($preview -join ' | ')
        }
    }
    else {
        $preview = @($blockingLocalRows | Select-Object -First 5 | ForEach-Object { "pid=$($_.ProcessId),role=$($_.Role),reason=$($_.BlockingReason),cmd=$((Get-CommandPreview -CommandLine ([string]$_.CommandLine)))" })
        $localRelatedDetail = "local related blocking count=$($blockingLocalRows.Count); " + ($preview -join ' | ')
    }
}
catch {
    $localRelatedPass = $false
    $localRelatedDetail = "local related process check error: $($_.Exception.Message)"
}

$updates.PRECHECK_LOCAL_RELATED_PROCESSES = if ($localRelatedPass) { 'PASS' } else { 'FAIL' }
Write-CheckLine -Name 'PRECHECK_LOCAL_RELATED_PROCESSES' -Pass $localRelatedPass -Detail $localRelatedDetail
if (-not $localRelatedPass) {
    [void]$failReasons.Add($localRelatedDetail)
}
$localRelatedNote = 'fail'
if ($localRelatedPass) {
    $localRelatedNote = 'pass'
}
[void]$notes.Add(("local_related={0}" -f $localRelatedNote))

$workspacePass = $false
$workspaceDetail = ''
try {
    $workspace = Get-WorkspaceStatus -RepoRoot $repoRoot
    if ($workspace.ExitCode -ne 0) {
        $workspacePass = $false
        $workspaceDetail = "git status failed: $($workspace.Lines -join ' | ')"
    }
    else {
        $workspaceSummary = Get-WorkspaceSummary -Lines $workspace.Lines
        if ($workspace.Lines.Count -eq 0) {
            $workspacePass = $true
            $workspaceDetail = 'CLEAN'
        }
        else {
            if ($RequireCleanWorkspace.IsPresent) {
                $workspacePass = $false
                $workspaceDetail = "dirty workspace not allowed: $workspaceSummary"
            }
            else {
                $workspacePass = $true
                $workspaceDetail = "dirty workspace allowed: $workspaceSummary"
            }
        }

        $updates.PRECHECK_WORKSPACE_STATUS_DETAIL = $workspaceSummary
    }
}
catch {
    $workspacePass = $false
    $workspaceDetail = "workspace check error: $($_.Exception.Message)"
}

$updates.PRECHECK_WORKSPACE_STATUS = if ($workspacePass) { 'PASS' } else { 'FAIL' }
if (-not $updates.ContainsKey('PRECHECK_WORKSPACE_STATUS_DETAIL')) {
    $updates.PRECHECK_WORKSPACE_STATUS_DETAIL = $workspaceDetail
}
Write-CheckLine -Name 'PRECHECK_WORKSPACE_STATUS' -Pass $workspacePass -Detail $workspaceDetail
if (-not $workspacePass) {
    [void]$failReasons.Add($workspaceDetail)
}
[void]$notes.Add(("workspace={0}" -f $updates.PRECHECK_WORKSPACE_STATUS_DETAIL))

$taskA = Test-TaskDefinition -RepoRoot $repoRoot -TaskValue ([string]$settings.A_TASK_DEFINITION) -Label 'A_TASK_DEFINITION'
$taskAExistsPass = [bool]$taskA.Exists
$taskATodoFreePass = [bool]$taskA.TodoFree
$updates.PRECHECK_TASK_A_EXISTS = if ($taskAExistsPass) { 'PASS' } else { 'FAIL' }
$updates.PRECHECK_TASK_A_TODO_FREE = if ($taskATodoFreePass) { 'PASS' } else { 'FAIL' }
Write-CheckLine -Name 'PRECHECK_TASK_A_EXISTS' -Pass $taskAExistsPass -Detail ([string]$taskA.ExistsDetail)
Write-CheckLine -Name 'PRECHECK_TASK_A_TODO_FREE' -Pass $taskATodoFreePass -Detail ([string]$taskA.TodoDetail)
if (-not $taskAExistsPass) {
    [void]$failReasons.Add([string]$taskA.ExistsDetail)
}
if (-not $taskATodoFreePass) {
    [void]$failReasons.Add([string]$taskA.TodoDetail)
}

$taskB = Test-TaskDefinition -RepoRoot $repoRoot -TaskValue ([string]$settings.B_TASK_DEFINITION) -Label 'B_TASK_DEFINITION'
$taskBExistsPass = [bool]$taskB.Exists
$taskBTodoFreePass = [bool]$taskB.TodoFree
$updates.PRECHECK_TASK_B_EXISTS = if ($taskBExistsPass) { 'PASS' } else { 'FAIL' }
$updates.PRECHECK_TASK_B_TODO_FREE = if ($taskBTodoFreePass) { 'PASS' } else { 'FAIL' }
Write-CheckLine -Name 'PRECHECK_TASK_B_EXISTS' -Pass $taskBExistsPass -Detail ([string]$taskB.ExistsDetail)
Write-CheckLine -Name 'PRECHECK_TASK_B_TODO_FREE' -Pass $taskBTodoFreePass -Detail ([string]$taskB.TodoDetail)
if (-not $taskBExistsPass) {
    [void]$failReasons.Add([string]$taskB.ExistsDetail)
}
if (-not $taskBTodoFreePass) {
    [void]$failReasons.Add([string]$taskB.TodoDetail)
}

$entryA = Test-EntryScript -RepoRoot $repoRoot -ScriptValue ([string]$settings.ENTRY_SCRIPT_A) -Label 'ENTRY_SCRIPT_A'
$entryB = Test-EntryScript -RepoRoot $repoRoot -ScriptValue ([string]$settings.ENTRY_SCRIPT_B) -Label 'ENTRY_SCRIPT_B'
$updates.PRECHECK_ENTRY_SCRIPT_A_EXISTS = if ($entryA.Pass) { 'PASS' } else { 'FAIL' }
$updates.PRECHECK_ENTRY_SCRIPT_B_EXISTS = if ($entryB.Pass) { 'PASS' } else { 'FAIL' }
Write-CheckLine -Name 'PRECHECK_ENTRY_SCRIPT_A_EXISTS' -Pass $entryA.Pass -Detail ([string]$entryA.Detail)
Write-CheckLine -Name 'PRECHECK_ENTRY_SCRIPT_B_EXISTS' -Pass $entryB.Pass -Detail ([string]$entryB.Detail)
if (-not $entryA.Pass) {
    [void]$failReasons.Add([string]$entryA.Detail)
}
if (-not $entryB.Pass) {
    [void]$failReasons.Add([string]$entryB.Detail)
}

$runModeRaw = if ($settings.Contains('RUN_MODE')) { [string]$settings.RUN_MODE } else { '' }
$runModePass = (-not [string]::IsNullOrWhiteSpace($runModeRaw)) -and $runModeRaw.Trim().Equals($ExpectedRunMode, [System.StringComparison]::OrdinalIgnoreCase)
$updates.PRECHECK_RUN_MODE_CONFIRMED = if ($runModePass) { 'PASS' } else { 'FAIL' }
$runModeDetail = if ($runModePass) {
    "RUN_MODE=$runModeRaw"
}
else {
    "RUN_MODE expected=$ExpectedRunMode actual=$runModeRaw"
}
Write-CheckLine -Name 'PRECHECK_RUN_MODE_CONFIRMED' -Pass $runModePass -Detail $runModeDetail
if (-not $runModePass) {
    [void]$failReasons.Add($runModeDetail)
}

$entryModeRaw = if ($settings.Contains('ENTRY_MODE')) { [string]$settings.ENTRY_MODE } else { '' }
$entryModePass = (-not [string]::IsNullOrWhiteSpace($entryModeRaw)) -and $entryModeRaw.Trim().Equals($ExpectedEntryMode, [System.StringComparison]::OrdinalIgnoreCase)
$updates.PRECHECK_ENTRY_MODE_CONFIRMED = if ($entryModePass) { 'PASS' } else { 'FAIL' }
$entryModeDetail = if ($entryModePass) {
    "ENTRY_MODE=$entryModeRaw"
}
else {
    "ENTRY_MODE expected=$ExpectedEntryMode actual=$entryModeRaw"
}
Write-CheckLine -Name 'PRECHECK_ENTRY_MODE_CONFIRMED' -Pass $entryModePass -Detail $entryModeDetail
if (-not $entryModePass) {
    [void]$failReasons.Add($entryModeDetail)
}

$remoteIp = if ($settings.Contains('REMOTE_IP') -and -not [string]::IsNullOrWhiteSpace([string]$settings.REMOTE_IP)) {
    [string]$settings.REMOTE_IP
}
else {
    '10.0.0.199'
}
$remoteUser = if ($settings.Contains('REMOTE_USER') -and -not [string]::IsNullOrWhiteSpace([string]$settings.REMOTE_USER)) {
    [string]$settings.REMOTE_USER
}
else {
    'larson'
}
$remoteKeyRaw = if ($settings.Contains('REMOTE_KEYPATH') -and -not [string]::IsNullOrWhiteSpace([string]$settings.REMOTE_KEYPATH)) {
    [string]$settings.REMOTE_KEYPATH
}
else {
    "/c/Users/$env:USERNAME/.ssh/id_rsa"
}

$remoteLockRequired = if ($settings.Contains('REMOTE_BUILD_LOCK_REQUIRED')) {
    Convert-ToBooleanSetting -Value ([string]$settings.REMOTE_BUILD_LOCK_REQUIRED) -Default $true
}
else {
    $true
}

$sshPass = $false
$remoteRelatedPass = $false
$remoteLockStateForFile = 'unknown'
$remoteLockDetail = ''

if (-not $remoteLockRequired) {
    $sshPass = $true
    $remoteRelatedPass = $true
    $remoteLockStateForFile = 'absent'
    $remoteLockDetail = 'remote lock check skipped (REMOTE_BUILD_LOCK_REQUIRED=false)'
}
else {
    $lockScript = Join-Path $repoRoot 'tools\dev\check_remote_lock.ps1'
    if (-not (Test-Path -LiteralPath $lockScript)) {
        $sshPass = $false
        $remoteRelatedPass = $false
        $remoteLockStateForFile = 'unknown'
        $remoteLockDetail = "remote lock check script missing: $lockScript"
    }
    else {
        $resolvedKeyPath = ''
        try {
            $resolvedKeyPath = Resolve-RemoteKeyPath -InputPath $remoteKeyRaw
        }
        catch {
            $sshPass = $false
            $remoteRelatedPass = $false
            $remoteLockStateForFile = 'unknown'
            $remoteLockDetail = "remote key resolve failed: $($_.Exception.Message)"
        }

        if (-not [string]::IsNullOrWhiteSpace($resolvedKeyPath)) {
            $lockLines = @()
            $lockExitCode = 1
            try {
                $lockLines = @((& $lockScript -RemoteIp $remoteIp -RemoteUser $remoteUser -KeyPath $resolvedKeyPath -TimeoutSec 20 2>&1) | ForEach-Object { [string]$_ })
                $lockExitCode = if ($null -eq $LASTEXITCODE) { 0 } else { [int]$LASTEXITCODE }
            }
            catch {
                $lockExitCode = 1
                $lockLines = @($_.Exception.Message)
            }

            if ($lockExitCode -ne 0) {
                $sshPass = $false
                $remoteRelatedPass = $false
                $remoteLockStateForFile = 'unknown'
                $remoteLockDetail = "remote lock check failed exit=$lockExitCode output=$($lockLines -join ' | ')"
            }
            else {
                $sshPass = $true
                $rawState = (Get-RemoteLockField -Lines $lockLines -Key 'state').ToLowerInvariant()
                if ([string]::IsNullOrWhiteSpace($rawState)) {
                    $rawState = 'unknown'
                }

                $remoteLockStateForFile = Format-RemoteLockStateForStartFile -State $rawState
                if ($rawState -eq 'absent') {
                    $remoteRelatedPass = $true
                    $remoteLockDetail = 'remote lock state=absent'
                }
                elseif ($rawState -eq 'held-by-self') {
                    $remoteRelatedPass = $true
                    $remoteLockDetail = 'remote lock state=held-by-self'
                }
                elseif ($rawState -eq 'present') {
                    $remoteRelatedPass = $false
                    $remoteLockDetail = 'remote lock present'
                }
                else {
                    $remoteRelatedPass = $false
                    $remoteLockDetail = "remote lock state=$rawState"
                }
            }
        }
    }
}

$updates.PRECHECK_SSH_CONNECTIVITY = if ($sshPass) { 'PASS' } else { 'FAIL' }
$updates.PRECHECK_REMOTE_RELATED_PROCESSES = if ($remoteRelatedPass) { 'PASS' } else { 'FAIL' }
$updates.PRECHECK_REMOTE_LOCK = $remoteLockStateForFile
Write-CheckLine -Name 'PRECHECK_SSH_CONNECTIVITY' -Pass $sshPass -Detail $remoteLockDetail
Write-CheckLine -Name 'PRECHECK_REMOTE_RELATED_PROCESSES' -Pass $remoteRelatedPass -Detail $remoteLockDetail

if (-not $sshPass) {
    [void]$failReasons.Add($remoteLockDetail)
}
if (-not $remoteRelatedPass) {
    [void]$failReasons.Add($remoteLockDetail)
}
[void]$notes.Add(("remote_lock={0}" -f $remoteLockStateForFile))

$allRequiredPass =
    $localRelatedPass -and
    $workspacePass -and
    $taskAExistsPass -and
    $taskATodoFreePass -and
    $taskBExistsPass -and
    $taskBTodoFreePass -and
    $entryA.Pass -and
    $entryB.Pass -and
    $runModePass -and
    $entryModePass -and
    $sshPass -and
    $remoteRelatedPass

$updates.PRECHECK_STATUS = if ($allRequiredPass) { 'PASS' } else { 'FAIL' }

$allowedRemoteLock = @('absent', 'held-by-self')
$startGateReady = $allRequiredPass -and ($allowedRemoteLock -contains $remoteLockStateForFile)
$updates.PRECHECK_START_GATE = if ($startGateReady) { 'READY' } else { 'BLOCKED' }

$failureReason = Join-Detail -List $failReasons
if ($startGateReady) {
    $updates.PRECHECK_START_BLOCKER = ''
    $updates.PRECHECK_FAILURE_REASON = ''
}
else {
    if ([string]::IsNullOrWhiteSpace($failureReason)) {
        $failureReason = "PRECHECK_REMOTE_LOCK=$remoteLockStateForFile"
    }
    $updates.PRECHECK_START_BLOCKER = $failureReason
    $updates.PRECHECK_FAILURE_REASON = $failureReason
}

[void]$notes.Add(("start_gate={0}" -f $updates.PRECHECK_START_GATE))
[void]$notes.Add(("operator={0}" -f $Operator))
$updates.PRECHECK_NOTES = Join-Detail -List $notes

if ($DryRun.IsPresent) {
    Write-Output '[AB-PRECHECK] dry_run=true action=no_write'
    foreach ($key in @($updates.Keys | Sort-Object)) {
        Write-Output ("[AB-PRECHECK] dry_run_update {0}={1}" -f $key, [string]$updates[$key])
    }
}
else {
    Set-KeyValueFileValue -Path $startFilePath -Values $updates
    Write-Output ("[AB-PRECHECK] writeback=done start_file={0}" -f $startFilePath)
}

if ($startGateReady) {
    Write-Output ("[AB-PRECHECK] result=PASS start_gate={0} precheck_status={1}" -f $updates.PRECHECK_START_GATE, $updates.PRECHECK_STATUS)
    exit 0
}

Write-Output ("[AB-PRECHECK] result=FAIL start_gate={0} reason={1}" -f $updates.PRECHECK_START_GATE, $updates.PRECHECK_FAILURE_REASON)
Exit-UnattendedFailure -Tag $script:UnhandledExitTag -Reason ("precheck gate blocked: {0}" -f $updates.PRECHECK_FAILURE_REASON) -ExitCode 3
