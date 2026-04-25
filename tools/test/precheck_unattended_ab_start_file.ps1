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

function Resolve-RepoPath {
    param(
        [string]$RepoRoot,
        [string]$Path,
        [bool]$MustExist = $true
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw 'Path must not be empty.'
    }

    $combined = if ([System.IO.Path]::IsPathRooted($Path)) { $Path } else { Join-Path $RepoRoot $Path }
    $fullPath = [System.IO.Path]::GetFullPath($combined)

    if ($MustExist -and -not (Test-Path -LiteralPath $fullPath)) {
        throw "Path not found: $fullPath"
    }

    return $fullPath
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

function Read-KeyValueFile {
    param([string]$Path)

    $lines = @(Get-Content -LiteralPath $Path -Encoding utf8 -ErrorAction Stop)
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

    return [pscustomobject]@{
        Lines = $lines
        Map = $map
    }
}

function Set-KeyValueFileValues {
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

        $tempPath = "$Path.tmp.$PID.$([guid]::NewGuid().ToString('N'))"
        Set-Content -LiteralPath $tempPath -Value @($lines) -Encoding utf8 -ErrorAction Stop
        Move-Item -LiteralPath $tempPath -Destination $Path -Force
        $tempPath = ''
    }
    finally {
        if (-not [string]::IsNullOrWhiteSpace($tempPath) -and (Test-Path -LiteralPath $tempPath)) {
            Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue
        }

        if ($locked) {
            try { $mutex.ReleaseMutex() } catch {}
        }
        $mutex.Dispose()
    }
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

function Convert-MsysPathToWindowsPath {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return ''
    }

    if ($Path -match '^/([a-zA-Z])/(.*)$') {
        $drive = $Matches[1].ToUpperInvariant()
        $rest = $Matches[2] -replace '/', '\\'
        return ("{0}:\\{1}" -f $drive, $rest)
    }

    return $Path
}

function Resolve-RemoteKeyPath {
    param([string]$InputPath)

    if (-not [string]::IsNullOrWhiteSpace($InputPath) -and (Test-Path -LiteralPath $InputPath)) {
        return (Resolve-Path -LiteralPath $InputPath).Path
    }

    $converted = Convert-MsysPathToWindowsPath -Path $InputPath
    if (-not [string]::IsNullOrWhiteSpace($converted) -and (Test-Path -LiteralPath $converted)) {
        return (Resolve-Path -LiteralPath $converted).Path
    }

    throw "Unable to resolve SSH private key path. input=$InputPath"
}

function Get-LockField {
    param(
        [string[]]$Lines,
        [string]$Key
    )

    $escapedKey = [regex]::Escape($Key)
    foreach ($record in @($Lines)) {
        if ($null -eq $record) {
            continue
        }

        foreach ($rawLine in @(([string]$record) -split "`r?`n")) {
            if ([string]::IsNullOrWhiteSpace($rawLine)) {
                continue
            }

            $line = $rawLine.Trim().TrimStart([char]0xFEFF)
            if ($line -match ('^\[CHECK-REMOTE-LOCK\]\s+' + $escapedKey + '=(.*)$')) {
                return $Matches[1].Trim()
            }

            if ($line -match ('(?:^|\s)' + $escapedKey + '=(.*)$')) {
                return $Matches[1].Trim()
            }
        }
    }

    return ''
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

function Get-LocalRelatedProcesses {
    param(
        [string]$RepoRoot,
        [int]$SelfPid
    )

    $repoRootLower = $RepoRoot.ToLowerInvariant()
    $repoRootSlash = $repoRootLower.Replace('\\', '/')
    $keywordPattern = 'unattended_ab_supervisor\.ps1|unattended_ab_companion\.ps1|unattended_ab_session_guard\.ps1|open_unattended_ab_stage_window\.ps1|open_unattended_ab_resume_window\.ps1|start_dev_verify_fastmode_a\.ps1|start_dev_verify_fastmode_b\.ps1|start_dev_verify_8round_multiround\.ps1|autopilot_dev_recheck_8round\.ps1|remote_build_and_test\.sh'

    $rows = @(
        Get-CimInstance Win32_Process -ErrorAction Stop |
            Where-Object {
                $processId = [int]$_.ProcessId
                if ($processId -eq $SelfPid) {
                    return $false
                }

                $cmd = [string]$_.CommandLine
                if ([string]::IsNullOrWhiteSpace($cmd)) {
                    return $false
                }

                $line = $cmd.ToLowerInvariant()
                if ($line.Contains('precheck_unattended_ab_start_file.ps1')) {
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

    return @($rows)
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
        $taskPath = Resolve-RepoPath -RepoRoot $RepoRoot -Path $TaskValue -MustExist $false
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
        $scriptPath = Resolve-RepoPath -RepoRoot $RepoRoot -Path $ScriptValue -MustExist $false
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

function Join-Details {
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
$startFilePath = Resolve-RepoPath -RepoRoot $repoRoot -Path $StartFile -MustExist $true
$state = Read-KeyValueFile -Path $startFilePath
$settings = $state.Map
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
    $localRows = @(Get-LocalRelatedProcesses -RepoRoot $repoRoot -SelfPid $PID)
    if ($localRows.Count -eq 0) {
        $localRelatedPass = $true
        $localRelatedDetail = 'local related process count=0'
    }
    else {
        $preview = @($localRows | Select-Object -First 5 | ForEach-Object { "pid=$($_.ProcessId),name=$($_.Name),cmd=$((Get-CommandPreview -CommandLine ([string]$_.CommandLine)))" })
        $localRelatedDetail = "local related process count=$($localRows.Count); " + ($preview -join ' | ')
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
                $rawState = (Get-LockField -Lines $lockLines -Key 'state').ToLowerInvariant()
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

$failureReason = Join-Details -List $failReasons
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
$updates.PRECHECK_NOTES = Join-Details -List $notes

if ($DryRun.IsPresent) {
    Write-Output '[AB-PRECHECK] dry_run=true action=no_write'
    foreach ($key in @($updates.Keys | Sort-Object)) {
        Write-Output ("[AB-PRECHECK] dry_run_update {0}={1}" -f $key, [string]$updates[$key])
    }
}
else {
    Set-KeyValueFileValues -Path $startFilePath -Values $updates
    Write-Output ("[AB-PRECHECK] writeback=done start_file={0}" -f $startFilePath)
}

if ($startGateReady) {
    Write-Output ("[AB-PRECHECK] result=PASS start_gate={0} precheck_status={1}" -f $updates.PRECHECK_START_GATE, $updates.PRECHECK_STATUS)
    exit 0
}

Write-Output ("[AB-PRECHECK] result=FAIL start_gate={0} reason={1}" -f $updates.PRECHECK_START_GATE, $updates.PRECHECK_FAILURE_REASON)
exit 1