param(
    [AllowEmptyString()][string]$StartFile = '',
    [int]$MainPid = 0,
    [Alias('pdateStartFileStatus')][switch]$UpdateStartFileStatus,
    [switch]$MainProcessOnly,
    [switch]$DryRun,
    [string]$SshHost = '10.0.0.199',
    [string]$SshUser = 'larson',
    [string]$SshKeyPath = ("C:\Users\{0}\.ssh\id_rsa" -f $env:USERNAME),
    [string]$RemoteLockDir = '/home/larson/whois_remote/.remote_build.lock'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'unattended_exit_result.ps1')
$script:UnhandledExitTag = 'STOP-UNATTENDED-AB-ONECLICK'

trap {
    $exitCode = Get-UnattendedExitCodeFromRecord -Tag $script:UnhandledExitTag -Record $_ -DefaultExitCode 1
    Write-UnattendedUnhandledResult -Tag $script:UnhandledExitTag -Record $_ -ExitCode $exitCode
    exit $exitCode
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

    $combined = if ([System.IO.Path]::IsPathRooted($Path)) { $Path } else { Join-Path $RepoRoot $Path }
    $fullPath = [System.IO.Path]::GetFullPath($combined)

    if ($MustExist -and -not (Test-Path -LiteralPath $fullPath)) {
        throw "Path not found: $fullPath"
    }

    return $fullPath
}

function Read-KeyValueFile {
    param([string]$Path)

    $map = [ordered]@{}
    foreach ($line in @(Get-Content -LiteralPath $Path -Encoding utf8 -ErrorAction Stop)) {
        if ($line -match '^([^=]+)=(.*)$') {
            $map[$Matches[1].Trim()] = $Matches[2]
        }
    }

    return $map
}

function Set-KeyValueFileValue {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [string]$Path,
        [hashtable]$Values
    )

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
        $normalizedLines = @($buffer | ForEach-Object { [string]$_ })
        $text = [string]::Join("`n", $normalizedLines)
        if ($normalizedLines.Count -gt 0) {
            $text += "`n"
        }
        [System.IO.File]::WriteAllText($Path, $text, [System.Text.UTF8Encoding]::new($true))
    }
}

function Get-ParsedProcessId {
    param([AllowEmptyString()][string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return 0
    }

    $parsed = 0
    if ([int]::TryParse($Value.Trim(), [ref]$parsed) -and $parsed -gt 0) {
        return $parsed
    }

    return 0
}

function Get-RelativeRepoPath {
    param(
        [string]$RepoRoot,
        [string]$Path
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return ''
    }

    $full = [System.IO.Path]::GetFullPath($Path)
    $repo = [System.IO.Path]::GetFullPath($RepoRoot)
    if ($full.StartsWith($repo, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $full.Substring($repo.Length).TrimStart('\\')
    }

    return $full
}

function Get-ChildMap {
    param([object[]]$ProcessRows)

    $childMap = @{}
    foreach ($row in $ProcessRows) {
        $ppid = [int]$row.ParentProcessId
        if (-not $childMap.ContainsKey($ppid)) {
            $childMap[$ppid] = New-Object 'System.Collections.Generic.List[int]'
        }

        [void]$childMap[$ppid].Add([int]$row.ProcessId)
    }

    return $childMap
}

function Get-DescendantProcessIdList {
    param(
        [hashtable]$ChildMap,
        [System.Collections.Generic.HashSet[int]]$RootPids
    )

    $result = New-Object 'System.Collections.Generic.HashSet[int]'
    $queue = New-Object 'System.Collections.Generic.Queue[int]'

    foreach ($rootPid in $RootPids) {
        [void]$queue.Enqueue([int]$rootPid)
    }

    while ($queue.Count -gt 0) {
        $current = [int]$queue.Dequeue()
        if ($result.Contains($current)) {
            continue
        }

        [void]$result.Add($current)

        if (-not $ChildMap.ContainsKey($current)) {
            continue
        }

        foreach ($childPid in $ChildMap[$current]) {
            if (-not $result.Contains([int]$childPid)) {
                [void]$queue.Enqueue([int]$childPid)
            }
        }
    }

    return ,$result
}

function Get-ProcessSnapshotText {
    param(
        [object[]]$Rows,
        [string[]]$Keywords
    )

    $lines = New-Object 'System.Collections.Generic.List[string]'

    [void]$lines.Add(("snapshot_at={0}" -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')))
    [void]$lines.Add(("row_count={0}" -f @($Rows).Count))
    [void]$lines.Add(("keywords={0}" -f ($Keywords -join ';')))
    [void]$lines.Add('')

    if (@($Rows).Count -lt 1) {
        [void]$lines.Add('no-processes')
        return ($lines -join [Environment]::NewLine)
    }

    $formatted = @(
        $Rows |
            Sort-Object ProcessId |
            Select-Object ProcessId,
                ParentProcessId,
                Name,
                CreationDate,
                @{Name = 'CommandLine'; Expression = {
                    $text = [string]$_.CommandLine
                    if ($text.Length -gt 260) {
                        return $text.Substring(0, 260) + '...'
                    }

                    return $text
                }} |
            Format-Table -AutoSize |
            Out-String -Width 500
    )

    foreach ($line in $formatted) {
        [void]$lines.Add([string]$line)
    }

    return ($lines -join [Environment]::NewLine)
}

function Get-AppendedSessionNoteText {
    param(
        [AllowEmptyString()][string]$Existing,
        [string[]]$Segments
    )

    $items = New-Object 'System.Collections.Generic.List[string]'
    foreach ($piece in @($Existing -split ';')) {
        $trimmed = [string]$piece
        if ([string]::IsNullOrWhiteSpace($trimmed)) {
            continue
        }

        [void]$items.Add($trimmed.Trim())
    }

    foreach ($segment in $Segments) {
        if ([string]::IsNullOrWhiteSpace($segment)) {
            continue
        }

        [void]$items.Add($segment.Trim())
    }

    return ($items -join '; ')
}

function Resolve-OptionalPathUnderRepo {
    param(
        [string]$RepoRoot,
        [AllowEmptyString()][string]$PathValue
    )

    if ([string]::IsNullOrWhiteSpace($PathValue)) {
        return ''
    }

    $candidate = $PathValue.Trim()
    if (-not [System.IO.Path]::IsPathRooted($candidate)) {
        $candidate = Join-Path $RepoRoot $candidate
    }

    try {
        return [System.IO.Path]::GetFullPath($candidate)
    }
    catch {
        return $candidate
    }
}

function Test-SamePath {
    param(
        [AllowEmptyString()][string]$Left,
        [AllowEmptyString()][string]$Right
    )

    if ([string]::IsNullOrWhiteSpace($Left) -or [string]::IsNullOrWhiteSpace($Right)) {
        return $false
    }

    try {
        $leftFull = [System.IO.Path]::GetFullPath($Left)
        $rightFull = [System.IO.Path]::GetFullPath($Right)
        return $leftFull.Equals($rightFull, [System.StringComparison]::OrdinalIgnoreCase)
    }
    catch {
        return $false
    }
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\\..')).Path
Set-Location $repoRoot

$startFilePath = ''
$startSettings = [ordered]@{}
if (-not [string]::IsNullOrWhiteSpace($StartFile)) {
    $startFilePath = Resolve-RepoPath -RepoRoot $repoRoot -Path $StartFile -MustExist $true
    $startSettings = Read-KeyValueFile -Path $startFilePath
}

$keywords = @(
    'start_dev_verify_fastmode_A.ps1',
    'start_dev_verify_fastmode_B.ps1',
    'start_dev_verify_8round_multiround.ps1',
    'autopilot_dev_recheck_8round.ps1',
    'watch_ab_light.ps1',
    'open_unattended_ab_stage_window.ps1',
    'open_unattended_ab_takeover_trigger_window.ps1',
    'unattended_ab_session_guard.ps1',
    'unattended_ab_takeover_trigger.ps1',
    'one_click_release.ps1'
)

$allProcesses = @(
    Get-CimInstance Win32_Process -ErrorAction Stop |
        Select-Object ProcessId, ParentProcessId, Name, CommandLine, CreationDate
)

$existingProcessIds = New-Object 'System.Collections.Generic.HashSet[int]'
foreach ($processRow in $allProcesses) {
    [void]$existingProcessIds.Add([int]$processRow.ProcessId)
}

$rootPids = New-Object 'System.Collections.Generic.HashSet[int]'
if ($MainPid -gt 0) {
    [void]$rootPids.Add([int]$MainPid)
}

if (-not $MainProcessOnly.IsPresent) {
    foreach ($field in @('A_LAUNCH_PID', 'B_LAUNCH_PID', 'WATCH_LAUNCH_PID')) {
        if ($startSettings.Contains($field)) {
            $candidatePid = Get-ParsedProcessId -Value ([string]$startSettings[$field])
            if ($candidatePid -gt 0) {
                [void]$rootPids.Add($candidatePid)
            }
        }
    }
}

$childMap = Get-ChildMap -ProcessRows $allProcesses
$treePids = Get-DescendantProcessIdList -ChildMap $childMap -RootPids $rootPids

$startFileFullHint = ''
$startFileNameHint = ''
if (-not [string]::IsNullOrWhiteSpace($startFilePath)) {
    $startFileFullHint = [System.IO.Path]::GetFullPath($startFilePath)
    $startFileNameHint = [System.IO.Path]::GetFileName($startFilePath)
}

$keywordRows = @()
foreach ($row in $allProcesses) {
    $cmd = [string]$row.CommandLine
    if ([string]::IsNullOrWhiteSpace($cmd)) {
        continue
    }

    $containsKeyword = $false
    foreach ($keyword in $keywords) {
        if ($cmd.IndexOf($keyword, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
            $containsKeyword = $true
            break
        }
    }

    if (-not $containsKeyword) {
        continue
    }

    if ($cmd.IndexOf($repoRoot, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) {
        continue
    }

    $includeByStartHint = $false
    if (-not [string]::IsNullOrWhiteSpace($startFileFullHint) -and
        $cmd.IndexOf($startFileFullHint, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
        $includeByStartHint = $true
    }

    if (-not $includeByStartHint -and
        -not [string]::IsNullOrWhiteSpace($startFileNameHint) -and
        $cmd.IndexOf($startFileNameHint, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
        $includeByStartHint = $true
    }

    if ($rootPids.Count -lt 1) {
        $keywordRows += $row
        continue
    }

    if ($treePids.Contains([int]$row.ProcessId) -or $includeByStartHint) {
        $keywordRows += $row
    }
}

$keywordPids = New-Object 'System.Collections.Generic.HashSet[int]'
if (-not $MainProcessOnly.IsPresent) {
    foreach ($keywordRow in $keywordRows) {
        if ($null -eq $keywordRow) {
            continue
        }

        $keywordProcessId = 0
        if ([int]::TryParse(([string]$keywordRow.ProcessId), [ref]$keywordProcessId) -and $keywordProcessId -gt 0) {
            [void]$keywordPids.Add($keywordProcessId)
        }
    }
}

$targetPids = New-Object 'System.Collections.Generic.HashSet[int]'
if ($MainProcessOnly.IsPresent) {
    foreach ($rootPid in $rootPids) {
        [void]$targetPids.Add([int]$rootPid)
    }
}
else {
    foreach ($targetProcessId in $treePids) {
        [void]$targetPids.Add([int]$targetProcessId)
    }
    foreach ($keywordProcessId in $keywordPids) {
        [void]$targetPids.Add([int]$keywordProcessId)
    }
}

if ($null -eq $targetPids -or $targetPids.Count -lt 1) {
    Write-Output ("[AB-STOP] no-target-process-found")
    exit 0
}

$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$evidenceDir = Join-Path $repoRoot (Join-Path 'out\artifacts\ab_manual_stop' $timestamp)
[void](New-Item -Path $evidenceDir -ItemType Directory -Force)

$beforeRows = @(
    $allProcesses |
        Where-Object {
            $processId = [int]$_.ProcessId
            $targetPids.Contains($processId) -or $keywordPids.Contains($processId)
        }
)
$beforeText = Get-ProcessSnapshotText -Rows $beforeRows -Keywords $keywords
[System.IO.File]::WriteAllText((Join-Path $evidenceDir 'stop_before_processes.txt'), [string]$beforeText, [System.Text.UTF8Encoding]::new($false))

$stopResult = New-Object 'System.Collections.Generic.List[string]'
$stopped = 0
$failed = 0
$alreadyExited = 0

# Clean up stale remote build processes and lock BEFORE local process kill.
# Order: remote kill -> remote lock cleanup -> local process kill.
$sshExe = "C:\Windows\System32\OpenSSH\ssh.exe"
$remoteHost = $SshHost
$remoteUser = $SshUser
$remoteKey = $SshKeyPath
$remoteLockDir = $RemoteLockDir

if (-not $DryRun.IsPresent -and (Test-Path -LiteralPath $sshExe)) {
    $remoteCleanupCmd = (& $sshExe -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new -i $remoteKey "${remoteUser}@${remoteHost}" @"
pkill -f 'whois_remote' 2>/dev/null || true
sleep 1
rm -rf '$remoteLockDir' 2>/dev/null
echo LOCK_CLEANED
"@ 2>&1) -join ' '
    $rc = $LASTEXITCODE
    if ($remoteCleanupCmd -match 'LOCK_CLEANED') {
        Write-Output ("[AB-STOP] remote_build_cleaned host={0} dir={1}" -f $remoteHost, $remoteLockDir)
    }
    elseif ($rc -eq 0 -or $rc -eq 255) {
        Write-Output ("[AB-STOP] remote_build_check host={0} exit={1} output={2}" -f $remoteHost, $rc, $remoteCleanupCmd)
    }
}
elseif ($DryRun.IsPresent) {
    Write-Output ("[AB-STOP] remote_build_dryrun host={0} dir={1}" -f $remoteHost, $remoteLockDir)
}
else {
    Write-Output ("[AB-STOP] remote_build_skip reason=ssh-not-found path={0}" -f $sshExe)
}

$orderedPids = @($targetPids | Sort-Object -Descending)

if ($DryRun.IsPresent) {
    foreach ($targetProcessId in $orderedPids) {
        [void]$stopResult.Add(("dryrun-stop pid={0}" -f $targetProcessId))
    }
}
else {
    foreach ($targetProcessId in $orderedPids) {
        $taskkillExitCode = 0
        $taskkillOutput = ''
        try {
            $taskkillOutput = (& "taskkill.exe" "/F" "/T" "/PID" $targetProcessId 2>&1) -join ' '
            $taskkillExitCode = $LASTEXITCODE
        }
        catch {
            $taskkillOutput = "taskkill_error: $($_.Exception.Message)"
            $taskkillExitCode = 1
        }
        if ($taskkillExitCode -eq 0) {
            $stopped++
            [void]$stopResult.Add(("stopped pid={0} (tree)" -f $targetProcessId))
        }
        elseif ($taskkillExitCode -eq 128 -or $taskkillExitCode -eq 1) {
            $alreadyExited++
            [void]$stopResult.Add(("already-exited pid={0}" -f $targetProcessId))
        }
        else {
            $failed++
            [void]$stopResult.Add(("failed pid={0} exit={1} detail={2}" -f $targetProcessId, $taskkillExitCode, $taskkillOutput))
        }
    }
}

$afterAllProcesses = @(
    Get-CimInstance Win32_Process -ErrorAction Stop |
        Select-Object ProcessId, ParentProcessId, Name, CommandLine, CreationDate
)
$afterRows = @(
    $afterAllProcesses |
        Where-Object {
            $processId = [int]$_.ProcessId
            $targetPids.Contains($processId) -or $keywordPids.Contains($processId)
        }
)
$afterText = Get-ProcessSnapshotText -Rows $afterRows -Keywords $keywords
[System.IO.File]::WriteAllText((Join-Path $evidenceDir 'stop_after_processes.txt'), [string]$afterText, [System.Text.UTF8Encoding]::new($false))

$resultLines = New-Object 'System.Collections.Generic.List[string]'
$dryRunText = if ($DryRun.IsPresent) { 'true' } else { 'false' }
[void]$resultLines.Add(("run_at={0}" -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')))
[void]$resultLines.Add(("dry_run={0}" -f $dryRunText))
[void]$resultLines.Add(("target_pid_count={0}" -f $targetPids.Count))
[void]$resultLines.Add(("stopped={0}" -f $stopped))
[void]$resultLines.Add(("already_exited={0}" -f $alreadyExited))
[void]$resultLines.Add(("failed={0}" -f $failed))
foreach ($line in $stopResult) {
    [void]$resultLines.Add([string]$line)
}
$normalizedResultLines = @($resultLines | ForEach-Object { [string]$_ })
$resultText = [string]::Join("`n", $normalizedResultLines)
if ($normalizedResultLines.Count -gt 0) {
    $resultText += "`n"
}
[System.IO.File]::WriteAllText((Join-Path $evidenceDir 'stop_actions.txt'), $resultText, [System.Text.UTF8Encoding]::new($false))

if ($UpdateStartFileStatus.IsPresent -and -not [string]::IsNullOrWhiteSpace($startFilePath)) {
    $existingNotes = if ($startSettings.Contains('SESSION_FINAL_NOTES')) { [string]$startSettings['SESSION_FINAL_NOTES'] } else { '' }
    $relativeEvidence = Get-RelativeRepoPath -RepoRoot $repoRoot -Path $evidenceDir
    $updatedNotes = Get-AppendedSessionNoteText -Existing $existingNotes -Segments @(
        ("manual_stop_at={0}" -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')),
        ("stop_evidence={0}" -f $relativeEvidence)
    )

    Set-KeyValueFileValue -Path $startFilePath -Values @{
        A_FINAL_STATUS = 'BLOCKED'
        B_FINAL_STATUS = 'BLOCKED'
        SESSION_FINAL_STATUS = 'BLOCKED'
        SESSION_FINAL_NOTES = $updatedNotes
        WATCH_LAUNCH_PID = '0'
    }

    Write-Output ("[AB-STOP] start_file_updated={0}" -f $startFilePath)
}

Write-Output ("[AB-STOP] evidence_dir={0}" -f $evidenceDir)
Write-Output ("[AB-STOP] target_pids={0}" -f ($orderedPids -join ','))
Write-Output ("[AB-STOP] dry_run={0} stopped={1} already_exited={2} failed={3}" -f $dryRunText, $stopped, $alreadyExited, $failed)
