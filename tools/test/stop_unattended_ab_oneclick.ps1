param(
    [AllowEmptyString()][string]$StartFile = '',
    [int]$MainPid = 0,
    [switch]$UpdateStartFileStatus,
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

function Set-KeyValueFileValues {
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

    Set-Content -LiteralPath $Path -Value @($buffer) -Encoding utf8
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

function New-ChildMap {
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

function Get-DescendantProcessIds {
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

    return $result
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

function Get-AppendedSessionNotes {
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
    'open_unattended_ab_stage_window.ps1',
    'open_unattended_ab_supervisor_window.ps1',
    'open_unattended_ab_companion_window.ps1',
    'unattended_ab_supervisor.ps1',
    'unattended_ab_companion.ps1',
    'unattended_ab_session_guard.ps1'
)

$allProcesses = @(
    Get-CimInstance Win32_Process -ErrorAction Stop |
        Select-Object ProcessId, ParentProcessId, Name, CommandLine, CreationDate
)

$rootPids = New-Object 'System.Collections.Generic.HashSet[int]'
if ($MainPid -gt 0) {
    [void]$rootPids.Add([int]$MainPid)
}

foreach ($field in @('A_LAUNCH_PID', 'B_LAUNCH_PID')) {
    if ($startSettings.Contains($field)) {
        $candidatePid = Get-ParsedProcessId -Value ([string]$startSettings[$field])
        if ($candidatePid -gt 0) {
            [void]$rootPids.Add($candidatePid)
        }
    }
}

$childMap = New-ChildMap -ProcessRows $allProcesses
$treePids = Get-DescendantProcessIds -ChildMap $childMap -RootPids $rootPids

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
foreach ($keywordRow in $keywordRows) {
    if ($null -eq $keywordRow) {
        continue
    }

    $keywordProcessId = 0
    if ([int]::TryParse(([string]$keywordRow.ProcessId), [ref]$keywordProcessId) -and $keywordProcessId -gt 0) {
        [void]$keywordPids.Add($keywordProcessId)
    }
}

$targetPids = New-Object 'System.Collections.Generic.HashSet[int]'
foreach ($targetProcessId in $treePids) {
    [void]$targetPids.Add([int]$targetProcessId)
}
foreach ($keywordProcessId in $keywordPids) {
    [void]$targetPids.Add([int]$keywordProcessId)
}

if ($targetPids.Count -lt 1) {
    Write-Output '[AB-STOP] no-target-process-found'
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
Set-Content -LiteralPath (Join-Path $evidenceDir 'stop_before_processes.txt') -Value $beforeText -Encoding utf8

$stopResult = New-Object 'System.Collections.Generic.List[string]'
$stopped = 0
$failed = 0
$alreadyExited = 0
$orderedPids = @($targetPids | Sort-Object -Descending)

if ($DryRun.IsPresent) {
    foreach ($targetProcessId in $orderedPids) {
        [void]$stopResult.Add(("dryrun-stop pid={0}" -f $targetProcessId))
    }
}
else {
    foreach ($targetProcessId in $orderedPids) {
        try {
            Stop-Process -Id $targetProcessId -Force -ErrorAction Stop
            $stopped++
            [void]$stopResult.Add(("stopped pid={0}" -f $targetProcessId))
        }
        catch {
            if ([string]$_.FullyQualifiedErrorId -like 'NoProcessFoundForGivenId*') {
                $alreadyExited++
                [void]$stopResult.Add(("already-exited pid={0}" -f $targetProcessId))
                continue
            }

            $failed++
            [void]$stopResult.Add(("failed pid={0} reason={1}" -f $targetProcessId, $_.Exception.Message))
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
Set-Content -LiteralPath (Join-Path $evidenceDir 'stop_after_processes.txt') -Value $afterText -Encoding utf8

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
Set-Content -LiteralPath (Join-Path $evidenceDir 'stop_actions.txt') -Value @($resultLines) -Encoding utf8

if ($UpdateStartFileStatus.IsPresent -and -not [string]::IsNullOrWhiteSpace($startFilePath)) {
    $existingNotes = if ($startSettings.Contains('SESSION_FINAL_NOTES')) { [string]$startSettings['SESSION_FINAL_NOTES'] } else { '' }
    $relativeEvidence = Get-RelativeRepoPath -RepoRoot $repoRoot -Path $evidenceDir
    $updatedNotes = Get-AppendedSessionNotes -Existing $existingNotes -Segments @(
        ("manual_stop_at={0}" -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')),
        ("stop_evidence={0}" -f $relativeEvidence)
    )

    Set-KeyValueFileValues -Path $startFilePath -Values @{
        A_FINAL_STATUS = 'BLOCKED'
        B_FINAL_STATUS = 'BLOCKED'
        SESSION_FINAL_STATUS = 'BLOCKED'
        SESSION_FINAL_NOTES = $updatedNotes
    }

    Write-Output ("[AB-STOP] start_file_updated={0}" -f $startFilePath)
}

Write-Output ("[AB-STOP] evidence_dir={0}" -f $evidenceDir)
Write-Output ("[AB-STOP] target_pids={0}" -f ($orderedPids -join ','))
Write-Output ("[AB-STOP] dry_run={0} stopped={1} already_exited={2} failed={3}" -f $dryRunText, $stopped, $alreadyExited, $failed)
