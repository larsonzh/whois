<#
Common startup commands:
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/watch_ab_light.ps1 -StartFile tmp/unattended_ab_start_20260422-2300.md -Once -NoClear
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/watch_ab_light.ps1 -StartFile tmp/unattended_ab_start_20260422-2300.md -IntervalSec 20
#>

param(
    [string]$StartFile = 'tmp\unattended_ab_start_20260422-2300.md',
    [ValidateRange(5, 300)][int]$IntervalSec = 20,
    [ValidateRange(1, 200)][int]$TailLines = 8,
    [switch]$NoClear,
    [switch]$Once
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
        return $fullPath.Substring($repoRootFull.Length).TrimStart('\\')
    }

    return $Path
}

function Read-KeyValueFile {
    param([string]$Path)

    $map = [ordered]@{}
    foreach ($line in @(Get-Content -LiteralPath $Path -ErrorAction Stop)) {
        if ($line -match '^([^=]+)=(.*)$') {
            $map[$Matches[1].Trim()] = $Matches[2]
        }
    }

    return $map
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

function Get-AnchorMap {
    param([System.Collections.IDictionary]$Settings)

    $notes = if ($Settings.Contains('SESSION_FINAL_NOTES')) {
        [string]$Settings.SESSION_FINAL_NOTES
    }
    else {
        ''
    }

    $anchors = [ordered]@{}
    foreach ($key in @('run_dir', 'supervisor_log', 'companion_log', 'live_status', 'guard_log', 'guard_state')) {
        $anchors[$key] = Get-LatestAnchorValueFromNotes -Notes $notes -Key $key
    }

    return $anchors
}

function Get-LatestGuardArtifacts {
    $guardRoot = Join-Path $script:RepoRoot 'out\artifacts\ab_session_guard'
    if (-not (Test-Path -LiteralPath $guardRoot)) {
        return $null
    }

    $latest = Get-ChildItem -LiteralPath $guardRoot -Directory -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1

    if ($null -eq $latest) {
        return $null
    }

    return [pscustomobject]@{
        Dir = $latest.FullName
        Log = (Join-Path $latest.FullName 'guard.log')
        State = (Join-Path $latest.FullName 'guard_state.json')
    }
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

function Get-PathStatus {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
		return [pscustomobject]@{
			State = 'missing-anchor'
			Time = ''
		}
    }

    if (-not (Test-Path -LiteralPath $Path)) {
		return [pscustomobject]@{
			State = 'missing-path'
			Time = ''
		}
    }

    $item = Get-Item -LiteralPath $Path
	return [pscustomobject]@{
		State = 'ok'
		Time = $item.LastWriteTime.ToString('HH:mm:ss')
	}
}

function Get-DisplayPath {
    param(
        [string]$Path,
        [ValidateRange(20, 220)][int]$MaxLength = 92
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return '-'
    }

    $display = (Convert-ToRepoRelativePath -Path $Path).Replace('\\', '/')
    if ($display.Length -le $MaxLength) {
        return $display
    }

    return ('...' + $display.Substring($display.Length - ($MaxLength - 3)))
}

function Get-TimestampShort {
    param([string]$Line)

    if ($Line -match 'timestamp=([0-9]{4}-[0-9]{2}-[0-9]{2}\s+([0-9]{2}:[0-9]{2}:[0-9]{2}))') {
        return $Matches[2]
    }

    return '--:--:--'
}

function Get-PathLeafToken {
    param([string]$Token)

    if ([string]::IsNullOrWhiteSpace($Token)) {
        return ''
    }

    $normalized = $Token.Trim().TrimEnd(',', ';').Replace('/', '\\')
    return [System.IO.Path]::GetFileName($normalized)
}

function Format-SupervisorEventLine {
    param([string]$Line)

    $time = Get-TimestampShort -Line $Line

    if ($Line -match 'stage_final\s+stage=([A-Z])\s+result=([A-Za-z]+)\s+exit_code=([0-9-]+)') {
        return ('[{0}] stage_final stage={1} result={2} exit={3}' -f $time, $Matches[1], $Matches[2], $Matches[3])
    }

    if ($Line -match 'heartbeat.*stage=([A-Z]).*row_count=([0-9]+).*file_count=([0-9]+).*latest_path=([^ ]+).*remote_chain_count=([0-9]+)') {
        $leaf = Get-PathLeafToken -Token $Matches[4]
        return ('[{0}] heartbeat stage={1} rows={2} files={3} chain={4} latest={5}' -f $time, $Matches[1], $Matches[2], $Matches[3], $Matches[5], $leaf)
    }

    $compact = [regex]::Replace($Line, '^\[[^\]]+\]\s*', '')
    $compact = [regex]::Replace($compact, '\s+', ' ').Trim()
    if ($compact.Length -gt 135) {
        $compact = $compact.Substring(0, 132) + '...'
    }

    return ('[{0}] {1}' -f $time, $compact)
}

function Format-CompanionEventLine {
    param([string]$Line)

    $time = Get-TimestampShort -Line $Line

    if ($Line -match 'heartbeat.*stage=([A-Z]).*row_count=([0-9]+).*file_count=([0-9]+).*latest_path=([^ ]+).*remote_chain_count=([0-9]+)(?:.*supervisor_quiet=([A-Za-z]+))?') {
        $leaf = Get-PathLeafToken -Token $Matches[4]
        $quiet = if ($Matches[6]) { $Matches[6] } else { '?' }
        return ('[{0}] heartbeat stage={1} rows={2} files={3} chain={4} quiet={5} latest={6}' -f $time, $Matches[1], $Matches[2], $Matches[3], $Matches[5], $quiet, $leaf)
    }

    $compact = [regex]::Replace($Line, '^\[[^\]]+\]\s*', '')
    $compact = [regex]::Replace($compact, '\s+', ' ').Trim()
    if ($compact.Length -gt 135) {
        $compact = $compact.Substring(0, 132) + '...'
    }

    return ('[{0}] {1}' -f $time, $compact)
}

function Format-GuardEventLine {
    param([string]$Line)

    $time = Get-TimestampShort -Line $Line

    if ($Line -match 'incident\s+status=([A-Z]+)\s+a=([A-Z]+)\s+b=([A-Z]+)\s+evidence=([^ ]+)') {
        $incident = Get-PathLeafToken -Token $Matches[4]
        return ('[{0}] incident status={1} a={2} b={3} evidence={4}' -f $time, $Matches[1], $Matches[2], $Matches[3], $incident)
    }

    if ($Line -match 'recovery_triggered\s+stage=([A-Z])\s+attempt=([0-9]+)') {
        return ('[{0}] recovery_triggered stage={1} attempt={2}' -f $time, $Matches[1], $Matches[2])
    }

    if ($Line -match 'heartbeat\s+session=([A-Z]+)\s+a=([A-Z]+)\s+b=([A-Z]+)\s+running=([A-Za-z]+)\s+run_dir=([^ ]+)') {
        $runId = Get-PathLeafToken -Token $Matches[5]
        return ('[{0}] heartbeat session={1} a={2} b={3} running={4} run={5}' -f $time, $Matches[1], $Matches[2], $Matches[3], $Matches[4], $runId)
    }

    if ($Line -match 'loop_error\s+detail=(.+)$') {
        return ('[{0}] loop_error {1}' -f $time, $Matches[1])
    }

    $compact = [regex]::Replace($Line, '^\[[^\]]+\]\s*', '')
    $compact = [regex]::Replace($compact, '\s+', ' ').Trim()
    if ($compact.Length -gt 135) {
        $compact = $compact.Substring(0, 132) + '...'
    }

    return ('[{0}] {1}' -f $time, $compact)
}

function Write-EventSection {
    param(
        [string]$Title,
        [string[]]$Lines,
        [scriptblock]$Formatter
    )

    if ($Lines.Count -lt 1) {
        return $false
    }

    Write-Host ('  ' + $Title + ':')
    foreach ($line in $Lines) {
        $formatted = & $Formatter $line
        if (-not [string]::IsNullOrWhiteSpace($formatted)) {
            Write-Host ('    - ' + $formatted)
        }
    }

    return $true
}

function Get-LogTailMatch {
    param(
        [string]$Path,
        [string]$Pattern,
        [int]$Lines
    )

    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) {
        return @()
    }

    return @(Get-Content -LiteralPath $Path -Tail $Lines -ErrorAction SilentlyContinue | Where-Object { $_ -match $Pattern })
}

function Write-Snapshot {
    param([string]$StartFilePath)

    $settings = Read-KeyValueFile -Path $StartFilePath
    $anchors = Get-AnchorMap -Settings $settings

    $guardArtifacts = Get-LatestGuardArtifacts
    if ([string]::IsNullOrWhiteSpace([string]$anchors.guard_log) -and $null -ne $guardArtifacts -and (Test-Path -LiteralPath $guardArtifacts.Log)) {
        $anchors.guard_log = $guardArtifacts.Log
    }
    if ([string]::IsNullOrWhiteSpace([string]$anchors.guard_state) -and $null -ne $guardArtifacts -and (Test-Path -LiteralPath $guardArtifacts.State)) {
        $anchors.guard_state = $guardArtifacts.State
    }

    $resolved = [ordered]@{}
    foreach ($key in $anchors.Keys) {
        $resolved[$key] = Resolve-AnchorPath -Path ([string]$anchors[$key])
    }

    $now = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Write-Host ("[{0}] status  A={1}  B={2}  SESSION={3}" -f $now, [string]$settings.A_FINAL_STATUS, [string]$settings.B_FINAL_STATUS, [string]$settings.SESSION_FINAL_STATUS)
    Write-Host ''
    Write-Host 'Anchors'

    foreach ($key in @('run_dir', 'supervisor_log', 'companion_log', 'live_status', 'guard_log', 'guard_state')) {
        $path = [string]$resolved[$key]
        $status = Get-PathStatus -Path $path
        $statusText = if ($status.State -eq 'ok') { 'ok@' + $status.Time } else { $status.State }
        $pathText = Get-DisplayPath -Path $path
        Write-Host ("  {0,-14} {1,-14} {2}" -f ($key + ':'), $statusText, $pathText)
    }

    $supTail = Get-LogTailMatch -Path ([string]$resolved.supervisor_log) -Pattern 'heartbeat|stage_final|blocked|stop|complete|error|exception' -Lines $TailLines

    $compTail = Get-LogTailMatch -Path ([string]$resolved.companion_log) -Pattern 'heartbeat|blocked|unknown-stage-stall|error|exception' -Lines $TailLines

    $guardTail = Get-LogTailMatch -Path ([string]$resolved.guard_log) -Pattern 'incident|restart_begin|recovery_triggered|loop_error|manual_action_required|heartbeat' -Lines $TailLines

    Write-Host ''
    Write-Host ('Events (last ' + $TailLines + ' matching lines)')
    $printed = $false
    if (Write-EventSection -Title 'Supervisor' -Lines $supTail -Formatter { param($line) Format-SupervisorEventLine -Line $line }) {
        $printed = $true
    }
    if (Write-EventSection -Title 'Companion' -Lines $compTail -Formatter { param($line) Format-CompanionEventLine -Line $line }) {
        $printed = $true
    }
    if (Write-EventSection -Title 'Guard' -Lines $guardTail -Formatter { param($line) Format-GuardEventLine -Line $line }) {
        $printed = $true
    }
    if (-not $printed) {
        Write-Host '  (no matching events in current tail window)'
    }
}

$script:RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$startFilePath = Resolve-RepoPath -Path $StartFile

do {
    if (-not $NoClear.IsPresent) {
        Clear-Host
    }

    try {
        Write-Snapshot -StartFilePath $startFilePath
    }
    catch {
        Write-Host ("[WATCH-AB-LIGHT] error={0}" -f $_.Exception.Message)
    }

    if ($Once.IsPresent) {
        break
    }

    Start-Sleep -Seconds $IntervalSec
}
while ($true)