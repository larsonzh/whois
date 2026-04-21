param(
    [string]$StartFile = 'tmp\unattended_ab_start_20260418-2200.md',
    [AllowEmptyString()][string]$SupervisorLog = '',
    [ValidateRange(15, 300)][int]$PollSec = 60,
    [ValidateRange(5, 120)][int]$SupervisorQuietMinutes = 5,
    [ValidateRange(10, 180)][int]$UnknownStageStallMinutes = 20
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-LatestTimestampedDirectory {
    param(
        [string]$Root,
        [datetime]$After
    )

    if (-not (Test-Path -LiteralPath $Root)) {
        return $null
    }

    $dirs = Get-ChildItem -LiteralPath $Root -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^[0-9]{8}-[0-9]{6}$' }

    if ($null -ne $After) {
        $dirs = @($dirs | Where-Object { $_.CreationTime -ge $After.AddSeconds(-2) -or $_.LastWriteTime -ge $After.AddSeconds(-2) })
    }

    $candidates = @($dirs | Sort-Object CreationTime, LastWriteTime -Descending | Select-Object -First 1)
    if ($candidates.Count -lt 1) {
        return $null
    }

    return $candidates[0]
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$scriptPath = Join-Path $repoRoot 'tools\test\unattended_ab_companion.ps1'
$powershellPath = Join-Path $PSHOME 'powershell.exe'
if (-not (Test-Path -LiteralPath $powershellPath)) {
    $powershellPath = 'powershell.exe'
}

$launchTime = Get-Date

$argumentList = @(
    '-NoExit',
    '-NoProfile',
    '-ExecutionPolicy', 'Bypass',
    '-File', $scriptPath,
    '-StartFile', $StartFile,
    '-PollSec', [string]$PollSec,
    '-SupervisorQuietMinutes', [string]$SupervisorQuietMinutes,
    '-UnknownStageStallMinutes', [string]$UnknownStageStallMinutes
)

if (-not [string]::IsNullOrWhiteSpace($SupervisorLog)) {
    $argumentList += @('-SupervisorLog', $SupervisorLog)
}

$processInfo = Start-Process -FilePath $powershellPath -WorkingDirectory $repoRoot -ArgumentList $argumentList -PassThru
$companionRoot = Join-Path $repoRoot 'out\artifacts\ab_companion'
$companionDir = $null
for ($attempt = 0; $attempt -lt 24; $attempt++) {
    $companionDir = Get-LatestTimestampedDirectory -Root $companionRoot -After $launchTime
    if ($null -ne $companionDir) {
        break
    }

    Start-Sleep -Seconds 5
}

$companionLog = if ($null -ne $companionDir) {
    Join-Path $companionDir.FullName 'companion.log'
}
else {
    ''
}

Write-Output ("[OPEN-AB-COMPANION] pid={0} launcher_pid={1} script={2} start_file={3} companion_log={4}" -f $processInfo.Id, $PID, $scriptPath, $StartFile, $companionLog)