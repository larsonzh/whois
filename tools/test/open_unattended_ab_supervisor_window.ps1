param(
    [string]$StartFile = 'tmp\unattended_ab_start_20260418-2200.md',
    [AllowEmptyString()][string]$CurrentARunDir = '',
    [ValidateRange(1, 8)][int]$CurrentAStartRound = 1,
    [ValidateRange(15, 300)][int]$PollSec = 60,
    [ValidateRange(0, 3)][int]$MaxStageRestarts = 2
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
$scriptPath = Join-Path $repoRoot 'tools\test\unattended_ab_supervisor.ps1'
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
    '-CurrentAStartRound', [string]$CurrentAStartRound,
    '-PollSec', [string]$PollSec,
    '-MaxStageRestarts', [string]$MaxStageRestarts
)

if (-not [string]::IsNullOrWhiteSpace($CurrentARunDir)) {
    $argumentList += @('-CurrentARunDir', $CurrentARunDir)
}

$processInfo = Start-Process -FilePath $powershellPath -WorkingDirectory $repoRoot -ArgumentList $argumentList -PassThru
$supervisorRoot = Join-Path $repoRoot 'out\artifacts\ab_supervisor'
$supervisorDir = $null
for ($attempt = 0; $attempt -lt 24; $attempt++) {
    $supervisorDir = Get-LatestTimestampedDirectory -Root $supervisorRoot -After $launchTime
    if ($null -ne $supervisorDir) {
        break
    }

    Start-Sleep -Seconds 5
}

$supervisorLog = if ($null -ne $supervisorDir) {
    Join-Path $supervisorDir.FullName 'supervisor.log'
}
else {
    ''
}

Write-Output ("[OPEN-AB-SUPERVISOR] pid={0} launcher_pid={1} script={2} start_file={3} supervisor_log={4}" -f $processInfo.Id, $PID, $scriptPath, $StartFile, $supervisorLog)
