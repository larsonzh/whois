param(
    [string]$StartFile = 'tmp\unattended_ab_start_20260418-2200.md',
    [ValidateRange(1, 8)][int]$StartRound = 7,
    [ValidateRange(1, 8)][int]$EndRound = 8
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

    return (Resolve-Path -LiteralPath (Join-Path $repoRoot $Path)).Path
}

function Read-KeyValueFile {
    param([string]$Path)

    $map = [ordered]@{}
    foreach ($line in @(Get-Content -LiteralPath $Path)) {
        if ($line -match '^([^=]+)=(.*)$') {
            $map[$Matches[1].Trim()] = $Matches[2]
        }
    }

    return $map
}

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

function Quote-ArgumentIfNeeded {
    param([string]$Value)

    if ($null -eq $Value) {
        return '""'
    }

    if ($Value -match '[\s"]') {
        return '"' + $Value.Replace('"', '\"') + '"'
    }

    return $Value
}

if ($StartRound -gt $EndRound) {
    throw 'StartRound must be less than or equal to EndRound.'
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$settings = Read-KeyValueFile -Path (Resolve-RepoPath -Path $StartFile)

$entryScriptPath = Resolve-RepoPath -Path 'tools/test/start_dev_verify_8round_multiround.ps1'
$powershellPath = Join-Path $PSHOME 'powershell.exe'
if (-not (Test-Path -LiteralPath $powershellPath)) {
    $powershellPath = 'powershell.exe'
}

$taskDefinition = [string]$settings.A_TASK_DEFINITION
if ([string]::IsNullOrWhiteSpace($taskDefinition)) {
    throw 'A_TASK_DEFINITION is missing in start file.'
}

$argumentList = @(
    '-NoExit',
    '-NoProfile',
    '-ExecutionPolicy', 'Bypass',
    '-File', $entryScriptPath,
    '-CodeStepResetPolicy', [string]$settings.RESET_POLICY_A,
    '-TaskDefinitionFile', $taskDefinition,
    '-StartRound', [string]$StartRound,
    '-EndRound', [string]$EndRound,
    '-DevVerifyStride', [string]$settings.DEV_VERIFY_STRIDE_A,
    '-VerifyExecutionProfile', [string]$settings.VERIFY_EXECUTION_PROFILE,
    '-EnableGuardedFastMode', [string]$settings.ENABLE_GUARDED_FAST_MODE,
    '-EnableGateOnlySourceDrivenSkip', [string]$settings.ENABLE_GATE_ONLY_SOURCE_DRIVEN_SKIP,
    '-RbPreflight', [string]$settings.RB_PREFLIGHT,
    '-RbPreclassTableGuard', [string]$settings.RB_PRECLASS_TABLE_GUARD,
    '-QuietTerminalOutput', 'true',
    '-TerminalWatchdogMode', [string]$settings.TERMINAL_WATCHDOG_MODE,
    '-TerminalWatchdogIntervalSec', [string]$settings.TERMINAL_WATCHDOG_INTERVAL_SEC,
    '-TerminalWatchdogMinAgeSec', [string]$settings.TERMINAL_WATCHDOG_MIN_AGE_SEC,
    '-QuietRemoteBuildLogs', 'false',
    '-TaskDesignQualityPolicy', [string]$settings.TASK_DESIGN_QUALITY_POLICY,
    '-UnknownNoOpBudget', [string]$settings.UNKNOWN_NOOP_BUDGET,
    '-UnknownNoOpConsecutiveLimit', [string]$settings.UNKNOWN_NOOP_CONSECUTIVE_LIMIT,
    '-KeyPath', [string]$settings.REMOTE_KEYPATH,
    '-RemoteIp', [string]$settings.REMOTE_IP,
    '-User', [string]$settings.REMOTE_USER,
    '-Queries', (Quote-ArgumentIfNeeded -Value ([string]$settings.QUERIES))
)

$disableUnknownNoOpBudgetGate = $false
if ($settings.Contains('DISABLE_UNKNOWN_NOOP_BUDGET_GATE')) {
    $rawDisableUnknownNoOpBudgetGate = [string]$settings.DISABLE_UNKNOWN_NOOP_BUDGET_GATE
    if (-not [string]::IsNullOrWhiteSpace($rawDisableUnknownNoOpBudgetGate)) {
        $disableUnknownNoOpBudgetGate = $rawDisableUnknownNoOpBudgetGate.Trim().ToLowerInvariant() -in @('1', 'true', 'yes', 'on')
    }
}

if ($disableUnknownNoOpBudgetGate) {
    $argumentList += '-DisableUnknownNoOpBudgetGate'
}

$sessionRoot = Join-Path $repoRoot 'out\artifacts\dev_verify_multiround'
$launchTime = Get-Date
$processInfo = Start-Process -FilePath $powershellPath -WorkingDirectory $repoRoot -ArgumentList $argumentList -PassThru

$runDir = $null
for ($attempt = 0; $attempt -lt 24; $attempt++) {
    $runDir = Get-LatestTimestampedDirectory -Root $sessionRoot -After $launchTime
    if ($null -ne $runDir) {
        break
    }

    Start-Sleep -Seconds 5
}

$runDirPath = if ($null -ne $runDir) { $runDir.FullName } else { '' }
Write-Output ("[OPEN-AB-RESUME] pid={0} launcher_pid={1} start_round={2} end_round={3} run_dir={4} task={5}" -f $processInfo.Id, $PID, $StartRound, $EndRound, $runDirPath, $taskDefinition)