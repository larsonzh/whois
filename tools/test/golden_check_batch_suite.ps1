param(
    [string]$RawLog = "",
    [string]$HealthFirstLog = "",
    [string]$PlanALog = "",
    [string]$PlanBLog = "",
    [string]$ExtraArgs = "",
    [string]$PrefLabels = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2
$scriptStopwatch = [System.Diagnostics.Stopwatch]::StartNew()

function Is-SkipInput {
    param([string]$Value)
    if ($null -eq $Value) {
        return $true
    }
    $normalized = Normalize-Input -Value $Value
    if ([string]::IsNullOrWhiteSpace($normalized)) {
        return $true
    }
    return $normalized -match '^(?i)NONE$'
}

function Normalize-Input {
    param([string]$Value)
    if ($null -eq $Value) {
        return ""
    }
    $normalized = $Value
    if ($normalized.StartsWith("__WC_ARG__")) {
        $normalized = $normalized.Substring(10)
    }
    $trimmed = $normalized.Trim()
    $trimmed = $trimmed.Trim('"', "'").Trim()
    return $trimmed
}

function Fail-Friendly {
    param([string]$Message)
    Write-Host "[golden-suite][ERROR] $Message" -ForegroundColor Red
    $scriptStopwatch.Stop()
    Write-Host ("[golden-suite] Elapsed: {0:N3}s" -f $scriptStopwatch.Elapsed.TotalSeconds) -ForegroundColor DarkCyan
    exit 2
}

function Convert-ToMsysPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    $normalized = $Path -replace "\\", "/"
    if ($normalized -match '^([A-Za-z]):') {
        $drive = $matches[1].ToLower()
        return "/$drive" + $normalized.Substring(2)
    }
    return $normalized
}

function Resolve-LogPath {
    param(
        [string]$Candidate,
        [string]$RepoRoot
    )
    if (Is-SkipInput -Value $Candidate) {
        return $null
    }
    $normalized = Normalize-Input -Value $Candidate
    if ([string]::IsNullOrWhiteSpace($normalized)) {
        return $null
    }
    $target = $normalized
    if (-not [IO.Path]::IsPathRooted($normalized)) {
        $target = Join-Path -Path $RepoRoot -ChildPath $normalized
    }
    if (-not (Test-Path -LiteralPath $target)) {
        throw "Log path not found: $target"
    }
    return (Resolve-Path -LiteralPath $target).ProviderPath
}

function Get-LatestLogPathForPreset {
    param(
        [string]$Preset,
        [string]$RepoRoot
    )
    $subdir = switch ($Preset) {
        "raw" { "out/artifacts/batch_raw" }
        "health-first" { "out/artifacts/batch_health" }
        "plan-a" { "out/artifacts/batch_plan" }
        "plan-b" { "out/artifacts/batch_planb" }
        default { throw "Unknown preset for latest log: $Preset" }
    }
    $base = Join-Path -Path $RepoRoot -ChildPath $subdir
    if (-not (Test-Path -LiteralPath $base)) {
        throw "Artifacts directory missing: $base"
    }
    $latest = Get-ChildItem -LiteralPath $base -Directory | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $latest) {
        throw "No timestamped artifacts under $base"
    }
    $logPath = Join-Path $latest.FullName "build_out/smoke_test.log"
    if (-not (Test-Path -LiteralPath $logPath)) {
        throw "smoke_test.log not found: $logPath"
    }
    return $logPath
}

$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\..")).ProviderPath
$repoMsys = Convert-ToMsysPath -Path $repoRoot

$RawLog = Normalize-Input -Value $RawLog
$HealthFirstLog = Normalize-Input -Value $HealthFirstLog
$PlanALog = Normalize-Input -Value $PlanALog
$PlanBLog = Normalize-Input -Value $PlanBLog
$ExtraArgs = Normalize-Input -Value $ExtraArgs
$PrefLabels = Normalize-Input -Value $PrefLabels

function Resolve-GitBashPath {
    $candidates = @()
    try {
        $candidates += (Get-Command bash.exe -All -ErrorAction Stop)
    } catch {
        # no bash.exe on PATH, continue with manual probes below
    }

    $fromPath = @($candidates | Where-Object { $_.Source -match '(?i)\\Git\\bin\\bash\.exe$' })
    if ($fromPath.Count -gt 0) {
        return $fromPath[0].Source
    }

    $manualProbes = @()
    if ($env:ProgramFiles) {
        $manualProbes += Join-Path $env:ProgramFiles "Git\bin\bash.exe"
    }
    if (${env:ProgramFiles(x86)}) {
        $manualProbes += Join-Path ${env:ProgramFiles(x86)} "Git\bin\bash.exe"
    }
    $manualHit = @($manualProbes | Where-Object { Test-Path $_ })
    if ($manualHit.Count -gt 0) {
        return $manualHit[0]
    }

    if ($candidates.Count -gt 0) {
        $fallback = $candidates[0].Source
        if ($fallback -match '(?i)\\system32\\bash\.exe$') {
            Write-Warning "Detected Windows Subsystem for Linux bash (System32). Please install Git for Windows or add its bash.exe to PATH to avoid WSL prompts. Falling back to $fallback."
        }
        return $fallback
    }

    throw "Cannot locate Git Bash (bash.exe). Please install Git for Windows and ensure bash.exe is on PATH."
}

$bashPath = Resolve-GitBashPath
$extraSegment = ""
$extraNormalized = Normalize-Input -Value $ExtraArgs
if (-not [string]::IsNullOrWhiteSpace($extraNormalized) -and $extraNormalized -ne "NONE") {
    $extraSegment = " $extraNormalized"
}
$prefSegment = ""
$prefNormalized = Normalize-Input -Value $PrefLabels
if (-not [string]::IsNullOrWhiteSpace($prefNormalized) -and $prefNormalized -ne "NONE") {
    $prefSegment = " --pref-labels '$prefNormalized'"
}

if ((Is-SkipInput -Value $RawLog) -and (Is-SkipInput -Value $HealthFirstLog) -and (Is-SkipInput -Value $PlanALog) -and (Is-SkipInput -Value $PlanBLog)) {
    Write-Host "[golden-suite] No presets selected (all blank/NONE)." -ForegroundColor Yellow
    $scriptStopwatch.Stop()
    Write-Host ("[golden-suite] Elapsed: {0:N3}s" -f $scriptStopwatch.Elapsed.TotalSeconds) -ForegroundColor DarkCyan
    exit 0
}

function Invoke-GoldenPreset {
    param(
        [string]$Preset,
        [string]$DisplayName,
        [string]$LogInput
    )
    $logValue = Normalize-Input -Value $LogInput
    if ([string]::IsNullOrWhiteSpace($logValue) -or $logValue -match '^(?i)NONE$') {
        return
    }
    $resolved = $null
    try {
        if ($logValue -match '^(?i)(AUTO|LATEST)$') {
            $resolved = Get-LatestLogPathForPreset -Preset $Preset -RepoRoot $repoRoot
        } else {
            $resolved = Resolve-LogPath -Candidate $logValue -RepoRoot $repoRoot
        }
    } catch {
        Fail-Friendly -Message $_.Exception.Message
    }
    if ([string]::IsNullOrWhiteSpace($resolved)) {
        Fail-Friendly -Message "Log path not resolved for preset: $Preset"
    }
    $logMsys = Convert-ToMsysPath -Path $resolved
    Write-Host "[golden-suite] $DisplayName preset=$Preset log=$resolved" -ForegroundColor Cyan
    $command = "cd '$repoMsys' && ./tools/test/golden_check_batch_presets.sh $Preset -l '$logMsys'$prefSegment$extraSegment"
    & $bashPath -lc $command
}

Invoke-GoldenPreset -Preset "raw" -DisplayName "Raw" -LogInput $RawLog
Invoke-GoldenPreset -Preset "health-first" -DisplayName "Health-first" -LogInput $HealthFirstLog
Invoke-GoldenPreset -Preset "plan-a" -DisplayName "Plan-A" -LogInput $PlanALog
Invoke-GoldenPreset -Preset "plan-b" -DisplayName "Plan-B" -LogInput $PlanBLog

$scriptStopwatch.Stop()
Write-Host ("[golden-suite] Elapsed: {0:N3}s" -f $scriptStopwatch.Elapsed.TotalSeconds) -ForegroundColor DarkCyan
