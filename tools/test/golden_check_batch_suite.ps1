param(
    [string]$RawLog = "",
    [string]$HealthFirstLog = "",
    [string]$PlanALog = "",
    [string]$ExtraArgs = "",
    [string]$PrefLabels = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2

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
    if ([string]::IsNullOrWhiteSpace($Candidate) -or $Candidate -eq "NONE") {
        return $null
    }
    $target = $Candidate
    if (-not [IO.Path]::IsPathRooted($Candidate)) {
        $target = Join-Path -Path $RepoRoot -ChildPath $Candidate
    }
    return (Resolve-Path -LiteralPath $target).ProviderPath
}

$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\..")).ProviderPath
$repoMsys = Convert-ToMsysPath -Path $repoRoot

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
if (-not [string]::IsNullOrWhiteSpace($ExtraArgs) -and $ExtraArgs -ne "NONE") {
    $extraSegment = " $ExtraArgs"
}
$prefSegment = ""
if (-not [string]::IsNullOrWhiteSpace($PrefLabels) -and $PrefLabels -ne "NONE") {
    $prefSegment = " --pref-labels '$PrefLabels'"
}

if ([string]::IsNullOrWhiteSpace($RawLog) -and [string]::IsNullOrWhiteSpace($HealthFirstLog) -and [string]::IsNullOrWhiteSpace($PlanALog)) {
    throw "Please provide at least one log path via -RawLog/-HealthFirstLog/-PlanALog."
}

function Invoke-GoldenPreset {
    param(
        [string]$Preset,
        [string]$DisplayName,
        [string]$LogInput
    )
    if ([string]::IsNullOrWhiteSpace($LogInput)) {
        return
    }
    $resolved = Resolve-LogPath -Candidate $LogInput -RepoRoot $repoRoot
    $logMsys = Convert-ToMsysPath -Path $resolved
    Write-Host "[golden-suite] $DisplayName preset=$Preset log=$resolved" -ForegroundColor Cyan
    $command = "cd '$repoMsys' && ./tools/test/golden_check_batch_presets.sh $Preset -l '$logMsys'$prefSegment$extraSegment"
    & $bashPath -lc $command
}

Invoke-GoldenPreset -Preset "raw" -DisplayName "Raw" -LogInput $RawLog
Invoke-GoldenPreset -Preset "health-first" -DisplayName "Health-first" -LogInput $HealthFirstLog
Invoke-GoldenPreset -Preset "plan-a" -DisplayName "Plan-A" -LogInput $PlanALog
