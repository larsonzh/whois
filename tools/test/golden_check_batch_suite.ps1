param(
    [string]$RawLog = "",
    [string]$HealthFirstLog = "",
    [string]$PlanALog = "",
    [string]$ExtraArgs = ""
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
$bashPath = (Get-Command bash.exe).Source
$extraSegment = ""
if (-not [string]::IsNullOrWhiteSpace($ExtraArgs) -and $ExtraArgs -ne "NONE") {
    $extraSegment = " $ExtraArgs"
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
    $command = "cd '$repoMsys' && ./tools/test/golden_check_batch_presets.sh $Preset -l '$logMsys'$extraSegment"
    & $bashPath -lc $command
}

Invoke-GoldenPreset -Preset "raw" -DisplayName "Raw" -LogInput $RawLog
Invoke-GoldenPreset -Preset "health-first" -DisplayName "Health-first" -LogInput $HealthFirstLog
Invoke-GoldenPreset -Preset "plan-a" -DisplayName "Plan-A" -LogInput $PlanALog
