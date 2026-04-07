param(
    [switch]$Reset,
    [string]$StateDir = "",
    [string]$IncludeFile = "",
    [string]$SourceFile = ""
)

$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path

if ([string]::IsNullOrWhiteSpace($StateDir)) {
    $StateDir = Join-Path $repoRoot "out\artifacts\autopilot_dev_recheck_8round\_code_step_state"
}
if ([string]::IsNullOrWhiteSpace($IncludeFile)) {
    $IncludeFile = Join-Path $repoRoot "include\wc\wc_autopilot_round_marker.h"
}
if ([string]::IsNullOrWhiteSpace($SourceFile)) {
    $SourceFile = Join-Path $repoRoot "src\core\wc_autopilot_round_marker.c"
}

$stateFile = Join-Path $StateDir "state.json"

if ($Reset) {
    if (Test-Path -LiteralPath $StateDir) {
        Remove-Item -LiteralPath $StateDir -Recurse -Force
    }
    Write-Output "[CODE-STEP] state_reset=true state_dir=$StateDir"
    exit 0
}

New-Item -ItemType Directory -Path $StateDir -Force | Out-Null

if (-not (Test-Path -LiteralPath $IncludeFile)) {
    $headerInit = @"
#ifndef WC_AUTOPILOT_ROUND_MARKER_H
#define WC_AUTOPILOT_ROUND_MARKER_H

#define WC_AUTOPILOT_ROUND_MARKER "INIT"
#define WC_AUTOPILOT_ROUND_NOTE   "INIT"

const char *wc_autopilot_round_marker_value(void);

#endif
"@
    $headerInit | Out-File -FilePath $IncludeFile -Encoding utf8
}

if (-not (Test-Path -LiteralPath $SourceFile)) {
    $sourceInit = @"
#include "wc/wc_autopilot_round_marker.h"

const char *wc_autopilot_round_marker_value(void) {
    return WC_AUTOPILOT_ROUND_MARKER;
}
"@
    $sourceInit | Out-File -FilePath $SourceFile -Encoding utf8
}

$state = [pscustomobject]@{
    invocationCount = 0
    lastRound = ""
    lastTimestamp = ""
}

if (Test-Path -LiteralPath $stateFile) {
    try {
        $rawState = Get-Content -LiteralPath $stateFile -Raw
        if (-not [string]::IsNullOrWhiteSpace($rawState)) {
            $state = $rawState | ConvertFrom-Json
        }
    }
    catch {
        Write-Warning "[CODE-STEP] invalid state file, resetting: $stateFile"
    }
}

$next = [int]$state.invocationCount + 1
$roundTag = switch ($next) {
    1 { "D1" }
    2 { "D2" }
    3 { "D3" }
    4 { "D4" }
    default { "VERIFY_OR_EXTRA" }
}

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"

if ($next -le 4) {
    $marker = "$roundTag-$timestamp"
    $note = "placeholder-change-$roundTag"
    $markerLine = "#define WC_AUTOPILOT_ROUND_MARKER `"$marker`""
    $noteLine = "#define WC_AUTOPILOT_ROUND_NOTE   `"$note`""

    $headerText = Get-Content -LiteralPath $IncludeFile -Raw
    $headerText = [regex]::Replace($headerText, '(?m)^#define\s+WC_AUTOPILOT_ROUND_MARKER\s+".*"\s*$', $markerLine)
    $headerText = [regex]::Replace($headerText, '(?m)^#define\s+WC_AUTOPILOT_ROUND_NOTE\s+".*"\s*$', $noteLine)
    $headerText | Out-File -FilePath $IncludeFile -Encoding utf8

    $sourceText = Get-Content -LiteralPath $SourceFile -Raw
    $sourceText = $sourceText.TrimEnd() + "`r`n/* AUTOPILOT-CODE-STEP $roundTag applied $timestamp */`r`n"
    $sourceText | Out-File -FilePath $SourceFile -Encoding utf8

    Write-Output "[CODE-STEP] round=$roundTag action=applied include=$IncludeFile src=$SourceFile marker=$marker"
}
else {
    Write-Output "[CODE-STEP] round=$roundTag action=no-op reason=dev-rounds-completed"
}

$stateOut = [pscustomobject]@{
    invocationCount = $next
    lastRound = $roundTag
    lastTimestamp = $timestamp
}

$stateOut | ConvertTo-Json | Out-File -FilePath $stateFile -Encoding utf8
