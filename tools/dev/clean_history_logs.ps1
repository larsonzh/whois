<#
Clear history logs under the repository's local working directories.

Behavior:
    - Removes all current contents under out/artifacts and tmp/logs.
    - Keeps the root directories themselves.
    - Does not touch source files, release artifacts, or Git index state.

Difference from tools/dev/prune_artifacts_all.ps1:
    - prune_artifacts_all.ps1 is retention-based and keeps recent artifact runs.
    - this script is wipe-based and removes all current history under the target paths.

Usage examples:
    .\tools\dev\clean_history_logs.ps1
    .\tools\dev\clean_history_logs.ps1 -DryRun
#>

param(
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$targets = @(
    "out/artifacts",
    "tmp/logs"
)

foreach ($target in $targets) {
    $fullPath = Join-Path $repoRoot $target
    if (-not (Test-Path -LiteralPath $fullPath)) {
        Write-Output ("[CLEAN-HISTORY] skip missing: {0}" -f $fullPath)
        continue
    }

    $items = @(Get-ChildItem -LiteralPath $fullPath -Force)
    if ($items.Count -eq 0) {
        Write-Output ("[CLEAN-HISTORY] empty: {0}" -f $fullPath)
        continue
    }

    Write-Output ("[CLEAN-HISTORY] target={0} items={1}" -f $fullPath, $items.Count)

    foreach ($item in $items) {
        if ($DryRun.IsPresent) {
            Write-Output ("[CLEAN-HISTORY] dry-run remove: {0}" -f $item.FullName)
            continue
        }

        Remove-Item -LiteralPath $item.FullName -Recurse -Force
        Write-Output ("[CLEAN-HISTORY] removed: {0}" -f $item.FullName)
    }
}

Write-Output "[CLEAN-HISTORY] done"