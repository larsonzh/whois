Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'task_definition_target_set_delta.ps1')

function New-Snapshot([string]$HashA, [string]$HashB) {
    return [pscustomobject]@{
        TargetSetSha256 = 'frozen-target-set'
        Targets = @(
            [pscustomobject]@{ Id = 'source_a'; Path = 'src/a.c'; Exists = $true; Sha256 = $HashA },
            [pscustomobject]@{ Id = 'source_b'; Path = 'src/b.c'; Exists = $true; Sha256 = $HashB }
        )
    }
}

$unchanged = Compare-TaskTargetSetSnapshot -Before (New-Snapshot 'a1' 'b1') -After (New-Snapshot 'a1' 'b1')
if ($unchanged.Changed -or @($unchanged.ChangedTargets).Count -ne 0) { throw 'all-unchanged target set was classified as changed' }

$mixed = Compare-TaskTargetSetSnapshot -Before (New-Snapshot 'a1' 'b1') -After (New-Snapshot 'a2' 'b1')
if (-not $mixed.Changed -or [string]::Join(',', @($mixed.ChangedTargets)) -ne 'source_a') { throw 'changed+unchanged target set was not aggregated as changed' }

$wrapperPath = Join-Path $PSScriptRoot 'start_dev_verify_8round_multiround.ps1'
$wrapperText = [IO.File]::ReadAllText($wrapperPath)
if (-not $wrapperText.Contains('Compare-TaskTargetSetSnapshot -Before $beforeTargetSetSnapshot -After $afterTargetSetSnapshot')) {
    throw 'wrapper does not consume target-set delta helper'
}

Write-Output '[TARGET-SET-DELTA-REGRESSION] case=all-unchanged status=pass'
Write-Output '[TARGET-SET-DELTA-REGRESSION] case=changed-plus-unchanged-aggregates-changed status=pass'
Write-Output '[TARGET-SET-DELTA-REGRESSION] status=PASS'