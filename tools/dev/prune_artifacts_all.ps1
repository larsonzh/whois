param(
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$pruneScript = Join-Path $PSScriptRoot "prune_artifacts.ps1"

if (-not (Test-Path -LiteralPath $pruneScript)) {
    throw "Missing script: $pruneScript"
}

$plans = @(
    @{ Keep = 25; ArtifactsDir = "out/artifacts" },
    @{ Keep = 8; ArtifactsDir = "out/artifacts/batch_raw" },
    @{ Keep = 8; ArtifactsDir = "out/artifacts/batch_health" },
    @{ Keep = 8; ArtifactsDir = "out/artifacts/batch_plan" },
    @{ Keep = 8; ArtifactsDir = "out/artifacts/batch_planb" },
    @{ Keep = 8; ArtifactsDir = "out/artifacts/redirect_matrix_10x6" },
    @{ Keep = 8; ArtifactsDir = "out/artifacts/oneclick_dryrun_guard" },
    @{ Keep = 8; ArtifactsDir = "out/artifacts/dev_verify_multiround" },
    @{ Keep = 8; ArtifactsDir = "out/artifacts/d6_consistency_double_round" },
    @{ Keep = 8; ArtifactsDir = "out/artifacts/cidr_body_contract" },
    @{ Keep = 8; ArtifactsDir = "out/artifacts/preclass_matrix" },
    @{ Keep = 8; ArtifactsDir = "out/artifacts/preclass_p1_matrix" },
    @{ Keep = 8; ArtifactsDir = "out/artifacts/preclass_table_guard" },
    @{ Keep = 8; ArtifactsDir = "out/artifacts/redirect_matrix" },
    @{ Keep = 8; ArtifactsDir = "out/artifacts/step47_ab" },
    @{ Keep = 8; ArtifactsDir = "out/artifacts/step47_matrix" },
    @{ Keep = 8; ArtifactsDir = "out/artifacts/step47_preclass_preflight" },
    @{ Keep = 8; ArtifactsDir = "out/artifacts/step47_prerelease" },
    @{ Keep = 8; ArtifactsDir = "out/artifacts/step47_rollback" }
)

foreach ($plan in $plans) {
    $dirPath = Join-Path $repoRoot $plan.ArtifactsDir
    Write-Output ("[PRUNE-ALL] keep={0} dir={1}" -f $plan.Keep, $dirPath)

    $invokeArgs = @{
        Keep = $plan.Keep
        ArtifactsDir = $dirPath
    }

    if ($DryRun.IsPresent) {
        $invokeArgs["DryRun"] = $true
    }

    & $pruneScript @invokeArgs
}

Write-Output "[PRUNE-ALL] done"
