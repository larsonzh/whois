<#
Prune old artifact runs locally without touching Git index.

Usage examples:
  # 保留最近 10 次（默认），执行删除
  .\tools\dev\prune_artifacts.ps1

  # 仅演示将会删除哪些目录，不实际删除
  .\tools\dev\prune_artifacts.ps1 -DryRun

  # 指定保留数量或目录
  .\tools\dev\prune_artifacts.ps1 -Keep 15 -ArtifactsDir "out/artifacts"

Note:
  - 自 v3.2.0 起，out/artifacts 已加入 .gitignore 且不再被版本库跟踪；
    因此该脚本仅做本地磁盘清理，不进行任何 git 操作。
#>

param(
    [int]$Keep = 10,
    [string]$ArtifactsDir = "out/artifacts",
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not (Test-Path $ArtifactsDir)) {
    Write-Output "No artifacts dir: $ArtifactsDir"
    exit 0
}

$dirs = Get-ChildItem -LiteralPath $ArtifactsDir -Directory | Sort-Object Name -Descending
$prune = $dirs | Select-Object -Skip $Keep

if (-not $prune -or $prune.Count -eq 0) {
    Write-Output "Nothing to prune (<= $Keep runs present)."
    exit 0
}

$keepList = ($dirs | Select-Object -First $Keep).Name -join ", "
$pruneList = $prune.Name -join ", "
Write-Output "Keeping: $keepList"
Write-Output "Pruning: $pruneList"

if ($DryRun) {
    Write-Output "DryRun: no deletion performed."
    exit 0
}

$prunePaths = $prune | ForEach-Object { $_.FullName }
foreach ($p in $prunePaths) {
    if (Test-Path -LiteralPath $p) {
        Remove-Item -LiteralPath $p -Recurse -Force
    }
}

Write-Output "Prune done."
