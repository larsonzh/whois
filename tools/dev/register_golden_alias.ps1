param(
    [string]$AliasName = "golden-suite"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2

$targetScript = Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\test\golden_check_batch_suite.ps1")
Set-Alias -Name $AliasName -Value $targetScript.ProviderPath -Scope Global
Write-Host "Alias '$AliasName' now points to $($targetScript.ProviderPath)" -ForegroundColor Green
Write-Host "Example:" -ForegroundColor Gray
Write-Host "$AliasName -RawLog ./out/artifacts/20251128-000717/build_out/smoke_test.log `\" -HealthFirstLog ./out/artifacts/20251128-002850/build_out/smoke_test.log `\" -PlanALog ./out/artifacts/20251128-004128/build_out/smoke_test.log -ExtraArgs --strict" -ForegroundColor Gray
Write-Host "Add this script to your PowerShell profile to auto-register the alias on new sessions." -ForegroundColor Gray
