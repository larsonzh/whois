param(
    [string]$StartFile = 'testdata/unattended_start/active/unattended_ab_start_20261031-20261115.md',
    [string]$OutDirRoot = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'unattended_exit_result.ps1')
$script:UnhandledExitTag = 'ROUTE-GUARD-SMOKE-SUITE'

function Resolve-RepoRoot {
    return (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
}

function Invoke-SmokeScript {
    param(
        [string]$ScriptPath,
        [string[]]$Arguments
    )

    $output = @(& powershell -NoProfile -ExecutionPolicy Bypass -File $ScriptPath @Arguments 2>&1 | ForEach-Object { [string]$_ })
    return [pscustomobject]@{
        Output = $output
        ExitCode = $LASTEXITCODE
    }
}

function Get-ResultLine {
    param(
        [string[]]$Lines,
        [string]$Prefix
    )

    foreach ($line in $Lines) {
        if ($line.StartsWith($Prefix)) {
            return $line
        }
    }

    return ''
}

$repoRoot = Resolve-RepoRoot
if ([string]::IsNullOrWhiteSpace($OutDirRoot)) {
    $OutDirRoot = Join-Path $repoRoot 'out\artifacts\route_guard_smoke_suite'
}

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$outDir = Join-Path $OutDirRoot $stamp
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

$triggerScript = Join-Path $repoRoot 'tools\test\trigger_route_guard_gate_smoke.ps1'
$dispatchScript = Join-Path $repoRoot 'tools\test\dispatch_route_guard_live_override_smoke.ps1'
$classificationScript = Join-Path $repoRoot 'tools\test\classification_contract_tests.ps1'

if (-not (Test-Path -LiteralPath $triggerScript)) {
    throw ('trigger smoke not found: {0}' -f $triggerScript)
}
if (-not (Test-Path -LiteralPath $dispatchScript)) {
    throw ('dispatch smoke not found: {0}' -f $dispatchScript)
}
if (-not (Test-Path -LiteralPath $classificationScript)) {
    throw ('classification contract test not found: {0}' -f $classificationScript)
}

$triggerResult = Invoke-SmokeScript -ScriptPath $triggerScript -Arguments @('-StartFile', $StartFile)
$dispatchResult = Invoke-SmokeScript -ScriptPath $dispatchScript -Arguments @('-StartFile', $StartFile)
$classificationResult = Invoke-SmokeScript -ScriptPath $classificationScript -Arguments @()

$triggerLog = Join-Path $outDir 'trigger_smoke.log'
$dispatchLog = Join-Path $outDir 'dispatch_smoke.log'
$classificationLog = Join-Path $outDir 'classification_contract.log'
$triggerResult.Output | Out-File -LiteralPath $triggerLog -Encoding utf8
$dispatchResult.Output | Out-File -LiteralPath $dispatchLog -Encoding utf8
$classificationResult.Output | Out-File -LiteralPath $classificationLog -Encoding utf8

$triggerSummaryLine = Get-ResultLine -Lines $triggerResult.Output -Prefix '[TRIGGER-ROUTE-GATE-SMOKE] checks '
$dispatchSummaryLine = Get-ResultLine -Lines $dispatchResult.Output -Prefix '[DISPATCH-LIVE-OVERRIDE-SMOKE] checks '
$classificationSummaryLine = Get-ResultLine -Lines $classificationResult.Output -Prefix '[CLASSIFICATION-CONTRACT] result='

$pass = ($triggerResult.ExitCode -eq 0 -and $dispatchResult.ExitCode -eq 0 -and $classificationResult.ExitCode -eq 0)

$summary = [ordered]@{
    schema = 'AB_ROUTE_GUARD_SMOKE_SUITE_V1'
    generated_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    start_file = $StartFile
    out_dir = $outDir
    trigger = [ordered]@{
        exit_code = $triggerResult.ExitCode
        summary_line = $triggerSummaryLine
        log_path = $triggerLog
    }
    dispatch = [ordered]@{
        exit_code = $dispatchResult.ExitCode
        summary_line = $dispatchSummaryLine
        log_path = $dispatchLog
    }
    classification_contract = [ordered]@{
        exit_code = $classificationResult.ExitCode
        summary_line = $classificationSummaryLine
        log_path = $classificationLog
    }
    pass = $pass
}

$summaryJson = Join-Path $outDir 'summary.json'
$summaryTxt = Join-Path $outDir 'summary.txt'
$summary | ConvertTo-Json -Depth 8 | Out-File -LiteralPath $summaryJson -Encoding utf8
$summary | Format-List | Out-String | Out-File -LiteralPath $summaryTxt -Encoding utf8

Write-Output ('[ROUTE-GUARD-SMOKE-SUITE] out_dir={0}' -f $outDir)
Write-Output ('[ROUTE-GUARD-SMOKE-SUITE] trigger_exit={0} dispatch_exit={1} classification_exit={2}' -f $triggerResult.ExitCode, $dispatchResult.ExitCode, $classificationResult.ExitCode)
Write-Output ('[ROUTE-GUARD-SMOKE-SUITE] trigger_summary={0}' -f $triggerSummaryLine)
Write-Output ('[ROUTE-GUARD-SMOKE-SUITE] dispatch_summary={0}' -f $dispatchSummaryLine)
Write-Output ('[ROUTE-GUARD-SMOKE-SUITE] classification_summary={0}' -f $classificationSummaryLine)

if (-not $pass) {
    Write-Output '[ROUTE-GUARD-SMOKE-SUITE] result=fail'
    Exit-UnattendedFailure -Tag $script:UnhandledExitTag -Reason 'route-guard-smoke-suite failed' -ExitCode 1
}

Write-Output '[ROUTE-GUARD-SMOKE-SUITE] result=pass'
exit 0
