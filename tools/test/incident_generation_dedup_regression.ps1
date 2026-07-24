param(
    [string]$OutDirRoot = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'unattended_startfile_identity.ps1')

if ([string]::IsNullOrWhiteSpace($OutDirRoot)) {
    $OutDirRoot = Join-Path $PSScriptRoot '..\..\out\artifacts\incident_generation_dedup_regression'
}

$outDir = Join-Path $OutDirRoot (Get-Date -Format 'yyyyMMdd-HHmmssfff')
New-Item -ItemType Directory -Path $outDir -Force | Out-Null
$queuePath = Join-Path $outDir 'agent_tickets.jsonl'
$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$startFilePath = Join-Path $repoRoot 'testdata\unattended_start\active\unattended_ab_start_20261116-20261130.md'
$generation = 'start=testdata/unattended_start/active/unattended_ab_start_20261116-20261130.md|stage=B|run=out/artifacts/dev_verify_multiround/20260724-034718|round=D3|phase=task-static|source=d:/lzprojects/whois/out/artifacts/dev_verify_multiround/20260724-034718/d3.log'

$ticket = [ordered]@{
    event = 'incident-captured'
    start_file = 'testdata\unattended_start\active\unattended_ab_start_20261116-20261130.md'
    incident_dir = 'out/artifacts/ab_session_guard/example/incident_first'
    detail = 'first incident package'
    dedup_signature = "incident-captured|FAIL|PASS|FAIL|out\artifacts\dev_verify_multiround\20260724-034718|incident_first|first incident package|$generation"
}
$ticket | ConvertTo-Json -Compress | Set-Content -LiteralPath $queuePath -Encoding utf8

$sameGenerationFound = Test-AgentTicketQueueContainsDedupSuffix -QueuePath $queuePath -StartFilePath $startFilePath -EventName 'incident-captured' -Signature $generation
$differentRunFound = Test-AgentTicketQueueContainsDedupSuffix -QueuePath $queuePath -StartFilePath $startFilePath -EventName 'incident-captured' -Signature ($generation.Replace('20260724-034718', '20260724-050000'))
$differentRoundFound = Test-AgentTicketQueueContainsDedupSuffix -QueuePath $queuePath -StartFilePath $startFilePath -EventName 'incident-captured' -Signature ($generation.Replace('round=D3', 'round=D4'))
$differentSourceFound = Test-AgentTicketQueueContainsDedupSuffix -QueuePath $queuePath -StartFilePath $startFilePath -EventName 'incident-captured' -Signature ($generation.Replace('/d3.log', '/d3_retry.log'))
$differentEventFound = Test-AgentTicketQueueContainsDedupSuffix -QueuePath $queuePath -StartFilePath $startFilePath -EventName 'running-status-report' -Signature $generation

if (-not $sameGenerationFound) {
    throw 'Same canonical incident generation was not found in queue history.'
}
if ($differentRunFound -or $differentRoundFound -or $differentSourceFound -or $differentEventFound) {
    throw 'Distinct incident identity was incorrectly suppressed by queue-history dedup.'
}

Write-Output ('[INCIDENT-GENERATION-DEDUP-REGRESSION] PASS queue={0}' -f (Convert-ToRepoRelativePath -Path $queuePath))