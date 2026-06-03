param(
    [string]$StartFile = 'testdata/unattended_start/smoke/unattended_ab_start_status_ticket_smoke.md',
    [ValidateRange(1, 200)][int]$Last = 20,
    [string]$ExecutionTokenSettingKey = 'LOCAL_GUARD_STATUS_ONLY_AUTOFLOW_EXEC_TOKEN',
    [string]$ExecutionTokenValue = 'token-guard-smoke',
    [string]$MismatchTokenValue = 'token-guard-smoke-mismatch',
    [string]$OutDirRoot = '',
    [switch]$SkipFieldSyncCheck
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $OutDirRoot -or $OutDirRoot.Trim().Length -eq 0) {
    $OutDirRoot = Join-Path $PSScriptRoot '..\..\out\artifacts\status_only_autoflow_token_guard_smoke'
}

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$outDir = Join-Path $OutDirRoot $stamp
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path

$resolvedStartFile = if ([System.IO.Path]::IsPathRooted($StartFile)) {
    [System.IO.Path]::GetFullPath($StartFile)
}
else {
    [System.IO.Path]::GetFullPath((Join-Path $repoRoot $StartFile))
}

if (-not (Test-Path -LiteralPath $resolvedStartFile)) {
    throw ('start file not found: {0}' -f $resolvedStartFile)
}

$autoflowScript = Join-Path $repoRoot 'tools\test\run_unattended_status_only_autoflow.ps1'
$routineScript = Join-Path $repoRoot 'tools\test\check_unattended_routine_status.ps1'
$fieldSyncScript = Join-Path $repoRoot 'tools\test\check_unattended_start_field_sync.ps1'

if (-not (Test-Path -LiteralPath $autoflowScript)) {
    throw ('autoflow script not found: {0}' -f $autoflowScript)
}
if (-not (Test-Path -LiteralPath $routineScript)) {
    throw ('routine script not found: {0}' -f $routineScript)
}
if (-not (Test-Path -LiteralPath $fieldSyncScript)) {
    throw ('field sync script not found: {0}' -f $fieldSyncScript)
}

$fieldSyncResult = $null
if (-not $SkipFieldSyncCheck.IsPresent) {
    $fieldSyncResult = & powershell -NoProfile -ExecutionPolicy Bypass -File $fieldSyncScript -FieldName $ExecutionTokenSettingKey -AsJson | ConvertFrom-Json
    if (-not [bool]$fieldSyncResult.pass) {
        Write-Output '[STATUS-AUTOFLOW-TOKEN-GUARD-SMOKE] precheck=field-sync-fail'
        $fieldSyncResult | ConvertTo-Json -Depth 8 | Out-File -FilePath (Join-Path $outDir 'field_sync_check.json') -Encoding utf8
        exit 1
    }
}

$tmpStartFile = Join-Path $outDir 'startfile_token_guard_probe.md'
Copy-Item -LiteralPath $resolvedStartFile -Destination $tmpStartFile -Force

$tmpText = [System.IO.File]::ReadAllText($tmpStartFile, [System.Text.Encoding]::UTF8)
$tokenLine = ('{0}={1}' -f $ExecutionTokenSettingKey, $ExecutionTokenValue)

if ($tmpText -match ('(?m)^{0}=' -f [regex]::Escape($ExecutionTokenSettingKey))) {
    $tmpText = [regex]::Replace($tmpText, ('(?m)^{0}=.*$' -f [regex]::Escape($ExecutionTokenSettingKey)), $tokenLine)
}
else {
    $tmpText = $tmpText.TrimEnd() + "`r`n" + $tokenLine + "`r`n"
}

[System.IO.File]::WriteAllText($tmpStartFile, $tmpText, [System.Text.UTF8Encoding]::new($false))

$routine = & powershell -NoProfile -ExecutionPolicy Bypass -File $routineScript -StartFile $tmpStartFile -Last $Last -AsJson | ConvertFrom-Json

$selectedTicket = $routine.commands.selected_ticket
if ($null -eq $selectedTicket) {
    throw 'selected_ticket is null; cannot validate token guard smoke'
}

$ticketId = [string]$selectedTicket.ticket_id
if ([string]::IsNullOrWhiteSpace($ticketId)) {
    throw 'selected_ticket.ticket_id is empty; cannot validate token guard smoke'
}

$baseArgs = @(
    '-NoProfile',
    '-ExecutionPolicy',
    'Bypass',
    '-File',
    $autoflowScript,
    '-StartFile',
    $tmpStartFile,
    '-Last',
    [string]$Last,
    '-EnableExecute',
    '-AllowedTicketIds',
    $ticketId,
    '-DryRun',
    '-AsJson'
)

function Invoke-Case {
    param(
        [string]$Case,
        [AllowEmptyString()][string]$Token
    )

    $invokeArgs = @($baseArgs)
    if (-not [string]::IsNullOrWhiteSpace($Token)) {
        $invokeArgs += @('-ExecutionToken', $Token)
    }

    $result = & powershell @invokeArgs | ConvertFrom-Json
    return [pscustomobject]@{
        case = $Case
        can_execute = [bool]$result.can_execute
        reason = [string]$result.reason
        configured = [bool]$result.execution_token.configured
        provided = [bool]$result.execution_token.provided
        matched = [bool]$result.execution_token.matched
        verdict = [string]$result.verdict
        selected_ticket_allowed = [bool]$result.selected_ticket_allowed
        steps = @($result.steps).Count
    }
}

$missing = Invoke-Case -Case 'missing' -Token ''
$mismatch = Invoke-Case -Case 'mismatch' -Token $MismatchTokenValue
$match = Invoke-Case -Case 'match' -Token $ExecutionTokenValue

$cases = @($missing, $mismatch, $match)

$pass = $true
if ($missing.can_execute -ne $false -or $missing.reason -ne 'skip-execution-token-missing') { $pass = $false }
if ($mismatch.can_execute -ne $false -or $mismatch.reason -ne 'skip-execution-token-mismatch') { $pass = $false }
if ($match.can_execute -ne $true -or $match.matched -ne $true) { $pass = $false }

$summary = [pscustomobject]@{
    schema = 'AB_STATUS_ONLY_AUTOFLOW_TOKEN_GUARD_SMOKE_V1'
    generated_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    start_file = $resolvedStartFile
    temp_start_file = $tmpStartFile
    field_sync_check = if ($null -ne $fieldSyncResult) {
        [ordered]@{
            executed = $true
            pass = [bool]$fieldSyncResult.pass
            start_file_count = [int]$fieldSyncResult.start_file_count
            missing_field_files = @($fieldSyncResult.missing_field_files)
            missing_reset_files = @($fieldSyncResult.missing_reset_files)
        }
    }
    else {
        [ordered]@{
            executed = $false
            pass = $null
            start_file_count = $null
            missing_field_files = @()
            missing_reset_files = @()
        }
    }
    ticket_id = $ticketId
    verdict = [string]$routine.verdict
    pass = [bool]$pass
    cases = $cases
}

$summaryPath = Join-Path $outDir 'summary.json'
$summaryTxtPath = Join-Path $outDir 'summary.txt'
$summary | ConvertTo-Json -Depth 8 | Out-File -FilePath $summaryPath -Encoding utf8
$summary | Format-List | Out-String | Out-File -FilePath $summaryTxtPath -Encoding utf8

Write-Output ('[STATUS-AUTOFLOW-TOKEN-GUARD-SMOKE] out_dir={0}' -f $outDir)
Write-Output ('[STATUS-AUTOFLOW-TOKEN-GUARD-SMOKE] summary_json={0}' -f $summaryPath)
Write-Output ('[STATUS-AUTOFLOW-TOKEN-GUARD-SMOKE] summary_txt={0}' -f $summaryTxtPath)
if ($null -ne $fieldSyncResult) {
    Write-Output ('[STATUS-AUTOFLOW-TOKEN-GUARD-SMOKE] field_sync_check pass={0} start_files={1} missing_field_files={2} missing_reset_files={3}' -f [bool]$fieldSyncResult.pass, [int]$fieldSyncResult.start_file_count, @($fieldSyncResult.missing_field_files).Count, @($fieldSyncResult.missing_reset_files).Count)
}
foreach ($row in $cases) {
    Write-Output ('[STATUS-AUTOFLOW-TOKEN-GUARD-SMOKE] case={0} can_execute={1} reason={2} configured={3} provided={4} matched={5}' -f $row.case, $row.can_execute, $row.reason, $row.configured, $row.provided, $row.matched)
}

if (-not $pass) {
    Write-Output '[STATUS-AUTOFLOW-TOKEN-GUARD-SMOKE] result=fail'
    exit 1
}

Write-Output '[STATUS-AUTOFLOW-TOKEN-GUARD-SMOKE] result=pass'
exit 0
