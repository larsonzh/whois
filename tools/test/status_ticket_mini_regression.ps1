param(
    [string]$DispatchScript = 'tools/test/dispatch_takeover_to_chat.ps1',
    [string]$MainHealthScript = 'tools/test/check_unattended_main_process_health.ps1',
    [string]$PromptDoc = 'docs/UNATTENDED_AB_PROMPTS_CN.md',
    [string]$OutDirRoot = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $OutDirRoot -or $OutDirRoot.Trim().Length -eq 0) {
    $OutDirRoot = Join-Path $PSScriptRoot '..\..\out\artifacts\status_ticket_mini_regression'
}

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$outDir = Join-Path $OutDirRoot $stamp
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path

function Resolve-RepoPath {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw 'Path must not be empty.'
    }

    $fullPath = if ([System.IO.Path]::IsPathRooted($Path)) {
        [System.IO.Path]::GetFullPath($Path)
    }
    else {
        [System.IO.Path]::GetFullPath((Join-Path $repoRoot $Path))
    }

    if (-not (Test-Path -LiteralPath $fullPath)) {
        throw ("Path not found: {0}" -f $fullPath)
    }

    return $fullPath
}

function Convert-ToRepoRelativePath {
    param([string]$Path)

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $repoRootFull = [System.IO.Path]::GetFullPath($repoRoot)
    if ($fullPath.StartsWith($repoRootFull, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $fullPath.Substring($repoRootFull.Length).TrimStart('\\').Replace('\\', '/')
    }

    return $fullPath.Replace('\\', '/')
}

function New-CaseResult {
    param(
        [string]$Name,
        [bool]$Pass,
        [string]$Reason
    )

    return [pscustomobject]@{
        case = $Name
        pass = [bool]$Pass
        reason = $Reason
    }
}

$dispatchPath = Resolve-RepoPath -Path $DispatchScript
$mainHealthPath = Resolve-RepoPath -Path $MainHealthScript
$promptDocPath = Resolve-RepoPath -Path $PromptDoc

$dispatchText = Get-Content -LiteralPath $dispatchPath -Raw -Encoding utf8
$mainHealthText = Get-Content -LiteralPath $mainHealthPath -Raw -Encoding utf8
$promptDocText = Get-Content -LiteralPath $promptDocPath -Raw -Encoding utf8

$results = New-Object 'System.Collections.Generic.List[object]'

# Case 1: healthy status ticket should map to continue-watch-only guidance.
$healthyHasSummary = $mainHealthText.Contains('B main process is alive; treat this status ticket as normal monitoring and do not infer a B restart from stale history.')
$healthyHasAction = $mainHealthText.Contains('$recommendedAction = ''continue-watch-only''')
$healthyPass = ($healthyHasSummary -and $healthyHasAction)
$healthyReason = if ($healthyPass) { 'healthy-status-ticket-guidance-present' } else { 'missing-healthy-status-ticket-guidance' }
[void]$results.Add((New-CaseResult -Name 'healthy-status-ticket' -Pass $healthyPass -Reason $healthyReason))

# Case 2: stale latest_b_exit must be identified explicitly and surfaced in output verdict.
$staleHasSignal = $mainHealthText.Contains('$staleExitEvidence = ([bool]$bExitEvidence.Available -and (-not [bool]$reasonMatched))')
$staleHasOutput = $mainHealthText.Contains('stale_exit_evidence = [bool]$staleExitEvidence')
$stalePass = ($staleHasSignal -and $staleHasOutput)
$staleReason = if ($stalePass) { 'stale-latest-b-exit-signal-present' } else { 'missing-stale-latest-b-exit-signal' }
[void]$results.Add((New-CaseResult -Name 'stale-latest-b-exit' -Pass $stalePass -Reason $staleReason))

# Case 3: low-disturb response must enforce two-line healthy reply contract.
$lowDisturbEnTwoLine = $dispatchText.Contains('reply with only two lines: "Running normal" and "handled_at: YYYY-MM-DD HH:mm:ss"')
$lowDisturbHasHandledAtToken = $dispatchText.Contains('handled_at: YYYY-MM-DD HH:mm:ss')
$lowDisturbHasLowDisturbToken = $dispatchText.Contains('[LOW-DISTURB]')
$lowDisturbPass = ($lowDisturbEnTwoLine -and $lowDisturbHasHandledAtToken -and $lowDisturbHasLowDisturbToken)
$lowDisturbReason = if ($lowDisturbPass) { 'low-disturb-two-line-contract-present' } else { 'missing-low-disturb-two-line-contract' }
[void]$results.Add((New-CaseResult -Name 'low-disturb-two-line-reply' -Pass $lowDisturbPass -Reason $lowDisturbReason))

# Case 4: do-not-create-non-tmp-script guardrail must be present in runtime prompt channels.
$dispatchNoNonTmp = $dispatchText.Contains('do not create new scripts outside tmp')
$promptNoNonTmp = [regex]::IsMatch($promptDocText, 'chat_heartbeat\*\.jsonl.*handled.*tmp', [System.Text.RegularExpressions.RegexOptions]::Singleline)
$noNonTmpPass = ($dispatchNoNonTmp -and $promptNoNonTmp)
$noNonTmpReason = if ($noNonTmpPass) { 'no-non-tmp-script-guardrail-present' } else { 'missing-no-non-tmp-script-guardrail' }
[void]$results.Add((New-CaseResult -Name 'no-non-tmp-script-creation' -Pass $noNonTmpPass -Reason $noNonTmpReason))

$failedCases = @($results | Where-Object { -not [bool]$_.pass })
$pass = ($failedCases.Count -eq 0)

$summary = [pscustomobject]@{
    schema = 'AB_STATUS_TICKET_MINI_REGRESSION_V1'
    generated_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    pass = [bool]$pass
    total_cases = $results.Count
    failed_cases = $failedCases.Count
    inputs = [pscustomobject]@{
        dispatch_script = (Convert-ToRepoRelativePath -Path $dispatchPath)
        main_health_script = (Convert-ToRepoRelativePath -Path $mainHealthPath)
        prompt_doc = (Convert-ToRepoRelativePath -Path $promptDocPath)
    }
    cases = @($results.ToArray())
}

$summaryJson = Join-Path $outDir 'summary.json'
$summaryTxt = Join-Path $outDir 'summary.txt'
$summary | ConvertTo-Json -Depth 8 | Out-File -LiteralPath $summaryJson -Encoding utf8
$summary | Format-List | Out-String | Out-File -LiteralPath $summaryTxt -Encoding utf8

Write-Output ('[STATUS-TICKET-MINI] out_dir={0}' -f $outDir)
Write-Output ('[STATUS-TICKET-MINI] summary_json={0}' -f $summaryJson)
Write-Output ('[STATUS-TICKET-MINI] summary_txt={0}' -f $summaryTxt)
foreach ($entry in $results.ToArray()) {
    Write-Output ('[STATUS-TICKET-MINI] case={0} pass={1} reason={2}' -f [string]$entry.case, [bool]$entry.pass, [string]$entry.reason)
}

if (-not $pass) {
    Write-Output '[STATUS-TICKET-MINI] result=fail'
    exit 1
}

Write-Output '[STATUS-TICKET-MINI] result=pass'
exit 0
