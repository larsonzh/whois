param(
    [string]$Version = "3.2.12",
    [ValidateSet("true", "false")][string]$BuildAndSyncIf = "false",
    [string]$OutDirRoot = ""
)

$ErrorActionPreference = "Continue"
$PSNativeCommandUseErrorActionPreference = $false

if (-not $OutDirRoot -or $OutDirRoot.Trim().Length -eq 0) {
    $OutDirRoot = Join-Path $PSScriptRoot "..\..\out\artifacts\oneclick_dryrun_guard"
}

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$outDir = Join-Path $OutDirRoot $stamp
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

$oneClickScript = Join-Path $PSScriptRoot "..\release\one_click_release.ps1"
if (-not (Test-Path $oneClickScript)) {
    Write-Error "One-click script not found: $oneClickScript"
    exit 2
}

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Write-Error "git not found in PATH"
    exit 2
}

function ConvertTo-NormalizedLine {
    param([object[]]$Raw)

    return $Raw | ForEach-Object {
        if ($_ -is [System.Management.Automation.ErrorRecord]) {
            $_.Exception.Message
        }
        else {
            $_
        }
    }
}

$gitBeforeRaw = & git status --porcelain 2>&1
$gitBeforeLines = ConvertTo-NormalizedLine -Raw $gitBeforeRaw
$gitBeforeText = ($gitBeforeLines -join "`n")
$gitBeforePath = Join-Path $outDir "git_status_before.txt"
$gitBeforeText | Out-File -FilePath $gitBeforePath -Encoding utf8

$raw = & powershell -NoProfile -ExecutionPolicy Bypass -File $oneClickScript -Version $Version -BuildAndSyncIf $BuildAndSyncIf -DryRunIf true -SkipTagIf false 2>&1
$lines = ConvertTo-NormalizedLine -Raw $raw
$exitCode = $LASTEXITCODE
if ($null -eq $exitCode) {
    $exitCode = 0
}

$gitAfterRaw = & git status --porcelain 2>&1
$gitAfterLines = ConvertTo-NormalizedLine -Raw $gitAfterRaw
$gitAfterText = ($gitAfterLines -join "`n")
$gitAfterPath = Join-Path $outDir "git_status_after.txt"
$gitAfterText | Out-File -FilePath $gitAfterPath -Encoding utf8

$gitStateUnchanged = ($gitBeforeText -eq $gitAfterText)
$requireGitStateUnchanged = ($BuildAndSyncIf -eq "false")
$gitStateCheckPass = if ($requireGitStateUnchanged) { $gitStateUnchanged } else { $true }

$logPath = Join-Path $outDir "oneclick_dryrun.log"
$lines | Out-File -FilePath $logPath -Encoding utf8
$text = ($lines -join "`n")

$guardRx = '(?m)^\[ONECLICK-DRYRUN-GUARD\]\s+skip_tag=(true|false)\s+skip_github_release=(true|false)\s+skip_gitee_release=(true|false)\s+statics_detected=(true|false)\s+statics_commit_pushed=(true|false)\s+result=(pass|fail)$'
$guardMatch = [regex]::Match($text, $guardRx)

$guardFound = $guardMatch.Success
$skipTag = ""
$skipGithub = ""
$skipGitee = ""
$staticsDetected = ""
$staticsCommitPushed = ""
$result = ""

if ($guardFound) {
    $skipTag = $guardMatch.Groups[1].Value
    $skipGithub = $guardMatch.Groups[2].Value
    $skipGitee = $guardMatch.Groups[3].Value
    $staticsDetected = $guardMatch.Groups[4].Value
    $staticsCommitPushed = $guardMatch.Groups[5].Value
    $result = $guardMatch.Groups[6].Value
}

$pass = (
    ($exitCode -eq 0) -and
    $guardFound -and
    ($skipTag -eq "true") -and
    ($skipGithub -eq "true") -and
    ($skipGitee -eq "true") -and
    ($staticsCommitPushed -eq "false") -and
    ($result -eq "pass") -and
    $gitStateCheckPass
)

$summary = [pscustomobject]@{
    version = $Version
    build_and_sync = $BuildAndSyncIf
    exit_code = $exitCode
    guard_found = $guardFound
    skip_tag = $skipTag
    skip_github_release = $skipGithub
    skip_gitee_release = $skipGitee
    statics_detected = $staticsDetected
    statics_commit_pushed = $staticsCommitPushed
    guard_result = $result
    require_git_state_unchanged = $requireGitStateUnchanged
    git_state_unchanged = $gitStateUnchanged
    git_state_check_pass = $gitStateCheckPass
    git_status_before = $gitBeforePath
    git_status_after = $gitAfterPath
    smoke_result = if ($pass) { "pass" } else { "fail" }
    log = $logPath
}

$summaryJson = Join-Path $outDir "summary.json"
$summaryTxt = Join-Path $outDir "summary.txt"
$summary | ConvertTo-Json -Depth 4 | Out-File -FilePath $summaryJson -Encoding utf8
$summary | Format-List | Out-String | Out-File -FilePath $summaryTxt -Encoding utf8

Write-Output ("[ONECLICK-DRYRUN-SMOKE] out_dir={0}" -f $outDir)
Write-Output ("[ONECLICK-DRYRUN-SMOKE] log={0}" -f $logPath)
Write-Output ("[ONECLICK-DRYRUN-SMOKE] summary_json={0}" -f $summaryJson)
Write-Output ("[ONECLICK-DRYRUN-SMOKE] summary_txt={0}" -f $summaryTxt)
Write-Output ("[ONECLICK-DRYRUN-SMOKE] guard_found={0} skip_tag={1} skip_github_release={2} skip_gitee_release={3} statics_detected={4} statics_commit_pushed={5} guard_result={6}" -f $guardFound, $skipTag, $skipGithub, $skipGitee, $staticsDetected, $staticsCommitPushed, $result)
Write-Output ("[ONECLICK-DRYRUN-SMOKE] require_git_state_unchanged={0} git_state_unchanged={1} git_state_check_pass={2}" -f $requireGitStateUnchanged, $gitStateUnchanged, $gitStateCheckPass)

if (-not $pass) {
    Write-Output "[ONECLICK-DRYRUN-SMOKE] result=fail"
    exit 1
}

Write-Output "[ONECLICK-DRYRUN-SMOKE] result=pass"
exit 0
