param(
    [string]$FieldName = 'LOCAL_GUARD_STATUS_ONLY_AUTOFLOW_EXEC_TOKEN',
    [string]$TemplatePath = 'docs/UNATTENDED_AB_START_TEMPLATE_CN.md',
    [string[]]$StartFileDirs = @('testdata/unattended_start/active', 'testdata/unattended_start/smoke'),
    [string]$ResetScriptPath = 'tools/test/reset_unattended_ab_start_file.ps1',
    [string]$RoutineScriptPath = 'tools/test/check_unattended_routine_status.ps1',
    [string]$RequiredRoutineTokenArg = '-ExecutionToken "<token>"',
    [switch]$AsJson
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Resolve-RepoPath {
    param(
        [string]$RepoRoot,
        [string]$Path,
        [bool]$MustExist = $true
    )

    $resolved = if ([System.IO.Path]::IsPathRooted($Path)) {
        [System.IO.Path]::GetFullPath($Path)
    }
    else {
        [System.IO.Path]::GetFullPath((Join-Path $RepoRoot $Path))
    }

    if ($MustExist -and -not (Test-Path -LiteralPath $resolved)) {
        throw ('path not found: {0}' -f $resolved)
    }

    return $resolved
}

function Test-FieldLinePresent {
    param(
        [string]$Text,
        [string]$Name
    )

    return ($Text -match ('(?m)^{0}=' -f [regex]::Escape($Name)))
}

function Test-ResetFieldHasValue {
    param(
        [string]$Text,
        [string]$Name
    )

    return ($Text -match ('(?m)^RERUN_FROM_A_STARTFILE_RESET_FIELDS=.*(?:^|;){0}(?:;|$)' -f [regex]::Escape($Name)))
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path

$template = Resolve-RepoPath -RepoRoot $repoRoot -Path $TemplatePath -MustExist $true
$resetScript = Resolve-RepoPath -RepoRoot $repoRoot -Path $ResetScriptPath -MustExist $true
$routineScript = Resolve-RepoPath -RepoRoot $repoRoot -Path $RoutineScriptPath -MustExist $true

$startFiles = New-Object 'System.Collections.Generic.List[string]'
foreach ($dir in $StartFileDirs) {
    $resolvedDir = Resolve-RepoPath -RepoRoot $repoRoot -Path $dir -MustExist $true
    foreach ($file in @(Get-ChildItem -LiteralPath $resolvedDir -Filter '*.md' -File -ErrorAction Stop)) {
        [void]$startFiles.Add($file.FullName)
    }
}

$templateText = [System.IO.File]::ReadAllText($template, [System.Text.Encoding]::UTF8)
$resetScriptText = [System.IO.File]::ReadAllText($resetScript, [System.Text.Encoding]::UTF8)
$routineScriptText = [System.IO.File]::ReadAllText($routineScript, [System.Text.Encoding]::UTF8)

$missingFieldFiles = New-Object 'System.Collections.Generic.List[string]'
$missingResetFiles = New-Object 'System.Collections.Generic.List[string]'

foreach ($file in @($startFiles.ToArray())) {
    $text = [System.IO.File]::ReadAllText($file, [System.Text.Encoding]::UTF8)

    if (-not (Test-FieldLinePresent -Text $text -Name $FieldName)) {
        [void]$missingFieldFiles.Add($file)
    }

    if ($text -match '(?m)^RERUN_FROM_A_STARTFILE_RESET_FIELDS=' -and -not (Test-ResetFieldHasValue -Text $text -Name $FieldName)) {
        [void]$missingResetFiles.Add($file)
    }
}

$templateHasField = Test-FieldLinePresent -Text $templateText -Name $FieldName
$templateResetHasField = Test-ResetFieldHasValue -Text $templateText -Name $FieldName
$resetScriptHasField = ($resetScriptText -match [regex]::Escape($FieldName))
$routineHasTokenArg = ($routineScriptText -match [regex]::Escape($RequiredRoutineTokenArg))

$pass = $true
if (-not $templateHasField) { $pass = $false }
if (-not $templateResetHasField) { $pass = $false }
if (-not $resetScriptHasField) { $pass = $false }
if (-not $routineHasTokenArg) { $pass = $false }
if ($missingFieldFiles.Count -gt 0) { $pass = $false }
if ($missingResetFiles.Count -gt 0) { $pass = $false }

$summary = [ordered]@{
    schema = 'AB_UNATTENDED_START_FIELD_SYNC_CHECK_V1'
    generated_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    field_name = $FieldName
    template = $template
    reset_script = $resetScript
    routine_script = $routineScript
    start_file_dirs = $StartFileDirs
    start_file_count = $startFiles.Count
    template_has_field = [bool]$templateHasField
    template_reset_has_field = [bool]$templateResetHasField
    reset_script_has_field = [bool]$resetScriptHasField
    routine_has_token_arg = [bool]$routineHasTokenArg
    missing_field_files = @($missingFieldFiles.ToArray())
    missing_reset_files = @($missingResetFiles.ToArray())
    pass = [bool]$pass
}

if ($AsJson.IsPresent) {
    $summary | ConvertTo-Json -Depth 8
}
else {
    Write-Output ('[START-FIELD-SYNC] field={0} start_files={1}' -f $FieldName, $startFiles.Count)
    Write-Output ('[START-FIELD-SYNC] template_has_field={0} template_reset_has_field={1} reset_script_has_field={2} routine_has_token_arg={3}' -f [bool]$templateHasField, [bool]$templateResetHasField, [bool]$resetScriptHasField, [bool]$routineHasTokenArg)
    Write-Output ('[START-FIELD-SYNC] missing_field_files={0} missing_reset_files={1}' -f $missingFieldFiles.Count, $missingResetFiles.Count)
    if ($missingFieldFiles.Count -gt 0) {
        foreach ($item in @($missingFieldFiles.ToArray())) {
            Write-Output ('[START-FIELD-SYNC] missing_field_file={0}' -f $item)
        }
    }
    if ($missingResetFiles.Count -gt 0) {
        foreach ($item in @($missingResetFiles.ToArray())) {
            Write-Output ('[START-FIELD-SYNC] missing_reset_file={0}' -f $item)
        }
    }
    Write-Output ('[START-FIELD-SYNC] result={0}' -f ($(if ($pass) { 'pass' } else { 'fail' })))
}

if (-not $pass) {
    exit 1
}

exit 0
