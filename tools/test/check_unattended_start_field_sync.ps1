param(
    [string]$FieldName = '',
    [string[]]$FieldNames = @('LOCAL_GUARD_STATUS_ONLY_AUTOFLOW_EXEC_TOKEN', 'LOCAL_GUARD_WRITE_HANDLED_ARTIFACTS'),
    [string]$TemplatePath = 'docs/UNATTENDED_AB_START_TEMPLATE_CN.md',
    [string[]]$StartFileDirs = @('testdata/unattended_start/active', 'testdata/unattended_start/smoke'),
    [string]$ResetScriptPath = 'tools/test/reset_unattended_ab_start_file.ps1',
    [string]$RoutineScriptPath = 'tools/test/check_unattended_routine_status.ps1',
    [string]$RequiredRoutineTokenArg = '-ExecutionToken "<token>"',
    [switch]$AssertEntryScriptACanonical,
    [string]$ExpectedEntryScriptA = 'tools/test/start_dev_verify_fastmode_A.ps1',
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

function Get-FieldValue {
    param(
        [string]$Text,
        [string]$Name
    )

    if ($Text -match ('(?m)^{0}=(.*)$' -f [regex]::Escape($Name))) {
        return [string]$Matches[1]
    }

    return ''
}

function Convert-PathValueForCompare {
    param([AllowEmptyString()][string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return ''
    }

    return $Value.Trim().Replace('\\', '/').ToLowerInvariant()
}

function Get-EffectiveFieldNameList {
    param(
        [AllowEmptyString()][string]$SingleFieldName,
        [string[]]$MultipleFieldNames
    )

    $single = ([string]$SingleFieldName).Trim()
    if (-not [string]::IsNullOrWhiteSpace($single)) {
        return @($single)
    }

    $values = New-Object 'System.Collections.Generic.List[string]'
    $seen = @{}
    foreach ($raw in @($MultipleFieldNames)) {
        $name = ([string]$raw).Trim()
        if ([string]::IsNullOrWhiteSpace($name)) {
            continue
        }

        if ($seen.ContainsKey($name)) {
            continue
        }

        $seen[$name] = $true
        [void]$values.Add($name)
    }

    if ($values.Count -lt 1) {
        throw 'At least one field name must be provided.'
    }

    return @($values.ToArray())
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$effectiveFieldNames = Get-EffectiveFieldNameList -SingleFieldName $FieldName -MultipleFieldNames $FieldNames

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

$mismatchedEntryScriptAFiles = New-Object 'System.Collections.Generic.List[string]'

$expectedEntryScriptANormalized = Convert-PathValueForCompare -Value $ExpectedEntryScriptA
$templateEntryScriptAValue = ''
$templateEntryScriptAOk = $true
if ($AssertEntryScriptACanonical.IsPresent) {
    $templateEntryScriptAValue = Get-FieldValue -Text $templateText -Name 'ENTRY_SCRIPT_A'
    $templateEntryScriptAOk = (Convert-PathValueForCompare -Value $templateEntryScriptAValue) -eq $expectedEntryScriptANormalized
}

foreach ($file in @($startFiles.ToArray())) {
    $text = [System.IO.File]::ReadAllText($file, [System.Text.Encoding]::UTF8)

    if ($AssertEntryScriptACanonical.IsPresent) {
        $entryScriptAValue = Get-FieldValue -Text $text -Name 'ENTRY_SCRIPT_A'
        $entryScriptAOk = (Convert-PathValueForCompare -Value $entryScriptAValue) -eq $expectedEntryScriptANormalized
        if (-not $entryScriptAOk) {
            [void]$mismatchedEntryScriptAFiles.Add($file)
        }
    }
}

$fieldResults = New-Object 'System.Collections.Generic.List[object]'
$missingFieldFilesAll = New-Object 'System.Collections.Generic.List[string]'
$missingResetFilesAll = New-Object 'System.Collections.Generic.List[string]'

foreach ($effectiveFieldName in @($effectiveFieldNames)) {
    $missingFieldFiles = New-Object 'System.Collections.Generic.List[string]'
    $missingResetFiles = New-Object 'System.Collections.Generic.List[string]'

    foreach ($file in @($startFiles.ToArray())) {
        $text = [System.IO.File]::ReadAllText($file, [System.Text.Encoding]::UTF8)

        if (-not (Test-FieldLinePresent -Text $text -Name $effectiveFieldName)) {
            [void]$missingFieldFiles.Add($file)
            [void]$missingFieldFilesAll.Add(('{0}:{1}' -f $effectiveFieldName, $file))
        }

        if ($text -match '(?m)^RERUN_FROM_A_STARTFILE_RESET_FIELDS=' -and -not (Test-ResetFieldHasValue -Text $text -Name $effectiveFieldName)) {
            [void]$missingResetFiles.Add($file)
            [void]$missingResetFilesAll.Add(('{0}:{1}' -f $effectiveFieldName, $file))
        }
    }

    $templateHasField = Test-FieldLinePresent -Text $templateText -Name $effectiveFieldName
    $templateResetHasField = Test-ResetFieldHasValue -Text $templateText -Name $effectiveFieldName
    $resetScriptHasField = ($resetScriptText -match [regex]::Escape($effectiveFieldName))
    $routineHasTokenArg = $true
    if ($effectiveFieldName -eq 'LOCAL_GUARD_STATUS_ONLY_AUTOFLOW_EXEC_TOKEN') {
        $routineHasTokenArg = ($routineScriptText -match [regex]::Escape($RequiredRoutineTokenArg))
    }

    [void]$fieldResults.Add([ordered]@{
        field_name = $effectiveFieldName
        template_has_field = [bool]$templateHasField
        template_reset_has_field = [bool]$templateResetHasField
        reset_script_has_field = [bool]$resetScriptHasField
        routine_has_token_arg = [bool]$routineHasTokenArg
        missing_field_files = @($missingFieldFiles.ToArray())
        missing_reset_files = @($missingResetFiles.ToArray())
        pass = [bool]($templateHasField -and $templateResetHasField -and $resetScriptHasField -and $routineHasTokenArg -and $missingFieldFiles.Count -eq 0 -and $missingResetFiles.Count -eq 0)
    })
}

$pass = $true
foreach ($fieldResult in @($fieldResults.ToArray())) {
    if (-not [bool]$fieldResult.pass) {
        $pass = $false
    }
}
if ($AssertEntryScriptACanonical.IsPresent -and -not $templateEntryScriptAOk) { $pass = $false }
if ($AssertEntryScriptACanonical.IsPresent -and $mismatchedEntryScriptAFiles.Count -gt 0) { $pass = $false }

$summary = [ordered]@{
    schema = 'AB_UNATTENDED_START_FIELD_SYNC_CHECK_V1'
    generated_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    field_name = $FieldName
    field_names = @($effectiveFieldNames)
    template = $template
    reset_script = $resetScript
    routine_script = $routineScript
    start_file_dirs = $StartFileDirs
    start_file_count = $startFiles.Count
    fields = @($fieldResults.ToArray())
    assert_entry_script_a_canonical = [bool]$AssertEntryScriptACanonical
    expected_entry_script_a = [string]$ExpectedEntryScriptA
    template_entry_script_a = [string]$templateEntryScriptAValue
    template_entry_script_a_ok = [bool]$templateEntryScriptAOk
    mismatched_entry_script_a_files = @($mismatchedEntryScriptAFiles.ToArray())
    missing_field_files = @($missingFieldFilesAll.ToArray())
    missing_reset_files = @($missingResetFilesAll.ToArray())
    pass = [bool]$pass
}

if ($AsJson.IsPresent) {
    $summary | ConvertTo-Json -Depth 8
}
else {
    Write-Output ('[START-FIELD-SYNC] fields={0} start_files={1}' -f (($effectiveFieldNames -join ',')), $startFiles.Count)
    foreach ($fieldResult in @($fieldResults.ToArray())) {
        Write-Output ('[START-FIELD-SYNC] field={0} template_has_field={1} template_reset_has_field={2} reset_script_has_field={3} routine_has_token_arg={4} missing_field_files={5} missing_reset_files={6}' -f [string]$fieldResult.field_name, [bool]$fieldResult.template_has_field, [bool]$fieldResult.template_reset_has_field, [bool]$fieldResult.reset_script_has_field, [bool]$fieldResult.routine_has_token_arg, @($fieldResult.missing_field_files).Count, @($fieldResult.missing_reset_files).Count)
        foreach ($item in @($fieldResult.missing_field_files)) {
            Write-Output ('[START-FIELD-SYNC] missing_field_file field={0} path={1}' -f [string]$fieldResult.field_name, $item)
        }
        foreach ($item in @($fieldResult.missing_reset_files)) {
            Write-Output ('[START-FIELD-SYNC] missing_reset_file field={0} path={1}' -f [string]$fieldResult.field_name, $item)
        }
    }
    if ($AssertEntryScriptACanonical.IsPresent) {
        Write-Output ('[START-FIELD-SYNC] entry_script_a expected={0} template_ok={1} mismatched_files={2}' -f [string]$ExpectedEntryScriptA, [bool]$templateEntryScriptAOk, $mismatchedEntryScriptAFiles.Count)
        if (-not $templateEntryScriptAOk) {
            Write-Output ('[START-FIELD-SYNC] template_entry_script_a_actual={0}' -f [string]$templateEntryScriptAValue)
        }
        if ($mismatchedEntryScriptAFiles.Count -gt 0) {
            foreach ($item in @($mismatchedEntryScriptAFiles.ToArray())) {
                Write-Output ('[START-FIELD-SYNC] mismatched_entry_script_a_file={0}' -f $item)
            }
        }
    }
    Write-Output ('[START-FIELD-SYNC] result={0}' -f ($(if ($pass) { 'pass' } else { 'fail' })))
}

if (-not $pass) {
    exit 1
}

exit 0
