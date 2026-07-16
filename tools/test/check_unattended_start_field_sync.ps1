param(
    [string]$FieldName = '',
    [string[]]$FieldNames = @(
        'LOCAL_GUARD_STATUS_ONLY_AUTOFLOW_EXEC_TOKEN',
        'LOCAL_GUARD_WRITE_HANDLED_ARTIFACTS',
        'AI_CHAT_TRIGGER_SKIP_EXISTING_QUEUE_ON_START',
        'AI_CHAT_DISPATCH_ALLOW_RUNNING_STATUS_MESSAGE_OVERRIDE',
        'LOCAL_GUARD_POLL_STATUS_REPORT_INCLUDE_MAIN_PROCESS_HEALTH_CHECK',
        'LOCAL_GUARD_POLL_STATUS_REPORT_ENABLE_MAIN_PROCESS_SELF_HEAL',
        'LOCAL_GUARD_POLL_STATUS_REPORT_INCLUDE_TICKET_CHAIN_CHECK',
        'LOCAL_GUARD_POLL_EVENT_POLICY_STRICT'
        'TASK_STATIC_CROSS_ROUND_REPAIR_ENABLED'
    ),
    [string[]]$BackwardCompatibleOptionalFields = @(
        'TASK_STATIC_CROSS_ROUND_REPAIR_ENABLED'
    ),
    [string]$TemplatePath = 'docs/UNATTENDED_AB_START_TEMPLATE_CN.md',
    [string]$StartFile = '',
    [string[]]$StartFileDirs = @('testdata/unattended_start/active', 'testdata/unattended_start/smoke'),
    [string]$ResetScriptPath = 'tools/test/reset_unattended_ab_start_file.ps1',
    [string]$RoutineScriptPath = 'tools/test/check_unattended_routine_status.ps1',
    [string]$RequiredRoutineTokenArg = '-ExecutionToken "<token>"',
    [string[]]$RequiredNonEmptyFields = @(
        'AI_CHAT_DISPATCH_MESSAGE_RUNNING_STATUS_FULL',
        'AI_CHAT_DISPATCH_MESSAGE_RUNNING_STATUS_SHORT'
    ),
    [string[]]$RequiredPresenceFields = @(
        'LAUNCH_READY_GATE_ENABLED'
    ),
    [switch]$EnforceRunningStatusMessageTemplateMatch,
    [string[]]$TemplateMatchFields = @(
        'AI_CHAT_DISPATCH_MESSAGE_RUNNING_STATUS_FULL',
        'AI_CHAT_DISPATCH_MESSAGE_RUNNING_STATUS_SHORT'
    ),
    [switch]$AssertEntryScriptACanonical,
    [string]$ExpectedEntryScriptA = 'tools/test/start_dev_verify_fastmode_A.ps1',
    [switch]$AsJson
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'unattended_exit_result.ps1')
. (Join-Path $PSScriptRoot 'unattended_startfile_identity.ps1')
$script:UnhandledExitTag = 'CHECK-UNATTENDED-START-FIELD-SYNC'

trap {
    $exitCode = Get-UnattendedExitCodeFromRecord -Tag $script:UnhandledExitTag -Record $_ -DefaultExitCode 1
    Write-UnattendedUnhandledResult -Tag $script:UnhandledExitTag -Record $_ -ExitCode $exitCode
    exit $exitCode
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
        # Normalize CRLF-vs-LF differences so template/value comparisons
        # are not tripped by trailing carriage returns.
        return ([string]$Matches[1]).TrimEnd("`r")
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

function Get-EffectiveNonEmptyFieldNameList {
    param([string[]]$Names)

    $values = New-Object 'System.Collections.Generic.List[string]'
    $seen = @{}
    foreach ($raw in @($Names)) {
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

    return @($values.ToArray())
}

function Get-EffectiveTemplateMatchFieldNameList {
    param([string[]]$Names)

    $values = New-Object 'System.Collections.Generic.List[string]'
    $seen = @{}
    foreach ($raw in @($Names)) {
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

    return @($values.ToArray())
}

$effectiveFieldNames = Get-EffectiveFieldNameList -SingleFieldName $FieldName -MultipleFieldNames $FieldNames
$effectiveBackwardCompatibleOptionalFields = Get-EffectiveNonEmptyFieldNameList -Names $BackwardCompatibleOptionalFields
$backwardCompatibleOptionalFieldSet = @{}
foreach ($name in @($effectiveBackwardCompatibleOptionalFields)) {
    $backwardCompatibleOptionalFieldSet[$name] = $true
}
$effectiveNonEmptyFieldNames = Get-EffectiveNonEmptyFieldNameList -Names $RequiredNonEmptyFields
$effectiveRequiredPresenceFieldNames = Get-EffectiveNonEmptyFieldNameList -Names $RequiredPresenceFields
$effectiveTemplateMatchFieldNames = Get-EffectiveTemplateMatchFieldNameList -Names $TemplateMatchFields

$template = Resolve-RepoPath -Path $TemplatePath -MustExist $true
$resetScript = Resolve-RepoPath -Path $ResetScriptPath -MustExist $true
$routineScript = Resolve-RepoPath -Path $RoutineScriptPath -MustExist $true

$startFiles = New-Object 'System.Collections.Generic.List[string]'
$effectiveStartFile = ([string]$StartFile).Trim()
if (-not [string]::IsNullOrWhiteSpace($effectiveStartFile)) {
    $resolvedStartFile = Resolve-RepoPath -Path $effectiveStartFile -MustExist $true
    if (-not ([string]$resolvedStartFile).ToLowerInvariant().EndsWith('.md')) {
        throw ('StartFile must be a .md file: {0}' -f $resolvedStartFile)
    }

    [void]$startFiles.Add($resolvedStartFile)
}
else {
    foreach ($dir in $StartFileDirs) {
        $resolvedDir = Resolve-RepoPath -Path $dir -MustExist $true
        foreach ($file in @(Get-ChildItem -LiteralPath $resolvedDir -Filter '*.md' -File -ErrorAction Stop)) {
            [void]$startFiles.Add($file.FullName)
        }
    }
}

$checkScope = if ([string]::IsNullOrWhiteSpace($effectiveStartFile)) { 'directories' } else { 'single-file' }
$checkedStartFiles = New-Object 'System.Collections.Generic.List[string]'
foreach ($file in @($startFiles.ToArray())) {
    [void]$checkedStartFiles.Add((Convert-ToRepoRelativePath -Path $file))
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
$nonEmptyFieldResults = New-Object 'System.Collections.Generic.List[object]'
$emptyValueFilesAll = New-Object 'System.Collections.Generic.List[string]'
$requiredPresenceFieldResults = New-Object 'System.Collections.Generic.List[object]'
$missingRequiredPresenceFilesAll = New-Object 'System.Collections.Generic.List[string]'
$templateMatchFieldResults = New-Object 'System.Collections.Generic.List[object]'
$mismatchedValueFilesAll = New-Object 'System.Collections.Generic.List[string]'

foreach ($effectiveFieldName in @($effectiveFieldNames)) {
    $missingFieldFiles = New-Object 'System.Collections.Generic.List[string]'
    $missingResetFiles = New-Object 'System.Collections.Generic.List[string]'

    $allowMissingInDirectoryScan = ($checkScope -eq 'directories' -and $backwardCompatibleOptionalFieldSet.ContainsKey($effectiveFieldName))
    foreach ($file in @($startFiles.ToArray())) {
        $text = [System.IO.File]::ReadAllText($file, [System.Text.Encoding]::UTF8)

        if (-not $allowMissingInDirectoryScan -and -not (Test-FieldLinePresent -Text $text -Name $effectiveFieldName)) {
            [void]$missingFieldFiles.Add($file)
            [void]$missingFieldFilesAll.Add(('{0}:{1}' -f $effectiveFieldName, $file))
        }

        if (-not $allowMissingInDirectoryScan -and $text -match '(?m)^RERUN_FROM_A_STARTFILE_RESET_FIELDS=' -and -not (Test-ResetFieldHasValue -Text $text -Name $effectiveFieldName)) {
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

foreach ($requiredNonEmptyFieldName in @($effectiveNonEmptyFieldNames)) {
    $emptyValueFiles = New-Object 'System.Collections.Generic.List[string]'

    $templateValue = Get-FieldValue -Text $templateText -Name $requiredNonEmptyFieldName
    $templateHasNonEmptyValue = -not [string]::IsNullOrWhiteSpace($templateValue)

    foreach ($file in @($startFiles.ToArray())) {
        $text = [System.IO.File]::ReadAllText($file, [System.Text.Encoding]::UTF8)
        $value = Get-FieldValue -Text $text -Name $requiredNonEmptyFieldName
        if ([string]::IsNullOrWhiteSpace($value)) {
            [void]$emptyValueFiles.Add($file)
            [void]$emptyValueFilesAll.Add(('{0}:{1}' -f $requiredNonEmptyFieldName, $file))
        }
    }

    [void]$nonEmptyFieldResults.Add([ordered]@{
        field_name = $requiredNonEmptyFieldName
        template_has_non_empty_value = [bool]$templateHasNonEmptyValue
        empty_value_files = @($emptyValueFiles.ToArray())
        pass = [bool]($templateHasNonEmptyValue -and $emptyValueFiles.Count -eq 0)
    })
}

foreach ($requiredPresenceFieldName in @($effectiveRequiredPresenceFieldNames)) {
    $missingPresenceFiles = New-Object 'System.Collections.Generic.List[string]'

    $templateHasField = Test-FieldLinePresent -Text $templateText -Name $requiredPresenceFieldName

    foreach ($file in @($startFiles.ToArray())) {
        $text = [System.IO.File]::ReadAllText($file, [System.Text.Encoding]::UTF8)
        if (-not (Test-FieldLinePresent -Text $text -Name $requiredPresenceFieldName)) {
            [void]$missingPresenceFiles.Add($file)
            [void]$missingRequiredPresenceFilesAll.Add(('{0}:{1}' -f $requiredPresenceFieldName, $file))
        }
    }

    [void]$requiredPresenceFieldResults.Add([ordered]@{
        field_name = $requiredPresenceFieldName
        template_has_field = [bool]$templateHasField
        missing_field_files = @($missingPresenceFiles.ToArray())
        pass = [bool]($templateHasField -and $missingPresenceFiles.Count -eq 0)
    })
}

foreach ($templateMatchFieldName in @($effectiveTemplateMatchFieldNames)) {
    $mismatchedValueFiles = New-Object 'System.Collections.Generic.List[string]'

    $templateValue = Get-FieldValue -Text $templateText -Name $templateMatchFieldName
    $templateHasValue = -not [string]::IsNullOrWhiteSpace($templateValue)

    foreach ($file in @($startFiles.ToArray())) {
        $text = [System.IO.File]::ReadAllText($file, [System.Text.Encoding]::UTF8)
        $value = Get-FieldValue -Text $text -Name $templateMatchFieldName
        if ($value -ne $templateValue) {
            [void]$mismatchedValueFiles.Add($file)
            [void]$mismatchedValueFilesAll.Add(('{0}:{1}' -f $templateMatchFieldName, $file))
        }
    }

    [void]$templateMatchFieldResults.Add([ordered]@{
        field_name = $templateMatchFieldName
        template_has_value = [bool]$templateHasValue
        mismatched_value_files = @($mismatchedValueFiles.ToArray())
        pass = [bool]($templateHasValue -and $mismatchedValueFiles.Count -eq 0)
    })
}

$pass = $true
foreach ($fieldResult in @($fieldResults.ToArray())) {
    if (-not [bool]$fieldResult.pass) {
        $pass = $false
    }
}
foreach ($nonEmptyFieldResult in @($nonEmptyFieldResults.ToArray())) {
    if (-not [bool]$nonEmptyFieldResult.pass) {
        $pass = $false
    }
}
foreach ($requiredPresenceFieldResult in @($requiredPresenceFieldResults.ToArray())) {
    if (-not [bool]$requiredPresenceFieldResult.pass) {
        $pass = $false
    }
}
if ($EnforceRunningStatusMessageTemplateMatch.IsPresent) {
    foreach ($templateMatchFieldResult in @($templateMatchFieldResults.ToArray())) {
        if (-not [bool]$templateMatchFieldResult.pass) {
            $pass = $false
        }
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
    start_file = $effectiveStartFile
    start_file_dirs = $StartFileDirs
    check_scope = $checkScope
    checked_start_files = @($checkedStartFiles.ToArray())
    start_file_count = $startFiles.Count
    fields = @($fieldResults.ToArray())
    required_non_empty_fields = @($effectiveNonEmptyFieldNames)
    non_empty_field_checks = @($nonEmptyFieldResults.ToArray())
    required_presence_fields = @($effectiveRequiredPresenceFieldNames)
    required_presence_field_checks = @($requiredPresenceFieldResults.ToArray())
    enforce_running_status_message_template_match = [bool]$EnforceRunningStatusMessageTemplateMatch
    template_match_fields = @($effectiveTemplateMatchFieldNames)
    template_match_field_checks = @($templateMatchFieldResults.ToArray())
    assert_entry_script_a_canonical = [bool]$AssertEntryScriptACanonical
    expected_entry_script_a = [string]$ExpectedEntryScriptA
    template_entry_script_a = [string]$templateEntryScriptAValue
    template_entry_script_a_ok = [bool]$templateEntryScriptAOk
    mismatched_entry_script_a_files = @($mismatchedEntryScriptAFiles.ToArray())
    missing_field_files = @($missingFieldFilesAll.ToArray())
    missing_reset_files = @($missingResetFilesAll.ToArray())
    missing_required_presence_files = @($missingRequiredPresenceFilesAll.ToArray())
    empty_value_files = @($emptyValueFilesAll.ToArray())
    mismatched_value_files = @($mismatchedValueFilesAll.ToArray())
    pass = [bool]$pass
}

if ($AsJson.IsPresent) {
    $summary | ConvertTo-Json -Depth 8
}
else {
    Write-Output ('[START-FIELD-SYNC] fields={0} start_files={1} check_scope={2}' -f (($effectiveFieldNames -join ',')), $startFiles.Count, $checkScope)
    foreach ($checkedStartFile in @($checkedStartFiles.ToArray())) {
        Write-Output ('[START-FIELD-SYNC] checked_start_file={0}' -f $checkedStartFile)
    }
    foreach ($fieldResult in @($fieldResults.ToArray())) {
        Write-Output ('[START-FIELD-SYNC] field={0} template_has_field={1} template_reset_has_field={2} reset_script_has_field={3} routine_has_token_arg={4} missing_field_files={5} missing_reset_files={6}' -f [string]$fieldResult.field_name, [bool]$fieldResult.template_has_field, [bool]$fieldResult.template_reset_has_field, [bool]$fieldResult.reset_script_has_field, [bool]$fieldResult.routine_has_token_arg, @($fieldResult.missing_field_files).Count, @($fieldResult.missing_reset_files).Count)
        foreach ($item in @($fieldResult.missing_field_files)) {
            Write-Output ('[START-FIELD-SYNC] missing_field_file field={0} path={1}' -f [string]$fieldResult.field_name, $item)
        }
        foreach ($item in @($fieldResult.missing_reset_files)) {
            Write-Output ('[START-FIELD-SYNC] missing_reset_file field={0} path={1}' -f [string]$fieldResult.field_name, $item)
        }
    }
    foreach ($nonEmptyFieldResult in @($nonEmptyFieldResults.ToArray())) {
        Write-Output ('[START-FIELD-SYNC] non_empty_field={0} template_has_non_empty_value={1} empty_value_files={2}' -f [string]$nonEmptyFieldResult.field_name, [bool]$nonEmptyFieldResult.template_has_non_empty_value, @($nonEmptyFieldResult.empty_value_files).Count)
        foreach ($item in @($nonEmptyFieldResult.empty_value_files)) {
            Write-Output ('[START-FIELD-SYNC] empty_value_file field={0} path={1}' -f [string]$nonEmptyFieldResult.field_name, $item)
        }
    }
    foreach ($requiredPresenceFieldResult in @($requiredPresenceFieldResults.ToArray())) {
        Write-Output ('[START-FIELD-SYNC] required_presence_field={0} template_has_field={1} missing_field_files={2}' -f [string]$requiredPresenceFieldResult.field_name, [bool]$requiredPresenceFieldResult.template_has_field, @($requiredPresenceFieldResult.missing_field_files).Count)
        foreach ($item in @($requiredPresenceFieldResult.missing_field_files)) {
            Write-Output ('[START-FIELD-SYNC] missing_required_presence_file field={0} path={1}' -f [string]$requiredPresenceFieldResult.field_name, $item)
        }
    }
    if ($EnforceRunningStatusMessageTemplateMatch.IsPresent) {
        foreach ($templateMatchFieldResult in @($templateMatchFieldResults.ToArray())) {
            Write-Output ('[START-FIELD-SYNC] template_match_field={0} template_has_value={1} mismatched_value_files={2}' -f [string]$templateMatchFieldResult.field_name, [bool]$templateMatchFieldResult.template_has_value, @($templateMatchFieldResult.mismatched_value_files).Count)
            foreach ($item in @($templateMatchFieldResult.mismatched_value_files)) {
                Write-Output ('[START-FIELD-SYNC] mismatched_value_file field={0} path={1}' -f [string]$templateMatchFieldResult.field_name, $item)
            }
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
    $resultToken = if ($pass) { 'pass' } else { 'fail' }
    Write-Output ('[START-FIELD-SYNC] result={0}' -f $resultToken)
}

if (-not $pass) {
    Exit-UnattendedFailure -Tag $script:UnhandledExitTag -Reason 'start field sync failed' -ExitCode 3
}

exit 0
