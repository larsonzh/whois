Set-StrictMode -Version Latest

function Get-UnattendedExitCodeFromRecord {
    param(
        [string]$Tag,
        [System.Management.Automation.ErrorRecord]$Record,
        [int]$DefaultExitCode = 1
    )

    $exitCode = if ($DefaultExitCode -gt 0) { [int]$DefaultExitCode } else { 1 }
    $detail = ''
    if ($null -ne $Record -and $null -ne $Record.Exception) {
        $detail = [string]$Record.Exception.Message
    }

    $normalized = $detail.Trim().ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($normalized)) {
        return $exitCode
    }

    if ($normalized -match 'path must not be empty|must be an integer within|missing script|not found|cannot find path|because it does not exist|is missing in start file') {
        return 2
    }

    if ($normalized -match 'a_only_guard blocked|precheck gate blocked|launch-ready gate blocked|start gate blocked|task static precheck failed') {
        return 3
    }

    if ($normalized -match 'stage_delegate_failed') {
        return 4
    }

    return $exitCode
}

function Write-UnattendedUnhandledResult {
    param(
        [string]$Tag,
        [System.Management.Automation.ErrorRecord]$Record,
        [int]$ExitCode = 1
    )

    if ([string]::IsNullOrWhiteSpace($Tag)) {
        $Tag = 'UNATTENDED-SCRIPT'
    }

    $detail = if ($null -ne $Record -and $null -ne $Record.Exception) {
        [string]$Record.Exception.Message
    }
    else {
        'unknown-error'
    }

    $detail = ([regex]::Replace($detail, '\s+', ' ')).Trim()
    if ([string]::IsNullOrWhiteSpace($detail)) {
        $detail = 'unknown-error'
    }

    if ($ExitCode -le 0) {
        $ExitCode = 1
    }

    Write-Output ("[AB-UNATTENDED-RESULT] schema=AB_UNATTENDED_SCRIPT_RESULT_V1 script={0} result=FAIL final_result=FAIL exit_code={1} error={2}" -f $Tag, $ExitCode, $detail)
}

function Exit-UnattendedFailure {
    param(
        [string]$Tag,
        [string]$Reason,
        [int]$ExitCode = 1
    )

    if ([string]::IsNullOrWhiteSpace($Tag)) {
        $Tag = 'UNATTENDED-SCRIPT'
    }

    $detail = ([regex]::Replace([string]$Reason, '\s+', ' ')).Trim()
    if ([string]::IsNullOrWhiteSpace($detail)) {
        $detail = 'script-failed'
    }

    if ($ExitCode -le 0) {
        $ExitCode = 1
    }

    Write-Output ("[AB-UNATTENDED-RESULT] schema=AB_UNATTENDED_SCRIPT_RESULT_V1 script={0} result=FAIL final_result=FAIL exit_code={1} error={2}" -f $Tag, $ExitCode, $detail)
    exit $ExitCode
}
