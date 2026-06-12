Set-StrictMode -Version Latest

function Write-UnattendedUnhandledResult {
    param(
        [string]$Tag,
        [System.Management.Automation.ErrorRecord]$Record
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

    Write-Output ("[AB-UNATTENDED-RESULT] schema=AB_UNATTENDED_SCRIPT_RESULT_V1 script={0} result=FAIL final_result=FAIL exit_code=1 error={1}" -f $Tag, $detail)
}
