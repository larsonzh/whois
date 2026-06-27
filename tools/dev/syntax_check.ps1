$files = @(
    'D:\LZProjects\whois\tools\test\unattended_ab_supervisor.ps1',
    'D:\LZProjects\whois\tools\test\open_unattended_ab_supervisor_window.ps1',
    'D:\LZProjects\whois\tools\test\open_unattended_ab_companion_window.ps1',
    'D:\LZProjects\whois\tools\test\open_unattended_ab_session_guard_window.ps1',
    'D:\LZProjects\whois\tools\test\open_unattended_ab_takeover_trigger_window.ps1',
    'D:\LZProjects\whois\tools\test\start_dev_verify_8round_multiround.ps1'
)

foreach ($file in $files) {
    $errors = $null
    $null = [System.Management.Automation.Language.Parser]::ParseFile($file, [ref]$null, [ref]$errors)
    if ($errors.Count -eq 0) {
        Write-Output ("PASS: {0}" -f $file)
    } else {
        Write-Output ("FAIL: {0}" -f $file)
        foreach ($err in $errors) {
            Write-Output ("  Line {0}: {1}" -f $err.Extent.StartLine, $err.Message)
        }
    }
}
