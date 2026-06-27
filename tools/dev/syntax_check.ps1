$file = 'D:\LZProjects\whois\tools\test\unattended_ab_supervisor.ps1'
$errors = $null
$null = [System.Management.Automation.Language.Parser]::ParseFile($file, [ref]$null, [ref]$errors)
if ($errors.Count -eq 0) {
    Write-Output "SYNTAX: PASS"
} else {
    Write-Output ("SYNTAX: FAIL - {0} errors" -f $errors.Count)
    foreach ($err in $errors) {
        Write-Output ("  Line {0}: {1}" -f $err.Extent.StartLine, $err.Message)
    }
}
