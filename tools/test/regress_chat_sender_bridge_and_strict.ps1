param(
    [AllowEmptyString()][string]$PythonExePath = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'unattended_exit_result.ps1')
$script:UnhandledExitTag = 'REGRESS-CHAT-SENDER-BRIDGE-STRICT'

$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$pythonFile = Join-Path $repoRoot 'tools\test\copilot_chat_sender.py'
$dispatchFile = Join-Path $repoRoot 'tools\test\dispatch_takeover_to_chat.ps1'

$errors = New-Object 'System.Collections.Generic.List[string]'

function Add-CheckError {
    param([string]$Message)
    [void]$script:errors.Add($Message)
}

function Assert-Regex {
    param(
        [string]$Text,
        [string]$Pattern,
        [string]$Name
    )

    $opts = [System.Text.RegularExpressions.RegexOptions]::Singleline
    if (-not [System.Text.RegularExpressions.Regex]::IsMatch($Text, $Pattern, $opts)) {
        Add-CheckError -Message ("missing check: {0}" -f $Name)
    }
}

function Assert-NotRegex {
    param(
        [string]$Text,
        [string]$Pattern,
        [string]$Name
    )

    $opts = [System.Text.RegularExpressions.RegexOptions]::Singleline
    if ([System.Text.RegularExpressions.Regex]::IsMatch($Text, $Pattern, $opts)) {
        Add-CheckError -Message ("unexpected pattern: {0}" -f $Name)
    }
}

if (-not (Test-Path -LiteralPath $pythonFile)) {
    throw ("python sender file not found: {0}" -f $pythonFile)
}
if (-not (Test-Path -LiteralPath $dispatchFile)) {
    throw ("dispatch file not found: {0}" -f $dispatchFile)
}

$pythonText = Get-Content -LiteralPath $pythonFile -Raw -Encoding utf8
$dispatchText = Get-Content -LiteralPath $dispatchFile -Raw -Encoding utf8

# P1 strict transcript-source hardening checks
Assert-Regex -Text $pythonText -Pattern 'source\s*=\s*"main_window_fallback"' -Name 'fallback source renamed to main_window_fallback'
Assert-NotRegex -Text $pythonText -Pattern 'chat_root_main_window_fallback' -Name 'legacy chat_root_main_window_fallback removed'
Assert-Regex -Text $pythonText -Pattern 'def\s+_signature_source_allows_ticket_fingerprint\s*\([^)]*\)\s*(?:->\s*[^:]+)?\s*:\s*[\s\S]*if\s+source\.startswith\("chat_root"\):\s*\r?\n\s*return\s+True' -Name 'ticket fingerprint source guard keeps chat-root fast path'
Assert-Regex -Text $pythonText -Pattern 'def\s+_signature_source_allows_ticket_fingerprint\s*\([^)]*\)\s*(?:->\s*[^:]+)?\s*:\s*[\s\S]*return\s+source\s*==\s*"main_window_fallback"' -Name 'ticket fingerprint source guard allows main-window fallback only'

# P2 below-anchor fallback switch is actually consumed
Assert-Regex -Text $pythonText -Pattern 'self\.policy\.allow_below_anchor_restore_fallback' -Name 'below-anchor policy is consumed in capture'
Assert-Regex -Text $pythonText -Pattern 'below_anchor_fallback_used\s*=\s*True' -Name 'below-anchor fallback execution marker exists'

# P3 restore candidate corrections
Assert-Regex -Text $pythonText -Pattern 'return\s+True,\s*"candidate_qwindowtoolsavebits_untitled_iconic"' -Name 'untitled iconic qwindowtoolsavebits accepted'
Assert-Regex -Text $pythonText -Pattern 'if\s*\(not\s+is_visible\)\s+and\s+\(not\s+is_iconic\):\s*\r?\n\s*return\s+False,\s*"not_visible"' -Name 'untitled visibility guard allows iconic window'

# New bridge argument and dead-code cleanup markers
Assert-Regex -Text $pythonText -Pattern '--restore-previous-window-handles-csv' -Name 'python cli supports restore handles csv'
Assert-NotRegex -Text $pythonText -Pattern '"captured"\s*:\s*len\(handles\)' -Name 'legacy dead return block removed'

# Cross-sender handoff checks in dispatch
Assert-Regex -Text $dispatchText -Pattern 'Invoke-PythonChatDispatch\s*\{[\s\S]*PreferredRestoreWindowHandles' -Name 'python dispatch supports preferred restore handles'
Assert-Regex -Text $dispatchText -Pattern '--restore-previous-window-handles-csv' -Name 'dispatch forwards preferred handles to python cli'
Assert-Regex -Text $dispatchText -Pattern 'ahkRestoreHandlesForFallback' -Name 'ahk->python fallback handle bridge variable exists'
Assert-Regex -Text $dispatchText -Pattern 'Invoke-PythonChatDispatch[\s\S]*-PreferredRestoreWindowHandles\s+\$ahkRestoreHandlesForFallback' -Name 'ahk->python fallback passes preferred handles'

# Resolve python executable
$pythonExe = ''
if (-not [string]::IsNullOrWhiteSpace($PythonExePath) -and (Test-Path -LiteralPath $PythonExePath)) {
    $pythonExe = [System.IO.Path]::GetFullPath($PythonExePath)
}
elseif (Test-Path -LiteralPath 'C:\Program Files\Python313\python.exe') {
    $pythonExe = 'C:\Program Files\Python313\python.exe'
}
else {
    $pythonCmd = Get-Command python -ErrorAction SilentlyContinue
    if ($null -ne $pythonCmd -and -not [string]::IsNullOrWhiteSpace([string]$pythonCmd.Source)) {
        $pythonExe = [string]$pythonCmd.Source
    }
}

if ([string]::IsNullOrWhiteSpace($pythonExe)) {
    Add-CheckError -Message 'python executable not found for runtime probe'
}
else {
    & $pythonExe -m py_compile $pythonFile
    if ($LASTEXITCODE -ne 0) {
        Add-CheckError -Message 'py_compile failed for copilot_chat_sender.py'
    }

    $probeOutput = @(
        & $pythonExe $pythonFile --message 'regression-probe' --ticket-id 'regression-probe' --event 'regression' --json-output --dry-run --restore-previous-window-handles-csv '111,222|333' 2>&1
    )
    if ($LASTEXITCODE -ne 0) {
        Add-CheckError -Message 'python dry-run probe failed'
    }
    else {
        $jsonLine = ''
        for ($idx = $probeOutput.Count - 1; $idx -ge 0; $idx--) {
            $line = [string]$probeOutput[$idx]
            $trimmed = $line.Trim()
            if ($trimmed.StartsWith('{') -and $trimmed.EndsWith('}')) {
                $jsonLine = $trimmed
                break
            }
        }

        if ([string]::IsNullOrWhiteSpace($jsonLine)) {
            Add-CheckError -Message 'no json payload found in python dry-run probe output'
        }
        else {
            try {
                $probeObj = $jsonLine | ConvertFrom-Json -ErrorAction Stop
                if ([string]$probeObj.schema -ne 'AHK_CHAT_SEND_RESULT_V1') {
                    Add-CheckError -Message 'unexpected schema in python dry-run payload'
                }
            }
            catch {
                Add-CheckError -Message ('invalid json payload in python dry-run probe: {0}' -f $_.Exception.Message)
            }
        }
    }
}

if ($errors.Count -gt 0) {
    Write-Output '[CHAT-SENDER-REGRESSION] FAIL'
    foreach ($item in @($errors)) {
        Write-Output ("- {0}" -f $item)
    }
    Exit-UnattendedFailure -Tag $script:UnhandledExitTag -Reason ("chat-sender-regression failed: errors={0}" -f $errors.Count) -ExitCode 1
}

Write-Output '[CHAT-SENDER-REGRESSION] PASS all checks'
exit 0
