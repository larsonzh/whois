param(
    [switch]$AsJson
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path

$stageFiles = @(
    'tools/test/open_unattended_ab_stage_window.ps1',
    'tools/test/open_unattended_ab_resume_window.ps1',
    'tools/test/unattended_ab_session_guard.ps1'
)
$coreFile = 'tools/test/unattended_startfile_identity.ps1'

$forbiddenPattern = '^function\s+Invoke-KeyValueFileValueUpdate\b'
$corePattern = '^function\s+Invoke-KeyValueFileValueUpdateCore\b'
$legacyCallPattern = '\bInvoke-KeyValueFileValueUpdate\s+-Path\b'
$coreCallPattern = '\bInvoke-KeyValueFileValueUpdateCore\s+-Path\b'

$forbiddenMatches = New-Object 'System.Collections.Generic.List[object]'
$coreMatches = New-Object 'System.Collections.Generic.List[object]'
$legacyCalls = New-Object 'System.Collections.Generic.List[object]'
$coreCalls = New-Object 'System.Collections.Generic.List[object]'

foreach ($relativePath in $stageFiles) {
    $fullPath = Join-Path $repoRoot $relativePath
    if (-not (Test-Path -LiteralPath $fullPath)) {
        throw ("missing stage file: {0}" -f $relativePath)
    }

    foreach ($match in @(Select-String -Path $fullPath -Pattern $forbiddenPattern)) {
        [void]$forbiddenMatches.Add([pscustomobject]@{
            path = $relativePath
            line = [int]$match.LineNumber
            text = [string]$match.Line
        })
    }

    foreach ($match in @(Select-String -Path $fullPath -Pattern $legacyCallPattern)) {
        [void]$legacyCalls.Add([pscustomobject]@{
            path = $relativePath
            line = [int]$match.LineNumber
            text = [string]$match.Line
        })
    }

    foreach ($match in @(Select-String -Path $fullPath -Pattern $coreCallPattern)) {
        [void]$coreCalls.Add([pscustomobject]@{
            path = $relativePath
            line = [int]$match.LineNumber
            text = [string]$match.Line
        })
    }
}

$coreFullPath = Join-Path $repoRoot $coreFile
if (-not (Test-Path -LiteralPath $coreFullPath)) {
    throw ("missing shared core file: {0}" -f $coreFile)
}

foreach ($match in @(Select-String -Path $coreFullPath -Pattern $corePattern)) {
    [void]$coreMatches.Add([pscustomobject]@{
        path = $coreFile
        line = [int]$match.LineNumber
        text = [string]$match.Line
    })
}

$pass = ($forbiddenMatches.Count -eq 0 -and $coreMatches.Count -eq 1 -and $legacyCalls.Count -eq 0)
$result = [ordered]@{
    schema = 'UNATTENDED_WRITE_CORE_GUARD_V1'
    generated_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    pass = [bool]$pass
    forbidden_function_count = [int]$forbiddenMatches.Count
    shared_core_count = [int]$coreMatches.Count
    legacy_call_count = [int]$legacyCalls.Count
    shared_core_call_count = [int]$coreCalls.Count
    stage_files = $stageFiles
    shared_core_file = $coreFile
    forbidden_function_matches = @($forbiddenMatches.ToArray())
    shared_core_matches = @($coreMatches.ToArray())
    legacy_call_matches = @($legacyCalls.ToArray())
}

if ($AsJson.IsPresent) {
    $result | ConvertTo-Json -Depth 8
}
else {
    Write-Output ('[WRITE-CORE-GUARD] pass={0}' -f [string]$result.pass)
    Write-Output ('[WRITE-CORE-GUARD] forbidden_function_count={0}' -f [int]$result.forbidden_function_count)
    Write-Output ('[WRITE-CORE-GUARD] shared_core_count={0}' -f [int]$result.shared_core_count)
    Write-Output ('[WRITE-CORE-GUARD] legacy_call_count={0}' -f [int]$result.legacy_call_count)
    Write-Output ('[WRITE-CORE-GUARD] shared_core_call_count={0}' -f [int]$result.shared_core_call_count)

    if ($forbiddenMatches.Count -gt 0) {
        foreach ($item in @($forbiddenMatches.ToArray())) {
            Write-Output ('[WRITE-CORE-GUARD] forbidden_function path={0} line={1} text={2}' -f $item.path, [int]$item.line, [string]$item.text.Trim())
        }
    }

    if ($legacyCalls.Count -gt 0) {
        foreach ($item in @($legacyCalls.ToArray())) {
            Write-Output ('[WRITE-CORE-GUARD] legacy_call path={0} line={1} text={2}' -f $item.path, [int]$item.line, [string]$item.text.Trim())
        }
    }

    if ($coreMatches.Count -gt 0) {
        foreach ($item in @($coreMatches.ToArray())) {
            Write-Output ('[WRITE-CORE-GUARD] shared_core path={0} line={1} text={2}' -f $item.path, [int]$item.line, [string]$item.text.Trim())
        }
    }
}

if (-not $pass) {
    exit 1
}

exit 0
