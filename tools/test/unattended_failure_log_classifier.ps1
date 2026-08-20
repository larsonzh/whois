Set-StrictMode -Version Latest

function Test-UnattendedFailureLogClassificationAuthoritative {
    param(
        [AllowEmptyString()][string]$Category,
        [bool]$HasCodeFault = $false
    )

    $normalized = $Category.Trim().ToLowerInvariant()
    return (
        $normalized -match '^task-definition(?:-|$)' -or
        $normalized -in @('script-fault', 'noncode-transient') -or
        [bool]$HasCodeFault
    )
}

function Get-UnattendedFailureLogClassification {
    param(
        [Parameter(Mandatory = $true)][object[]]$LogCandidates,
        [ValidateRange(1, 10000)][int]$TailLines = 600
    )

    $result = [ordered]@{
        Category = 'code-or-unknown'
        Evidence = 'no-script-or-network-marker'
        SourceLog = ''
        HasScriptFault = $false
        HasNetworkTransient = $false
        HasCodeFault = $false
    }

    $patterns = [ordered]@{
        TaskDefinition = '(?im)(\[DEV-VERIFY-MULTI\]\s+round_task_static_gate_fail=|\[TASK-STATIC-CHECK\]\s+severity=(?:error|warn)\s+detail=)'
        StructuredValidation = '(?im)(\[AB-UNATTENDED-RESULT\][^\r\n]*script=[^\r\n]*(?:PREFLIGHT|CHECK|GOLDEN|SELFTEST|MATRIX|VERIFY|SMOKE|PRECLASS)[^\r\n]*result=FAIL[^\r\n]*exit_code=\d+|\[[A-Z0-9_-]*(?:PREFLIGHT|CHECK|GOLDEN|SELFTEST|MATRIX|VERIFY|SMOKE|PRECLASS)[A-Z0-9_-]*\][^\r\n]*(?:\bresult=fail\b|(?<![=A-Za-z])(?-i:FAIL)(?![A-Za-z]))|\[remote_build\]\[ERROR\][^\r\n]*(?:preflight|golden|selftest|matrix|check|validation|verify|preclass)[^\r\n]*(?-i:FAIL))'
        StructuredChildExit = '(?im)(\[AB-UNATTENDED-RESULT\][^\r\n]*exit_code=\d+|\[ONECLICK-DRYRUN-SMOKE\]\s+oneclick_end exit_code=\d+)'
        StrongScriptFault = '(?im)(parsererror|unexpectedtoken|propertynotfoundexception|argumentexception|ioexception|参数类型不匹配|is not recognized as the name of a cmdlet|cannot find path\s+.*\.ps1)'
        WrapperStack = '(?im)(所在位置\s+.*\.ps1:\d+|at\s+.*\.ps1:\d+|line:\s*\d+\s*char:\s*\d+)'
        RequiredNetworkFailure = '(?im)(^\[CHECK-NET-PREFLIGHT(?:-REMOTE)?\][^\r\n]*\brequired=(?:true|True)\s+status=fail\b|^\[CHECK-NET-PREFLIGHT(?:-REMOTE)?\]\s+(?:summary\s+)?overall=FAIL\b[^\r\n]*\brequired_fails=[1-9]\d*\b|network_precheck_error|ssh_command_timed_out_after_[0-9]+_seconds)'
        SourceCode = '(?im)(\[CODE-STEP\]\s+fatal_error=\s*[^\r\n]+|code-step\s+fatal\s+error[^\r\n]*|src[\\/].*\.(c|h):\d+:\d+:\s*error:[^\r\n]*|error\s+C\d{4}\b[^\r\n]*|undefined\s+reference\s+to[^\r\n]*|compilation\s+terminated[^\r\n]*|was\s+not\s+declared\s+in\s+this\s+scope[^\r\n]*|conflicting\s+types\s+for[^\r\n]*|redefinition\s+of[^\r\n]*|no\s+member\s+named[^\r\n]*|fatal\s+error:\s+[^\r\n]*)'
    }

    $evidence = [ordered]@{
        TaskDefinition = $null
        SourceCode = $null
        Script = $null
        Network = $null
        StructuredValidation = $null
    }

    $artifactRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\out\artifacts'))
    $artifactRootPrefix = $artifactRoot.TrimEnd([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
    $expandedCandidateCount = 0
    $pendingCandidates = New-Object 'System.Collections.Generic.Queue[object]'
    $seenCandidatePaths = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($candidate in @($LogCandidates)) {
        $pendingCandidates.Enqueue($candidate)
    }

    while ($pendingCandidates.Count -gt 0 -and $expandedCandidateCount -lt 128) {
        $candidate = $pendingCandidates.Dequeue()
        $path = [string]$candidate.Path
        if ([string]::IsNullOrWhiteSpace($path)) {
            continue
        }

        try {
            $resolvedPath = [System.IO.Path]::GetFullPath((Resolve-Path -LiteralPath $path -ErrorAction Stop).Path)
        }
        catch {
            continue
        }
        if (-not $seenCandidatePaths.Add($resolvedPath)) {
            continue
        }
        $expandedCandidateCount++

        try {
            $allLines = @(Get-Content -LiteralPath $resolvedPath -ErrorAction Stop)
        }
        catch {
            continue
        }
        $fullText = ($allLines -join "`n")
        $text = ($allLines | Select-Object -Last $TailLines) -join "`n"

        foreach ($summaryMatch in [regex]::Matches($fullText, '(?im)^\[[^\]]+\]\s+summary_csv=(?<path>[^\r\n]+\.csv)\s*$')) {
            $summaryPath = [string]$summaryMatch.Groups['path'].Value
            if ([string]::IsNullOrWhiteSpace($summaryPath)) {
                continue
            }
            try {
                $resolvedSummaryPath = [System.IO.Path]::GetFullPath((Resolve-Path -LiteralPath $summaryPath -ErrorAction Stop).Path)
                if (-not $resolvedSummaryPath.StartsWith($artifactRootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
                    continue
                }
                $summaryRows = @(Import-Csv -LiteralPath $resolvedSummaryPath -ErrorAction Stop)
            }
            catch {
                continue
            }
            foreach ($summaryRow in $summaryRows) {
                $passValue = if ($summaryRow.PSObject.Properties.Name -contains 'Pass') { [string]$summaryRow.Pass } elseif ($summaryRow.PSObject.Properties.Name -contains 'RoundPass') { [string]$summaryRow.RoundPass } else { '' }
                if ($passValue.Trim().ToLowerInvariant() -notin @('false', '0')) {
                    continue
                }
                foreach ($propertyName in @('Log', 'FailureSourceLog')) {
                    if ($summaryRow.PSObject.Properties.Name -notcontains $propertyName) {
                        continue
                    }
                    $childPath = [string]$summaryRow.$propertyName
                    if (-not [string]::IsNullOrWhiteSpace($childPath)) {
                        try {
                            $resolvedChildPath = [System.IO.Path]::GetFullPath((Resolve-Path -LiteralPath $childPath -ErrorAction Stop).Path)
                        }
                        catch {
                            continue
                        }
                        if ($resolvedChildPath.StartsWith($artifactRootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
                            $pendingCandidates.Enqueue([pscustomobject]@{ Path = $resolvedChildPath; Label = 'failed-child-log' })
                        }
                    }
                }
            }
        }

        $path = $resolvedPath

        $scanFindings = [ordered]@{
            TaskDefinition = [regex]::Match($text, [string]$patterns.TaskDefinition)
            SourceCode = [regex]::Match($text, [string]$patterns.SourceCode)
            StrongScriptFault = [regex]::Match($text, [string]$patterns.StrongScriptFault)
            WrapperStack = [regex]::Match($text, [string]$patterns.WrapperStack)
            StructuredChildExit = [regex]::Match($text, [string]$patterns.StructuredChildExit)
            Network = [regex]::Match($text, [string]$patterns.RequiredNetworkFailure)
            StructuredValidation = [regex]::Match($text, [string]$patterns.StructuredValidation)
        }

        if ($scanFindings.TaskDefinition.Success -and $null -eq $evidence.TaskDefinition) {
            $evidence.TaskDefinition = [pscustomobject]@{ Value = [string]$scanFindings.TaskDefinition.Value; Path = $path }
        }
        if ($scanFindings.SourceCode.Success -and $null -eq $evidence.SourceCode) {
            $evidence.SourceCode = [pscustomobject]@{ Value = [string]$scanFindings.SourceCode.Value; Path = $path }
        }
        if (($scanFindings.StrongScriptFault.Success -or ($scanFindings.WrapperStack.Success -and -not $scanFindings.StructuredChildExit.Success)) -and $null -eq $evidence.Script) {
            $scriptValue = if ($scanFindings.StrongScriptFault.Success) { [string]$scanFindings.StrongScriptFault.Value } else { [string]$scanFindings.WrapperStack.Value }
            $evidence.Script = [pscustomobject]@{ Value = $scriptValue; Path = $path }
        }
        if ($scanFindings.Network.Success -and $null -eq $evidence.Network) {
            $evidence.Network = [pscustomobject]@{ Value = [string]$scanFindings.Network.Value; Path = $path }
        }
        if ($scanFindings.StructuredValidation.Success -and $null -eq $evidence.StructuredValidation) {
            $evidence.StructuredValidation = [pscustomobject]@{ Value = [string]$scanFindings.StructuredValidation.Value; Path = $path }
        }
    }

    $result.HasCodeFault = ($null -ne $evidence.SourceCode)
    $result.HasScriptFault = ($null -ne $evidence.Script)
    $result.HasNetworkTransient = ($null -ne $evidence.Network)

    $selected = $null
    $prefix = ''
    if ($null -ne $evidence.TaskDefinition) {
        $result.Category = 'task-definition-mismatch'
        $selected = $evidence.TaskDefinition
        $prefix = 'matched='
    }
    elseif ($null -ne $evidence.SourceCode) {
        $result.Category = 'code-or-unknown'
        $selected = $evidence.SourceCode
        $prefix = 'code='
    }
    elseif ($null -ne $evidence.Script) {
        $result.Category = 'script-fault'
        $selected = $evidence.Script
        $prefix = 'matched='
    }
    elseif ($null -ne $evidence.Network) {
        $result.Category = 'noncode-transient'
        $selected = $evidence.Network
        $prefix = 'matched='
    }
    elseif ($null -ne $evidence.StructuredValidation) {
        $result.Category = 'code-or-unknown'
        $selected = $evidence.StructuredValidation
        $prefix = 'validation='
    }

    if ($null -ne $selected) {
        $singleLine = [regex]::Replace(([string]$selected.Value -replace '\r?\n', ' '), '\s+', ' ').Trim()
        if ($singleLine.Length -gt 120) {
            $singleLine = $singleLine.Substring(0, 120)
        }
        $result.Evidence = $prefix + $singleLine
        $result.SourceLog = [string]$selected.Path
    }

    return [pscustomobject]$result
}