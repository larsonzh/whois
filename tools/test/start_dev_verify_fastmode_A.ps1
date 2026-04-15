param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$TaskDefinitionFileName
)

$ErrorActionPreference = "Stop"

function Resolve-TaskDefinitionRelativePath {
    param([string]$InputName)

    if ([string]::IsNullOrWhiteSpace($InputName)) {
        throw "TaskDefinitionFileName is required."
    }

    $normalized = $InputName.Trim().Replace("\\", "/")
    if ($normalized.StartsWith("./")) {
        $normalized = $normalized.Substring(2)
    }

    if ($normalized -match "^(?:[A-Za-z]:|/|\\\\)") {
        throw "TaskDefinitionFileName must be a repository-relative path under testdata/."
    }

    if (-not $normalized.StartsWith("testdata/")) {
        $normalized = "testdata/$normalized"
    }

    return $normalized
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
Set-Location $repoRoot

$taskDefinitionRelative = Resolve-TaskDefinitionRelativePath -InputName $TaskDefinitionFileName
$taskDefinitionAbsolute = Join-Path $repoRoot ($taskDefinitionRelative -replace "/", [System.IO.Path]::DirectorySeparatorChar)

if (-not (Test-Path -LiteralPath $taskDefinitionAbsolute)) {
    throw "Task definition file not found: $taskDefinitionRelative"
}

if (Select-String -Path $taskDefinitionAbsolute -Pattern "TODO_" -Quiet) {
    throw "Task definition still contains TODO placeholders: $taskDefinitionRelative"
}

$remoteIp = if ([string]::IsNullOrWhiteSpace($env:AUTO_REMOTE_IP)) { "10.0.0.199" } else { $env:AUTO_REMOTE_IP }
$remoteUser = if ([string]::IsNullOrWhiteSpace($env:AUTO_REMOTE_USER)) { "larson" } else { $env:AUTO_REMOTE_USER }
$keyPath = if ([string]::IsNullOrWhiteSpace($env:AUTO_REMOTE_KEYPATH)) { "/c/Users/$env:USERNAME/.ssh/id_rsa" } else { $env:AUTO_REMOTE_KEYPATH }
$queries = if ([string]::IsNullOrWhiteSpace($env:AUTO_QUERIES)) { "8.8.8.8 1.1.1.1 10.0.0.8" } else { $env:AUTO_QUERIES }

$entryScript = Join-Path $PSScriptRoot "start_dev_verify_8round_multiround.ps1"
if (-not (Test-Path -LiteralPath $entryScript)) {
    throw "Entry script not found: $entryScript"
}

Write-Output ("[FASTMODE-A] task_definition={0}" -f $taskDefinitionRelative)

& $entryScript `
    -ResetCodeStepState `
    -CodeStepResetPolicy restore-source `
    -TaskDefinitionFile $taskDefinitionRelative `
    -StartRound 1 -EndRound 8 `
    -DevVerifyStride 2 `
    -VerifyExecutionProfile d6-only `
    -EnableGuardedFastMode $true `
    -EnableGateOnlySourceDrivenSkip $true `
    -RbPreflight 1 -RbPreclassTableGuard 1 `
    -QuietTerminalOutput true `
    -QuietRemoteBuildLogs false `
    -TaskDesignQualityPolicy enforce `
    -UnknownNoOpBudget 1 -UnknownNoOpConsecutiveLimit 2 `
    -DisableUnknownNoOpBudgetGate:$false `
    -KeyPath $keyPath -RemoteIp $remoteIp -User $remoteUser -Queries $queries

$exitCode = if ($null -eq $LASTEXITCODE) { 0 } else { [int]$LASTEXITCODE }
Write-Output ("A_EXIT={0}" -f $exitCode)
exit $exitCode
