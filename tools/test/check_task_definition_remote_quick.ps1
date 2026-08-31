param(
    [Parameter(Mandatory = $true)][string[]]$TaskDefinitionFiles,
    [string]$RemoteHost = '10.0.0.199',
    [string]$RemoteUser = 'larson',
    [AllowEmptyString()][string]$SshKeyPath = '',
    [string]$Targets = 'x86_64 win64',
    [switch]$PrepareOnly,
    [switch]$KeepWorkspace
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$runRoot = Join-Path $repoRoot "tmp\task-definition-remote-quick\$timestamp"
$workspace = Join-Path $runRoot 'workspace'
$artifactRoot = Join-Path $workspace 'tmp\checker-artifacts'
$stateRoot = Join-Path $workspace 'tmp\code-step-state'
$remoteArtifacts = Join-Path $runRoot 'remote-artifacts'
$resolvedDefinitions = New-Object 'System.Collections.Generic.List[string]'

function Resolve-RepositoryFile {
    param([string]$Path)

    $candidate = if ([IO.Path]::IsPathRooted($Path)) { $Path } else { Join-Path $repoRoot $Path }
    $resolved = (Resolve-Path -LiteralPath $candidate -ErrorAction Stop).Path
    $rootPrefix = $repoRoot.TrimEnd('\') + '\'
    if (-not $resolved.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "[TASK-REMOTE-QUICK] task definition escapes repository: $Path"
    }
    return $resolved
}

foreach ($definitionGroup in $TaskDefinitionFiles) {
    foreach ($definition in @($definitionGroup -split ',')) {
        if ([string]::IsNullOrWhiteSpace($definition)) {
            throw '[TASK-REMOTE-QUICK] task definition path must not be empty'
        }
        [void]$resolvedDefinitions.Add((Resolve-RepositoryFile -Path $definition.Trim()))
    }
}

if ($resolvedDefinitions.Count -eq 0) {
    throw '[TASK-REMOTE-QUICK] at least one task definition is required'
}

New-Item -ItemType Directory -Path $workspace, $artifactRoot, $stateRoot, $remoteArtifacts -Force | Out-Null

try {
    Write-Output "[TASK-REMOTE-QUICK] step=copy-worktree status=start destination=$workspace"
    foreach ($item in Get-ChildItem -LiteralPath $repoRoot -Force) {
        if ($item.Name -in @('.git', 'out', 'tmp')) { continue }
        Copy-Item -LiteralPath $item.FullName -Destination $workspace -Recurse -Force
    }
    Write-Output '[TASK-REMOTE-QUICK] step=copy-worktree status=pass'

    for ($definitionIndex = 0; $definitionIndex -lt $resolvedDefinitions.Count; $definitionIndex++) {
        $sourceDefinition = $resolvedDefinitions[$definitionIndex]
        $relativeDefinition = $sourceDefinition.Substring($repoRoot.Length).TrimStart('\', '/')
        $workspaceDefinition = Join-Path $workspace $relativeDefinition
        $definitionLabel = 'definition-{0}' -f ($definitionIndex + 1)

        foreach ($round in @('D1', 'D2', 'D3', 'D4')) {
            $artifactDirectory = Join-Path $artifactRoot "$definitionLabel-$round"
            $stateDirectory = Join-Path $stateRoot $definitionLabel
            $checker = Join-Path $workspace 'tools\test\check_task_definition_static.ps1'
            $codeStep = Join-Path $workspace 'tools\test\autopilot_code_step_rounds.ps1'

            Write-Output "[TASK-REMOTE-QUICK] step=effective-tree definition=$definitionLabel round=$round status=start"
            & powershell -NoProfile -ExecutionPolicy Bypass -File $checker `
                -TaskDefinitionFile $workspaceDefinition -RepoRoot $workspace `
                -Policy enforce -FailOnWarnings -RoundTag $round `
                -OutputValidatedArtifactDirectory $artifactDirectory
            if ($LASTEXITCODE -ne 0) {
                throw "[TASK-REMOTE-QUICK] checker failed definition=$definitionLabel round=$round exit_code=$LASTEXITCODE"
            }

            & powershell -NoProfile -ExecutionPolicy Bypass -File $codeStep `
                -TaskDefinitionFile $workspaceDefinition -StateDir $stateDirectory `
                -ValidatedArtifactDirectory $artifactDirectory
            if ($LASTEXITCODE -ne 0) {
                throw "[TASK-REMOTE-QUICK] code-step failed definition=$definitionLabel round=$round exit_code=$LASTEXITCODE"
            }
            Write-Output "[TASK-REMOTE-QUICK] step=effective-tree definition=$definitionLabel round=$round status=pass"
        }
    }

    if ($PrepareOnly.IsPresent) {
        Write-Output "[TASK-REMOTE-QUICK] result=pass mode=prepare-only run_root=$runRoot"
        exit 0
    }

    $bashCandidates = @(
        (Join-Path $env:ProgramFiles 'Git\bin\bash.exe'),
        (Join-Path $env:ProgramFiles 'Git\usr\bin\bash.exe')
    )
    $bash = @($bashCandidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1)
    if ($bash.Count -eq 0) {
        throw '[TASK-REMOTE-QUICK] Git Bash not found'
    }

    Push-Location $workspace
    try {
        $arguments = @(
            './tools/remote/remote_build_and_test.sh',
            '-H', $RemoteHost,
            '-u', $RemoteUser,
            '-t', $Targets,
            '-w', '0',
            '-r', '0',
            '-L', '0',
            '-Y', '1',
            '-f', '../remote-artifacts'
        )
        if (-not [string]::IsNullOrWhiteSpace($SshKeyPath)) {
            $arguments += @('-k', $SshKeyPath)
        }
        Write-Output "[TASK-REMOTE-QUICK] step=remote-compile status=start targets=$Targets"
        & $bash[0] @arguments
        if ($LASTEXITCODE -ne 0) {
            throw "[TASK-REMOTE-QUICK] remote compile failed exit_code=$LASTEXITCODE"
        }
    }
    finally {
        Pop-Location
    }

    Write-Output "[TASK-REMOTE-QUICK] result=pass mode=remote-compile targets=$Targets run_root=$runRoot"
}
finally {
    if (-not $KeepWorkspace.IsPresent -and (Test-Path -LiteralPath $workspace)) {
        Remove-Item -LiteralPath $workspace -Recurse -Force -ErrorAction SilentlyContinue
    }
}