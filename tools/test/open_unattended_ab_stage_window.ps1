param(
    [ValidateSet('A', 'B')][string]$Stage,
    [string]$StartFile = 'tmp\unattended_ab_start_20260418-2200.md'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Resolve-RepoPath {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw 'Path must not be empty.'
    }

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return (Resolve-Path -LiteralPath $Path).Path
    }

    return (Resolve-Path -LiteralPath (Join-Path $repoRoot $Path)).Path
}

function Read-KeyValueFile {
    param([string]$Path)

    $map = [ordered]@{}
    foreach ($line in @(Get-Content -LiteralPath $Path)) {
        if ($line -match '^([^=]+)=(.*)$') {
            $map[$Matches[1].Trim()] = $Matches[2]
        }
    }

    return $map
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$settings = Read-KeyValueFile -Path (Resolve-RepoPath -Path $StartFile)

$entryScriptKey = if ($Stage -eq 'A') { 'ENTRY_SCRIPT_A' } else { 'ENTRY_SCRIPT_B' }
$taskKey = if ($Stage -eq 'A') { 'A_TASK_DEFINITION' } else { 'B_TASK_DEFINITION' }

$entryScriptPath = Resolve-RepoPath -Path ([string]$settings[$entryScriptKey])
$taskLeaf = [System.IO.Path]::GetFileName([string]$settings[$taskKey])

$powershellPath = Join-Path $PSHOME 'powershell.exe'
if (-not (Test-Path -LiteralPath $powershellPath)) {
    $powershellPath = 'powershell.exe'
}

$processInfo = Start-Process -FilePath $powershellPath -WorkingDirectory $repoRoot -ArgumentList @(
    '-NoExit',
    '-NoProfile',
    '-ExecutionPolicy', 'Bypass',
    '-File', $entryScriptPath,
    $taskLeaf
) -PassThru

Write-Output ("[OPEN-AB-STAGE] stage={0} pid={1} launcher_pid={2} entry={3} task={4}" -f $Stage, $processInfo.Id, $PID, $entryScriptPath, $taskLeaf)