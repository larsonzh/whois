<#
.SYNOPSIS
    Install the vscode-chat-sender extension into VS Code.
    Run once before using ipc_chat_sender.py.
.DESCRIPTION
    Copies the extension files into the VS Code extensions directory.
    This extension is driven by file-based IPC scripts.
#>

param(
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'unattended_exit_result.ps1')
$script:UnhandledExitTag = 'INSTALL-IPC-CHAT-EXTENSION'
$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$srcDir = Join-Path $repoRoot 'tools\test\vscode-chat-sender'
$extDir = Join-Path $env:USERPROFILE '.vscode\extensions\larsonzh.vscode-chat-sender'

Write-Output "Source: $srcDir"
Write-Output "Target: $extDir"

if (-not (Test-Path -LiteralPath $srcDir)) {
    Write-Error "Extension source not found: $srcDir"
    Exit-UnattendedFailure -Tag $script:UnhandledExitTag -Reason ("extension source not found: {0}" -f $srcDir) -ExitCode 1
}

if (-not (Test-Path -LiteralPath (Join-Path $srcDir 'package.json'))) {
    Write-Error "package.json missing in $srcDir"
    Exit-UnattendedFailure -Tag $script:UnhandledExitTag -Reason ("package.json missing in {0}" -f $srcDir) -ExitCode 1
}

if (-not (Test-Path -LiteralPath (Join-Path $srcDir 'extension.js'))) {
    Write-Error "extension.js missing in $srcDir"
    Exit-UnattendedFailure -Tag $script:UnhandledExitTag -Reason ("extension.js missing in {0}" -f $srcDir) -ExitCode 1
}

if (Test-Path -LiteralPath $extDir) {
    if (-not $Force.IsPresent) {
        Write-Output "Extension already installed at $extDir"
        Write-Output "Use -Force to overwrite, or manually remove it first."
        exit 0
    }
    Remove-Item -LiteralPath $extDir -Recurse -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 300
}

New-Item -ItemType Directory -Path $extDir -Force | Out-Null

# Copy all files from source to extension directory
foreach ($item in Get-ChildItem -LiteralPath $srcDir -File) {
    Copy-Item -LiteralPath $item.FullName -Destination (Join-Path $extDir $item.Name) -Force
}

Write-Output "Extension installed successfully to $extDir"
Write-Output "Please reload the VS Code window (Ctrl+Shift+P -> Developer: Reload Window) to activate."
Write-Output "Then you can use: .\\tools\\test\\Send-IpcChatMessage.ps1 -Message 'hello'"
Write-Output "Or use: python tools/test/ipc_chat_sender.py --message 'hello'"

