<#
.SYNOPSIS
    Install the vscode-chat-sender extension into VS Code.
    Run once before using ipc_chat_sender.py.
.DESCRIPTION
    Creates a symlink (or copy) of the extension in the VS Code extensions
    directory so that `code --command vscodeChatSender.send` works.
#>

param(
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$srcDir = Join-Path $repoRoot 'tools\test\vscode-chat-sender'
$extDir = Join-Path $env:USERPROFILE '.vscode\extensions\larsonzh.vscode-chat-sender'

Write-Host "Source: $srcDir" -ForegroundColor Cyan
Write-Host "Target: $extDir" -ForegroundColor Cyan

if (-not (Test-Path -LiteralPath $srcDir)) {
    Write-Error "Extension source not found: $srcDir"
    exit 1
}

if (-not (Test-Path -LiteralPath (Join-Path $srcDir 'package.json'))) {
    Write-Error "package.json missing in $srcDir"
    exit 1
}

if (-not (Test-Path -LiteralPath (Join-Path $srcDir 'extension.js'))) {
    Write-Error "extension.js missing in $srcDir"
    exit 1
}

if (Test-Path -LiteralPath $extDir) {
    if (-not $Force.IsPresent) {
        Write-Host "Extension already installed at $extDir" -ForegroundColor Yellow
        Write-Host "Use -Force to overwrite, or manually remove it first."
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

Write-Host "Extension installed successfully to $extDir" -ForegroundColor Green
Write-Host "Please reload the VS Code window (Ctrl+Shift+P -> Developer: Reload Window) to activate." -ForegroundColor Yellow
Write-Host "Then you can use: code --command vscodeChatSender.send" -ForegroundColor Cyan
Write-Host "Or use: python tools/test/ipc_chat_sender.py --message 'hello'" -ForegroundColor Cyan
