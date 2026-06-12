param(
    [string]$StartFile = 'testdata/unattended_start/active/unattended_ab_start_20260929-20261014.md',
    [AllowEmptyString()][string]$TaskDefinitionFile = '',
    [AllowEmptyString()][string]$RemoteIp = '',
    [AllowEmptyString()][string]$RemoteUser = '',
    [AllowEmptyString()][string]$KeyPath = '',
    [AllowEmptyString()][string]$RemoteBase = '',
    [string]$WindowsSshPath = 'C:\Windows\System32\OpenSSH\ssh.exe',
    [ValidateRange(1, 65535)][int]$SshPort = 22,
    [ValidateRange(1, 300)][int]$TimeoutSec = 20,
    [switch]$AllowExistingLock,
    [switch]$SkipBRun,
    [switch]$KeepInjectedLock
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Convert-MsysPathToWindowsPath {
    param([AllowEmptyString()][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return ''
    }

    if ($Path -match '^/([a-zA-Z])/(.*)$') {
        $drive = $Matches[1].ToUpperInvariant()
        $rest = $Matches[2] -replace '/', '\\'
        return ('{0}:\\{1}' -f $drive, $rest)
    }

    return $Path
}

function Convert-ToBashSingleQuotedLiteral {
    param([AllowNull()][string]$Value)

    if ($null -eq $Value) {
        return "''"
    }

    return "'" + $Value.Replace("'", "'`"'`"'") + "'"
}

function Convert-ToProcessArgument {
    param([AllowNull()][string]$Value)

    if ($null -eq $Value) {
        return '""'
    }

    if ($Value -notmatch '[\s"]') {
        return $Value
    }

    $escaped = $Value -replace '(\\*)"', '$1$1\\"'
    $escaped = $escaped -replace '(\\+)$', '$1$1'
    return '"' + $escaped + '"'
}

function Invoke-SshScript {
    param(
        [string]$FilePath,
        [string[]]$Arguments,
        [string]$InputScript,
        [int]$TimeoutSec
    )

    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $FilePath
    $startInfo.Arguments = (($Arguments | ForEach-Object { Convert-ToProcessArgument -Value $_ }) -join ' ')
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardInput = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.CreateNoWindow = $true

    $process = [System.Diagnostics.Process]::Start($startInfo)
    try {
        $normalizedScript = $InputScript -replace "`r`n", "`n"
        $process.StandardInput.NewLine = "`n"
        $process.StandardInput.Write($normalizedScript)
        $process.StandardInput.Close()

        if (-not $process.WaitForExit($TimeoutSec * 1000)) {
            try {
                $process.Kill()
            }
            catch {
            }
            throw "ssh command timed out after $TimeoutSec seconds"
        }

        $stdout = $process.StandardOutput.ReadToEnd()
        $stderr = $process.StandardError.ReadToEnd()

        return [pscustomobject]@{
            ExitCode = $process.ExitCode
            StdOut = $stdout
            StdErr = $stderr
        }
    }
    finally {
        $process.Dispose()
    }
}

function Read-KeyValueFile {
    param([string]$Path)

    $lineMap = @{}
    $map = [ordered]@{}
    $lineNo = 0
    foreach ($line in @(Get-Content -LiteralPath $Path -Encoding utf8 -ErrorAction Stop)) {
        $lineNo++
        if ($line -match '^([^=]+)=(.*)$') {
            $key = $Matches[1].Trim()
            if ($map.Contains($key)) {
                throw ("Duplicate key '{0}' detected in {1} at line {2} and line {3}." -f $key, $Path, [int]$lineMap[$key], $lineNo)
            }
            $lineMap[$key] = $lineNo
            $map[$key] = $Matches[2]
        }
    }

    return $map
}

function Resolve-StartFilePath {
    param(
        [string]$RepoRoot,
        [string]$InputPath
    )

    if ([string]::IsNullOrWhiteSpace($InputPath)) {
        throw 'StartFile is required.'
    }

    $candidate = $InputPath
    if (-not [System.IO.Path]::IsPathRooted($candidate)) {
        $candidate = Join-Path $RepoRoot $candidate
    }

    $full = [System.IO.Path]::GetFullPath($candidate)
    if (-not (Test-Path -LiteralPath $full)) {
        throw "Start file not found: $InputPath"
    }

    return $full
}

function Resolve-TaskDefinitionRelativePath {
    param(
        [string]$RepoRoot,
        [AllowEmptyString()][string]$InputValue,
        [System.Collections.IDictionary]$Settings
    )

    $value = $InputValue
    if ([string]::IsNullOrWhiteSpace($value)) {
        if ($null -ne $Settings -and $Settings.Contains('B_TASK_DEFINITION')) {
            $value = [string]$Settings.B_TASK_DEFINITION
        }
    }

    if ([string]::IsNullOrWhiteSpace($value)) {
        throw 'Unable to resolve B task definition. Pass -TaskDefinitionFile or set B_TASK_DEFINITION in start file.'
    }

    $normalized = $value.Trim().Replace('\\', '/')
    if ($normalized.StartsWith('./')) {
        $normalized = $normalized.Substring(2)
    }

    if ($normalized -match '^(?:[A-Za-z]:|/|\\\\)') {
        $full = [System.IO.Path]::GetFullPath($normalized)
        $repoFull = [System.IO.Path]::GetFullPath($RepoRoot)
        if (-not $full.StartsWith($repoFull, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Task definition must be inside repository: $normalized"
        }

        $normalized = $full.Substring($repoFull.Length).TrimStart('\\').Replace('\\', '/')
    }

    if (-not $normalized.StartsWith('testdata/')) {
        $normalized = 'testdata/' + $normalized
    }

    $absolute = Join-Path $RepoRoot ($normalized -replace '/', [System.IO.Path]::DirectorySeparatorChar)
    if (-not (Test-Path -LiteralPath $absolute)) {
        throw "Task definition file not found: $normalized"
    }

    return $normalized
}

function Resolve-RemoteKeyPath {
    param(
        [AllowEmptyString()][string]$Candidate
    )

    $raw = $Candidate
    if ([string]::IsNullOrWhiteSpace($raw)) {
        $raw = "/c/Users/$env:USERNAME/.ssh/id_rsa"
    }

    if (-not [string]::IsNullOrWhiteSpace($raw) -and (Test-Path -LiteralPath $raw)) {
        return (Resolve-Path -LiteralPath $raw).Path
    }

    $converted = Convert-MsysPathToWindowsPath -Path $raw
    if (-not [string]::IsNullOrWhiteSpace($converted) -and (Test-Path -LiteralPath $converted)) {
        return (Resolve-Path -LiteralPath $converted).Path
    }

    $fallback = Join-Path ([Environment]::GetFolderPath('UserProfile')) '.ssh\id_rsa'
    if (Test-Path -LiteralPath $fallback) {
        return (Resolve-Path -LiteralPath $fallback).Path
    }

    throw "Unable to resolve SSH private key path. input=$Candidate"
}

function Get-TaggedOutputField {
    param(
        [string[]]$Lines,
        [string]$Tag,
        [string]$Key
    )

    $pattern = '^\[' + [regex]::Escape($Tag) + '\]\s+' + [regex]::Escape($Key) + '=(.*)$'
    foreach ($record in @($Lines)) {
        if ($null -eq $record) {
            continue
        }

        foreach ($rawLine in @(([string]$record) -split "`r?`n")) {
            if ([string]::IsNullOrWhiteSpace($rawLine)) {
                continue
            }

            $line = $rawLine.Trim().TrimStart([char]0xFEFF)
            if ($line -match $pattern) {
                return $Matches[1].Trim()
            }
        }
    }

    return ''
}

function Get-OutputField {
    param(
        [string[]]$Lines,
        [string]$Key
    )

    $pattern = '^' + [regex]::Escape($Key) + '=(.*)$'
    foreach ($record in @($Lines)) {
        if ($null -eq $record) {
            continue
        }

        foreach ($rawLine in @(([string]$record) -split "`r?`n")) {
            if ([string]::IsNullOrWhiteSpace($rawLine)) {
                continue
            }

            $line = $rawLine.Trim().TrimStart([char]0xFEFF)
            if ($line -match $pattern) {
                return $Matches[1].Trim()
            }
        }
    }

    return ''
}

function Resolve-ScenePathFromLines {
    param([string[]]$Lines)

    $scene = ''
    foreach ($record in @($Lines)) {
        if ($null -eq $record) {
            continue
        }

        foreach ($rawLine in @(([string]$record) -split "`r?`n")) {
            if ([string]::IsNullOrWhiteSpace($rawLine)) {
                continue
            }

            $line = $rawLine.Trim()
            if ($line -match '(?:^|[\s,])scene=([^\s,]+)') {
                $scene = $Matches[1]
            }
        }
    }

    return $scene
}

function Invoke-CheckRemoteLock {
    param(
        [string]$RepoRoot,
        [string]$RemoteIp,
        [string]$RemoteUser,
        [string]$KeyPath,
        [string]$RemoteBase,
        [int]$SshPort,
        [int]$TimeoutSec
    )

    $checkScript = Join-Path $RepoRoot 'tools\dev\check_remote_lock.ps1'
    if (-not (Test-Path -LiteralPath $checkScript)) {
        throw "remote lock check script not found: $checkScript"
    }

    $params = @{
        RemoteIp = $RemoteIp
        RemoteUser = $RemoteUser
        KeyPath = $KeyPath
        SshPort = $SshPort
        TimeoutSec = $TimeoutSec
    }
    if (-not [string]::IsNullOrWhiteSpace($RemoteBase)) {
        $params.RemoteBase = $RemoteBase
    }

    return @((& $checkScript @params 2>&1) | ForEach-Object { [string]$_ })
}

function Invoke-ClearRemoteLock {
    param(
        [string]$RepoRoot,
        [string]$RemoteIp,
        [string]$RemoteUser,
        [string]$KeyPath,
        [string]$RemoteBase,
        [int]$SshPort,
        [int]$TimeoutSec
    )

    $clearScript = Join-Path $RepoRoot 'tools\dev\clear_remote_lock.ps1'
    if (-not (Test-Path -LiteralPath $clearScript)) {
        throw "remote lock clear script not found: $clearScript"
    }

    $params = @{
        RemoteIp = $RemoteIp
        RemoteUser = $RemoteUser
        KeyPath = $KeyPath
        SshPort = $SshPort
        TimeoutSec = $TimeoutSec
    }
    if (-not [string]::IsNullOrWhiteSpace($RemoteBase)) {
        $params.RemoteBase = $RemoteBase
    }

    return @((& $clearScript @params 2>&1) | ForEach-Object { [string]$_ })
}

function Invoke-InjectRemoteLock {
    param(
        [string]$WindowsSshPath,
        [string]$RemoteIp,
        [string]$RemoteUser,
        [string]$KeyPath,
        [int]$SshPort,
        [int]$TimeoutSec,
        [AllowEmptyString()][string]$RemoteBase,
        [string]$Token,
        [string]$CreatedAt,
        [string]$CreatedEpoch,
        [string]$LocalHost,
        [string]$LocalUser,
        [string]$LocalPid,
        [string]$Repo
    )

    if (-not (Test-Path -LiteralPath $WindowsSshPath)) {
        throw "ssh executable not found: $WindowsSshPath"
    }

    if (-not (Test-Path -LiteralPath $KeyPath)) {
        throw "SSH private key not found: $KeyPath"
    }

    $remoteBaseLiteral = if ([string]::IsNullOrWhiteSpace($RemoteBase)) { "''" } else { Convert-ToBashSingleQuotedLiteral -Value $RemoteBase }
    $remoteBaseValue = if ([string]::IsNullOrWhiteSpace($RemoteBase)) { '/home/' + $RemoteUser + '/whois_remote' } else { $RemoteBase }

    $ownerLines = @(
        "token=$Token",
        "created_at=$CreatedAt",
        "created_epoch=$CreatedEpoch",
        "local_host=$LocalHost",
        "local_user=$LocalUser",
        "local_pid=$LocalPid",
        "ssh_user=$RemoteUser",
        "repo=$Repo",
        "remote_base=$remoteBaseValue"
    )
    $ownerLiteralArgs = ($ownerLines | ForEach-Object { Convert-ToBashSingleQuotedLiteral -Value $_ }) -join ' '

    $scriptTemplate = @'
REMOTE_BASE_INPUT=__REMOTE_BASE__

if [ -n "$REMOTE_BASE_INPUT" ]; then
  REMOTE_BASE="$REMOTE_BASE_INPUT"
else
  REMOTE_HOME=$(cd ~ && pwd)
  REMOTE_BASE="$REMOTE_HOME/whois_remote"
fi

LOCK_DIR="$REMOTE_BASE/.remote_build.lock"
rm -rf "$LOCK_DIR"
mkdir -p "$LOCK_DIR"
printf '%s\n' __OWNER_LINES__ > "$LOCK_DIR/owner.txt"

echo "[REMOTE-LOCK-REPRO] injected_token=__TOKEN__"
echo "[REMOTE-LOCK-REPRO] lock_dir=$LOCK_DIR"
'@

    $remoteScript = $scriptTemplate.Replace('__REMOTE_BASE__', $remoteBaseLiteral)
    $remoteScript = $remoteScript.Replace('__OWNER_LINES__', $ownerLiteralArgs)
    $remoteScript = $remoteScript.Replace('__TOKEN__', $Token)

    $sshArgs = @(
        '-o', 'BatchMode=yes',
        '-o', 'ConnectTimeout=10',
        '-o', 'ServerAliveInterval=5',
        '-o', 'ServerAliveCountMax=2',
        '-o', 'StrictHostKeyChecking=accept-new',
        '-o', 'UserKnownHostsFile=/dev/null',
        '-o', 'LogLevel=ERROR',
        '-i', $KeyPath,
        '-p', [string]$SshPort,
        ("{0}@{1}" -f $RemoteUser, $RemoteIp),
        'sh', '-s', '--'
    )

    $result = Invoke-SshScript -FilePath $WindowsSshPath -Arguments $sshArgs -InputScript $remoteScript -TimeoutSec $TimeoutSec
    $lines = @()
    if (-not [string]::IsNullOrWhiteSpace($result.StdOut)) {
        $lines += @($result.StdOut.TrimEnd() -split "`r?`n")
    }
    if (-not [string]::IsNullOrWhiteSpace($result.StdErr)) {
        $lines += @($result.StdErr.TrimEnd() -split "`r?`n")
    }

    if ($result.ExitCode -ne 0) {
        throw ("ssh inject lock failed (exit={0})" -f $result.ExitCode)
    }

    return @($lines | ForEach-Object { [string]$_ })
}

function Invoke-FastmodeB {
    param(
        [string]$RepoRoot,
        [string]$TaskDefinitionRelative
    )

    $scriptPath = Join-Path $RepoRoot 'tools\test\start_dev_verify_fastmode_B.ps1'
    if (-not (Test-Path -LiteralPath $scriptPath)) {
        throw "Fastmode B script not found: $scriptPath"
    }

    $lines = @((& $scriptPath $TaskDefinitionRelative 2>&1) | ForEach-Object { [string]$_ })
    $exitCode = if ($null -eq $LASTEXITCODE) { 0 } else { [int]$LASTEXITCODE }

    return [pscustomobject]@{
        ExitCode = $exitCode
        Lines = @($lines)
    }
}

function Restore-EnvVar {
    param(
        [string]$Name,
        [AllowNull()][string]$Value,
        [bool]$HadValue
    )

    if ($HadValue) {
        Set-Item -Path ("Env:{0}" -f $Name) -Value $Value
    }
    else {
        Remove-Item -Path ("Env:{0}" -f $Name) -ErrorAction SilentlyContinue
    }
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location $repoRoot

$startFilePath = Resolve-StartFilePath -RepoRoot $repoRoot -InputPath $StartFile
$settings = Read-KeyValueFile -Path $startFilePath
$taskDefinitionRelative = Resolve-TaskDefinitionRelativePath -RepoRoot $repoRoot -InputValue $TaskDefinitionFile -Settings $settings

$resolvedRemoteIp = if (-not [string]::IsNullOrWhiteSpace($RemoteIp)) { $RemoteIp } elseif ($settings.Contains('REMOTE_IP')) { [string]$settings.REMOTE_IP } else { '10.0.0.199' }
$resolvedRemoteUser = if (-not [string]::IsNullOrWhiteSpace($RemoteUser)) { $RemoteUser } elseif ($settings.Contains('REMOTE_USER')) { [string]$settings.REMOTE_USER } else { 'larson' }
$keyPathInput = if (-not [string]::IsNullOrWhiteSpace($KeyPath)) { $KeyPath } elseif (-not [string]::IsNullOrWhiteSpace([string]$env:AUTO_REMOTE_KEYPATH)) { [string]$env:AUTO_REMOTE_KEYPATH } else { "/c/Users/$env:USERNAME/.ssh/id_rsa" }
$resolvedKeyPath = Resolve-RemoteKeyPath -Candidate $keyPathInput

Write-Output ("[REMOTE-LOCK-REPRO] start_file={0}" -f $startFilePath)
Write-Output ("[REMOTE-LOCK-REPRO] task_definition={0}" -f $taskDefinitionRelative)
Write-Output ("[REMOTE-LOCK-REPRO] remote={0}@{1}" -f $resolvedRemoteUser, $resolvedRemoteIp)
Write-Output ("[REMOTE-LOCK-REPRO] key_path={0}" -f $resolvedKeyPath)
Write-Output ("[REMOTE-LOCK-REPRO] timeout_sec={0} ssh_port={1}" -f $TimeoutSec, $SshPort)

$envBackup = @{
    AUTO_START_FILE_PATH = [pscustomobject]@{ Had = (Test-Path -Path 'Env:AUTO_START_FILE_PATH'); Value = [string]$env:AUTO_START_FILE_PATH }
    AUTO_REMOTE_IP = [pscustomobject]@{ Had = (Test-Path -Path 'Env:AUTO_REMOTE_IP'); Value = [string]$env:AUTO_REMOTE_IP }
    AUTO_REMOTE_USER = [pscustomobject]@{ Had = (Test-Path -Path 'Env:AUTO_REMOTE_USER'); Value = [string]$env:AUTO_REMOTE_USER }
    AUTO_REMOTE_KEYPATH = [pscustomobject]@{ Had = (Test-Path -Path 'Env:AUTO_REMOTE_KEYPATH'); Value = [string]$env:AUTO_REMOTE_KEYPATH }
}

$injectedToken = ''
$bRun = $null
$scenePath = ''
$reproSucceeded = $false

try {
    Set-Item -Path Env:AUTO_START_FILE_PATH -Value $startFilePath
    Set-Item -Path Env:AUTO_REMOTE_IP -Value $resolvedRemoteIp
    Set-Item -Path Env:AUTO_REMOTE_USER -Value $resolvedRemoteUser
    Set-Item -Path Env:AUTO_REMOTE_KEYPATH -Value $resolvedKeyPath

    $preCheckLines = Invoke-CheckRemoteLock -RepoRoot $repoRoot -RemoteIp $resolvedRemoteIp -RemoteUser $resolvedRemoteUser -KeyPath $resolvedKeyPath -RemoteBase $RemoteBase -SshPort $SshPort -TimeoutSec $TimeoutSec
    foreach ($line in $preCheckLines) {
        if (-not [string]::IsNullOrWhiteSpace($line)) {
            Write-Output $line
        }
    }

    $preState = (Get-TaggedOutputField -Lines $preCheckLines -Tag 'CHECK-REMOTE-LOCK' -Key 'state').ToLowerInvariant()
    if ($preState -eq 'present' -and -not $AllowExistingLock.IsPresent) {
        throw 'Remote lock is already present before repro. Re-run with -AllowExistingLock only if you intend to replace it.'
    }

    $injectedToken = ('repro-{0}-{1}' -f (Get-Date -Format 'yyyyMMddHHmmss'), $PID)
    $createdAt = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss')
    $createdEpoch = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds().ToString()
    $localHost = [string]$env:COMPUTERNAME
    $localUser = [string]$env:USERNAME
    $repoTag = '/d/LZProjects/whois'

    $injectLines = Invoke-InjectRemoteLock -WindowsSshPath $WindowsSshPath -RemoteIp $resolvedRemoteIp -RemoteUser $resolvedRemoteUser -KeyPath $resolvedKeyPath -SshPort $SshPort -TimeoutSec $TimeoutSec -RemoteBase $RemoteBase -Token $injectedToken -CreatedAt $createdAt -CreatedEpoch $createdEpoch -LocalHost $localHost -LocalUser $localUser -LocalPid '999999' -Repo $repoTag
    foreach ($line in $injectLines) {
        if (-not [string]::IsNullOrWhiteSpace($line)) {
            Write-Output $line
        }
    }

    $postInjectLines = Invoke-CheckRemoteLock -RepoRoot $repoRoot -RemoteIp $resolvedRemoteIp -RemoteUser $resolvedRemoteUser -KeyPath $resolvedKeyPath -RemoteBase $RemoteBase -SshPort $SshPort -TimeoutSec $TimeoutSec
    foreach ($line in $postInjectLines) {
        if (-not [string]::IsNullOrWhiteSpace($line)) {
            Write-Output $line
        }
    }

    $postInjectState = (Get-TaggedOutputField -Lines $postInjectLines -Tag 'CHECK-REMOTE-LOCK' -Key 'state').ToLowerInvariant()
    $postInjectToken = Get-TaggedOutputField -Lines $postInjectLines -Tag 'CHECK-REMOTE-LOCK' -Key 'token'
    if ($postInjectState -ne 'present') {
        throw 'Injected lock is not present after injection step.'
    }
    if ($postInjectToken -ne $injectedToken) {
        throw ("Injected token mismatch. expected={0} actual={1}" -f $injectedToken, $postInjectToken)
    }

    if ($SkipBRun.IsPresent) {
        Write-Output '[REMOTE-LOCK-REPRO] skip_b_run=true'
    }
    else {
        $bRun = Invoke-FastmodeB -RepoRoot $repoRoot -TaskDefinitionRelative $taskDefinitionRelative
        foreach ($line in @($bRun.Lines)) {
            if (-not [string]::IsNullOrWhiteSpace($line)) {
                Write-Output $line
            }
        }

        $scenePath = Resolve-ScenePathFromLines -Lines $bRun.Lines
        if (-not [string]::IsNullOrWhiteSpace($scenePath)) {
            Write-Output ("[REMOTE-LOCK-REPRO] scene_path={0}" -f $scenePath)
        }

        $bFailCategory = (Get-OutputField -Lines $bRun.Lines -Key 'B_FAIL_CATEGORY').ToLowerInvariant()
        $reproSucceeded = ($bFailCategory -eq 'remote-lock-gate' -and -not [string]::IsNullOrWhiteSpace($scenePath))
        Write-Output ("[REMOTE-LOCK-REPRO] b_exit={0}" -f [int]$bRun.ExitCode)
        Write-Output ("[REMOTE-LOCK-REPRO] b_fail_category={0}" -f $bFailCategory)
        Write-Output ("[REMOTE-LOCK-REPRO] repro_success={0}" -f ([string]$reproSucceeded).ToLowerInvariant())
    }
}
finally {
    Restore-EnvVar -Name 'AUTO_START_FILE_PATH' -Value ([string]$envBackup.AUTO_START_FILE_PATH.Value) -HadValue ([bool]$envBackup.AUTO_START_FILE_PATH.Had)
    Restore-EnvVar -Name 'AUTO_REMOTE_IP' -Value ([string]$envBackup.AUTO_REMOTE_IP.Value) -HadValue ([bool]$envBackup.AUTO_REMOTE_IP.Had)
    Restore-EnvVar -Name 'AUTO_REMOTE_USER' -Value ([string]$envBackup.AUTO_REMOTE_USER.Value) -HadValue ([bool]$envBackup.AUTO_REMOTE_USER.Had)
    Restore-EnvVar -Name 'AUTO_REMOTE_KEYPATH' -Value ([string]$envBackup.AUTO_REMOTE_KEYPATH.Value) -HadValue ([bool]$envBackup.AUTO_REMOTE_KEYPATH.Had)

    if ($KeepInjectedLock.IsPresent) {
        Write-Output '[REMOTE-LOCK-REPRO] keep_injected_lock=true skip_cleanup=true'
    }
    elseif (-not [string]::IsNullOrWhiteSpace($injectedToken)) {
        try {
            $checkBeforeCleanup = Invoke-CheckRemoteLock -RepoRoot $repoRoot -RemoteIp $resolvedRemoteIp -RemoteUser $resolvedRemoteUser -KeyPath $resolvedKeyPath -RemoteBase $RemoteBase -SshPort $SshPort -TimeoutSec $TimeoutSec
            foreach ($line in $checkBeforeCleanup) {
                if (-not [string]::IsNullOrWhiteSpace($line)) {
                    Write-Output $line
                }
            }

            $stateBeforeCleanup = (Get-TaggedOutputField -Lines $checkBeforeCleanup -Tag 'CHECK-REMOTE-LOCK' -Key 'state').ToLowerInvariant()
            $tokenBeforeCleanup = Get-TaggedOutputField -Lines $checkBeforeCleanup -Tag 'CHECK-REMOTE-LOCK' -Key 'token'
            if ($stateBeforeCleanup -eq 'present' -and $tokenBeforeCleanup -eq $injectedToken) {
                $clearLines = Invoke-ClearRemoteLock -RepoRoot $repoRoot -RemoteIp $resolvedRemoteIp -RemoteUser $resolvedRemoteUser -KeyPath $resolvedKeyPath -RemoteBase $RemoteBase -SshPort $SshPort -TimeoutSec $TimeoutSec
                foreach ($line in $clearLines) {
                    if (-not [string]::IsNullOrWhiteSpace($line)) {
                        Write-Output $line
                    }
                }
            }
            elseif ($stateBeforeCleanup -eq 'present') {
                Write-Output ("[REMOTE-LOCK-REPRO] cleanup_skipped token_mismatch current={0} expected={1}" -f $tokenBeforeCleanup, $injectedToken)
            }
            else {
                Write-Output '[REMOTE-LOCK-REPRO] cleanup_skip lock_absent'
            }

            $finalCheck = Invoke-CheckRemoteLock -RepoRoot $repoRoot -RemoteIp $resolvedRemoteIp -RemoteUser $resolvedRemoteUser -KeyPath $resolvedKeyPath -RemoteBase $RemoteBase -SshPort $SshPort -TimeoutSec $TimeoutSec
            foreach ($line in $finalCheck) {
                if (-not [string]::IsNullOrWhiteSpace($line)) {
                    Write-Output $line
                }
            }
        }
        catch {
            Write-Output ("[REMOTE-LOCK-REPRO] cleanup_error detail={0}" -f $_.Exception.Message)
        }
    }
}

if ($SkipBRun.IsPresent) {
    exit 0
}

if ($reproSucceeded) {
    exit 0
}

exit 2
