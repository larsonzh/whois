<#
Check the remote build lock used by tools/remote/remote_build_and_test.sh.

Behavior:
  - Uses Windows OpenSSH directly instead of nesting PowerShell -> Git Bash -> ssh.
  - Resolves the remote base to <remote home>/whois_remote unless -RemoteBase is provided.
  - Reads .remote_build.lock/owner.txt and reports current lock state and stale age.
  - Does not mutate remote files or processes.

Usage examples:
  .\tools\dev\check_remote_lock.ps1
  .\tools\dev\check_remote_lock.ps1 -RemoteIp 10.0.0.199 -RemoteUser larson
  .\tools\dev\check_remote_lock.ps1 -RemoteBase /home/larson/whois_remote -StaleSec 14400
#>

param(
    [string]$RemoteIp = "10.0.0.199",
    [string]$RemoteUser = "larson",
    [string]$KeyPath = ("C:\Users\{0}\.ssh\id_rsa" -f $env:USERNAME),
    [string]$WindowsSshPath = "C:\Windows\System32\OpenSSH\ssh.exe",
    [AllowEmptyString()][string]$RemoteBase = "",
    [ValidateRange(0, [int]::MaxValue)][int]$StaleSec = 14400,
    [ValidateRange(1, 65535)][int]$SshPort = 22,
    [ValidateRange(1, 300)][int]$TimeoutSec = 20
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

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

if (-not (Test-Path -LiteralPath $WindowsSshPath)) {
    throw "ssh executable not found: $WindowsSshPath"
}

if (-not (Test-Path -LiteralPath $KeyPath)) {
    throw "SSH private key not found: $KeyPath"
}

$remoteBaseLiteral = if ([string]::IsNullOrWhiteSpace($RemoteBase)) {
    "''"
}
else {
    Convert-ToBashSingleQuotedLiteral -Value $RemoteBase
}

$remoteScript = @'
REMOTE_BASE_INPUT=__REMOTE_BASE__
STALE_SEC=__STALE_SEC__

read_field() {
  key="$1"
  sed -n "s/^${key}=//p" "$LOCK_INFO" | head -n1
}

if [ -n "$REMOTE_BASE_INPUT" ]; then
  REMOTE_BASE="$REMOTE_BASE_INPUT"
else
  REMOTE_HOME=$(cd ~ && pwd)
  REMOTE_BASE="$REMOTE_HOME/whois_remote"
fi

LOCK_DIR="$REMOTE_BASE/.remote_build.lock"
LOCK_INFO="$LOCK_DIR/owner.txt"
NOW_EPOCH=$(date +%s)

echo "[CHECK-REMOTE-LOCK] remote_base=$REMOTE_BASE"
echo "[CHECK-REMOTE-LOCK] lock_dir=$LOCK_DIR"
echo "[CHECK-REMOTE-LOCK] stale_threshold_sec=$STALE_SEC"

if [ ! -d "$LOCK_DIR" ]; then
  echo "[CHECK-REMOTE-LOCK] state=absent"
  exit 0
fi

echo "[CHECK-REMOTE-LOCK] state=present"

if [ ! -f "$LOCK_INFO" ]; then
  echo "[CHECK-REMOTE-LOCK] owner_info=missing"
  exit 0
fi

TOKEN=$(read_field token || true)
CREATED_AT=$(read_field created_at || true)
CREATED_EPOCH=$(read_field created_epoch || true)
LOCAL_HOST=$(read_field local_host || true)
LOCAL_USER=$(read_field local_user || true)
LOCAL_PID=$(read_field local_pid || true)
SSH_USER=$(read_field ssh_user || true)
REPO=$(read_field repo || true)
RECORDED_REMOTE_BASE=$(read_field remote_base || true)

echo "[CHECK-REMOTE-LOCK] owner_info=present"
echo "[CHECK-REMOTE-LOCK] token=${TOKEN}"
echo "[CHECK-REMOTE-LOCK] created_at=${CREATED_AT}"
echo "[CHECK-REMOTE-LOCK] created_epoch=${CREATED_EPOCH}"
echo "[CHECK-REMOTE-LOCK] local_host=${LOCAL_HOST}"
echo "[CHECK-REMOTE-LOCK] local_user=${LOCAL_USER}"
echo "[CHECK-REMOTE-LOCK] local_pid=${LOCAL_PID}"
echo "[CHECK-REMOTE-LOCK] ssh_user=${SSH_USER}"
echo "[CHECK-REMOTE-LOCK] repo=${REPO}"
echo "[CHECK-REMOTE-LOCK] recorded_remote_base=${RECORDED_REMOTE_BASE}"

case "$CREATED_EPOCH" in
  ''|*[!0-9]*)
    echo "[CHECK-REMOTE-LOCK] age_sec=unknown"
    echo "[CHECK-REMOTE-LOCK] stale=unknown"
    ;;
  *)
    AGE_SEC=$((NOW_EPOCH - CREATED_EPOCH))
    echo "[CHECK-REMOTE-LOCK] age_sec=${AGE_SEC}"
    if [ "$STALE_SEC" -gt 0 ] && [ "$AGE_SEC" -ge "$STALE_SEC" ]; then
      echo "[CHECK-REMOTE-LOCK] stale=true"
    else
      echo "[CHECK-REMOTE-LOCK] stale=false"
    fi
    ;;
esac
'@

$remoteScript = $remoteScript.Replace('__REMOTE_BASE__', $remoteBaseLiteral)
$remoteScript = $remoteScript.Replace('__STALE_SEC__', [string]$StaleSec)

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

Write-Output ("[CHECK-REMOTE-LOCK] host={0}" -f $RemoteIp)
Write-Output ("[CHECK-REMOTE-LOCK] user={0}" -f $RemoteUser)
Write-Output ("[CHECK-REMOTE-LOCK] timeout_sec={0}" -f $TimeoutSec)

$result = Invoke-SshScript -FilePath $WindowsSshPath -Arguments $sshArgs -InputScript $remoteScript -TimeoutSec $TimeoutSec
if (-not [string]::IsNullOrWhiteSpace($result.StdOut)) {
    Write-Output $result.StdOut.TrimEnd()
}
if (-not [string]::IsNullOrWhiteSpace($result.StdErr)) {
    Write-Warning $result.StdErr.TrimEnd()
}
if ($result.ExitCode -ne 0) {
    throw "ssh command failed (exit=$($result.ExitCode))"
}
