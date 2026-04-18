<#
Clear the remote build lock used by tools/remote/remote_build_and_test.sh.

Behavior:
  - Uses Windows OpenSSH directly instead of nesting PowerShell -> Git Bash -> ssh.
  - Reads the remote lock first and refuses unsafe deletion by default.
  - Safe default deletion cases:
      * the lock is stale according to the configured threshold
      * the lock belongs to this host and the recorded local PID no longer exists,
        and no remote build processes are currently active
  - Use -DryRun to inspect the decision without deleting anything.
  - Use -Force to override non-stale ambiguity, but active remote build processes
    still block deletion.

Usage examples:
  .\tools\dev\clear_remote_lock.ps1 -DryRun
  .\tools\dev\clear_remote_lock.ps1
  .\tools\dev\clear_remote_lock.ps1 -Force
#>

param(
    [string]$RemoteIp = "10.0.0.199",
    [string]$RemoteUser = "larson",
    [string]$KeyPath = ("C:\Users\{0}\.ssh\id_rsa" -f $env:USERNAME),
    [string]$WindowsSshPath = "C:\Windows\System32\OpenSSH\ssh.exe",
    [AllowEmptyString()][string]$RemoteBase = "",
    [ValidateRange(0, [int]::MaxValue)][int]$StaleSec = 14400,
    [ValidateRange(1, 65535)][int]$SshPort = 22,
    [ValidateRange(1, 300)][int]$TimeoutSec = 20,
    [switch]$DryRun,
    [switch]$Force
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

function Get-TaggedFieldValue {
    param(
        [string[]]$Lines,
        [string]$Tag,
        [string]$Key
    )

    $pattern = "^\[$([regex]::Escape($Tag))\] $([regex]::Escape($Key))=(.*)$"
    foreach ($line in $Lines) {
        if ($line -match $pattern) {
            return $Matches[1].Trim()
        }
    }

    return ""
}

function Get-CurrentHostAliases {
    $aliases = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($value in @($env:COMPUTERNAME, $env:HOSTNAME, [System.Net.Dns]::GetHostName())) {
        if (-not [string]::IsNullOrWhiteSpace($value)) {
            [void]$aliases.Add($value.Trim())
        }
    }

    try {
        $hostname = hostname 2>$null
        if (-not [string]::IsNullOrWhiteSpace($hostname)) {
            [void]$aliases.Add($hostname.Trim())
        }
    }
    catch {
    }

    return @($aliases)
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

$inspectScript = @'
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
PROC_MATCHES=$(ps -eo pid=,ppid=,args= 2>/dev/null | grep -E 'remote_build_and_test\.sh|(^|[[:space:]])make([[:space:]]|$)|(^|[[:space:]])gcc([[:space:]]|$)|(^|[[:space:]])g\+\+([[:space:]]|$)|(^|[[:space:]])clang([[:space:]]|$)|(^|[[:space:]])cc1([[:space:]]|$)' | grep -v 'grep -E' || true)

echo "[CLEAR-REMOTE-LOCK] remote_base=$REMOTE_BASE"
echo "[CLEAR-REMOTE-LOCK] lock_dir=$LOCK_DIR"
echo "[CLEAR-REMOTE-LOCK] stale_threshold_sec=$STALE_SEC"

if [ -z "$PROC_MATCHES" ]; then
  echo "[CLEAR-REMOTE-LOCK] remote_build_processes=absent"
else
  echo "[CLEAR-REMOTE-LOCK] remote_build_processes=present"
  printf '%s\n' "$PROC_MATCHES" | sed 's/^/[CLEAR-REMOTE-LOCK] remote_proc=/'
fi

if [ ! -d "$LOCK_DIR" ]; then
  echo "[CLEAR-REMOTE-LOCK] state=absent"
  exit 0
fi

echo "[CLEAR-REMOTE-LOCK] state=present"

if [ ! -f "$LOCK_INFO" ]; then
  echo "[CLEAR-REMOTE-LOCK] owner_info=missing"
  echo "[CLEAR-REMOTE-LOCK] age_sec=unknown"
  echo "[CLEAR-REMOTE-LOCK] stale=unknown"
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

echo "[CLEAR-REMOTE-LOCK] owner_info=present"
echo "[CLEAR-REMOTE-LOCK] token=${TOKEN}"
echo "[CLEAR-REMOTE-LOCK] created_at=${CREATED_AT}"
echo "[CLEAR-REMOTE-LOCK] created_epoch=${CREATED_EPOCH}"
echo "[CLEAR-REMOTE-LOCK] local_host=${LOCAL_HOST}"
echo "[CLEAR-REMOTE-LOCK] local_pid=${LOCAL_PID}"
echo "[CLEAR-REMOTE-LOCK] ssh_user=${SSH_USER}"
echo "[CLEAR-REMOTE-LOCK] repo=${REPO}"
echo "[CLEAR-REMOTE-LOCK] recorded_remote_base=${RECORDED_REMOTE_BASE}"

case "$CREATED_EPOCH" in
  ''|*[!0-9]*)
    echo "[CLEAR-REMOTE-LOCK] age_sec=unknown"
    echo "[CLEAR-REMOTE-LOCK] stale=unknown"
    ;;
  *)
    AGE_SEC=$((NOW_EPOCH - CREATED_EPOCH))
    echo "[CLEAR-REMOTE-LOCK] age_sec=${AGE_SEC}"
    if [ "$STALE_SEC" -gt 0 ] && [ "$AGE_SEC" -ge "$STALE_SEC" ]; then
      echo "[CLEAR-REMOTE-LOCK] stale=true"
    else
      echo "[CLEAR-REMOTE-LOCK] stale=false"
    fi
    ;;
esac
'@

$deleteScript = @'
REMOTE_BASE_INPUT=__REMOTE_BASE__

if [ -n "$REMOTE_BASE_INPUT" ]; then
  REMOTE_BASE="$REMOTE_BASE_INPUT"
else
  REMOTE_HOME=$(cd ~ && pwd)
  REMOTE_BASE="$REMOTE_HOME/whois_remote"
fi

LOCK_DIR="$REMOTE_BASE/.remote_build.lock"

if [ ! -d "$LOCK_DIR" ]; then
  echo "[CLEAR-REMOTE-LOCK] delete_state=absent"
  exit 0
fi

rm -rf "$LOCK_DIR"

if [ -d "$LOCK_DIR" ]; then
  echo "[CLEAR-REMOTE-LOCK] delete_state=failed"
  exit 18
fi

echo "[CLEAR-REMOTE-LOCK] delete_state=removed"
'@

$inspectScript = $inspectScript.Replace('__REMOTE_BASE__', $remoteBaseLiteral)
$inspectScript = $inspectScript.Replace('__STALE_SEC__', [string]$StaleSec)
$deleteScript = $deleteScript.Replace('__REMOTE_BASE__', $remoteBaseLiteral)

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

Write-Output ("[CLEAR-REMOTE-LOCK] host={0}" -f $RemoteIp)
Write-Output ("[CLEAR-REMOTE-LOCK] user={0}" -f $RemoteUser)
Write-Output ("[CLEAR-REMOTE-LOCK] timeout_sec={0}" -f $TimeoutSec)
Write-Output ("[CLEAR-REMOTE-LOCK] dry_run={0}" -f $DryRun.IsPresent.ToString().ToLowerInvariant())
Write-Output ("[CLEAR-REMOTE-LOCK] force={0}" -f $Force.IsPresent.ToString().ToLowerInvariant())

$inspectResult = Invoke-SshScript -FilePath $WindowsSshPath -Arguments $sshArgs -InputScript $inspectScript -TimeoutSec $TimeoutSec
if (-not [string]::IsNullOrWhiteSpace($inspectResult.StdErr)) {
    Write-Warning $inspectResult.StdErr.TrimEnd()
}
if ($inspectResult.ExitCode -ne 0) {
    throw "ssh inspection failed (exit=$($inspectResult.ExitCode))"
}

$inspectOutput = $inspectResult.StdOut.TrimEnd()
if (-not [string]::IsNullOrWhiteSpace($inspectOutput)) {
    Write-Output $inspectOutput
}

$lines = @()
if (-not [string]::IsNullOrWhiteSpace($inspectOutput)) {
    $lines = @($inspectOutput -split "`r?`n")
}

$state = Get-TaggedFieldValue -Lines $lines -Tag 'CLEAR-REMOTE-LOCK' -Key 'state'
$ownerInfo = Get-TaggedFieldValue -Lines $lines -Tag 'CLEAR-REMOTE-LOCK' -Key 'owner_info'
$stale = Get-TaggedFieldValue -Lines $lines -Tag 'CLEAR-REMOTE-LOCK' -Key 'stale'
$remoteBuildProcesses = Get-TaggedFieldValue -Lines $lines -Tag 'CLEAR-REMOTE-LOCK' -Key 'remote_build_processes'
$ownerHost = Get-TaggedFieldValue -Lines $lines -Tag 'CLEAR-REMOTE-LOCK' -Key 'local_host'
$ownerPidText = Get-TaggedFieldValue -Lines $lines -Tag 'CLEAR-REMOTE-LOCK' -Key 'local_pid'

$currentHostAliases = Get-CurrentHostAliases
$sameHost = $false
if (-not [string]::IsNullOrWhiteSpace($ownerHost)) {
    $sameHost = $currentHostAliases -contains $ownerHost
}

$ownerPidDigits = ''
if (-not [string]::IsNullOrWhiteSpace($ownerPidText)) {
    $ownerPidMatch = [regex]::Match($ownerPidText, '[0-9]+')
    if ($ownerPidMatch.Success) {
        $ownerPidDigits = $ownerPidMatch.Value
    }
}

$localPidState = 'unknown'
if ($sameHost) {
    if (-not [string]::IsNullOrWhiteSpace($ownerPidDigits)) {
        $ownerPid = [int]$ownerPidDigits
        $ownerProcess = Get-Process -Id $ownerPid -ErrorAction SilentlyContinue
        if ($null -ne $ownerProcess) {
            $localPidState = 'present'
        }
        else {
            $localPidState = 'missing'
        }
    }
    else {
        $localPidState = 'invalid'
    }
}
elseif (-not [string]::IsNullOrWhiteSpace($ownerHost)) {
    $localPidState = 'foreign-host'
}

Write-Output ("[CLEAR-REMOTE-LOCK] same_host={0}" -f $sameHost.ToString().ToLowerInvariant())
Write-Output ("[CLEAR-REMOTE-LOCK] local_pid_state={0}" -f $localPidState)

if ($state -eq 'absent') {
    Write-Output '[CLEAR-REMOTE-LOCK] decision=no-op'
    Write-Output '[CLEAR-REMOTE-LOCK] reason=lock-absent'
    exit 0
}

if ($remoteBuildProcesses -eq 'present') {
    Write-Output '[CLEAR-REMOTE-LOCK] decision=refuse'
    Write-Output '[CLEAR-REMOTE-LOCK] reason=active-remote-build-processes'
    throw 'Refusing to clear remote lock while remote build processes are active.'
}

$safeToRemove = $false
$reason = ''

if ($stale -eq 'true') {
    $safeToRemove = $true
    $reason = 'stale-lock'
}
elseif ($sameHost -and $localPidState -eq 'missing') {
    $safeToRemove = $true
    $reason = 'orphan-lock-same-host-missing-local-pid'
}
elseif ($Force.IsPresent) {
    $safeToRemove = $true
    $reason = 'force-override'
}

if (-not $safeToRemove) {
    Write-Output '[CLEAR-REMOTE-LOCK] decision=refuse'
    if ([string]::IsNullOrWhiteSpace($reason)) {
        $reason = 'lock-not-stale-and-owner-not-provably-dead'
    }
    Write-Output ("[CLEAR-REMOTE-LOCK] reason={0}" -f $reason)
    throw 'Refusing to clear remote lock without stale or verifiable orphan evidence. Use -Force only after manual confirmation.'
}

if ($DryRun.IsPresent) {
    Write-Output '[CLEAR-REMOTE-LOCK] decision=would-remove'
    Write-Output ("[CLEAR-REMOTE-LOCK] reason={0}" -f $reason)
    exit 0
}

Write-Output '[CLEAR-REMOTE-LOCK] decision=remove'
Write-Output ("[CLEAR-REMOTE-LOCK] reason={0}" -f $reason)

$deleteResult = Invoke-SshScript -FilePath $WindowsSshPath -Arguments $sshArgs -InputScript $deleteScript -TimeoutSec $TimeoutSec
if (-not [string]::IsNullOrWhiteSpace($deleteResult.StdErr)) {
    Write-Warning $deleteResult.StdErr.TrimEnd()
}
if (-not [string]::IsNullOrWhiteSpace($deleteResult.StdOut)) {
    Write-Output $deleteResult.StdOut.TrimEnd()
}
if ($deleteResult.ExitCode -ne 0) {
    throw "ssh delete failed (exit=$($deleteResult.ExitCode))"
}