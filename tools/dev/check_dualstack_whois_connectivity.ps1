<#
Check dual-stack WHOIS connectivity for both local host and remote Ubuntu VM.

Default targets:
  - whois.iana.org
  - whois.arin.net

Behavior:
  - Validates IPv4 and/or IPv6 connectivity to TCP/43.
  - Can test local only, remote only, or both.
  - Exits non-zero if any required check fails.
#>

param(
    [string]$Targets = 'whois.iana.org;whois.arin.net',
    [ValidateRange(1, 65535)][int]$Port = 43,
    [ValidateRange(1, 30)][int]$TimeoutSec = 8,
    [bool]$CheckLocal = $true,
    [bool]$CheckRemote = $true,
    [bool]$CheckIPv4 = $true,
    [bool]$CheckIPv6 = $true,
    [bool]$RequireIPv4 = $false,
    [bool]$RequireIPv6 = $true,
    [string]$RemoteIp = '10.0.0.199',
    [string]$RemoteUser = 'larson',
    [string]$KeyPath = ("C:\Users\{0}\.ssh\id_rsa" -f $env:USERNAME),
    [string]$WindowsSshPath = 'C:\Windows\System32\OpenSSH\ssh.exe',
    [ValidateRange(1, 65535)][int]$SshPort = 22,
    [ValidateRange(1, 60)][int]$SshConnectTimeoutSec = 12
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Convert-MsysPathToWindowsPath {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return ''
    }

    if ($Path -match '^/([a-zA-Z])/(.*)$') {
        $drive = $Matches[1].ToUpperInvariant()
        $rest = $Matches[2] -replace '/', '\\'
        return ("{0}:\\{1}" -f $drive, $rest)
    }

    return $Path
}

function Resolve-RemoteKeyPath {
    param([string]$InputPath)

    if (-not [string]::IsNullOrWhiteSpace($InputPath) -and (Test-Path -LiteralPath $InputPath)) {
        return (Resolve-Path -LiteralPath $InputPath).Path
    }

    $converted = Convert-MsysPathToWindowsPath -Path $InputPath
    if (-not [string]::IsNullOrWhiteSpace($converted) -and (Test-Path -LiteralPath $converted)) {
        return (Resolve-Path -LiteralPath $converted).Path
    }

    throw "SSH private key not found: input=$InputPath"
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

function Get-TargetList {
    param([string]$RawTargets)

    $items = @($RawTargets -split '[;,\s]+' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $result = New-Object 'System.Collections.Generic.List[string]'

    foreach ($item in $items) {
        $targetHost = $item.Trim()
        if ([string]::IsNullOrWhiteSpace($targetHost)) {
            continue
        }

        if ($seen.Add($targetHost)) {
            [void]$result.Add($targetHost)
        }
    }

    return @($result)
}

function Get-ConnectResult {
    param(
        [System.Net.IPAddress]$Address,
        [int]$Port,
        [int]$TimeoutSec
    )

    $client = New-Object System.Net.Sockets.TcpClient($Address.AddressFamily)
    try {
        $iar = $client.BeginConnect($Address, $Port, $null, $null)
        $completed = $iar.AsyncWaitHandle.WaitOne([TimeSpan]::FromSeconds($TimeoutSec))
        if (-not $completed) {
            return [pscustomobject]@{
                Success = $false
                Error = 'connect-timeout'
            }
        }

        $client.EndConnect($iar)
        return [pscustomobject]@{
            Success = $true
            Error = 'ok'
        }
    }
    catch {
        return [pscustomobject]@{
            Success = $false
            Error = $_.Exception.Message.Replace(' ', '_')
        }
    }
    finally {
        $client.Close()
        $client.Dispose()
    }
}

function Test-LocalHostFamily {
    param(
        [string]$TargetHost,
        [ValidateSet('ipv4', 'ipv6')][string]$Family,
        [bool]$Required,
        [int]$Port,
        [int]$TimeoutSec
    )

    try {
        $all = @([System.Net.Dns]::GetHostAddresses($TargetHost))
    }
    catch {
        return [pscustomobject]@{
            Scope = 'local'
            Host = $TargetHost
            Family = $Family
            Required = $Required
            Status = 'fail'
            Resolved = 0
            Ip = '-'
            Detail = 'dns-failed'
        }
    }

    $targetFamily = if ($Family -eq 'ipv4') {
        [System.Net.Sockets.AddressFamily]::InterNetwork
    }
    else {
        [System.Net.Sockets.AddressFamily]::InterNetworkV6
    }

    $addresses = @($all | Where-Object { $_.AddressFamily -eq $targetFamily })
    if ($addresses.Count -lt 1) {
        return [pscustomobject]@{
            Scope = 'local'
            Host = $TargetHost
            Family = $Family
            Required = $Required
            Status = 'fail'
            Resolved = 0
            Ip = '-'
            Detail = 'no-dns-record'
        }
    }

    $lastError = 'connect-failed'
    foreach ($address in $addresses) {
        $connect = Get-ConnectResult -Address $address -Port $Port -TimeoutSec $TimeoutSec
        if ($connect.Success) {
            return [pscustomobject]@{
                Scope = 'local'
                Host = $TargetHost
                Family = $Family
                Required = $Required
                Status = 'pass'
                Resolved = $addresses.Count
                Ip = $address.ToString()
                Detail = 'ok'
            }
        }

        $lastError = $connect.Error
    }

    return [pscustomobject]@{
        Scope = 'local'
        Host = $TargetHost
        Family = $Family
        Required = $Required
        Status = 'fail'
        Resolved = $addresses.Count
        Ip = '-'
        Detail = $lastError
    }
}

function Test-RemoteConnectivity {
    param(
        [string[]]$Targets,
        [int]$Port,
        [int]$TimeoutSec,
        [bool]$CheckIPv4,
        [bool]$CheckIPv6,
        [bool]$RequireIPv4,
        [bool]$RequireIPv6,
        [string]$RemoteIp,
        [string]$RemoteUser,
        [string]$KeyPath,
        [string]$WindowsSshPath,
        [int]$SshPort,
        [int]$SshConnectTimeoutSec
    )

    if (-not (Test-Path -LiteralPath $WindowsSshPath)) {
        throw "ssh executable not found: $WindowsSshPath"
    }

    $resolvedKey = Resolve-RemoteKeyPath -InputPath $KeyPath
    $targetsCsv = ($Targets -join ';')
    $chk4 = if ($CheckIPv4) { '1' } else { '0' }
    $chk6 = if ($CheckIPv6) { '1' } else { '0' }
    $req4 = if ($RequireIPv4) { '1' } else { '0' }
    $req6 = if ($RequireIPv6) { '1' } else { '0' }

    $remoteScript = @'
TARGETS_RAW="__TARGETS__"
PORT="__PORT__"
TIMEOUT_SEC="__TIMEOUT__"
CHK4="__CHK4__"
CHK6="__CHK6__"
REQ4="__REQ4__"
REQ6="__REQ6__"

if ! command -v python3 >/dev/null 2>&1; then
  echo "[CHECK-NET-PREFLIGHT-REMOTE] status=fail reason=python3-missing"
  exit 3
fi

python3 - "$TARGETS_RAW" "$PORT" "$TIMEOUT_SEC" "$CHK4" "$CHK6" "$REQ4" "$REQ6" <<'PY'
import socket
import sys

targets_raw, port_s, timeout_s, chk4_s, chk6_s, req4_s, req6_s = sys.argv[1:8]
targets = [t.strip() for t in targets_raw.replace(',', ';').split(';') if t.strip()]
port = int(port_s)
timeout = float(timeout_s)
check4 = chk4_s == '1'
check6 = chk6_s == '1'
require4 = req4_s == '1'
require6 = req6_s == '1'

families = []
if check4:
    families.append(('ipv4', socket.AF_INET))
if check6:
    families.append(('ipv6', socket.AF_INET6))

total = 0
required_fails = 0
optional_fails = 0

def out(line: str) -> None:
    print(line, flush=True)

for host in targets:
    for family_name, family in families:
        total += 1
        required = (family_name == 'ipv4' and require4) or (family_name == 'ipv6' and require6)
        addrs = []
        detail = 'ok'
        try:
            infos = socket.getaddrinfo(host, port, family, socket.SOCK_STREAM)
            seen = set()
            for info in infos:
                addr = info[4][0]
                if addr not in seen:
                    seen.add(addr)
                    addrs.append(addr)
        except Exception:
            addrs = []
            detail = 'dns-failed'

        if not addrs:
            if required:
                required_fails += 1
            else:
                optional_fails += 1
            out(f"[CHECK-NET-PREFLIGHT-REMOTE] host={host} family={family_name} required={str(required).lower()} status=fail resolved=0 ip=- detail={detail if detail != 'ok' else 'no-dns-record'}")
            continue

        success = False
        ip = '-'
        last_err = 'connect-failed'
        for addr in addrs:
            try:
                s = socket.socket(family, socket.SOCK_STREAM)
                s.settimeout(timeout)
                if family == socket.AF_INET6:
                    s.connect((addr, port, 0, 0))
                else:
                    s.connect((addr, port))
                s.close()
                success = True
                ip = addr
                break
            except Exception as ex:
                last_err = str(ex).replace(' ', '_')[:120]
                try:
                    s.close()
                except Exception:
                    pass

        if success:
            out(f"[CHECK-NET-PREFLIGHT-REMOTE] host={host} family={family_name} required={str(required).lower()} status=pass resolved={len(addrs)} ip={ip} detail=ok")
        else:
            if required:
                required_fails += 1
            else:
                optional_fails += 1
            out(f"[CHECK-NET-PREFLIGHT-REMOTE] host={host} family={family_name} required={str(required).lower()} status=fail resolved={len(addrs)} ip=- detail={last_err}")

overall = 'PASS' if required_fails == 0 else 'FAIL'
out(f"[CHECK-NET-PREFLIGHT-REMOTE] overall={overall} checks={total} required_fails={required_fails} optional_fails={optional_fails}")
sys.exit(0 if required_fails == 0 else 2)
PY
'@

    $remoteScript = $remoteScript.Replace('__TARGETS__', $targetsCsv.Replace('"', '\\"'))
    $remoteScript = $remoteScript.Replace('__PORT__', [string]$Port)
    $remoteScript = $remoteScript.Replace('__TIMEOUT__', [string]$TimeoutSec)
    $remoteScript = $remoteScript.Replace('__CHK4__', $chk4)
    $remoteScript = $remoteScript.Replace('__CHK6__', $chk6)
    $remoteScript = $remoteScript.Replace('__REQ4__', $req4)
    $remoteScript = $remoteScript.Replace('__REQ6__', $req6)

    $sshArgs = @(
        '-o', 'BatchMode=yes',
        '-o', ("ConnectTimeout={0}" -f $SshConnectTimeoutSec),
        '-o', 'ServerAliveInterval=5',
        '-o', 'ServerAliveCountMax=2',
        '-o', 'StrictHostKeyChecking=accept-new',
        '-o', 'UserKnownHostsFile=/dev/null',
        '-o', 'LogLevel=ERROR',
        '-i', $resolvedKey,
        '-p', [string]$SshPort,
        ("{0}@{1}" -f $RemoteUser, $RemoteIp),
        'sh', '-s', '--'
    )

    return Invoke-SshScript -FilePath $WindowsSshPath -Arguments $sshArgs -InputScript $remoteScript -TimeoutSec ($SshConnectTimeoutSec + $TimeoutSec + 8)
}

if (-not $CheckIPv4 -and -not $CheckIPv6) {
    throw 'At least one of CheckIPv4/CheckIPv6 must be true.'
}

if ($RequireIPv4 -and -not $CheckIPv4) {
    $CheckIPv4 = $true
}
if ($RequireIPv6 -and -not $CheckIPv6) {
    $CheckIPv6 = $true
}

$targetList = Get-TargetList -RawTargets $Targets
if ($targetList.Count -lt 1) {
    throw 'No valid targets resolved from -Targets.'
}

Write-Output ("[CHECK-NET-PREFLIGHT] config targets={0} port={1} timeout_sec={2} check_local={3} check_remote={4} check_ipv4={5} check_ipv6={6} require_ipv4={7} require_ipv6={8}" -f ($targetList -join ';'), $Port, $TimeoutSec, $CheckLocal, $CheckRemote, $CheckIPv4, $CheckIPv6, $RequireIPv4, $RequireIPv6)

$allResults = New-Object 'System.Collections.Generic.List[object]'

if ($CheckLocal) {
    $families = New-Object 'System.Collections.Generic.List[string]'
    if ($CheckIPv4) { [void]$families.Add('ipv4') }
    if ($CheckIPv6) { [void]$families.Add('ipv6') }

    foreach ($targetHost in $targetList) {
        foreach ($family in $families) {
            $required = (($family -eq 'ipv4' -and $RequireIPv4) -or ($family -eq 'ipv6' -and $RequireIPv6))
            $result = Test-LocalHostFamily -TargetHost $targetHost -Family $family -Required $required -Port $Port -TimeoutSec $TimeoutSec
            [void]$allResults.Add($result)
            Write-Output ("[CHECK-NET-PREFLIGHT] scope={0} host={1} family={2} required={3} status={4} resolved={5} ip={6} detail={7}" -f $result.Scope, $result.Host, $result.Family, $result.Required, $result.Status, $result.Resolved, $result.Ip, $result.Detail)
        }
    }
}
else {
    Write-Output '[CHECK-NET-PREFLIGHT] scope=local status=skip reason=check_local_false'
}

if ($CheckRemote) {
    $remoteResult = Test-RemoteConnectivity -Targets $targetList -Port $Port -TimeoutSec $TimeoutSec -CheckIPv4 $CheckIPv4 -CheckIPv6 $CheckIPv6 -RequireIPv4 $RequireIPv4 -RequireIPv6 $RequireIPv6 -RemoteIp $RemoteIp -RemoteUser $RemoteUser -KeyPath $KeyPath -WindowsSshPath $WindowsSshPath -SshPort $SshPort -SshConnectTimeoutSec $SshConnectTimeoutSec
    if (-not [string]::IsNullOrWhiteSpace($remoteResult.StdOut)) {
        foreach ($line in @($remoteResult.StdOut -split "`r?`n")) {
            if ([string]::IsNullOrWhiteSpace($line)) {
                continue
            }

            Write-Output $line.Trim()
            if ($line -match '^\[CHECK-NET-PREFLIGHT-REMOTE\]\s+host=([^\s]+)\s+family=([^\s]+)\s+required=([^\s]+)\s+status=([^\s]+)\s+resolved=([^\s]+)\s+ip=([^\s]+)\s+detail=(.+)$') {
                [void]$allResults.Add([pscustomobject]@{
                    Scope = 'remote'
                    Host = $Matches[1]
                    Family = $Matches[2]
                    Required = ($Matches[3] -eq 'true')
                    Status = $Matches[4]
                    Resolved = $Matches[5]
                    Ip = $Matches[6]
                    Detail = $Matches[7]
                })
            }
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($remoteResult.StdErr)) {
        Write-Warning $remoteResult.StdErr.TrimEnd()
    }

    if ($remoteResult.ExitCode -ne 0) {
        Write-Output ("[CHECK-NET-PREFLIGHT] scope=remote status=fail reason=ssh_or_remote_check_failed exit={0}" -f $remoteResult.ExitCode)
        exit 2
    }
}
else {
    Write-Output '[CHECK-NET-PREFLIGHT] scope=remote status=skip reason=check_remote_false'
}

$requiredFailCount = @($allResults | Where-Object { $_.Required -eq $true -and [string]$_.Status -ne 'pass' }).Count
$optionalFailCount = @($allResults | Where-Object { $_.Required -ne $true -and [string]$_.Status -ne 'pass' }).Count
$checkCount = $allResults.Count
$overall = if ($requiredFailCount -eq 0) { 'PASS' } else { 'FAIL' }
Write-Output ("[CHECK-NET-PREFLIGHT] summary overall={0} checks={1} required_fails={2} optional_fails={3}" -f $overall, $checkCount, $requiredFailCount, $optionalFailCount)

if ($requiredFailCount -gt 0) {
    exit 2
}

exit 0