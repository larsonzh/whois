param(
    [string]$ScriptPath = (Join-Path $PSScriptRoot 'Send-IpcChatMessage.ps1'),

    [ValidateRange(3, 120)]
    [int]$CaseTimeoutSec = 12,

    [ValidateRange(5, 120)]
    [int]$ChildProcessTimeoutSec = 20,

    [switch]$IncludeLiveCase
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-IpcFilePaths {
    param(
        [ValidateRange(0, 99999)]
        [int]$TargetPid = 0
    )

    if ($TargetPid -gt 0) {
        return [pscustomobject]@{
            cmd_file = Join-Path $env:TEMP ("vscode_chat_send_cmd_{0}.json" -f $TargetPid)
            res_file = Join-Path $env:TEMP ("vscode_chat_send_res_{0}.json" -f $TargetPid)
        }
    }

    return [pscustomobject]@{
        cmd_file = Join-Path $env:TEMP 'vscode_chat_send_cmd.json'
        res_file = Join-Path $env:TEMP 'vscode_chat_send_result.json'
    }
}

function Get-ObjectPropertyValue {
    param(
        [AllowNull()][object]$InputObject,
        [Parameter(Mandatory = $true)][string]$PropertyName,
        [AllowNull()][object]$DefaultValue = $null
    )

    if ($null -eq $InputObject) {
        return $DefaultValue
    }

    $property = $InputObject.PSObject.Properties[$PropertyName]
    if ($null -eq $property) {
        return $DefaultValue
    }

    return $property.Value
}

function Resolve-PowerShellExecutable {
    $command = Get-Command powershell.exe -ErrorAction SilentlyContinue
    if ($null -ne $command -and -not [string]::IsNullOrWhiteSpace([string]$command.Source)) {
        return [string]$command.Source
    }

    $fallback = Get-Command pwsh.exe -ErrorAction SilentlyContinue
    if ($null -ne $fallback -and -not [string]::IsNullOrWhiteSpace([string]$fallback.Source)) {
        return [string]$fallback.Source
    }

    throw 'Unable to find powershell.exe or pwsh.exe.'
}

function Remove-IpcTempFiles {
    param(
        [AllowEmptyString()][string]$CmdFile = '',
        [AllowEmptyString()][string]$ResFile = ''
    )

    if ([string]::IsNullOrWhiteSpace($CmdFile) -or [string]::IsNullOrWhiteSpace($ResFile)) {
        $paths = Get-IpcFilePaths
        if ([string]::IsNullOrWhiteSpace($CmdFile)) {
            $CmdFile = [string]$paths.cmd_file
        }
        if ([string]::IsNullOrWhiteSpace($ResFile)) {
            $ResFile = [string]$paths.res_file
        }
    }

    foreach ($path in @($CmdFile, $ResFile)) {
        if (Test-Path -LiteralPath $path) {
            Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        }
    }
}

function Start-MockIpcResponder {
    param(
        [Parameter(Mandatory = $true)]
        [string]$CmdFile,

        [Parameter(Mandatory = $true)]
        [string]$ResFile,

        [ValidateSet('success', 'failure')]
        [string]$Mode,

        [ValidateRange(3, 120)]
        [int]$TimeoutSec,

        [AllowEmptyString()]
        [string]$SuccessReason = 'sent_via_mock',

        [AllowEmptyString()]
        [string]$FailureReason = 'mock_failure'
    )

    return Start-Job -ScriptBlock {
        param(
            [string]$CmdFile,
            [string]$ResFile,
            [string]$Mode,
            [int]$TimeoutSec,
            [string]$SuccessReason,
            [string]$FailureReason
        )

        Set-StrictMode -Version Latest
        $ErrorActionPreference = 'Stop'

        $deadline = (Get-Date).AddSeconds([Math]::Max(3, $TimeoutSec))
        while ((Get-Date) -lt $deadline) {
            if (-not (Test-Path -LiteralPath $CmdFile)) {
                Start-Sleep -Milliseconds 50
                continue
            }

            $raw = ''
            $cmdPayload = $null
            try {
                $raw = Get-Content -LiteralPath $CmdFile -Raw -Encoding utf8
                $cmdPayload = ($raw | ConvertFrom-Json -ErrorAction Stop)
            }
            catch {
                Start-Sleep -Milliseconds 50
                continue
            }

            Remove-Item -LiteralPath $CmdFile -Force -ErrorAction SilentlyContinue
            Start-Sleep -Milliseconds 250

            $reason = ''
            if ($Mode -eq 'success') {
                if ([string]::IsNullOrWhiteSpace($SuccessReason)) {
                    $reason = 'sent_via_mock'
                }
                else {
                    $reason = $SuccessReason
                }
            }
            else {
                if ([string]::IsNullOrWhiteSpace($FailureReason)) {
                    $reason = 'mock_failure'
                }
                else {
                    $reason = $FailureReason
                }
            }

            $requestId = ''
            if ($null -ne $cmdPayload) {
                $requestIdProperty = $cmdPayload.PSObject.Properties['request_id']
                if ($null -ne $requestIdProperty) {
                    $requestId = [string]$requestIdProperty.Value
                }
            }

            $resultPayload = @{
                success    = ($Mode -eq 'success')
                reason     = $reason
                request_id = $requestId
            }

            $jsonText = $resultPayload | ConvertTo-Json -Compress -Depth 4
            [System.IO.File]::WriteAllText([string]$ResFile, [string]$jsonText, [System.Text.UTF8Encoding]::new($false))

            return [pscustomobject]@{
                timed_out    = $false
                wrote_result = $true
                mode         = $Mode
                observed     = $cmdPayload
                emitted      = $resultPayload
            }
        }

        return [pscustomobject]@{
            timed_out    = $true
            wrote_result = $false
            mode         = $Mode
            observed     = $null
            emitted      = $null
        }
    } -ArgumentList $CmdFile, $ResFile, $Mode, $TimeoutSec, $SuccessReason, $FailureReason
}

function Complete-MockIpcResponder {
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Job]$Job,

        [ValidateRange(3, 120)]
        [int]$WaitSec = 20
    )

    $null = Wait-Job -Job $Job -Timeout $WaitSec
    $received = Receive-Job -Job $Job -ErrorAction SilentlyContinue
    Remove-Job -Job $Job -Force -ErrorAction SilentlyContinue

    if ($received -is [array]) {
        if ($received.Length -gt 0) {
            return $received[-1]
        }
        return $null
    }

    return $received
}

function Invoke-InIpcTempSandbox {
    param(
        [Parameter(Mandatory = $true)][string]$CaseName,
        [Parameter(Mandatory = $true)][scriptblock]$ScriptBlock,
        [switch]$PassPid
    )

    $baseTemp = [string]$env:TEMP
    if ([string]::IsNullOrWhiteSpace($baseTemp)) {
        throw 'TEMP environment variable is missing.'
    }

    $sandboxPath = Join-Path $baseTemp ("ipc_sender_test_{0}_{1}" -f $CaseName, ([guid]::NewGuid().ToString('N')))
    New-Item -ItemType Directory -Path $sandboxPath -Force | Out-Null

    $savedTemp = [string]$env:TEMP
    $savedTmp = [string]$env:TMP
    $savedVscodePid = [string]$env:VSCODE_PID

    # Capture the VS Code main window PID before clearing env, so mock and
    # sender agree on PID-scoped file paths (the sender auto-detects it via
    # Get-Process -Name Code when VSCODE_PID is absent).
    $capturedPid = 0
    $vscodePidRaw = [string]$env:VSCODE_PID
    if (-not [string]::IsNullOrWhiteSpace($vscodePidRaw)) {
        [int]::TryParse($vscodePidRaw, [ref]$capturedPid) | Out-Null
    }
    if ($capturedPid -le 0) {
        try {
            $codeProc = Get-Process -Name 'Code' -ErrorAction SilentlyContinue |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_.MainWindowTitle) } |
                Sort-Object StartTime -Descending |
                Select-Object -First 1
            if ($null -ne $codeProc) {
                $capturedPid = [int]$codeProc.Id
            }
        }
        catch {
            $null = $null
        }
    }

    try {
        $env:TEMP = $sandboxPath
        $env:TMP = $sandboxPath
        # Clear VSCODE_PID so code under test exercises PID auto-detection
        # via Get-Process -Name Code (same as external-terminal scenario).
        [Environment]::SetEnvironmentVariable('VSCODE_PID', '', 'Process')

        if ($PassPid.IsPresent -and $capturedPid -gt 0) {
            return (& $ScriptBlock $sandboxPath $capturedPid)
        }
        return (& $ScriptBlock $sandboxPath)
    }
    finally {
        [Environment]::SetEnvironmentVariable('VSCODE_PID', $savedVscodePid, 'Process')
        $env:TEMP = $savedTemp
        $env:TMP = $savedTmp

        if (Test-Path -LiteralPath $sandboxPath) {
            Remove-Item -LiteralPath $sandboxPath -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Invoke-IpcSenderProcess {
    param(
        [Parameter(Mandatory = $true)][string]$PowerShellExe,
        [Parameter(Mandatory = $true)][string]$TargetScriptPath,
        [Parameter(Mandatory = $true)][string]$Message,
        [AllowEmptyString()][string]$RequestId = '',
        [ValidateSet('normal', 'high')][string]$Priority = 'normal',
        [ValidateRange(0, 99999)][int]$TargetPid = 0,
        [ValidateRange(5, 120)][int]$TimeoutSec = 20
    )

    $stdoutPath = [System.IO.Path]::GetTempFileName()
    $stderrPath = [System.IO.Path]::GetTempFileName()

    $savedMessageEnv = [Environment]::GetEnvironmentVariable('IPC_TEST_MESSAGE', 'Process')
    $savedRequestIdEnv = [Environment]::GetEnvironmentVariable('IPC_TEST_REQUEST_ID', 'Process')
    $savedTargetPidEnv = [Environment]::GetEnvironmentVariable('IPC_TEST_TARGET_PID', 'Process')
    $savedPriorityEnv = [Environment]::GetEnvironmentVariable('IPC_TEST_PRIORITY', 'Process')

    try {
        [Environment]::SetEnvironmentVariable('IPC_TEST_MESSAGE', $Message, 'Process')
        [Environment]::SetEnvironmentVariable('IPC_TEST_REQUEST_ID', $RequestId, 'Process')
        [Environment]::SetEnvironmentVariable('IPC_TEST_TARGET_PID', ([string]$TargetPid), 'Process')
        [Environment]::SetEnvironmentVariable('IPC_TEST_PRIORITY', $Priority, 'Process')

        $targetPidArg = if ($TargetPid -gt 0) { ' -TargetPid $env:IPC_TEST_TARGET_PID' } else { '' }
        $commandText = "& '$TargetScriptPath' -Message `$env:IPC_TEST_MESSAGE -RequestId `$env:IPC_TEST_REQUEST_ID -Priority `$env:IPC_TEST_PRIORITY -JsonOutput$targetPidArg"
        $arguments = @(
            '-NoProfile',
            '-ExecutionPolicy', 'Bypass',
            '-Command', $commandText
        )

        $process = $null
        try {
            $process = Start-Process -FilePath $PowerShellExe -ArgumentList $arguments -PassThru -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath -ErrorAction Stop
        }
        catch {
            return [pscustomobject]@{
                timed_out         = $false
                exit_code         = -97
                stdout            = ''
                stderr            = [string]$_.Exception.Message
                json              = $null
                json_parse_failed = $false
            }
        }

        if ($null -eq $process) {
            return [pscustomobject]@{
                timed_out         = $false
                exit_code         = -98
                stdout            = ''
                stderr            = 'Start-Process returned a null process object.'
                json              = $null
                json_parse_failed = $false
            }
        }

        $timeoutMs = [Math]::Max(5000, $TimeoutSec * 1000)
        $exited = $process.WaitForExit($timeoutMs)
        $timedOut = -not $exited

        if ($timedOut) {
            try {
                $process.Kill()
                $process.WaitForExit()
            }
            catch {
                $null = $null
            }
        }

        $stdoutText = ''
        if (Test-Path -LiteralPath $stdoutPath) {
            $rawStdout = Get-Content -LiteralPath $stdoutPath -Raw -Encoding utf8
            if ($null -ne $rawStdout) {
                $stdoutText = [string]$rawStdout
            }
        }

        $stderrText = ''
        if (Test-Path -LiteralPath $stderrPath) {
            $rawStderr = Get-Content -LiteralPath $stderrPath -Raw -Encoding utf8
            if ($null -ne $rawStderr) {
                $stderrText = [string]$rawStderr
            }
        }

        if ($null -eq $stdoutText) {
            $stdoutText = ''
        }
        if ($null -eq $stderrText) {
            $stderrText = ''
        }

        $jsonObject = $null
        $jsonParseFailed = $false
        $trimmed = $stdoutText.Trim()
        if (-not [string]::IsNullOrWhiteSpace($trimmed)) {
            try {
                $jsonObject = ($trimmed | ConvertFrom-Json -ErrorAction Stop)
            }
            catch {
                $jsonParseFailed = $true
            }
        }

        $exitCodeValue = -99
        if (-not $timedOut) {
            $exitCodeValue = [int]$process.ExitCode
        }

        return [pscustomobject]@{
            timed_out         = $timedOut
            exit_code         = $exitCodeValue
            stdout            = $stdoutText
            stderr            = $stderrText
            json              = $jsonObject
            json_parse_failed = $jsonParseFailed
        }
    }
    finally {
        [Environment]::SetEnvironmentVariable('IPC_TEST_MESSAGE', $savedMessageEnv, 'Process')
        [Environment]::SetEnvironmentVariable('IPC_TEST_REQUEST_ID', $savedRequestIdEnv, 'Process')
        [Environment]::SetEnvironmentVariable('IPC_TEST_TARGET_PID', $savedTargetPidEnv, 'Process')
        [Environment]::SetEnvironmentVariable('IPC_TEST_PRIORITY', $savedPriorityEnv, 'Process')

        foreach ($path in @($stdoutPath, $stderrPath)) {
            if (Test-Path -LiteralPath $path) {
                Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

function Add-TestResult {
    param(
        [Parameter(Mandatory = $true)][object]$Results,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][bool]$Passed,
        [Parameter(Mandatory = $true)][string]$Detail
    )

    [void]$Results.Add([pscustomobject]@{
            name   = $Name
            passed = $Passed
            detail = $Detail
        })
}

if (-not (Test-Path -LiteralPath $ScriptPath)) {
    Write-Error ("Target script not found: {0}" -f $ScriptPath)
    exit 2
}

$powerShellExe = Resolve-PowerShellExecutable
$results = New-Object 'System.Collections.Generic.List[object]'

# Case 1: parameter guard for empty message.
$case1 = Invoke-InIpcTempSandbox -CaseName 'empty_message' -ScriptBlock {
    param([string]$SandboxPath)
    Remove-IpcTempFiles
    Invoke-IpcSenderProcess -PowerShellExe $powerShellExe -TargetScriptPath $ScriptPath -Message '   ' -RequestId 'tc-empty' -TimeoutSec $ChildProcessTimeoutSec
}
$case1Reason = [string](Get-ObjectPropertyValue -InputObject $case1.json -PropertyName 'reason' -DefaultValue '')
$case1Success = [bool](Get-ObjectPropertyValue -InputObject $case1.json -PropertyName 'success' -DefaultValue $true)
$case1Pass = (-not [bool]$case1.timed_out) -and (-not $case1Success) -and ($case1Reason -eq 'empty_message')
Add-TestResult -Results $results -Name 'empty-message-guard' -Passed $case1Pass -Detail ("exit={0}; success={1}; reason={2}; timed_out={3}" -f $case1.exit_code, $case1Success, $case1Reason, $case1.timed_out)

# Case 2: mocked success path (PID-scoped routing).
$message2 = "ipc-mock-success-{0}" -f ((Get-Date).ToString('yyyyMMddHHmmssfff'))
$request2 = 'tc-success'
$case2Bundle = Invoke-InIpcTempSandbox -CaseName 'mock_success' -ScriptBlock {
    param([string]$SandboxPath, [int]$PassedPid)
    $paths = Get-IpcFilePaths -TargetPid $PassedPid
    Remove-IpcTempFiles -CmdFile $paths.cmd_file -ResFile $paths.res_file
    $job = Start-MockIpcResponder -CmdFile $paths.cmd_file -ResFile $paths.res_file -Mode 'success' -TimeoutSec $CaseTimeoutSec -SuccessReason 'sent_via_mock'
    $case = Invoke-IpcSenderProcess -PowerShellExe $powerShellExe -TargetScriptPath $ScriptPath -Message $message2 -RequestId $request2 -Priority 'high' -TargetPid $PassedPid -TimeoutSec $ChildProcessTimeoutSec
    $mock = Complete-MockIpcResponder -Job $job -WaitSec ([Math]::Max(6, $CaseTimeoutSec + 4))
    [pscustomobject]@{
        case = $case
        mock = $mock
    }
} -PassPid
$case2 = Get-ObjectPropertyValue -InputObject $case2Bundle -PropertyName 'case' -DefaultValue $null
$mock2 = Get-ObjectPropertyValue -InputObject $case2Bundle -PropertyName 'mock' -DefaultValue $null
$case2Reason = [string](Get-ObjectPropertyValue -InputObject $case2.json -PropertyName 'reason' -DefaultValue '')
$case2Success = [bool](Get-ObjectPropertyValue -InputObject $case2.json -PropertyName 'success' -DefaultValue $false)
$case2Request = [string](Get-ObjectPropertyValue -InputObject $case2.json -PropertyName 'request_id' -DefaultValue '')
$mock2Observed = Get-ObjectPropertyValue -InputObject $mock2 -PropertyName 'observed' -DefaultValue $null
$mock2Message = [string](Get-ObjectPropertyValue -InputObject $mock2Observed -PropertyName 'message' -DefaultValue '')
$mock2Request = [string](Get-ObjectPropertyValue -InputObject $mock2Observed -PropertyName 'request_id' -DefaultValue '')
$mock2Priority = [string](Get-ObjectPropertyValue -InputObject $mock2Observed -PropertyName 'priority' -DefaultValue '')
$mock2Wrote = [bool](Get-ObjectPropertyValue -InputObject $mock2 -PropertyName 'wrote_result' -DefaultValue $false)
$mock2TimedOut = [bool](Get-ObjectPropertyValue -InputObject $mock2 -PropertyName 'timed_out' -DefaultValue $true)
$case2Pass = (-not [bool]$case2.timed_out) -and $case2Success -and ($case2Reason -eq 'sent_via_mock') -and ($case2Request -eq $request2) -and $mock2Wrote -and (-not $mock2TimedOut) -and ($mock2Message -eq $message2) -and ($mock2Request -eq $request2) -and ($mock2Priority -eq 'high')
Add-TestResult -Results $results -Name 'mock-success' -Passed $case2Pass -Detail ("exit={0}; success={1}; reason={2}; req={3}; priority={4}; timed_out={5}" -f $case2.exit_code, $case2Success, $case2Reason, $case2Request, $mock2Priority, $case2.timed_out)

# Case 3: mocked failure path (PID-scoped routing).
$message3 = "ipc-mock-failure-{0}" -f ((Get-Date).ToString('yyyyMMddHHmmssfff'))
$request3 = 'tc-failure'
$case3Bundle = Invoke-InIpcTempSandbox -CaseName 'mock_failure' -ScriptBlock {
    param([string]$SandboxPath, [int]$PassedPid)
    $paths = Get-IpcFilePaths -TargetPid $PassedPid
    Remove-IpcTempFiles -CmdFile $paths.cmd_file -ResFile $paths.res_file
    $job = Start-MockIpcResponder -CmdFile $paths.cmd_file -ResFile $paths.res_file -Mode 'failure' -TimeoutSec $CaseTimeoutSec -FailureReason 'mock_failure'
    $case = Invoke-IpcSenderProcess -PowerShellExe $powerShellExe -TargetScriptPath $ScriptPath -Message $message3 -RequestId $request3 -Priority 'normal' -TargetPid $PassedPid -TimeoutSec $ChildProcessTimeoutSec
    $mock = Complete-MockIpcResponder -Job $job -WaitSec ([Math]::Max(6, $CaseTimeoutSec + 4))
    [pscustomobject]@{
        case = $case
        mock = $mock
    }
} -PassPid
$case3 = Get-ObjectPropertyValue -InputObject $case3Bundle -PropertyName 'case' -DefaultValue $null
$mock3 = Get-ObjectPropertyValue -InputObject $case3Bundle -PropertyName 'mock' -DefaultValue $null
$case3Reason = [string](Get-ObjectPropertyValue -InputObject $case3.json -PropertyName 'reason' -DefaultValue '')
$case3Success = [bool](Get-ObjectPropertyValue -InputObject $case3.json -PropertyName 'success' -DefaultValue $true)
$mock3Observed = Get-ObjectPropertyValue -InputObject $mock3 -PropertyName 'observed' -DefaultValue $null
$mock3Priority = [string](Get-ObjectPropertyValue -InputObject $mock3Observed -PropertyName 'priority' -DefaultValue '')
$mock3Wrote = [bool](Get-ObjectPropertyValue -InputObject $mock3 -PropertyName 'wrote_result' -DefaultValue $false)
$mock3TimedOut = [bool](Get-ObjectPropertyValue -InputObject $mock3 -PropertyName 'timed_out' -DefaultValue $true)
$case3Pass = (-not [bool]$case3.timed_out) -and (-not $case3Success) -and ($case3Reason -eq 'mock_failure') -and $mock3Wrote -and (-not $mock3TimedOut) -and ($mock3Priority -eq 'normal')
Add-TestResult -Results $results -Name 'mock-failure' -Passed $case3Pass -Detail ("exit={0}; success={1}; reason={2}; priority={3}; timed_out={4}" -f $case3.exit_code, $case3Success, $case3Reason, $mock3Priority, $case3.timed_out)

# Case 4: explicit -TargetPid with matching mock (verifies PID routing end-to-end).
$message4 = "ipc-pid-routing-{0}" -f ((Get-Date).ToString('yyyyMMddHHmmssfff'))
$request4 = 'tc-pid-routing'
$case4Bundle = Invoke-InIpcTempSandbox -CaseName 'pid_routing' -ScriptBlock {
    param([string]$SandboxPath, [int]$PassedPid)
    $paths = Get-IpcFilePaths -TargetPid $PassedPid
    Remove-IpcTempFiles -CmdFile $paths.cmd_file -ResFile $paths.res_file
    $job = Start-MockIpcResponder -CmdFile $paths.cmd_file -ResFile $paths.res_file -Mode 'success' -TimeoutSec $CaseTimeoutSec -SuccessReason 'sent_via_mock'
    $case = Invoke-IpcSenderProcess -PowerShellExe $powerShellExe -TargetScriptPath $ScriptPath -Message $message4 -RequestId $request4 -Priority 'high' -TargetPid $PassedPid -TimeoutSec $ChildProcessTimeoutSec
    $mock = Complete-MockIpcResponder -Job $job -WaitSec ([Math]::Max(6, $CaseTimeoutSec + 4))
    [pscustomobject]@{
        case = $case
        mock = $mock
    }
} -PassPid
$case4 = Get-ObjectPropertyValue -InputObject $case4Bundle -PropertyName 'case' -DefaultValue $null
$mock4 = Get-ObjectPropertyValue -InputObject $case4Bundle -PropertyName 'mock' -DefaultValue $null
$case4Reason = [string](Get-ObjectPropertyValue -InputObject $case4.json -PropertyName 'reason' -DefaultValue '')
$case4Success = [bool](Get-ObjectPropertyValue -InputObject $case4.json -PropertyName 'success' -DefaultValue $false)
$mock4Observed = Get-ObjectPropertyValue -InputObject $mock4 -PropertyName 'observed' -DefaultValue $null
$mock4Priority = [string](Get-ObjectPropertyValue -InputObject $mock4Observed -PropertyName 'priority' -DefaultValue '')
$mock4Wrote = [bool](Get-ObjectPropertyValue -InputObject $mock4 -PropertyName 'wrote_result' -DefaultValue $false)
$mock4TimedOut = [bool](Get-ObjectPropertyValue -InputObject $mock4 -PropertyName 'timed_out' -DefaultValue $true)
$case4Pass = (-not [bool]$case4.timed_out) -and $case4Success -and ($case4Reason -eq 'sent_via_mock') -and $mock4Wrote -and (-not $mock4TimedOut) -and ($mock4Priority -eq 'high')
Add-TestResult -Results $results -Name 'pid-scoped-routing' -Passed $case4Pass -Detail ("exit={0}; success={1}; reason={2}; priority={3}; timed_out={4}" -f $case4.exit_code, $case4Success, $case4Reason, $mock4Priority, $case4.timed_out)

# Optional live integration case.
if ($IncludeLiveCase.IsPresent) {
    Remove-IpcTempFiles
    $liveMessage = "ipc-live-smoke-{0}" -f ((Get-Date).ToString('yyyyMMddHHmmssfff'))
    $liveCase = Invoke-IpcSenderProcess -PowerShellExe $powerShellExe -TargetScriptPath $ScriptPath -Message $liveMessage -RequestId 'tc-live' -TimeoutSec ([Math]::Max($ChildProcessTimeoutSec, 40))
    $liveReason = [string](Get-ObjectPropertyValue -InputObject $liveCase.json -PropertyName 'reason' -DefaultValue '')
    $liveSuccess = [bool](Get-ObjectPropertyValue -InputObject $liveCase.json -PropertyName 'success' -DefaultValue $false)
    $livePass = (-not [bool]$liveCase.timed_out) -and $liveSuccess
    Add-TestResult -Results $results -Name 'live-integration' -Passed $livePass -Detail ("exit={0}; success={1}; reason={2}; timed_out={3}" -f $liveCase.exit_code, $liveSuccess, $liveReason, $liveCase.timed_out)
}

$passCount = (@($results | Where-Object { $_.passed })).Count
$failCount = $results.Count - $passCount

foreach ($item in $results) {
    if ($item.passed) {
        Write-Output ("[PASS] {0} :: {1}" -f $item.name, $item.detail)
    }
    else {
        Write-Output ("[FAIL] {0} :: {1}" -f $item.name, $item.detail)
    }
}

Write-Output ("Summary: pass={0} fail={1}" -f $passCount, $failCount)

if ($failCount -gt 0) {
    exit 1
}

exit 0
