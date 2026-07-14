param(
    [Parameter(Mandatory = $true)][string]$StartFile,
    [Parameter(Mandatory = $true)][string]$TicketId,
    [AllowEmptyString()][string]$QueuePath = '',
    [AllowEmptyString()][string]$StatePath = '',
    [AllowEmptyString()][string]$LedgerPath = '',
    [AllowEmptyString()][string]$TakeoverRoot = '',
    [AllowEmptyString()][string]$AcknowledgeRetryBudgetUsed = '',
    [ValidateRange(1, 200)][int]$Last = 20,
    [switch]$AsJson
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Convert-CommandOutputToJson {
    param(
        [object[]]$Output,
        [string]$Step
    )

    $text = [string]::Join("`n", @($Output | ForEach-Object { [string]$_ }))
    $jsonStart = $text.IndexOf('{')
    if ($jsonStart -lt 0) {
        throw ("{0} did not return JSON" -f $Step)
    }

    try {
        return ($text.Substring($jsonStart) | ConvertFrom-Json -ErrorAction Stop)
    }
    catch {
        throw ("{0} returned invalid JSON: {1}" -f $Step, $_.Exception.Message)
    }
}

function Resolve-OutputPath {
    param(
        [string]$RepoRoot,
        [string]$Path
    )

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return [System.IO.Path]::GetFullPath($Path)
    }

    return [System.IO.Path]::GetFullPath((Join-Path $RepoRoot $Path))
}

function Write-CloseoutResult {
    param(
        [hashtable]$Result,
        [switch]$Json
    )

    if ($Json.IsPresent) {
        $Result | ConvertTo-Json -Depth 8
        return
    }

    Write-Output ('[AB-TICKET-CLOSEOUT] ticket={0} success={1} reason={2} handled_at={3}' -f $Result.ticket_id, $Result.success, $Result.reason, $Result.handled_at)
    Write-Output ('[AB-TICKET-CLOSEOUT] ledger_status={0} processed={1} receipt_valid={2} closure_pass={3}' -f $Result.ledger_status, $Result.processed, $Result.receipt_valid, $Result.closure_pass)
}

$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$ticket = $TicketId.Trim()
$result = [ordered]@{
    schema = 'AB_AGENT_TICKET_CLOSEOUT_V1'
    generated_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    success = $false
    reason = 'not-started'
    ticket_id = $ticket
    handled_at = ''
    ledger_status = ''
    processed = $false
    receipt_valid = $false
    closure_pass = $false
    poll_lock_busy = $false
}

try {
    if ([string]::IsNullOrWhiteSpace($ticket)) {
        throw 'TicketId must not be empty'
    }

    Push-Location $repoRoot
    try {
        $pollArgs = @(
            '-NoProfile', '-ExecutionPolicy', 'Bypass',
            '-File', (Join-Path $PSScriptRoot 'poll_agent_tickets.ps1'),
            '-StartFile', $StartFile,
            '-AcknowledgeTicketIds', $ticket,
            '-Last', [string]$Last,
            '-AsJson'
        )
        $retryBudget = $AcknowledgeRetryBudgetUsed.Trim().ToLowerInvariant()
        if (-not [string]::IsNullOrWhiteSpace($retryBudget)) {
            if ($retryBudget -notin @('yes', 'no')) {
                throw 'AcknowledgeRetryBudgetUsed must be yes or no'
            }
            $pollArgs += @('-AcknowledgeRetryBudgetUsed', $retryBudget)
        }
        if (-not [string]::IsNullOrWhiteSpace($QueuePath)) { $pollArgs += @('-QueuePath', $QueuePath) }
        if (-not [string]::IsNullOrWhiteSpace($StatePath)) { $pollArgs += @('-StatePath', $StatePath) }
        if (-not [string]::IsNullOrWhiteSpace($LedgerPath)) { $pollArgs += @('-LedgerPath', $LedgerPath) }

        $pollOutput = @(& powershell @pollArgs 2>&1)
        $pollExitCode = $LASTEXITCODE
        $poll = Convert-CommandOutputToJson -Output $pollOutput -Step 'acknowledge'
        $pollLockBusy = $false
        if ($poll.PSObject.Properties.Name -contains 'lock_busy') {
            $pollLockBusy = [bool]$poll.lock_busy
        }
        elseif ($poll.PSObject.Properties.Name -contains 'poll_lock' -and $null -ne $poll.poll_lock) {
            $pollLockBusy = [bool]$poll.poll_lock.lock_busy
        }

        if ($pollLockBusy) {
            $result.poll_lock_busy = $true
            throw 'acknowledge poll lock is busy'
        }
        if ($pollExitCode -ne 0) {
            throw ("acknowledge exited with code {0}" -f $pollExitCode)
        }

        $statePath = Resolve-OutputPath -RepoRoot $repoRoot -Path ([string]$poll.state_path)
        $state = Get-Content -LiteralPath $statePath -Raw -Encoding utf8 | ConvertFrom-Json -ErrorAction Stop
        $result.processed = (@($state.processed_ids) -contains $ticket)

        $validateArgs = @(
            '-NoProfile', '-ExecutionPolicy', 'Bypass',
            '-File', (Join-Path $PSScriptRoot 'validate_ticket_handled_receipt.ps1'),
            '-StartFile', $StartFile,
            '-TicketId', $ticket,
            '-EnqueueReminder', 'false',
            '-AsJson'
        )
        if (-not [string]::IsNullOrWhiteSpace($retryBudget)) {
            $validateArgs += @('-ExpectedRetryBudgetUsed', $retryBudget)
        }
        if (-not [string]::IsNullOrWhiteSpace($QueuePath)) { $validateArgs += @('-QueuePath', $QueuePath) }
        if (-not [string]::IsNullOrWhiteSpace($LedgerPath)) { $validateArgs += @('-LedgerPath', $LedgerPath) }

        $validateOutput = @(& powershell @validateArgs 2>&1)
        $validateExitCode = $LASTEXITCODE
        $validation = Convert-CommandOutputToJson -Output $validateOutput -Step 'receipt-validation'
        $result.receipt_valid = ($validateExitCode -eq 0 -and [bool]$validation.success -and [bool]$validation.handled_at_format_valid)
        $result.handled_at = [string]$validation.handled_at
        $result.ledger_status = [string]$validation.ledger_status

        $closureArgs = @(
            '-NoProfile', '-ExecutionPolicy', 'Bypass',
            '-File', (Join-Path $PSScriptRoot 'check_unattended_ticket_closure.ps1'),
            '-StartFile', $StartFile,
            '-TicketId', $ticket,
            '-AsJson'
        )
        if (-not [string]::IsNullOrWhiteSpace($QueuePath)) { $closureArgs += @('-QueuePath', $QueuePath) }
        if (-not [string]::IsNullOrWhiteSpace($LedgerPath)) { $closureArgs += @('-LedgerPath', $LedgerPath) }
        if (-not [string]::IsNullOrWhiteSpace($TakeoverRoot)) { $closureArgs += @('-TakeoverRoot', $TakeoverRoot) }
        $closureOutput = @(& powershell @closureArgs 2>&1)
        $closureExitCode = $LASTEXITCODE
        $closure = Convert-CommandOutputToJson -Output $closureOutput -Step 'closure-check'
        $result.closure_pass = ($closureExitCode -eq 0 -and [bool]$closure.pass)

        if (-not $result.processed) {
            throw 'ticket is absent from persisted processed_ids'
        }
        if (-not $result.receipt_valid) {
            throw 'persisted handled receipt is invalid'
        }
        if ($result.ledger_status -ne 'done') {
            throw ("ledger status is {0}, expected done" -f $result.ledger_status)
        }
        if (-not $result.closure_pass) {
            throw 'ticket closure check returned pass=false'
        }

        $result.success = $true
        $result.reason = 'closeout-verified'
    }
    finally {
        Pop-Location
    }
}
catch {
    $result.reason = $_.Exception.Message
}

Write-CloseoutResult -Result $result -Json:$AsJson
if (-not $result.success) {
    exit 2
}