param(
    [switch]$DryRun,
    [switch]$SkipAgentTicketStatusView,
    [ValidateRange(1, 200)][int]$AgentTicketViewKeepRecentStatus = 5,
    [ValidateRange(1, 720)][int]$AgentTicketViewKeepStatusHours = 24,
    [ValidateRange(1, 200)][int]$AgentTicketViewStartFileLimit = 40
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$pruneScript = Join-Path $PSScriptRoot "prune_artifacts.ps1"
$statusViewScript = Join-Path $PSScriptRoot "build_agent_ticket_status_view.ps1"

if (-not (Test-Path -LiteralPath $pruneScript)) {
    throw "Missing script: $pruneScript"
}

function Convert-ToRepoRelativePath {
    param(
        [string]$RepoRoot,
        [string]$Path
    )

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $repoRootFull = [System.IO.Path]::GetFullPath($RepoRoot)
    if ($fullPath.StartsWith($repoRootFull, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $fullPath.Substring($repoRootFull.Length).TrimStart('\\').Replace('\\', '/')
    }

    return $fullPath.Replace('\\', '/')
}

function Invoke-AgentTicketStatusViewRefresh {
    if ($SkipAgentTicketStatusView.IsPresent) {
        Write-Output '[PRUNE-ALL][STATUS-VIEW] skipped by switch'
        return
    }

    if (-not (Test-Path -LiteralPath $statusViewScript)) {
        Write-Output ("[PRUNE-ALL][STATUS-VIEW] skip_missing script={0}" -f $statusViewScript)
        return
    }

    $queuePath = Join-Path $repoRoot 'out\artifacts\ab_agent_queue\agent_tickets.jsonl'
    if (-not (Test-Path -LiteralPath $queuePath)) {
        Write-Output ("[PRUNE-ALL][STATUS-VIEW] skip_missing queue={0}" -f $queuePath)
        return
    }

    $startDir = Join-Path $repoRoot 'testdata\unattended_start\active'
    if (-not (Test-Path -LiteralPath $startDir)) {
        Write-Output ("[PRUNE-ALL][STATUS-VIEW] skip_missing start_dir={0}" -f $startDir)
        return
    }

    $startFiles = @(
        Get-ChildItem -LiteralPath $startDir -File -Filter 'unattended_ab_start_*.md' -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending |
            Select-Object -First $AgentTicketViewStartFileLimit
    )

    if ($startFiles.Count -eq 0) {
        Write-Output ("[PRUNE-ALL][STATUS-VIEW] nothing_to_refresh start_dir={0}" -f $startDir)
        return
    }

    Write-Output ("[PRUNE-ALL][STATUS-VIEW] refresh_count={0} keep_recent={1} keep_hours={2}" -f $startFiles.Count, $AgentTicketViewKeepRecentStatus, $AgentTicketViewKeepStatusHours)

    foreach ($startFile in $startFiles) {
        $startFileRel = Convert-ToRepoRelativePath -RepoRoot $repoRoot -Path $startFile.FullName
        $invokeArgs = @{
            StartFile = $startFileRel
            KeepRecentStatus = $AgentTicketViewKeepRecentStatus
            KeepStatusHours = $AgentTicketViewKeepStatusHours
        }
        if ($DryRun.IsPresent) {
            $invokeArgs['DryRun'] = $true
        }

        try {
            $summaryText = (& $statusViewScript @invokeArgs) -join [Environment]::NewLine
            $summary = $null
            try {
                $summary = $summaryText | ConvertFrom-Json -ErrorAction Stop
            }
            catch {
                $summary = $null
            }

            if ($null -ne $summary) {
                Write-Output (
                    "[PRUNE-ALL][STATUS-VIEW] refreshed start={0} total={1} status={2} pruned={3} view={4}" -f
                    $startFileRel,
                    [int]$summary.total_for_start,
                    [int]$summary.status_total,
                    [int]$summary.status_pruned,
                    [int]$summary.view_total
                )
            }
            else {
                Write-Output ("[PRUNE-ALL][STATUS-VIEW] refreshed start={0}" -f $startFileRel)
            }
        }
        catch {
            Write-Output ("[PRUNE-ALL][STATUS-VIEW] failed start={0} error={1}" -f $startFileRel, $_.Exception.Message)
        }
    }
}

function Invoke-DirectoryPrunePlan {
    param(
        [int]$Keep,
        [string]$RelativePath
    )

    $dirPath = Join-Path $repoRoot $RelativePath
    Write-Output ("[PRUNE-ALL] keep={0} dir={1}" -f $Keep, $dirPath)

    $invokeArgs = @{
        Keep = $Keep
        ArtifactsDir = $dirPath
    }

    if ($DryRun.IsPresent) {
        $invokeArgs["DryRun"] = $true
    }

    & $pruneScript @invokeArgs
}

function Invoke-TimestampDirectoryPrunePlan {
    param(
        [int]$Keep,
        [string]$RelativePath,
        [string]$NameRegex = '^[0-9]{8}-[0-9]{6}$'
    )

    $dirPath = Join-Path $repoRoot $RelativePath
    Write-Output ("[PRUNE-ALL][TS-DIR] keep={0} dir={1} regex={2}" -f $Keep, $dirPath, $NameRegex)

    if (-not (Test-Path -LiteralPath $dirPath)) {
        Write-Output ("[PRUNE-ALL][TS-DIR] skip_missing dir={0}" -f $dirPath)
        return
    }

    $dirs = @(
        Get-ChildItem -LiteralPath $dirPath -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match $NameRegex } |
            Sort-Object Name -Descending
    )
    $prune = @($dirs | Select-Object -Skip $Keep)

    if ($prune.Count -eq 0) {
        Write-Output ("[PRUNE-ALL][TS-DIR] nothing_to_prune dir={0}" -f $dirPath)
        return
    }

    Write-Output ("[PRUNE-ALL][TS-DIR] prune_count={0} dir={1}" -f $prune.Count, $dirPath)

    foreach ($entry in $prune) {
        if ($DryRun.IsPresent) {
            Write-Output ("[PRUNE-ALL][TS-DIR] DryRun remove={0}" -f $entry.FullName)
        }
        elseif (Test-Path -LiteralPath $entry.FullName) {
            Remove-Item -LiteralPath $entry.FullName -Recurse -Force
        }
    }
}

function Invoke-TimestampFilePrunePlan {
    param(
        [int]$Keep,
        [string]$RelativePath,
        [string]$Filter
    )

    $dirPath = Join-Path $repoRoot $RelativePath
    Write-Output ("[PRUNE-ALL][TS-FILE] keep={0} dir={1} filter={2}" -f $Keep, $dirPath, $Filter)

    if (-not (Test-Path -LiteralPath $dirPath)) {
        Write-Output ("[PRUNE-ALL][TS-FILE] skip_missing dir={0}" -f $dirPath)
        return
    }

    $files = @(Get-ChildItem -LiteralPath $dirPath -File -Filter $Filter -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)
    $prune = @($files | Select-Object -Skip $Keep)

    if ($prune.Count -eq 0) {
        Write-Output ("[PRUNE-ALL][TS-FILE] nothing_to_prune dir={0} filter={1}" -f $dirPath, $Filter)
        return
    }

    Write-Output ("[PRUNE-ALL][TS-FILE] prune_count={0} dir={1} filter={2}" -f $prune.Count, $dirPath, $Filter)

    foreach ($entry in $prune) {
        if ($DryRun.IsPresent) {
            Write-Output ("[PRUNE-ALL][TS-FILE] DryRun remove={0}" -f $entry.FullName)
        }
        elseif (Test-Path -LiteralPath $entry.FullName) {
            Remove-Item -LiteralPath $entry.FullName -Force
        }
    }
}

$timestampDirectoryPlans = @(
    @{ Keep = 25; RelativePath = 'out/artifacts'; NameRegex = '^[0-9]{8}-[0-9]{6}$' },
    @{ Keep = 12; RelativePath = 'out/release_flow'; NameRegex = '^[0-9]{8}-[0-9]{6}$' },
    @{ Keep = 12; RelativePath = 'out/stress'; NameRegex = '^[0-9]{8}-[0-9]{6}$' }
)

$directoryPlans = @(
    @{ Keep = 8; RelativePath = "out/artifacts/batch_raw" },
    @{ Keep = 8; RelativePath = "out/artifacts/batch_health" },
    @{ Keep = 8; RelativePath = "out/artifacts/batch_plan" },
    @{ Keep = 8; RelativePath = "out/artifacts/batch_planb" },
    @{ Keep = 8; RelativePath = "out/artifacts/autopilot_dev_recheck_8round" },
    @{ Keep = 8; RelativePath = "out/artifacts/autopilot_four_round" },
    @{ Keep = 8; RelativePath = "out/artifacts/redirect_matrix_10x6" },
    @{ Keep = 8; RelativePath = "out/artifacts/oneclick_dryrun_guard" },
    @{ Keep = 8; RelativePath = "out/artifacts/dev_verify_multiround" },
    @{ Keep = 8; RelativePath = "out/artifacts/d6_consistency_double_round" },
    @{ Keep = 8; RelativePath = "out/artifacts/cidr_body_contract" },
    @{ Keep = 8; RelativePath = "out/artifacts/preclass_matrix" },
    @{ Keep = 8; RelativePath = "out/artifacts/preclass_p1_matrix" },
    @{ Keep = 8; RelativePath = "out/artifacts/preclass_table_guard" },
    @{ Keep = 8; RelativePath = "out/artifacts/redirect_matrix" },
    @{ Keep = 8; RelativePath = "out/artifacts/ab_manual_stop" },
    @{ Keep = 8; RelativePath = "out/artifacts/ab_companion" },
    @{ Keep = 8; RelativePath = "out/artifacts/ab_supervisor" },
    @{ Keep = 8; RelativePath = "out/artifacts/ab_session_guard" },
    @{ Keep = 8; RelativePath = "out/artifacts/step47_ab" },
    @{ Keep = 8; RelativePath = "out/artifacts/step47_matrix" },
    @{ Keep = 8; RelativePath = "out/artifacts/step47_preclass_preflight" },
    @{ Keep = 8; RelativePath = "out/artifacts/step47_prerelease" },
    @{ Keep = 8; RelativePath = "out/artifacts/step47_rollback" }
)

$timestampFilePlans = @(
    @{ Keep = 40; RelativePath = 'out/artifacts/ab_stage_runtime/A'; Filter = 'a_runtime_*.log' },
    @{ Keep = 40; RelativePath = 'out/artifacts/ab_stage_runtime/B'; Filter = 'b_runtime_*.log' },
    @{ Keep = 40; RelativePath = 'out/artifacts/ab_stage_exit'; Filter = '*_a_pid*.json' },
    @{ Keep = 40; RelativePath = 'out/artifacts/ab_stage_exit'; Filter = '*_b_pid*.json' },
    @{ Keep = 30; RelativePath = 'out/artifacts/cidr_bundle'; Filter = 'cidr_bundle_summary_*.txt' },
    @{ Keep = 30; RelativePath = 'out/artifacts/ab_agent_queue'; Filter = 'takeover_trigger_*.log' },
    @{ Keep = 30; RelativePath = 'out/artifacts/ab_agent_queue'; Filter = 'chat_session_heartbeat_*.json' },
    @{ Keep = 30; RelativePath = 'out/artifacts/ab_agent_queue'; Filter = 'ai_ticket_poll_state_*.json' },
    @{ Keep = 30; RelativePath = 'out/artifacts/ab_agent_queue'; Filter = 'ai_ticket_ledger_*.json' },
    @{ Keep = 40; RelativePath = 'out/artifacts/ab_agent_queue'; Filter = 'agent_tickets_view_*.jsonl' },
    @{ Keep = 40; RelativePath = 'out/artifacts/ab_agent_queue'; Filter = 'agent_tickets_view_*.jsonl.summary.json' },
    @{ Keep = 60; RelativePath = 'out/artifacts/ab_agent_queue/archive'; Filter = 'ai_ticket_ledger_archive_*.jsonl' },
    @{ Keep = 40; RelativePath = 'out/artifacts/ab_agent_queue/chat_dispatch'; Filter = 'dispatch_*.log' },
    @{ Keep = 120; RelativePath = 'out/artifacts/ab_agent_queue/chat_dispatch'; Filter = 'relay_*.md' }
)

foreach ($plan in $timestampDirectoryPlans) {
    Invoke-TimestampDirectoryPrunePlan -Keep ([int]$plan.Keep) -RelativePath ([string]$plan.RelativePath) -NameRegex ([string]$plan.NameRegex)
}

foreach ($plan in $directoryPlans) {
    Invoke-DirectoryPrunePlan -Keep ([int]$plan.Keep) -RelativePath ([string]$plan.RelativePath)
}

Invoke-AgentTicketStatusViewRefresh

foreach ($plan in $timestampFilePlans) {
    Invoke-TimestampFilePrunePlan -Keep ([int]$plan.Keep) -RelativePath ([string]$plan.RelativePath) -Filter ([string]$plan.Filter)
}

Write-Output "[PRUNE-ALL] done"
