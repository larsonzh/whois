Set-StrictMode -Version Latest

function New-RecoveryGraceState {
    param([int]$Generation = 0)

    return [pscustomobject]@{
        Active = $false
        Kind = ''
        Scope = ''
        Reason = ''
        Source = ''
        ExpiryAction = ''
        Detail = ''
        StartedAt = $null
        LastNoticeAt = $null
        Generation = $Generation
    }
}

function Start-RecoveryGrace {
    param(
        [ValidateSet('main-exit', 'monitor-chain')][string]$Kind,
        [ValidateSet('A', 'B', 'SESSION')][string]$Scope,
        [string]$Reason,
        [string]$Source,
        [ValidateSet('main-exit-shutdown', 'monitor-chain-shutdown', 'expire-and-clear')][string]$ExpiryAction,
        [AllowEmptyString()][string]$Detail
    )

    if ($script:RecoveryGraceState.Active) {
        if ($script:RecoveryGraceState.Scope -eq 'SESSION' -and $Scope -ne 'SESSION') {
            return $false
        }
        if ($script:RecoveryGraceState.Kind -eq $Kind -and
            $script:RecoveryGraceState.Scope -eq $Scope -and
            $script:RecoveryGraceState.Reason -eq $Reason -and
            $script:RecoveryGraceState.Detail -eq $Detail) {
            return $false
        }
    }

    $nextGeneration = [int]$script:RecoveryGraceState.Generation + 1
    $script:RecoveryGraceState = [pscustomobject]@{
        Active = $true
        Kind = $Kind
        Scope = $Scope
        Reason = $Reason
        Source = $Source
        ExpiryAction = $ExpiryAction
        Detail = $Detail
        StartedAt = Get-Date
        LastNoticeAt = $null
        Generation = $nextGeneration
    }
    return $true
}

function Clear-RecoveryGrace {
    $generation = [int]$script:RecoveryGraceState.Generation
    $script:RecoveryGraceState = New-RecoveryGraceState -Generation $generation
}

function Update-RecoveryGraceLastNotice {
    if (-not $script:RecoveryGraceState.Active) {
        return
    }

    $script:RecoveryGraceState.LastNoticeAt = Get-Date
}

$script:RecoveryGraceState = New-RecoveryGraceState