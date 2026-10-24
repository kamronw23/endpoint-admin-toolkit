<#
.SYNOPSIS
    Help desk helper for "I'm locked out" tickets: shows account status and WHERE the lockouts come from.

.DESCRIPTION
    Repeated lockouts usually have a source: an old password saved on a phone, a mapped drive,
    a scheduled task, or an attacker guessing passwords. This script shows:

      * Account status: locked, enabled, bad password count, password last set/expiry
        (Active Directory if the RSAT module is available, otherwise the local account)
      * Recent lockout events (4740) and failed logons (4625) for the user, with the
        CALLER COMPUTER / source IP, so you can find the device that keeps locking it out

    Lockouts from unfamiliar IPs or many accounts at once point to brute force or password
    spraying. Escalate to security instead of just unlocking.

    For domain accounts, run it on a Domain Controller (or point -Server at the PDC emulator) to see 4740 events.

.EXAMPLE
    .\Get-AccountLockoutInfo.ps1 -UserName jsmith
.EXAMPLE
    .\Get-AccountLockoutInfo.ps1 -UserName jsmith -Server DC01 -Hours 48
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$UserName,
    [string]$Server = $env:COMPUTERNAME,
    [int]$Hours = 24
)

Write-Host "`n== Account status: $UserName ==" -ForegroundColor Cyan
if (Get-Module -ListAvailable -Name ActiveDirectory) {
    Import-Module ActiveDirectory
    try {
        $u = Get-ADUser $UserName -Properties LockedOut, Enabled, badPwdCount, LastBadPasswordAttempt, PasswordLastSet, PasswordExpired, 'msDS-UserPasswordExpiryTimeComputed', LastLogonDate -ErrorAction Stop
        $expiry = if ($u.'msDS-UserPasswordExpiryTimeComputed' -and $u.'msDS-UserPasswordExpiryTimeComputed' -lt [long]::MaxValue) { [datetime]::FromFileTime($u.'msDS-UserPasswordExpiryTimeComputed') } else { "Never" }
        [pscustomobject]@{
            Account         = $u.SamAccountName
            Enabled         = $u.Enabled
            LockedOut       = $u.LockedOut
            BadPwdCount     = $u.badPwdCount
            LastBadPassword = $u.LastBadPasswordAttempt
            PasswordLastSet = $u.PasswordLastSet
            PasswordExpired = $u.PasswordExpired
            PasswordExpires = $expiry
            LastLogon       = $u.LastLogonDate
        } | Format-List
        if ($u.LockedOut) { Write-Host "To unlock after verifying identity:  Unlock-ADAccount -Identity $UserName" -ForegroundColor Yellow }
    } catch { Write-Warning "AD lookup failed: $_" }
} else {
    $l = Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue
    if ($l) { $l | Select-Object Name, Enabled, PasswordLastSet, PasswordExpires, LastLogon | Format-List }
    else { Write-Warning "No local account '$UserName' and the ActiveDirectory module isn't installed." }
}

$since = (Get-Date).AddHours(-$Hours)
Write-Host "== Lockout events (4740) on $Server, last $Hours h ==" -ForegroundColor Cyan
try {
    $lock = Get-WinEvent -ComputerName $Server -FilterHashtable @{ LogName = 'Security'; Id = 4740; StartTime = $since } -ErrorAction Stop |
        Where-Object { $_.Properties[0].Value -eq $UserName }
    if ($lock) {
        $lock | Select-Object TimeCreated, @{ n = 'User'; e = { $_.Properties[0].Value } }, @{ n = 'CallerComputer'; e = { $_.Properties[1].Value } } | Format-Table -AutoSize
        $top = $lock | Group-Object { $_.Properties[1].Value } | Sort-Object Count -Descending | Select-Object -First 1
        Write-Host ">> Most lockouts come from '$($top.Name)'. Check that device for saved/old credentials." -ForegroundColor Yellow
    } else { Write-Host "  none" }
} catch { Write-Host "  No 4740 events found (or no access; run as admin on the DC)." }

Write-Host "`n== Failed logons (4625) for $UserName on $Server, last $Hours h ==" -ForegroundColor Cyan
try {
    $fails = Get-WinEvent -ComputerName $Server -FilterHashtable @{ LogName = 'Security'; Id = 4625; StartTime = $since } -ErrorAction Stop | ForEach-Object {
        $x = [xml]$_.ToXml(); $d = @{}
        foreach ($n in $x.Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
        if ($d['TargetUserName'] -eq $UserName) {
            [pscustomobject]@{ Time = $_.TimeCreated; SourceIP = $d['IpAddress']; Workstation = $d['WorkstationName']; LogonType = $d['LogonType']; SubStatus = $d['SubStatus'] }
        }
    }
    if ($fails) {
        $fails | Group-Object SourceIP, Workstation | Sort-Object Count -Descending |
            Select-Object Count, @{ n = 'Source (IP, Workstation)'; e = { $_.Name } } | Format-Table -AutoSize
        $ext = $fails | Where-Object { $_.SourceIP -and $_.SourceIP -notmatch '^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|::1|-)' }
        if ($ext) { Write-Host "!! Failed logons from PUBLIC IPs. Possible attack: escalate to security (see the brute force playbook)." -ForegroundColor Red }
    } else { Write-Host "  none" }
} catch { Write-Host "  No 4625 events found (or no access)." }
