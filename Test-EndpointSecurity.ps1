<#
.SYNOPSIS
    Read-only security baseline check for a Windows endpoint. Prints PASS / WARN / FAIL with a fix for each item.

.DESCRIPTION
    Checks the controls that matter most on a user workstation: antivirus, firewall, disk
    encryption, patching, local admins, legacy protocols, and logging. Run it after imaging a
    device and before handing it to the user, or during an incident to spot weakened defenses.
    It changes nothing.

    Run from an elevated PowerShell prompt for complete results.

.EXAMPLE
    .\Test-EndpointSecurity.ps1
.EXAMPLE
    .\Test-EndpointSecurity.ps1 -ReportPath .\baseline_$env:COMPUTERNAME.csv
#>
[CmdletBinding()]
param([string]$ReportPath)

$results = New-Object System.Collections.Generic.List[object]
function Add-Result([string]$Area, [string]$Check, [ValidateSet('PASS', 'WARN', 'FAIL', 'INFO')][string]$Status, [string]$Fix = "") {
    $results.Add([pscustomobject]@{ Area = $Area; Check = $Check; Status = $Status; Fix = $Fix })
    $color = @{ PASS = 'Green'; WARN = 'Yellow'; FAIL = 'Red'; INFO = 'Cyan' }[$Status]
    Write-Host ("  [{0}] {1}" -f $Status, $Check) -ForegroundColor $color
    if ($Fix -and $Status -ne 'PASS') { Write-Host "         fix: $Fix" -ForegroundColor DarkGray }
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Host "`nEndpoint Security Baseline: $env:COMPUTERNAME  $(Get-Date -Format 'yyyy-MM-dd HH:mm')" -ForegroundColor White
if (-not $isAdmin) { Write-Host "Note: not elevated, so some checks will show as unknown." -ForegroundColor Yellow }

# --- Antivirus ---------------------------------------------------------------
Write-Host "`n== Antivirus (Microsoft Defender) ==" -ForegroundColor Cyan
try {
    $mp = Get-MpComputerStatus -ErrorAction Stop
    if ($mp.AntivirusEnabled) { Add-Result AV "Defender antivirus enabled" PASS } else { Add-Result AV "Defender antivirus disabled" FAIL "Enable Defender or confirm a third-party AV is active" }
    if ($mp.RealTimeProtectionEnabled) { Add-Result AV "Real-time protection on" PASS } else { Add-Result AV "Real-time protection OFF" FAIL "Set-MpPreference -DisableRealtimeMonitoring `$false" }
    $age = $mp.AntivirusSignatureAge
    if ($age -le 3) { Add-Result AV "Signatures $age day(s) old" PASS } else { Add-Result AV "Signatures $age day(s) old" WARN "Update-MpSignature" }
    if ($mp.IsTamperProtected) { Add-Result AV "Tamper protection on" PASS } else { Add-Result AV "Tamper protection off" WARN "Enable in Windows Security > Virus & threat protection settings" }
} catch { Add-Result AV "Could not query Defender (third-party AV installed?)" INFO }

# --- Firewall ----------------------------------------------------------------
Write-Host "`n== Firewall ==" -ForegroundColor Cyan
foreach ($p in Get-NetFirewallProfile) {
    if ($p.Enabled) { Add-Result Firewall "$($p.Name) profile enabled" PASS }
    else { Add-Result Firewall "$($p.Name) profile DISABLED" FAIL "Set-NetFirewallProfile -Profile $($p.Name) -Enabled True" }
}

# --- Encryption --------------------------------------------------------------
Write-Host "`n== Disk Encryption ==" -ForegroundColor Cyan
try {
    $bl = Get-BitLockerVolume -MountPoint C: -ErrorAction Stop
    if ($bl.ProtectionStatus -eq 'On') { Add-Result Encryption "BitLocker protecting C:" PASS }
    else { Add-Result Encryption "BitLocker is NOT protecting C: ($($bl.VolumeStatus))" FAIL "Enable BitLocker and escrow the recovery key (AD/Entra ID)" }
} catch { Add-Result Encryption "BitLocker status unknown (needs admin / not supported on this edition)" INFO }

# --- Patching ----------------------------------------------------------------
Write-Host "`n== Updates ==" -ForegroundColor Cyan
$hf = Get-HotFix | Where-Object InstalledOn | Sort-Object InstalledOn -Descending | Select-Object -First 1
if ($hf) {
    $days = [int]((Get-Date) - $hf.InstalledOn).TotalDays
    if ($days -le 35) { Add-Result Updates "Last update installed $days day(s) ago ($($hf.HotFixID))" PASS }
    else { Add-Result Updates "Last update installed $days day(s) ago" FAIL "Run Windows Update. Monthly patches are missing" }
}
$pending = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or
           (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
if ($pending) { Add-Result Updates "Reboot pending to finish updates" WARN "Restart the device" } else { Add-Result Updates "No reboot pending" PASS }

# --- Accounts ----------------------------------------------------------------
Write-Host "`n== Accounts ==" -ForegroundColor Cyan
try {
    $admins = Get-LocalGroupMember -Group Administrators -ErrorAction Stop
    Add-Result Accounts "Local Administrators: $(($admins.Name) -join ', ')" INFO
    if ($admins.Count -gt 3) { Add-Result Accounts "$($admins.Count) members in local Administrators" WARN "Remove standard users from local admin (least privilege)" }
} catch { Add-Result Accounts "Could not list local Administrators" INFO }
$guest = Get-LocalUser -Name Guest -ErrorAction SilentlyContinue
if ($guest -and $guest.Enabled) { Add-Result Accounts "Guest account ENABLED" FAIL "Disable-LocalUser -Name Guest" } else { Add-Result Accounts "Guest account disabled" PASS }
$builtinAdmin = Get-LocalUser | Where-Object { $_.SID -like 'S-1-5-*-500' }
if ($builtinAdmin -and $builtinAdmin.Enabled) { Add-Result Accounts "Built-in Administrator (RID 500) enabled" WARN "Disable it, or use LAPS to randomize its password" }
$uac = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction SilentlyContinue).EnableLUA
if ($uac -eq 1) { Add-Result Accounts "UAC enabled" PASS } else { Add-Result Accounts "UAC DISABLED" FAIL "Set EnableLUA = 1 and reboot" }

# --- Legacy / risky services ---------------------------------------------------
Write-Host "`n== Network Attack Surface ==" -ForegroundColor Cyan
try {
    $smb1 = (Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol
    if ($smb1) { Add-Result Network "SMBv1 enabled (WannaCry/EternalBlue risk)" FAIL "Set-SmbServerConfiguration -EnableSMB1Protocol `$false" } else { Add-Result Network "SMBv1 disabled" PASS }
} catch { Add-Result Network "SMBv1 status unknown" INFO }
$rdp = (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -ErrorAction SilentlyContinue).fDenyTSConnections
if ($rdp -eq 0) {
    $nla = (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -ErrorAction SilentlyContinue).UserAuthentication
    if ($nla -eq 1) { Add-Result Network "RDP enabled (with NLA)" WARN "Disable RDP if not needed; never expose 3389 to the internet" }
    else { Add-Result Network "RDP enabled WITHOUT Network Level Authentication" FAIL "Require NLA, or disable RDP" }
} else { Add-Result Network "RDP disabled" PASS }

# --- Logging -----------------------------------------------------------------
Write-Host "`n== Logging ==" -ForegroundColor Cyan
$sbl = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -ErrorAction SilentlyContinue).EnableScriptBlockLogging
if ($sbl -eq 1) { Add-Result Logging "PowerShell script block logging (4104) on" PASS } else { Add-Result Logging "PowerShell script block logging off" WARN "Enable via GPO: Administrative Templates > Windows Components > Windows PowerShell" }
try {
    $secLog = Get-WinEvent -ListLog Security -ErrorAction Stop
    $mb = [math]::Round($secLog.MaximumSizeInBytes / 1MB)
    if ($mb -ge 128) { Add-Result Logging "Security log max size $mb MB" PASS } else { Add-Result Logging "Security log max size only $mb MB (rolls over fast)" WARN "Increase to at least 128 MB, or forward logs to a SIEM" }
} catch { Add-Result Logging "Security log settings unknown (needs admin)" INFO }

# --- Summary -----------------------------------------------------------------
$scored = $results | Where-Object Status -in 'PASS', 'WARN', 'FAIL'
$pass = @($scored | Where-Object Status -eq 'PASS').Count
$warnN = @($scored | Where-Object Status -eq 'WARN').Count
$failN = @($scored | Where-Object Status -eq 'FAIL').Count
$score = if ($scored.Count) { [math]::Round(100 * $pass / $scored.Count) } else { 0 }
Write-Host "`n== Summary ==  PASS $pass   WARN $warnN   FAIL $failN   ->  baseline score $score%`n" -ForegroundColor White

if ($ReportPath) {
    $results | Export-Csv -Path $ReportPath -NoTypeInformation
    Write-Host "Report saved to $ReportPath"
}
