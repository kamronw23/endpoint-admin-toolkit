<#
.SYNOPSIS
    Step-by-step network connectivity troubleshooter for help desk tickets ("the Wi-Fi isn't working").

.DESCRIPTION
    Walks the network stack from the bottom up, the way you'd troubleshoot by hand
    (OSI layers 1 → 7), and stops at the first broken layer with a plain-English diagnosis:

      1. Adapter up?             (cable / Wi-Fi radio / driver)
      2. Valid IP address?       (169.254.x.x APIPA = DHCP failed)
      3. Default gateway reachable?
      4. DNS servers configured and answering?
      5. Internet reachable by IP and by name, over HTTPS?
      6. Wi-Fi details           (SSID, signal, band)

.EXAMPLE
    .\Invoke-NetworkTroubleshooter.ps1
.EXAMPLE
    .\Invoke-NetworkTroubleshooter.ps1 -TestHost portal.company.com
#>
[CmdletBinding()]
param([string]$TestHost = "www.microsoft.com")

function Step([string]$Name) { Write-Host "`n[$Name]" -ForegroundColor Cyan }
function Ok([string]$Msg) { Write-Host "  OK   $Msg" -ForegroundColor Green }
function Bad([string]$Msg, [string]$Fix) {
    Write-Host "  FAIL $Msg" -ForegroundColor Red
    Write-Host "  >>   $Fix" -ForegroundColor Yellow
}
$problems = 0

Step "1. Network adapters"
$up = Get-NetAdapter | Where-Object Status -eq 'Up'
if (-not $up) {
    Bad "No network adapter is connected" "Check the cable or turn Wi-Fi on (airplane mode off), then check Device Manager for driver errors"
    return
}
foreach ($a in $up) { Ok "$($a.Name): $($a.InterfaceDescription), $($a.LinkSpeed)" }

Step "2. IP configuration"
$cfg = Get-NetIPConfiguration | Where-Object { $_.IPv4Address -and $_.NetAdapter.Status -eq 'Up' } | Select-Object -First 1
$ip = $cfg.IPv4Address.IPAddress
if (-not $ip) {
    Bad "No IPv4 address" "Run: ipconfig /release; ipconfig /renew"; $problems++
} elseif ($ip -like '169.254.*') {
    Bad "APIPA address $($ip): the device could NOT get an address from DHCP" "Run 'ipconfig /renew'. If it persists, check the switch port/VLAN or Wi-Fi authentication, and whether the DHCP scope is full"; $problems++
} else { Ok "IPv4 $ip/$($cfg.IPv4Address.PrefixLength) on $($cfg.InterfaceAlias)" }

Step "3. Default gateway"
$gw = $cfg.IPv4DefaultGateway.NextHop
if (-not $gw) {
    Bad "No default gateway" "DHCP problem or static IP misconfigured"; $problems++
} elseif (Test-Connection -ComputerName $gw -Count 2 -Quiet) {
    Ok "Gateway $gw responds"
} else {
    Bad "Gateway $gw does not respond to ping" "Local network issue: check the cable/AP, reboot the adapter, or the gateway may block ICMP"; $problems++
}

Step "4. DNS"
$dns = (Get-DnsClientServerAddress -InterfaceIndex $cfg.InterfaceIndex -AddressFamily IPv4).ServerAddresses
if (-not $dns) { Bad "No DNS servers configured" "Set DNS via DHCP or manually"; $problems++ }
else {
    Ok "DNS servers: $($dns -join ', ')"
    try {
        $r = Resolve-DnsName -Name $TestHost -Type A -DnsOnly -ErrorAction Stop | Where-Object Type -eq 'A' | Select-Object -First 1
        Ok "$TestHost resolves to $($r.IPAddress)"
    } catch {
        Bad "Cannot resolve $TestHost" "DNS failure. Run 'ipconfig /flushdns', try another DNS server, and check for a proxy/VPN"; $problems++
    }
}

Step "5. Internet / service reachability"
if (Test-Connection -ComputerName 1.1.1.1 -Count 2 -Quiet) { Ok "Internet reachable by IP (1.1.1.1)" }
else { Bad "Cannot reach the internet by IP" "Upstream/ISP or firewall issue; check whether other users are affected"; $problems++ }
$https = Test-NetConnection -ComputerName $TestHost -Port 443 -WarningAction SilentlyContinue
if ($https.TcpTestSucceeded) { Ok "HTTPS to $TestHost works" }
else { Bad "HTTPS (443) to $TestHost failed" "Possible proxy, captive portal (hotel/guest Wi-Fi), or firewall block"; $problems++ }

Step "6. Wi-Fi details"
$wlan = netsh wlan show interfaces 2>$null
if ($wlan -match 'SSID') {
    $ssid   = (($wlan | Select-String '^\s+SSID\s+:') -split ':', 2)[1].Trim()
    $signal = (($wlan | Select-String '^\s+Signal\s+:') -split ':', 2)[1].Trim()
    $band   = ($wlan | Select-String '^\s+(Radio type|Band)\s+:') | ForEach-Object { ($_ -split ':', 2)[1].Trim() }
    Ok "SSID '$ssid', signal $signal, $($band -join ' / ')"
    if ([int]($signal -replace '%', '') -lt 50) { Bad "Weak Wi-Fi signal ($signal)" "Move closer to the access point or switch to 5 GHz"; $problems++ }
} else { Write-Host "  --   Not on Wi-Fi (wired connection)" }

Write-Host ""
if ($problems -eq 0) { Write-Host "Result: no network problems found. The issue is likely the application or account (try another site/app, check credentials)." -ForegroundColor Green }
else { Write-Host "Result: $problems problem(s) found. Fix the FIRST failure above; the later ones are often caused by it." -ForegroundColor Yellow }
