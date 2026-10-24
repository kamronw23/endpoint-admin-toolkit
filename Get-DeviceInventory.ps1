<#
.SYNOPSIS
    Collects a hardware/OS/security inventory of a Windows device for deployment and asset tracking.

.DESCRIPTION
    Gathers what a deployment tech records when imaging or refreshing a device (serial number,
    model, OS build, CPU, RAM, disk, network adapters, BitLocker status, domain, last boot) and
    appends it to a CSV, so a whole rollout can be tracked in one spreadsheet.

    An accurate asset inventory is CIS Critical Security Control #1: you can't protect devices
    you don't know you have.

.EXAMPLE
    .\Get-DeviceInventory.ps1
.EXAMPLE
    .\Get-DeviceInventory.ps1 -CsvPath \\fileserver\deploy\inventory.csv -AssetTag MED-04412
#>
[CmdletBinding()]
param(
    [string]$CsvPath = ".\device_inventory.csv",
    [string]$AssetTag = ""
)

$cs   = Get-CimInstance Win32_ComputerSystem
$bios = Get-CimInstance Win32_BIOS
$os   = Get-CimInstance Win32_OperatingSystem
$cpu  = Get-CimInstance Win32_Processor | Select-Object -First 1
$disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"
$nics = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True"

$bitlocker = "Unknown (run as Administrator)"
try {
    $vol = Get-BitLockerVolume -MountPoint "C:" -ErrorAction Stop
    $bitlocker = "$($vol.ProtectionStatus) ($($vol.VolumeStatus), $($vol.EncryptionPercentage)%)"
} catch { }

$tpm = "Unknown"
try {
    $t = Get-Tpm -ErrorAction Stop
    $tpm = if ($t.TpmPresent) { "Present, Ready=$($t.TpmReady)" } else { "Not present" }
} catch { }

$record = [pscustomobject]@{
    CollectedUtc   = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
    AssetTag       = $AssetTag
    Hostname       = $env:COMPUTERNAME
    SerialNumber   = $bios.SerialNumber
    Manufacturer   = $cs.Manufacturer
    Model          = $cs.Model
    OS             = $os.Caption
    OSBuild        = "$($os.Version) (build $($os.BuildNumber))"
    InstallDate    = $os.InstallDate.ToString("yyyy-MM-dd")
    LastBoot       = $os.LastBootUpTime.ToString("yyyy-MM-dd HH:mm")
    CPU            = $cpu.Name.Trim()
    RAM_GB         = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)
    Disk_C_GB      = [math]::Round($disk.Size / 1GB, 0)
    Disk_C_Free_GB = [math]::Round($disk.FreeSpace / 1GB, 0)
    Domain         = if ($cs.PartOfDomain) { $cs.Domain } else { "WORKGROUP: $($cs.Workgroup)" }
    LoggedOnUser   = $cs.UserName
    IPv4           = ($nics | ForEach-Object { $_.IPAddress | Where-Object { $_ -match '^\d+\.' } }) -join "; "
    MAC            = ($nics.MACAddress | Where-Object { $_ }) -join "; "
    BitLocker_C    = $bitlocker
    TPM            = $tpm
    BIOSVersion    = $bios.SMBIOSBIOSVersion
}

$record | Format-List

$record | Export-Csv -Path $CsvPath -NoTypeInformation -Append
Write-Host "[+] Appended to $CsvPath" -ForegroundColor Green

if ($bitlocker -notmatch '^On') {
    Write-Host "[!] BitLocker is not protecting C:. Lost or stolen devices would expose data." -ForegroundColor Yellow
}
if ($record.Disk_C_Free_GB -lt 10) {
    Write-Host "[!] Less than 10 GB free on C:." -ForegroundColor Yellow
}
