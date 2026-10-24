# 💻 endpoint-admin-toolkit

PowerShell scripts that come from real **help desk and device deployment** work: inventorying devices during a hardware refresh, checking a freshly imaged machine before it goes to a user, troubleshooting "the Wi-Fi isn't working," and tracking down why an account keeps locking out.

Each script also has a **security angle**, because endpoint support and security operations overlap: asset inventory, baseline hardening, and lockout investigation are where many incidents are first noticed.

> Written for **Windows PowerShell 5.1** (built into Windows 10/11), so nothing extra to install. Linted and smoke-tested on a Windows runner by GitHub Actions on every push.

---

## 🧰 Scripts

| Script | Use case | Security tie-in |
|---|---|---|
| [`Get-DeviceInventory.ps1`](Get-DeviceInventory.ps1) | Records serial, model, OS build, CPU/RAM/disk, IP/MAC, domain, **BitLocker** and **TPM** status, and appends to a CSV, so a whole rollout lives in one spreadsheet | Asset inventory is **CIS Control #1**. You can't protect devices you don't know about |
| [`Test-EndpointSecurity.ps1`](Test-EndpointSecurity.ps1) | Read-only **PASS/WARN/FAIL** baseline: Defender (real-time, signatures, tamper protection), firewall profiles, BitLocker, patch age, pending reboot, local admins, Guest/RID-500, UAC, **SMBv1**, RDP/NLA, PowerShell logging, Security log size | Catches weakened defenses before handoff, or during an incident |
| [`Invoke-NetworkTroubleshooter.ps1`](Invoke-NetworkTroubleshooter.ps1) | Walks the stack bottom-up (adapter → IP/**APIPA** → gateway → DNS → internet/HTTPS → Wi-Fi signal) and **stops at the first broken layer** with a plain-English fix | Rules out the network fast so real problems (e.g. DNS hijack, proxy) stand out |
| [`Get-AccountLockoutInfo.ps1`](Get-AccountLockoutInfo.ps1) | AD or local account status plus **4740 lockout** and **4625 failed logon** events, grouped by **source computer/IP** | Separates "old password on a phone" from **password spraying**, and flags public-IP sources to escalate |

---

## 🚀 Usage

```powershell
git clone https://github.com/kamronw23/endpoint-admin-toolkit.git
cd endpoint-admin-toolkit
Set-ExecutionPolicy -Scope Process Bypass      # allow scripts for this window only

.\Get-DeviceInventory.ps1 -CsvPath .\inventory.csv -AssetTag LAPTOP-0142
.\Test-EndpointSecurity.ps1 -ReportPath .\baseline.csv     # run elevated for full results
.\Invoke-NetworkTroubleshooter.ps1 -TestHost portal.company.com
.\Get-AccountLockoutInfo.ps1 -UserName jsmith -Server DC01 -Hours 48
```

### Example: endpoint baseline (abridged)
```
== Antivirus (Microsoft Defender) ==
  [PASS] Defender antivirus enabled
  [PASS] Real-time protection on
  [WARN] Signatures 6 day(s) old
         fix: Update-MpSignature
== Disk Encryption ==
  [FAIL] BitLocker is NOT protecting C: (FullyDecrypted)
         fix: Enable BitLocker and escrow the recovery key (AD/Entra ID)
== Network Attack Surface ==
  [PASS] SMBv1 disabled
  [WARN] RDP enabled (with NLA)
== Summary ==  PASS 13   WARN 3   FAIL 1   ->  baseline score 76%
```

### Example: network troubleshooter (abridged)
```
[2. IP configuration]
  FAIL APIPA address 169.254.31.7: the device could NOT get an address from DHCP
  >>   Run 'ipconfig /renew'. If it persists, check the switch port/VLAN or Wi-Fi authentication, and whether the DHCP scope is full
Result: 3 problem(s) found. Fix the FIRST failure above; the later ones are often caused by it.
```

---

## 🧠 What This Reflects
- **Deployment at scale:** imaging and refreshing many devices means tracking serials, builds, and encryption status consistently. Scripts beat clipboards.
- **Troubleshoot in layers:** most "network is down" tickets are one broken layer; find it first.
- **Help desk is the front line of security:** a lockout ticket can be the first sign of a password-spraying attack, so knowing when to escalate matters as much as knowing how to unlock.

## 🗺️ Roadmap
- [ ] `Get-DeviceInventory` remote mode (`-ComputerName` list via WinRM)
- [ ] Software inventory with known-vulnerable version flags
- [ ] Intune/Entra ID device compliance export

---

Part of my [cybersecurity portfolio](https://github.com/kamronw23/Portfolio) · See also: [security-scripts](https://github.com/kamronw23/security-scripts) · [soc-playbooks](https://github.com/kamronw23/soc-playbooks)
