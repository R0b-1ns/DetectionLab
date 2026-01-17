Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Host "===============================" -ForegroundColor Green
Write-Host "Lab DC/AD Configuration Script" -ForegroundColor Green
Write-Host "===============================" -ForegroundColor Green

function Write-Section {
  param([Parameter(Mandatory)][string]$Message)
  Write-Host "[+] $Message" -ForegroundColor Cyan
}

function Fail {
  param([Parameter(Mandatory)][string]$Message)
  Write-Host "[-] $Message" -ForegroundColor Red
  throw $Message
}

function Assert-Admin {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($identity)
  if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Fail "This script must be run as Administrator."
  }
}

function Ensure-Directory {
  param([Parameter(Mandatory)][string]$Path)
  if (-not (Test-Path $Path)) {
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
  }
}

function Ensure-OU {
  param(
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][string]$DomainDn
  )
  $ouDn = "OU=$Name,$DomainDn"
  try {
    Get-ADOrganizationalUnit -Identity $ouDn -ErrorAction Stop | Out-Null
  } catch {
    New-ADOrganizationalUnit -Name $Name -Path $DomainDn | Out-Null
  }
  return $ouDn
}

function Ensure-GPO {
  param([Parameter(Mandatory)][string]$Name)
  $gpo = Get-GPO -Name $Name -ErrorAction SilentlyContinue
  if (-not $gpo) {
    $gpo = New-GPO -Name $Name
  }
  return $gpo
}

function Ensure-GpoLink {
  param(
    [Parameter(Mandatory)][string]$GpoName,
    [Parameter(Mandatory)][string]$TargetDn
  )
  $inheritance = Get-GPInheritance -Target $TargetDn
  if (-not ($inheritance.GpoLinks | Where-Object { $_.DisplayName -eq $GpoName })) {
    New-GPLink -Name $GpoName -Target $TargetDn -LinkEnabled Yes | Out-Null
  }
}

function Get-LabConfig {
  param([Parameter(Mandatory)][string]$Path)

  if (-not (Test-Path $Path)) {
    Fail "Config file not found: $Path"
  }

  try {
    $cfg = Get-Content -Raw -Path $Path | ConvertFrom-Json
  } catch {
    Fail "Unable to read config.json: $($_.Exception.Message)"
  }

  $requiredPaths = @(
    "AD.Domain.DnsName",
    "AD.Domain.NetBiosName",
    "AD.Domain.SafeModeAdminPasswordPrompt",
    "AD.DC.InterfaceAlias",
    "AD.DC.IpAddress",
    "AD.DC.PrefixLength",
    "AD.DC.Gateway",
    "AD.DC.hostname",
    "AD.Path.SysvolScripts",
    "AD.OU.Workstations",
    "AD.OU.Users",
    "AD.GPO.Users.Name",
    "AD.GPO.Users.GpoBackup",
    "AD.GPO.Workstations.Name",
    "AD.GPO.Workstations.GpoBackup",
    "AD.GPO.Workstations.BootstrapScript"
  )

  foreach ($item in $requiredPaths) {
    $parts = $item.Split(".")
    $current = $cfg
    foreach ($part in $parts) {
      if (-not $current.$part) {
        Fail "Missing config value: $item"
      }
      $current = $current.$part
    }
  }

  return $cfg
}

Assert-Admin
Write-Section "AD lab configuration initialization"

Write-Section "Reading config.json"
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$configPath = Join-Path (Resolve-Path (Join-Path $scriptRoot "..\..\..\config")) "config.json"
$Config = Get-LabConfig -Path $configPath
$AdConfig = $Config.AD

$DomainName = $AdConfig.Domain.DnsName
$Netbios = $AdConfig.Domain.NetBiosName

$promptDsrm = [bool]$AdConfig.Domain.SafeModeAdminPasswordPrompt
if (-not $promptDsrm) {
  Fail "SafeModeAdminPasswordPrompt must be true to continue."
}
$DsrmPassword = Read-Host "Enter DSRM password" -AsSecureString

$InterfaceAlias = $AdConfig.DC.InterfaceAlias
$IPAddress = $AdConfig.DC.IpAddress
$PrefixLength = $AdConfig.DC.PrefixLength
$Gateway = $AdConfig.DC.Gateway
$Hostname = $AdConfig.DC.hostname

$SysvolScripts = $AdConfig.Path.SysvolScripts

$OUWorkstationsName = $AdConfig.OU.Workstations
$OUUsersName = $AdConfig.OU.Users

$GPOUserName = $AdConfig.GPO.Users.Name
$GPOUserBackup = $AdConfig.GPO.Users.GpoBackup

$GPOWorkstationName = $AdConfig.GPO.Workstations.Name
$GPOWorkstationBackup = $AdConfig.GPO.Workstations.GpoBackup
$GPOWorkstationBootstrapScript = $AdConfig.GPO.Workstations.BootstrapScript

Write-Section "Domain Controller configuration"

if ($Hostname -and ($env:COMPUTERNAME -ne $Hostname)) {
  Write-Host "[!] Renaming computer to $Hostname (reboot required)" -ForegroundColor Yellow
  Rename-Computer -NewName $Hostname -Force
  Write-Host "[!] Reboot and re-run the script to continue." -ForegroundColor Yellow
  exit 0
}

Write-Host "Removing DHCP configuration" -ForegroundColor DarkGray
$dhcpIps = Get-NetIPAddress -InterfaceAlias $InterfaceAlias -AddressFamily IPv4 -ErrorAction Stop |
  Where-Object { $_.PrefixOrigin -eq "Dhcp" }
if ($dhcpIps) {
  $dhcpIps | Remove-NetIPAddress -Confirm:$false
}

$existingIp = Get-NetIPAddress -InterfaceAlias $InterfaceAlias -AddressFamily IPv4 -ErrorAction Stop |
  Where-Object { $_.IPAddress -eq $IPAddress }
$otherStaticIps = Get-NetIPAddress -InterfaceAlias $InterfaceAlias -AddressFamily IPv4 -ErrorAction Stop |
  Where-Object { $_.IPAddress -ne $IPAddress -and $_.PrefixOrigin -ne "Dhcp" }
if ($otherStaticIps) {
  Write-Host "[!] Other static IPv4 addresses exist on $InterfaceAlias; leaving them unchanged." -ForegroundColor Yellow
}

if (-not $existingIp) {
  Write-Host "Setting static IP" -ForegroundColor DarkGray
  New-NetIPAddress `
    -InterfaceAlias $InterfaceAlias `
    -IPAddress $IPAddress `
    -PrefixLength $PrefixLength `
    -DefaultGateway $Gateway
}

Write-Host "Setting DNS" -ForegroundColor DarkGray
$currentDns = (Get-DnsClientServerAddress -InterfaceAlias $InterfaceAlias -AddressFamily IPv4).ServerAddresses
if (-not ($currentDns -contains $IPAddress)) {
  Set-DnsClientServerAddress `
    -InterfaceAlias $InterfaceAlias `
    -ServerAddresses $IPAddress
}

Write-Section "Active Directory installation"

$adFeature = Get-WindowsFeature -Name AD-Domain-Services
if (-not $adFeature.Installed) {
  Install-WindowsFeature AD-Domain-Services -IncludeManagementTools | Out-Null
}

$dnsFeature = Get-WindowsFeature -Name DNS
if (-not $dnsFeature.Installed) {
  Install-WindowsFeature DNS -IncludeManagementTools | Out-Null
}

$domainPresent = $false
try {
  Import-Module ActiveDirectory -ErrorAction Stop
  Get-ADDomain -ErrorAction Stop | Out-Null
  $domainPresent = $true
} catch {
  $domainPresent = $false
}

if (-not $domainPresent) {
  Write-Host "[!] Installing new forest $DomainName (this will reboot)" -ForegroundColor Yellow
  Install-ADDSForest `
    -DomainName $DomainName `
    -DomainNetbiosName $Netbios `
    -InstallDns `
    -SafeModeAdministratorPassword $DsrmPassword `
    -Force
  exit 0
}

$gpmcFeature = Get-WindowsFeature -Name GPMC
if (-not $gpmcFeature.Installed) {
  Install-WindowsFeature GPMC | Out-Null
}

Import-Module GroupPolicy -ErrorAction Stop

Write-Section "Organizational Units configuration"
$currentDomain = Get-ADDomain
if ($currentDomain.DNSRoot -ne $DomainName) {
  Fail "Existing domain DNSRoot ($($currentDomain.DNSRoot)) does not match config ($DomainName)."
}
if ($currentDomain.NetBIOSName -ne $Netbios) {
  Fail "Existing domain NetBIOSName ($($currentDomain.NetBIOSName)) does not match config ($Netbios)."
}
$DomainDN = $currentDomain.DistinguishedName
$UsersOuDn = Ensure-OU -Name $OUUsersName -DomainDn $DomainDN
$WorkstationsOuDn = Ensure-OU -Name $OUWorkstationsName -DomainDn $DomainDN

Write-Section "Group Policy configuration"
Ensure-Directory -Path $GPOUserBackup
Ensure-Directory -Path $GPOWorkstationBackup

Ensure-GPO -Name $GPOUserName | Out-Null
Ensure-GPO -Name $GPOWorkstationName | Out-Null

Backup-GPO -Name $GPOUserName -Path $GPOUserBackup | Out-Null
Backup-GPO -Name $GPOWorkstationName -Path $GPOWorkstationBackup | Out-Null

Ensure-GpoLink -GpoName $GPOUserName -TargetDn $UsersOuDn
Ensure-GpoLink -GpoName $GPOWorkstationName -TargetDn $WorkstationsOuDn

Write-Host "Creating user policies" -ForegroundColor DarkGray

Set-GPRegistryValue -Name $GPOUserName `
  -Key "HKCU\Software\Policies\Microsoft\Windows\Control Panel\Desktop" `
  -ValueName "ScreenSaveTimeOut" -Type String -Value "600"

Set-GPRegistryValue -Name $GPOUserName `
  -Key "HKCU\Software\Policies\Microsoft\Windows\Control Panel\Desktop" `
  -ValueName "ScreenSaveActive" -Type String -Value "1"

Set-GPRegistryValue -Name $GPOUserName `
  -Key "HKCU\Software\Policies\Microsoft\Windows\Control Panel\Desktop" `
  -ValueName "ScreenSaverIsSecure" -Type String -Value "1"

Set-GPRegistryValue -Name $GPOUserName `
  -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
  -ValueName "NoControlPanel" -Type DWord -Value 1

Set-GPRegistryValue -Name $GPOUserName `
  -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
  -ValueName "DisableRegistryTools" -Type DWord -Value 1

Set-GPRegistryValue -Name $GPOUserName `
  -Key "HKCU\Software\Policies\Microsoft\Windows\System" `
  -ValueName "DisableCMD" -Type DWord -Value 2

Set-GPRegistryValue -Name $GPOUserName `
  -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" `
  -ValueName "HideFileExt" -Type DWord -Value 0

Set-GPRegistryValue -Name $GPOUserName `
  -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
  -ValueName "Wallpaper" -Type String -Value "C:\Backups\GPO\Users\wallpaper.jpg"

Set-GPRegistryValue -Name $GPOUserName `
  -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
  -ValueName "WallpaperStyle" -Type String -Value "2"

Set-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain).DNSRoot `
  -MinPasswordLength 12 `
  -ComplexityEnabled $true `
  -LockoutThreshold 5 `
  -LockoutDuration (New-TimeSpan -Minutes 15) `
  -LockoutObservationWindow (New-TimeSpan -Minutes 15)

Write-Host "Creating workstation policies" -ForegroundColor DarkGray

Set-GPRegistryValue -Name $GPOWorkstationName `
  -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
  -ValueName "ProcessCreationIncludeCmdLine_Enabled" `
  -Type DWord -Value 1

Set-GPRegistryValue -Name $GPOWorkstationName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
  -ValueName "EnableScriptBlockLogging" -Type DWord -Value 1

Set-GPRegistryValue -Name $GPOWorkstationName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" `
  -ValueName "EnableModuleLogging" -Type DWord -Value 1

Set-GPRegistryValue -Name $GPOWorkstationName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" `
  -ValueName "*" -Type String -Value "*"

Set-GPRegistryValue -Name $GPOWorkstationName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell" `
  -ValueName "ExecutionPolicy" -Type String -Value "RemoteSigned"

Set-GPRegistryValue -Name $GPOWorkstationName `
  -Key "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" `
  -ValueName "UseLogonCredential" -Type DWord -Value 0

Set-GPRegistryValue -Name $GPOWorkstationName `
  -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" `
  -ValueName "SCENoApplyLegacyAuditPolicy" -Type DWord -Value 1

Set-GPRegistryValue -Name $GPOWorkstationName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" `
  -ValueName "EnableFirewall" -Type DWord -Value 1

Set-GPRegistryValue -Name $GPOWorkstationName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" `
  -ValueName "LogDroppedPackets" -Type DWord -Value 1

Set-GPRegistryValue -Name $GPOWorkstationName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" `
  -ValueName "DisableAntiSpyware" -Type DWord -Value 0

Set-GPRegistryValue -Name $GPOWorkstationName `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" `
  -ValueName "DisableRealtimeMonitoring" -Type DWord -Value 0

Set-GPRegistryValue -Name $GPOWorkstationName `
  -Key "HKLM\Software\Policies\Microsoft\Windows\PowerShell" `
  -ValueName "EnableScripts" `
  -Type DWord `
  -Value 1

Ensure-Directory -Path (Split-Path -Parent $GPOWorkstationBootstrapScript)
if (-not (Test-Path $GPOWorkstationBootstrapScript)) {
  Fail "Bootstrap script not found: $GPOWorkstationBootstrapScript"
}

$BootstrapScriptName = Split-Path -Leaf $GPOWorkstationBootstrapScript
$BootstrapScriptSysvolPath = Join-Path $SysvolScripts $BootstrapScriptName

Ensure-Directory -Path $SysvolScripts
Copy-Item -Path $GPOWorkstationBootstrapScript -Destination $BootstrapScriptSysvolPath -Force

$runOnceCommand = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$BootstrapScriptSysvolPath`""
Set-GPRegistryValue `
  -Name $GPOWorkstationName `
  -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce" `
  -ValueName "DL-Bootstrap" `
  -Type String `
  -Value $runOnceCommand
