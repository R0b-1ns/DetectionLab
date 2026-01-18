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
    "AD.OU.Workstations",
    "AD.OU.Users",
    "AD.GPO.Users.Name",
    "AD.GPO.Users.GpoBackup",
    "AD.GPO.Workstations.Name",
    "AD.GPO.Workstations.GpoBackup"
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

$OUWorkstationsName = $AdConfig.OU.Workstations
$OUUsersName = $AdConfig.OU.Users

$GPOUserName = $AdConfig.GPO.Users.Name
$GPOUserBackup = $AdConfig.GPO.Users.GpoBackup

$GPOWorkstationName = $AdConfig.GPO.Workstations.Name
$GPOWorkstationBackup = $AdConfig.GPO.Workstations.GpoBackup

$gpmcFeature = Get-WindowsFeature -Name GPMC
if (-not $gpmcFeature.Installed) {
  Install-WindowsFeature GPMC | Out-Null
}

Import-Module ActiveDirectory -ErrorAction Stop
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

Write-Section "Wazuh agent installation"
$wazuhScript = Join-Path $scriptRoot "..\\wazuh-agents\\install-wazuh-agent.ps1"
if (-not (Test-Path $wazuhScript)) {
  Fail "Wazuh agent install script not found: $wazuhScript"
}
& $wazuhScript -MachineType "ad"

Write-Section "Starting Wazuh agent"
& net start Wazuh
