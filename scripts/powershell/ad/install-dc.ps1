Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Host "===============================" -ForegroundColor Green
Write-Host "Lab DC Installation Script" -ForegroundColor Green
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
    "AD.DC.hostname"
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
Write-Section "DC installation initialization"

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

Write-Section "System configuration"

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

Write-Host "[+] DC installation complete."
