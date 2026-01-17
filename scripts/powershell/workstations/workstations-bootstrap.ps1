# ===============================
# Workstations Bootstrap 
# ===============================

$BaselineName    = "Workstations-Baseline"
$BaselineVersion = "1.0"

$MarkerPath = "HKLM:\Software\LabBaseline\$BaselineName"

try {
  $current = Get-ItemProperty -Path $MarkerPath -Name "Version" -ErrorAction Stop
  if ($current.Version -eq $BaselineVersion) {
    Write-Host "[=] Baseline already applied (Version $BaselineVersion). Exiting."
    return
  }
} catch {
}

$LogFile = "C:\Windows\Temp\workstations-bootstrap.log"
Start-Transcript -Path $LogFile -Append

Write-Host "[+] Applying baseline $BaselineName v$BaselineVersion"

# --- Advanced Audit Policies
auditpol /set /subcategory:"Process Creation" /success:enable /failure:disable
auditpol /set /subcategory:"Logon"            /success:enable /failure:enable
auditpol /set /subcategory:"Special Logon"    /success:enable /failure:disable
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Computer Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable

$domainRole = (Get-CimInstance Win32_ComputerSystem).DomainRole
if ($domainRole -in 4, 5) {
  auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable
}

# --- 4688 include command line
$AuditRegPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
New-Item -Path $AuditRegPath -Force | Out-Null
New-ItemProperty -Path $AuditRegPath `
  -Name "ProcessCreationIncludeCmdLine_Enabled" `
  -PropertyType DWord -Value 1 -Force | Out-Null

# --- PowerShell logging (SOC)
$PSLogPath = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell"
New-Item -Path $PSLogPath -Force | Out-Null

New-ItemProperty -Path $PSLogPath `
  -Name "EnableScriptBlockLogging" `
  -PropertyType DWord -Value 1 -Force | Out-Null

New-ItemProperty -Path $PSLogPath `
  -Name "EnableModuleLogging" `
  -PropertyType DWord -Value 1 -Force | Out-Null

$TranscriptionPath = "$PSLogPath\Transcription"
New-Item -Path $TranscriptionPath -Force | Out-Null
New-ItemProperty -Path $TranscriptionPath `
  -Name "EnableTranscripting" `
  -PropertyType DWord -Value 1 -Force | Out-Null
New-ItemProperty -Path $TranscriptionPath `
  -Name "OutputDirectory" `
  -PropertyType String -Value "C:\ProgramData\PSLogs" -Force | Out-Null

New-Item -Path $MarkerPath -Force | Out-Null
New-ItemProperty -Path $MarkerPath -Name "Version" -Value $BaselineVersion -Force | Out-Null
New-ItemProperty -Path $MarkerPath -Name "AppliedAt" -Value (Get-Date).ToString("s") -Force | Out-Null

Write-Host "[+] Baseline applied successfully."
Stop-Transcript
