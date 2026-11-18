#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'

$dir = "$env:ProgramData\Sysmon"
$cfg = "$dir\config.xml"

New-Item -ItemType Directory $dir -Force | Out-Null
Invoke-WebRequest 'https://raw.githubusercontent.com/mark-b1980/Cybersecurity_Stack/refs/heads/main/endpoint_security/Sysmon/Windows/config.xml' -OutFile $cfg -UseBasicParsing

dism /online /enable-feature /featurename:Sysmon /norestart | Out-Null   # built-in Sysmon (Win11 24H2+, Server 2025)
if ($LASTEXITCODE -eq 3010) { Write-Warning 'Reboot required - run this script again afterwards'; exit 3010 }
if ($LASTEXITCODE -eq 0) { 
    sysmon -accepteula -i $cfg 
} else {                                                                   # older Windows: Sysinternals
    Invoke-WebRequest 'https://download.sysinternals.com/files/Sysmon.zip' -OutFile "$dir\Sysmon.zip" -UseBasicParsing
    Expand-Archive "$dir\Sysmon.zip" "$dir\bin" -Force
    & "$dir\bin\Sysmon64.exe" -accepteula -i $cfg
}

wevtutil sl Microsoft-Windows-Sysmon/Operational /ms:1073741824   # 1 GB event log