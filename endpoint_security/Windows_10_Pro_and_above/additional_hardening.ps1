# Block unsigned code and drivers in the kernel
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v Enabled /t REG_DWORD /d 1 /f

# Vulnerable driver blocklist
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CI\Config" /v VulnerableDriverBlocklistEnable /t REG_DWORD /d 1 /f

# Windows PowerShell 5.1 logging
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f

# PowerShell 7 (pwsh) logging
reg add "HKLM\SOFTWARE\Policies\Microsoft\PowerShellCore\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f

# Larger log so it does not roll over within hours (100 MB)
wevtutil sl "Microsoft-Windows-PowerShell/Operational" /ms:104857600

