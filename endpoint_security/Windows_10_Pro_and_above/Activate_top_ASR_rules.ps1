#Requires -RunAsAdministrator
# Microsoft Defender Attack Surface Reduction (ASR) baseline
# Value: @(Name, AuditOnly) - AuditOnly = known compatibility risk, stays in Audit even in Enforce mode
$ASRRules = [ordered]@{
    # --- Standard protection (Microsoft: safe to block everywhere)
    '56a863a9-875e-4185-98a7-b882c64b5ce5' = @('Block abuse of exploited vulnerable signed drivers', $false)
    '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' = @('Block credential stealing from LSASS', $false)
    'e6db77e5-3df2-4cf1-b95a-636979351e5b' = @('Block persistence through WMI event subscription', $false)
    # --- Office / PDF / mail
    'd4f940ab-401b-4efc-aadc-ad5f3c50688a' = @('Block all Office apps from creating child processes', $false)
    '3b576869-a4ec-4529-8536-b80a7769e899' = @('Block Office apps from creating executable content', $false)
    '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84' = @('Block Office apps from injecting code into other processes', $false)
    '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b' = @('Block Win32 API calls from Office macros', $false)
    '26190899-1602-49e8-8b27-eb1d0a1ce869' = @('Block Office communication app from creating child processes', $false)
    '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c' = @('Block Adobe Reader from creating child processes', $false)
    'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550' = @('Block executable content from email client and webmail', $false)
    # --- Scripts / ransomware / system
    'd3e037e1-3eb8-44c8-a917-57927947596d' = @('Block JavaScript or VBScript from launching downloaded executables', $false)
    '5beb7efe-fd9a-4556-801d-275e5ffc04cc' = @('Block execution of potentially obfuscated scripts', $false)
    'c1db55ab-c21a-4637-bb3f-a12568109d35' = @('Use advanced protection against ransomware', $false)
    '33ddedf1-c6e0-47cb-833e-de6133960387' = @('Block rebooting machine in Safe Mode', $false)
    'a8f5898e-1dc8-49a9-9878-85004b8a61e6' = @('Block webshell creation for servers', $false)
    # --- Compatibility risk: Audit first, switch to Block per customer after review
    'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4' = @('Block untrusted and unsigned processes that run from USB', $true)
    'c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb' = @('Block use of copied or impersonated system tools', $true)
    'd1e49aac-8f56-4280-b9ba-993a6d77406c' = @('Block process creations from PSExec and WMI commands', $true)   # breaks ConfigMgr / some RMM tools
    '01443614-cd74-433a-b99e-2ecdc07bfc25' = @('Block executables unless prevalence, age or trusted list', $true)  # needs cloud protection
}

# ASR only works when Defender is the active antivirus
if ((Get-MpComputerStatus).AMRunningMode -ne 'Normal') { Write-Warning 'Defender is not the active AV (passive/third-party) - ASR rules will not be enforced.' }

do { $ModeInput = Read-Host 'Mode: 1 = Enforce (BLOCK, risky rules AUDIT), 2 = Audit only, 3 = Disable all' } while ($ModeInput -notin '1', '2', '3')

$Actions = foreach ($Id in $ASRRules.Keys) {
    switch ($ModeInput) {
        '1' { if ($ASRRules[$Id][1]) { 'AuditMode' } else { 'Enabled' } }
        '2' { 'AuditMode' }
        '3' { 'Disabled' }
    }
}
Add-MpPreference -AttackSurfaceReductionRules_Ids @($ASRRules.Keys) -AttackSurfaceReductionRules_Actions @($Actions)

# Show current state
$Pref = Get-MpPreference
$(for ($i = 0; $i -lt $Pref.AttackSurfaceReductionRules_Ids.Count; $i++) {
    $Id = $Pref.AttackSurfaceReductionRules_Ids[$i]
    [PSCustomObject]@{
        RuleName = if ($ASRRules.Contains($Id)) { $ASRRules[$Id][0] } else { 'Unknown rule' }
        Action   = switch ([int]$Pref.AttackSurfaceReductionRules_Actions[$i]) { 0 { 'DISABLED' } 1 { 'BLOCK' } 2 { 'AUDIT' } 6 { 'WARN' } default { $_ } }
        RuleId   = $Id
    }
}) | Sort-Object Action, RuleName | Format-Table -AutoSize

Write-Host 'Events: Microsoft-Windows-Windows Defender/Operational - ID 1121 = blocked, 1122 = audited'
