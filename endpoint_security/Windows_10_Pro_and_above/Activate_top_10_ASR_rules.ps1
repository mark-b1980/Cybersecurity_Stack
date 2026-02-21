$ASRNames = @{
    "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" = "Block Adore Reader from creating child processes"
    "d4f940ab-401b-4efc-aadc-ad5f3c50688a" = "Block all Office apps from creating child processes"
    "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b" = "Block Win32 API calls from Office macros"
    "3b576869-a4ec-4529-8536-b80a7769e899" = "Block Office applications from creating executable content"
    "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84" = "Block Office applications from injecting code into other processes"
    "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" = "Block credential stealing from the Windows local security authority subsystem (lsass.exe)"
    "d3e037e1-3eb8-44c8-a917-57927947596d" = "Block JavaScript or VBScript from launching downloaded executable content"
    "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550" = "Block executable content from email client and webmail"
    "26190899-1602-49e8-8b27-eb1d0a1ce869" = "Block Office communication application from creating child processes"
    "c1db55ab-c21a-4637-bb3f-a12568109d35" = "Use advanced protection against ransomware"
}

# Ask for mode
do {
    $ModeInput = Read-Host "Enter mode - 1 for Enforce (BLOCK), 2 for Audit only"
} while ($ModeInput -notin '1','2')

if ($ModeInput -eq '1') {
    $Mode = "AuditMode"
} else {
    $Mode = "Enabled"
}

# Activate the rules
foreach ($RuleId in $ASRNames.Keys) {
    Add-MpPreference -AttackSurfaceReductionRules_Ids $RuleId -AttackSurfaceReductionRules_Actions $Mode
}

# Check status of the rules
$(for ($i = 0; $i -lt $Preference.AttackSurfaceReductionRules_Ids.Count; $i++) {
    $Id = $Preference.AttackSurfaceReductionRules_Ids[$i]
    [PSCustomObject]@{
        RuleName = if ($ASRNames[$Id]) { $ASRNames[$Id] } else { "Unknown Rule" }
        Action   = switch($Preference.AttackSurfaceReductionRules_Actions[$i]) {
            1 { "BLOCK" }
            2 { "AUDIT" }
            0 { "DISABLED" }
            default { $_ }
        }
        RuleId   = $Id
    }
}) | Format-Table -AutoSize
