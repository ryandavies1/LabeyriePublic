# Define the path for the Hardening folder in ProgramData
$HardeningFolderPath = Join-Path -Path $env:ProgramData -ChildPath "Hardening"

# Create the Hardening folder if it doesn't exist
if (-not (Test-Path -Path $HardeningFolderPath -PathType Container)) {
    New-Item -Path $HardeningFolderPath -ItemType Directory
    Write-Host "Hardening folder created at $HardeningFolderPath"
} else {
    Write-Host "Hardening folder already exists at $HardeningFolderPath"
}

# Start a transcript and save the log in the Hardening folder
$LogFilePath = Join-Path -Path $HardeningFolderPath -ChildPath "Hardening.log"
Start-Transcript -Path $LogFilePath -Append

Write-Host "Transcript started. PowerShell commands and output will be logged in $LogFilePath"

#Hardening Config#
function hardening {

    # Define settings as hashtables
$settings = @(
    @{
        Path = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access'
        Name = 'Enabled'
        Value = 1
        Type = 'DWord'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        Name = 'RunAsPPL'
        Value = 1
        Type = 'DWord'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI'
        Name = 'EnumerateAdministrators'
        Value = 0
        Type = 'DWord'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'
        Name = 'DisableNotifications'
        Value = 1
        Type = 'DWord'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
        Name = 'DisableNotifications'
        Value = 1
        Type = 'DWord'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
        Name = 'DisableNotifications'
        Value = 1
        Type = 'DWord'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
        Name = 'AllowLocalIPsecPolicyMerge'
        Value = 0
        Type = 'DWord'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections'
        Name = 'NC_AllowNetBridge_NLA'
        Value = 0
        Type = 'DWord'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections'
        Name = 'NC_StdDomainUserSetLocation'
        Value = 1
        Type = 'DWord'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer'
        Name = 'NoAutoplayfornonVolume'
        Value = 1
        Type = 'DWord'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
        Name = 'NoDriveTypeAutoRun'
        Value = 255
        Type = 'DWord'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
        Name = 'NoAutorun'
        Value = 1
        Type = 'DWord'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        Name = 'LmCompatibilityLevel'
        Value = 5
        Type = 'DWord'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'
        Name = 'AllowBasic'
        Value = 0
        Type = 'DWord'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'
        Name = 'AllowBasic'
        Value = 0
        Type = 'DWord'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Download'
        Name = 'RunInvalidSignatures'
        Value = 0
        Type = 'DWord'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters'
        Name = 'DisableIPSourceRouting'
        Value = 2
        Type = 'DWord'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
        Name = 'DisableIPSourceRouting'
        Value = 2
        Type = 'DWord'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Ext'
        Name = 'VersionCheckEnabled'
        Value = 1
        Type = 'DWord'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
        Name = 'fAllowToGetHelp'
        Value = 0
        Type = 'DWord'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
        Name = 'UserAuthentication'
        Value = 1
        Type = 'DWord'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        Name = 'RestrictAnonymous'
        Value = 1
        Type = 'DWord'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
        Name = 'RequireSecuritySignature'
        Value = 1
        Type = 'DWord'
    },
    @{
        Path = 'HKLM:\Software\Policies\Microsoft\Windows Defender'
        Name = 'PUAProtection'
        Value = 1
        Type = 'DWord'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'
        Name = 'EnableVirtualizationBasedSecurity'
        Value = 1
        Type = 'DWord'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'
        Name = 'RequirePlatformSecurityFeatures'
        Value = 3
        Type = 'DWord'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'
        Name = 'LsaCfgFlags'
        Value = 2
        Type = 'DWord'
    },
    @{
        Path = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR'
        Name = 'ExploitGuard_ASR_Rules'
        Value = 1
        Type = 'DWord'
    },
    @{
        Path = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
        Name = 'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550'
        Value = 1
        Type = 'String'
    },
    @{
        Path = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
        Name = 'd4f940ab-401b-4efc-aadc-ad5f3c50688a'
        Value = 1
        Type = 'String'
    },
    @{
        Path = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
        Name = '3b576869-a4ec-4529-8536-b80a7769e899'
        Value = 1
        Type = 'String'
    },
    @{
        Path = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
        Name = '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84'
        Value = 1
        Type = 'String'
    },
    @{
        Path = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
        Name = 'd3e037e1-3eb8-44c8-a917-57927947596d'
        Value = 1
        Type = 'String'
    },
    @{
        Path = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
        Name = '5beb7efe-fd9a-4556-801d-275e5ffc04cc'
        Value = 1
        Type = 'String'
    },
    @{
        Path = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
        Name = '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b'
        Value = 1
        Type = 'String'
    },
    @{
        Path = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
        Name = '01443614-cd74-433a-b99e-2ecdc07bfc25'
        Value = 1
        Type = 'String'
    },
    @{
        Path = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
        Name = 'c1db55ab-c21a-4637-bb3f-a12568109d35'
        Value = 1
        Type = 'String'
    },
    @{
        Path = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
        Name = '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2'
        Value = 1
        Type = 'String'
    },
    @{
        Path = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
        Name = 'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4'
        Value = 1
        Type = 'String'
    },
    @{
        Path = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
        Name = '26190899-1602-49e8-8b27-eb1d0a1ce869'
        Value = 1
        Type = 'String'
    },
    @{
        Path = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
        Name = '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c'
        Value = 1
        Type = 'String'
    },
    @{
        Path = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
        Name = 'e6db77e5-3df2-4cf1-b95a-636979351e5b'
        Value = 1
        Type = 'String'
    },
    @{
        Path = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
        Name = '56a863a9-875e-4185-98a7-b882c64b5ce5'
        Value = 1
        Type = 'String'
    },
    @{
        Path = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
        Name = 'd1e49aac-8f56-4280-b9ba-993a6d77406c'
        Value = 1
        Type = 'String'
    },
    @{
        Path = 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell'
        Name = 'ExecutionPolicy'
        Value = 'AllSigned'
        Type = 'String'
    }
)

# Apply the settings
foreach ($setting in $settings) {

# Check if the registry path exists, and if not, create it
    if (!(Test-Path -Path $setting.Path)) {
        New-Item -Path $setting.Path -Force
    }


 # Set the registry property
    New-ItemProperty -LiteralPath $setting.Path -Name $setting.Name -Value $setting.Value -PropertyType $setting.Type -Force -ErrorAction SilentlyContinue -Verbose


}


}

#Defender Settings
function defender {

# Define settings as hashtables
$settings = @(
    @{
        Path = 'HKLM:\Software\Policies\Microsoft\Windows Defender'
        Name = 'ServiceKeepAlive'
        Value = 1
        Type = 'DWord'
    },
    @{
        Path = 'HKLM:\Software\Policies\Microsoft\Windows Defender'
        Name = 'DisableLocalAdminMerge'
        Value = 1
        Type = 'DWord'
    },
    @{
        Path = 'HKLM:\Software\Policies\Microsoft\Windows Defender'
        Name = 'DisableAntiSpyware'
        Value = 0
        Type = 'DWord'
    },
    @{
        Path = 'HKLM:\Software\Policies\Microsoft\Windows Defender\UX Configuration'
        Name = 'UILockdown'
        Value = 0
        Type = 'DWord'
    },
    @{
        Path = 'HKLM:\Software\Policies\Microsoft\Windows Defender\UX Configuration'
        Name = 'Notification_Suppress'
        Value = 0
        Type = 'DWord'
    },
    @{
        Path = 'HKLM:\Software\Policies\Microsoft\Windows Defender\UX Configuration'
        Name = 'SuppressRebootNotification'
        Value = 0
        Type = 'DWord'
    },
    @{
        Path = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions'
        Name = 'DisableAutoExclusions'
        Value = 0
        Type = 'DWord'
    },
    @{
        Path = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet'
        Name = 'LocalSettingOverrideSpynetReporting'
        Value = 0
        Type = 'DWord'
    },
    @{
        Path = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet'
        Name = 'DisableBlockAtFirstSeen'
        Value = 0
        Type = 'DWord'
    },
    @{
        Path = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet'
        Name = 'SpynetReporting'
        Value = 2
        Type = 'DWord'
    },
    @{
        Path = 'HKLM:\Software\Policies\Microsoft\Microsoft Antimalware\SpyNet'
        Name = 'SubmitSamplesConsent'
        Value = 3
        Type = 'DWord'
    },
    @{
        Path = 'HKLM:\Software\Policies\Microsoft\Windows Defender\MpEngine'
        Name = 'MpBafsExtendedTimeout'
        Value = 50
        Type = 'DWord'
    },
    @{
        Path = 'HKLM:\Software\Policies\Microsoft\Windows Defender\MpEngine'
        Name = 'MpCloudBlockLevel'
        Value = 2
        Type = 'DWord'
    },
    @{
        Path = 'HKLM:\Software\Policies\Microsoft\Microsoft Antimalware\Quarantine'
        Name = 'LocalSettingOverridePurgeItemsAfterDelay'
        Value = 0
        Type = 'DWord'
    },
    @{
        Path = 'HKLM:\Software\Policies\Microsoft\Microsoft Antimalware\Remediation'
        Name = 'LocalSettingOverrideScan_ScheduleTime'
        Value = 0
        Type = 'DWord'
    },
    @{
        Path = 'HKLM:\Software\Policies\Microsoft\Microsoft Antimalware\Scan'
        Name = 'CheckForSignaturesBeforeRunningScan'
        Value = 1
        Type = 'DWord'
    },
    @{
        Path = 'HKLM:\Software\Policies\Microsoft\Microsoft Antimalware\Scan'
        Name = 'LocalSettingOverrideAvgCPULoadFactor'
        Value = 0
        Type = 'DWord'
    },
    @{
        Path = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Scan'
        Name = 'LocalSettingOverrideScheduleDay'
        Value = 0
        Type = 'DWord'
    },
    @{
        Path = 'HKLM:\Software\Policies\Microsoft\Microsoft Antimalware\Scan'
        Name = 'LocalSettingOverrideScheduleQuickScanTime'
        Value = 0
        Type = 'DWord'
    },
    @{
        Path = 'HKLM:\Software\Policies\Microsoft\Microsoft Antimalware\Scan'
        Name = 'LocalSettingOverrideScheduleTime'
        Value = 0
        Type = 'DWord'
    },
    @{
        Path = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Scan'
        Name = 'LocalSettingOverrideScheduleDay'
        Value = 0
        Type = 'DWord'
    },
    @{
        Path = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Scan'
        Name = 'LowCpuPriority'
        Value = 1
        Type = 'DWord'
    },
    @{
        Path = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Scan'
        Name = 'DisableRemovableDriveScanning'
        Value = 0
        Type = 'DWord'
    },
    @{
        Path = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Scan'
        Name = 'ScheduleDay'
        Value = 0
        Type = 'DWord'
    },
    @{
        Path = 'HKLM:\Software\Policies\Microsoft\Microsoft Antimalware\Scan'
        Name = 'AvgCPULoadFactor'
        Value = 25
        Type = 'DWord'
    },
    @{
        Path = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Scan'
        Name = 'ScanParameters'
        Value = 1
        Type = 'DWord'
    },
    @{
        Path = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Scan'
        Name = 'DisableEmailScanning'
        Value = 0
        Type = 'DWord'
    },
    @{
        Path = 'HKLM:\Software\Policies\Microsoft\Microsoft Antimalware\Signature Updates'
        Name = 'SignatureUpdateInterval'
        Value = 8
        Type = 'DWord'
    },
    @{
        Path = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection'
        Name = 'EnableNetworkProtection'
        Value = 1
        Type = 'DWord'
    },
    @{
        Path = 'HKLM:\Software\Policies\Microsoft\Windows\System'
        Name = 'EnableSmartScreen'
        Value = 1
        Type = 'DWord'
    },
    @{
        Path = 'HKLM:\Software\Policies\Microsoft\Windows\System'
        Name = 'ShellSmartScreenLevel'
        Value = 0
        Type = 'String'
    }
)

# Apply the settings
foreach ($setting in $settings) {
    # Check if the registry path exists, and if not, create it
    if (!(Test-Path -Path $setting.Path)) {
        New-Item -Path $setting.Path -Force
    }

    # Set the registry property
    New-ItemProperty -LiteralPath $setting.Path -Name $setting.Name -Value $setting.Value -PropertyType $setting.Type -Force -ErrorAction SilentlyContinue -Verbose
}


}

#Defender real time protection#
function scanning {

# Define settings as hashtables
$settings = @(
    @{
        Path = 'HKLM:\Software\Policies\Microsoft\Microsoft Antimalware\Real-Time Protection'
        Name = 'LocalSettingOverrideDisableOnAccessProtection'
        Value = 0
        Type = 'DWord'
    },
    @{
        Path = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection'
        Name = 'LocalSettingOverrideDisableIOAVProtection'
        Value = 0
        Type = 'DWord'
    },
    @{
        Path = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection'
        Name = 'LocalSettingOverrideDisableBehaviorMonitoring'
        Value = 0
        Type = 'DWord'
    },
    @{
        Path = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection'
        Name = 'LocalSettingOverrideDisableRealtimeMonitoring'
        Value = 0
        Type = 'DWord'
    },
    @{
        Path = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection'
        Name = 'RealtimeScanDirection'
        Value = 0
        Type = 'DWord'
    },
    @{
        Path = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection'
        Name = 'DisableOnAccessProtection'
        Value = 0
        Type = 'DWord'
    },
    @{
        Path = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection'
        Name = 'DisableIOAVProtection'
        Value = 0
        Type = 'DWord'
    },
    @{
        Path = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection'
        Name = 'DisableRealtimeMonitoring'
        Value = 0
        Type = 'DWord'
    },
    @{
        Path = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection'
        Name = 'DisableBehaviorMonitoring'
        Value = 0
        Type = 'DWord'
    }
)

# Apply the settings
foreach ($setting in $settings) {
    # Check if the registry path exists, and if not, create it
    if (!(Test-Path -Path $setting.Path)) {
        New-Item -Path $setting.Path -Force
    }

    # Set the registry property
    New-ItemProperty -LiteralPath $setting.Path -Name $setting.Name -Value $setting.Value -PropertyType $setting.Type -Force -ErrorAction SilentlyContinue -Verbose
}


}

#windows update settings#
function windowsupdates {

# Define Windows Update settings as hashtables
$windowsUpdateSettings = @(
    @{
        Path = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
        Name = 'AllowAutoWindowsUpdateDownloadOverMeteredNetwork'
        Value = 1
        Type = 'DWord'
    },
    @{
        Path = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
        Name = 'NoAutoUpdate'
        Value = 0
        Type = 'DWord'
    },
    @{
        Path = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
        Name = 'AUOptions'
        Value = 3
        Type = 'DWord'
    },
    @{
        Path = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
        Name = 'AllowMUUpdateService'
        Value = 1
        Type = 'DWord'
    }
)

# Apply the Windows Update settings
foreach ($setting in $windowsUpdateSettings) {
    # Check if the registry path exists, and if not, create it
    if (!(Test-Path -Path $setting.Path)) {
        New-Item -Path $setting.Path -Force
    }

    # Set the registry property
    New-ItemProperty -LiteralPath $setting.Path -Name $setting.Name -Value $setting.Value -PropertyType $setting.Type -Force -ErrorAction SilentlyContinue -Verbose
}


}

 do {
   do {

    Clear-Host
    write-host ""
    write-host "****************************"
    write-host "**       Main Menu        **"
    write-host "****************************"
    write-host ""
    write-host "********************************"
    write-host "**Checkpoint The Server First!**"
    write-host "********************************"
    write-host ""
    write-host "1 - Apply Defender Settings"
    write-host "2 - Apply Defender Scanning"
    write-host "3 - Apply Hardening"
    write-host "4 - Apply Windows Updates"
    write-host "5 - Apply All (Recommended)"
    Write-Host ""
    Write-Host ""
    write-host "6 - Exit"
    write-host ""
    $answer = read-host "Select number(s)"

    $ok = $answer -match '[123456]+$'
    if ( -not $ok) {write-host "Invalid selection"
                    Start-Sleep 2
                    write-host ""
                    }
    } until ($ok)

    

    switch -Regex ( $answer ) {
        "1" {
        defender
        pause
        }
        "2" {
        scanning
        pause
        }
        "3" {
        hardening
        pause
        }
        "4" {
        windowsupdates
        pause
        }
        "5" {
        defender
        scanning
        hardening
        windowsupdates
        pause
        }

    }

   } until ( $answer -match "6" )

# Stop the transcript and close the log
Stop-Transcript
Write-Host "Transcript stopped. Log saved in $LogFilePath"
