######SCRIPT FOR FULL INSTALL AND CONFIGURE ON STANDALONE MACHINE#####
#Continue on error
$ErrorActionPreference= 'silentlycontinue'

#Require elivation for script run
#Requires -RunAsAdministrator

#Unblock all files required for script
Get-ChildItem *.ps*1 -recurse | Unblock-File

#Remove and Refresh Local Policies
Remove-Item -Recurse -Force "$env:WinDir\System32\GroupPolicy" | Out-Null
Remove-Item -Recurse -Force "$env:WinDir\System32\GroupPolicyUsers" | Out-Null
secedit /configure /cfg "$env:WinDir\inf\defltbase.inf" /db defltbase.sdb /verbose | Out-Null

Start-Job -Name "Mitigations" -ScriptBlock {
    #####SPECTURE MELTDOWN#####
    #https://support.microsoft.com/en-us/help/4073119/protect-against-speculative-execution-side-channel-vulnerabilities-in
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name FeatureSettingsOverride -Type "DWORD" -Value 72 -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name FeatureSettingsOverrideMask -Type "DWORD" -Value 3 -Force
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Virtualization" -Name MinVmVersionForCpuBasedMitigations -Type "String" -Value "1.0" -Force

    #Disable LLMNR
    #https://www.blackhillsinfosec.com/how-to-disable-llmnr-why-you-want-to/
    New-Item -Path "HKLM:\Software\policies\Microsoft\Windows NT\" -Name "DNSClient" -Force
    Set-ItemProperty -Path "HKLM:\Software\policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Type "DWORD" -Value 0 -Force

    #Disable TCP Timestamps
    netsh int tcp set global timestamps=disabled

    #Enable DEP
    BCDEDIT /set "{current}" nx OptOut
    Set-Processmitigation -System -Enable DEP
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoDataExecutionPrevention" -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableHHDEP" -Type "DWORD" -Value 0 -Force

    #Enable SEHOP
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "DisableExceptionChainValidation" -Type "DWORD" -Value 0 -Force

    #Disable NetBIOS by updating Registry
    #http://blog.dbsnet.fr/disable-netbios-with-powershell#:~:text=Disabling%20NetBIOS%20over%20TCP%2FIP,connection%2C%20then%20set%20NetbiosOptions%20%3D%202
    $key = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"
    Get-ChildItem $key | ForEach-Object { 
        Write-Host("Modify $key\$($_.pschildname)")
        $NetbiosOptions_Value = (Get-ItemProperty "$key\$($_.pschildname)").NetbiosOptions
        Write-Host("NetbiosOptions updated value is $NetbiosOptions_Value")
    }
    
    #Disable WPAD
    #https://adsecurity.org/?p=3299
    New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\" -Name "Wpad" -Force
    New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" -Name "Wpad" -Force
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" -Name "WpadOverride" -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" -Name "WpadOverride" -Type "DWORD" -Value 1 -Force

    #Enable LSA Protection/Auditing
    #https://adsecurity.org/?p=3299
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\" -Name "LSASS.exe" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" -Name "AuditLevel" -Type "DWORD" -Value 8 -Force

    #Disable Windows Script Host
    #https://adsecurity.org/?p=3299
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\" -Name "Settings" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -Type "DWORD" -Value 0 -Force
    
    #Disable WDigest
    #https://adsecurity.org/?p=3299
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\Wdigest" -Name "UseLogonCredential" -Type "DWORD" -Value 0 -Force

    #Block Untrusted Fonts
    #https://adsecurity.org/?p=3299
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" -Name "MitigationOptions" -Type "QWORD" -Value "1000000000000" -Force
    
    #Disable Office OLE
    #https://adsecurity.org/?p=3299
    $officeversions = '16.0', '15.0', '14.0', '12.0'
    ForEach ($officeversion in $officeversions) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Office\$officeversion\Outlook\" -Name "Security" -Force
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\$officeversion\Outlook\" -Name "Security" -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Office\$officeversion\Outlook\Security\" -Name "ShowOLEPackageObj" -Type "DWORD" -Value "0" -Force
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\$officeversion\Outlook\Security\" -Name "ShowOLEPackageObj" -Type "DWORD" -Value "0" -Force
    }

    #Disable Hibernate
    powercfg -h off
}

Start-Job -Name "STIG Addendum" -ScriptBlock {
#Basic authentication for RSS feeds over HTTP must not be used.
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" -Name AllowBasicAuthInClear -Type DWORD -Value 0 -Force
#InPrivate browsing in Microsoft Edge must be disabled.
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Name AllowInPrivate -Type DWORD -Value 0 -Force
#Windows 10 must be configured to prevent Microsoft Edge browser data from being cleared on exit.
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Privacy" -Name ClearBrowsingHistoryOnExit -Type DWORD -Value 0 -Force
}

Start-Job -Name "Adobe Reader DC STIG" -ScriptBlock {
#Adobe Reader DC STIG
New-Item -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\" -Name cCloud
New-Item -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\" -Name cDefaultLaunchURLPerms
New-Item -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\" -Name cServices
New-Item -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\" -Name cSharePoint
New-Item -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\" -Name cWebmailProfiles
New-Item -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\" -Name cWelcomeScreen
Set-ItemProperty -Path "HKLM:\Software\Adobe\Acrobat Reader\DC\Installer" -Name DisableMaintenance -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name bAcroSuppressUpsell -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name bDisablePDFHandlerSwitching -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name bDisableTrustedFolders -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name bDisableTrustedSites -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name bEnableFlash -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name bEnhancedSecurityInBrowser -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name bEnhancedSecurityStandalone -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name bProtectedMode -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name iFileAttachmentPerms -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name iProtectedView -Type DWORD -Value 2 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cCloud" -Name bAdobeSendPluginToggle -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cDefaultLaunchURLPerms" -Name iURLPerms -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cDefaultLaunchURLPerms" -Name iUnknownURLPerms -Type DWORD -Value 3 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices" -Name bToggleAdobeDocumentServices -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices" -Name bToggleAdobeSign -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices" -Name bTogglePrefsSync -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices" -Name bToggleWebConnectors -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices" -Name bUpdater -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cSharePoint" -Name bDisableSharePointFeatures -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cWebmailProfiles" -Name bDisableWebmail -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cWelcomeScreen" -Name bShowWelcomeScreen -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Software\Wow6432Node\Adobe\Acrobat Reader\DC\Installer" -Name DisableMaintenance -Type DWORD -Value 1 -Force
}

Start-Job -Name "VM and VDI Optimizations" -ScriptBlock {
#VM Performance Improvements
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name VisualFXSetting -Type DWORD -Value 2
# Apply appearance customizations to default user registry hive, then close hive file
& REG LOAD HKLM\DEFAULT C:\Users\Default\NTUSER.DAT
New-ItemProperty -Path "HKLM:\Default\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name IconsOnly -Type DWORD -Value 1 -Force
New-ItemProperty -Path "HKLM:\Default\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name ListviewAlphaSelect -Type DWORD -Value 0 -Force
New-ItemProperty -Path "HKLM:\Default\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name ListviewShadow -Type DWORD -Value 0 -Force
New-ItemProperty -Path "HKLM:\Default\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name ShowCompColor -Type DWORD -Value 1 -Force
New-ItemProperty -Path "HKLM:\Default\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name ShowInfoTip -Type DWORD -Value 1 -Force
New-ItemProperty -Path "HKLM:\Default\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name TaskbarAnimations -Type DWORD -Value 0 -Force
New-ItemProperty -Path "HKLM:\Default\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name VisualFXSetting -Type DWORD -Value 3 -Force
New-ItemProperty -Path "HKLM:\Default\Software\Microsoft\Windows\DWM" -Name EnableAeroPeek -Type DWORD -Value 0 -Force
New-ItemProperty -Path "HKLM:\Default\Software\Microsoft\Windows\DWM" -Name AlwaysHiberNateThumbnails -Type DWORD -Value 0 -Force
New-ItemProperty -Path "HKLM:\Default\Control Panel\Desktop" -Name DragFullWindows -Type STRING -Value 0 -Force
New-ItemProperty -Path "HKLM:\Default\Control Panel\Desktop" -Name FontSmoothing -Type STRING -Value 2 -Force
New-ItemProperty -Path "HKLM:\Default\Control Panel\Desktop\WindowMetrics" -Name MinAnimate -Type STRING -Value 0 -Force
New-ItemProperty -Path "HKLM:\Default\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Name 01 -Type DWORD -Value 0 -Force
New-ItemProperty -Path "HKLM:\Default\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name SubscribedContent-338393Enabled -Type DWORD -Value 0 -Force
New-ItemProperty -Path "HKLM:\Default\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name SubscribedContent-353694Enabled -Type DWORD -Value 0 -Force
New-ItemProperty -Path "HKLM:\Default\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name SubscribedContent-353696Enabled -Type DWORD -Value 0 -Force
New-ItemProperty -Path "HKLM:\Default\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name SubscribedContent-338388Enabled -Type DWORD -Value 0 -Force
New-ItemProperty -Path "HKLM:\Default\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name SubscribedContent-338389Enabled -Type DWORD -Value 0 -Force
New-ItemProperty -Path "HKLM:\Default\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name SystemPaneSuggestionsEnabled -Type DWORD -Value 0 -Force
New-ItemProperty -Path "HKLM:\Default\Control Panel\International\User Profile" -Name HttpAcceptLanguageOptOut -Type DWORD -Value 1 -Force
New-ItemProperty -Path "HKLM:\Default\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.Windows.Photos_8wekyb3d8bbwe" -Name Disabled -Type DWORD -Value 1 -Force
New-ItemProperty -Path "HKLM:\Default\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.Windows.Photos_8wekyb3d8bbwe" -Name DisabledByUser -Type DWORD -Value 1 -Force
New-ItemProperty -Path "HKLM:\Default\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.SkypeApp_kzf8qxf38zg5c" -Name Disabled -Type DWORD -Value 1 -Force
New-ItemProperty -Path "HKLM:\Default\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.SkypeApp_kzf8qxf38zg5c" -Name DisabledByUser -Type DWORD -Value 1 -Force
New-ItemProperty -Path "HKLM:\Default\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.YourPhone_8wekyb3d8bbwe" -Name Disabled -Type DWORD -Value 1 -Force
New-ItemProperty -Path "HKLM:\Default\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.YourPhone_8wekyb3d8bbwe" -Name DisabledByUser -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Default\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name IconsOnly -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Default\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name ListviewAlphaSelect -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Default\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name ListviewShadow -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Default\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name ShowCompColor -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Default\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name ShowInfoTip -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Default\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name TaskbarAnimations -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Default\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name VisualFXSetting -Type DWORD -Value 3 -Force
Set-ItemProperty -Path "HKLM:\Default\Software\Microsoft\Windows\DWM" -Name EnableAeroPeek -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Default\Software\Microsoft\Windows\DWM" -Name AlwaysHiberNateThumbnails -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Default\Control Panel\Desktop" -Name DragFullWindows -Type STRING -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Default\Control Panel\Desktop" -Name FontSmoothing -Type STRING -Value 2 -Force
Set-ItemProperty -Path "HKLM:\Default\Control Panel\Desktop\WindowMetrics" -Name MinAnimate -Type STRING -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Default\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Name 01 -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Default\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name SubscribedContent-338393Enabled -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Default\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name SubscribedContent-353694Enabled -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Default\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name SubscribedContent-353696Enabled -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Default\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name SubscribedContent-338388Enabled -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Default\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name SubscribedContent-338389Enabled -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Default\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name SystemPaneSuggestionsEnabled -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Default\Control Panel\International\User Profile" -Name HttpAcceptLanguageOptOut -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Default\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.Windows.Photos_8wekyb3d8bbwe" -Name Disabled -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Default\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.Windows.Photos_8wekyb3d8bbwe" -Name DisabledByUser -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Default\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.SkypeApp_kzf8qxf38zg5c" -Name Disabled -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Default\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.SkypeApp_kzf8qxf38zg5c" -Name DisabledByUser -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Default\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.YourPhone_8wekyb3d8bbwe" -Name Disabled -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Default\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.YourPhone_8wekyb3d8bbwe" -Name DisabledByUser -Type DWORD -Value 1 -Force
& REG UNLOAD HKLM\DEFAULT
}


#Windows Defender Configuration Files
New-Item -Path "C:\" -Name "Temp" -ItemType "directory" -Force | Out-Null; New-Item -Path "C:\temp\" -Name "Windows Defender" -ItemType "directory" -Force | Out-Null; Copy-Item -Path .\Files\"Windows Defender Configuration Files"\* -Destination "C:\temp\Windows Defender\" -Force -Recurse -ErrorAction SilentlyContinue | Out-Null

#Enable Windows Defender Exploit Protection
Set-ProcessMitigation -PolicyFilePath "C:\temp\Windows Defender\DOD_EP_V3.xml"

#Enable Windows Defender Application Control
#https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/select-types-of-rules-to-create
Set-RuleOption -FilePath "C:\temp\Windows Defender\WDAC_V1_Recommended_Enforced.xml" -Option 0

#https://www.itsupportguides.com/knowledge-base/tech-tips-tricks/how-to-customise-firefox-installs-using-mozilla-cfg/
$firefox64 = "C:\Program Files\Mozilla Firefox"
$firefox32 = "C:\Program Files (x86)\Mozilla Firefox"
Write-Output "Installing Firefox Configurations - Please Wait."
Write-Output "Window will close after install is complete"
If (Test-Path -Path $firefox64){
    Copy-Item -Path .\Files\"FireFox Configuration Files"\defaults -Destination $firefox64 -Force -Recurse
    Copy-Item -Path .\Files\"FireFox Configuration Files"\mozilla.cfg -Destination $firefox64 -Force
    Copy-Item -Path .\Files\"FireFox Configuration Files"\local-settings.js -Destination $firefox64 -Force 
    Write-Host "Firefox 64-Bit Configurations Installed"
}Else {
    Write-Host "FireFox 64-Bit Is Not Installed"
}
If (Test-Path -Path $firefox32){
    Copy-Item -Path .\Files\"FireFox Configuration Files"\defaults -Destination $firefox32 -Force -Recurse
    Copy-Item -Path .\Files\"FireFox Configuration Files"\mozilla.cfg -Destination $firefox32 -Force
    Copy-Item -Path .\Files\"FireFox Configuration Files"\local-settings.js -Destination $firefox32 -Force 
    Write-Host "Firefox 32-Bit Configurations Installed"
}Else {
    Write-Host "FireFox 32-Bit Is Not Installed"
}

#https://gist.github.com/MyITGuy/9628895
#http://stu.cbu.edu/java/docs/technotes/guides/deploy/properties.html

#<Windows Directory>\Sun\Java\Deployment\deployment.config
#- or -
#<JRE Installation Directory>\lib\deployment.config

If (Test-Path -Path "C:\Windows\Sun\Java\Deployment\deployment.config"){
    Write-Host "Deployment Config Already Installed"
}Else {
    Write-Output "Installing Java Deployment Config...."
    Mkdir "C:\Windows\Sun\Java\Deployment\"
    Copy-Item -Path .\Files\"JAVA Configuration Files"\deployment.config -Destination "C:\Windows\Sun\Java\Deployment\" -Force
    Write-Output "JAVA Configs Installed"
}
If (Test-Path -Path "C:\temp\JAVA\"){
    Write-Host "Configs Already Deployed"
}Else {
    Write-Output "Installing Java Configurations...."
    Mkdir "C:\temp\JAVA"
    Copy-Item -Path .\Files\"JAVA Configuration Files"\deployment.properties -Destination "C:\temp\JAVA\" -Force
    Copy-Item -Path .\Files\"JAVA Configuration Files"\exception.sites -Destination "C:\temp\JAVA\" -Force
    Write-Output "JAVA Configs Installed"
}


# .Net STIG

#SimeonOnSecurity - Microsoft .Net Framework 4 STIG Script
#https://github.com/simeononsecurity
#https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_DotNet_Framework_4-0_V1R9_STIG.zip
#https://docs.microsoft.com/en-us/dotnet/framework/tools/caspol-exe-code-access-security-policy-tool

$netframework32="C:\Windows\Microsoft.NET\Framework"
$netframework64="C:\Windows\Microsoft.NET\Framework64"
$netframeworks=($netframework32,$netframework64)

# .Net 32-Bit
ForEach ($dotnet32version in (Get-ChildItem $netframework32 | ?{ $_.PSIsContainer }).Name){
    $netframework32="C:\Windows\Microsoft.NET\Framework"
    Write-Host ".Net 32-Bit $dotnet32version Is Installed"
    cmd /c $netframework32\$dotnet32version\caspol.exe -q -f -pp on 
    cmd /c $netframework32\$dotnet32version\caspol.exe -m -lg
    #Vul ID: V-30935	   	Rule ID: SV-40977r3_rule	   	STIG ID: APPNET0063
    If (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\AllowStrongNameBypass"){
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -Value "0" -Force
    }Else {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\" -Name ".NETFramework" -Force
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -PropertyType "DWORD" -Value "0" -Force
    }
    #Vul ID: V-81495	   	Rule ID: SV-96209r2_rule	   	STIG ID: APPNET0075	
    If (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\$dotnet32version\SchUseStrongCrypto"){
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\$dotnet32version\" -Name "SchUseStrongCrypto" -Value "1" -Force
    }Else {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework" -Name "$dotnet32version" -Force
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\$dotnet32version\" -Name "SchUseStrongCrypto" -PropertyType "DWORD" -Value "1" -Force
    }
}
# .Net 64-Bit
ForEach ($dotnet64version in (Get-ChildItem $netframework64 | ?{ $_.PSIsContainer }).Name){
    $netframework64="C:\Windows\Microsoft.NET\Framework64"
    Write-Host ".Net 64-Bit $dotnet64version Is Installed"
    cmd /c $netframework64\$dotnet64version\caspol.exe -q -f -pp on 
    cmd /c $netframework64\$dotnet64version\caspol.exe -m -lg
    #Vul ID: V-30935	   	Rule ID: SV-40977r3_rule	   	STIG ID: APPNET0063
    If (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\AllowStrongNameBypass") {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -Value "0" -Force
    }Else {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\" -Name ".NETFramework" -Force
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -PropertyType "DWORD" -Value "0" -Force
    }
    #Vul ID: V-81495	   	Rule ID: SV-96209r2_rule	   	STIG ID: APPNET0075	
    If (Test-Path -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\$dotnet64version\") {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\$dotnet64version\" -Name "SchUseStrongCrypto" -Value "1" -Force
    }Else {
        New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\" -Name "$dotnet64version" -Force
        New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\$dotnet64version\" -Name "SchUseStrongCrypto" -PropertyType "DWORD" -Value "1" -Force
    }
}

#Vul ID: V-30937	   	Rule ID: SV-40979r3_rule	   	STIG ID: APPNET0064	  
#FINDSTR /i /s "NetFx40_LegacySecurityPolicy" c:\*.exe.config 

#GPO Configurations
$gposdir = "$(Get-Location)\Files\GPOs"
Foreach ($gpocategory in Get-ChildItem "$(Get-Location)\Files\GPOs") {
    
    Write-Output "Importing $gpocategory GPOs"

    Foreach ($gpo in (Get-ChildItem "$(Get-Location)\Files\GPOs\$gpocategory")) {
        $gpopath = "$gposdir\$gpocategory\$gpo"
        Write-Output "Importing $gpo"
        .\Files\LGPO\LGPO.exe /g $gpopath
    }
}

Add-Type -AssemblyName PresentationFramework
$Answer = [System.Windows.MessageBox]::Show("Reboot to make changes effective?", "Restart Computer", "YesNo", "Question")
Switch ($Answer) {
    "Yes" { Write-Host "Performing Gpupdate"; Gpupdate /force /boot; Get-Job; Write-Warning "Restarting Computer in 15 Seconds"; Start-sleep -seconds 15; Restart-Computer -Force }
    "No" { Write-Host "Performing Gpupdate"; Gpupdate /force ; Get-Job; Write-Warning "A reboot is required for all changed to take effect" }
    Default { Write-Warning "A reboot is required for all changed to take effect" }
}
