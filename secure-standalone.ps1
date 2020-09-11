######SCRIPT FOR FULL INSTALL AND CONFIGURE ON STANDALONE MACHINE#####
#Continue on error
$ErrorActionPreference= 'silentlycontinue'

#Require elivation for script run
#Requires -RunAsAdministrator
Write-Output "Elevating priviledges for this process"
do {} until (Elevate-Privileges SeTakeOwnershipPrivilege)

#Unblock all files required for script
Get-ChildItem *.ps*1 -recurse | Unblock-File

#Windows 10 Defenter Exploit Guard Configuration File
start-job -ScriptBlock {mkdir "C:\temp\Windows Defender"; copy-item -Path .\Files\"Windows Defender Configuration Files"\DOD_EP_V3.xml -Destination "C:\temp\Windows Defender\" -Force -Recurse -ErrorAction SilentlyContinue} 

#Optional Scripts 
#.\Files\Optional\sos-ssl-hardening.ps1
# powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61

#Security Scripts
start-job -ScriptBlock {takeown /f C:\WINDOWS\Policydefinitions /r /a; icacls C:\WINDOWS\PolicyDefinitions /grant Administrators:(OI)(CI)F /t; copy-item -Path .\Files\PolicyDefinitions\* -Destination C:\Windows\PolicyDefinitions -Force -Recurse -ErrorAction SilentlyContinue}

#Disable TCP Timestamps
netsh int tcp set global timestamps=disabled

#Disable Powershell v2
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root

#Enable DEP
BCDEDIT /set "{current}" nx OptOut

#Basic authentication for RSS feeds over HTTP must not be used.
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" -Name AllowBasicAuthInClear -Type DWORD -Value 1 -Force
#InPrivate browsing in Microsoft Edge must be disabled.
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Name AllowInPrivate -Type DWORD -Value 0 -Force
#Windows 10 must be configured to prevent Microsoft Edge browser data from being cleared on exit.
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Privacy" -Name ClearBrowsingHistoryOnExit -Type DWORD -Value 0 -Force

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

#####SPECTURE MELTDOWN#####
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name FeatureSettingsOverride -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name FeatureSettingsOverrideMask -Type DWORD -Value 3 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name FeatureSettingsOverride -Type DWORD -Value 8 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name FeatureSettingsOverrideMask -Type DWORD -Value 3 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name FeatureSettingsOverride -Type DWORD -Value 72 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name FeatureSettingsOverrideMask -Type DWORD -Value 3 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name FeatureSettingsOverride -Type DWORD -Value 8264 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name FeatureSettingsOverrideMask -Type DWORD -Value 3 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization" -Name MinVmVersionForCpuBasedMitigations -Type String -Value "1.0" -Force

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

#Continue on error
$ErrorActionPreference= 'silentlycontinue'

#Require elivation for script run
#Requires -RunAsAdministrator
Write-Output "Elevating priviledges for this process"
do {} until (Elevate-Privileges SeTakeOwnershipPrivilege)

If (Test-Path -Path "HKLM:\Software\Microsoft\StrongName\Verification"){
    Remove-Item "HKLM:\Software\Microsoft\StrongName\Verification" -Recurse -Force
    Write-Host ".Net StrongName Verification Registry Removed"
}

# .Net 32-Bit
If (Test-Path -Path C:\Windows\Microsoft.NET\Framework\v2.0.50727){
    Write-Host ".Net 32-Bit v2.0.50727 Is Installed"
    C:\Windows\Microsoft.NET\Framework\v2.0.50727\caspol.exe -q -f -pp on 
    C:\Windows\Microsoft.NET\Framework\v2.0.50727\caspol.exe -m -lg
    If (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\AllowStrongNameBypass"){
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -PropertyType "DWORD" -Value "0"
    }Else {
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -PropertyType "DWORD" -Value "0"
    }
    If (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727\SchUseStrongCrypto"){
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727\" -Name "SchUseStrongCrypto" -PropertyType "DWORD" -Value "1"
    }Else {
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727\" -Name "SchUseStrongCrypto" -PropertyType "DWORD" -Value "1"
    }
}Else {
    Write-Host ".Net 32-Bit v2.0.50727 Is Not Installed"
}
If (Test-Path -Path C:\Windows\Microsoft.NET\Framework\v3.0){
    Write-Host ".Net 32-Bit v3.0 Is Installed"
    C:\Windows\Microsoft.NET\Framework\v3.0\caspol.exe -q -f -pp on 
    C:\Windows\Microsoft.NET\Framework\v3.0\caspol.exe -m -lg
    If (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\AllowStrongNameBypass"){
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -PropertyType "DWORD" -Value "0"
    }Else {
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -PropertyType "DWORD" -Value "0"
    }
    If (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v3.0\SchUseStrongCrypto"){
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v3.0\" -Name "SchUseStrongCrypto" -PropertyType "DWORD" -Value "1"
    }Else {
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v3.0\" -Name "SchUseStrongCrypto" -PropertyType "DWORD" -Value "1"
    }
}Else {
    Write-Host ".Net 32-Bit v3.0 Is Not Installed"
}
If (Test-Path -Path C:\Windows\Microsoft.NET\Framework\v3.5){
    Write-Host ".Net 32-Bit v3.5 Is Installed"
    C:\Windows\Microsoft.NET\Framework\v3.5\caspol.exe -q -f -pp on 
    C:\Windows\Microsoft.NET\Framework\v3.5\caspol.exe -m -lg
    If (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\AllowStrongNameBypass"){
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -PropertyType "DWORD" -Value "0"
    }Else {
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -PropertyType "DWORD" -Value "0"
    }
    If (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v3.5\SchUseStrongCrypto"){
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v3.5\" -Name "SchUseStrongCrypto" -PropertyType "DWORD" -Value "1"
    }Else {
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v3.5\" -Name "SchUseStrongCrypto" -PropertyType "DWORD" -Value "1"
    }
}Else {
    Write-Host ".Net 32-Bit v3.5 Is Not Installed"
}
If (Test-Path -Path C:\Windows\Microsoft.NET\Framework\v4.0.30319){
    Write-Host ".Net 32-Bit v4.0.30319 Is Installed"
    C:\Windows\Microsoft.NET\Framework\v4.0.30319\caspol.exe -q -f -pp on 
    C:\Windows\Microsoft.NET\Framework\v4.0.30319\caspol.exe -m -lg
    If (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\AllowStrongNameBypass"){
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -PropertyType "DWORD" -Value "0"
    }Else {
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -PropertyType "DWORD" -Value "0"
    }
    If (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319\SchUseStrongCrypto"){
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319\" -Name "SchUseStrongCrypto" -PropertyType "DWORD" -Value "1"
    }Else {
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319\" -Name "SchUseStrongCrypto" -PropertyType "DWORD" -Value "1"
    }
    #Copy-Item -Path .\Files\machine.config -Destination C:\Windows\Microsoft.NET\Framework\v4.0.30319\Config -Force 
}Else {
    Write-Host ".Net 32-Bit v4.0.30319 Is Not Installed"
}

# .Net 64-Bit
If (Test-Path -Path C:\Windows\Microsoft.NET\Framework64\v2.0.50727){
    Write-Host ".Net 64-Bit v2.0.50727 Is Installed"
    C:\Windows\Microsoft.NET\Framework64\v2.0.50727\caspol.exe -q -f -pp on 
    C:\Windows\Microsoft.NET\Framework64\v2.0.50727\caspol.exe -m -lg
    If (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\AllowStrongNameBypass") {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -PropertyType "DWORD" -Value "0"
    }Else {
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -PropertyType "DWORD" -Value "0"
    }
    If (Test-Path -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727\") {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727\" -Name "SchUseStrongCrypto" -PropertyType "DWORD" -Value "1"
    }Else {
        New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727\" -Name "SchUseStrongCrypto" -PropertyType "DWORD" -Value "1"
    }
}Else {
    Write-Host ".Net 64-Bit v2.0.50727 Is Not Installed"
}
If (Test-Path -Path C:\Windows\Microsoft.NET\Framework64\v3.0){
    Write-Host ".Net 64-Bit v3.0 Is Installed"
    C:\Windows\Microsoft.NET\Framework64\v3.0\caspol.exe -q -f -pp on 
    C:\Windows\Microsoft.NET\Framework64\v3.0\caspol.exe -m -lg
    If (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\AllowStrongNameBypass") {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -PropertyType "DWORD" -Value "0"
    }Else {
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -PropertyType "DWORD" -Value "0"
    }
    If (Test-Path -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v3.0\") {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v3.0\" -Name "SchUseStrongCrypto" -PropertyType "DWORD" -Value "1"
    }Else {
        New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v3.0\" -Name "SchUseStrongCrypto" -PropertyType "DWORD" -Value "1"
    }
}Else {
    Write-Host ".Net 64-Bit v3.0 Is Not Installed"
}
If (Test-Path -Path C:\Windows\Microsoft.NET\Framework64\v3.5){
    Write-Host ".Net 64-Bit v3.5 Is Installed"
    C:\Windows\Microsoft.NET\Framework64\v3.5\caspol.exe -q -f -pp on 
    C:\Windows\Microsoft.NET\Framework64\v3.5\caspol.exe -m -lg
    If (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\AllowStrongNameBypass") {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -PropertyType "DWORD" -Value "0"
    }Else {
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -PropertyType "DWORD" -Value "0"
    }
    If (Test-Path -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v3.5\") {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v3.5\" -Name "SchUseStrongCrypto" -PropertyType "DWORD" -Value "1"
    }Else {
        New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v3.5\" -Name "SchUseStrongCrypto" -PropertyType "DWORD" -Value "1"
    }
}Else {
    Write-Host ".Net 64-Bit v3.5 Is Not Installed"
}
If (Test-Path -Path C:\Windows\Microsoft.NET\Framework64\v4.0.30319){
    Write-Host ".Net 64-Bit v4.0.30319 Is Installed"
    C:\Windows\Microsoft.NET\Framework64\v4.0.30319\caspol.exe -q -f -pp on 
    C:\Windows\Microsoft.NET\Framework64\v4.0.30319\caspol.exe -m -lg
    If (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\AllowStrongNameBypass") {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -PropertyType "DWORD" -Value "0"
    }Else {
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -PropertyType "DWORD" -Value "0"
    }
    If (Test-Path -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319\") {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319\" -Name "SchUseStrongCrypto" -PropertyType "DWORD" -Value "1"
    }Else {
        New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319\" -Name "SchUseStrongCrypto" -PropertyType "DWORD" -Value "1"
    }
    #Copy-Item -Path .\Files\machine.config -Destination C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config -Force 
}Else {
    Write-Host ".Net 64-Bit v4.0.30319 Is Not Installed"
}

FINDSTR /i /s "NetFx40_LegacySecurityPolicy" c:\*.exe.config 

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
Switch ($Answer)
{
    "Yes"   { Write-Warning "Restarting Computer in 15 Seconds"; Start-sleep -seconds 15; Restart-Computer -Force }
    "No"    { Write-Warning "A reboot is required for all changed to take effect" }
    Default { Write-Warning "A reboot is required for all changed to take effect" }
}
