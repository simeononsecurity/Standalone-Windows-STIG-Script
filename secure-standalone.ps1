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

#Work In Progress
.\Files\Optional\sos-.net-4-stig.ps1

#Security Scripts
start-job -ScriptBlock {takeown /f C:\WINDOWS\Policydefinitions /r /a; icacls C:\WINDOWS\PolicyDefinitions /grant Administrators:(OI)(CI)F /t; copy-item -Path .\Files\PolicyDefinitions\* -Destination C:\Windows\PolicyDefinitions -Force -Recurse -ErrorAction SilentlyContinue}

#Disable TCP Timestamps
netsh int tcp set global timestamps=disabled

#Disable Powershell v2
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root

#Enable DEP
BCDEDIT /set {"current"} nx OptOut

#Basic authentication for RSS feeds over HTTP must not be used.
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" -Name AllowBasicAuthInClear -Type DWORD -Value 1 -Force
#InPrivate browsing in Microsoft Edge must be disabled.
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Name AllowInPrivate -Type DWORD -Value 0 -Force
#Windows 10 must be configured to prevent Microsoft Edge browser data from being cleared on exit.
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Privacy" -Name ClearBrowsingHistoryOnExit -Type DWORD -Value 0 -Force



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

#GPO Configurations
.\Files\LGPO\LGPO.exe /g .\Files\GPOs\

Add-Type -AssemblyName PresentationFramework
$Answer = [System.Windows.MessageBox]::Show("Reboot to make changes effective?", "Restart Computer", "YesNo", "Question")
Switch ($Answer)
{
    "Yes"   { Write-Warning "Restarting Computer in 15 Seconds"; Start-sleep -seconds 15; Restart-Computer -Force }
    "No"    { Write-Warning "A reboot is required for all changed to take effect" }
    Default { Write-Warning "A reboot is required for all changed to take effect" }
}
