
param(
    [Parameter(Mandatory = $false)]
    [bool]$cleargpos = $true,
    [Parameter(Mandatory = $false)]
    [bool]$installupdates = $true,
    [Parameter(Mandatory = $false)]
    [bool]$adobe = $true,
    [Parameter(Mandatory = $false)]
    [bool]$firefox = $true,
    [Parameter(Mandatory = $false)]
    [bool]$chrome = $true,
    [Parameter(Mandatory = $false)]
    [bool]$IE11 = $true,
    [Parameter(Mandatory = $false)]
    [bool]$edge = $true,
    [Parameter(Mandatory = $false)]
    [bool]$dotnet = $true,
    [Parameter(Mandatory = $false)]
    [bool]$office = $true,
    [Parameter(Mandatory = $false)]
    [bool]$onedrive = $true,
    [Parameter(Mandatory = $false)]
    [bool]$java = $true,
    [Parameter(Mandatory = $false)]
    [bool]$windows = $true,
    [Parameter(Mandatory = $false)]
    [bool]$defender = $true,
    [Parameter(Mandatory = $false)]
    [bool]$firewall = $true,
    [Parameter(Mandatory = $false)]
    [bool]$mitigations = $true,
    [Parameter(Mandatory = $false)]
    [bool]$nessusPID = $true,
    [Parameter(Mandatory = $false)]
    [bool]$horizon = $true,
    [Parameter(Mandatory = $false)]
    [bool]$sosoptional = $true
)

######SCRIPT FOR FULL INSTALL AND CONFIGURE ON STANDALONE MACHINE#####
#Continue on error
$ErrorActionPreference = 'silentlycontinue'

#Require elivation for script run
#Requires -RunAsAdministrator

#Set Directory to PSScriptRoot
if ((Get-Location).Path -NE $PSScriptRoot) { Set-Location $PSScriptRoot }

$paramscheck = $cleargpos, $installupdates, $adobe, $firefox, $chrome, $IE11, $edge, $dotnet, $office, $onedrive, $java, $windows, $defender, $firewall, $mitigations, $nessusPID, $sosoptional

# run a warning if no options are set to true
if ($paramscheck | Where-Object { $_ -eq $false } | Select-Object -Count -EQ $params.Count) {
    Write-Error "No Options Were Selected. Exiting..."
    Exit
}

# if any parameters are set to true take a restore point
$date = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$scriptName = $MyInvocation.MyCommand.Name
if ($paramscheck | Where-Object { $_ } | Select-Object) {
    $freespace = (Get-WmiObject -class Win32_LogicalDisk | Where-Object { $_.DeviceID -eq 'C:' }).FreeSpace
    $minfreespace = 10000000000 #10GB
    if ($freespace -gt $minfreespace) {
        Write-Host "Taking a Restore Point Before Continuing...."
        $job = Start-Job -Name Take Restore Point -ScriptBlock {
            New-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\SystemRestore' -Name 'SystemRestorePointCreationFrequency' -PropertyType DWORD -Value 0 -Force
            Checkpoint-Computer -Description "RestorePoint $scriptName $date" -RestorePointType "MODIFY_SETTINGS"
        }
        Wait-Job -Job $job
    }
    else {
        Write-Output "Not enough disk space to create a restore point. Current free space: $(($freespace/1GB)) GB"
    }
}

# Install Local Group Policy if Not Already Installed
if ($paramscheck | Where-Object { $_ } | Select-Object) {
    Start-Job -Name InstallGPOPackages -ScriptBlock {
        foreach ($F in (Get-ChildItem "$env:SystemRoot\servicing\Packages\Microsoft-Windows-GroupPolicy-ClientTools-Package~*.mum").FullName) {
            if ((dism /online /get-packages | where-object { $_.name -like "*Microsoft-Windows-GroupPolicy-ClientTools*" }).count -eq 0) {
                dism /Online /NoRestart /Add-Package:$F
            }
        }

        foreach ($F in (Get-ChildItem "$env:SystemRoot\servicing\Packages\Microsoft-Windows-GroupPolicy-ClientExtensions-Package~*.mum").FullName) {
            if ((dism /online /get-packages | where-object { $_.name -like "*Microsoft-Windows-GroupPolicy-ClientExtensions*" }).count -eq 0) {
                dism /Online /NoRestart /Add-Package:$F
            }
        }
    }
}

#GPO Configurations
function Import-GPOs([string]$gposdir) {
    Write-Host "Importing Group Policies from $gposdir ..." -ForegroundColor Green
    Foreach ($gpoitem in Get-ChildItem $gposdir) {
        Write-Host "Importing $gpoitem GPOs..." -ForegroundColor White
        $gpopath = "$gposdir\$gpoitem"
        #Write-Host "Importing $gpo" -ForegroundColor White
        .\Files\LGPO\LGPO.exe /g $gpopath > $null 2>&1
        #Write-Host "Done" -ForegroundColor Green
    }
}

if ($cleargpos -eq $true) {
    Write-Host "Removing Existing Local GPOs" -ForegroundColor Green
    #Remove and Refresh Local Policies
    Remove-Item -Recurse -Force "$env:WinDir\System32\GroupPolicy" | Out-Null
    Remove-Item -Recurse -Force "$env:WinDir\System32\GroupPolicyUsers" | Out-Null
    secedit /configure /cfg "$env:WinDir\inf\defltbase.inf" /db defltbase.sdb /verbose | Out-Null
    gpupdate /force | Out-Null
}
else {
    Write-Output "The Clear Existing GPOs Section Was Skipped..."
}

if ($installupdates -eq $true) {
    Write-Host "Installing the Latest Windows Updates" -ForegroundColor Green
    #Install PowerShell Modules
    Copy-Item -Path .\Files\"PowerShell Modules"\* -Destination C:\Windows\System32\WindowsPowerShell\v1.0\Modules -Force -Recurse
    #Unblock New PowerShell Modules
    Get-ChildItem C:\Windows\System32\WindowsPowerShell\v1.0\Modules\PSWindowsUpdate\ -recurse | Unblock-File
    #Install PSWindowsUpdate
    Import-Module -Name PSWindowsUpdate -Force -Global 

    #Install Latest Windows Updates
    Start-Job -Name "Windows Updates" -ScriptBlock {
        Install-WindowsUpdate -MicrosoftUpdate -AcceptAll; Get-WuInstall -AcceptAll -IgnoreReboot; Get-WuInstall -AcceptAll -Install -IgnoreReboot
    }
}
else {
    Write-Output "The Install Update Section Was Skipped..."
}

if ($adobe -eq $true) {
    Write-Host "Implementing the Adobe STIGs" -ForegroundColor Green
    Import-GPOs -gposdir ".\Files\GPOs\DoD\Adobe"

    Start-Job -Name "Adobe Reader DC STIG" -ScriptBlock {
        #Adobe Reader DC STIG
        New-Item -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\" -Name cCloud -Force
        New-Item -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\" -Name cDefaultLaunchURLPerms -Force
        New-Item -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\" -Name cServices -Force
        New-Item -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\" -Name cSharePoint -Force
        New-Item -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\" -Name cWebmailProfiles -Force
        New-Item -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\" -Name cWelcomeScreen -Force
        Set-ItemProperty -Path "HKLM:\Software\Adobe\Acrobat Reader\DC\Installer" -Name DisableMaintenance -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name bAcroSuppressUpsell -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name bDisablePDFHandlerSwitching -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name bDisableTrustedFolders -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name bDisableTrustedSites -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name bEnableFlash -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name bEnhancedSecurityInBrowser -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name bEnhancedSecurityStandalone -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name bProtectedMode -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name iFileAttachmentPerms -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name iProtectedView -Type "DWORD" -Value 2 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cCloud" -Name bAdobeSendPluginToggle -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cDefaultLaunchURLPerms" -Name iURLPerms -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cDefaultLaunchURLPerms" -Name iUnknownURLPerms -Type "DWORD" -Value 3 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices" -Name bToggleAdobeDocumentServices -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices" -Name bToggleAdobeSign -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices" -Name bTogglePrefsSync -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices" -Name bToggleWebConnectors -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices" -Name bUpdater -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cSharePoint" -Name bDisableSharePointFeatures -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cWebmailProfiles" -Name bDisableWebmail -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cWelcomeScreen" -Name bShowWelcomeScreen -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\Wow6432Node\Adobe\Acrobat Reader\DC\Installer" -Name DisableMaintenance -Type "DWORD" -Value 1 -Force
    }
}
else {
    Write-Output "The Adobe Section Was Skipped..."
}

if ($firefox -eq $true) {
    Write-Host "Implementing the FireFox STIGs" -ForegroundColor Green
    Import-GPOs -gposdir ".\Files\GPOs\DoD\FireFox"
    Import-GPOs -gposdir ".\Files\GPOs\SoS\FireFox"

    Write-Host "simeononsecurity/FireFox-STIG-Script" -ForegroundColor Green
    Write-Host "https://github.com/simeononsecurity/FireFox-STIG-Script" -ForegroundColor Green 

    #https://www.itsupportguides.com/knowledge-base/tech-tips-tricks/how-to-customise-firefox-installs-using-mozilla-cfg/
    $firefox64 = "C:\Program Files\Mozilla Firefox"
    $firefox32 = "C:\Program Files (x86)\Mozilla Firefox"
    Write-Host "Installing Firefox Configurations - Please Wait." -ForegroundColor White
    Write-Host "Window will close after install is complete" -ForegroundColor White
    If (Test-Path -Path $firefox64) {
        Copy-Item -Path .\Files\"FireFox Configuration Files"\defaults -Destination $firefox64 -Force -Recurse
        Copy-Item -Path .\Files\"FireFox Configuration Files"\mozilla.cfg -Destination $firefox64 -Force
        Copy-Item -Path .\Files\"FireFox Configuration Files"\local-settings.js -Destination $firefox64 -Force 
        Write-Host "Firefox 64-Bit Configurations Installed" -ForegroundColor Green
    }
    Else {
        Write-Host "FireFox 64-Bit Is Not Installed" -ForegroundColor Red
    }
    If (Test-Path -Path $firefox32) {
        Copy-Item -Path .\Files\"FireFox Configuration Files"\defaults -Destination $firefox32 -Force -Recurse
        Copy-Item -Path .\Files\"FireFox Configuration Files"\mozilla.cfg -Destination $firefox32 -Force
        Copy-Item -Path .\Files\"FireFox Configuration Files"\local-settings.js -Destination $firefox32 -Force 
        Write-Host "Firefox 32-Bit Configurations Installed" -ForegroundColor Green
    }
    Else {
        Write-Host "FireFox 32-Bit Is Not Installed" -ForegroundColor Red
    }
}
else {
    Write-Output "The FireFox Section Was Skipped..."
}

if ($chrome -eq $true) {
    Write-Host "Implementing the Google Chrome STIGs" -ForegroundColor Green
    Import-GPOs -gposdir ".\Files\GPOs\DoD\Chrome"
}
else {
    Write-Output "The Google Chrome Section Was Skipped..."
}

if ($IE11 -eq $true) {
    Write-Host "Implementing the Internet Explorer 11 STIGs" -ForegroundColor Green
    Import-GPOs -gposdir ".\Files\GPOs\DoD\IE11"
}
else {
    Write-Output "The Internet Explorer 11 Section Was Skipped..."
}

if ($edge -eq $true) {
    Write-Host "Implementing the Microsoft Edge STIGs" -ForegroundColor Green
    Import-GPOs -gposdir ".\Files\GPOs\DoD\Edge"

    #InPrivate browsing in Microsoft Edge must be disabled.
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\MicrosoftEdge\Main" -Name "AllowInPrivate" -Type "DWORD" -Value 0 -Force
    #Windows 10 must be configured to prevent Microsoft Edge browser data from being cleared on exit.
    New-Item -Path "HKLM:\Software\Policies\Microsoft\MicrosoftEdge\" -Name "Privacy" -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\MicrosoftEdge\Privacy" -Name ClearBrowsingHistoryOnExit -Type "DWORD" -Value 0 -Force
}
else {
    Write-Output "The Microsoft Edge Section Was Skipped..."
}

if ($dotnet -eq $true) {
    Write-Host "Implementing the Dot Net Framework STIGs" -ForegroundColor Green
    #SimeonOnSecurity - Microsoft .Net Framework 4 STIG Script
    #https://github.com/simeononsecurity
    #https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_DotNet_Framework_4-0_V1R9_STIG.zip
    #https://docs.microsoft.com/en-us/dotnet/framework/tools/caspol-exe-code-access-security-policy-tool

    Write-Host "Implementing simeononsecurity/.NET-STIG-Script" -ForegroundColor Green
    Write-Host "https://github.com/simeononsecurity/.NET-STIG-Script" -ForegroundColor Green 

    #Setting Netframework path variables
    $NetFramework32 = "C:\Windows\Microsoft.NET\Framework"
    $NetFramework64 = "C:\Windows\Microsoft.NET\Framework64"

    Write-Host "Beginning .NET STIG Script" -ForegroundColor Green

    #Vul ID: V-7055	   	Rule ID: SV-7438r3_rule	   	STIG ID: APPNET0031
    #Removing registry value
    If (Test-Path -Path "HKLM:\Software\Microsoft\StrongName\Verification") {
        Remove-Item "HKLM:\Software\Microsoft\StrongName\Verification" -Recurse -Force
        Write-Host ".Net StrongName Verification Registry Removed"
    } 
    Else {
        Write-Host ".Net StrongName Verification Registry Does Not Exist" -ForegroundColor Green
    }

    #Vul ID: V-7061	   	Rule ID: SV-7444r3_rule   	STIG ID: APPNET0046
    #The Trust Providers Software Publishing State must be set to 0x23C00.
    New-PSDrive HKU Registry HKEY_USERS | Out-Null
    ForEach ($UserSID in (Get-ChildItem "HKU:\")) {
        Write-Output $UserSID.Name | ConvertFrom-String -Delimiter "\\" -PropertyNames "PATH", "SID" | Set-Variable -Name "SIDs"
        ForEach ($SID in $SIDs.SID) {
            #Vul ID: V-30935	   	Rule ID: SV-40977r3_rule	   	STIG ID: APPNET0063
            If (Test-Path -Path "HKU:\$SID\Software\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing\State") {
                Set-ItemProperty -Path "HKU:\$SID\Software\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing\" -Name "State" -Value "0x23C00" -Force | Out-Null
                Write-Host "Set Trust Providers Software Publishing State to 146432/0x23C00 for SID $SID" -ForegroundColor White
            }
            Else {
                New-Item -Path "HKU:\$SID\Software\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing\" -Name "State" -Force | Out-Null
                New-ItemProperty -Path "HKU:\$SID\Software\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing\" -Name "State" -Value "0x23C00" -Force | Out-Null
                Write-Host "Set Trust Providers Software Publishing State to 146432/0x23C00 for SID $SID" -ForegroundColor White
            }
        }
    }
    [gc]::collect()


    <#
    Creating secure configuration Function. It needs to be called in the
    two foreach loops as it has to touch every config file in each
    .net framework version folder

    Function Set-SecureConfig {
        param (
            $VersionPath,
            $SecureMachineConfigPath
        )
        
        #Declaration and error prevention
        $SecureMachineConfig = $Null
        $MachineConfig = $Null
        [system.gc]::Collect() 
        
        #Getting Secure Machine.Configs
        $SecureMachineConfig = [xml](Get-Content $SecureMachineConfigPath)
            
        #Write-Host "Still using test path at $(Get-CurrentLine)"
        #$MachineConfigPath = "C:\Users\hiden\Desktop\NET-STIG-Script-master\Files\secure.machine - Copy.config"
        $MachineConfigPath = "$VersionPath"
        $MachineConfig = [xml](Get-Content $MachineConfigPath)
        #Ensureing file is closed
        [IO.File]::OpenWrite((Resolve-Path $MachineConfigPath).Path).close()

        #Apply Machine.conf Configurations
        #Pulled XML assistance from https://stackoverflow.com/questions/9944885/powershell-xml-importnode-from-different-file
        #Pulled more XML details from http://www.maxtblog.com/2012/11/add-from-one-xml-data-to-another-existing-xml-file/
    
        Write-Host "Begining work on $MachineConfigPath..." -ForegroundColor White
    
        # Do out. Automate each individual childnode for infinite nested. Currently only goes two deep
        $SecureChildNodes = $SecureMachineConfig.configuration | Get-Member | Where-Object MemberType -match "^Property" | Select-Object -ExpandProperty Name
        $MachineChildNodes = $MachineConfig.configuration | Get-Member | Where-Object MemberType -match "^Property" | Select-Object -ExpandProperty Name


        #Checking if each secure node is present in the XML file
        ForEach ($SecureChildNode in $SecureChildNodes) {
            #If it is not present, easy day. Add it in.
            If ($SecureChildNode -notin $MachineChildNodes) {
                #Adding node from the secure.machine.config file and appending it to the XML file
                $NewNode = $MachineConfig.ImportNode($SecureMachineConfig.configuration.$SecureChildNode, $true)
                $MachineConfig.DocumentElement.AppendChild($NewNode) | Out-Null
                #Saving changes to XML file
                $MachineConfig.Save($MachineConfigPath)
            }
            Elseif ($MachineConfig.configuration.$SecureChildNode -eq "") {
                #Turns out element sometimes is present but entirely empty. If that is the case we need to remove it
                # and add what we want         
                $MachineConfig.configuration.ChildNodes | Where-Object name -eq $SecureChildNode | ForEach-Object { $MachineConfig.configuration.RemoveChild($_) } | Out-Null
                $MachineConfig.Save($MachineConfigPath)
                #Adding node from the secure.machine.config file and appending it to the XML file            
                $NewNode = $MachineConfig.ImportNode($SecureMachineConfig.configuration.$SecureChildNode, $true)
                $MachineConfig.DocumentElement.AppendChild($NewNode) | Out-Null
                #Saving changes to XML file
                $MachineConfig.Save($MachineConfigPath)
            }
            Else {
                
                #If it is present... we have to check if the node contains the elements we want.
                #Going through each node in secure.machine.config for comparison
                $SecureElements = $SecureMachineConfig.configuration.$SecureChildNode | Get-Member | Where-Object MemberType -Match "^Property" | Where-object Name -notmatch "#comment" | Select-Object -Expandproperty Name        
                #Pull the Machine.config node and childnode and get the data properties for comparison
                $MachineElements = $MachineConfig.configuration.$SecureChildNode | Get-Member | Where-Object MemberType -Match "^Property" | Where-object Name -notmatch "#comment" | Select-Object -Expandproperty Name

                #I feel like there has got to be a better way to do this as we're three loops deep
                foreach ($SElement in $SecureElements) {
                    #Comparing Element pulled earlier against Machine Elements.  If it's not present we will add it in
                    If ($SElement -notin $MachineElements) {
                        #Adding in element that is not present
                        If ($SecureMachineConfig.configuration.$SecureChildNode.$SElement -NE "") {
                            $NewNode = $MachineConfig.ImportNode($SecureMachineConfig.configuration.$SecureChildNode.$SElement, $true)
                            $MachineConfig.configuration.$SecureChildNode.AppendChild($NewNode) | Out-Null
                            #Saving changes to XML file
                            $MachineConfig.Save($MachineConfigPath)
                        }
                        Else {
                            #This is for when the value declared is empty.
                            $NewNode = $MachineConfig.CreateElement("$SElement")                     
                            $MachineConfig.configuration.$SecureChildNode.AppendChild($NewNode) | Out-Null
                            #Saving changes to XML file
                            $MachineConfig.Save($MachineConfigPath)
                        }
                    }
                    Else {
                        $OldNode = $MachineConfig.SelectSingleNode("//$SElement")
                        $MachineConfig.configuration.$SecureChildNode.RemoveChild($OldNode) | Out-Null
                        $MachineConfig.Save($MachineConfigPath)
                        If ($SecureMachineConfig.configuration.$SecureChildNode.$SElement -EQ "") {
                            $NewElement = $MachineConfig.CreateElement("$SElement")
                            $MachineConfig.configuration.$SecureChildNode.AppendChild($NewElement) | Out-Null
                        }
                        Else {
                            $NewNode = $MachineConfig.ImportNode($SecureMachineConfig.configuration.$SecureChildNode.$SElement, $true)
                            $MachineConfig.configuration.$SecureChildNode.AppendChild($NewNode) | Out-Null
                        }
                    
                        #Saving changes to XML file
                        $MachineConfig.Save($MachineConfigPath)               
                    }#End else
                }#Foreach Element within SecureElements
            }#Else end for an if statement checking if the desired childnode is in the parent file
        }#End of iterating through SecureChildNodes
    
        Write-Host "Merge Complete" -ForegroundColor White
    }
    #>

    # .Net 32-Bit
    ForEach ($DotNetVersion in (Get-ChildItem $netframework32 -Directory)) {
        Write-Host ".Net 32-Bit $DotNetVersion Is Installed" -ForegroundColor Green
        #Starting .net exe/API to pass configuration Arguments
        If (Test-Path "$($DotNetVersion.FullName)\caspol.exe") {
            Start-Process "$($DotNetVersion.FullName)\caspol.exe" -ArgumentList "-q -f -pp on" -WindowStyle Hidden
            Start-Process "$($DotNetVersion.FullName)\caspol.exe" -ArgumentList "-m -lg" -WindowStyle Hidden 
            # Comment lines above and uncomment lines below to see output
            #Start-Process "$($DotNetVersion.FullName)\caspol.exe" -ArgumentList "-q -f -pp on" -NoNewWindow
            #Start-Process "$($DotNetVersion.FullName)\caspol.exe" -ArgumentList "-m -lg" -NoNewWindow
            Write-Host "Set CAS policy for $DotNetVersion 32-Bit" -ForegroundColor White
        }
        #Vul ID: V-30935	   	Rule ID: SV-40977r3_rule	   	STIG ID: APPNET0063
        If (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\AllowStrongNameBypass") {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -Value "0" -Force | Out-Null
            Write-Host "Disabled Strong Name Bypass for $DotNetVersion 32-Bit" -ForegroundColor White
        }
        Else {
            New-Item -Path "HKLM:\SOFTWARE\Microsoft\" -Name ".NETFramework" -Force | Out-Null
            New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -PropertyType "DWORD" -Value "0" -Force | Out-Null
            Write-Host "Disabled Strong Name Bypass for $DotNetVersion 32-Bit" -ForegroundColor White
        }
        #Vul ID: V-81495	   	Rule ID: SV-96209r2_rule	   	STIG ID: APPNET0075	
        If (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\$DotNetVersion\SchUseStrongCrypto") {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\$DotNetVersion\" -Name "SchUseStrongCrypto" -Value "1" -Force | Out-Null
            Write-Host "Enforced Strong Crypto for $DotNetVersion 32-Bit" -ForegroundColor White
        }
        Else {
            New-Item -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework" -Name "$DotNetVersion" -Force | Out-Null
            New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\$DotNetVersion\" -Name "SchUseStrongCrypto" -PropertyType "DWORD" -Value "1" -Force | Out-Null
            Write-Host "Enforced Strong Crypto for $DotNetVersion 32-Bit" -ForegroundColor White
        }

        <# Source for specifying configs for specific .Net versions
        https://docs.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/enforcefipspolicy-element (2.0 or higher)
        https://docs.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/loadfromremotesources-element (4.0 or higher)
        https://docs.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/netfx40-legacysecuritypolicy-element (4.0 or higher)
        https://docs.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/etwenable-element (Doesn't specify. Assuming 3.0 or higher because it mentions Vista)
        https://docs.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/network/defaultproxy-element-network-settings (Doesn't specify.)

        
        #Ensuring .net version has machine.config
        If (Test-Path "$($DotNetVersion.FullName)\Config\Machine.config") {
            #.net Version testing.
            If (($DotNetVersion -Split "v" )[1] -ge 2) {
                #.net version testing.
                If (($DotNetVersion -Split "v" )[1] -ge 4) {
                    Write-Host ".Net version 4 or higher... Continuing with v4.0+ Machine.conf Merge..." -ForegroundColor White
                    Set-SecureConfig -VersionPath "$($DotNetVersion.FullName)\Config\Machine.config" -SecureMachineConfigPath "$PSScriptRoot\Files\.Net Configuration Files\secure.machine-v4.config"
                }
                Else {
                    Write-Host ".Net version is less than 4... Continuing with v2.0+ Machine.conf Merge..." -ForegroundColor White
                    Set-SecureConfig -VersionPath "$($DotNetVersion.FullName)\Config\Machine.config" -SecureMachineConfigPath "$PSScriptRoot\Files\.Net Configuration Files\secure.machine-v2.config"
                }
            }
            Else {
                Write-Host ".Net version is less than 2... Skipping Machine.conf Merge..." -ForegroundColor Yellow
            }#End dotnet version test
        }
        Else {
            Write-Host "No Machine.Conf file exists for .Net version $DotNetVersion" -ForegroundColor Red
        }#End testpath
        #>
    }
    

    # .Net 64-Bit
    ForEach ($DotNetVersion in (Get-ChildItem $netframework64 -Directory)) {  
        Write-Host ".Net 64-Bit $DotNetVersion Is Installed" -ForegroundColor Green
        #Starting .net exe/API to pass configuration Arguments
        If (Test-Path "$($DotNetVersion.FullName)\caspol.exe") {
            Start-Process "$($DotNetVersion.FullName)\caspol.exe" -ArgumentList "-q -f -pp on" -WindowStyle Hidden
            Start-Process "$($DotNetVersion.FullName)\caspol.exe" -ArgumentList "-m -lg" -WindowStyle Hidden 
            # Comment lines above and uncomment lines below to see output
            #Start-Process "$($DotNetVersion.FullName)\caspol.exe" -ArgumentList "-q -f -pp on" -NoNewWindow
            #Start-Process "$($DotNetVersion.FullName)\caspol.exe" -ArgumentList "-m -lg" -NoNewWindow
            Write-Host "Set CAS policy for $DotNetVersion 64-Bit" -ForegroundColor White
        }
        #Vul ID: V-30935	   	Rule ID: SV-40977r3_rule	   	STIG ID: APPNET0063
        If (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\AllowStrongNameBypass") {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -Value "0" -Force | Out-Null
            Write-Host "Disabled Strong Name Bypass for $DotNetVersion 64-Bit" -ForegroundColor White
        }
        Else {
            New-Item -Path "HKLM:\SOFTWARE\Microsoft\" -Name ".NETFramework" -Force | Out-Null
            New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -PropertyType "DWORD" -Value "0" -Force | Out-Null
            Write-Host "Disabled Strong Name Bypass for $DotNetVersion 64-Bit" -ForegroundColor White
        }
        #Vul ID: V-81495	   	Rule ID: SV-96209r2_rule	   	STIG ID: APPNET0075	
        If (Test-Path -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\$DotNetVersion\") {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\$DotNetVersion\" -Name "SchUseStrongCrypto" -Value "1" -Force | Out-Null
            Write-Host "Enforced Strong Crypto for $DotNetVersion 64-Bit" -ForegroundColor White
        }
        Else {
            New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\" -Name "$DotNetVersion" -Force | Out-Null
            New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\$DotNetVersion\" -Name "SchUseStrongCrypto" -PropertyType "DWORD" -Value "1" -Force | Out-Null
            Write-Host "Enforced Strong Crypto for $DotNetVersion 64-Bit" -ForegroundColor White
        }

        <# Source for specifying configs for specific .Net versions
        https://docs.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/enforcefipspolicy-element (2.0 or higher)
        https://docs.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/loadfromremotesources-element (4.0 or higher)
        https://docs.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/netfx40-legacysecuritypolicy-element (4.0 or higher)
        https://docs.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/etwenable-element (Doesn't specify. Assuming 3.0 or higher because it mentions Vista)
        https://docs.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/network/defaultproxy-element-network-settings (Doesn't specify.)

        
        #Ensuring current version has a machine.config to use
        If (Test-Path "$($DotNetVersion.FullName)\Config\Machine.config") {
            #version testing
            If (($DotNetVersion -Split "v" )[1] -ge 2) {
                #More version testing.
                If (($DotNetVersion -Split "v" )[1] -ge 4) {
                    Write-Host ".Net version 4 or higher... Continuing with v4.0+ Machine.conf Merge..." -ForegroundColor White
                    Set-SecureConfig -VersionPath "$($DotNetVersion.FullName)\Config\Machine.config" -SecureMachineConfigPath "$PSScriptRoot\Files\.Net Configuration Files\secure.machine-v4.config"
                }
                Else {
                    Write-Host ".Net version is less than 4... Continuing with v2.0+ Machine.conf Merge..." -ForegroundColor White
                    Set-SecureConfig -VersionPath "$($DotNetVersion.FullName)\Config\Machine.config" -SecureMachineConfigPath "$PSScriptRoot\Files\.Net Configuration Files\secure.machine-v2.config"
                }
            }
            Else {
                Write-Host ".Net version is less than 2... Skipping Machine.conf Merge..." -ForegroundColor Yellow
            }#End .net version test
        }
        Else {
            Write-Host "No Machine.Conf file exists for .Net version $DotNetVersion" -ForegroundColor Red
        }#End testpath
            #>
    }
}
else {
    Write-Output "The Dot Net Framework Section Was Skipped..."
}

if ($office -eq $true) {
    Write-Host "Implementing the Microsoft Office STIGs" -ForegroundColor Green
    Import-GPOs -gposdir ".\Files\GPOs\DoD\Office"
}
else {
    Write-Output "The Microsoft Office Section Was Skipped..."
}

if ($onedrive -eq $true) {
    Write-Host "Implementing the Microsoft OneDrive STIGs" -ForegroundColor Green
    Import-GPOs -gposdir ".\Files\GPOs\SoS\Onedrive"
}
else {
    Write-Output "The OneDrive Section Was Skipped..."
}

if ($java -eq $true) {
    Write-Host "Implementing the Oracle Java JRE 8 STIGs" -ForegroundColor Green
    Write-Host "Implementing simeononsecurity/JAVA-STIG-Script" -ForegroundColor Green
    Write-Host "https://github.com/simeononsecurity/JAVA-STIG-Script" -ForegroundColor Green 

    #https://gist.github.com/MyITGuy/9628895
    #http://stu.cbu.edu/java/docs/technotes/guides/deploy/properties.html

    #<Windows Directory>\Sun\Java\Deployment\deployment.config
    #- or -
    #<JRE Installation Directory>\lib\deployment.config

    if (Test-Path -Path "C:\Windows\Sun\Java\Deployment\deployment.config") {
        Write-Host "JAVA Deployment Config Already Installed" -ForegroundColor Green
    }
    else {
        Write-Host "Installing JAVA Deployment Config...." -ForegroundColor Green
        Mkdir "C:\Windows\Sun\Java\Deployment\"
        Copy-Item -Path .\Files\"JAVA Configuration Files"\deployment.config -Destination "C:\Windows\Sun\Java\Deployment\" -Force
        Write-Host "JAVA Configs Installed" -ForegroundColor White
    }
    if (Test-Path -Path "C:\Windows\Java\Deployment\") {
        Write-Host "JAVA Configs Already Deployed" -ForegroundColor Green
    }
    else {
        Write-Host "Installing JAVA Configurations...." -ForegroundColor Green
        Mkdir "C:\Windows\Java\Deployment\"
        Copy-Item -Path .\Files\"JAVA Configuration Files"\deployment.properties -Destination "C:\Windows\Java\Deployment\" -Force
        Copy-Item -Path .\Files\"JAVA Configuration Files"\exception.sites -Destination "C:\Windows\Java\Deployment\" -Force
        Write-Host "JAVA Configs Installed" -ForegroundColor White
    }
}
else {
    Write-Output "The Oracle Java JRE 8 Section Was Skipped..."
}

if ($windows -eq $true) {
    Write-Host "Implementing the Windows 10/11 STIGs" -ForegroundColor Green
    Import-GPOs -gposdir ".\Files\GPOs\DoD\Windows"

    Write-Host "Implementing simeononsecurity/Windows-Audit-Policy" -ForegroundColor Green
    Write-Host "https://github.com/simeononsecurity/Windows-Audit-Policy" -ForegroundColor Green 

    New-Item -Force -ItemType "Directory" "C:\temp"
    Copy-Item $PSScriptRoot\files\auditing\auditbaseline.csv C:\temp\auditbaseline.csv 

    #Clear Audit Policy
    auditpol /clear /y

    #Enforce the Audit Policy Baseline
    auditpol /restore /file:C:\temp\auditbaseline.csv

    #Confirm Changes
    auditpol /list /user /v
    auditpol.exe /get /category:*

    #Basic authentication for RSS feeds over HTTP must not be used.
    New-Item -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer" -Name "Feeds" -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer\Feeds" -Name "AllowBasicAuthInClear" -Type "DWORD" -Value 0 -Force
    #Check for publishers certificate revocation must be enforced.
    New-Item -Path "HKLM:\Software\Microsoft\Windows\Current Version\WinTrust\Trust Providers\" -Name "Software Publishing" -Force
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\Current Version\WinTrust\Trust Providers\Software Publishing" -Name State -Type "DWORD" -Value 146432 -Force
    New-Item -Path "HKCU:\Software\Microsoft\Windows\Current Version\WinTrust\Trust Providers\" -Name "Software Publishing" -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\Current Version\WinTrust\Trust Providers\Software Publishing" -Name State -Type "DWORD" -Value 146432 -Force
    #AutoComplete feature for forms must be disallowed.
    New-Item -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer\" -Name "Main Criteria" -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main Criteria" -Name "Use FormSuggest" -Type "String" -Value no -Force
    New-Item -Path "HKCU:\Software\Policies\Microsoft\Internet Explorer\" -Name "Main Criteria" -Force
    Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Internet Explorer\Main Criteria" -Name "Use FormSuggest" -Type "String" -Value no -Force
    #Turn on the auto-complete feature for user names and passwords on forms must be disabled.
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main Criteria" -Name "FormSuggest PW Ask" -Type "String" -Value no -Force
    Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Internet Explorer\Main Criteria" -Name "FormSuggest PW Ask" -Type "String" -Value no -Force
    #Windows 10 must be configured to prioritize ECC Curves with longer key lengths first.
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" -Name "EccCurves" -Type "MultiString" -Value "NistP384 NistP256" -Force
    #Zone information must be preserved when saving attachments.
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments\" -Name "Main Criteria" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments\" -Name "SaveZoneInformation" -Type "DWORD" -Value 2 -Force
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments\" -Name "SaveZoneInformation" -Type "DWORD" -Value 2 -Force
    #Toast notifications to the lock screen must be turned off.
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\" -Name "PushNotifications" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications\" -Name "NoToastApplicationNotificationOnLockScreen" -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications\" -Name "NoToastApplicationNotificationOnLockScreen" -Type "DWORD" -Value 1 -Force
    #Windows 10 should be configured to prevent users from receiving suggestions for third-party or additional applications.
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows" -Name "CloudContent" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableThirdPartySuggestions" -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableThirdPartySuggestions" -Type "DWORD" -Value 1 -Force
    #Windows 10 must be configured to prevent Windows apps from being activated by voice while the system is locked.
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows" -Name "AppPrivacy" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy\" -Name "LetAppsActivateWithVoice" -Type "DWORD" -Value 2 -Force
    #The Windows Explorer Preview pane must be disabled for Windows 10.
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies" -Name "Explorer" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoReadingPane" -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoReadingPane" -Type "DWORD" -Value 1 -Force
    #The use of a hardware security device with Windows Hello for Business must be enabled.
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft" -Name "PassportForWork" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\" -Name "RequireSecurityDevice" -Type "DWORD" -Value 1 -Force
}
else {
    Write-Output "The Windows Desktop Section Was Skipped..."
}

if ($defender -eq $true) {
    Write-Host "Implementing the Windows Defender STIGs" -ForegroundColor Green
    Import-GPOs -gposdir ".\Files\GPOs\DoD\Defender"
}
else {
    Write-Output "The Windows Defender Section Was Skipped..."
}

if ($firewall -eq $true) {
    Write-Host "Implementing the Windows Firewall STIGs" -ForegroundColor Green
    Import-GPOs -gposdir ".\Files\GPOs\DoD\FireWall"
}
else {
    Write-Output "The Windows Firewall Section Was Skipped..."
}

if ($mitigations -eq $true) {
    Write-Host "Implementing the General Vulnerability Mitigations" -ForegroundColor Green
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
}
else {
    Write-Output "The General Mitigations Section Was Skipped..."
}

if ($nessusPID -eq $true) {
    Write-Host "Resolve: Nessus Plugin ID 63155 - Microsoft Windows Unquoted Service Path Enumeration" -ForegroundColor Green
    Start-Job -Name "Nessus Plugin ID 63155 - Microsoft Windows Unquoted Service Path Enumeration" -ScriptBlock {
        # https://github.com/VectorBCO/windows-path-enumerate/blob/development/Windows_Path_Enumerate.ps1
        ForEach ($i in 1..2) {
            # Get all services
            $FixParameters = @()
            If ($i = 1) {
                $FixParameters += @{"Path" = "HKLM:\SYSTEM\CurrentControlSet\Services\" ; "ParamName" = "ImagePath" }
            }
            If ($i = 2) {
                $FixParameters += @{"Path" = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" ; "ParamName" = "UninstallString" }
                # If OS x64 - adding paths for x86 programs
                If (Test-Path "$($env:SystemDrive)\Program Files (x86)\") {
                    $FixParameters += @{"Path" = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\" ; "ParamName" = "UninstallString" }
                }
            }
            $PTElements = @()
            ForEach ($FixParameter in $FixParameters) {
                Get-ChildItem $FixParameter.Path -ErrorAction SilentlyContinue | ForEach-Object {
                    $SpCharREGEX = '([\[\]])'
                    $RegistryPath = $_.name -Replace 'HKEY_LOCAL_MACHINE', 'HKLM:' -replace $SpCharREGEX, '`$1'
                    $OriginalPath = (Get-ItemProperty "$RegistryPath")
                    $ImagePath = $OriginalPath.$($FixParameter.ParamName)
                    If ($i = 1, 2) {
                        If ($($OriginalPath.$($FixParameter.ParamName)) -match '%(?''envVar''[^%]+)%') {
                            $EnvVar = $Matches['envVar']
                            $FullVar = (Get-ChildItem env: | Where-Object { $_.Name -eq $EnvVar }).value
                            $ImagePath = $OriginalPath.$($FixParameter.ParamName) -replace "%$EnvVar%", $FullVar
                            Clear-Variable Matches
                        } # End If
                    } # End If $fixEnv
                    # Get all services with vulnerability
                    If (($ImagePath -like "* *") -and ($ImagePath -notLike '"*"*') -and ($ImagePath -like '*.exe*')) {
                        # Skip MsiExec.exe in uninstall strings
                        If ((($FixParameter.ParamName -eq 'UninstallString') -and ($ImagePath -NotMatch 'MsiExec(\.exe)?') -and ($ImagePath -Match '^((\w\:)|(%[-\w_()]+%))\\')) -or ($FixParameter.ParamName -eq 'ImagePath')) {
                            $NewPath = ($ImagePath -split ".exe ")[0]
                            $key = ($ImagePath -split ".exe ")[1]
                            $trigger = ($ImagePath -split ".exe ")[2]
                            $NewValue = ''
                            # Get service with vulnerability with key in ImagePath
                            If (-not ($trigger | Measure-Object).count -ge 1) {
                                If (($NewPath -like "* *") -and ($NewPath -notLike "*.exe")) {
                                    $NewValue = "`"$NewPath.exe`" $key"
                                } # End If
                                # Get service with vulnerability with out key in ImagePath
                                ElseIf (($NewPath -like "* *") -and ($NewPath -like "*.exe")) {
                                    $NewValue = "`"$NewPath`""
                                } # End ElseIf
                                If ((-not ([string]::IsNullOrEmpty($NewValue))) -and ($NewPath -like "* *")) {
                                    try {
                                        $soft_service = $(if ($FixParameter.ParamName -Eq 'ImagePath') { 'Service' }Else { 'Software' })
                                        $OriginalPSPathOptimized = $OriginalPath.PSPath -replace $SpCharREGEX, '`$1'
                                        Write-Host "$(get-date -format u)  :  Old Value : $soft_service : '$($OriginalPath.PSChildName)' - $($OriginalPath.$($FixParameter.ParamName))"
                                        Write-Host "$(get-date -format u)  :  Expected  : $soft_service : '$($OriginalPath.PSChildName)' - $NewValue"
                                        if ($Passthru) {
                                            $PTElements += '' | Select-Object `
                                            @{n = 'Name'; e = { $OriginalPath.PSChildName } }, `
                                            @{n = 'Type'; e = { $soft_service } }, `
                                            @{n = 'ParamName'; e = { $FixParameter.ParamName } }, `
                                            @{n = 'Path'; e = { $OriginalPSPathOptimized } }, `
                                            @{n = 'OriginalValue'; e = { $OriginalPath.$($FixParameter.ParamName) } }, `
                                            @{n = 'ExpectedValue'; e = { $NewValue } }
                                        }
                                        If (! ($i -gt 2)) {
                                            Set-ItemProperty -Path $OriginalPSPathOptimized -Name $($FixParameter.ParamName) -Value $NewValue -ErrorAction Stop
                                            $DisplayName = ''
                                            $keyTmp = (Get-ItemProperty -Path $OriginalPSPathOptimized)
                                            If ($soft_service -match 'Software') {
                                                $DisplayName = $keyTmp.DisplayName
                                            }
                                            If ($keyTmp.$($FixParameter.ParamName) -eq $NewValue) {
                                                Write-Host "$(get-date -format u)  :  SUCCESS  : Path value was changed for $soft_service '$($OriginalPath.PSChildName)' $(if($DisplayName){"($DisplayName)"})"
                                            } # End If
                                            Else {
                                                Write-Host "$(get-date -format u)  :  ERROR  : Something is going wrong. Path was not changed for $soft_service '$(if($DisplayName){$DisplayName}else{$OriginalPath.PSChildName})'."
                                            } # End Else
                                        } # End If
                                    } # End try
                                    Catch {
                                        Write-Host "$(get-date -format u)  :  ERROR  : Something is going wrong. Value changing failed in service '$($OriginalPath.PSChildName)'."
                                        Write-Host "$(get-date -format u)  :  ERROR  : $_"
                                    } # End Catch
                                    Clear-Variable NewValue
                                } # End If
                            } # End Main If
                        } # End if (Skip not needed strings)
                    } # End If
                    If (($trigger | Measure-Object).count -ge 1) {
                        Write-Host "$(get-date -format u)  :  ERROR  : Can't parse  $($OriginalPath.$($FixParameter.ParamName)) in registry  $($OriginalPath.PSPath -replace 'Microsoft\.PowerShell\.Core\\Registry\:\:') "
                    } # End If
                } # End Foreach
            } # End Foreach
        } # End Foreach   
    } # End Job
}
else {
    Write-Output "The Nessus PID 63155 Section Was Skipped..."
}

if ($horizon -eq $true) {
    Write-Host "Implementing the VMWare Horizon STIG Configurations" -ForegroundColor Green
    Import-GPOs -gposdir ".\Files\GPOs\DoD\Horizon"
}
else {
    Write-Output "The VMware Horizon STIG Section Was Skipped..."
}

if ($sosoptional -eq $true) {
    Write-Host "Implementing the Optional SimeonOnSecurity Configurations Section" -ForegroundColor Green
    Import-GPOs -gposdir ".\Files\GPOs\SoS"
}
else {
    Write-Output "The Optional SimeonOnSecurity Configurations Section Was Skipped..."
}

Write-Host "Checking Backgrounded Processes" ; Get-Job
Write-Host "Performing Group Policy Update" ; Gpupdate /force
Write-Warning "A reboot is required for all changed to take effect"
