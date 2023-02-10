# Windows 10 and 11 STIG Script

[![Test script against windows docker container](https://github.com/simeononsecurity/Standalone-Windows-STIG-Script/actions/workflows/test-with-docker.yml/badge.svg)](https://github.com/simeononsecurity/Standalone-Windows-STIG-Script/actions/workflows/test-with-docker.yml)[![VirusTotal Scan](https://github.com/simeononsecurity/Standalone-Windows-STIG-Script/actions/workflows/virustotal.yml/badge.svg)](https://github.com/simeononsecurity/Standalone-Windows-STIG-Script/actions/workflows/virustotal.yml)[![PSScriptAnalyzer](https://github.com/simeononsecurity/Standalone-Windows-STIG-Script/actions/workflows/powershell.yml/badge.svg)](https://github.com/simeononsecurity/Standalone-Windows-STIG-Script/actions/workflows/powershell.yml)

**Download all the required files from the [GitHub Repository](https://github.com/simeononsecurity/Standalone-Windows-STIG-Script)**

**Note:** This script should work for most, if not all, systems without issue. While [@SimeonOnSecurity](https://github.com/simeononsecurity) creates, reviews, and tests each repo intensively, we can not test every possible configuration nor does [@SimeonOnSecurity](https://github.com/simeononsecurity) take any responsibility for breaking your system. If something goes wrong, be prepared to submit an [issue](../../issues). Do not run this script if you don't understand what it does. It is your responsibility to review and test the script before running it.

## Ansible:
We now offer a playbook collection for this script. Please see the following:
- [Github Repo](https://github.com/simeononsecurity/Windows_STIG_Ansible)
- [Ansible Galaxy](https://galaxy.ansible.com/simeononsecurity/windows_stigs)

## Introduction:

Windows is insecure operating system out of the box and requires many changes to insure [FISMA](https://www.cisa.gov/federal-information-security-modernization-act) compliance. 
Organizations like [Microsoft](https://microsoft.com), [Cyber.mil](https://public.cyber.mil), the [Department of Defense](https://dod.gov), and the [National Security Agency](https://www.nsa.gov/) have recommended and required configuration changes to lockdown, harden, and secure the operating system and ensure government compliance. These changes cover a wide range of mitigations including blocking telemetry, macros, removing bloatware, and preventing many physical attacks on a system.

Standalone systems are some of the most difficult and annoying systems to secure. When not automated, they require manual changes of each STIG/SRG. Totalling over 1000 configuration changes on a typical deployment and an average of 5 minutes per change equaling 3.5 days worth of work. This script aims to speed up that process significantly.

## Notes: 

- This script is designed for operation in **Enterprise** environments and assumes you have hardware support for all the requirements.
  - For personal systems please see this [GitHub Repository](https://github.com/simeononsecurity/Windows-Optimize-Harden-Debloat)
- This script is not designed to bring a system to 100% compliance, rather it should be used as a stepping stone to complete most, if not all, the configuration changes that can be scripted. 
  - Minus system documentation, this collection should bring you up to about 95% compliance on all the STIGS/SRGs applied.

## Requirements:
- [X] Windows 10 Enterprise is required per STIG.
- [X] [Standards](https://docs.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-highly-secure) for a highly secure Windows 10 device
- [X] System is [fully up to date](https://support.microsoft.com/en-gb/help/4027667/windows-10-update)
  - Run the [Windows 10 Upgrade Assistant](https://support.microsoft.com/en-us/help/3159635/windows-10-update-assistant) to update and verify latest major release.
- [X] Bitlocker must be suspended or turned off prior to implementing this script, it can be enabled again after rebooting.
  - Follow-up runs of this script can be run without disabling bitlocker.
- [X] Hardware Requirements
  - [Hardware Requirements for Memory Integrity](https://docs.microsoft.com/en-us/windows/security/threat-protection/device-guard/requirements-and-deployment-planning-guidelines-for-virtualization-based-protection-of-code-integrity#baseline-protections) 
  - [Hardware Requirements for Virtualization-Based Security](https://docs.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-vbs)
  - [Hardware Requirements for Windows Defender Application Guard](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-guard/reqs-wd-app-guard)
  - [Hardware Requirements for Windows Defender Credential Guard](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-requirements)
  
## Recommended reading material:
  - [System Guard Secure Launch](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-system-guard/system-guard-secure-launch-and-smm-protection#requirements-met-by-system-guard-enabled-machines)
  - [System Guard Root of Trust](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-system-guard/system-guard-how-hardware-based-root-of-trust-helps-protect-windows)
  - [Hardware-based Isolation](https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/overview-hardware-based-isolation)
  - [Memory integrity](https://docs.microsoft.com/en-us/windows/security/threat-protection/device-guard/memory-integrity)
  - [Windows Defender Application Guard](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-guard/wd-app-guard-overview)
  - [Windows Defender Credential Guard](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-how-it-works)

## A list of scripts and tools this collection utilizes:
- [Cyber.mil - Group Policy Objects](https://public.cyber.mil/stigs/gpo/)
- [Microsoft Security Compliance Toolkit 1.0](https://www.microsoft.com/en-us/download/details.aspx?id=55319)

## Additional configurations were considered from:
- [Microsoft - Recommended block rules](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-block-rules)
- [Microsoft - Recommended driver block rules](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules)
- [Microsoft - Windows Defender Application Control](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/windows-defender-application-control-design-guide)
- [NSACyber - Application Whitelisting Using Microsoft AppLocker](https://apps.nsa.gov/iad/library/ia-guidance/tech-briefs/application-whitelisting-using-microsoft-applocker.cfm)
- [NSACyber - Hardware-and-Firmware-Security-Guidance](https://github.com/nsacyber/Hardware-and-Firmware-Security-Guidance)
- [NSACyber - Windows Secure Host Baseline](https://github.com/nsacyber/Windows-Secure-Host-Baseline)

## STIGS/SRGs Applied:
- [Adobe Acrobat Pro DC Continuous V2R1](https://public.cyber.mil/stigs/downloads/)
- [Adobe Acrobat Reader DC Continuous V2R1](https://public.cyber.mil/stigs/downloads/)
- [Firefox V5R2](https://public.cyber.mil/stigs/downloads/)
- [Google Chrome V2R4](https://public.cyber.mil/stigs/downloads/)
- [Internet Explorer 11 V1R19](https://public.cyber.mil/stigs/downloads/)
- [Microsoft Edge V1R2](https://public.cyber.mil/stigs/downloads/)
- [Microsoft .Net Framework 4 V1R9](https://public.cyber.mil/stigs/downloads/)
- [Microsoft Office 2013 V2R1](https://public.cyber.mil/stigs/downloads/)
- [Microsoft Office 2016 V2R1](https://public.cyber.mil/stigs/downloads/)
- [Microsoft Office 2019/Office 365 Pro Plus V2R3](https://public.cyber.mil/stigs/downloads/)
- [Microsoft OneDrive STIG V2R1](https://public.cyber.mil/stigs/downloads/)
- [Oracle JRE 8 V1R5](https://public.cyber.mil/stigs/downloads/)
- [Windows 10 V2R2](https://public.cyber.mil/stigs/downloads/)
- [Windows Firewall V1R7](https://public.cyber.mil/stigs/downloads/)

## Editing policies in Local Group Policy after the fact:
- Import the ADMX Policy definitions from this [repo](https://github.com/simeononsecurity/STIG-Compliant-Domain-Prep/tree/master/Files/PolicyDefinitions) into *C:\windows\PolicyDefinitions* on the system you're trying to modify.
- Open ```gpedit.msc``` on on the system you're trying to modify. 


## How to run the script:
### Automated Install:
The script may be launched from the extracted GitHub download like this:
```powershell
iex ((New-Object System.Net.WebClient).DownloadString('https://simeononsecurity.ch/scripts/standalonewindows.ps1'))
```

### Manual Install:
If manually downloaded, the script must be launched from the directory containing all the other files from the [GitHub Repository](https://github.com/simeononsecurity/Standalone-Windows-STIG-Script)

All of the parameters in the "secure-standalone.ps1" script are optional, with a default value of $true. This means that if no value is specified for a parameter when the script is run, it will be treated as if it were set to $true.

The script takes the following parameters, all of which are optional and default to $true if not specified:

- **cleargpos**: (Boolean) Clear GPOs not being used
- **installupdates**: (Boolean) Install updates and reboot if necessary
- **adobe**: (Boolean) STIG Adobe Reader
- **firefox**: (Boolean) STIG Firefox
- **chrome**: (Boolean) STIG Chrome
- **IE11**: (Boolean) STIG Internet Explorer 11
- **edge**: (Boolean) STIG Edge
- **dotnet**: (Boolean) STIG .NET Framework
- **office**: (Boolean) STIG Office
- **onedrive**: (Boolean) STIG OneDrive
- **java**: (Boolean) STIG Java
- **windows**: (Boolean) STIG Windows
- **defender**: (Boolean) STIG Windows Defender
- **firewall**: (Boolean) STIG Windows Firewall
- **mitigations**: (Boolean) STIG Mitigations
- **nessusPID**: (Boolean) Resolve Unquoted Strings in Path
- **horizon**: (Boolean) STIG VMware Horizon
- **sosoptional**: (Boolean) Optional STIG/Hardening items

An example of how to run the script with all default parameters would be:

```powershell
.\secure-standalone.ps1
```
If you want to specify a different value for one or more of the parameters, you can include them in the command along with their desired value. For example, if you wanted to run the script and set the $firefox parameter to $false, the command would be:

```powershell
.\secure-standalone.ps1 -firefox $false
```

You can also specify multiple parameters in the command like this:

```powershell
.\secure-standalone.ps1 -firefox $false -chrome $false
```

Note that in this example, both the Firefox and Chrome parameters are set to $false.



