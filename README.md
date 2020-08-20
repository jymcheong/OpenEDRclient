# Open Endpoint Defense & Response

* Tested on Windows 10, Server 2012R2 to 2019
* Protects non-escalated file-based PE Malware (EXE/DLL)
* Detects Living-Off-The-Land offensive techniques without hard-coding rules
* Responds by automated or backend triggered malicious process termination 

It leverages the following components.

## Sysmon
Sysinternal's license forbids redistribution: 
https://docs.microsoft.com/en-us/sysinternals/license-terms

For non-Internet facing environments, please download Sysmon, modifiy `install.ps1` accordingly & host within your internal web-server.

## Nxlog-CE 
This is an archived version of NXLog-CE tested with OpenEDR client agents.
