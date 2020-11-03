# Changes

## 3 Nov 2020
* Refactored `install.ps1` to perform offline installation; installer.zip needs to be same path as install.ps1
* Rollback to Sysmon 10.42; see https://social.technet.microsoft.com/Forums/en-US/9e2f381e-f4cd-4b6e-89dd-21c466509af9/rollback-to-sysmon-version-1042-?forum=miscutils
* Fixed Office-Macro configuration in `install.ps1`

## 23 Oct 2020
* Added MSOffice Macro restriction in install.ps1

## 2 Oct 2020
* Added Attack Surface Reduction Rules enablement - https://github.com/jymcheong/OpenEDRclient/issues/6

## 1 Oct 2020
* Fixed #4
* Added MSI & LNK file block; LNK created by user using explorer.exe are allowed. 

## 28 Sep 2020
Deny .HTA file by associating with notepad: https://github.com/jymcheong/OpenEDRclient/issues/2

## 25 Sep 2020
Terminate child processes from MSOffice-macros https://github.com/jymcheong/OpenEDRclient/commit/c34868b119cddf996ddfc510d69fbfe88c493742 https://github.com/jymcheong/OpenEDRclient/issues/1
