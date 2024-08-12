# Wynis
Forked from https://github.com/Sneakysecdoggo/Wynis

Updated to the latest CIS benchmarks for Windows Server 2022 (v3.0.0), 2019 (v3.0.1), 2016 (v3.0.0), 2012R2 (v3.0.0) and 2008R2 (v3.3.0).

Powershell scripts for auditing windows security in accordance with the CIS Standards.
You just need to run the script, it will create a directory named: AUDIT_CONF_%MACHINENAME_%DATE%


![W1](../master/Examples/W1-ScriptOverView.png)


Actually, the scripts are : 

- WynisWIN2008R2-CISv3.3.0.ps1: Auditing Windows Server 2008R2 with CIS Benchmarks

- WynisWIN2012R2-CISv3.0.0_Final.ps1: Auditing Windows Server 2012R2 with CIS Benchmarks

- WynisWIN2016-CISv3.0.0.ps1: Auditing Windows Server 2016 with CIS Benchmarks

- WynisWIN2019-CISv3.0.1.ps1: Auditing Windows Server 2019 with CIS Benchmarks

- WynisWIN2022-CISv3.0.0.ps1: Auditing Windows Server 2022 with CIS Benchmarks


# Prerequisites

Before running the script either you : 

    -'Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope CurrentUser' before running the script in your powershell console

    - Sign Wynis with your PKi https://devblogs.microsoft.com/scripting/hey-scripting-guy-how-can-i-sign-windows-powershell-scripts-with-an-enterprise-windows-pki-part-2-of-2/







# Informations

The directory output will contain the files below:

![W2](../master/Examples/W2-FilesList.png)


-Antivirus-%COMPUTERNAME% : List installed Antivirus software

![W3](../master/Examples/W3-Antivirus.jpg)

-APPDATA%COMPUTERNAME% : List all executable file in APPDATA directory
![W4](../master/Examples/W3-Appdataa.jpg)


-Audit%DATE%: list the result of all CIS tests

![W4](../master/Examples/W4-OutPutExemple.jpg)

-auditpolicy-%COMPUTERNAME% : audit policy configured

![W5](../master/Examples/W5-AuditConfiguration.jpg)

-firewall-rules-%COMPUTERNAME% : List all local windows firewall rules

![W6](../master/Examples/W6-FirewallRules.jpg)

-gpo-%COMPUTERNAME% : Gpresult for applied GPO

![W10](../master/Examples/W12-GPRESULT.jpg)


-Installed-Software-%COMPUTERNAME% : List installed software

![W6](../master/Examples/W6-InstalledSoftware.jpg)

-Listen-port-%COMPUTERNAME% : netstat with associate executable
![W11](../master/Examples/W11-netsat.jpg)
-localuser-%COMPUTERNAME% : list all local users

-OptionnalFeature-%COMPUTERNAME% :List all enabled optional feature

![W7](../master/Examples/W7-InstalledOptionnalFeature.jpg)

-Scheduled-task-%COMPUTERNAME% : list all scheduled task

![W8](../master/Examples/W8-SchedulTaks.jpg)
-Service-%COMPUTERNAME% : list all service

![W9](../master/Examples/W9-ListService.jpg)

-Share-%COMPUTERNAME% : list all share

![W10](../master/Examples/W10-ListService.jpg)

-StartUp-%COMPUTERNAME% : check registry to identify start-up executable

-System-%COMPUTERNAME%  : systeminfo

-SystemUpdate : Check Wmi Quickfix to identify installed update

