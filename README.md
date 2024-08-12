# Wynis
Forked from https://github.com/Sneakysecdoggo/Wynis

Updated to the latest CIS benchmarks for Windows Server 2022 (v3.0.0), 2019 (v3.0.1), 2016 (v3.0.0), 2012R2 (v3.0.0) and 2008R2 (v3.3.0).

Powershell scripts for auditing windows security in accordance with the CIS Standards.
You just need to run the script, it will create a directory named: AUDIT_CONF_%MACHINENAME_%DATE%


![W1](../master/Examples/W1-ScriptOverView.png)


Actualy, the script are : 

-WynisWIN2016DC-CISv1.0 : Auditing DC 2016 with CIS

-Wynis-AD-STIG : Auditing Domain Security with STIG and other security Best Practice (Work In Progress)

-WynisO365-CIS : Auditing O365 with CIS Best Practice (Work in Progress)

-WynisWIN10-CIS : Auditing Win 10 with CIS Best Practice 

-WynisWIN2016-CIS : Auditing Win 2016 with CIS Best Practice 


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

