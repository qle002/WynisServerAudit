#Requires -RunAsAdministrator
# Requires -Version 4.0
#Author:Sneakysecdoggo
#Be awesome send me cookie
#This script must be run with admin rights 
#Check Windows Security Best Practice CIS 
#https://github.com/Sneakysecdoggo/
#Script Server Version
#MIT License

#Copyright (c) [2019] [Sneakysecdoggo]

#Permission is hereby granted, free of charge, to any person obtaining a copy
#of this software and associated documentation files (the "Software"), to deal
#in the Software without restriction, including without limitation the rights
#to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#copies of the Software, and to permit persons to whom the Software is
#furnished to do so, subject to the following conditions:

#The above copyright notice and this permission notice shall be included in all
#copies or substantial portions of the Software.

#THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#SOFTWARE
#For running Prod , for debug comment the ligne below
# $ErrorActionPreference= 'silentlycontinue'
##########

#ASCII ART 

Write-Host "__          ____     ___   _ _____  _____ "  -ForegroundColor Cyan
Write-Host "\ \        / /\ \   / / \ | |_   _|/ ____|"  -ForegroundColor Cyan
Write-Host " \ \  /\  / /  \ \_/ /|  \| | | | | (___  "  -ForegroundColor Cyan
Write-Host "  \ \/  \/ /    \   / | . ` | | |  \___ \ "  -ForegroundColor Cyan
Write-Host "   \  /\  /      | |  | |\  |_| |_ ____) |"  -ForegroundColor Cyan
Write-Host "__  \/  \/  _____|_|__|_| \_|_____|_____/ "  -ForegroundColor Cyan
Write-Host "\ \        / / ____|__ \ / _ \/_ |/ _ \   "  -ForegroundColor Cyan
Write-Host " \ \  /\  / / (___    ) | | | || | (_) |  "  -ForegroundColor Cyan
Write-Host "  \ \/  \/ / \___ \  / /| | | || |\__, |  "  -ForegroundColor Cyan
Write-Host "   \  /\  /  ____) |/ /_| |_| || |  / /   "  -ForegroundColor Cyan
Write-Host "    \/  \/  |_____/|____|\___/ |_| /_/    "  -ForegroundColor Cyan
#FUNCTION                                        


$reverveCommand = Get-Command | Where-Object { $_.name -match "Get-WSManInstance"}
if ($null -ne $reverveCommand) {
  $reverseCommandExist = $true
} else {
  $reverseCommandExist = $false
}
# Function to reverse SID from SecPol
Function Format-SID ($chainSID) {
  $chainSID = $chainSID -creplace '^[^\\]*=', ''
  $chainSID = $chainSID.replace("*", "")
  $chainSID = $chainSID.replace(" ", "")
 
  if ($null -ne $chainSID) {
    $table = @()
    $table = $chainSID.Split(",")
 
    ForEach ($line in $table) { 
      $sid = $null
      
      if ($line -like "S-*") {
        if($reverseCommandExist -eq $true){
          $sid = Get-WSManInstance -ResourceURI "wmicimv2/Win32_SID" -SelectorSet @{SID="$line"}|Select-Object AccountName
          $sid = $sid.AccountName
        }

        if ( $null -eq $sid) {
          $objSID = New-Object System.Security.Principal.SecurityIdentifier ("$line")
          $objUser = $objSID.Translate( [System.Security.Principal.NTAccount])
          $sid = $objUser.Value
        
          if ( $sid -eq $null){
            $objUser = New-Object System.Security.Principal.NTAccount("$line") 
            $strSID = $objUser.Translate([System.Security.Principal.SecurityIdentifier])
            $sid = $strSID.Value
          }
          $outpuReverseSid += $sid + "|"
        } else {
          $outpuReverseSid += $line + "|"
        }
      }
    }
  return $outpuReverseSid
  } else {
    $outpuReverseSid += No One 
    return $outpuReverseSid
  }
}


# convert Stringarray to comma separated liste (String)
function StringArrayToList($StringArray) {
  if ($StringArray) {
    $Result = ""
    Foreach ($Value In $StringArray) {
      if ($Result -ne "") { $Result += "," }
      $Result += $Value
    }
    return $Result
  } else {
    return ""
  }
}
#Get intel from the machine

$OSInfo = Get-WmiObject Win32_OperatingSystem | Select-Object Caption, Version, ServicePackMajorVersion, OSArchitecture, CSName, WindowsDirectory, NumberOfUsers, BootDevice


$OSversion = $OSInfo.Caption
$OSName = $OSInfo.CSName
$OSArchi = $OSInfo.OSArchitecture

#get the date
$Date = Get-Date -U %d%m%Y


$filename = "CIS_audit" + $date + "-" + $OSName +".txt"

Write-Host "#########>Create Audit directory<#########" -ForegroundColor DarkGreen

$foldername = "Audit_CONF_" + $OSName + "_" + $date


New-Item -ItemType Directory -Name $foldername

Set-Location $foldername



#Put it in a file
Write-Host "#########>Take Server Information<#########" -ForegroundColor DarkGreen
"#########INFO MACHINE#########" > $filename
"Os version: $OSversion " >> $filename
"Machine name : $OSName " >> $filename
"Machine architecture : $OSArchi" >> $filename
#Start testing
"#########AUDIT MACHINE#########" >> $filename
$indextest = 1
$chaine = $null
$traitement = $null


#Take file important for analysis 
Write-Host "#########>Take File to analyse<#########" -ForegroundColor DarkGreen
$seceditfile = "./secpol" + "-" + "$OSName" + ".cfg"
secedit /export /cfg $seceditfile 
$gpofile = "./gpo" + "-" + "$OSName" + ".txt"
gpresult /r /V > $gpofile
$gpofile = "./gpo" + "-" + "$OSName" + ".html"
gpresult /h $gpofile /f | out-null
#Second command in case of emergency


$auditconfigfile = "./auditpolicy" + "-" + "$OSName" + ".txt"

auditpol.exe /get /Category:* > $auditconfigfile


#Dump some Windows registry 
Write-Host "#########>Dump Windows Registry <#########" -ForegroundColor DarkGreen
$auditregHKLM = "./auditregistry-HKLMicrosoft" + "-" + "$OSName" + ".txt"
reg export "HKLM\SOFTWARE\Microsoft\" "$auditregHKLM"
$auditregHKLM = "./auditregistry-HKLMCUrrentControlSet" + "-" + "$OSName" + ".txt"
reg export "HKLM\SYSTEM\CurrentControlSet" "$auditregHKLM"
$auditregHKLM = "./auditregistry-HKLMPolicies" + "-" + "$OSName" + ".txt"
reg export "HKLM\SOFTWARE\Policies" "$auditregHKLM"

#Take Firewall Configuration
Write-Host "#########>Take local Firewall Rules Information<#########" -ForegroundColor DarkGreen
$CSVFile = "./firewall-rules-" + "$OSName" + ".csv"
# read firewall rules
$FirewallRules = Get-NetFirewallRule -PolicyStore "ActiveStore"

# start array of rules
$FirewallRuleSet = @()
ForEach ($Rule In $FirewallRules) {
  # iterate throug rules
  # Retrieve addresses,
  $AdressFilter = $Rule | Get-NetFirewallAddressFilter
  # ports,
  $PortFilter = $Rule | Get-NetFirewallPortFilter
  # application,
  $ApplicationFilter = $Rule | Get-NetFirewallApplicationFilter
  # service,
  $ServiceFilter = $Rule | Get-NetFirewallServiceFilter
  # interface,
  $InterfaceFilter = $Rule | Get-NetFirewallInterfaceFilter
  # interfacetype
  $InterfaceTypeFilter = $Rule | Get-NetFirewallInterfaceTypeFilter
  # and security settings
  $SecurityFilter = $Rule | Get-NetFirewallSecurityFilter

  # generate sorted Hashtable
  $HashProps = [PSCustomObject]@{
    Name        = $Rule.Name
    DisplayName     = $Rule.DisplayName
    Description     = $Rule.Description
    Group        = $Rule.Group
    Enabled       = $Rule.Enabled
    Profile       = $Rule.Profile
    Platform      = StringArrayToList $Rule.Platform
    Direction      = $Rule.Direction
    Action       = $Rule.Action
    EdgeTraversalPolicy = $Rule.EdgeTraversalPolicy
    LooseSourceMapping = $Rule.LooseSourceMapping
    LocalOnlyMapping  = $Rule.LocalOnlyMapping
    Owner        = $Rule.Owner
    LocalAddress    = StringArrayToList $AdressFilter.LocalAddress
    RemoteAddress    = StringArrayToList $AdressFilter.RemoteAddress
    Protocol      = $PortFilter.Protocol
    LocalPort      = StringArrayToList $PortFilter.LocalPort
    RemotePort     = StringArrayToList $PortFilter.RemotePort
    IcmpType      = StringArrayToList $PortFilter.IcmpType
    DynamicTarget    = $PortFilter.DynamicTarget
    Program       = $ApplicationFilter.Program -Replace "$($ENV:SystemRoot.Replace("\","\\"))\\", "%SystemRoot%\" -Replace "$(${ENV:ProgramFiles(x86)}.Replace("\","\\").Replace("(","\(").Replace(")","\)"))\\", "%ProgramFiles(x86)%\" -Replace "$($ENV:ProgramFiles.Replace("\","\\"))\\", "%ProgramFiles%\"
    Package       = $ApplicationFilter.Package
    Service       = $ServiceFilter.Service
    InterfaceAlias   = StringArrayToList $InterfaceFilter.InterfaceAlias
    InterfaceType    = $InterfaceTypeFilter.InterfaceType
    LocalUser      = $SecurityFilter.LocalUser
    RemoteUser     = $SecurityFilter.RemoteUser
    RemoteMachine    = $SecurityFilter.RemoteMachine
    Authentication   = $SecurityFilter.Authentication
    Encryption     = $SecurityFilter.Encryption
    OverrideBlockRules = $SecurityFilter.OverrideBlockRules
  }

  # add to array with rules
  $FirewallRuleSet += $HashProps
}

$FirewallRuleSet | ConvertTo-CSV -NoTypeInformation -Delimiter ";" | Set-Content $CSVFile



Write-Host "#########>Take Antivirus Information<#########" -ForegroundColor DarkGreen

# Initialize an empty array to store results
$resultsAV = @()

# Define registry paths for 32-bit and 64-bit software installations
$regPathList = @(
    "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    "Registry::HKEY_LOCAL_MACHINE\SOFTWARE",
    "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node"
)

# Define keywords related to antivirus software
$antivirusKeywords = "(?i)antivirus|EPP|EDR|security|malware|defender|sophos|mcafee|kaspersky|symantec|norton|avast|avg|bitdefender|eset|trend micro|panda|f-secure|webroot|comodo|drweb|zonealarm|bullguard|360 total security|qihoo|g data|avira|emisoft|fortinet|norman|secureaplus|viper|quick heal|clamwin|adaware|cybereason|CrowdStrike|csfalconservice"

# List of common antivirus service names
$antivirusServices = @(
    "WinDefend",                # Windows Defender
    "mcshield",                 # McAfee
    "avastsvc",                 # Avast
    "avgsvc",                   # AVG
    "bdservicehost",            # Bitdefender
    "kavsvc",                   # Kaspersky
    "SepMasterService",         # Symantec Endpoint Protection
    "Sophos Anti-Virus status reporter", # Sophos
    "NortonSecurity",           # Norton
    "ESETService",              # ESET
    "TmListen",                 # Trend Micro
    "Panda Endpoint Agent",     # Panda
    "fsma",                     # F-Secure
    "wrsvc",                    # Webroot
    "cmdagent",                 # Comodo
    "MBAMService",              # Malwarebytes
    "DrWeb",                    # Dr.Web
    "ZoneAlarm",                # ZoneAlarm
    "BullGuard",                # BullGuard
    "360rp",                    # 360 Total Security
    "QHActiveDefense",          # Qihoo 360
    "GDataSecurityService",     # G Data
    "Avira.ServiceHost",        # Avira
    "a2service",                # Emsisoft
    "fortiscanservice",         # Fortinet
    "zanda",                    # Norman Security Suite
    "SecureAPlusService",       # SecureAPlus
    "SBAMSvc",                  # VIPRE
    "QHActiveDefense",          # Quick Heal
    "ClamWin",                  # ClamWin
    "AdAwareService",           # Ad-Aware
    "CybereasonRansomFree",     # Cybereason RansomFree
    "sentinelagent",            # SentinelOne
    "MsMpEng",                  # Microsoft Security Essentials (also used by Windows Defender)
    "eScanWinService",          # MicroWorld
    "savservice",               # Sophos Anti-Virus
    "Tmlisten",                 # Trend Micro Security
    "TmProxy",                  # Trend Micro Security
    "PccNTMon",                 # Trend Micro Security
    "PccSvcFactory",            # Trend Micro Security
    "ds_agent",                 # Trend Micro Security
    "ds_client",                # Trend Micro Security
    "CrowdStrike",       # CrowdStrike
    "csfalconservice",   # CrowdStrike Falcon
    "MBAMService",       # Malwarebytes Anti-Malware Service
    "MBAMTray",          # Malwarebytes Tray Application
    "MBAMWebProtection"  # Malwarebytes Web Protection Service
)

# Define false positive keywords
$falsePositiveAntivirus = "(?i)OneDrive|Microsoft Office|Teams|Visual Studio"

# Check for third-party antivirus software
foreach ($reg in $regPathList) {
    # Retrieve all subkeys in the current registry path
    $key = Get-ChildItem -Path $reg -ErrorAction SilentlyContinue
    
    foreach ($subkey in $key) {
        # Get properties of each subkey
        $subkeyProps = Get-ItemProperty -Path $subkey.PSPath -ErrorAction SilentlyContinue | Select-Object -Property DisplayName, DisplayVersion, Comments, InstallDate
        # $subkeyProps

        # Convert InstallDate to a datetime object if it exists
        $installTimestamp = $null
        if ($subkeyProps.InstallDate) {
            $installTimestamp = Get-Date -Year $subkeyProps.InstallDate.Substring(0,4) -Month $subkeyProps.InstallDate.Substring(4,2) -Day $subkeyProps.InstallDate.Substring(6,2)
        }

        # Check for security-related keywords in DisplayName or Comments
        if (($subkeyProps.DisplayName -match $antivirusKeywords -or $subkeyProps.Comments -match $antivirusKeywords) -and !($subkeyProps.DisplayName -match $falsePositiveAntivirus)) {
            # Initialize status variable
            $status = "Unknown"
            
            # Check if there's a service for this antivirus product
            $matchingServices = Get-Service -ErrorAction SilentlyContinue | Where-Object { $antivirusServices -contains $_.Name }
            foreach ($service in $matchingServices) {
                # if ($subkeyProps.DisplayName -match $service.DisplayName) {
                    $status = $service.Status
                    break
                # }
            }

            Write-Output "Found antivirus product: $($subkeyProps.DisplayName)"

            # Create a custom object for the found antivirus product
            $resultsAV += [PSCustomObject]@{
                Product  = $subkeyProps.DisplayName
                Version  = $subkeyProps.DisplayVersion
                Status   = $status
                Comments = $subkeyProps.Comments
                InstallTimestamp = $installTimestamp
            }
        }
    }
}

# Check if Windows Defender is installed and running
$defenderService = Get-Service -Name "WinDefend" -ErrorAction SilentlyContinue
if ($defenderService -and $defenderService.Status -eq 'Running') {
  # Retrieve the InstallTime from the registry  
  $installTimeRaw = (Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender" -ErrorAction SilentlyContinue).InstallTime

  # Convert the byte array to an Int64 (64-bit integer)
  $installTimeInt64 = [BitConverter]::ToInt64($installTimeRaw, 0)

  # Convert the Int64 value to a DateTime object
  $installTimeConverted = [System.DateTime]::FromFileTime($installTimeInt64)

  $defenderVersion = (Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Signature Updates" -ErrorAction SilentlyContinue).AVSignatureVersion
  Write-Output "Windows Defender is running, version: $defenderVersion"
  $resultsAV += [PSCustomObject]@{
      Product  = "Windows Defender"
      Version  = $defenderVersion
      Status  = $defenderService.Status
      Comments = "Built-in Windows antivirus solution"
      InstallTimestamp = $installTimeConverted
    }
} else {
    # Check the status of Windows Defender Antivirus on Windows Server
    $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue

    # Retrieve the InstallTime from the registry  
    $installTimeRaw = (Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender" -ErrorAction SilentlyContinue).InstallTime

    # Convert the byte array to an Int64 (64-bit integer)
    $installTimeInt64 = [BitConverter]::ToInt64($installTimeRaw, 0)

    # Convert the Int64 value to a DateTime object
    $installTimeConverted = [System.DateTime]::FromFileTime($installTimeInt64)

    if ($defenderStatus) {
        Write-Output "Windows Defender status found, version: $($defenderStatus.AVSignatureVersion)"
        $resultsAV += [PSCustomObject]@{
            Product  = "Windows Defender"
            Version  = $defenderStatus.AntispywareSignatureVersion
            Status   = $defenderService.Status
            Comments = "Built-in Windows antivirus solution"
            InstallTimestamp = $installTimeConverted
        }
    } else {
        Write-Output "Windows Defender not detected"
    }
}

$CSVFileAntivirus = "./Antivirus-" + "$OSName" + ".csv"

if ($resultsAV.count -ge 1) { 
  $resultsAV | Export-Csv -NoTypeInformation $CSVFileAntivirus
} else {
  Write-Host "Antivirus software not detected, please check manually" -ForegroundColor Red
}


#Audit share present on the server 

Write-Host "#########>Take Share Information<#########" -ForegroundColor DarkGreen
$filenameShare = "./SHARE " + "$OSName" + ".csv"
  
function addShare {
  param([string]$NS, [string]$CS, [string]$US, [string]$TS, [string]$NDS)
  $d = New-Object PSObject
  $d | Add-Member -Name "Share Name" -MemberType NoteProperty -Value $NS
  $d | Add-Member -Name "Share Path "-MemberType NoteProperty -Value $CS
  $d | Add-Member -Name "Account Name "-MemberType NoteProperty -Value $US
  $d | Add-Member -Name "AccessControlType"-MemberType NoteProperty -Value $TS
  $d | Add-Member -Name "AccessRight"-MemberType NoteProperty -Value $NDS
  return $d
}
$tableShare = @()
    
$listShare = Get-SmbShare 
  
  
foreach ( $share in $listShare) {
  $droits = Get-SmbShareAccess $share.name
  
  foreach ( $droit in $droits) {
    $tableShare += addShare -NS $share.name -CS $share.path -US $droit.AccountName -TS $droit.AccessControlType -NDS $droit.AccessRight
  }
}

$tableShare | ConvertTo-CSV -NoTypeInformation -Delimiter ";" | Set-Content $filenameShare

#Audit Appdata 
Write-Host "#########>Take Appdata Information<#########" -ForegroundColor DarkGreen
$pathProfiles = (Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList").ProfilesDirectory


$presentProfile = Get-ChildItem -Path $pathProfiles 
  
$resultAPP = @()
$filenameAPP = "./APPDATA" + "$OSName" + ".csv"
  
  
foreach ($profil in $presentProfile) {
  $verifAppdata = Test-Path -Path $pathProfiles\$profil\Appdata
  
  if ($verifAppdata -eq $true) {
    $result = Get-ChildItem -Path $pathProfiles\$profil\Appdata -Recurse -Include *.bat, *.exe, *.ps1, *.ps1xml, *.PS2, *.PS2XML, *.psc1, *.PSC2, *.msi, *.py, *.pif, *.MSP , *.COM, *.SCR, *.hta, *.CPL, *.MSC, *.JAR, *.VB, *.VBS, *.VBE, *.JS, *.JSE, *.WS, *.wsf, *.wsc, *.wsh, *.msh, *.MSH1, *.MSH2, *.MSHXML, *.MSH1XML, *.MSH2XML, *.scf, *.REG, *.INF   | Select-Object Name, Directory, Fullname 
  
    foreach ($riskyfile in $result) {
      $signature = Get-FileHash -Algorithm SHA256 $riskyfile.Fullname
      $resultApptemp = [PSCustomObject]@{
                          Name  = $riskyfile.Name
                          Directory = $riskyfile.Directory
                          Path = $riskyfile.Fullname
                          Signature = $signature.Hash
                          Profil= $profil.name
                        }
      $resultAPP +=$resultApptemp
    }
  }
}

$resultAPP
$resulatCount = $resultAPP |Measure-Object 
$resulatCount = $resulatCount.Count
    
if ($resulatCount -gt 0) {
  $resultAPP | Export-Csv -NoTypeInformation $filenameAPP
}


  
#Check feature and optionnal who are installed 
Write-Host "#########>Take Feature and Optionnal Feature Information<#########" -ForegroundColor DarkGreen

$filenameFeature = "./Feature-" + "$OSName" + ".txt"
$filenameOptionnalFeature = "./OptionnalFeature-" + "$OSName" + ".txt" 

if ( $OSversion -match "Server") {
  #Import serverManger
  import-module servermanager
  
  Get-WindowsFeature | Where-Object {$_.Installed -eq $True} |Format-Table * -Autosize >> ./$filenameFeature   
}

Get-WindowsOptionalFeature -Online | Where-Object {$_.State -eq "Enabled"} |Format-Table * -Autosize >> $filenameOptionnalFeature

#Check installed software
Write-Host "#########>Take Software Information<#########" -ForegroundColor DarkGreen
$filenameInstall = "./Installed-software- " + "$OSName" + ".csv"

$installedsoftware = Get-WmiObject win32_product | Select-Object Name, Caption, Description, InstallLocation, InstallSource, InstallDate, PackageName, Version

$installedsoftware | ConvertTo-CSV -NoTypeInformation -Delimiter ";" | Set-Content $filenameInstall
#Get system Info 
Write-Host "#########>Take System Information<#########" -ForegroundColor DarkGreen
$filenameSystem = "./systeminfo- " + "$OSName" + ".txt"
systeminfo > $filenameSystem 


#Microsoft Update Liste 
Write-Host "#########>Take Update Information<#########" -ForegroundColor DarkGreen
$filenameUpdate = "./systemUpdate- " + "$OSName" + ".html"
wmic qfe list brief /format:htable > $filenameUpdate


#Check installed Service
Write-Host "#########>Take Service Information<#########" -ForegroundColor DarkGreen
$filenameservice = "./Service- " + "$OSName" + ".csv"

Get-WmiObject win32_service | Select-Object Name, DisplayName, State, StartName, StartMode, PathName |Export-Csv -Delimiter ";" $filenameservice -NoTypeInformation

#Check Scheduled task
Write-Host "#########>Take Scheduled task Information<#########" -ForegroundColor DarkGreen

$filenamettache = "./Scheduled-task- " + "$OSName" + ".csv"
$tabletache = Get-ScheduledTask |Select-Object -Property *
$resultTask= @()

foreach ($tache in $tabletache) {
  $taskactions = Get-ScheduledTask $tache.Taskname |Select-Object -ExpandProperty Actions

  foreach ( $taskaction in $taskactions ) {
    $resultTasktemp = [PSCustomObject]@{
                                Task_name = $tache.Taskname
                                Task_URI = $tache.URI
                                Task_state = $tache.State
                                Task_Author = $tache.Author
                                Task_Description = $tache.Description
                                Task_action = $taskaction.Execute 
                                Task_action_Argument = $taskaction.Arguments
                                Task_Action_WorkingDirectory = $taskaction.WorkingDirectory
                              }
    $resultTask += $resultTasktemp
  }
}

$resultTask

$resultTask | Export-Csv -NoTypeInformation $filenamettache

#check net accounts intel
Write-Host "#########>Take Service Information<#########" -ForegroundColor DarkGreen

$filenameNetAccount = "./AccountsPolicy-" + "$OSName" + ".txt"
net accounts > $filenameNetAccount

#Check listen port 
Write-Host "#########>Take Port listening Information<#########" -ForegroundColor DarkGreen

$filenamePort = "./Listen-port- " + "$OSName" + ".csv"
$listport = Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, State, OwningProcess
"LocalAddress;LocalPort;State;OwningProcess;Path" > $filenamePort

foreach ($port in $listport) {
  $exepath = Get-Process -PID $port.OwningProcess |Select-Object Path
  $port.LocalAddress + ";" + $port.LocalPort + ";" + $port.State + ";" + $exepath.path >> $filenamePort
}

#List all local user 
# Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount=True"
$listlocaluser = Get-WmiObject -Class Win32_UserAccount

foreach ($user in $listlocaluser) {
  if ( $user.sid -like "*-500") {
    $nomcompteadmin = $user.Name
    # REMOVE FROM CIS

    # $statutcompteadmin = $user.Disabled
    # if ($statutcompteadmin -eq $true) {
    #   $adminstate = "disable"
    # }
    # else {
    #   $adminstate = "enable"
    # }
  } elseif ($user.sid -like "*-501") {
      $nomcompteguest = $user.Name
      $statutcompteguest = $user.Disabled
      
      if ($statutcompteguest -eq $true) {
        $gueststate = "disable"
      } else {
        $gueststate = "enable"
      }
    }
}

$listlocaluser > "localuser-$OSName.txt"

#Check Startup registry key
Write-Host "#########>Take Startup Registry Information<#########" -ForegroundColor DarkGreen
$filenameStartup = "./Startup- " + "$OSName" + ".txt"
"HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" >> $filenameStartup
Get-ItemProperty -Path "Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" | Select-Object * -exclude PSPath,PSParentPath, PSChildName, PSProvider, PSDrive >> $filenameStartup
"HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce" >> $filenameStartup
Get-ItemProperty -Path "Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce" | Select-Object * -exclude PSPath,PSParentPath, PSChildName, PSProvider, PSDrive >> $filenameStartup
"HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows" >> $filenameStartup
Get-ItemProperty -Path "Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows" | Select-Object * -exclude PSPath,PSParentPath, PSChildName, PSProvider, PSDrive >> $filenameStartup
"HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" >> $filenameStartup
Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run" | Select-Object * -exclude PSPath,PSParentPath, PSChildName, PSProvider, PSDrive >> $filenameStartup
"HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" >> $filenameStartup
Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce" | Select-Object * -exclude PSPath,PSParentPath, PSChildName, PSProvider, PSDrive >> $filenameStartup



$checkConditions = @("Not Configured", "NotConfigured", "Not Configure", "Not Defined", "NotDefined", "Not Define", $null, "")


Write-Host "#########>Begin CIS Audit<#########" -ForegroundColor Green

#Check Password Policy
Write-Host "#########>Begin Password Policy Audit<#########" -ForegroundColor DarkGreen

#Check Enforce Password History
$indextest += 1
$id = "PP" + "$indextest"
$chaine = $null
$traitement = $null

$chaine = "$id" + ";" + "(L1) Ensure 'Enforce password history' is set to '24 or more password(s)'" + ";"
$traitement = Get-Content $seceditfile |Select-String "PasswordHistorySize"

if ($checkConditions -notcontains $traitement) {
  $traitement = $traitement
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename

#Check Maximum Password age 
$indextest += 1
$id = "PP" + "$indextest"
$chaine = $null
$traitement = $null

$chaine = "$id" + ";" + "(L1) Ensure 'Maximum password age' is set to '365 or fewer days, but not 0'" + ";"
$traitement = Get-Content $seceditfile |Select-String "MaximumPasswordAge" | Select-Object -First 1

if ($checkConditions -notcontains $traitement) {
  $traitement = $traitement
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename

#Check Minimum Password Age
$indextest += 1
$id = "PP" + "$indextest"
$chaine = $null
$traitement = $null

$chaine = "$id" + ";" + "(L1) Ensure 'Minimum password age' is set to '1 or more day(s)'" + ";"
$traitement = Get-Content $seceditfile |Select-String "MinimumPasswordAge"

if ($checkConditions -notcontains $traitement) {
  $traitement = $traitement
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename

# Check Minimum Password Length
$indextest += 1
$id = "PP" + "$indextest"
$chaine = $null
$traitement = $null

$chaine = "$id" + ";" + "(L1) Ensure 'Minimum password length' is set to 14 or more character(s)'" + ";"
$traitement = Get-Content $seceditfile |Select-String "MinimumPasswordLength"

if ($checkConditions -notcontains $traitement) {
  $traitement = $traitement
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename

#Check Password must meet complexity requirements
$indextest += 1
$id = "PP" + "$indextest"
$chaine = $null
$traitement = $null

$chaine = "$id" + ";" + "(L1) Ensure 'Password must meet complexity requirements' is set to 'Enabled' (Value must be 1)" + ";"
$traitement = Get-Content $seceditfile |Select-String "PasswordComplexity"

if ($checkConditions -notcontains $traitement) {
  $traitement = $traitement
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename

#Check Store passwords using reversible encryption
$indextest += 1
$id = "PP" + "$indextest"
$chaine = $null
$traitement = $null

$chaine = "$id" + ";" + "(L1) Ensure 'Store passwords using reversible encryption' is set to 'Disabled' (Value must be 0)" + ";"
$traitement = Get-Content $seceditfile |Select-String "ClearTextPassword"

if ($checkConditions -notcontains $traitement) {
  $traitement = $traitement
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename


#Check Account Lockout Policy
Write-Host "#########>Begin Account Lockout Policy Audit<#########" -ForegroundColor DarkGreen

#Check Account lockout duration
$indextest += 1
$chaine = $null
$traitement = $null
$id = "ALP" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Account lockout duration' is set to '15 or more minute(s)'" + ";"
$traitement = Get-Content $filenameNetAccount |Select-String -Pattern '(Lockout duration)'

if ($checkConditions -notcontains $traitement) {
  $traitement = $traitement
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename

#Check Account lockout threshold
$indextest += 1
$chaine = $null
$traitement = $null
$id = "ALP" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Account lockout threshold' is set to 5 or fewer invalid logon attempt(s), but not 0'" + ";"
$traitement = Get-Content $filenameNetAccount |Select-String -Pattern '(Lockout threshold)'

if ($checkConditions -notcontains $traitement) {
  $traitement = $traitement
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename

#Check Admin account lockout 
$indextest += 1
$chaine = $null
$traitement = $null
$id = "ALP" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Allow Administrator account lockout' is set to 'Enabled' (MS Only)" + ";"
$traitement = Get-Content $filenameNetAccount |Select-String -Pattern "(Administrator account lockout)"

if ($checkConditions -notcontains $traitement) {
  $traitement = $traitement
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename

#Check Reset account lockout 
$indextest += 1
$chaine = $null
$traitement = $null
$id = "ALP" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Reset account lockout counter after' is set to 15 or more minute(s)'" + ";"
$traitement = Get-Content $filenameNetAccount |Select-String -Pattern "(Account lockout counter)|(Lockout observation window)"

if ($checkConditions -notcontains $traitement) {
  $traitement = $traitement
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename


#Check User Rights Assignment Audit
Write-Host "#########>Begin User Rights Assignment Audit<#########" -ForegroundColor DarkGreen

#Check Access Credential Manager 
$indextest += 1
$chaine = $null
$traitement = $null
$id = "URA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Access Credential Manager as a trusted caller' is set to 'No One' (Value must be empty)" + ";"
$traitement = Get-Content $seceditfile |Select-String "SeTrustedCredManAccessPrivilege"

if ($checkConditions -notcontains $traitement) {
  $traitement = $traitement
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename

#Check Access this computer from the network (DC)
$indextest += 1
$chaine = $null
$traitement = $null
$id = "URA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Access this computer from the network' is set to 'Administrators, Authenticated Users, ENTERPRISE DOMAIN CONTROLLERS' (DC only)" + ";"
$chainSID = Get-Content $seceditfile |Select-String "SeNetworkLogonRight" 

if ($checkConditions -notcontains $chainSID) {
  $chainSID = $chainSID.line
  $traitement = "SeNetworkLogonRight" + ":"
  $traitement += Format-SID $chainSID
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename

#Check Access this computer from the network (MS)
$indextest += 1
$chaine = $null
$traitement = $null
$id = "URA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Access this computer from the network' is set to 'Administrators, Authenticated Users' (MS only)" + ";"
$chainSID = Get-Content $seceditfile |Select-String "SeNetworkLogonRight" 

if ($checkConditions -notcontains $chainSID) {
  $chainSID = $chainSID.line
  $traitement = "SeNetworkLogonRight" + ":"
  $traitement += Format-SID $chainSID
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename


#Check Act as part of the operating system
$indextest += 1
$chaine = $null
$traitement = $null
$id = "URA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Act as part of the operating system' is set to 'No One' (Must be empty)" + ";"
$chainSID = Get-Content $seceditfile |Select-String "SeTcbPrivilege"

if ($checkConditions -notcontains $chainSID) {
  $chainSID = $chainSID.line
  $traitement = "SeTcbPrivilege" + ":"
  $traitement += Format-SID $chainSID
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename


#Check Add workstations to domain (DC)
$indextest += 1
$chaine = $null
$traitement = $null
$id = "URA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Add workstations to domain' is set to 'Administrators' (DC only) " + ";"
$chainSID = Get-Content $seceditfile |Select-String "SeMachineAccountPrivilege"

if ($checkConditions -notcontains $chainSID) {
  $chainSID = $chainSID.line
  $traitement = "SeMachineAccountPrivilege" + ":"
  $traitement += Format-SID $chainSID
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename


#Check Adjust memory quotas for a process
$indextest += 1
$chaine = $null
$traitement = $null
$id = "URA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Adjust memory quotas for a process' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE'" + ";"
$chainSID = Get-Content $seceditfile |Select-String "SeIncreaseQuotaPrivilege"

if ($checkConditions -notcontains $chainSID) {
  $chainSID = $chainSID.line
  $traitement = "SeIncreaseQuotaPrivilege" + ":"
  $traitement += Format-SID $chainSID
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename

#Allow log on locally (DC)
$indextest += 1
$chaine = $null
$traitement = $null
$id = "URA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Allow log on locally' is set to 'Administrators, ENTERPRISE DOMAIN CONTROLLERS' (DC only)" + ";"
$chainSID = Get-Content $seceditfile |Select-String "SeInteractiveLogonRight" 

if ($checkConditions -notcontains $chainSID) {
  $chainSID = $chainSID.line
  $traitement = "SeInteractiveLogonRight" + ":"
  $traitement += Format-SID $chainSID
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename

#Allow log on locally (MS)
$indextest += 1
$chaine = $null
$traitement = $null
$id = "URA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Allow log on locally' is set to 'Administrators' (MS only)" + ";"
$chainSID = Get-Content $seceditfile |Select-String "SeInteractiveLogonRight" 

if ($checkConditions -notcontains $chainSID) {
  $chainSID = $chainSID.line
  $traitement = "SeInteractiveLogonRight" + ":"
  $traitement += Format-SID $chainSID
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename

#Allow log on through Remote Desktop Services (DC)
$indextest += 1
$chaine = $null
$traitement = $null
$id = "URA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Allow log on through Remote Desktop Services' is set to 'Administrators' (DC only)" + ";"
$chainSID = Get-Content $seceditfile |Select-String "SeRemoteInteractiveLogonRight" 

if ($checkConditions -notcontains $chainSID) {
  $chainSID = $chainSID.line
  $traitement = "SeRemoteInteractiveLogonRight" + ":"
  $traitement += Format-SID $chainSID
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename


#Allow log on through Remote Desktop Services (MS)
$indextest += 1
$chaine = $null
$traitement = $null
$id = "URA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Allow log on through Remote Desktop Services' is set to 'Administrators, Remote Desktop Users' (MS only)" + ";"
$chainSID = Get-Content $seceditfile |Select-String "SeRemoteInteractiveLogonRight" 

if ($checkConditions -notcontains $chainSID) {
  $chainSID = $chainSID.line
  $traitement = "SeRemoteInteractiveLogonRight" + ":"
  $traitement += Format-SID $chainSID
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename

#Ensure Back up files and directories
$indextest += 1
$chaine = $null
$traitement = $null
$id = "URA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Back up files and directories' is set to 'Administrators'" + ";"
$chainSID = Get-Content $seceditfile |Select-String "SeBackupPrivilege" 

if ($checkConditions -notcontains $chainSID) {
  $chainSID = $chainSID.line
  $traitement = "SeBackupPrivilege" + ":"
  $traitement += Format-SID $chainSID
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename

#Change the system time
$indextest += 1
$chaine = $null
$traitement = $null
$id = "URA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Change the system time' is set to 'Administrators, LOCAL SERVICE'" + ";"
$chainSID = Get-Content $seceditfile |Select-String "SeSystemtimePrivilege" 

if ($checkConditions -notcontains $chainSID) {
  $chainSID = $chainSID.line
  $traitement = "SeSystemtimePrivilege" + ":"
  $traitement += Format-SID $chainSID
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename


#Change the time zone
$indextest += 1
$chaine = $null
$traitement = $null
$id = "URA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Change the time zone' is set to 'Administrators, LOCAL SERVICE'" + ";"
$chainSID = Get-Content $seceditfile |Select-String "SeTimeZonePrivilege" 

if ($checkConditions -notcontains $chainSID) {
  $chainSID = $chainSID.line
  $traitement = "SeTimeZonePrivilege" + ":"
  $traitement += Format-SID $chainSID
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename

#Create a pagefile
$indextest += 1
$chaine = $null
$traitement = $null
$id = "URA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Create a pagefile' is set to 'Administrators'" + ";"
$chainSID = Get-Content $seceditfile |Select-String "SeCreatePagefilePrivilege" 

if ($checkConditions -notcontains $chainSID) {
  $chainSID = $chainSID.line
  $traitement = "SeCreatePagefilePrivilege" + ":"
  $traitement += Format-SID $chainSID
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename


#Create a token object
$indextest += 1
$chaine = $null
$traitement = $null
$id = "URA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Create a token object' is set to 'No One'" + ";"
$chainSID = Get-Content $seceditfile |Select-String "SeCreateTokenPrivilege" 

if ($checkConditions -notcontains $chainSID) {
  $chainSID = $chainSID.line
  $traitement = "SeCreateTokenPrivilege" + ":"
  $traitement += Format-SID $chainSID
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename


#Create global objects
$indextest += 1
$chaine = $null
$traitement = $null
$id = "URA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Create global objects' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'" + ";"
$chainSID = Get-Content $seceditfile |Select-String "SeCreateGlobalPrivilege" 

if ($checkConditions -notcontains $chainSID) {
  $chainSID = $chainSID.line
  $traitement = "SeCreateGlobalPrivilege" + ":"
  $traitement += Format-SID $chainSID
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename


#Create permanent shared objects'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "URA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Create permanent shared objects' is set to 'No One'" + ";"
$chainSID = Get-Content $seceditfile |Select-String "SeCreatePermanentPrivilege" 

if ($checkConditions -notcontains $chainSID) {
  $chainSID = $chainSID.line
  $traitement = "SeCreatePermanentPrivilege" + ":"
  $traitement += Format-SID $chainSID
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename


#Create symbolic links (DC)
$indextest += 1
$chaine = $null
$traitement = $null
$id = "URA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Create symbolic links' is set to 'Administrators' (DC only)" + ";"
$chainSID = Get-Content $seceditfile |Select-String "SeCreateSymbolicLinkPrivilege" 

if ($checkConditions -notcontains $chainSID) {
  $chainSID = $chainSID.line
  $traitement = "SeCreateSymbolicLinkPrivilege" + ":"
  $traitement += Format-SID $chainSID
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename


#Create symbolic links (MS)
$indextest += 1
$chaine = $null
$traitement = $null
$id = "URA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Create symbolic links' is set to 'Administrators, NT VIRTUAL MACHINE\Virtual Machines' (MS only)" + ";"
$chainSID = Get-Content $seceditfile |Select-String "SeCreateSymbolicLinkPrivilege" 

if ($checkConditions -notcontains $chainSID) {
  $chainSID = $chainSID.line
  $traitement = "SeCreateSymbolicLinkPrivilege" + ":"
  $traitement += Format-SID $chainSID
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename


#Debug programs
$indextest += 1
$chaine = $null
$traitement = $null
$id = "URA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Debug programs' is set to 'Administrators'" + ";"
$chainSID = Get-Content $seceditfile |Select-String "SeDebugPrivilege" 

if ($checkConditions -notcontains $chainSID) {
  $chainSID = $chainSID.line
  $traitement = "SeDebugPrivilege" + ":"
  $traitement += Format-SID $chainSID
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename


#Deny access to this computer from the network (DC)
$indextest += 1
$chaine = $null
$traitement = $null
$id = "URA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Deny access to this computer from the network' to include 'Guests' (DC only)" + ";"
$chainSID = Get-Content $seceditfile |Select-String "SeDenyNetworkLogonRight" 

if ($checkConditions -notcontains $chainSID) {
  $chainSID = $chainSID.line
  $traitement = "SeDenyNetworkLogonRight" + ":"
  $traitement += Format-SID $chainSID
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename


#Deny access to this computer from the network (MS)
$indextest += 1
$chaine = $null
$traitement = $null
$id = "URA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Deny access to this computer from the network' to include 'Guests, Local account and member of Administrators group' (MS only)" + ";"
$chainSID = Get-Content $seceditfile |Select-String "SeDenyNetworkLogonRight" 

if ($checkConditions -notcontains $chainSID) {
  $chainSID = $chainSID.line
  $traitement = "SeDenyNetworkLogonRight" + ":"
  $traitement += Format-SID $chainSID
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename


#Deny log on as a batch job
$indextest += 1
$chaine = $null
$traitement = $null
$id = "URA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Deny log on as a batch job' to include 'Guests'" + ";"
$chainSID = Get-Content $seceditfile |Select-String "SeDenyBatchLogonRight" 

if ($checkConditions -notcontains $chainSID) {
  $chainSID = $chainSID.line
  $traitement = "SeDenyBatchLogonRight" + ":"
  $traitement += Format-SID $chainSID
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename


#Deny log on as a service
$indextest += 1
$chaine = $null
$traitement = $null
$id = "URA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Deny log on as a service' to include 'Guests'" + ";"
$chainSID = Get-Content $seceditfile |Select-String "SeDenyServiceLogonRight" 

if ($checkConditions -notcontains $chainSID) {
  $chainSID = $chainSID.line
  $traitement = "SeDenyServiceLogonRight" + ":"
  $traitement += Format-SID $chainSID
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename


#Deny log on locally
$indextest += 1
$chaine = $null
$traitement = $null
$id = "URA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Deny log on locally' to include 'Guests'" + ";"
$chainSID = Get-Content $seceditfile |Select-String "SeDenyInteractiveLogonRight" 

if ($checkConditions -notcontains $chainSID) {
  $chainSID = $chainSID.line
  $traitement = "SeDenyInteractiveLogonRight" + ":"
  $traitement += Format-SID $chainSID
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename


#Deny log on through Remote Desktop Services (DC only)
$indextest += 1
$chaine = $null
$traitement = $null
$id = "URA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Deny log on through Remote Desktop Services' to include 'Guests' (DC only)" + ";"
$chainSID = Get-Content $seceditfile |Select-String "SeDenyRemoteInteractiveLogonRight" 

if ($checkConditions -notcontains $chainSID) {
  $chainSID = $chainSID.line
  $traitement = "SeDenyRemoteInteractiveLogonRight" + ":"
  $traitement += Format-SID $chainSID
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename


#Deny log on through Remote Desktop Services (MS only)
$indextest += 1
$chaine = $null
$traitement = $null
$id = "URA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Deny log on through Remote Desktop Services' is set to 'Guests, Local account' (MS only)" + ";"
$chainSID = Get-Content $seceditfile |Select-String "SeDenyRemoteInteractiveLogonRight" 

if ($checkConditions -notcontains $chainSID) {
  $chainSID = $chainSID.line
  $traitement = "SeDenyRemoteInteractiveLogonRight" + ":"
  $traitement += Format-SID $chainSID
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename


#Enable computer and user accounts to be trusted for delegation (DC only)
$indextest += 1
$chaine = $null
$traitement = $null
$id = "URA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Enable computer and user accounts to be trusted for delegation' is set to 'Administrators' (DC only)" + ";"
$chainSID = Get-Content $seceditfile |Select-String "SeEnableDelegationPrivilege" 

if ($checkConditions -notcontains $chainSID) {
  $chainSID = $chainSID.line
  $traitement = "SeEnableDelegationPrivilege" + ":"
  $traitement += Format-SID $chainSID
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename


#Enable computer and user accounts to be trusted for delegation (MS only)
$indextest += 1
$chaine = $null
$traitement = $null
$id = "URA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Enable computer and user accounts to be trusted for delegation' is set to 'No One' (MS only)" + ";"
$chainSID = Get-Content $seceditfile |Select-String "SeEnableDelegationPrivilege" 

if ($checkConditions -notcontains $chainSID) {
  $chainSID = $chainSID.line
  $traitement = "SeEnableDelegationPrivilege" + ":"
  $traitement += Format-SID $chainSID
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename

#Force shutdown from a remote system
$indextest += 1
$chaine = $null
$traitement = $null
$id = "URA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Force shutdown from a remote system' is set to 'Administrators'" + ";"
$chainSID = Get-Content $seceditfile |Select-String "SeRemoteShutdownPrivilege"

if ($checkConditions -notcontains $chainSID) {
  $chainSID = $chainSID.line
  $traitement = "SeRemoteShutdownPrivilege" + ":"
  $traitement += Format-SID $chainSID
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename

#Generate security audits'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "URA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Generate security audits' is set to 'LOCAL SERVICE, NETWORK SERVICE'" + ";"
$chainSID = Get-Content $seceditfile |Select-String "SeAuditPrivilege" 

if ($checkConditions -notcontains $chainSID) {
  $chainSID = $chainSID.line
  $traitement = "SeAuditPrivilege" + ":"
  $traitement += Format-SID $chainSID
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename

#Impersonate a client after authentication (DC only)
$indextest += 1
$chaine = $null
$traitement = $null
$id = "URA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Impersonate a client after authentication' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE' (DC only)" + ";"
$chainSID = Get-Content $seceditfile |Select-String "SeImpersonatePrivilege" 

if ($checkConditions -notcontains $chainSID) {
  $chainSID = $chainSID.line
  $traitement = "SeImpersonatePrivilege" + ":"
  $traitement += Format-SID $chainSID
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename


#Impersonate a client after authentication (MS only)
$indextest += 1
$chaine = $null
$traitement = $null
$id = "URA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Impersonate a client after authentication' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE' and (when the Web Server (IIS) Role with Web Services Role Service is installed) 'IIS_IUSRS' (MS only)" + ";"
$chainSID = Get-Content $seceditfile |Select-String "SeImpersonatePrivilege" 

if ($checkConditions -notcontains $chainSID) {
  $chainSID = $chainSID.line
  $traitement = "SeImpersonatePrivilege" + ":"
  $traitement += Format-SID $chainSID
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename


#Increase scheduling priority
$indextest += 1
$chaine = $null
$traitement = $null
$id = "URA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Increase scheduling priority' is set to 'Administrators, Window Manager\Window Manager Group'" + ";"
$chainSID = Get-Content $seceditfile |Select-String "SeIncreaseBasePriorityPrivilege" 

if ($checkConditions -notcontains $chainSID) {
  $chainSID = $chainSID.line
  $traitement = "SeIncreaseBasePriorityPrivilege" + ":"
  $traitement += Format-SID $chainSID
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename


#Load and unload device drivers
$indextest += 1
$chaine = $null
$traitement = $null
$id = "URA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Load and unload device drivers' is set to 'Administrators'" + ";"
$chainSID = Get-Content $seceditfile |Select-String "SeLoadDriverPrivilege" 

if ($checkConditions -notcontains $chainSID) {
  $chainSID = $chainSID.line
  $traitement = "SeLoadDriverPrivilege" + ":"
  $traitement += Format-SID $chainSID
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename

#Lock pages in memory
$indextest += 1
$chaine = $null
$traitement = $null
$id = "URA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Lock pages in memory' is set to 'No One'" + ";"
$chainSID = Get-Content $seceditfile |Select-String "SeLockMemoryPrivilege" 

if ($checkConditions -notcontains $chainSID) {
  $chainSID = $chainSID.line
  $traitement = "SeLockMemoryPrivilege" + ":"
  $traitement += Format-SID $chainSID
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename


#Log on as a batch job (DC only)
$indextest += 1
$chaine = $null
$traitement = $null
$id = "URA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Log on as a batch job' is set to 'Administrators' (DC Only)" + ";"
$chainSID = Get-Content $seceditfile |Select-String "SeBatchLogonRight" 

if ($checkConditions -notcontains $chainSID) {
  $chainSID = $chainSID.line
  $traitement = "SeBatchLogonRight" + ":"
  $traitement += Format-SID $chainSID
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename


#Manage auditing and security log (DC only)
$indextest += 1
$chaine = $null
$traitement = $null
$id = "URA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Manage auditing and security log' is set to 'Administrators' and (when Exchange is running in the environment) 'Exchange Servers' (DC only)" + ";"
$chainSID = Get-Content $seceditfile |Select-String "SeSecurityPrivilege" 

if ($checkConditions -notcontains $chainSID) {
  $chainSID = $chainSID.line
  $traitement = "SeSecurityPrivilege" + ":"
  $traitement += Format-SID $chainSID
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename


#Manage auditing and security log (MS only)
$indextest += 1
$chaine = $null
$traitement = $null
$id = "URA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Manage auditing and security log' is set to 'Administrators' (MS only)" + ";"
$chainSID = Get-Content $seceditfile |Select-String "SeSecurityPrivilege" 

if ($checkConditions -notcontains $chainSID) {
  $chainSID = $chainSID.line
  $traitement = "SeSecurityPrivilege" + ":"
  $traitement += Format-SID $chainSID
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename

#Modify an object label
$indextest += 1
$chaine = $null
$traitement = $null
$id = "URA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Modify an object label' is set to 'No One'" + ";"
$chainSID = Get-Content $seceditfile |Select-String "SeRelabelPrivilege" 

if ($checkConditions -notcontains $chainSID) {
  $chainSID = $chainSID.line
  $traitement = "SeRelabelPrivilege" + ":"
  $traitement += Format-SID $chainSID
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename

#Modify firmware environment values
$indextest += 1
$chaine = $null
$traitement = $null
$id = "URA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Modify firmware environment values' is set to 'Administrators'" + ";"
$chainSID = Get-Content $seceditfile |Select-String "SeSystemEnvironmentPrivilege" 

if ($checkConditions -notcontains $chainSID) {
  $chainSID = $chainSID.line
  $traitement = "SeSystemEnvironmentPrivilege" + ":"
  $traitement += Format-SID $chainSID
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename

#Perform volume maintenance tasks
$indextest += 1
$chaine = $null
$traitement = $null
$id = "URA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Perform volume maintenance tasks' is set to 'Administrators'" + ";"
$chainSID = Get-Content $seceditfile |Select-String "SeManageVolumePrivilege" 

if ($checkConditions -notcontains $chainSID) {
  $chainSID = $chainSID.line
  $traitement = "SeManageVolumePrivilege" + ":"
  $traitement += Format-SID $chainSID
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename

#Profile single process
$indextest += 1
$chaine = $null
$traitement = $null
$id = "URA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Profile single process' is set to 'Administrators'" + ";"
$chainSID = Get-Content $seceditfile |Select-String "SeProfileSingleProcessPrivilege" 

if ($checkConditions -notcontains $chainSID) {
  $chainSID = $chainSID.line
  $traitement = "SeProfileSingleProcessPrivilege" + ":"
  $traitement += Format-SID $chainSID
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename


#Profile system performance
$indextest += 1
$chaine = $null
$traitement = $null
$id = "URA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Profile system performance' is set to 'Administrators, NT SERVICE\WdiServiceHost'" + ";"
$chainSID = Get-Content $seceditfile |Select-String "SeSystemProfilePrivilege" 

if ($checkConditions -notcontains $chainSID) {
  $chainSID = $chainSID.line
  $traitement = "SeSystemProfilePrivilege" + ":"
  $traitement += Format-SID $chainSID
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename

#Replace a process level token
$indextest += 1
$chaine = $null
$traitement = $null
$id = "URA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Replace a process level token' is set to 'LOCAL SERVICE, NETWORK SERVICE'" + ";"
$chainSID = Get-Content $seceditfile |Select-String "SeAssignPrimaryTokenPrivilege" 

if ($checkConditions -notcontains $chainSID) {
  $chainSID = $chainSID.line
  $traitement = "SeAssignPrimaryTokenPrivilege" + ":"
  $traitement += Format-SID $chainSID
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename

#Restore files and directories'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "URA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Restore files and directories' is set to 'Administrators'" + ";"
$chainSID = Get-Content $seceditfile |Select-String "SeRestorePrivilege" 

if ($checkConditions -notcontains $chainSID) {
  $chainSID = $chainSID.line
  $traitement = "SeRestorePrivilege" + ":"
  $traitement += Format-SID $chainSID
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename

#Shut down the system
$indextest += 1
$chaine = $null
$traitement = $null
$id = "URA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Shut down the system' is set to 'Administrators'" + ";"
$chainSID = Get-Content $seceditfile |Select-String "SeShutdownPrivilege" 

if ($checkConditions -notcontains $chainSID) {
  $chainSID = $chainSID.line
  $traitement = "SeShutdownPrivilege" + ":"
  $traitement += Format-SID $chainSID
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename


#Synchronize directory service data (DC only)
$indextest += 1
$chaine = $null
$traitement = $null
$id = "URA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Synchronize directory service data' is set to 'No One' (DC only)" + ";"
$chainSID = Get-Content $seceditfile |Select-String "SeSyncAgentPrivilege" 

if ($checkConditions -notcontains $chainSID) {
  $chainSID = $chainSID.line
  $traitement = "SeSyncAgentPrivilege" + ":"
  $traitement += Format-SID $chainSID
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename


#Take ownership of files or other objects
$indextest += 1
$chaine = $null
$traitement = $null
$id = "URA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Take ownership of files or other objects' is set to 'Administrators'" + ";"
$chainSID = Get-Content $seceditfile |Select-String "SeTakeOwnershipPrivilege" 

if ($checkConditions -notcontains $chainSID) {
  $chainSID = $chainSID.line
  $traitement = "SeTakeOwnershipPrivilege" + ":"
  $traitement += Format-SID $chainSID
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename



#Checking Accounts
Write-Host "#########>Begin Accounts audit<#########" -ForegroundColor DarkGreen

#Accounts: Block Microsoft accounts' is set to 'Users can't add or log on with Microsoft accounts'
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "AA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Accounts: Block Microsoft accounts' is set to 'Users can't add or log on with Microsoft accounts'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" | Select-Object -ExpandProperty NoConnectedUser

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Ensure 'Accounts: Guest account status' is set to 'Disabled' (MS only)
$indextest += 1
$chaine = $null
$traitement = $null
$id = "AA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Accounts: Guest account status' is set to 'Disabled' (MS only)" + ";"
$traitement = "Default guest Account: " + $nomcompteguest + ", status : $gueststate"

$chaine += $traitement
$chaine>> $filename


#Accounts: Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled'
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "AA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" | Select-Object -ExpandProperty LimitBlankPasswordUse

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Configure 'Accounts: Rename administrator account'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "AA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Configure 'Accounts: Rename administrator account'" + ";"
$traitement = "Default local admin Account: " + $nomcompteadmin 

$chaine += $traitement
$chaine>> $filename

#Configure 'Accounts: Rename guest account'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "AA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Configure 'Accounts: Rename guest account'" + ";"
$traitement = "Default guest Account: " + $nomcompteguest

$chaine += $traitement
$chaine>> $filename


#Checking Audit
Write-Host "#########>Begin Audit Policy Audit<#########" -ForegroundColor DarkGreen

#Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "APA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" | Select-Object -ExpandProperty SCENoApplyLegacyAuditPolicy

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Audit: Shut down system immediately if unable to log security audits' is set to 'Disabled'
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "APA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Audit: Shut down system immediately if unable to log security audits' is set to 'Disabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" | Select-Object -ExpandProperty CrashOnAuditFail

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename



#Checking Devices
Write-Host "#########>Begin Devices Policy Audit<#########" -ForegroundColor DarkGreen

#Devices: Prevent users from installing printer drivers
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "DEV" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Devices: Prevent users from installing printer drivers' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" | Select-Object -ExpandProperty AddPrinterDrivers

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Checking Domain Controller Audit
Write-Host "#########>Begin Domain Controller Policy Audit<#########" -ForegroundColor DarkGreen

#Domain controller: Allow server operators to schedule tasks
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "DCP" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Domain controller: Allow server operators to schedule tasks' is set to 'Disabled' (DC only)" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" | Select-Object -ExpandProperty SubmitControl

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#####MAY NEED TO RECHECK / TO IMPROVE#####
#Domain controller: Allow vulnerable Netlogon secure channel connections
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "DCP" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Domain controller: Allow vulnerable Netlogon secure channel connections' is set to 'Not Configured' (DC Only)" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" | Select-Object -ExpandProperty VulnerableChannelAllowList

if ($exist -eq $true) {
  $traitement = $traitement
}
else {
  $traitement = "Check manually"
}

$chaine += $traitement
$chaine>> $filename
##########################################

#Domain controller: LDAP server channel binding token requirements
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "DCP" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Domain controller: LDAP server channel binding token requirements' is set to 'Always' (DC Only)" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" | Select-Object -ExpandProperty LdapEnforceChannelBinding

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Domain controller: LDAP server signing requirements
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "DCP" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Domain controller: LDAP server signing requirements' is set to 'Require signing' (DC only)" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" | Select-Object -ExpandProperty LDAPServerIntegrity

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Domain controller: Refuse machine account password changes
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "DCP" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Domain controller: Refuse machine account password changes' is set to 'Disabled' (DC only)" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" | Select-Object -ExpandProperty RefusePasswordChange

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Checking Domain Member Audit
Write-Host "#########>Begin Domain Member Policy Audit<#########" -ForegroundColor DarkGreen

#Domain member: Digitally encrypt or sign secure channel data (always) is set to Enable
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "DMP" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Domain member: Digitally encrypt or sign secure channel data (always)' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" | Select-Object -ExpandProperty RequireSignOrSeal

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Domain member: Digitally encrypt secure channel data (when possible)
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "DMP" + "$indextest"

$chaine = "$id" + ";" + "(L1)Ensure 'Domain member: Digitally encrypt secure channel data (when possible)' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" | Select-Object -ExpandProperty SealSecureChannel

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Domain member: Digitally sign secure channel data (when possible)
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "DMP" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Domain member: Digitally sign secure channel data (when possible)' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" | Select-Object -ExpandProperty SignSecureChannel

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Domain member: Disable machine account password changes
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "DMP" + "$indextest"

$chaine = "$id" + ";" + "(L1)Domain member: Disable machine account password changes is set to Disabled, Value must be 0 " + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" | Select-Object -ExpandProperty DisablePasswordChange

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Domain member: Maximum machine account password age' is set to '30 or fewer days, but not 0'
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "DMP" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Domain member: Maximum machine account password age' is set to '30 or fewer days, but not 0'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters" | Select-Object -ExpandProperty MaximumPasswordAge

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Domain member: Require strong (Windows 2000 or later) session key' is set to 'Enabled'
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "DMP" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Domain member: Require strong (Windows 2000 or later) session key' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" | Select-Object -ExpandProperty RequireStrongKey

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename



#Checking Interactive logon
Write-Host "#########>Begin Interactive Logon Audit<#########" -ForegroundColor DarkGreen

#Ensure 'Interactive logon: Do not require CTRL+ALT+DEL' is set to 'Disabled'
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "IL" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Interactive logon: Do not require CTRL+ALT+DEL' is set to 'Disabled' " + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" | Select-Object -ExpandProperty DisableCAD

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Ensure 'Interactive logon: Don't display last signed-in' is set to 'Enabled'
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "IL" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Interactive logon: Don't display last signed-in' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" | Select-Object -ExpandProperty DontDisplayLastUserName

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Interactive logon: Machine inactivity limit'
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "IL" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Interactive logon: Machine inactivity limit' is set to '900 or fewer second(s), but not 0'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" | Select-Object -ExpandProperty InactivityTimeoutSecs

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Configure 'Interactive logon: Message text for users attempting to log on
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "IL" + "$indextest"

$chaine = "$id" + ";" + "(L1) Configure 'Interactive logon: Message text for users attempting to log on'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" | Select-Object -ExpandProperty LegalNoticeText

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Configure 'Interactive logon: Message title for users attempting to log on
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "IL" + "$indextest"

$chaine = "$id" + ";" + "(L1) Configure 'Interactive logon: Message title for users attempting to log on'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" | Select-Object -ExpandProperty LegalNoticeCaption

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Configure Interactive logon: Number of previous logons to cache (in case domain controller is not available) (MS only)
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "IL" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Interactive logon: Number of previous logons to cache (in case domain controller is not available)' is set to '4 or fewer logon(s)' (MS only)" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" | Select-Object -ExpandProperty CachedLogonsCount

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Ensure 'Interactive logon: Prompt user to change password before expiration
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "IL" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Interactive logon: Prompt user to change password before expiration' is set to 'between 5 and 14 days'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" | Select-Object -ExpandProperty PasswordExpiryWarning

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


# Interactive logon: Require Domain Controller Authentication to unlock workstation (MS only)
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "IL" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Interactive logon: Require Domain Controller Authentication to unlock workstation' is set to 'Enabled' (MS only)" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" | Select-Object -ExpandProperty ForceUnlockLogon

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


# Ensure Interactive logon: Smart card removal behavior' is set to 'Lock Workstation' or higher
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "IL" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Interactive logon: Smart card removal behavior' is set to 'Lock Workstation' or higher" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" | Select-Object -ExpandProperty ScRemoveOption

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Checking Microsoft Network Client
Write-Host "#########>Begin Microsoft Network Client Audit<#########" -ForegroundColor DarkGreen

#Microsoft network client: Digitally sign communications (always)
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "MNC" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" | Select-Object -ExpandProperty RequireSecuritySignature

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Microsoft network client: Digitally sign communications (if server agrees)
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "MNC" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Microsoft network client: Digitally sign communications (if server agrees)' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" | Select-Object -ExpandProperty EnableSecuritySignature

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Microsoft network client: Send unencrypted password to third-party SMB servers
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "MNC" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Microsoft network client: Send unencrypted password to third-party SMB servers' is set to 'Disabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" | Select-Object -ExpandProperty EnablePlainTextPassword

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Checking Microsoft network server 
Write-Host "#########>Begin Microsoft Network Server Audit<#########" -ForegroundColor DarkGreen

#Microsoft network server: Amount of idle time required before suspending session
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "MNS" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Microsoft network server: Amount of idle time required before suspending session' is set to '15 or fewer minute(s)'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" | Select-Object -ExpandProperty AutoDisconnect

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Ensure 'Microsoft network server: Digitally sign communications (always)
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "MNS" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" 
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" | Select-Object -ExpandProperty RequireSecuritySignature

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


# Ensure 'Microsoft network server: Digitally sign communications (if client agrees)'
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "MNS" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Microsoft network server: Digitally sign communications (if client agrees)' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" | Select-Object -ExpandProperty EnableSecuritySignature

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


# Microsoft network server: Disconnect clients when logon hours expire'
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "MNS" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Microsoft network server: Disconnect clients when logon hours expire' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" | Select-Object -ExpandProperty EnableForcedLogoff

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


# Microsoft network server: Server SPN target name validation level (MS Only)
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "MNS" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Microsoft network server: Server SPN target name validation level' is set to 'Accept if provided by client' or higher (MS only)" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" | Select-Object -ExpandProperty SMBServerNameHardeningLevel

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Checking network access
Write-Host "#########>Begin Network Access Audit<#########" -ForegroundColor DarkGreen

# Ensure 'Network access: Allow anonymous SID/Name translation' is set to 'Disabled'
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "NA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Network access: Allow anonymous SID/Name translation' is set to 'Disabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" | Select-Object -ExpandProperty TurnOffAnonymousBlock

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


# Network access: Do not allow anonymous enumeration of SAM accounts (MS only)
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "NA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts' is set to 'Enabled' (MS only)" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" | Select-Object -ExpandProperty RestrictAnonymousSAM

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


# Network access: Do not allow anonymous enumeration of SAM accounts and shares (MS only)
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "NA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' is set to 'Enabled' (MS only)" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" | Select-Object -ExpandProperty RestrictAnonymous

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


# Network access: Do not allow storage of passwords and credentials for network authentication
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "NA" + "$indextest"

$chaine = "$id" + ";" + "(L2) Ensure 'Network access: Do not allow storage of passwords and credentials for network authentication' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" | Select-Object -ExpandProperty DisableDomainCreds

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


# Network access: Let Everyone permissions apply to anonymous user
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "NA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Network access: Let Everyone permissions apply to anonymous users' is set to 'Disabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" | Select-Object -ExpandProperty EveryoneIncludesAnonymous

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


# Network access: Named Pipes that can be accessed anonymously (DC only)
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "NA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Configure 'Network access: Named Pipes that can be accessed anonymously' (DC only) " + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" | Select-Object -ExpandProperty NullSessionPipes

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


# Network access: Named Pipes that can be accessed anonymously (MS only)
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "NA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Configure 'Network access: Named Pipes that can be accessed anonymously' (MS only)" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" | Select-Object -ExpandProperty NullSessionPipes

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


# Network access: Remotely accessible registry paths
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "NA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Configure 'Network access: Remotely accessible registry paths' is configured" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths" | Select-Object -ExpandProperty Machine

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


# Network access: Remotely accessible registry paths and sub-paths
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "NA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Configure 'Network access: Remotely accessible registry paths and sub-paths' is configured" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths" | Select-Object -ExpandProperty Machine

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

# Network access: Restrict anonymous access to Named Pipes and Shares
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "NA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Network access: Restrict anonymous access to Named Pipes and Shares' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" | Select-Object -ExpandProperty RestrictNullSessAccess

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


# Network access: Restrict clients allowed to make remote calls to SAM (MS only)
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "NA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Network access: Restrict clients allowed to make remote calls to SAM' is set to 'Administrators: Remote Access: Allow' (MS only) " + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" | Select-Object -ExpandProperty restrictremotesam

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


# Network access: Shares that can be accessed anonymously
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "NA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Network access: Shares that can be accessed anonymously' is set to 'None' " + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" | Select-Object -ExpandProperty NullSessionShares

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


# Network access: Sharing and security model for local accounts
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "NA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Network access: Sharing and security model for local accounts' is set to 'Classic - local users authenticate as themselves'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" | Select-Object -ExpandProperty ForceGuest

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Checking network security 
Write-Host "#########>Begin Network Security Audit<#########" -ForegroundColor DarkGreen

#Network security: Allow Local System to use computer identity for NTLM
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "NS" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Network security: Allow Local System to use computer identity for NTLM' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" | Select-Object -ExpandProperty UseMachineId

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Network security: Allow LocalSystem NULL session fallback
$indextest += 1
$chaine = $null
$traitement = $null
$id = "NS" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Network security: Allow LocalSystem NULL session fallback' is set to 'Disabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" | Select-Object -ExpandProperty AllowNullSessionFallback

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Network Security: Allow PKU2U authentication requests to this computer to use online identities
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "NS" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Network Security: Allow PKU2U authentication requests to this computer to use online identities' is set to 'Disabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\pku2u"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\pku2u" | Select-Object -ExpandProperty AllowOnlineID

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Network security: Configure encryption types allowed for Kerberos
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "NS" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Network security: Configure encryption types allowed for Kerberos' is set to 'AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" | Select-Object -ExpandProperty SupportedEncryptionTypes

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#'Network security: Do not store LAN Manager hash value on next password change
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "NS" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Network security: Do not store LAN Manager hash value on next password change' is set to 'Enabled' " + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" | Select-Object -ExpandProperty NoLMHash

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Network security: Force logoff when logon hours expire' is set to 'Enabled'
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "NS" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Network security: Force logoff when logon hours expire' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" | Select-Object -ExpandProperty EnableForcedLogOff

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Network security: LAN Manager authentication level
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "NS" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" | Select-Object -ExpandProperty LmCompatibilityLevel

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Network security: LDAP client signing requirements'
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "NS" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Network security: LDAP client signing requirements' is set to 'Negotiate signing' or higher" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LDAP"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LDAP" | Select-Object -ExpandProperty LDAPClientIntegrity

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Network security: Minimum session security for NTLM SSP based (including secure RPC) clients
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "NS" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set to 'Require NTLMv2 session security, Require 128-bit encryption' (Value must be 537395200)" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" | Select-Object -ExpandProperty NTLMMinClientSec

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Network security: Minimum session security for NTLM SSP based (including secure RPC) servers'
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "NS" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' is set to 'Require NTLMv2 session security, Require 128-bit encryption' (Value must be 537395200)" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" | Select-Object -ExpandProperty NTLMMinServerSec

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Network security: Restrict NTLM: Audit Incoming NTLM Traffic
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "NS" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Network security: Restrict NTLM: Audit Incoming NTLM Traffic' is set to 'Enable auditing for all accounts' " + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" | Select-Object -ExpandProperty AuditReceivingNTLMTraffic

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Network security: Restrict NTLM: Audit NTLM authentication in this domain (DC only)
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "NS" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Network security: Restrict NTLM: Audit NTLM authentication in this domain' is set to 'Enable all' (DC only)" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" | Select-Object -ExpandProperty AuditNTLMInDomain

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "NS" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers' is set to 'Audit all' or higher" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" | Select-Object -ExpandProperty RestrictSendingNTLMTraffic

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename



#Checking Shutdown
Write-Host "#########>Begin Shutdown Audit<#########" -ForegroundColor DarkGreen

#Shutdown: Allow system to be shut down without having to log on
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "SHUT" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Shutdown: Allow system to be shut down without having to log on' is set to 'Disabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" | Select-Object -ExpandProperty ShutdownWithoutLogon

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename



#Checking System objects
Write-Host "#########>Begin System Objects Audit<#########" -ForegroundColor DarkGreen

#System objects: Require case insensitivity for non-Windows subsystems
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "SO" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'System objects: Require case insensitivity for non-Windows subsystems' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel" | Select-Object -ExpandProperty ObCaseInsensitive

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "SO" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager" | Select-Object -ExpandProperty ProtectionMode

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Checking User Account Control
Write-Host "#########>Begin User Account Control Audit<#########" -ForegroundColor DarkGreen

#User Account Control: Admin Approval Mode for the Built-in Administrator account
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "UAC" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'User Account Control: Admin Approval Mode for the Built-in Administrator account' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" | Select-Object -ExpandProperty FilterAdministratorToken

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "UAC" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' is set to 'Prompt for consent on the secure desktop' or higher" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" | Select-Object -ExpandProperty ConsentPromptBehaviorAdmin

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#User Account Control: Behavior of the elevation prompt for standard users
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "UAC" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'User Account Control: Behavior of the elevation prompt for standard users' is set to 'Automatically deny elevation requests'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" | Select-Object -ExpandProperty ConsentPromptBehaviorUser

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#User Account Control: Detect application installations and prompt for elevation
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "UAC" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'User Account Control: Detect application installations and prompt for elevation' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" | Select-Object -ExpandProperty EnableInstallerDetection

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#User Account Control: Only elevate UIAccess applications that are installed in secure locations
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "UAC" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'User Account Control: Only elevate UIAccess applications that are installed in secure locations' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" | Select-Object -ExpandProperty EnableSecureUIAPaths

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#User Account Control: Run all administrators in Admin Approval Mode
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "UAC" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'User Account Control: Run all administrators in Admin Approval Mode' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" | Select-Object -ExpandProperty EnableLUA

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#User Account Control: Switch to the secure desktop when prompting for elevation
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "UAC" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'User Account Control: Switch to the secure desktop when prompting for elevation' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" | Select-Object -ExpandProperty PromptOnSecureDesktop

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#User Account Control: Virtualize file and registry write failures to per-user locations
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "UAC" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'User Account Control: Virtualize file and registry write failures to per-user locations' is set to 'Enabled' " + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" | Select-Object -ExpandProperty EnableVirtualization

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename



#Checking System Services
Write-Host "#########>Begin System Services Audit<#########" -ForegroundColor DarkGreen

#Ensure 'Print Spooler (Spooler)' is set to 'Disabled' (DC only)
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "SS" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Print Spooler (Spooler)' is set to 'Disabled' (DC only)" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Spooler"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Spooler" | Select-Object -ExpandProperty Start

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Ensure 'Print Spooler (Spooler)' is set to 'Disabled' (MS only)
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "SS" + "$indextest"

$chaine = "$id" + ";" + "(L2) Ensure 'Print Spooler (Spooler)' is set to 'Disabled' (MS only)" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Spooler"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Spooler" | Select-Object -ExpandProperty Start

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename



#Checking Firewall Domain Profile
Write-Host "#########>Begin Firewall Domain Profile Audit<#########" -ForegroundColor DarkGreen

#Windows Firewall: Domain: Firewall state
$indextest += 1
$chaine = $null
$traitement = $null
$id = "WFDP" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Windows Firewall: Domain: Firewall state' is set to 'On (recommended)" + ";"
$traitement = Get-NetFirewallProfile -Name "Domain" | Select-Object -ExpandProperty Enabled

if ($checkConditions -notcontains $traitement) {
  $traitement = $traitement
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename


#Windows Firewall: Domain: Inbound connections
$indextest += 1
$chaine = $null
$traitement = $null
$id = "WFDP" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Windows Firewall: Domain: Inbound connections' is set to 'Block (default)" + ";"
$traitement = Get-NetFirewallProfile -Name "Domain" | Select-Object -ExpandProperty DefaultInboundAction

if ($checkConditions -notcontains $traitement) {
  $traitement = $traitement
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename


#Windows Firewall: Domain: Settings: Display a notification'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "WFDP" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Windows Firewall: Domain: Settings: Display a notification' is set to 'No'" + ";"
$traitement = Get-NetFirewallProfile -Name "Domain" | Select-Object -ExpandProperty NotifyOnListen

if ($checkConditions -notcontains $traitement) {
  $traitement = $traitement
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename


#Windows Firewall: Domain: Logging: Name''
$indextest += 1
$chaine = $null
$traitement = $null
$id = "WFDP" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Windows Firewall: Domain: Logging: Name' is set to '%SystemRoot%\System32\logfiles\firewall\domainfw.log'" + ";"
$traitement = Get-NetFirewallProfile -Name "Domain" | Select-Object -ExpandProperty LogFileName

if ($checkConditions -notcontains $traitement) {
  $traitement = $traitement
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename

#Windows Firewall: Domain: Logging: Size limit (KB)''
$indextest += 1
$chaine = $null
$traitement = $null
$id = "WFDP" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Windows Firewall: Domain: Logging: Size limit (KB)' is set to '16,384 KB or greater'" + ";"
$traitement = Get-NetFirewallProfile -Name "Domain" | Select-Object -ExpandProperty LogMaxSizeKilobytes

if ($checkConditions -notcontains $traitement) {
  $traitement = $traitement
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename

#Windows Firewall: Domain: Logging: Log dropped packets
$indextest += 1
$chaine = $null
$traitement = $null
$id = "WFDP" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Windows Firewall: Domain: Logging: Log dropped packets' is set to 'Yes'" + ";"
$traitement = Get-NetFirewallProfile -Name "Domain" | Select-Object -ExpandProperty LogBlocked

if ($checkConditions -notcontains $traitement) {
  $traitement = $traitement
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename

#Windows Firewall: Log successful connections'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "WFDP" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Windows Firewall: Domain: Logging: Log successful connections' is set to 'Yes'" + ";"
$traitement = Get-NetFirewallProfile -Name "Domain" | Select-Object -ExpandProperty LogAllowed

if ($checkConditions -notcontains $traitement) {
  $traitement = $traitement
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename


#Checking Firewall Private Profile
Write-Host "#########>Begin Firewall Private Profile Audit<#########" -ForegroundColor DarkGreen

#Windows Firewall: Private: Firewall state
$indextest += 1
$chaine = $null
$traitement = $null
$id = "WFPPRIP" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Windows Firewall: Private: Firewall state' is set to 'On (recommended)'" + ";"
$traitement = Get-NetFirewallProfile -Name "Private" | Select-Object -ExpandProperty Enabled

if ($checkConditions -notcontains $traitement) {
  $traitement = $traitement
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename


#Windows Firewall: Private: Inbound connections
$indextest += 1
$chaine = $null
$traitement = $null
$id = "WFPPRIP" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Windows Firewall: Private: Inbound connections' is set to 'Block (default)'" + ";"
$traitement = Get-NetFirewallProfile -Name "Private" | Select-Object -ExpandProperty DefaultInboundAction

if ($checkConditions -notcontains $traitement) {
  $traitement = $traitement
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename


#Windows Firewall: Private: Settings: Display a notification'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "WFPPRIP" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Windows Firewall: Private: Settings: Display a notification' is set to 'No'" + ";"
$traitement = Get-NetFirewallProfile -Name "Private" | Select-Object -ExpandProperty NotifyOnListen

if ($checkConditions -notcontains $traitement) {
  $traitement = $traitement
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename


#Windows Firewall: Private: Logging: Name
$indextest += 1
$chaine = $null
$traitement = $null
$id = "WFPPRIP" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Windows Firewall: Private: Logging: Name' is set to '%SystemRoot%\System32\logfiles\firewall\privatefw.log'" + ";"
$traitement = Get-NetFirewallProfile -Name "Private" | Select-Object -ExpandProperty LogFileName

if ($checkConditions -notcontains $traitement) {
  $traitement = $traitement
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename


#Windows Firewall: Private: Logging: Size limit (KB)'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "WFPPRIP" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Windows Firewall: Private: Logging: Size limit (KB)' is set to '16,384 KB or greater'" + ";"
$traitement = Get-NetFirewallProfile -Name "Private" | Select-Object -ExpandProperty LogMaxSizeKilobytes

if ($checkConditions -notcontains $traitement) {
  $traitement = $traitement
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename

#Windows Firewall: Private: Logging: Log dropped packets
$indextest += 1
$chaine = $null
$traitement = $null
$id = "WFPPRIP" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Windows Firewall: Private: Logging: Log dropped packets' is set to 'Yes'" + ";"
$traitement = Get-NetFirewallProfile -Name "Private" | Select-Object -ExpandProperty LogBlocked

if ($checkConditions -notcontains $traitement) {
  $traitement = $traitement
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename

#Windows Firewall: Private: Logging: Log successful connections'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "WFPPRIP" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Windows Firewall: Private: Logging: Log successful connections' is set to 'Yes'" + ";"
$traitement = Get-NetFirewallProfile -Name "Private" | Select-Object -ExpandProperty LogAllowed

if ($checkConditions -notcontains $traitement) {
  $traitement = $traitement
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename


#Checking Firewall Public Profile
Write-Host "#########>Begin Firewall Public Profile Audit<#########" -ForegroundColor DarkGreen

#Windows Firewall: Public: Firewall state
$indextest += 1
$chaine = $null
$traitement = $null
$id = "WFPPUBP" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Windows Firewall: Public: Firewall state' is set to 'On (recommended)'" + ";"
$traitement = Get-NetFirewallProfile -Name "Public" | Select-Object -ExpandProperty Enabled

if ($checkConditions -notcontains $traitement) {
  $traitement = $traitement
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename


#Windows Firewall: Public: Inbound connections
$indextest += 1
$chaine = $null
$traitement = $null
$id = "WFPPUBP" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Windows Firewall: Public: Inbound connections' is set to 'Block (default)'" + ";"
$traitement = Get-NetFirewallProfile -Name "Public" | Select-Object -ExpandProperty DefaultInboundAction

if ($checkConditions -notcontains $traitement) {
  $traitement = $traitement
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename


#Windows Firewall: Public: Settings: Display a notification
$indextest += 1
$chaine = $null
$traitement = $null
$id = "WFPPUBP" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Windows Firewall: Public: Settings: Display a notification' is set to 'No'" + ";"
$traitement = Get-NetFirewallProfile -Name "Public" | Select-Object -ExpandProperty NotifyOnListen

if ($checkConditions -notcontains $traitement) {
  $traitement = $traitement
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename


#Windows Firewall: Public: Settings: Apply local firewall rules
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "WFPPUBP" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Windows Firewall: Public: Settings: Apply local firewall rules' is set to 'No'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" | Select-Object -ExpandProperty AllowLocalPolicyMerge

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Windows Firewall: Public: Settings: Apply local connection security rules
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "WFPPUBP" + "$indextest"
$chaine = "$id" + ";" + "(L1) Ensure 'Windows Firewall: Public: Settings: Apply local connection security rules' is set to 'No'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" | Select-Object -ExpandProperty AllowLocalIPsecPolicyMerge

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Windows Firewall: Public: Logging: Name'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "WFPPUBP" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Windows Firewall: Public: Logging: Name' is set to '%SystemRoot%\System32\logfiles\firewall\publicfw.log'" + ";"
$traitement = Get-NetFirewallProfile -Name "Public" | Select-Object -ExpandProperty LogFileName

if ($checkConditions -notcontains $traitement) {
  $traitement = $traitement
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename

#Windows Firewall: Public: Logging: Size limit (KB)'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "WFPPUBP" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Windows Firewall: Public: Logging: Size limit (KB)' is set to '16,384 KB or greater'" + ";"
$traitement = Get-NetFirewallProfile -Name "Public" | Select-Object -ExpandProperty LogMaxSizeKilobytes

if ($checkConditions -notcontains $traitement) {
  $traitement = $traitement
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename

#Windows Firewall: Public: Logging: Log dropped packets
$indextest += 1
$chaine = $null
$traitement = $null
$id = "WFPPUBP" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Windows Firewall: Public: Logging: Log dropped packets' is set to 'Yes'" + ";"
$traitement = Get-NetFirewallProfile -Name "Public" | Select-Object -ExpandProperty LogBlocked

if ($checkConditions -notcontains $traitement) {
  $traitement = $traitement
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename

#Windows Firewall: Public: Logging: Log successful connections
$indextest += 1
$chaine = $null
$traitement = $null
$id = "WFPPUBP" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Windows Firewall: Public: Logging: Log successful connections' is set to 'Yes'" + ";"
$traitement = Get-NetFirewallProfile -Name "Public" | Select-Object -ExpandProperty LogAllowed

if ($checkConditions -notcontains $traitement) {
  $traitement = $traitement
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename



#Checking Advanced Audit Policy Account Logon
Write-Host "#########>Begin Advanced Audit Policy Audit<#########" -ForegroundColor DarkGreen

#Audit Credential Validation
$indextest += 1
$chaine = $null
$traitement = $null
$id = "AAAPA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Audit Credential Validation' is set to 'Success and Failure'" + ";"
$traitement = Get-Content $auditconfigfile |Select-String -Pattern "(Credential Validation)"

if ($checkConditions -notcontains $traitement) {
  $traitement = $traitement
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename

#Audit Kerberos Authentication Service (DC only)
$indextest += 1
$chaine = $null
$traitement = $null
$id = "AAAPA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Audit Kerberos Authentication Service' is set to 'Success and Failure' (DC Only)'" + ";"
$traitement = Get-Content $auditconfigfile |Select-String -Pattern "(Kerberos Authentication Service)"

if ($checkConditions -notcontains $traitement) {
  $traitement = $traitement
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename

#Audit Kerberos Service Ticket Operations (DC only)
$indextest += 1
$chaine = $null
$traitement = $null
$id = "AAAPA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Audit Kerberos Service Ticket Operations' is set to 'Success and Failure' (DC Only)'" + ";"
$traitement = Get-Content $auditconfigfile |Select-String -Pattern "(Kerberos Service Ticket Operations)"

if ($checkConditions -notcontains $traitement) {
  $traitement = $traitement
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename

#Audit Application Group Management
$indextest += 1
$chaine = $null
$traitement = $null
$id = "AAAPA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Audit Application Group Management' is set to 'Success and Failure'" + ";"
$traitement = Get-Content $auditconfigfile |Select-String -Pattern "(Application Group Management)"

if ($checkConditions -notcontains $traitement) {
  $traitement = $traitement
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename

#Audit Computer Account Management (DC only)
$indextest += 1
$chaine = $null
$traitement = $null
$id = "AAAPA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Audit Computer Account Management' is set to include 'Success' (DC only)" + ";"
$traitement = Get-Content $auditconfigfile |Select-String -Pattern "(Computer Account Management)"

if ($checkConditions -notcontains $traitement) {
  $traitement = $traitement
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename

#Audit Distribution Group Management (DC only)
$indextest += 1
$chaine = $null
$traitement = $null
$id = "AAAPA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Audit Distribution Group Management' is set to include 'Success' (DC only)" + ";"
$traitement = Get-Content $auditconfigfile |Select-String -Pattern "(Distribution Group Management)"

if ($checkConditions -notcontains $traitement) {
  $traitement = $traitement
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename

#Audit Other Account Management Events (DC only)
$indextest += 1
$chaine = $null
$traitement = $null
$id = "AAAPA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Audit Other Account Management Events' is set to include 'Success' (DC only)" + ";"
$traitement = Get-Content $auditconfigfile |Select-String -Pattern "(Other Account Management Events)"

if ($checkConditions -notcontains $traitement) {
  $traitement = $traitement
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename

#Audit Security Group Management
$indextest += 1
$chaine = $null
$traitement = $null
$id = "AAAPA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Audit Security Group Management' is set to include 'Success'" + ";"
$traitement = Get-Content $auditconfigfile |Select-String -Pattern "(Security Group Management)"

if ($checkConditions -notcontains $traitement) {
  $traitement = $traitement
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename

#Audit User Account Management
$indextest += 1
$chaine = $null
$traitement = $null
$id = "AAAPA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Audit User Account Management' is set to 'Success and Failure'" + ";"
$traitement = Get-Content $auditconfigfile |Select-String -Pattern "(User Account Management)"

if ($checkConditions -notcontains $traitement) {
  $traitement = $traitement
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename

#Audit PNP Activity
$indextest += 1
$chaine = $null
$traitement = $null
$id = "AAAPA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Audit PNP Activity' is set to include 'Success'" + ";"
$traitement = Get-Content $auditconfigfile |Select-String -Pattern "(PNP Activity)"

if ($checkConditions -notcontains $traitement) {
  $traitement = $traitement
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename

#Audit Process Creation'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "AAAPA" + "$indextest"
$chaine = "$id" + ";" + "(L1) Ensure 'Audit Process Creation' is set to include 'Success'" + ";"
$traitement = Get-Content $auditconfigfile |Select-String -Pattern "(Process Creation)"

if ($checkConditions -notcontains $traitement) {
  $traitement = $traitement
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename

#Audit Directory Service Access (DC only)
$indextest += 1
$chaine = $null
$traitement = $null
$id = "AAAPA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Audit Directory Service Access' is set to include 'Failure' (DC only)" + ";"
$traitement = Get-Content $auditconfigfile |Select-String -Pattern "(Directory Service Access)"

if ($checkConditions -notcontains $traitement) {
  $traitement = $traitement
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename

#Audit Directory Service Changes (DC only)
$indextest += 1
$chaine = $null
$traitement = $null
$id = "AAAPA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Audit Directory Service Changes' is set to include 'Success' (DC only)" + ";"
$traitement = Get-Content $auditconfigfile |Select-String -Pattern "(Directory Service Changes)"

if ($checkConditions -notcontains $traitement) {
  $traitement = $traitement
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename

#Audit Account Lockout
$indextest += 1
$chaine = $null
$traitement = $null
$id = "AAAPA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Audit Account Lockout' is set to include 'Failure'" + ";"
$traitement = Get-Content $auditconfigfile |Select-String -Pattern "(Account Lockout)"

if ($checkConditions -notcontains $traitement) {
  $traitement = $traitement
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename


#Audit Group Membership'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "AAAPA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Audit Group Membership' is set to include 'Success'" + ";"
$traitement = Get-Content $auditconfigfile |Select-String -Pattern "(Group Membership)"

if ($checkConditions -notcontains $traitement) {
  $traitement = $traitement
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename


#Ensure 'Audit Logoff'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "AAAPA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Audit Logoff' is set to include 'Success'" + ";"
$traitement = Get-Content $auditconfigfile |Select-String -Pattern "(Logoff)"

if ($checkConditions -notcontains $traitement) {
  $traitement = $traitement
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename


#Ensure Audit Logon
$indextest += 1
$chaine = $null
$traitement = $null
$id = "AAAPA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Audit Logon' is set to 'Success and Failure'" + ";"
$traitement = Get-Content $auditconfigfile |Select-String -Pattern "(Logon)"

if ($checkConditions -notcontains $traitement) {
  $traitement = $traitement
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename


#Audit Other Logon/Logoff Events
$indextest += 1
$chaine = $null
$traitement = $null
$id = "AAAPA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Audit Other Logon/Logoff Events' is set to 'Success and Failure'" + ";"
$traitement = Get-Content $auditconfigfile |Select-String -Pattern "(Other Logon/Logoff Events)"

if ($checkConditions -notcontains $traitement) {
  $traitement = $traitement
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename

#Audit Special Logon
$indextest += 1
$chaine = $null
$traitement = $null
$id = "AAAPA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Audit Special Logon' is set to include 'Success'" + ";"
$traitement = Get-Content $auditconfigfile |Select-String -Pattern "(Special Logon)"

if ($checkConditions -notcontains $traitement) {
  $traitement = $traitement
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename

#Audit Detailed File Share'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "AAAPA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Audit Detailed File Share' is set to include 'Failure'" + ";"
$traitement = Get-Content $auditconfigfile |Select-String -Pattern "(Audit Detailed File Share)"

if ($checkConditions -notcontains $traitement) {
  $traitement = $traitement
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename

#Audit File Share
$indextest += 1
$chaine = $null
$traitement = $null
$id = "AAAPA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Audit File Share' is set to 'Success and Failure'" + ";"
$traitement = Get-Content $auditconfigfile |Select-String -Pattern "(Audit File Share)"

if ($checkConditions -notcontains $traitement) {
  $traitement = $traitement
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename

#Audit Other Object Access Events
$indextest += 1
$chaine = $null
$traitement = $null
$id = "AAAPA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Audit Other Object Access Events' is set to 'Success and Failure'" + ";"
$traitement = Get-Content $auditconfigfile |Select-String -Pattern "(Audit Other Object Access Events)"

if ($checkConditions -notcontains $traitement) {
  $traitement = $traitement
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename

#Audit Removable Storage
$indextest += 1
$chaine = $null
$traitement = $null
$id = "AAAPA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Audit Removable Storage' is set to 'Success and Failure'" + ";"
$traitement = Get-Content $auditconfigfile |Select-String -Pattern "(Removable Storage)"

if ($checkConditions -notcontains $traitement) {
  $traitement = $traitement
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename


#Audit Audit Policy Change
$indextest += 1
$chaine = $null
$traitement = $null
$id = "AAAPA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Audit Audit Policy Change' is set to include 'Success'" + ";"
$traitement = Get-Content $auditconfigfile |Select-String -Pattern "(Audit Policy Change)"

if ($checkConditions -notcontains $traitement) {
  $traitement = $traitement
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename

#Audit Authentication Policy Change
$indextest += 1
$chaine = $null
$traitement = $null
$id = "AAAPA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Audit Authentication Policy Change' is set to include 'Success'" + ";"
$traitement = Get-Content $auditconfigfile |Select-String -Pattern "(Authentication Policy Change)"

if ($checkConditions -notcontains $traitement) {
  $traitement = $traitement
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename

#Audit Authorization Policy Change
$indextest += 1
$chaine = $null
$traitement = $null
$id = "AAAPA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Audit Authorization Policy Change' is set to include 'Success'" + ";"
$traitement = Get-Content $auditconfigfile |Select-String -Pattern "(Authorization Policy Change)"

if ($checkConditions -notcontains $traitement) {
  $traitement = $traitement
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename

#Audit SMPSSVC Rule-Level Policy Change'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "AAPU" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Audit MPSSVC Rule-Level Policy Change' is set to 'Success and Failure' " + ";"
$traitement = Get-Content $auditconfigfile |Select-String -Pattern "(MPSSVC Rule-Level Policy Change)"

if ($checkConditions -notcontains $traitement) {
  $traitement = $traitement
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename


#Audit Other Policy Change Events'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "AAPU" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Audit Other Policy Change Events' is set to include 'Failure'" + ";"
$traitement = Get-Content $auditconfigfile |Select-String -Pattern "(Audit Other Policy Change Events)"

if ($checkConditions -notcontains $traitement) {
  $traitement = $traitement
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename


#Audit Sensitive Privilege Use'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "AAAPA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Audit Sensitive Privilege Use' is set to 'Success and Failure'" + ";"
$traitement = Get-Content $auditconfigfile |Select-String -Pattern "(Sensitive Privilege Use)"

if ($checkConditions -notcontains $traitement) {
  $traitement = $traitement
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename

#Ensure 'Audit IPsec Driver' is set to 'Success and Failure'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "AAAPA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Audit IPsec Driver' is set to 'Success and Failure'" + ";"
$traitement = Get-Content $auditconfigfile |Select-String -Pattern "(IPsec Driver)"

if ($checkConditions -notcontains $traitement) {
  $traitement = $traitement
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename



#Audit Other System Events
$indextest += 1
$chaine = $null
$traitement = $null
$id = "AAAPA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Audit Other System Events' is set to 'Success and Failure'" + ";"
$traitement = Get-Content $auditconfigfile |Select-String -Pattern "(Other System Events)"

if ($checkConditions -notcontains $traitement) {
  $traitement = $traitement
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename

#Audit Security State Change'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "AAAPA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Audit Security State Change' is set to include 'Success'" + ";"
$traitement = Get-Content $auditconfigfile |Select-String -Pattern "(Security State Change)"

if ($checkConditions -notcontains $traitement) {
  $traitement = $traitement
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename

#Audit Security System Extension
$indextest += 1
$chaine = $null
$traitement = $null
$id = "AAAPA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Audit Security System Extension' is set to include 'Success'" + ";"
$traitement = Get-Content $auditconfigfile |Select-String -Pattern "(Security System Extension)"

if ($checkConditions -notcontains $traitement) {
  $traitement = $traitement
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename

#Audit System Integrity
$indextest += 1
$chaine = $null
$traitement = $null
$id = "AAAPA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Audit System Integrity' is set to 'Success and Failure'" + ";"
$traitement = Get-Content $auditconfigfile |Select-String -Pattern "(System Integrity)"

if ($checkConditions -notcontains $traitement) {
  $traitement = $traitement
} 
else {
  $traitement = "Not Configured"  
}

$chaine += $traitement
$chaine>> $filename


#Checking Personalization audit
Write-Host "#########>Begin Personalization Audit<#########" -ForegroundColor DarkGreen

#Prevent enabling lock screen camera
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "PA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Prevent enabling lock screen camera' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Personalization"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Personalization" | Select-Object -ExpandProperty NoLockScreenCamera

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Prevent enabling lock screen slide show'
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "PA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Prevent enabling lock screen slide show' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Personalization"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Personalization" | Select-Object -ExpandProperty NoLockScreenSlideshow

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Allow users to enable online speech recognition services
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "PA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Allow users to enable online speech recognition services' is set to 'Disabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\InputPersonalization"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\InputPersonalization" | Select-Object -ExpandProperty AllowInputPersonalization

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Allow Online Tips'
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "PA" + "$indextest"

$chaine = "$id" + ";" + "(L2) Ensure 'Allow Online Tips' is set to 'Disabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Select-Object -ExpandProperty AllowOnlineTips

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Checking MS Security Guide
Write-Host "#########>Begin MS Security Guide Audit<#########" -ForegroundColor DarkGreen

#Apply UAC restrictions to local accounts on network logons (MS only)
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "MSSG" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Apply UAC restrictions to local accounts on network logons' is set to 'Enabled' (MS only)" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" | Select-Object -ExpandProperty LocalAccountTokenFilterPolicy

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Configure RPC packet level privacy setting for incoming connections
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "MSSG" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Configure RPC packet level privacy setting for incoming connections' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Print"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Print" | Select-Object -ExpandProperty RpcAuthnLevelPrivacyEnabled

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Configure SMB v1 client driver'
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "MSSG" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Configure SMB v1 client driver' is set to 'Enabled: Disable driver (recommended)' (Value must be 4)" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mrxsmb10"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mrxsmb10" | Select-Object -ExpandProperty Start

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Configure SMB v1 server' is set to 'Disabled'
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "MSSG" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Configure SMB v1 server' is set to 'Disabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" | Select-Object -ExpandProperty SMB1

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Enable Certificate Padding
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "MSSG" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Enable Certificate Padding' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\Wintrust\Config"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\Wintrust\Config" | Select-Object -ExpandProperty EnableCertPaddingCheck

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#'Enable Structured Exception Handling Overwrite Protection (SEHOP)'
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "MSSG" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Enable Structured Exception Handling Overwrite Protection (SEHOP)' is set to 'Enabled' (Value must be 0)" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" | Select-Object -ExpandProperty DisableExceptionChainValidation

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#LSA Protection
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "MSSG" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'LSA Protection' is set to 'Enabled' " + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" | Select-Object -ExpandProperty RunAsPPL

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Ensure 'NetBT NodeType configuration' is set to 'Enabled: P-node (recommended)
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "MSSG" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'NetBT NodeType configuration' is set to 'Enabled: P-node (recommended)' (Value must be 2)" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetBT\Parameters"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" | Select-Object -ExpandProperty NodeType

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#WDigest Authentication'
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "MSSG" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'WDigest Authentication' is set to 'Disabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" | Select-Object -ExpandProperty UseLogonCredential

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)'
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "MSSG" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'MSS: (AutoAdminLogon) Enable Automatic Logon' is set to 'Disabled' (Value must be 0 or empty)" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" | Select-Object -ExpandProperty AutoAdminLogon

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)'
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "MSSG" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'MSS: (DisableIPSourceRouting IPv6) IP source routing protection level' is set to 'Enabled: Highest protection, source routing is completely disabled' (Value must be 2)" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" | Select-Object -ExpandProperty DisableIPSourceRouting

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#'MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)'
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "MSSG" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'MSS: (DisableIPSourceRouting) IP source routing protection level' is set to 'Enabled: Highest protection, source routing is completely disabled' (Value must be 2)" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" | Select-Object -ExpandProperty DisableIPSourceRouting

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename



#'MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes''
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "MSSG" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes' is set to 'Disabled' " + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" | Select-Object -ExpandProperty EnableICMPRedirect

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename



#MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds''
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "MSSG" + "$indextest"

$chaine = "$id" + ";" + "(L2) Ensure 'MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds' is set to 'Enabled: 300,000 or 5 minutes' (Value must be 300000)" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" | Select-Object -ExpandProperty KeepAliveTime

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "MSSG" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetBT\Parameters"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" | Select-Object -ExpandProperty NoNameReleaseOnDemand

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses (could lead to DoS)'
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "MSSG" + "$indextest"

$chaine = "$id" + ";" + "(L2) Ensure 'MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses' is set to 'Disabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" | Select-Object -ExpandProperty PerformRouterDiscovery

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended)'
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "MSSG" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'MSS: (SafeDllSearchMode) Enable Safe DLL search mode' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager" | Select-Object -ExpandProperty SafeDllSearchMode

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires (0 recommended)'
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "MSSG" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires' is set to 'Enabled: 5 or fewer seconds' (Value must be 5 or less)" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" | Select-Object -ExpandProperty ScreenSaverGracePeriod

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Ensure 'MSS: (TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is retransmitted
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "MSSG" + "$indextest"

$chaine = "$id" + ";" + "(L2) Ensure 'MSS: (TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is retransmitted' is set to 'Enabled: 3'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters" | Select-Object -ExpandProperty TcpMaxDataRetransmissions

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "MSSG" + "$indextest"

$chaine = "$id" + ";" + "(L2) Ensure 'MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted' is set to 'Enabled: 3'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TCPIP\Parameters" 
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TCPIP\Parameters" | Select-Object -ExpandProperty TcpMaxDataRetransmissions

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "MSSG" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning' is set to 'Enabled: 90% or less'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Security"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Security" | Select-Object -ExpandProperty WarningLevel

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename



#DNS Client
Write-Host "#########>Begin DNS Client Audit<#########" -ForegroundColor DarkGreen

#Configure NetBIOS settings
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "DNSC" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Configure NetBIOS settings' is set to 'Enabled: Disable NetBIOS name resolution on public networks'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" | Select-Object -ExpandProperty EnableNetbios

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Turn off multicast name resolution'
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "DNSC" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Turn off multicast name resolution' is set to 'Enabled' (Value must be 0) " + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" | Select-Object -ExpandProperty EnableMulticast

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename



#Check Fonts
Write-Host "#########>Begin Fonts Audit<#########" -ForegroundColor DarkGreen

#Enable Font Providers'
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "FONT" + "$indextest"

$chaine = "$id" + ";" + "(L2) Ensure 'Enable Font Providers' is set to 'Disabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" | Select-Object -ExpandProperty EnableFontProviders

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Check Lanman Workstation
Write-Host "#########>Begin Lanman Workstation Audit<#########" -ForegroundColor DarkGreen

#Enable insecure guest logons'
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "LW" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Enable insecure guest logons' is set to 'Disabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" | Select-Object -ExpandProperty AllowInsecureGuestAuth

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Check Link-Layer Topology Discovery
Write-Host "#########>Begin Link-Layer Topology Discovery Audit<#########" -ForegroundColor DarkGreen

#####TO IMPROVE#####
#Turn on Mapper I/O (LLTDIO) driver'
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "LLTDIO" + "$indextest"

$chaine = "$id" + ";" + "(L2) Ensure 'Turn on Mapper I/O (LLTDIO) driver' is set to 'Disabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD"

if ( $exist -eq $true) {
  $traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD" | Select-Object -ExpandProperty AllowLLTDIOOnDomain
  $traitementtemp = "AllowLLTDIOOnDomain" + ":" + "$traitement" + "|"
  $traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD" | Select-Object -ExpandProperty AllowLLTDIOOnPublicNet
  $traitementtemp += "AllowLLTDIOOnPublicNet" + ":" + "$traitement" + "|"
  $traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD" | Select-Object -ExpandProperty EnableLLTDIO
  $traitementtemp += "EnableLLTDIO" + ":" + "$traitement" + "|"
  $traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD" | Select-Object -ExpandProperty ProhibitLLTDIOOnPrivateNet
  $traitementtemp += "ProhibitLLTDIOOnPrivateNet" + ":" + "$traitement" + "|"
}
else {
  $traitementtemp = "Not Configured"
}

$chaine += $traitementtemp
$chaine>> $filename


#Turn on Responder (RSPNDR) driver
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "LLTDIO" + "$indextest"

$chaine = "$id" + ";" + "(L2) Ensure 'Turn on Responder (RSPNDR) driver' is set to 'Disabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD"

if ( $exist -eq $true) {
  $traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD" | Select-Object -ExpandProperty AllowRspndrOnDomain
  $traitementtemp = "AllowRspndrOnDomain" + ":" + "$traitement" + "|"
  $traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD" | Select-Object -ExpandProperty AllowRspndrOnPublicNet
  $traitementtemp += "AllowRspndrOnPublicNet" + ":" + "$traitement" + "|"
  $traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD" | Select-Object -ExpandProperty EnableRspndr
  $traitementtemp += "EnableRspndr" + ":" + "$traitement" + "|"
  $traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD" | Select-Object -ExpandProperty ProhibitRspndrOnPrivateNet
  $traitementtemp += "ProhibitRspndrOnPrivateNet" + ":" + "$traitement" + "|"
}
else {
  $traitementtemp = "Not Configured"
}

$chaine += $traitementtemp
$chaine>> $filename
####################

#Check Microsoft Peer-to-Peer Networking Services
Write-Host "#########>Begin Microsoft Peer-to-Peer Networking Services Audit<#########" -ForegroundColor DarkGreen

#Turn off Microsoft Peer-to-Peer Networking Services
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "PPNS" + "$indextest"

$chaine = "$id" + ";" + "(L2) Ensure 'Turn off Microsoft Peer-to-Peer Networking Services' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Peernet" 
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Peernet" | Select-Object -ExpandProperty Disabled

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Check Network Connections
Write-Host "#########>Begin Network Connections Audit<#########" -ForegroundColor DarkGreen

#Prohibit installation and configuration of Network Bridge on your DNS domain network
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "NC" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Prohibit installation and configuration of Network Bridge on your DNS domain network' is set to 'Enabled' " + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Network Connections" 
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Network Connections" | Select-Object -ExpandProperty NC_AllowNetBridge_NLA

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Prohibit use of Internet Connection Sharing on your DNS domain network
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "NC" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Prohibit use of Internet Connection Sharing on your DNS domain network' is set to 'Enabled' " + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Network Connections"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Network Connections" | Select-Object -ExpandProperty NC_ShowSharedAccessUI

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Require domain users to elevate when setting a network's location'
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "NC" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Require domain users to elevate when setting a network's location' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Network Connections"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Network Connections" | Select-Object -ExpandProperty NC_StdDomainUserSetLocation

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Check Network Provider
Write-Host "#########>Begin Network Provider Audit<#########" -ForegroundColor DarkGreen

#####TO IMPROVE#####
#Hardened UNC Paths
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "NP" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Hardened UNC Paths' is set to 'Enabled, with `Require Mutual Authentication`, `Require Integrity`, and `Require Privacy` set for all NETLOGON and SYSVOL shares'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths"

if ( $exist -eq $true) {
  $traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" | Select-Object -ExpandProperty "\\*\NETLOGON"
  $traitementtemp = "\\*\NETLOGON" + ":" + "$traitement" + "|"
  $traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" | Select-Object -ExpandProperty "\\*\SYSVOL"
  $traitementtemp += "\\*\SYSVOL" + ":" + "$traitement" + "|"
}
else {
  $traitementtemp = "Not Configured"
}

$chaine += $traitementtemp
$chaine>> $filename
####################

#Check TCPIP Settings
Write-Host "#########>Begin TCPIP Settings Audit<#########" -ForegroundColor DarkGreen

#Disable IPv6
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "TCPIPS" + "$indextest"

$chaine = "$id" + ";" + "(L2) Disable IPv6 (Ensure TCPIP6 Parameter 'DisabledComponents' is set to '0xff (255)')" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters" | Select-Object -ExpandProperty DisabledComponents

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Check Windows Connect Now
Write-Host "#########>Begin Windows Connect Now Audit<#########" -ForegroundColor DarkGreen

#####TO IMPROVE#####
#Configuration of wireless settings using Windows Connect Now
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "WNC" + "$indextest"

$chaine = "$id" + ";" + "(L2) Ensure 'Configuration of wireless settings using Windows Connect Now' is set to 'Disabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars"

if ( $exist -eq $true) {
  $traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" | Select-Object -ExpandProperty EnableRegistrars
  $traitementtemp = "EnableRegistrars" + ":" + "$traitement" + "|"
  $traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" | Select-Object -ExpandProperty DisableUPnPRegistrar
  $traitementtemp += "DisableUPnPRegistrar" + ":" + "$traitement" + "|"
  $traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" | Select-Object -ExpandProperty DisableInBand802DOT11Registrar
  $traitementtemp += "DisableInBand802DOT11Registrar" + ":" + "$traitement" + "|"
  $traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" | Select-Object -ExpandProperty DisableFlashConfigRegistrar
  $traitementtemp += "DisableFlashConfigRegistrar" + ":" + "$traitement" + "|"
  $traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" | Select-Object -ExpandProperty DisableWPDRegistrar
  $traitementtemp += "DisableWPDRegistrar" + ":" + "$traitement" + "|"
}
else {
  $traitementtemp = "Not Configured"
}

$chaine += $traitementtemp
$chaine>> $filename
####################

#Prohibit access of the Windows Connect Now wizards'
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "WNC" + "$indextest"

$chaine = "$id" + ";" + "(L2) Ensure 'Prohibit access of the Windows Connect Now wizards' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\UI"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\UI" | Select-Object -ExpandProperty DisableWcnUi

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Check Windows Connection Manager
Write-Host "#########>Begin Windows Connection Manager Audit<#########" -ForegroundColor DarkGreen

#Minimize the number of simultaneous connections to the Internet or a Windows Domain'
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "WCM" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Minimize the number of simultaneous connections to the Internet or a Windows Domain' is set to 'Enabled: 3 = Prevent Wi-Fi when on Ethernet'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" | Select-Object -ExpandProperty fMinimizeConnections

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Prohibit connection to non-domain networks when connected to domain authenticated network (MS only)
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "NC" + "$indextest"

$chaine = "$id" + ";" + "(L2) Ensure 'Prohibit connection to non-domain networks when connected to domain authenticated network' is set to 'Enabled' (MS only)" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" | Select-Object -ExpandProperty fBlockNonDomain

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Check Printers
Write-Host "#########>Begin Printers Audit<#########" -ForegroundColor DarkGreen

#Allow Print Spooler to accept client connections
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "PA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Allow Print Spooler to accept client connections' is set to 'Disabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers" | Select-Object -ExpandProperty RegisterSpoolerRemoteRpcEndPoint

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Configure Redirection Guard
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "PA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Configure Redirection Guard' is set to 'Enabled: Redirection Guard Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers" | Select-Object -ExpandProperty RedirectionguardPolicy

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Configure RPC connection settings: Protocol to use for outgoing RPC connections
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "PA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Configure RPC connection settings: Protocol to use for outgoing RPC connections' is set to 'Enabled: RPC over TCP'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC" | Select-Object -ExpandProperty RpcUseNamedPipeProtocol

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Configure RPC connection settings: Use authentication for outgoing RPC connections
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "PA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Configure RPC connection settings: Use authentication for outgoing RPC connections' is set to 'Enabled: Default'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC" | Select-Object -ExpandProperty RpcAuthentication

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Configure RPC listener settings: Protocols to allow for incoming RPC connections
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "PA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Configure RPC listener settings: Protocols to allow for incoming RPC connections' is set to 'Enabled: RPC over TCP'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC" | Select-Object -ExpandProperty RpcProtocols

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Configure RPC listener settings: Authentication protocol to use for incoming RPC connections
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "PA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Configure RPC listener settings: Authentication protocol to use for incoming RPC connections:' is set to 'Enabled: Negotiate' or higher" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC" | Select-Object -ExpandProperty ForceKerberosForRpc

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Configure RPC over TCP port
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "PA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Configure RPC over TCP port' is set to 'Enabled: 0'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC" | Select-Object -ExpandProperty RpcTcpPort

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Limits print driver installation to Administrators
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "NC" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Limits print driver installation to Administrators' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" | Select-Object -ExpandProperty RestrictDriverInstallationToAdministrators

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Manage processing of Queue-specific files
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "PA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Manage processing of Queue-specific files' is set to 'Enabled: Limit Queue-specific files to Color profiles' " + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers" | Select-Object -ExpandProperty CopyFilesPolicy

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Point and Print Restrictions: When installing drivers for a new connection
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "PA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Point and Print Restrictions: When installing drivers for a new connection' is set to 'Enabled: Show warning and elevation prompt'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" | Select-Object -ExpandProperty NoWarningNoElevationOnInstall

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Point and Print Restrictions: When updating drivers for an existing connection
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "PA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Point and Print Restrictions: When updating drivers for an existing connection' is set to 'Enabled: Show warning and elevation prompt'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" | Select-Object -ExpandProperty UpdatePromptSettings

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Check Notifications
Write-Host "#########>Begin Notifications Audit<#########" -ForegroundColor DarkGreen

#Turn off notifications network usage
$indextest += 1
$chaine = $null
$traitement = $null
$id = "NOTI" + "$indextest"

$chaine = "$id" + ";" + "(L2) Ensure 'Turn off notifications network usage' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" | Select-Object -ExpandProperty NoCloudApplicationNotification

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Check Audit Process Creation
Write-Host "#########>Begin Audit Process Creation Audit<#########" -ForegroundColor DarkGreen

#Include command line in process creation events
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "APC" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Include command line in process creation events' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" | Select-Object -ExpandProperty ProcessCreationIncludeCmdLine_Enabled

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Check Credentials Delegation
Write-Host "#########>Begin Credentials Delegation Audit<#########" -ForegroundColor DarkGreen

#Encryption Oracle Remediation
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "CD" + "$indextest"

$chaine = "$indextest" + ";" + "(L1) Ensure 'Encryption Oracle Remediation' is set to 'Enabled: Force Updated Clients'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters" | Select-Object -ExpandProperty AllowEncryptionOracle

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Remote host allows delegation of non-exportable credentials
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "CD" + "$indextest"

$chaine = "$indextest" + ";" + "(L1) Ensure 'Remote host allows delegation of non-exportable credentials' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" | Select-Object -ExpandProperty AllowProtectedCreds

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Check Device Guard
Write-Host "#########>Begin Device Guard Audit<#########" -ForegroundColor DarkGreen

#Turn On Virtualization Based Security
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "DG" + "$indextest"

$chaine = "$id" + ";" + "(NG) Ensure 'Turn On Virtualization Based Security' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" | Select-Object -ExpandProperty EnableVirtualizationBasedSecurity

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Turn On Virtualization Based Security: Select Platform Security Level' is set to 'Secure Boot and DMA Protection
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "DG" + "$indextest"

$chaine = "$id" + ";" + "(NG) Ensure 'Turn On Virtualization Based Security: Select Platform Security Level' is set to 'Secure Boot' or higher " + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" | Select-Object -ExpandProperty RequirePlatformSecurityFeatures

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Turn On Virtualization Based Security: Virtualization Based Protection of Code Integrity'
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "DG" + "$indextest"

$chaine = "$id" + ";" + "(NG) Ensure 'Turn On Virtualization Based Security: Virtualization Based Protection of Code Integrity' is set to 'Enabled with UEFI lock'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" | Select-Object -ExpandProperty HypervisorEnforcedCodeIntegrity

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Turn On Virtualization Based Security: Require UEFI Memory Attributes Table' is set to 'True (checked)'
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "DG" + "$indextest"

$chaine = "$id" + ";" + "(NG) Ensure 'Turn On Virtualization Based Security: Require UEFI Memory Attributes Table' is set to 'True (checked)' " + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" | Select-Object -ExpandProperty HVCIMATRequired

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Turn On Virtualization Based Security: Credential Guard Configuration (MS only)
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "DG" + "$indextest"

$chaine = "$id" + ";" + " (NG) Ensure 'Turn On Virtualization Based Security: Credential Guard Configuration' is set to 'Enabled with UEFI lock' (MS Only)" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" | Select-Object -ExpandProperty LsaCfgFlags

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Turn On Virtualization Based Security: Credential Guard Configuration (DC only)
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "DG" + "$indextest"

$chaine = "$id" + ";" + " (NG) Ensure 'Turn On Virtualization Based Security: Credential Guard Configuration' is set to 'Enabled with UEFI lock' (DC Only)" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" | Select-Object -ExpandProperty LsaCfgFlags

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Turn On Virtualization Based Security: Secure Launch Configuration
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "DG" + "$indextest"

$chaine = "$id" + ";" + "(NG) Ensure 'Turn On Virtualization Based Security: Secure Launch Configuration' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" | Select-Object -ExpandProperty ConfigureSystemGuardLaunch

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Check Device Installation Restrictions
Write-Host "#########>Begin Device Installation Restrictions Audit<#########" -ForegroundColor DarkGreen

#Prevent device metadata retrieval from the Internet
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "DIR" + "$indextest"

$chaine = "$id" + ";" + " (L1) Ensure 'Prevent device metadata retrieval from the Internet' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Device Metadata"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" | Select-Object -ExpandProperty PreventDeviceMetadataFromNetwork

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Check Early Launch Antimalware
Write-Host "#########>Begin Early Launch Antimalware Audit<#########" -ForegroundColor DarkGreen

#Boot-Start Driver Initialization Policy
$indextest += 1
$chaine = $null
$traitement = $null
$exist = $null
$id = "ELA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Boot-Start Driver Initialization Policy' is set to 'Enabled: Good, unknown and bad but critical' (Value must be 3)" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Policies\EarlyLaunch"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" | Select-Object -ExpandProperty DriverLoadPolicy

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Check Logging and tracing
Write-Host "#########>Begin Logging and Tracing Audit<#########" -ForegroundColor DarkGreen

#Configure registry policy processing: Do not apply during periodic background processing
$indextest += 1
$chaine = $null
$traitement = $null
$id = "LT" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Configure registry policy processing: Do not apply during periodic background processing' is set to 'Enabled: FALSE'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" | Select-Object -ExpandProperty NoBackgroundPolicy

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Configure registry policy processing: Process even if the Group Policy objects have not changed
$indextest += 1
$chaine = $null
$traitement = $null
$id = "LT" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Configure registry policy processing: Process even if the Group Policy objects have not changed' is set to 'Enabled: TRUE'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" | Select-Object -ExpandProperty NoGPOListChanges

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Configure security policy processing: Do not apply during periodic background processing
$indextest += 1
$chaine = $null
$traitement = $null
$id = "LT" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Configure security policy processing: Do not apply during periodic background processing' is set to 'Enabled: FALSE'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}" | Select-Object -ExpandProperty NoBackgroundPolicy

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Configure security policy processing: Process even if the Group Policy objects have not changed
$indextest += 1
$chaine = $null
$traitement = $null
$id = "LT" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Configure security policy processing: Process even if the Group Policy objects have not changed' is set to 'Enabled: TRUE'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}" | Select-Object -ExpandProperty NoGPOListChanges

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Continue experiences on this device
$indextest += 1
$chaine = $null
$traitement = $null
$id = "LT" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Continue experiences on this device' is set to 'Disabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" | Select-Object -ExpandProperty EnableCdp

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Turn off background refresh of Group Policy'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "LT" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Turn off background refresh of Group Policy' is set to 'Disabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" 
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" | Select-Object -ExpandProperty DisableBkGndGroupPolicy

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Internet Communication Settings
Write-Host "#########>Begin Internet Communication Settings audit<#########" -ForegroundColor DarkGreen

#Turn off downloading of print drivers over HTTP 
$indextest += 1
$chaine = $null
$traitement = $null
$id = "ICS" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers" 
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers" | Select-Object -ExpandProperty DisableWebPnPDownload

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Turn off handwriting personalization data sharing
$indextest += 1
$chaine = $null
$traitement = $null
$id = "ICS" + "$indextest"

$chaine = "$id" + ";" + "(L2) Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC" | Select-Object -ExpandProperty PreventHandwritingDataSharing

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Turn off handwriting recognition error reporting
$indextest += 1
$chaine = $null
$traitement = $null
$id = "ICS" + "$indextest"

$chaine = "$id" + ";" + "(L2) Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" | Select-Object -ExpandProperty PreventHandwritingErrorReports

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#MAY NEED TO CHECK AGAIN / TO IMPROVE?
#Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com
$indextest += 1
$chaine = $null
$traitement = $null
$id = "ICS" + "$indextest"

$chaine = "$id" + ";" + "(L2) Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled' " + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard" | Select-Object -ExpandProperty ExitOnMSICW

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename
#######################################

#Turn off Internet download for Web publishing and online ordering wizards'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "ICS" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled' " + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Select-Object -ExpandProperty NoWebServices

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Turn off printing over HTTP
$indextest += 1
$chaine = $null
$traitement = $null
$id = "ICS" + "$indextest"

$chaine = "$id" + ";" + "(L2) Ensure 'Turn off printing over HTTP' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers" | Select-Object -ExpandProperty DisableHTTPPrinting

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Turn off Registration if URL connection is referring to Microsoft.com
$indextest += 1
$chaine = $null
$traitement = $null
$id = "ICS" + "$indextest"

$chaine = "$id" + ";" + "(L2) Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Registration Wizard Control"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Registration Wizard Control" | Select-Object -ExpandProperty NoRegistration

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Turn off Search Companion content file updates
$indextest += 1
$chaine = $null
$traitement = $null
$id = "ICS" + "$indextest"

$chaine = "$id" + ";" + "(L2) Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion" 
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion" | Select-Object -ExpandProperty DisableContentFileUpdates

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Turn off the "Order Prints" picture task
$indextest += 1
$chaine = $null
$traitement = $null
$id = "ICS" + "$indextest"

$chaine = "$id" + ";" + "(L2) Ensure 'Turn off the `Order Prints` picture task' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Select-Object -ExpandProperty NoOnlinePrintsWizard

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Turn off the "Publish to Web" task for files and folders'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "ICS" + "$indextest"

$chaine = "$id" + ";" + "(L2) Ensure 'Turn off the `Publish to Web` task for files and folders' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Select-Object -ExpandProperty NoPublishingWizard

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Turn off the Windows Messenger Customer Experience Improvement Program
$indextest += 1
$chaine = $null
$traitement = $null
$id = "ICS" + "$indextest"

$chaine = "$id" + ";" + "(L2) Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled' " + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client" | Select-Object -ExpandProperty CEIP

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Turn off Windows Customer Experience Improvement Program
$indextest += 1
$chaine = $null
$traitement = $null
$id = "ICS" + "$indextest"

$chaine = "$id" + ";" + "(L2) Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows" | Select-Object -ExpandProperty CEIPEnable

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#####TO IMPROVE#####
#'Turn off Windows Error Reporting
$indextest += 1
$chaine = $null
$traitement = $null
$id = "ICS" + "$indextest"

$chaine = "$id" + ";" + "(L2) Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" 
$exist2 = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting"

if ( $exist -eq $true -or $exist2 -eq $true) {
  $traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" | Select-Object -ExpandProperty Disabled
  $traitementtemp = "Disabled" + ":" + "$traitement" + "|"
  $traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting" | Select-Object -ExpandProperty DoReport
  $traitementtemp += "DoReport" + ":" + "$traitement" + "|"
}
else {
  $traitementtemp = "Not Configured"
}

$chaine += $traitementtemp
$chaine>> $filename
####################

#Check Kerberos
Write-Host "#########>Begin Kerberos Audit<#########" -ForegroundColor DarkGreen

#####TO IMPROVE#####
#Support device authentication using certificate'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "KERB" + "$indextest"

$chaine = "$id" + ";" + "(L2) Ensure 'Support device authentication using certificate' is set to 'Enabled: Automatic'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\kerberos\parameters"

if ( $exist -eq $true) {
  $traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\kerberos\parameters" | Select-Object -ExpandProperty DevicePKInitBehavior
  $traitementtemp = "DevicePKInitBehavior" + ":" + "$traitement" + "|"
  $traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\kerberos\parameters" | Select-Object -ExpandProperty DevicePKInitEnabled
  $traitementtemp += "DevicePKInitEnabled" + ":" + "$traitement" + "|"
}
else {
  $traitementtemp = "Not Configured"
}

$chaine += $traitementtemp
$chaine>> $filename
####################

#Kernel DMA Protection
Write-Host "#########>Begin Kernel DMA Protection Audit<#########" -ForegroundColor DarkGreen

#Enumeration policy for external devices incompatible with Kernel DMA Protection
$indextest += 1
$chaine = $null
$traitement = $null
$id = "KDMAP" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Enumeration policy for external devices incompatible with Kernel DMA Protection' is set to 'Enabled: Block All'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection" | Select-Object -ExpandProperty DeviceEnumerationPolicy

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#LAPS
Write-Host "#########>Begin LAPS audit<#########" -ForegroundColor DarkGreen

#Configure password backup directory
$indextest += 1
$chaine = $null
$traitement = $null
$id = "LAPS" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Configure password backup directory' is set to 'Enabled: Active Directory' or 'Enabled: Azure Active Directory'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" | Select-Object -ExpandProperty BackupDirectory

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Do not allow password expiration time longer than required by policy
$indextest += 1
$chaine = $null
$traitement = $null
$id = "LAPS" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Do not allow password expiration time longer than required by policy' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" | Select-Object -ExpandProperty PwdExpirationProtectionEnabled

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Enable password encryption
$indextest += 1
$chaine = $null
$traitement = $null
$id = "LAPS" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Enable password encryption' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" | Select-Object -ExpandProperty ADPasswordEncryptionEnabled  

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Password Settings: Password Complexity
$indextest += 1
$chaine = $null
$traitement = $null
$id = "LAPS" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Password Settings: Password Complexity' is set to 'Enabled: Large letters + small letters + numbers + special characters'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" | Select-Object -ExpandProperty PasswordComplexity  

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Password Settings: Password Length
$indextest += 1
$chaine = $null
$traitement = $null
$id = "LAPS" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Password Settings: Password Length' is set to 'Enabled: 15 or more'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" | Select-Object -ExpandProperty PasswordLength

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Password Settings: Password Age (Days)
$indextest += 1
$chaine = $null
$traitement = $null
$id = "LAPS" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Password Settings: Password Age (Days)' is set to 'Enabled: 30 or fewer'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" | Select-Object -ExpandProperty PasswordAgeDays

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Post-authentication actions: Grace period (hours)
$indextest += 1
$chaine = $null
$traitement = $null
$id = "LAPS" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Post-authentication actions: Grace period (hours)' is set to 'Enabled: 8 or fewer hours, but not 0' " + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" | Select-Object -ExpandProperty PostAuthenticationResetDelay  

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Post-authentication actions: Actions
$indextest += 1
$chaine = $null
$traitement = $null
$id = "LAPS" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Post-authentication actions: Actions' is set to 'Enabled: Reset the password and logoff the managed account' or higher" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" | Select-Object -ExpandProperty PostAuthenticationActions  

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Locale Services
Write-Host "#########>Begin Locale Services Audit<#########" -ForegroundColor DarkGreen

#Disallow copying of user input methods to the system account for sign-in'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "LSA" + "$indextest"

$chaine = "$id" + ";" + "(L2) Ensure 'Disallow copying of user input methods to the system account for sign-in' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Control Panel\International"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Control Panel\International" | Select-Object -ExpandProperty BlockUserInputMethodsForSignIn

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Logon
Write-Host "#########>Begin Logon audit<#########" -ForegroundColor DarkGreen

#Block user from showing account details on sign-in
$indextest += 1
$chaine = $null
$traitement = $null
$id = "LOGON" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Block user from showing account details on sign-in' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" | Select-Object -ExpandProperty BlockUserFromShowingAccountDetailsOnSignin

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Do not display network selection UI
$indextest += 1
$chaine = $null
$traitement = $null
$id = "LOGON" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Do not display network selection UI' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" | Select-Object -ExpandProperty DontDisplayNetworkSelectionUI

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Do not enumerate connected users on domain-joined computers'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "LOGON" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Do not enumerate connected users on domain-joined computers' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" | Select-Object -ExpandProperty DontEnumerateConnectedUsers

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Enumerate local users on domain-joined computers (MS only)
$indextest += 1
$chaine = $null
$traitement = $null
$id = "LOGON" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Enumerate local users on domain-joined computers' is set to 'Disabled' (MS only)" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" | Select-Object -ExpandProperty EnumerateLocalUsers

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Turn off app notifications on the lock screen'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "LOGON" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Turn off app notifications on the lock screen' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" 
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" | Select-Object -ExpandProperty DisableLockScreenAppNotifications

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Turn off picture password sign-in'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "LOGON" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Turn off picture password sign-in' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" 
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" | Select-Object -ExpandProperty BlockDomainPicturePassword

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Turn on convenience PIN sign-in'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "LOGON" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Turn on convenience PIN sign-in' is set to 'Disabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" 
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" | Select-Object -ExpandProperty AllowDomainPINLogon

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#OS Policies
Write-Host "#########>Begin OS Policies Audit<#########" -ForegroundColor DarkGreen

#Allow Clipboard synchronization across devices
$indextest += 1
$chaine = $null
$traitement = $null
$id = "OSP" + "$indextest"

$chaine = "$id" + ";" + "(L2) Ensure 'Allow Clipboard synchronization across devices' is set to 'Disabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" 
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" | Select-Object -ExpandProperty AllowCrossDeviceClipboard

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Allow upload of User Activities
$indextest += 1
$chaine = $null
$traitement = $null
$id = "OSP" + "$indextest"

$chaine = "$id" + ";" + "(L2) Ensure 'Allow upload of User Activities' is set to 'Disabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" 
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" | Select-Object -ExpandProperty UploadUserActivities

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Sleep Settings
Write-Host "#########>Begin Sleep Settings Audit<#########" -ForegroundColor DarkGreen

#Allow network connectivity during connected-standby (on battery)
$indextest += 1
$chaine = $null
$traitement = $null
$id = "SLEEP" + "$indextest"

$chaine = "$id" + ";" + "(L2) Ensure 'Allow network connectivity during connected-standby (on battery)' is set to 'Disabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9" | Select-Object -ExpandProperty DCSettingIndex

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Allow network connectivity during connected-standby (plugged in)
$indextest += 1
$chaine = $null
$traitement = $null
$id = "SLEEP" + "$indextest"

$chaine = "$id" + ";" + "(L2) Ensure 'Allow network connectivity during connected-standby (plugged in)' is set to 'Disabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9" | Select-Object -ExpandProperty ACSettingIndex

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Require a password when a computer wakes (on battery)'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "SLEEP" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Require a password when a computer wakes (on battery)' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" | Select-Object -ExpandProperty DCSettingIndex

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Require a password when a computer wakes (plugged in)
$indextest += 1
$chaine = $null
$traitement = $null
$id = "SLEEP" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Require a password when a computer wakes (plugged in)' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" | Select-Object -ExpandProperty ACSettingIndex

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Remote Assistance
Write-Host "#########>Begin Remote Assistance Audit<#########" -ForegroundColor DarkGreen

#Configure Offer Remote Assistance'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "RA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Configure Offer Remote Assistance' is set to 'Disabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" | Select-Object -ExpandProperty fAllowUnsolicited

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Configure Solicited Remote Assistance'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "RA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Configure Solicited Remote Assistance' is set to 'Disabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" | Select-Object -ExpandProperty fAllowToGetHelp

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Remote Procedure Call
Write-Host "#########>Begin Remote Procedure Call Audit<#########" -ForegroundColor DarkGreen

#Enable RPC Endpoint Mapper Client Authentication (MS only)
$indextest += 1
$chaine = $null
$traitement = $null
$id = "RPC" + "$indextest"

$chaine = "$id" + ";" + "(L1)  Ensure 'Enable RPC Endpoint Mapper Client Authentication' is set to 'Enabled' (MS only)" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Rpc"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" | Select-Object -ExpandProperty EnableAuthEpResolution

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Restrict Unauthenticated RPC clients (MS only)
$indextest += 1
$chaine = $null
$traitement = $null
$id = "RPC" + "$indextest"

$chaine = "$id" + ";" + "(L2) Ensure 'Restrict Unauthenticated RPC clients' is set to 'Enabled: Authenticated' (MS only)" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" 
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" | Select-Object -ExpandProperty RestrictRemoteClients

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Microsoft Support Diagnostic Tool
Write-Host "#########>Begin Microsoft Support Diagnostic Tool Audit<#########" -ForegroundColor DarkGreen

#Microsoft Support Diagnostic Tool: Turn on MSDT interactive communication with support provider
$indextest += 1
$chaine = $null
$traitement = $null
$id = "MSDT" + "$indextest"

$chaine = "$id" + ";" + "(L2) Ensure 'Microsoft Support Diagnostic Tool: Turn on MSDT interactive communication with support provider' is set to 'Disabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" 
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" | Select-Object -ExpandProperty DisableQueryRemoteServer

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Windows Performance PerfTrack
Write-Host "#########>Begin Windows Performance PerfTrack Audit<#########" -ForegroundColor DarkGreen

#Enable/Disable PerfTrack
$indextest += 1
$chaine = $null
$traitement = $null
$id = "WPP" + "$indextest"

$chaine = "$id" + ";" + "(L2) Ensure 'Enable/Disable PerfTrack' is set to 'Disabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}" | Select-Object -ExpandProperty ScenarioExecutionEnabled

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#User Profiles
Write-Host "#########>Begin User Profiles Audit<#########" -ForegroundColor DarkGreen

#Turn off the advertising ID'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "UP" + "$indextest"

$chaine = "$id" + ";" + "(L2) Ensure 'Turn off the advertising ID' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\policies\Microsoft\Windows\AdvertisingInfo" 
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\policies\Microsoft\Windows\AdvertisingInfo" | Select-Object -ExpandProperty DisabledByGroupPolicy

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Time Providers
Write-Host "#########>Begin Time Providers Audit<#########" -ForegroundColor DarkGreen

#Enable Windows NTP Client
$indextest += 1
$chaine = $null
$traitement = $null
$id = "TP" + "$indextest"

$chaine = "$id" + ";" + "(L2) Ensure 'Enable Windows NTP Client' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient" | Select-Object -ExpandProperty Enabled

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Enable Windows NTP Server (MS only)
$indextest += 1
$chaine = $null
$traitement = $null
$id = "TP" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Enable Windows NTP Server' is set to 'Disabled' (MS only)" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpServer"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpServer" | Select-Object -ExpandProperty Enabled

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#App Package Deployment
Write-Host "#########>Begin App Package Deployment Audit<#########" -ForegroundColor DarkGreen

#Allow a Windows app to share application data between user
$indextest += 1
$chaine = $null
$traitement = $null
$id = "APD" + "$indextest"

$chaine = "$id" + ";" + "(L2) Ensure 'Allow a Windows app to share application data between users' is set to 'Disabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\AppModel\StateManager"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\AppModel\StateManager" | Select-Object -ExpandProperty AllowSharedLocalAppData

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#App runtime
Write-Host "#########>Begin App Runtime Audit<#########" -ForegroundColor DarkGreen

#Allow Microsoft accounts to be optional'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "APR" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Allow Microsoft accounts to be optional' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" | Select-Object -ExpandProperty MSAOptional

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#AutoPlay Policies
Write-Host "#########>Begin AutoPlay Policies Audit<#########" -ForegroundColor DarkGreen

#Disallow Autoplay for non-volume devices
$indextest += 1
$chaine = $null
$traitement = $null
$id = "AP" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Disallow Autoplay for non-volume devices' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer" | Select-Object -ExpandProperty NoAutoplayfornonVolume

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Set the default behavior for AutoRun'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "AP" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Set the default behavior for AutoRun' is set to 'Enabled: Do not execute any autorun commands'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Select-Object -ExpandProperty NoAutorun

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Turn off Autoplay'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "AP" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Turn off Autoplay' is set to 'Enabled: All drives'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Select-Object -ExpandProperty NoDriveTypeAutoRun

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Facial Features
Write-Host "#########>Begin Facial Features Audit<#########" -ForegroundColor DarkGreen

#Use enhanced anti-spoofing when available'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "FF" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Configure enhanced anti-spoofing' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures" | Select-Object -ExpandProperty EnhancedAntiSpoofing

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Camera
Write-Host "#########>Begin Camera Audit<#########" -ForegroundColor DarkGreen

#Allow Use of Camera
$indextest += 1
$chaine = $null
$traitement = $null
$id = "CAM" + "$indextest"

$chaine = "$id" + ";" + "(L2) Ensure 'Allow Use of Camera' is set to 'Disabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Camera"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Camera" | Select-Object -ExpandProperty AllowCamera

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Cloud Content
Write-Host "#########>Begin Cloud Content Audit<#########" -ForegroundColor DarkGreen

#Turn off cloud consumer account state content
$indextest += 1
$chaine = $null
$traitement = $null
$id = "CC" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Turn off cloud consumer account state content' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent" | Select-Object -ExpandProperty DisableConsumerAccountStateContent

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Turn off Microsoft consumer experiences'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "CC" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Turn off Microsoft consumer experiences' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent" | Select-Object -ExpandProperty DisableWindowsConsumerFeatures

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Connect
Write-Host "#########>Begin Connect Audit<#########" -ForegroundColor DarkGreen

#Require pin for pairing'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "CONNECT" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Require pin for pairing' is set to 'Enabled: First Time' OR 'Enabled: Always'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Connect"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Connect" | Select-Object -ExpandProperty RequirePinForPairing

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Credential User Interface
Write-Host "#########>Begin Credential User Interface Audit<#########" -ForegroundColor DarkGreen

#Do not display the password reveal button
$indextest += 1
$chaine = $null
$traitement = $null
$id = "CUI" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Do not display the password reveal button' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CredUI" 
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CredUI" | Select-Object -ExpandProperty DisablePasswordReveal

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Enumerate administrator accounts on elevation'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "CUI" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Enumerate administrator accounts on elevation' is set to 'Disabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI" | Select-Object -ExpandProperty EnumerateAdministrators

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Data Collection and Preview Builds
Write-Host "#########>Begin Data Collection and Preview Builds Audit<#########" -ForegroundColor DarkGreen

#Allow Diagnostic Data
$indextest += 1
$chaine = $null
$traitement = $null
$id = "DCPB" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Allow Diagnostic Data' is set to 'Enabled: Diagnostic data off (not recommended)' or 'Enabled: Send required diagnostic data'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" | Select-Object -ExpandProperty AllowTelemetry

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Configure Authenticated Proxy usage for the Connected User Experience and Telemetry service
$indextest += 1
$chaine = $null
$traitement = $null
$id = "DCPB" + "$indextest"

$chaine = "$id" + ";" + "(L2) Ensure 'Configure Authenticated Proxy usage for the Connected User Experience and Telemetry service' is set to 'Enabled: Disable Authenticated Proxy usage'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" | Select-Object -ExpandProperty DisableEnterpriseAuthProxy

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Disable OneSettings Downloads
$indextest += 1
$chaine = $null
$traitement = $null
$id = "DCPB" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Disable OneSettings Downloads' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" | Select-Object -ExpandProperty DisableOneSettingsDownloads

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Do not show feedback notifications'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "DCPB" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Do not show feedback notifications' is set to 'Enabled' " + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" | Select-Object -ExpandProperty DoNotShowFeedbackNotifications

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Enable OneSettings Auditing
$indextest += 1
$chaine = $null
$traitement = $null
$id = "DCPB" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Enable OneSettings Auditing' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" | Select-Object -ExpandProperty EnableOneSettingsAuditing

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Limit Diagnostic Log Collection
$indextest += 1
$chaine = $null
$traitement = $null
$id = "DCPB" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Limit Diagnostic Log Collection' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" | Select-Object -ExpandProperty LimitDiagnosticLogCollection

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Limit Dump Collection
$indextest += 1
$chaine = $null
$traitement = $null
$id = "DCPB" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Limit Dump Collection' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" | Select-Object -ExpandProperty LimitDumpCollection

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Toggle user control over Insider builds
$indextest += 1
$chaine = $null
$traitement = $null
$id = "DCPB" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Toggle user control over Insider builds' is set to 'Disabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" | Select-Object -ExpandProperty AllowBuildPreview

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Desktop App Installer
Write-Host "#########>Begin Desktop App Installer Audit<#########" -ForegroundColor DarkGreen

#Enable App Installer
$indextest += 1
$chaine = $null
$traitement = $null
$id = "DAI" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Enable App Installer' is set to 'Disabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppInstaller"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" | Select-Object -ExpandProperty EnableAppInstaller

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Enable App Installer Experimental Features
$indextest += 1
$chaine = $null
$traitement = $null
$id = "DAI" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Enable App Installer Experimental Features' is set to 'Disabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppInstaller"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" | Select-Object -ExpandProperty EnableExperimentalFeatures

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Enable App Installer Hash Override
$indextest += 1
$chaine = $null
$traitement = $null
$id = "DAI" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Enable App Installer Hash Override' is set to 'Disabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppInstaller"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" | Select-Object -ExpandProperty EnableHashOverride

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Enable App Installer ms-appinstaller protocol
$indextest += 1
$chaine = $null
$traitement = $null
$id = "DAI" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Enable App Installer ms-appinstaller protocol' is set to 'Disabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppInstaller"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" | Select-Object -ExpandProperty EnableMSAppInstallerProtocol

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Application
Write-Host "#########>Begin Application Log Audit<#########" -ForegroundColor DarkGreen

#Application: Control Event Log behavior when the log file reaches its maximum size'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "APPL" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Application: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled' " + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" | Select-Object -ExpandProperty Retention

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Application: Specify the maximum log file size
$indextest += 1
$chaine = $null
$traitement = $null
$id = "APPL" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Application: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" | Select-Object -ExpandProperty MaxSize

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Security 
Write-Host "#########>Begin Security Log Audit<#########" -ForegroundColor DarkGreen

#Security: Control Event Log behavior when the log file reaches its maximum size
$indextest += 1
$chaine = $null
$traitement = $null
$id = "SECL" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Security: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" 
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" | Select-Object -ExpandProperty Retention

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Security: Specify the maximum log file size (KB)'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "SECL" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Security: Specify the maximum log file size (KB)' is set to 'Enabled: 196,608 or greater'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" | Select-Object -ExpandProperty MaxSize

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Setup 
Write-Host "#########>Begin Setup Log Audit<#########" -ForegroundColor DarkGreen

#Setup: Control Event Log behavior when the log file reaches its maximum size'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "SETL" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Setup: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup" | Select-Object -ExpandProperty Retention

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Setup: Specify the maximum log file size (KB)'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "SETL" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Setup: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup" 
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup" | Select-Object -ExpandProperty MaxSize

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#System 
Write-Host "#########>Begin System Log audit<#########" -ForegroundColor DarkGreen

#System: Control Event Log behavior when the log file reaches its maximum size'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "SYSL" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'System: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\System"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\System" | Select-Object -ExpandProperty Retention

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Setup: Specify the maximum log file size (KB)'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "SYSL" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'System: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\System"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\System" | Select-Object -ExpandProperty MaxSize

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Previous Versions
Write-Host "#########>Begin Previous Versions Audit<#########" -ForegroundColor DarkGreen

#Turn off Data Execution Prevention for Explorer'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "PV" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Turn off Data Execution Prevention for Explorer' is set to 'Disabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer" 
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer" | Select-Object -ExpandProperty NoDataExecutionPrevention

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Turn off heap termination on corruption'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "PV" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Turn off heap termination on corruption' is set to 'Disabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer" | Select-Object -ExpandProperty NoHeapTerminationOnCorruption

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Turn off shell protocol protected mode'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "PV" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Turn off shell protocol protected mode' is set to 'Disabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Select-Object -ExpandProperty PreXPSP2ShellProtocolBehavior

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Location and Sensors
Write-Host "#########>Begin Location and Sensors Audit<#########" -ForegroundColor DarkGreen

#Turn off location'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "LS" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Turn off location' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" 
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" | Select-Object -ExpandProperty DisableLocation

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Messaging
Write-Host "#########>Begin Messaging Audit<#########" -ForegroundColor DarkGreen

#Allow Message Service Cloud Sync
$indextest += 1
$chaine = $null
$traitement = $null
$id = "MESS" + "$indextest"

$chaine = "$id" + ";" + "(L2) Ensure 'Allow Message Service Cloud Sync' is set to 'Disabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Messaging" 
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Messaging" | Select-Object -ExpandProperty AllowMessageSync

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Microsoft Account
Write-Host "#########>Begin Microsoft Account Audit<#########" -ForegroundColor DarkGreen

#Block all consumer Microsoft account user authentication'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "MA" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Block all consumer Microsoft account user authentication' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MicrosoftAccount"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MicrosoftAccount" | Select-Object -ExpandProperty DisableUserAuth

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#MAPS
Write-Host "#########>Begin MAPS Audit<#########" -ForegroundColor DarkGreen

#Configure local setting override for reporting to Microsoft MAPS
$indextest += 1
$chaine = $null
$traitement = $null
$id = "MAPS" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Configure local setting override for reporting to Microsoft MAPS' is set to 'Disabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" | Select-Object -ExpandProperty LocalSettingOverrideSpynetReporting

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Join Microsoft MAPS
$indextest += 1
$chaine = $null
$traitement = $null
$id = "MAPS" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Join Microsoft MAPS' is set to 'Disabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" | Select-Object -ExpandProperty SpynetReporting

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Attack Surface Reduction
Write-Host "#########>Begin Attack Surface Reduction Audit<#########" -ForegroundColor DarkGreen

#Configure Attack Surface Reduction rules
$indextest += 1
$chaine = $null
$traitement = $null
$id = "ASR" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Configure Attack Surface Reduction rules' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR" | Select-Object -ExpandProperty ExploitGuard_ASR_Rules

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#####TO IMPROVE#####
#Configure Attack Surface Reduction rules: Set the state for each ASR rule
$indextest += 1
$chaine = $null
$traitement = $null
$id = "ASR" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is configured" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"

if ( $exist -eq $true) {
  $traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" | Select-Object -ExpandProperty "26190899-1602-49e8-8b27-eb1d0a1ce869"
  $traitementtemp = "26190899-1602-49e8-8b27-eb1d0a1ce869" + ":" + "$traitement" + "|"
  $traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" | Select-Object -ExpandProperty "3b576869-a4ec-4529-8536-b80a7769e899"
  $traitementtemp += "3b576869-a4ec-4529-8536-b80a7769e899" + ":" + "$traitement" + "|"
  $traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" | Select-Object -ExpandProperty "56a863a9-875e-4185-98a7-b882c64b5ce5"
  $traitementtemp += "56a863a9-875e-4185-98a7-b882c64b5ce5" + ":" + "$traitement" + "|"
  $traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" | Select-Object -ExpandProperty "5beb7efe-fd9a-4556-801d-275e5ffc04cc"
  $traitementtemp += "5beb7efe-fd9a-4556-801d-275e5ffc04cc" + ":" + "$traitement" + "|"
  $traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" | Select-Object -ExpandProperty "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84"
  $traitementtemp += "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84" + ":" + "$traitement" + "|"
  $traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" | Select-Object -ExpandProperty "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c"
  $traitementtemp += "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" + ":" + "$traitement" + "|"
  $traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" | Select-Object -ExpandProperty "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b"
  $traitementtemp += "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b" + ":" + "$traitement" + "|"
  $traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" | Select-Object -ExpandProperty "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2"
  $traitementtemp += "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" + ":" + "$traitement" + "|"
  $traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" | Select-Object -ExpandProperty "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4"
  $traitementtemp += "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" + ":" + "$traitement" + "|"
  $traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" | Select-Object -ExpandProperty "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550"
  $traitementtemp += "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550" + ":" + "$traitement" + "|"
  $traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" | Select-Object -ExpandProperty "d3e037e1-3eb8-44c8-a917-57927947596d"
  $traitementtemp += "d3e037e1-3eb8-44c8-a917-57927947596d" + ":" + "$traitement" + "|"
  $traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" | Select-Object -ExpandProperty "d4f940ab-401b-4efc-aadc-ad5f3c50688a"
  $traitementtemp += "d4f940ab-401b-4efc-aadc-ad5f3c50688a" + ":" + "$traitement" + "|"
  $traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" | Select-Object -ExpandProperty "e6db77e5-3df2-4cf1-b95a-636979351e5b"
  $traitementtemp += "e6db77e5-3df2-4cf1-b95a-636979351e5b" + ":" + "$traitement" + "|"
}
else {
  $traitementtemp = "Not Configured"
}

$chaine += $traitementtemp
$chaine>> $filename
####################

#Network Protection
Write-Host "#########>Begin Network Protection Audit<#########" -ForegroundColor DarkGreen

#Prevent users and apps from accessing dangerous websites
$indextest += 1
$chaine = $null
$traitement = $null
$id = "NP" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Prevent users and apps from accessing dangerous websites' is set to 'Enabled: Block'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" | Select-Object -ExpandProperty EnableNetworkProtection

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#MpEngine
Write-Host "#########>Begin MpEngine Audit<#########" -ForegroundColor DarkGreen

#Enable file hash computation feature
$indextest += 1
$chaine = $null
$traitement = $null
$id = "MPE" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Enable file hash computation feature' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" | Select-Object -ExpandProperty EnableFileHashComputation

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Real-time Protection
Write-Host "#########>Begin Real-time Protection Audit<#########" -ForegroundColor DarkGreen

#Scan all downloaded files and attachments
$indextest += 1
$chaine = $null
$traitement = $null
$id = "RTP" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Scan all downloaded files and attachments' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" | Select-Object -ExpandProperty DisableIOAVProtection

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Turn off real-time protection
$indextest += 1
$chaine = $null
$traitement = $null
$id = "RTP" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Turn off real-time protection' is set to 'Disabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" | Select-Object -ExpandProperty DisableRealtimeMonitoring

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Turn on behavior monitoring
$indextest += 1
$chaine = $null
$traitement = $null
$id = "RTP" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Turn on behavior monitoring' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" | Select-Object -ExpandProperty DisableBehaviorMonitoring

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Turn on script scanning
$indextest += 1
$chaine = $null
$traitement = $null
$id = "RTP" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Turn on script scanning' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" | Select-Object -ExpandProperty DisableScriptScanning

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Reporting
Write-Host "#########>Begin Reporting Audit<#########" -ForegroundColor DarkGreen

#Configure Watson events
$indextest += 1
$chaine = $null
$traitement = $null
$id = "RPRT" + "$indextest"

$chaine = "$id" + ";" + "(L2) Ensure 'Configure Watson events' is set to 'Disabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" | Select-Object -ExpandProperty DisableGenericRePorts

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Scan
Write-Host "#########>Begin Scan Audit<#########" -ForegroundColor DarkGreen

#Scan packed executables
$indextest += 1
$chaine = $null
$traitement = $null
$id = "SCAN" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Scan packed executables' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Scan"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" | Select-Object -ExpandProperty DisablePackedExeScanning

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Scan removable drives
$indextest += 1
$chaine = $null
$traitement = $null
$id = "SCAN" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Scan removable drives' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Scan"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" | Select-Object -ExpandProperty DisableRemovableDriveScanning

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Turn on e-mail scanning
$indextest += 1
$chaine = $null
$traitement = $null
$id = "SCAN" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Turn on e-mail scanning' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Scan"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" | Select-Object -ExpandProperty DisableEmailScanning

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Threats
Write-Host "#########>Begin Threats Audit<#########" -ForegroundColor DarkGreen

#Configure detection for potentially unwanted applications
$indextest += 1
$chaine = $null
$traitement = $null
$id = "THREAT" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Configure detection for potentially unwanted applications' is set to 'Enabled: Block'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" | Select-Object -ExpandProperty PUAProtection

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Turn off Microsoft Defender AntiVirus
$indextest += 1
$chaine = $null
$traitement = $null
$id = "THREAT" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Turn off Microsoft Defender AntiVirus' is set to 'Disabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" | Select-Object -ExpandProperty DisableAntiSpyware

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#OneDrive
Write-Host "#########>Begin OneDrive Audit<#########" -ForegroundColor DarkGreen

#Prevent the usage of OneDrive for file storage'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "OD" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Prevent the usage of OneDrive for file storage' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\OneDrive"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\OneDrive" | Select-Object -ExpandProperty DisableFileSyncNGSC

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Push To Install 
Write-Host "#########>Begin Push To Install Audit<#########" -ForegroundColor DarkGreen

#Turn off Push To Install service
$indextest += 1
$chaine = $null
$traitement = $null
$id = "PTI" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Turn off Push To Install service' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\PushToInstall"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\PushToInstall" | Select-Object -ExpandProperty DisablePushToInstall

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Remote Desktop Connection Client
Write-Host "#########>Begin Remote Desktop Connection Client Audit<#########" -ForegroundColor DarkGreen

#Do not allow passwords to be saved'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "RDCC" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Do not allow passwords to be saved' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" | Select-Object -ExpandProperty DisablePasswordSaving

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Remote Desktop Session Host
Write-Host "#########>Begin Remote Desktop Session Host Audit<#########" -ForegroundColor DarkGreen

#Restrict Remote Desktop Services users to a single Remote Desktop Services session'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "RDSH" + "$indextest"

$chaine = "$id" + ";" + "(L2) Ensure 'Restrict Remote Desktop Services users to a single Remote Desktop Services session' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" | Select-Object -ExpandProperty fSingleSessionPerUser

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Device and Resource Redirection
Write-Host "#########>Begin Device and Resource Redirection Audit<#########" -ForegroundColor DarkGreen

#Do not allow COM port redirection'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "DRR" + "$indextest"

$chaine = "$id" + ";" + "(L2) Ensure 'Do not allow COM port redirection' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" 
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" | Select-Object -ExpandProperty fDisableCcm

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Do not allow drive redirection'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "DRR" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Do not allow drive redirection' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" 
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" | Select-Object -ExpandProperty fDisableCdm

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Do not allow LPT port redirection'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "DRR" + "$indextest"

$chaine = "$id" + ";" + "(L2) Ensure 'Do not allow LPT port redirection' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" | Select-Object -ExpandProperty fDisableLPT

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Do not allow supported Plug and Play device redirection'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "DRR" + "$indextest"

$chaine = "$id" + ";" + "(L2) Ensure 'Do not allow supported Plug and Play device redirection' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" | Select-Object -ExpandProperty fDisablePNPRedir

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Security
Write-Host "#########>Begin Security Audit<#########" -ForegroundColor DarkGreen

#Always prompt for password upon connection'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "SEC" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Always prompt for password upon connection' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" | Select-Object -ExpandProperty fPromptForPassword

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Require secure RPC communication'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "SEC" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Require secure RPC communication' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" 
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" | Select-Object -ExpandProperty fEncryptRPCTraffic

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Require use of specific security layer for remote (RDP) connections''
$indextest += 1
$chaine = $null
$traitement = $null
$id = "SEC" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Require use of specific security layer for remote (RDP) connections' is set to 'Enabled: SSL'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" 
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" | Select-Object -ExpandProperty SecurityLayer

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Require user authentication for remote connections by using Network Level Authentication'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "SEC" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Require user authentication for remote connections by using Network Level Authentication' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" 
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" | Select-Object -ExpandProperty UserAuthentication

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#'Set client connection encryption level'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "SEC" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Set client connection encryption level' is set to 'Enabled: High Level'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" 
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" | Select-Object -ExpandProperty MinEncryptionLevel

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Session Time Limits
Write-Host "#########>Begin Session Time Limits Audit<#########" -ForegroundColor DarkGreen

#Set time limit for active but idle Remote Desktop Services sessions'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "STL" + "$indextest"

$chaine = "$id" + ";" + "(L2) Ensure 'Set time limit for active but idle Remote Desktop Services sessions' is set to 'Enabled: 15 minutes or less, but not Never (0)'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" | Select-Object -ExpandProperty MaxIdleTime

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Set time limit for disconnected sessions'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "STL" + "$indextest"

$chaine = "$id" + ";" + "(L2) Ensure 'Set time limit for disconnected sessions' is set to 'Enabled: 1 minute'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" | Select-Object -ExpandProperty MaxDisconnectionTime

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Temporary Folders
Write-Host "#########>Begin Temporary Folders Audit<#########" -ForegroundColor DarkGreen

#Do not delete temp folders upon exit'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "TF" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Do not delete temp folders upon exit' is set to 'Disabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" | Select-Object -ExpandProperty DeleteTempDirsOnExit

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Do not use temporary folders per session'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "TF" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Do not use temporary folders per session' is set to 'Disabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" | Select-Object -ExpandProperty PerSessionTempDir

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#RSS Feeds
Write-Host "#########>Begin RSS Feeds Audit<#########" -ForegroundColor DarkGreen

#Prevent downloading of enclosures'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "RSSF" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Prevent downloading of enclosures' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" | Select-Object -ExpandProperty DisableEnclosureDownload

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Search
Write-Host "#########>Begin Search Audit<#########" -ForegroundColor DarkGreen

#Allow Cloud Search'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "SEARCH" + "$indextest"

$chaine = "$id" + ";" + "(L2) Ensure 'Allow Cloud Search' is set to 'Enabled: Disable Cloud Search'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" | Select-Object -ExpandProperty AllowCloudSearch

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Allow indexing of encrypted files'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "SEARCH" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Allow indexing of encrypted files' is set to 'Disabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" | Select-Object -ExpandProperty AllowIndexingEncryptedStoresOrItems

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Allow search highlights
$indextest += 1
$chaine = $null
$traitement = $null
$id = "SEARCH" + "$indextest"

$chaine = "$id" + ";" + "(L2) Ensure 'Allow search highlights' is set to 'Disabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" | Select-Object -ExpandProperty EnableDynamicContentInWSB

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Software Protection Platform
Write-Host "#########>Begin Software Protection Platform Audit<#########" -ForegroundColor DarkGreen


#Turn off KMS Client Online AVS Validation'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "SPP" + "$indextest"

$chaine = "$id" + ";" + "(L2) Ensure 'Turn off KMS Client Online AVS Validation' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" 
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" | Select-Object -ExpandProperty NoGenTicket

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Explorer
Write-Host "#########>Begin Explorer Audit<#########" -ForegroundColor DarkGreen

#####TO IMPROVE#####
#Configure Windows Defender SmartScreen'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "EXPL" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Configure Windows Defender SmartScreen' is set to 'Enabled: Warn and prevent bypass' " + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System"

if ( $exist -eq $true) {
  $traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" | Select-Object -ExpandProperty EnableSmartScreen
  $traitementtemp = "EnableSmartScreen" + ":" + "$traitement" + "|"
  $traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" | Select-Object -ExpandProperty ShellSmartScreenLevel
  $traitementtemp += "ShellSmartScreenLevel" + ":" + "$traitement" + "|"
}
else {
  $traitementtemp = "Not Configured"
}

$chaine += $traitementtemp
$chaine>> $filename
####################


#Windows Ink Workspace
Write-Host "#########>Begin Windows Ink Workspace Audit<#########" -ForegroundColor DarkGreen

#Allow suggested apps in Windows Ink Workspace'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "WIW" + "$indextest"

$chaine = "$id" + ";" + "(L2) Ensure 'Allow suggested apps in Windows Ink Workspace' is set to 'Disabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" | Select-Object -ExpandProperty AllowSuggestedAppsInWindowsInkWorkspace

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Windows Ink Workspace'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "WIW" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Allow Windows Ink Workspace' is set to 'Enabled: On, but disallow access above lock' OR 'Enabled: Disabled' (Value must be 0 or 1)" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" | Select-Object -ExpandProperty AllowWindowsInkWorkspace

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Windows Installer
Write-Host "#########>Begin Windows Installer Audit<#########" -ForegroundColor DarkGreen

#Allow user control over installs'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "WI" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Allow user control over installs' is set to 'Disabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer" 
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer" | Select-Object -ExpandProperty EnableUserControl

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Always install with elevated privileges'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "WI" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Always install with elevated privileges' is set to 'Disabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer" 
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer" | Select-Object -ExpandProperty AlwaysInstallElevated

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Prevent Internet Explorer security prompt for Windows Installer scripts'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "WI" + "$indextest"

$chaine = "$id" + ";" + "(L2) Ensure 'Prevent Internet Explorer security prompt for Windows Installer scripts' is set to 'Disabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer" 
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer" | Select-Object -ExpandProperty SafeForScripting

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Windows Logon Options
Write-Host "#########>Begin Windows Logon Options Audit<#########" -ForegroundColor DarkGreen

#Sign-in and lock last interactive user automatically after a restart
$indextest += 1
$chaine = $null
$traitement = $null
$id = "WLO" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Sign-in and lock last interactive user automatically after a restart' is set to 'Disabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" | Select-Object -ExpandProperty DisableAutomaticRestartSignOn

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Windows PowerShell
Write-Host "#########>Begin Windows PowerShell Audit<#########" -ForegroundColor DarkGreen

#Turn on PowerShell Script Block Logging'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "WP" + "$indextest"

$chaine = "$id" + ";" + "(L2) Ensure 'Turn on PowerShell Script Block Logging' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" | Select-Object -ExpandProperty EnableScriptBlockLogging

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Turn on PowerShell Transcription'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "WP" + "$indextest"

$chaine = "$id" + ";" + "(L2) Ensure 'Turn on PowerShell Transcription' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" | Select-Object -ExpandProperty EnableTranscripting

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#WinRM Client
Write-Host "#########>Begin WinRM Client Audit<#########" -ForegroundColor DarkGreen

#Allow Basic authentication'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "WRMC" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Allow Basic authentication' is set to 'Disabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" | Select-Object -ExpandProperty AllowBasic

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Allow unencrypted traffic'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "WRMC" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Allow unencrypted traffic' is set to 'Disabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" | Select-Object -ExpandProperty AllowUnencryptedTraffic

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Disallow Digest authentication'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "WRMC" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Disallow Digest authentication' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" | Select-Object -ExpandProperty AllowDigest

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#WinRM Service
Write-Host "#########>Begin WinRM Service Audit<#########" -ForegroundColor DarkGreen

#Allow Basic authentication'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "WRMS" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Allow Basic authentication' is set to 'Disabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" 
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" | Select-Object -ExpandProperty AllowBasic

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Allow remote server management through WinRM'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "WRMS" + "$indextest"

$chaine = "$id" + ";" + "(L2) Ensure 'Allow remote server management through WinRM' is set to 'Disabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" | Select-Object -ExpandProperty AllowAutoConfig

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Allow unencrypted traffic'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "WRMS" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Allow unencrypted traffic' is set to 'Disabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" 
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" | Select-Object -ExpandProperty AllowUnencryptedTraffic

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Disallow WinRM from storing RunAs credentials'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "WRMS" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Disallow WinRM from storing RunAs credentials' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" 
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" | Select-Object -ExpandProperty DisableRunAs

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Windows Remote Shell
Write-Host "#########>Begin Windows Remote Shell Audit<#########" -ForegroundColor DarkGreen

#Allow Remote Shell Access'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "WRS" + "$indextest"

$chaine = "$id" + ";" + "(L2) Ensure 'Allow Remote Shell Access' is set to 'Disabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS" 
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS" | Select-Object -ExpandProperty AllowRemoteShellAccess

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#App and Browser Protection
Write-Host "#########>Begin App and Browser Protection Audit<#########" -ForegroundColor DarkGreen

#Prevent users from modifying settings'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "ABP" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Prevent users from modifying settings' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection" | Select-Object -ExpandProperty DisallowExploitProtectionOverride

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Legacy Policies
Write-Host "#########>Begin Legacy Policies Audit<#########" -ForegroundColor DarkGreen

#No auto-restart with logged on users for scheduled automatic updates installations
$indextest += 1
$chaine = $null
$traitement = $null
$id = "LP" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'No auto-restart with logged on users for scheduled automatic updates installations' is set to 'Disabled' " + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" | Select-Object -ExpandProperty NoAutoRebootWithLoggedOnUsers

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Manage End User Experience
Write-Host "#########>Begin Manage End User Experience Audit<#########" -ForegroundColor DarkGreen

#Configure Automatic Updates
$indextest += 1
$chaine = $null
$traitement = $null
$id = "MEUE" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Configure Automatic Updates' is set to 'Enabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" | Select-Object -ExpandProperty NoAutoUpdate

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#Configure Automatic Updates: Scheduled install day
$indextest += 1
$chaine = $null
$traitement = $null
$id = "MEUE" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Configure Automatic Updates: Scheduled install day' is set to '0 - Every day'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" | Select-Object -ExpandProperty ScheduledInstallDay

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename


#Manage Updates Offered from Windows Update
Write-Host "#########>Begin Manage Updates Offered from Windows Update Audit<#########" -ForegroundColor DarkGreen

#Manage preview builds
$indextest += 1
$chaine = $null
$traitement = $null
$id = "WU" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Manage preview builds' is set to 'Disabled'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
$traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" | Select-Object -ExpandProperty ManagePreviewBuildsPolicyValue

if ($exist -eq $true -and $checkConditions -notcontains $traitement) {
  $traitement = $traitement
}
else {
  $traitement = "Not Configured"
}

$chaine += $traitement
$chaine>> $filename

#####TO IMPROVE#####
#Select when Preview Builds and Feature Updates are received
$indextest += 1
$chaine = $null
$traitement = $null
$id = "WU" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Select when Preview Builds and Feature Updates are received' is set to 'Enabled: 180 or more days'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"

if ( $exist -eq $true) {
  $traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" | Select-Object -ExpandProperty DeferFeatureUpdates
  $traitementtemp = "DeferFeatureUpdates" + ":" + "$traitement" + "|"
  $traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" | Select-Object -ExpandProperty DeferFeatureUpdatesPeriodInDays
  $traitementtemp += "DeferFeatureUpdatesPeriodInDays" + ":" + "$traitement" + "|"
}
else {
  $traitementtemp = "Not Configured"
}

$chaine += $traitementtemp
$chaine>> $filename
####################

#####TO IMPROVE#####
#Select when Quality Updates are received'
$indextest += 1
$chaine = $null
$traitement = $null
$id = "WU" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Select when Quality Updates are received' is set to 'Enabled: 0 days'" + ";"
$exist = Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" 

if ( $exist -eq $true) {
  $traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" | Select-Object -ExpandProperty DeferQualityUpdates
  $traitementtemp = "DeferQualityUpdates" + ":" + "$traitement" + "|"
  $traitement = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" | Select-Object -ExpandProperty DeferQualityUpdatesPeriodInDays
  $traitementtemp += "DeferQualityUpdatesPeriodInDays" + ":" + "$traitement" + "|"
}
else {
  $traitementtemp = "Not Configured"
}

$chaine += $traitementtemp
$chaine>> $filename
####################


#Notifications
Write-Host "#########>Begin Notifications Audit<#########" -ForegroundColor DarkGreen

#Turn off toast notifications on the lock screen
$indextest += 1
$chaine = $null
$traitement = $null
$id = "NOTI" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Turn off toast notifications on the lock screen' is set to 'Enabled'" + ";"

# Get all SID paths under HKEY_USERS that match S-1-5-21-*
$sidPaths = Get-ChildItem -Path "Registry::HKEY_USERS" | Where-Object { $_.PSChildName -match '^S-1-5-21-' }

foreach ($sid in $sidPaths) {
    # Construct the registry path for the current SID
    $regPath = "Registry::HKEY_USERS\$($sid.PSChildName)\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"

    # Check if the registry path exists
    if (Test-Path -Path $regPath) {
        # Try to get the NoToastApplicationNotificationOnLockScreen property
        $traitementForSid = Get-ItemProperty -Path $regPath | Select-Object -ExpandProperty NoToastApplicationNotificationOnLockScreen

        # Check if traitementForSid is null, "Not Configured", or "Not Defined"
        if ($checkConditions -notcontains $traitementForSid) {
            $traitementForSid = $traitementForSid
        } else {
          $traitementForSid = "Not Configured / Check Manually"
        }
    } else {
        $traitementForSid = "Not Configured / Check Manually"
    }

    # Append the traitement for this SID to the main traitement string
    $traitement += "SID: $($sid.PSChildName) - Traitement: $traitementForSid | "
}

$chaine += $traitement
$chaine>> $filename


#Internet Communication Settings
Write-Host "#########>Begin Internet Communication Settings audit<#########" -ForegroundColor DarkGreen

#Turn off Help Experience Improvement Program
$indextest += 1
$chaine = $null
$traitement = $null
$id = "ICS" + "$indextest"

$chaine = "$id" + ";" + "(L2) Ensure 'Turn off Help Experience Improvement Program' is set to 'Enabled'" + ";"

# Get all SID paths under HKEY_USERS that match S-1-5-21-*
$sidPaths = Get-ChildItem -Path "Registry::HKEY_USERS" | Where-Object { $_.PSChildName -match '^S-1-5-21-' }

foreach ($sid in $sidPaths) {
    # Construct the registry path for the current SID
    $regPath = "Registry::HKEY_USERS\$($sid.PSChildName)\Software\Policies\Microsoft\Assistance\Client\1.0"

    # Check if the registry path exists
    if (Test-Path -Path $regPath) {
        # Try to get the NoImplicitFeedback property
        $traitementForSid = Get-ItemProperty -Path $regPath | Select-Object -ExpandProperty NoImplicitFeedback

        # Check if traitementForSid is null, "Not Configured", or "Not Defined"
        if ($checkConditions -notcontains $traitementForSid) {
            $traitementForSid = $traitementForSid
        } else {
          $traitementForSid = "Not Configured / Check Manually"
        }
    } else {
        $traitementForSid = "Not Configured / Check Manually"
    }

    # Append the traitement for this SID to the main traitement string
    $traitement += "SID: $($sid.PSChildName) - Traitement: $traitementForSid | "
}

$chaine += $traitement
$chaine>> $filename


#Attachment Manager
Write-Host "#########>Begin Attachment Manager Audit<#########" -ForegroundColor DarkGreen

#Do not preserve zone information in file attachments
$indextest += 1
$chaine = $null
$traitement = $null
$id = "AM" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Do not preserve zone information in file attachments' is set to 'Disabled'" + ";"

# Get all SID paths under HKEY_USERS that match S-1-5-21-*
$sidPaths = Get-ChildItem -Path "Registry::HKEY_USERS" | Where-Object { $_.PSChildName -match '^S-1-5-21-' }

foreach ($sid in $sidPaths) {
    # Construct the registry path for the current SID
    $regPath = "Registry::HKEY_USERS\$($sid.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments"

    # Check if the registry path exists
    if (Test-Path -Path $regPath) {
        # Try to get the SaveZoneInformation property
        $traitementForSid = Get-ItemProperty -Path $regPath | Select-Object -ExpandProperty SaveZoneInformation

        # Check if traitementForSid is null, "Not Configured", or "Not Defined"
        if ($checkConditions -notcontains $traitementForSid) {
            $traitementForSid = $traitementForSid
        } else {
          $traitementForSid = "Not Configured / Check Manually"
        }
    } else {
        $traitementForSid = "Not Configured / Check Manually"
    }

    # Append the traitement for this SID to the main traitement string
    $traitement += "SID: $($sid.PSChildName) - Traitement: $traitementForSid | "
}

$chaine += $traitement
$chaine>> $filename

#Notify antivirus programs when opening attachments
$indextest += 1
$chaine = $null
$traitement = $null
$id = "AM" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Notify antivirus programs when opening attachments' is set to 'Enabled'" + ";"

# Get all SID paths under HKEY_USERS that match S-1-5-21-*
$sidPaths = Get-ChildItem -Path "Registry::HKEY_USERS" | Where-Object { $_.PSChildName -match '^S-1-5-21-' }

foreach ($sid in $sidPaths) {
    # Construct the registry path for the current SID
    $regPath = "Registry::HKEY_USERS\$($sid.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments"

    # Check if the registry path exists
    if (Test-Path -Path $regPath) {
        # Try to get the ScanWithAntiVirus property
        $traitementForSid = Get-ItemProperty -Path $regPath | Select-Object -ExpandProperty ScanWithAntiVirus 

        # Check if traitementForSid is null, "Not Configured", or "Not Defined"
        if ($checkConditions -notcontains $traitementForSid) {
            $traitementForSid = $traitementForSid
        } else {
          $traitementForSid = "Not Configured / Check Manually"
        }
    } else {
        $traitementForSid = "Not Configured / Check Manually"
    }

    # Append the traitement for this SID to the main traitement string
    $traitement += "SID: $($sid.PSChildName) - Traitement: $traitementForSid | "
}

$chaine += $traitement
$chaine>> $filename


#Cloud Content
Write-Host "#########>Begin Cloud Content Audit<#########" -ForegroundColor DarkGreen

#Configure Windows spotlight on lock screen
$indextest += 1
$chaine = $null
$traitement = $null
$id = "CC" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Configure Windows spotlight on lock screen' is set to 'Disabled'" + ";"

# Get all SID paths under HKEY_USERS that match S-1-5-21-*
$sidPaths = Get-ChildItem -Path "Registry::HKEY_USERS" | Where-Object { $_.PSChildName -match '^S-1-5-21-' }

foreach ($sid in $sidPaths) {
    # Construct the registry path for the current SID
    $regPath = "Registry::HKEY_USERS\$($sid.PSChildName)\Software\Policies\Microsoft\Windows\CloudContent"

    # Check if the registry path exists
    if (Test-Path -Path $regPath) {
        # Try to get the ConfigureWindowsSpotlight property
        $traitementForSid = Get-ItemProperty -Path $regPath | Select-Object -ExpandProperty ConfigureWindowsSpotlight

        # Check if traitementForSid is null, "Not Configured", or "Not Defined"
        if ($checkConditions -notcontains $traitementForSid) {
            $traitementForSid = $traitementForSid
        } else {
          $traitementForSid = "Not Configured / Check Manually"
        }
    } else {
        $traitementForSid = "Not Configured / Check Manually"
    }

    # Append the traitement for this SID to the main traitement string
    $traitement += "SID: $($sid.PSChildName) - Traitement: $traitementForSid | "
}

$chaine += $traitement
$chaine>> $filename

#Do not suggest third-party content in Windows spotlight
$indextest += 1
$chaine = $null
$traitement = $null
$id = "CC" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Do not suggest third-party content in Windows spotlight' is set to 'Enabled'" + ";"

# Get all SID paths under HKEY_USERS that match S-1-5-21-*
$sidPaths = Get-ChildItem -Path "Registry::HKEY_USERS" | Where-Object { $_.PSChildName -match '^S-1-5-21-' }

foreach ($sid in $sidPaths) {
    # Construct the registry path for the current SID
    $regPath = "Registry::HKEY_USERS\$($sid.PSChildName)\Software\Policies\Microsoft\Windows\CloudContent"

    # Check if the registry path exists
    if (Test-Path -Path $regPath) {
        # Try to get the DisableThirdPartySuggestions property
        $traitementForSid = Get-ItemProperty -Path $regPath | Select-Object -ExpandProperty DisableThirdPartySuggestions

        # Check if traitementForSid is null, "Not Configured", or "Not Defined"
        if ($checkConditions -notcontains $traitementForSid) {
            $traitementForSid = $traitementForSid
        } else {
          $traitementForSid = "Not Configured / Check Manually"
        }
    } else {
        $traitementForSid = "Not Configured / Check Manually"
    }

    # Append the traitement for this SID to the main traitement string
    $traitement += "SID: $($sid.PSChildName) - Traitement: $traitementForSid | "
}

$chaine += $traitement
$chaine>> $filename

#Do not use diagnostic data for tailored experiences
$indextest += 1
$chaine = $null
$traitement = $null
$id = "CC" + "$indextest"

$chaine = "$id" + ";" + "(L2) Ensure 'Do not use diagnostic data for tailored experiences' is set to 'Enabled'" + ";"

# Get all SID paths under HKEY_USERS that match S-1-5-21-*
$sidPaths = Get-ChildItem -Path "Registry::HKEY_USERS" | Where-Object { $_.PSChildName -match '^S-1-5-21-' }

foreach ($sid in $sidPaths) {
    # Construct the registry path for the current SID
    $regPath = "Registry::HKEY_USERS\$($sid.PSChildName)\Software\Policies\Microsoft\Windows\CloudContent"

    # Check if the registry path exists
    if (Test-Path -Path $regPath) {
        # Try to get the DisableTailoredExperiencesWithDiagnosticData property
        $traitementForSid = Get-ItemProperty -Path $regPath | Select-Object -ExpandProperty DisableTailoredExperiencesWithDiagnosticData

        # Check if traitementForSid is null, "Not Configured", or "Not Defined"
        if ($checkConditions -notcontains $traitementForSid) {
            $traitementForSid = $traitementForSid
        } else {
          $traitementForSid = "Not Configured / Check Manually"
        }
    } else {
        $traitementForSid = "Not Configured / Check Manually"
    }

    # Append the traitement for this SID to the main traitement string
    $traitement += "SID: $($sid.PSChildName) - Traitement: $traitementForSid | "
}

$chaine += $traitement
$chaine>> $filename

#Turn off all Windows spotlight features
$indextest += 1
$chaine = $null
$traitement = $null
$id = "CC" + "$indextest"

$chaine = "$id" + ";" + "(L2) Ensure 'Turn off all Windows spotlight features' is set to 'Enabled'" + ";"

# Get all SID paths under HKEY_USERS that match S-1-5-21-*
$sidPaths = Get-ChildItem -Path "Registry::HKEY_USERS" | Where-Object { $_.PSChildName -match '^S-1-5-21-' }

foreach ($sid in $sidPaths) {
    # Construct the registry path for the current SID
    $regPath = "Registry::HKEY_USERS\$($sid.PSChildName)\Software\Policies\Microsoft\Windows\CloudContent"

    # Check if the registry path exists
    if (Test-Path -Path $regPath) {
        # Try to get the DisableWindowsSpotlightFeatures property
        $traitementForSid = Get-ItemProperty -Path $regPath | Select-Object -ExpandProperty DisableWindowsSpotlightFeatures

        # Check if traitementForSid is null, "Not Configured", or "Not Defined"
        if ($checkConditions -notcontains $traitementForSid) {
            $traitementForSid = $traitementForSid
        } else {
          $traitementForSid = "Not Configured / Check Manually"
        }
    } else {
        $traitementForSid = "Not Configured / Check Manually"
    }

    # Append the traitement for this SID to the main traitement string
    $traitement += "SID: $($sid.PSChildName) - Traitement: $traitementForSid | "
}

$chaine += $traitement
$chaine>> $filename

#Turn off Spotlight collection on Desktop
$indextest += 1
$chaine = $null
$traitement = $null
$id = "CC" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Turn off Spotlight collection on Desktop' is set to 'Enabled'" + ";"

# Get all SID paths under HKEY_USERS that match S-1-5-21-*
$sidPaths = Get-ChildItem -Path "Registry::HKEY_USERS" | Where-Object { $_.PSChildName -match '^S-1-5-21-' }

foreach ($sid in $sidPaths) {
    # Construct the registry path for the current SID
    $regPath = "Registry::HKEY_USERS\$($sid.PSChildName)\Software\Policies\Microsoft\Windows\CloudContent"

    # Check if the registry path exists
    if (Test-Path -Path $regPath) {
        # Try to get the DisableSpotlightCollectionOnDesktop property
        $traitementForSid = Get-ItemProperty -Path $regPath | Select-Object -ExpandProperty DisableSpotlightCollectionOnDesktop 

        # Check if traitementForSid is null, "Not Configured", or "Not Defined"
        if ($checkConditions -notcontains $traitementForSid) {
            $traitementForSid = $traitementForSid
        } else {
          $traitementForSid = "Not Configured / Check Manually"
        }
    } else {
        $traitementForSid = "Not Configured / Check Manually"
    }

    # Append the traitement for this SID to the main traitement string
    $traitement += "SID: $($sid.PSChildName) - Traitement: $traitementForSid | "
}

$chaine += $traitement
$chaine>> $filename


#Network Sharing
Write-Host "#########>Begin Network Sharing Audit<#########" -ForegroundColor DarkGreen


#Prevent users from sharing files within their profile
$indextest += 1
$chaine = $null
$traitement = $null
$id = "NS" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Prevent users from sharing files within their profile.' is set to 'Enabled'" + ";"

# Get all SID paths under HKEY_USERS that match S-1-5-21-*
$sidPaths = Get-ChildItem -Path "Registry::HKEY_USERS" | Where-Object { $_.PSChildName -match '^S-1-5-21-' }

foreach ($sid in $sidPaths) {
    # Construct the registry path for the current SID
    $regPath = "Registry::HKEY_USERS\$($sid.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"

    # Check if the registry path exists
    if (Test-Path -Path $regPath) {
        # Try to get the NoInplaceSharing property
        $traitementForSid = Get-ItemProperty -Path $regPath | Select-Object -ExpandProperty NoInplaceSharing

        # Check if traitementForSid is null, "Not Configured", or "Not Defined"
        if ($checkConditions -notcontains $traitementForSid) {
            $traitementForSid = $traitementForSid
        } else {
          $traitementForSid = "Not Configured / Check Manually"
        }
    } else {
        $traitementForSid = "Not Configured / Check Manually"
    }

    # Append the traitement for this SID to the main traitement string
    $traitement += "SID: $($sid.PSChildName) - Traitement: $traitementForSid | "
}

$chaine += $traitement
$chaine>> $filename


#Windows Installer
Write-Host "#########>Begin Windows Installer Audit<#########" -ForegroundColor DarkGreen


#Always install with elevated privileges
$indextest += 1
$chaine = $null
$traitement = $null
$id = "WI" + "$indextest"

$chaine = "$id" + ";" + "(L1) Ensure 'Always install with elevated privileges' is set to 'Disabled'" + ";"

# Get all SID paths under HKEY_USERS that match S-1-5-21-*
$sidPaths = Get-ChildItem -Path "Registry::HKEY_USERS" | Where-Object { $_.PSChildName -match '^S-1-5-21-' }

foreach ($sid in $sidPaths) {
    # Construct the registry path for the current SID
    $regPath = "Registry::HKEY_USERS\$($sid.PSChildName)\Software\Policies\Microsoft\Windows\Installer"

    # Check if the registry path exists
    if (Test-Path -Path $regPath) {
        # Try to get the AlwaysInstallElevated property
        $traitementForSid = Get-ItemProperty -Path $regPath | Select-Object -ExpandProperty AlwaysInstallElevated

        # Check if traitementForSid is null, "Not Configured", or "Not Defined"
        if ($checkConditions -notcontains $traitementForSid) {
            $traitementForSid = $traitementForSid
        } else {
          $traitementForSid = "Not Configured / Check Manually"
        }
    } else {
        $traitementForSid = "Not Configured / Check Manually"
    }

    # Append the traitement for this SID to the main traitement string
    $traitement += "SID: $($sid.PSChildName) - Traitement: $traitementForSid | "
}

$chaine += $traitement
$chaine>> $filename


#Playback
Write-Host "#########>Begin Playback Audit<#########" -ForegroundColor DarkGreen

#Prevent Codec Download
$indextest += 1
$chaine = $null
$traitement = $null
$id = "PB" + "$indextest"

$chaine = "$id" + ";" + "(L2) Ensure 'Prevent Codec Download' is set to 'Enabled'" + ";"

# Get all SID paths under HKEY_USERS that match S-1-5-21-*
$sidPaths = Get-ChildItem -Path "Registry::HKEY_USERS" | Where-Object { $_.PSChildName -match '^S-1-5-21-' }

foreach ($sid in $sidPaths) {
    # Construct the registry path for the current SID
    $regPath = "Registry::HKEY_USERS\$($sid.PSChildName)\Software\Policies\Microsoft\WindowsMediaPlayer"

    # Check if the registry path exists
    if (Test-Path -Path $regPath) {
        # Try to get the PreventCodecDownload property
        $traitementForSid = Get-ItemProperty -Path $regPath | Select-Object -ExpandProperty PreventCodecDownload

        # Check if traitementForSid is null, "Not Configured", or "Not Defined"
        if ($checkConditions -notcontains $traitementForSid) {
            $traitementForSid = $traitementForSid
        } else {
          $traitementForSid = "Not Configured / Check Manually"
        }
    } else {
        $traitementForSid = "Not Configured / Check Manually"
    }

    # Append the traitement for this SID to the main traitement string
    $traitement += "SID: $($sid.PSChildName) - Traitement: $traitementForSid | "
}

$chaine += $traitement
$chaine>> $filename


Write-Host "#########>END Audit<#########" -ForegroundColor DarkGreen
Set-Location ..