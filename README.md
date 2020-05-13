# Windows-events-for-Incident-Response

A list of Windows event that can be use during Incident Response


- [Windows events for Incident Response](#Windows-events-for-Incident-Response)
  - [Application](#application)
  - [System](#system)
  - [Security](#security)
  - [Powwershell](#powershell)
  - [Powershell](#powershell)
  



## Application

| Event ID	| Description	| Possible malicious behavior associated with	| Why is that useful | What should I do with that |
|------|------------|------------|------------|------------|
| 4778 |	"A session was reconnected to a Window Station." | Malicious connection using RDP | 	It can be use to identify the beginning of malicious remote connection to the host. But, you have to know what you are looking for or, at least a time period for suspicious activities because this event will list all remote connection to the host. |	Verify if this is a suspicious remote connections. |
| 4779	| "A session was disconnected from a Window Station." |	Malicious connection using RDP | It can be use to identify the end of a malicious remote connection to the host. But, you have to know what you are looking for or, at least a time period for suspicious activities because this event will list all remote connection to the host. |	Verify if this is a suspicious remote connections.|
| 4688	| ".A new process has been created.."	| Malware execution |	It can be use to identify the creation of malicious process. But, you have to know what you are looking for or, at least a time period for suspicious activities because this event will list all new process. |	Look at the "New Process Name" and the "Process command line". Convert the "New Process ID" from hexa to decimal. This can be used with event ID 5156 to look for outbound/inbound connection made by the malware. |
| 4698 |	".*A scheduled task was created..*"	| Persistence mechanism in scheduled task	| Identify new scheduled task as this is often use for persistence mechanism on a compromised host.	| Look at the "Task Name", the "Command" and the "Arguments". |
| 4700 |	"A scheduled task was enabled" |	Persistence mechanism in scheduled task |	Identify scheduled task enabled as this is often use for persistence mechanism on a compromised host. |	Look at the "Task Name", the "Command" and the "Arguments". |
| 4702 |	"A scheduled task was updated" |	Persistence mechanism in scheduled task |	Identify scheduled task that was changed as this is often use for persistence mechanism on a compromised host. |	Look at the "Task Name", the "Command" and the "Arguments". |
| 4697 |	"A service was installed in the system." |	Persistence mechanism in Windows Services |	Identify new Windows service as this is often use for persistence mechanism on a compromised host. |	Look at the "Service Name", the "Service Type", the "Serive Start Type" |
| 4624 |	"An account was successfully logged on" |	Detecting Lateral Movement |	Look for Logon type:<br> ".Logon Type:[\W](3 or 10).*" Identify successful logon to establish timeline of the remote connection.<br> Logon type 3 is Network (i.e. connection to shared folder on this computer from elsewhere on network.<br> Logon type 10: RemoteInteractive (Terminal Services, Remote Desktop or Remote Assistance). |
| 4625 |	"An account failed to log on" |	Detecting Lateral Movement |	Look for Logon type:<br> ".Logon Type:[\W](3 or 10).*"	<br>Identify unsuccessful logon to establish timeline of the remote connection. <br>Logon type 3 is Network (i.e. connection to shared folder on this computer from elsewhere on network. <br>Logon type 10: RemoteInteractive (Terminal Services, Remote Desktop or Remote Assistance). |
| 4720 |	"A user account was created" |	Malicious account created by attacker |	Identify possible malicious account created by malware or attacker. |	Look at the Security ID to understand what type of account was created:  For local account only: <br>Administrators: S-1-5-32-544 <br>Users: S-1-5-32-545 <br>Guests: S-1-5-32-546 <br><br>For domain account only: <br>Admin: S-1-5-21domain-500 <br>Domain users: S-1-5-21domain-513 <br>Domain admins: S-1-5-21domain-512 <br>Enterprise Admins: S-1-5-21root domain-519<br><br> Full list of SID available here<br> | Search for activities performed by the created account.|
| 4722 |	"A user account was enabled" |	Account enable by attacker | Identify possible account enable created by malware or attacker.	Look for Look at the Security ID to understand what type of account was enable: <br>Security ID:  The SID of the account. <br>Full list of SID available here <br>Account Name: The account logon name. <br>Account Domain: The domain or - in the case of local accounts - computer name. | Search for activities performed by the enabled account. |
| 4723 |	"An attempt was made to change an account's password" |	Attempt by attacker to change the user account password |		
| 4724 |	"An attempt was made to reset an accounts password" |	Attempt by attacker to reset the user account password |		
| 4725 |	"A user account was disabled" |	Account disable by attacker |		
| 4726 |	"A user account was deleted" |	Account deleted by attacker |		
| 4657 |	"A registry value was modified.*" |	Persistence mechanism in Windows registry |	Can be used to modify registry key related to persistence mechanism. |	Identify the process doing the modification using the "Process ID" and matching it with event ID 4688. <br><br>Look for modification related to the registry keys listed in persistence mechanism: <br>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run <br>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Runonce <br>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunonceEx <br>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run <br>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce <br>HKLM\SYSTEM\CurrentControlSet\Control\hivelist <br>HKEY_LOCAL_MACHINE\SYSTEM\ControlSet002\Control\Session Manager\BootExecute <br>HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon <br>HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\IniFileMapping\system.inin\boot (WIndows 8.1) <br>HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows |
| 4704 |	"A user right was assigned" |	Detecting Privilege Escalation |	This event documents a change to user right assignments on this computer including the right and user or group that received the new right. |	Look for user adding pirvilege to existing account.
Look for New right > User right | Full description for right added available here|
| 4689 |	"A process has exited" |	Malware execution |	It can be use to identify the end of malicious process. But, you have to know what you are looking for or, at least a time period for suspicious activities because this event will list all new process. |	Look at the "New Process Name" and establish a timeline of what happen when the malware was running. Convert the "New Process ID" from hexa to decimal. | This can be used with event ID 5156 to look for outbound/inbound connection made by the malware. |
| 5156 |	Windows Filtering Platform has permitted a connection	Identify malicious connections (IP & port) |	Discover who is calling out and to whom	Look at the details in "Application Information" and "Network Information". | Can bu used with Event ID 4688 & 4689 to identify which process is making the inbound/outbound connection. |
